//! vault.pqd write operations.
//!
//! Provides three public functions for serialising vault data to little-endian
//! binary format:
//!
//! - [`write_header`]: serialise a [`VaultHeader`] into any [`Write`] sink
//! - [`write_entries`]: serialise a slice of [`EntryRecord`]s into any [`Write`] sink
//! - [`write_vault`]: write a complete vault file to a [`Path`] with random tail padding

use std::io::Write;
use std::path::Path;

use rand::Rng;

use crate::error::DiaryError;
use crate::vault::format::{EntryRecord, VaultHeader, MAGIC};

// Fixed size of the on-disk verification-token ciphertext field (bytes 92-140).
const VERIFICATION_CT_LEN: usize = 48;

/// Serialise `header` into `writer` using little-endian byte order.
///
/// Writes the 204-byte fixed section followed by the variable-length
/// encrypted secret-key blocks:
///
/// ```text
/// [0..8]    magic b"PQDIARY\0"
/// [8]       schema_version
/// [9]       flags
/// [10..12]  reserved (0x00 0x00)
/// [12..16]  payload_size (LE u32)
/// [16..48]  kdf_salt (32 B)
/// [48..80]  legacy_salt (32 B)
/// [80..92]  verification_iv (12 B)
/// [92..140] verification_ct (48 B, zero-padded if field is shorter)
/// [140..172] kem_pk_offset (32 B)
/// [172..204] dsa_pk_hash (32 B)
/// [204..]   kem_encrypted_sk_len (LE u32) + kem_encrypted_sk bytes
///           dsa_encrypted_sk_len (LE u32) + dsa_encrypted_sk bytes
/// ```
pub fn write_header<W: Write>(writer: &mut W, header: &VaultHeader) -> Result<(), DiaryError> {
    // --- Fixed 204-byte section ---
    writer.write_all(MAGIC)?;
    writer.write_all(&[header.schema_version])?;
    writer.write_all(&[header.flags])?;
    writer.write_all(&[0u8; 2])?; // reserved
    writer.write_all(&header.payload_size.to_le_bytes())?;
    writer.write_all(&header.kdf_salt)?;
    writer.write_all(&header.legacy_salt)?;
    writer.write_all(&header.verification_iv)?;

    // verification_ct is fixed 48 bytes on disk; zero-pad if the Vec is shorter.
    let ct = &header.verification_ct;
    if ct.len() >= VERIFICATION_CT_LEN {
        writer.write_all(&ct[..VERIFICATION_CT_LEN])?;
    } else {
        let mut padded = [0u8; VERIFICATION_CT_LEN];
        padded[..ct.len()].copy_from_slice(ct);
        writer.write_all(&padded)?;
    }

    writer.write_all(&header.kem_pk_offset)?;
    writer.write_all(&header.dsa_pk_hash)?;

    // --- Variable-length encrypted secret-key blocks ---
    let kem_len = header.kem_encrypted_sk.len() as u32;
    writer.write_all(&kem_len.to_le_bytes())?;
    writer.write_all(&header.kem_encrypted_sk)?;

    let dsa_len = header.dsa_encrypted_sk.len() as u32;
    writer.write_all(&dsa_len.to_le_bytes())?;
    writer.write_all(&header.dsa_encrypted_sk)?;

    Ok(())
}

/// Serialise `entries` into `writer` using little-endian byte order.
///
/// Each entry record is written as a length-prefixed payload:
///
/// ```text
/// [record_len: LE u32]   -- byte count of the following payload
/// [record_type: 1 B]
/// [uuid: 16 B]
/// [created_at: LE u64]
/// [updated_at: LE u64]
/// [iv: 12 B]
/// [ciphertext_len: LE u32]
/// [ciphertext: variable]
/// [signature_len: LE u32]
/// [signature: variable]
/// [content_hmac: 32 B]
/// [legacy_flag: 1 B]
/// [legacy_key_block_len: LE u32]
/// [legacy_key_block: variable]
/// [attachment_count: LE u16]
/// [attachment_offset: LE u64]
/// [padding_len: 1 B]
/// [padding: variable]
/// ```
///
/// After all records a zero sentinel (`0u32` in LE) is appended so readers
/// can detect the end of the entry section without a separate count field.
pub fn write_entries<W: Write>(writer: &mut W, entries: &[EntryRecord]) -> Result<(), DiaryError> {
    for entry in entries {
        // Serialise the record payload into a temporary buffer so we know the length.
        let mut payload: Vec<u8> = Vec::new();

        // Record type is the first byte of every payload.
        payload.push(entry.record_type);
        payload.extend_from_slice(&entry.uuid);
        payload.extend_from_slice(&entry.created_at.to_le_bytes());
        payload.extend_from_slice(&entry.updated_at.to_le_bytes());
        payload.extend_from_slice(&entry.iv);

        let ct_len = entry.ciphertext.len() as u32;
        payload.extend_from_slice(&ct_len.to_le_bytes());
        payload.extend_from_slice(&entry.ciphertext);

        let sig_len = entry.signature.len() as u32;
        payload.extend_from_slice(&sig_len.to_le_bytes());
        payload.extend_from_slice(&entry.signature);

        payload.extend_from_slice(&entry.content_hmac);
        payload.push(entry.legacy_flag);

        let lkb_len = entry.legacy_key_block.len() as u32;
        payload.extend_from_slice(&lkb_len.to_le_bytes());
        payload.extend_from_slice(&entry.legacy_key_block);

        payload.extend_from_slice(&entry.attachment_count.to_le_bytes());
        payload.extend_from_slice(&entry.attachment_offset.to_le_bytes());

        let pad_len = entry.padding.len() as u8;
        payload.push(pad_len);
        payload.extend_from_slice(&entry.padding);

        // Write length prefix (LE u32) then the payload.
        let record_len = payload.len() as u32;
        writer.write_all(&record_len.to_le_bytes())?;
        writer.write_all(&payload)?;
    }

    // Zero sentinel — signals end of entry section to the reader.
    writer.write_all(&0u32.to_le_bytes())?;

    Ok(())
}

/// Write a complete vault to `path`.
///
/// Computes the serialised size of `entries`, sets `header.payload_size`
/// accordingly, writes the header followed by the entry section, then
/// appends a random padding block of 512–4 096 bytes to make file-size
/// analysis harder for an attacker.
///
/// # Errors
///
/// Returns [`DiaryError::Io`] on any I/O failure.
pub fn write_vault(
    path: &Path,
    mut header: VaultHeader,
    entries: &[EntryRecord],
) -> Result<(), DiaryError> {
    // Serialise entries first to measure the exact payload size.
    let mut entry_buf: Vec<u8> = Vec::new();
    write_entries(&mut entry_buf, entries)?;
    header.payload_size = entry_buf.len() as u32;

    // Generate cryptographically random padding (512–4 096 bytes).
    let mut rng = rand::thread_rng();
    let pad_size: usize = rng.gen_range(512..=4096);
    let mut padding = vec![0u8; pad_size];
    rng.fill(padding.as_mut_slice());

    // Write header → entries → padding to the target file.
    let mut file = std::fs::File::create(path)?;
    write_header(&mut file, &header)?;
    file.write_all(&entry_buf)?;
    file.write_all(&padding)?;

    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::format::{EntryRecord, VaultHeader, MAGIC, RECORD_TYPE_ENTRY};

    /// Build a minimal [`EntryRecord`] with known content for testing.
    fn make_test_entry() -> EntryRecord {
        EntryRecord {
            record_type: RECORD_TYPE_ENTRY,
            uuid: [0xABu8; 16],
            created_at: 1_000_000,
            updated_at: 2_000_000,
            iv: [0x01u8; 12],
            ciphertext: vec![0x10, 0x20, 0x30],
            signature: vec![0x40, 0x50],
            content_hmac: [0x7Fu8; 32],
            legacy_flag: 0x00,
            legacy_key_block: vec![],
            attachment_count: 0,
            attachment_offset: 0,
            padding: vec![],
        }
    }

    /// TC-021-01: write_header produces bytes whose first 8 bytes equal MAGIC.
    ///
    /// Given a default VaultHeader, when write_header writes it into a Vec<u8>,
    /// then the first 8 bytes of that buffer must equal b"PQDIARY\0".
    #[test]
    fn test_write_header_magic() {
        let header = VaultHeader::new();
        let mut buf: Vec<u8> = Vec::new();
        write_header(&mut buf, &header).expect("write_header must not fail");

        assert_eq!(&buf[..8], MAGIC.as_ref(), "first 8 bytes must equal MAGIC");
    }

    /// TC-021-02: payload_size field in the written bytes is accurate (LE u32).
    ///
    /// Given a VaultHeader and one entry, when write_vault writes to a temp file,
    /// then bytes [12..16] of the file must equal the actual entry-section size
    /// as a little-endian u32.
    #[test]
    fn test_write_vault_payload_size_accurate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.pqd");

        let entry = make_test_entry();
        write_vault(&path, VaultHeader::new(), &[entry]).expect("write_vault must not fail");

        let bytes = std::fs::read(&path).expect("read file");

        // payload_size is at header offset 12..16
        let payload_size = u32::from_le_bytes(bytes[12..16].try_into().expect("4 bytes"));

        // Independently compute the expected entry-section size.
        let mut expected_entry_buf: Vec<u8> = Vec::new();
        write_entries(&mut expected_entry_buf, &[make_test_entry()])
            .expect("write_entries must not fail");

        assert_eq!(
            payload_size,
            expected_entry_buf.len() as u32,
            "payload_size field must match actual entry-section byte count"
        );
    }

    /// TC-021-03: write_vault appends 512–4096 bytes of random padding.
    ///
    /// Given an empty vault (no entries, default header), when write_vault
    /// writes to a temp file, then (file_size - non_padding_size) must be
    /// in the range [512, 4096].
    #[test]
    fn test_write_vault_padding_size_in_range() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault_pad.pqd");

        write_vault(&path, VaultHeader::new(), &[]).expect("write_vault must not fail");

        let file_size = std::fs::metadata(&path).expect("metadata").len() as usize;

        // Compute the non-padding size by serialising header and entries independently.
        let mut entry_buf: Vec<u8> = Vec::new();
        write_entries(&mut entry_buf, &[]).expect("write_entries");
        let payload_size = entry_buf.len() as u32;

        let mut test_header = VaultHeader::new();
        test_header.payload_size = payload_size;
        let mut header_buf: Vec<u8> = Vec::new();
        write_header(&mut header_buf, &test_header).expect("write_header");

        let non_padding = header_buf.len() + entry_buf.len();
        let padding = file_size - non_padding;

        assert!(
            padding >= 512,
            "padding must be >= 512 bytes, got {}",
            padding
        );
        assert!(
            padding <= 4096,
            "padding must be <= 4096 bytes, got {}",
            padding
        );
    }
}
