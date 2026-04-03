//! vault.pqd read operations.
//!
//! Provides three public functions for deserialising vault data from
//! little-endian binary format:
//!
//! - [`read_header`]: parse a [`VaultHeader`] from any [`Read`] source
//! - [`read_entries`]: parse a sequence of [`EntryRecord`]s from any [`Read`] source
//! - [`read_vault`]: read a complete vault file from a [`Path`]

use std::io::{self, Read};
use std::path::Path;

use crate::error::DiaryError;
use crate::vault::format::{EntryRecord, VaultHeader, MAGIC, SCHEMA_VERSION};

/// Fixed size of the on-disk verification-token ciphertext field (bytes 92–140).
const VERIFICATION_CT_LEN: usize = 48;

/// Parse a [`VaultHeader`] from `reader`.
///
/// Reads the fixed 204-byte section then the variable-length encrypted
/// secret-key blocks. Validates magic bytes and schema version before
/// populating the struct.
///
/// # Errors
///
/// - [`DiaryError::Vault`] if the magic bytes do not match `b"PQDIARY\0"`.
/// - [`DiaryError::Vault`] if the schema version byte is not `0x04`.
/// - [`DiaryError::Io`] on any underlying I/O failure.
pub fn read_header(reader: &mut impl Read) -> Result<VaultHeader, DiaryError> {
    // --- Magic bytes [0..8] ---
    let mut magic = [0u8; 8];
    reader.read_exact(&mut magic)?;
    if magic != *MAGIC {
        return Err(DiaryError::Vault(
            "invalid magic bytes: not a pq-diary vault file".into(),
        ));
    }

    // --- Schema version [8] ---
    let mut version_buf = [0u8; 1];
    reader.read_exact(&mut version_buf)?;
    if version_buf[0] != SCHEMA_VERSION {
        return Err(DiaryError::Vault(format!(
            "unsupported schema version: expected 0x{:02x}, got 0x{:02x}",
            SCHEMA_VERSION, version_buf[0]
        )));
    }

    // --- Flags [9] ---
    let mut flags_buf = [0u8; 1];
    reader.read_exact(&mut flags_buf)?;

    // --- Reserved [10..12] (discarded) ---
    let mut reserved = [0u8; 2];
    reader.read_exact(&mut reserved)?;

    // --- Payload size [12..16] (LE u32) ---
    let mut payload_size_bytes = [0u8; 4];
    reader.read_exact(&mut payload_size_bytes)?;
    let payload_size = u32::from_le_bytes(payload_size_bytes);

    // --- KDF salt [16..48] ---
    let mut kdf_salt = [0u8; 32];
    reader.read_exact(&mut kdf_salt)?;

    // --- Legacy salt [48..80] ---
    let mut legacy_salt = [0u8; 32];
    reader.read_exact(&mut legacy_salt)?;

    // --- Verification token IV [80..92] ---
    let mut verification_iv = [0u8; 12];
    reader.read_exact(&mut verification_iv)?;

    // --- Verification token ciphertext [92..140] (48 bytes fixed on disk) ---
    let mut verification_ct_buf = [0u8; VERIFICATION_CT_LEN];
    reader.read_exact(&mut verification_ct_buf)?;
    let verification_ct = verification_ct_buf.to_vec();

    // --- ML-KEM public-key offset [140..172] ---
    let mut kem_pk_offset = [0u8; 32];
    reader.read_exact(&mut kem_pk_offset)?;

    // --- ML-DSA public-key hash [172..204] ---
    let mut dsa_pk_hash = [0u8; 32];
    reader.read_exact(&mut dsa_pk_hash)?;

    // --- Variable-length encrypted KEM secret key ---
    let mut kem_sk_len_bytes = [0u8; 4];
    reader.read_exact(&mut kem_sk_len_bytes)?;
    let kem_sk_len = u32::from_le_bytes(kem_sk_len_bytes) as usize;
    let mut kem_encrypted_sk = vec![0u8; kem_sk_len];
    if kem_sk_len > 0 {
        reader.read_exact(&mut kem_encrypted_sk)?;
    }

    // --- Variable-length encrypted DSA secret key ---
    let mut dsa_sk_len_bytes = [0u8; 4];
    reader.read_exact(&mut dsa_sk_len_bytes)?;
    let dsa_sk_len = u32::from_le_bytes(dsa_sk_len_bytes) as usize;
    let mut dsa_encrypted_sk = vec![0u8; dsa_sk_len];
    if dsa_sk_len > 0 {
        reader.read_exact(&mut dsa_encrypted_sk)?;
    }

    Ok(VaultHeader {
        schema_version: version_buf[0],
        flags: flags_buf[0],
        payload_size,
        kdf_salt,
        legacy_salt,
        verification_iv,
        verification_ct,
        kem_pk_offset,
        dsa_pk_hash,
        kem_encrypted_sk,
        dsa_encrypted_sk,
    })
}

/// Read all [`EntryRecord`]s from `reader` until a zero-length sentinel is encountered.
///
/// Each record begins with a LE u32 length prefix. A zero prefix signals the
/// end of the entry section; any trailing bytes (random file padding) are left
/// in the stream.
///
/// # Errors
///
/// Returns [`DiaryError::Io`] on any underlying I/O failure.
pub fn read_entries(reader: &mut impl Read) -> Result<Vec<EntryRecord>, DiaryError> {
    let mut entries = Vec::new();

    loop {
        // Read record length prefix (LE u32).
        let mut len_bytes = [0u8; 4];
        reader.read_exact(&mut len_bytes)?;
        let record_len = u32::from_le_bytes(len_bytes) as usize;

        // Zero sentinel signals end of entry section.
        if record_len == 0 {
            break;
        }

        // Read the record payload into a bounded buffer then parse it.
        let mut payload = vec![0u8; record_len];
        reader.read_exact(&mut payload)?;

        let entry = parse_entry_payload(&payload)?;
        entries.push(entry);
    }

    Ok(entries)
}

/// Parse a single [`EntryRecord`] from a pre-read payload buffer.
fn parse_entry_payload(payload: &[u8]) -> Result<EntryRecord, DiaryError> {
    let mut cursor = io::Cursor::new(payload);

    // UUID (16 bytes)
    let mut uuid = [0u8; 16];
    cursor.read_exact(&mut uuid)?;

    // created_at (LE u64)
    let mut ts_bytes = [0u8; 8];
    cursor.read_exact(&mut ts_bytes)?;
    let created_at = u64::from_le_bytes(ts_bytes);

    // updated_at (LE u64)
    cursor.read_exact(&mut ts_bytes)?;
    let updated_at = u64::from_le_bytes(ts_bytes);

    // IV (12 bytes)
    let mut iv = [0u8; 12];
    cursor.read_exact(&mut iv)?;

    // Ciphertext length (LE u32) + ciphertext
    let mut u32_buf = [0u8; 4];
    cursor.read_exact(&mut u32_buf)?;
    let ct_len = u32::from_le_bytes(u32_buf) as usize;
    let mut ciphertext = vec![0u8; ct_len];
    if ct_len > 0 {
        cursor.read_exact(&mut ciphertext)?;
    }

    // Signature length (LE u32) + signature
    cursor.read_exact(&mut u32_buf)?;
    let sig_len = u32::from_le_bytes(u32_buf) as usize;
    let mut signature = vec![0u8; sig_len];
    if sig_len > 0 {
        cursor.read_exact(&mut signature)?;
    }

    // HMAC-SHA256 (32 bytes)
    let mut content_hmac = [0u8; 32];
    cursor.read_exact(&mut content_hmac)?;

    // Legacy flag (1 byte)
    let mut flag_buf = [0u8; 1];
    cursor.read_exact(&mut flag_buf)?;
    let legacy_flag = flag_buf[0];

    // Legacy key block length (LE u32) + legacy key block
    cursor.read_exact(&mut u32_buf)?;
    let lkb_len = u32::from_le_bytes(u32_buf) as usize;
    let mut legacy_key_block = vec![0u8; lkb_len];
    if lkb_len > 0 {
        cursor.read_exact(&mut legacy_key_block)?;
    }

    // Attachment count (LE u16)
    let mut u16_buf = [0u8; 2];
    cursor.read_exact(&mut u16_buf)?;
    let attachment_count = u16::from_le_bytes(u16_buf);

    // Attachment offset (LE u64)
    cursor.read_exact(&mut ts_bytes)?;
    let attachment_offset = u64::from_le_bytes(ts_bytes);

    // Padding length (1 byte) + padding
    cursor.read_exact(&mut flag_buf)?;
    let pad_len = flag_buf[0] as usize;
    let mut padding = vec![0u8; pad_len];
    if pad_len > 0 {
        cursor.read_exact(&mut padding)?;
    }

    Ok(EntryRecord {
        uuid,
        created_at,
        updated_at,
        iv,
        ciphertext,
        signature,
        content_hmac,
        legacy_flag,
        legacy_key_block,
        attachment_count,
        attachment_offset,
        padding,
    })
}

/// Read a complete vault from `path`.
///
/// Opens the file at `path`, reads the header (verifying magic bytes and schema
/// version), then reads all entry records up to the zero sentinel. Any trailing
/// random padding bytes written by [`crate::vault::writer::write_vault`] are
/// silently ignored.
///
/// # Errors
///
/// - [`DiaryError::Vault`] on magic or version mismatch.
/// - [`DiaryError::Io`] on any I/O failure.
pub fn read_vault(path: &Path) -> Result<(VaultHeader, Vec<EntryRecord>), DiaryError> {
    let mut file = std::fs::File::open(path)?;
    let header = read_header(&mut file)?;
    let entries = read_entries(&mut file)?;
    Ok((header, entries))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::format::{VaultHeader, SCHEMA_VERSION};
    use crate::vault::writer::{write_header, write_vault};

    /// Build a [`VaultHeader`] with recognisable non-zero field values.
    fn make_test_header() -> VaultHeader {
        let mut h = VaultHeader::new();
        h.flags = 0x42;
        h.payload_size = 99;
        h.kdf_salt = [0xAAu8; 32];
        h.legacy_salt = [0xBBu8; 32];
        h.verification_iv = [0xCCu8; 12];
        h.verification_ct = vec![0xDDu8; 48];
        h.kem_pk_offset = [0xEEu8; 32];
        h.dsa_pk_hash = [0xFFu8; 32];
        h.kem_encrypted_sk = vec![0x11, 0x22, 0x33];
        h.dsa_encrypted_sk = vec![0x44, 0x55];
        h
    }

    /// Build a minimal [`EntryRecord`] with known content.
    fn make_test_entry() -> crate::vault::format::EntryRecord {
        crate::vault::format::EntryRecord {
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

    /// TC-001-01: write_header → read_header produces matching header fields.
    ///
    /// Given a VaultHeader with non-zero field values, when write_header writes
    /// it into a buffer and read_header reads it back, then all fields must
    /// match the original.
    #[test]
    fn test_read_header_roundtrip() {
        let original = make_test_header();

        let mut buf: Vec<u8> = Vec::new();
        write_header(&mut buf, &original).expect("write_header must not fail");

        let mut cursor = io::Cursor::new(&buf);
        let parsed = read_header(&mut cursor).expect("read_header must not fail");

        assert_eq!(parsed.schema_version, SCHEMA_VERSION);
        assert_eq!(parsed.flags, original.flags);
        assert_eq!(parsed.payload_size, original.payload_size);
        assert_eq!(parsed.kdf_salt, original.kdf_salt);
        assert_eq!(parsed.legacy_salt, original.legacy_salt);
        assert_eq!(parsed.verification_iv, original.verification_iv);
        assert_eq!(parsed.verification_ct, original.verification_ct);
        assert_eq!(parsed.kem_pk_offset, original.kem_pk_offset);
        assert_eq!(parsed.dsa_pk_hash, original.dsa_pk_hash);
        assert_eq!(parsed.kem_encrypted_sk, original.kem_encrypted_sk);
        assert_eq!(parsed.dsa_encrypted_sk, original.dsa_encrypted_sk);
    }

    /// TC-001-03: KDF salt and Legacy salt survive a write→read round trip.
    ///
    /// Given a VaultHeader with specific salt values, when written and read back,
    /// then kdf_salt and legacy_salt must equal the originals exactly.
    #[test]
    fn test_read_header_salts_match() {
        let mut original = VaultHeader::new();
        original.kdf_salt = [0x5Au8; 32];
        original.legacy_salt = [0xA5u8; 32];

        let mut buf: Vec<u8> = Vec::new();
        write_header(&mut buf, &original).expect("write_header must not fail");

        let mut cursor = io::Cursor::new(&buf);
        let parsed = read_header(&mut cursor).expect("read_header must not fail");

        assert_eq!(parsed.kdf_salt, original.kdf_salt, "kdf_salt mismatch");
        assert_eq!(parsed.legacy_salt, original.legacy_salt, "legacy_salt mismatch");
    }

    /// TC-001-E01: invalid magic bytes → DiaryError::Vault.
    ///
    /// Given a buffer whose first 8 bytes are not b"PQDIARY\0", when read_header
    /// is called, then DiaryError::Vault must be returned.
    #[test]
    fn test_read_header_invalid_magic() {
        // Write a valid header then overwrite the magic bytes.
        let mut buf: Vec<u8> = Vec::new();
        write_header(&mut buf, &VaultHeader::new()).expect("write_header must not fail");
        buf[0..8].copy_from_slice(b"INVALID!");

        let mut cursor = io::Cursor::new(&buf);
        let result = read_header(&mut cursor);

        assert!(
            matches!(result, Err(DiaryError::Vault(_))),
            "expected DiaryError::Vault for invalid magic, got {:?}",
            result
        );
    }

    /// TC-001-E02: invalid schema version → DiaryError::Vault.
    ///
    /// Given a buffer with correct magic bytes but an unsupported version byte,
    /// when read_header is called, then DiaryError::Vault must be returned.
    #[test]
    fn test_read_header_invalid_version() {
        // Write a valid header then corrupt the version byte at offset 8.
        let mut buf: Vec<u8> = Vec::new();
        write_header(&mut buf, &VaultHeader::new()).expect("write_header must not fail");
        buf[8] = 0xFF; // unsupported version

        let mut cursor = io::Cursor::new(&buf);
        let result = read_header(&mut cursor);

        assert!(
            matches!(result, Err(DiaryError::Vault(_))),
            "expected DiaryError::Vault for invalid version, got {:?}",
            result
        );
    }

    /// TC-022-01: write_vault → read_vault round trip.
    ///
    /// Given a VaultHeader and a list of EntryRecords, when write_vault writes
    /// them to a temporary file and read_vault reads it back, then the header
    /// fields and all entry record fields must match the originals.
    #[test]
    fn test_read_vault_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.pqd");

        let original_header = make_test_header();
        let original_entries = vec![make_test_entry()];

        write_vault(&path, original_header, &original_entries)
            .expect("write_vault must not fail");

        let (header, entries) = read_vault(&path).expect("read_vault must not fail");

        // Header field checks
        assert_eq!(header.schema_version, SCHEMA_VERSION);
        assert_eq!(header.flags, 0x42);
        assert_eq!(header.kdf_salt, [0xAAu8; 32]);
        assert_eq!(header.legacy_salt, [0xBBu8; 32]);
        assert_eq!(header.verification_iv, [0xCCu8; 12]);
        assert_eq!(header.kem_pk_offset, [0xEEu8; 32]);
        assert_eq!(header.dsa_pk_hash, [0xFFu8; 32]);
        assert_eq!(header.kem_encrypted_sk, vec![0x11, 0x22, 0x33]);
        assert_eq!(header.dsa_encrypted_sk, vec![0x44, 0x55]);

        // Entry checks
        assert_eq!(entries.len(), 1, "expected 1 entry");
        let e = &entries[0];
        assert_eq!(e.uuid, [0xABu8; 16]);
        assert_eq!(e.created_at, 1_000_000);
        assert_eq!(e.updated_at, 2_000_000);
        assert_eq!(e.iv, [0x01u8; 12]);
        assert_eq!(e.ciphertext, vec![0x10, 0x20, 0x30]);
        assert_eq!(e.signature, vec![0x40, 0x50]);
        assert_eq!(e.content_hmac, [0x7Fu8; 32]);
        assert_eq!(e.legacy_flag, 0x00);
    }
}
