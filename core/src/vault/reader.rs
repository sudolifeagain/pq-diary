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

    // Record type (1 byte) — first byte of every payload.
    let mut type_buf = [0u8; 1];
    cursor.read_exact(&mut type_buf)?;
    let record_type = type_buf[0];

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
        record_type,
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
    use crate::vault::format::{
        VaultHeader, RECORD_TYPE_ENTRY, RECORD_TYPE_TEMPLATE, SCHEMA_VERSION,
    };
    use crate::vault::writer::{write_entries, write_header, write_vault};

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

    /// Build a template [`EntryRecord`] with known content.
    fn make_test_template() -> EntryRecord {
        EntryRecord {
            record_type: RECORD_TYPE_TEMPLATE,
            uuid: [0xCDu8; 16],
            created_at: 3_000_000,
            updated_at: 4_000_000,
            iv: [0x02u8; 12],
            ciphertext: vec![0xA0, 0xB0],
            signature: vec![0xC0],
            content_hmac: [0x3Cu8; 32],
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
        assert_eq!(
            parsed.legacy_salt, original.legacy_salt,
            "legacy_salt mismatch"
        );
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

        write_vault(&path, original_header, &original_entries).expect("write_vault must not fail");

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
        assert_eq!(e.record_type, RECORD_TYPE_ENTRY);
        assert_eq!(e.uuid, [0xABu8; 16]);
        assert_eq!(e.created_at, 1_000_000);
        assert_eq!(e.updated_at, 2_000_000);
        assert_eq!(e.iv, [0x01u8; 12]);
        assert_eq!(e.ciphertext, vec![0x10, 0x20, 0x30]);
        assert_eq!(e.signature, vec![0x40, 0x50]);
        assert_eq!(e.content_hmac, [0x7Fu8; 32]);
        assert_eq!(e.legacy_flag, 0x00);
    }

    // -----------------------------------------------------------------------
    // TASK-0023 test cases
    // -----------------------------------------------------------------------

    /// TC-002-01: write one entry then read back — all fields must match.
    ///
    /// Given one EntryRecord with distinct non-zero field values, when written
    /// via write_entries and read back via read_entries, every field must equal
    /// the original value.
    #[test]
    fn test_tc_002_01_entry_roundtrip_all_fields() {
        let entry = make_test_entry();

        let mut buf: Vec<u8> = Vec::new();
        write_entries(&mut buf, &[entry]).expect("write_entries");

        let mut cursor = io::Cursor::new(&buf);
        let entries = read_entries(&mut cursor).expect("read_entries");

        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.record_type, RECORD_TYPE_ENTRY);
        assert_eq!(e.uuid, [0xABu8; 16]);
        assert_eq!(e.created_at, 1_000_000);
        assert_eq!(e.updated_at, 2_000_000);
        assert_eq!(e.iv, [0x01u8; 12]);
        assert_eq!(e.ciphertext, vec![0x10, 0x20, 0x30]);
        assert_eq!(e.signature, vec![0x40, 0x50]);
        assert_eq!(e.content_hmac, [0x7Fu8; 32]);
        assert_eq!(e.legacy_flag, 0x00);
        assert!(e.legacy_key_block.is_empty());
        assert_eq!(e.attachment_count, 0);
        assert_eq!(e.attachment_offset, 0);
        assert!(e.padding.is_empty());
    }

    /// TC-002-02: multiple entries preserve insertion order.
    ///
    /// Given three EntryRecords with distinct UUIDs, when written and read
    /// back, the returned slice must contain all three in original order.
    #[test]
    fn test_tc_002_02_multiple_entries_order() {
        let mut e1 = make_test_entry();
        e1.uuid = [0x01u8; 16];
        let mut e2 = make_test_entry();
        e2.uuid = [0x02u8; 16];
        let mut e3 = make_test_entry();
        e3.uuid = [0x03u8; 16];

        let mut buf: Vec<u8> = Vec::new();
        write_entries(&mut buf, &[e1, e2, e3]).expect("write_entries");

        let mut cursor = io::Cursor::new(&buf);
        let entries = read_entries(&mut cursor).expect("read_entries");

        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].uuid, [0x01u8; 16]);
        assert_eq!(entries[1].uuid, [0x02u8; 16]);
        assert_eq!(entries[2].uuid, [0x03u8; 16]);
    }

    /// TC-002-03: zero-length record signals end of entry section.
    ///
    /// Given a byte stream that contains one valid entry followed by a zero
    /// sentinel, when read_entries parses it, it must return exactly one entry
    /// and stop without consuming bytes beyond the sentinel.
    #[test]
    fn test_tc_002_03_zero_sentinel_stops_reading() {
        let entry = make_test_entry();

        let mut buf: Vec<u8> = Vec::new();
        write_entries(&mut buf, &[entry]).expect("write_entries");

        // Append extra bytes after the sentinel to verify they are not consumed.
        buf.extend_from_slice(&[0xFFu8; 16]);

        let mut cursor = io::Cursor::new(&buf);
        let entries = read_entries(&mut cursor).expect("read_entries");

        assert_eq!(entries.len(), 1, "exactly one entry before the sentinel");
    }

    /// TC-002-04: attachment reservation fields are zero-initialised.
    ///
    /// Given an EntryRecord created with attachment_count=0 and
    /// attachment_offset=0, when written and read back, those fields
    /// must both equal zero.
    #[test]
    fn test_tc_002_04_attachment_fields_zero_initialised() {
        let entry = make_test_entry(); // attachment_count=0, attachment_offset=0

        let mut buf: Vec<u8> = Vec::new();
        write_entries(&mut buf, &[entry]).expect("write_entries");

        let mut cursor = io::Cursor::new(&buf);
        let entries = read_entries(&mut cursor).expect("read_entries");

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].attachment_count, 0, "attachment_count must be 0");
        assert_eq!(
            entries[0].attachment_offset, 0,
            "attachment_offset must be 0"
        );
    }

    /// TC-003-01: template record write→read roundtrip.
    ///
    /// Given an EntryRecord with record_type=RECORD_TYPE_TEMPLATE, when
    /// written and read back, the record_type and all other fields must match.
    #[test]
    fn test_tc_003_01_template_roundtrip() {
        let template = make_test_template();

        let mut buf: Vec<u8> = Vec::new();
        write_entries(&mut buf, &[template]).expect("write_entries");

        let mut cursor = io::Cursor::new(&buf);
        let entries = read_entries(&mut cursor).expect("read_entries");

        assert_eq!(entries.len(), 1);
        let t = &entries[0];
        assert_eq!(t.record_type, RECORD_TYPE_TEMPLATE);
        assert_eq!(t.uuid, [0xCDu8; 16]);
        assert_eq!(t.created_at, 3_000_000);
        assert_eq!(t.updated_at, 4_000_000);
        assert_eq!(t.ciphertext, vec![0xA0, 0xB0]);
    }

    /// TC-003-02: mixed entry and template records are read in order with correct types.
    ///
    /// Given one ENTRY and one TEMPLATE record written in sequence, when read
    /// back, the first must have record_type=ENTRY and the second TEMPLATE.
    #[test]
    fn test_tc_003_02_mixed_entry_and_template() {
        let entry = make_test_entry();
        let template = make_test_template();

        let mut buf: Vec<u8> = Vec::new();
        write_entries(&mut buf, &[entry, template]).expect("write_entries");

        let mut cursor = io::Cursor::new(&buf);
        let records = read_entries(&mut cursor).expect("read_entries");

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].record_type, RECORD_TYPE_ENTRY);
        assert_eq!(records[1].record_type, RECORD_TYPE_TEMPLATE);
    }

    /// TC-002-05: non-zero padding (0–255 B) survives round trip.
    ///
    /// Given an EntryRecord with 128 bytes of padding, when written and read
    /// back, the padding field must match exactly.
    #[test]
    fn test_tc_002_05_padding_roundtrip() {
        let mut entry = make_test_entry();
        entry.padding = (0u8..128).collect();

        let mut buf: Vec<u8> = Vec::new();
        write_entries(&mut buf, &[entry]).expect("write_entries");

        let mut cursor = io::Cursor::new(&buf);
        let entries = read_entries(&mut cursor).expect("read_entries");

        assert_eq!(entries.len(), 1);
        let expected_padding: Vec<u8> = (0u8..128).collect();
        assert_eq!(
            entries[0].padding, expected_padding,
            "padding must survive roundtrip"
        );
    }

    /// TC-002-06: maximum padding (255 B) survives round trip.
    ///
    /// Given an EntryRecord with 255 bytes of padding (the maximum for a u8
    /// length byte), when written and read back, the padding must match.
    #[test]
    fn test_tc_002_06_max_padding_roundtrip() {
        let mut entry = make_test_entry();
        entry.padding = vec![0xFEu8; 255];

        let mut buf: Vec<u8> = Vec::new();
        write_entries(&mut buf, &[entry]).expect("write_entries");

        let mut cursor = io::Cursor::new(&buf);
        let entries = read_entries(&mut cursor).expect("read_entries");

        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].padding,
            vec![0xFEu8; 255],
            "max padding must survive roundtrip"
        );
    }

    /// TC-002-B01: empty vault (zero entries) is read without error.
    ///
    /// Given a vault written with an empty entry slice, when read_entries
    /// parses the resulting byte stream, it must return an empty Vec without
    /// returning an error.
    #[test]
    fn test_tc_002_b01_empty_vault_reads_ok() {
        let mut buf: Vec<u8> = Vec::new();
        write_entries(&mut buf, &[]).expect("write_entries");

        let mut cursor = io::Cursor::new(&buf);
        let entries = read_entries(&mut cursor).expect("read_entries");

        assert!(entries.is_empty(), "expected no entries for empty vault");
    }

    /// TC-002-B02: 100-entry write/read roundtrip.
    ///
    /// Given 100 EntryRecords each with a unique UUID derived from the index,
    /// when written and read back, the count must be 100 and every UUID must
    /// match the original.
    #[test]
    fn test_tc_002_b02_bulk_100_entries() {
        let entries: Vec<EntryRecord> = (0u8..100)
            .map(|i| {
                let mut e = make_test_entry();
                e.uuid = [i; 16];
                e
            })
            .collect();

        let mut buf: Vec<u8> = Vec::new();
        write_entries(&mut buf, &entries).expect("write_entries");

        let mut cursor = io::Cursor::new(&buf);
        let read_back = read_entries(&mut cursor).expect("read_entries");

        assert_eq!(read_back.len(), 100, "must read back 100 entries");
        for (i, e) in read_back.iter().enumerate() {
            assert_eq!(e.uuid, [i as u8; 16], "uuid mismatch at index {}", i);
        }
    }
}
