//! vault.pqd v4 binary format constants and structures.
//!
//! Defines the magic bytes, schema version, fixed-header size,
//! record-type constants, and the [`VaultHeader`] / [`EntryRecord`] structs
//! used for the custom binary serialisation of vault files.
//!
//! All multi-byte integer fields use little-endian byte order.

use crate::{crypto::aead, error::DiaryError};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

// =============================================================================
// Constants
// =============================================================================

/// vault.pqd magic bytes (8 bytes, ASCII "PQDIARY" followed by a NUL byte).
pub const MAGIC: &[u8; 8] = b"PQDIARY\0";

/// Current schema version embedded in every vault.pqd header.
pub const SCHEMA_VERSION: u8 = 0x04;

/// Size in bytes of the fixed portion of the vault.pqd header.
///
/// Layout (offsets are from byte 0):
/// - `[0..8]`   magic bytes
/// - `[8]`      schema version
/// - `[9]`      flags
/// - `[10..12]` reserved (zero-filled)
/// - `[12..16]` payload size (LE u32)
/// - `[16..48]` KDF salt (32 B)
/// - `[48..80]` legacy salt (32 B)
/// - `[80..92]` verification-token IV (12 B)
/// - `[92..140]` verification-token ciphertext (48 B)
/// - `[140..172]` ML-KEM public-key offset (32 B)
/// - `[172..204]` ML-DSA public-key hash (32 B)
pub const HEADER_SIZE: usize = 204;

/// Record type byte: journal entry.
pub const RECORD_TYPE_ENTRY: u8 = 0x01;

/// Record type byte: entry template.
pub const RECORD_TYPE_TEMPLATE: u8 = 0x02;

// =============================================================================
// VaultHeader
// =============================================================================

/// vault.pqd v4 header structure.
///
/// Holds the fixed-header fields (204 bytes on disk) plus the variable-length
/// encrypted secret-key blocks that follow immediately after.
///
/// The magic bytes are **not** stored here; they are written/verified
/// separately by the reader/writer.  `schema_version` is kept for informational
/// purposes.
#[derive(Debug)]
pub struct VaultHeader {
    /// Schema version byte (0x04 for v4).
    pub schema_version: u8,

    /// Header flags (reserved for future use; currently 0x00).
    pub flags: u8,

    /// Payload size in bytes (entry section + padding, LE u32).
    pub payload_size: u32,

    /// Argon2id KDF salt (32 bytes).
    pub kdf_salt: [u8; 32],

    /// Legacy-inheritance KDF salt (32 bytes).
    pub legacy_salt: [u8; 32],

    /// AES-256-GCM IV for the verification token (12 bytes).
    pub verification_iv: [u8; 12],

    /// Verification-token ciphertext (32-byte plaintext + 16-byte GCM tag = 48 bytes).
    pub verification_ct: Vec<u8>,

    /// ML-KEM public-key offset field (32 bytes).
    pub kem_pk_offset: [u8; 32],

    /// ML-DSA public-key SHA-256 hash (32 bytes).
    pub dsa_pk_hash: [u8; 32],

    /// AES-256-GCM-encrypted ML-KEM secret key (variable length).
    pub kem_encrypted_sk: Vec<u8>,

    /// AES-256-GCM-encrypted ML-DSA secret key (variable length).
    pub dsa_encrypted_sk: Vec<u8>,
}

impl VaultHeader {
    /// Create a new [`VaultHeader`] with safe default values.
    ///
    /// All byte-array fields are zero-initialised.
    /// `Vec` fields are empty.
    /// `schema_version` is set to [`SCHEMA_VERSION`].
    /// `payload_size` is 0 (updated when entries are written).
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            flags: 0,
            payload_size: 0,
            kdf_salt: [0u8; 32],
            legacy_salt: [0u8; 32],
            verification_iv: [0u8; 12],
            verification_ct: Vec::new(),
            kem_pk_offset: [0u8; 32],
            dsa_pk_hash: [0u8; 32],
            kem_encrypted_sk: Vec::new(),
            dsa_encrypted_sk: Vec::new(),
        }
    }
}

impl Default for VaultHeader {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// EntryRecord
// =============================================================================

/// A single entry record within the vault.pqd entry section.
///
/// Each record maps to one journal entry or template.
/// Fields are ordered to match the binary layout defined in the architecture
/// document (all multi-byte integers are little-endian).
///
/// The `record_type` byte is serialised as the first byte of each record's
/// payload and must be either [`RECORD_TYPE_ENTRY`] or [`RECORD_TYPE_TEMPLATE`].
#[derive(Debug)]
pub struct EntryRecord {
    /// Record type: [`RECORD_TYPE_ENTRY`] (0x01) or [`RECORD_TYPE_TEMPLATE`] (0x02).
    pub record_type: u8,

    /// Entry UUID (16 bytes, UUID v4 raw bytes).
    pub uuid: [u8; 16],

    /// Creation timestamp (Unix seconds, LE u64).
    pub created_at: u64,

    /// Last-update timestamp (Unix seconds, LE u64).
    pub updated_at: u64,

    /// AES-256-GCM initialisation vector (12 bytes).
    pub iv: [u8; 12],

    /// Ciphertext + GCM tag (variable length; plaintext_len + 16).
    pub ciphertext: Vec<u8>,

    /// ML-DSA-65 detached signature over the ciphertext (variable length).
    pub signature: Vec<u8>,

    /// HMAC-SHA-256 over the ciphertext (32 bytes).
    pub content_hmac: [u8; 32],

    /// Legacy flag: `0x00` = DESTROY, `0x01` = INHERIT.
    pub legacy_flag: u8,

    /// Encrypted legacy key block (variable length; empty when unused).
    pub legacy_key_block: Vec<u8>,

    /// Attachment count (Phase 2 reserved; always 0 in Phase 1).
    pub attachment_count: u16,

    /// Attachment section byte offset (Phase 2 reserved; always 0 in Phase 1).
    pub attachment_offset: u64,

    /// Random padding appended to this record (variable length).
    pub padding: Vec<u8>,
}

// =============================================================================
// Padding and verification-token helpers
// =============================================================================

/// Generate random padding for the end of a vault.pqd file.
///
/// Returns between 512 and 4096 bytes of cryptographically random data.
/// The random length makes it harder for an observer to infer the number of
/// entries in the vault from the file size.
pub fn generate_file_padding() -> Vec<u8> {
    let mut size_buf = [0u8; 4];
    OsRng.fill_bytes(&mut size_buf);
    let raw = u32::from_le_bytes(size_buf) as usize;
    // Range: 512..=4096  (4096 - 512 + 1 = 3585 possible sizes)
    let size = 512 + (raw % 3585);
    let mut padding = vec![0u8; size];
    OsRng.fill_bytes(&mut padding);
    padding
}

/// Generate random padding for the end of a single entry record.
///
/// Returns between 0 and 255 bytes of cryptographically random data.
/// The random length obscures individual entry sizes.
pub fn generate_entry_padding() -> Vec<u8> {
    let mut size_buf = [0u8; 1];
    OsRng.fill_bytes(&mut size_buf);
    let size = size_buf[0] as usize;
    let mut padding = vec![0u8; size];
    OsRng.fill_bytes(&mut padding);
    padding
}

/// Generate a verification token to be stored in the vault.pqd header.
///
/// Generates 32 bytes of cryptographically random data and encrypts them
/// with AES-256-GCM using `sym_key`.
///
/// Returns `(iv, ciphertext)` where `iv` is 12 bytes and `ciphertext` is
/// 48 bytes (32-byte plaintext + 16-byte GCM authentication tag).
pub fn generate_verification_token(
    sym_key: &[u8; 32],
) -> Result<([u8; 12], Vec<u8>), DiaryError> {
    let mut plaintext = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *plaintext);
    let (ciphertext, iv) = aead::encrypt(sym_key, &*plaintext)?;
    Ok((iv, ciphertext))
}

/// Verify a verification token against a symmetric key.
///
/// Decrypts `ciphertext` with AES-256-GCM using `sym_key` and `iv`.
/// Returns `Ok(true)` if decryption and authentication succeed,
/// `Ok(false)` if the key is wrong (GCM tag mismatch), and `Err` for
/// any other failure.
pub fn verify_token(
    sym_key: &[u8; 32],
    iv: [u8; 12],
    ciphertext: &[u8],
) -> Result<bool, DiaryError> {
    match aead::decrypt(sym_key, iv, ciphertext) {
        Ok(_) => Ok(true),
        Err(DiaryError::Crypto(_)) => Ok(false),
        Err(e) => Err(e),
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// TC-008-01: generate_file_padding() returns data in the 512–4096 byte range.
    ///
    /// Given no input, when generate_file_padding() is called, the returned
    /// Vec must have a length of at least 512 bytes and at most 4096 bytes.
    #[test]
    fn tc_008_01_file_padding_in_range() {
        for _ in 0..20 {
            let p = generate_file_padding();
            assert!(
                p.len() >= 512 && p.len() <= 4096,
                "file padding length {} is outside 512–4096",
                p.len()
            );
        }
    }

    /// TC-008-02: generate_entry_padding() returns data in the 0–255 byte range.
    ///
    /// Given no input, when generate_entry_padding() is called, the returned
    /// Vec must have a length between 0 and 255 bytes inclusive.
    #[test]
    fn tc_008_02_entry_padding_in_range() {
        for _ in 0..20 {
            let p = generate_entry_padding();
            assert!(
                p.len() <= 255,
                "entry padding length {} exceeds 255",
                p.len()
            );
        }
    }

    /// TC-008-03: two calls to generate_file_padding() produce different output.
    ///
    /// Given two independent calls, the resulting byte vectors must not be
    /// identical (same size AND same content).  With 512+ bytes of OsRng data
    /// the probability of a collision is negligible.
    #[test]
    fn tc_008_03_file_padding_differs_between_calls() {
        let p1 = generate_file_padding();
        let p2 = generate_file_padding();
        assert_ne!(p1, p2, "two calls to generate_file_padding must produce different data");
    }

    /// TC-007-01: generate_verification_token then verify_token with the same key → true.
    ///
    /// Given a 32-byte symmetric key, when a verification token is generated
    /// and immediately verified with the same key, the result must be Ok(true).
    #[test]
    fn tc_007_01_token_generate_and_verify_roundtrip() {
        let key = [0x42u8; 32];
        let (iv, ct) = generate_verification_token(&key).unwrap();
        let result = verify_token(&key, iv, &ct).unwrap();
        assert!(result, "verify_token with correct key must return true");
    }

    /// TC-007-02: verify_token with a wrong key → Ok(false).
    ///
    /// Given a token generated with one key, when verify_token is called
    /// with a different key, the result must be Ok(false) (not an error).
    #[test]
    fn tc_007_02_token_verify_with_wrong_key_returns_false() {
        let key = [0x42u8; 32];
        let wrong_key = [0xFFu8; 32];
        let (iv, ct) = generate_verification_token(&key).unwrap();
        let result = verify_token(&wrong_key, iv, &ct).unwrap();
        assert!(!result, "verify_token with wrong key must return false");
    }

    /// TC-020-01: MAGIC equals b"PQDIARY\0" and is exactly 8 bytes.
    ///
    /// Given the MAGIC constant, when its value and length are inspected,
    /// then it must equal the ASCII string "PQDIARY" followed by a NUL byte
    /// and have a length of 8.
    #[test]
    fn test_magic_value_and_length() {
        assert_eq!(MAGIC, b"PQDIARY\0");
        assert_eq!(MAGIC.len(), 8);
    }

    /// TC-020-02: SCHEMA_VERSION equals 0x04.
    ///
    /// Given the SCHEMA_VERSION constant, when its value is inspected,
    /// then it must equal 0x04.
    #[test]
    fn test_schema_version_value() {
        assert_eq!(SCHEMA_VERSION, 0x04);
    }

    /// TC-020-03: VaultHeader::new() returns correct default values.
    ///
    /// Given no input, when VaultHeader::new() is called, the resulting
    /// header must have schema_version = SCHEMA_VERSION, flags = 0,
    /// payload_size = 0, all salt/IV arrays zero-initialised, and all
    /// Vec fields empty.
    #[test]
    fn test_vault_header_new_defaults() {
        let h = VaultHeader::new();

        assert_eq!(h.schema_version, SCHEMA_VERSION);
        assert_eq!(h.flags, 0);
        assert_eq!(h.payload_size, 0);
        assert_eq!(h.kdf_salt, [0u8; 32]);
        assert_eq!(h.legacy_salt, [0u8; 32]);
        assert_eq!(h.verification_iv, [0u8; 12]);
        assert!(h.verification_ct.is_empty());
        assert_eq!(h.kem_pk_offset, [0u8; 32]);
        assert_eq!(h.dsa_pk_hash, [0u8; 32]);
        assert!(h.kem_encrypted_sk.is_empty());
        assert!(h.dsa_encrypted_sk.is_empty());
    }
}
