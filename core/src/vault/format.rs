//! vault.pqd v4 binary format constants and structures.
//!
//! Defines the magic bytes, schema version, fixed-header size,
//! record-type constants, and the [`VaultHeader`] / [`EntryRecord`] structs
//! used for the custom binary serialisation of vault files.
//!
//! All multi-byte integer fields use little-endian byte order.

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
#[derive(Debug)]
pub struct EntryRecord {
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
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
