//! Entry CRUD foundational types and operations.
//!
//! Provides [`EntryPlaintext`], [`EntryMeta`], [`Tag`], and [`IdPrefix`] types,
//! along with `create_entry` and other CRUD functions implemented in Sprint 4.

use crate::{
    crypto::CryptoEngine,
    error::DiaryError,
    vault::{
        format::{generate_entry_padding, EntryRecord, RECORD_TYPE_ENTRY},
        reader::read_vault,
        writer::write_vault,
    },
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Entry plaintext payload serialized before AES-256-GCM encryption.
///
/// Encryption flow:
/// `EntryPlaintext` → `serde_json::to_vec()` → `CryptoEngine::encrypt()` → `EntryRecord.ciphertext`
///
/// Decryption flow:
/// `EntryRecord.ciphertext` → `CryptoEngine::decrypt()` → `serde_json::from_slice()` → `EntryPlaintext`
///
/// The struct derives `Zeroize` and `ZeroizeOnDrop` because entry content is
/// secret data that must be erased from memory when no longer needed.
#[derive(Debug, Serialize, Deserialize, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct EntryPlaintext {
    /// Entry title.
    pub title: String,
    /// Tag list (nested tags supported: "work/design/review").
    pub tags: Vec<String>,
    /// Body text (Markdown).
    pub body: String,
}

/// Metadata for list display.
///
/// Lightweight struct containing only the fields needed for the `list` command.
/// The body is excluded as it is not needed for list operations.
pub struct EntryMeta {
    /// UUID in hex format (32 characters, no dashes).
    pub uuid_hex: String,
    /// Entry title.
    pub title: String,
    /// Tag list.
    pub tags: Vec<String>,
    /// Creation time (Unix timestamp seconds).
    pub created_at: u64,
    /// Last update time (Unix timestamp seconds).
    pub updated_at: u64,
}

impl EntryMeta {
    /// Returns a prefix of the UUID hex with the specified number of characters.
    ///
    /// The returned slice is at most `len` characters, clamped to the full
    /// length of `uuid_hex` if `len` exceeds it.
    pub fn id_prefix(&self, len: usize) -> &str {
        &self.uuid_hex[..len.min(self.uuid_hex.len())]
    }
}

/// Validated tag.
///
/// Allows alphanumeric characters, Unicode, `_`, `-`, and `/` (hierarchy separator).
/// Spaces are forbidden. Empty strings are forbidden.
/// Leading and trailing slashes are stripped during normalization.
pub struct Tag(String);

impl Tag {
    /// Validates and normalizes a tag string.
    ///
    /// Leading and trailing `/` characters are stripped before validation.
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::InvalidArgument`] if:
    /// - The string (after stripping) is empty.
    /// - The string contains a space character.
    pub fn new(s: &str) -> Result<Self, DiaryError> {
        let stripped = s.trim_matches('/');

        if stripped.contains(' ') {
            return Err(DiaryError::InvalidArgument(
                "tag must not contain spaces".to_string(),
            ));
        }

        if stripped.is_empty() {
            return Err(DiaryError::InvalidArgument(
                "tag must not be empty".to_string(),
            ));
        }

        if stripped.chars().all(|c| c.is_ascii_digit()) {
            return Err(DiaryError::InvalidArgument(
                "tag must not consist of digits only".to_string(),
            ));
        }

        // Normalize consecutive slashes: "a//b" → "a/b"
        let mut normalized = String::with_capacity(stripped.len());
        let mut prev_slash = false;
        for ch in stripped.chars() {
            if ch == '/' {
                if !prev_slash {
                    normalized.push(ch);
                }
                prev_slash = true;
            } else {
                normalized.push(ch);
                prev_slash = false;
            }
        }

        Ok(Tag(normalized))
    }

    /// Returns a reference to the inner normalized string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns true if `self` is an exact match or a hierarchical prefix of `other`.
    ///
    /// # Examples
    ///
    /// - `"work".is_prefix_of("work/design")` → `true`
    /// - `"work".is_prefix_of("work")` → `true`
    /// - `"work".is_prefix_of("worker")` → `false`
    pub fn is_prefix_of(&self, other: &Tag) -> bool {
        other.0 == self.0 || other.0.starts_with(&format!("{}/", self.0))
    }
}

/// Validated ID prefix for entry lookup.
///
/// Minimum 4 hex characters (`[0-9a-f]`). Uppercase letters are normalized
/// to lowercase on construction.
#[derive(Debug)]
pub struct IdPrefix(String);

impl IdPrefix {
    /// Validates a hex string as an ID prefix.
    ///
    /// Uppercase hex letters (A–F) are accepted and normalized to lowercase.
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::InvalidArgument`] if:
    /// - The string is fewer than 4 characters → `"ID prefix must be at least 4 characters"`
    /// - The string contains non-hex characters.
    pub fn new(s: &str) -> Result<Self, DiaryError> {
        let lower = s.to_lowercase();

        if lower.len() < 4 {
            return Err(DiaryError::InvalidArgument(
                "ID prefix must be at least 4 characters".to_string(),
            ));
        }

        if !lower.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(DiaryError::InvalidArgument(
                "ID prefix must contain only hex characters [0-9a-f]".to_string(),
            ));
        }

        Ok(IdPrefix(lower))
    }

    /// Returns a reference to the inner normalized hex string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns true if the UUID bytes start with this prefix.
    ///
    /// The UUID bytes are hex-encoded (32 lowercase characters) and compared
    /// with a `starts_with` check.
    pub fn matches(&self, uuid: &[u8; 16]) -> bool {
        let hex: String = uuid.iter().map(|b| format!("{:02x}", b)).collect();
        hex.starts_with(&self.0)
    }
}

// =============================================================================
// CRUD functions
// =============================================================================

/// List all entries in the vault and return their metadata.
///
/// Reads every [`EntryRecord`] from the vault, decrypts each one with
/// `engine.decrypt()`, deserialises the JSON payload into [`EntryPlaintext`],
/// and returns a flat [`Vec<EntryMeta>`] suitable for display or filtering.
///
/// HMAC and signature verification are intentionally **skipped** in this function
/// to preserve list performance.  Use [`get_entry`] or [`list_entries_with_body`]
/// when integrity checking is required.
///
/// Sorting and filtering are intentionally left to the caller (e.g. the CLI).
///
/// # Errors
///
/// Returns [`DiaryError::Io`] on vault I/O failure.
/// Returns [`DiaryError::Crypto`] if decryption fails for any record.
/// Returns [`DiaryError::Entry`] if JSON deserialisation fails for any record.
/// Returns [`DiaryError::NotUnlocked`] if the engine is locked.
pub fn list_entries(
    vault_path: &Path,
    engine: &CryptoEngine,
) -> Result<Vec<EntryMeta>, DiaryError> {
    let (_header, records) = read_vault(vault_path)?;
    let mut metas = Vec::with_capacity(records.len());
    for record in records {
        if record.record_type != RECORD_TYPE_ENTRY {
            continue;
        }
        let decrypted = engine.decrypt(&record.iv, &record.ciphertext)?;
        let mut plaintext: EntryPlaintext = serde_json::from_slice(decrypted.as_ref())
            .map_err(|e| DiaryError::Entry(format!("deserialization failed: {e}")))?;
        let uuid_hex: String = record.uuid.iter().map(|b| format!("{:02x}", b)).collect();
        metas.push(EntryMeta {
            uuid_hex,
            title: std::mem::take(&mut plaintext.title),
            tags: std::mem::take(&mut plaintext.tags),
            created_at: record.created_at,
            updated_at: record.updated_at,
        });
        // plaintext drops here; ZeroizeOnDrop zeroes any remaining data.
    }
    Ok(metas)
}

/// List all entries in the vault returning metadata paired with the decrypted body text.
///
/// Used internally by `DiaryCore::unlock` to build the [`crate::link::LinkIndex`]
/// in a single vault read.
///
/// Verifies `content_hmac` (HMAC-SHA256 over the ciphertext) and the ML-DSA-65
/// signature for every entry before decryption.  Returns [`DiaryError::Crypto`]
/// at the first integrity failure.
///
/// # Errors
///
/// Returns [`DiaryError::Io`] on vault I/O failure.
/// Returns [`DiaryError::Crypto`] if HMAC or signature verification fails, or if
///   decryption fails for any record.
/// Returns [`DiaryError::Entry`] if JSON deserialisation fails for any record.
pub fn list_entries_with_body(
    vault_path: &Path,
    engine: &CryptoEngine,
) -> Result<Vec<(EntryMeta, Zeroizing<String>)>, DiaryError> {
    let (_header, records) = read_vault(vault_path)?;
    let mut result = Vec::with_capacity(records.len());
    for record in records {
        if record.record_type != RECORD_TYPE_ENTRY {
            continue;
        }
        let uuid_hex: String = record.uuid.iter().map(|b| format!("{:02x}", b)).collect();

        // Verify HMAC over ciphertext before decryption.
        if !engine.hmac_verify(&record.ciphertext, &record.content_hmac)? {
            return Err(DiaryError::Crypto(format!(
                "content HMAC verification failed for entry {}",
                uuid_hex
            )));
        }

        // Verify ML-DSA-65 signature over ciphertext (skip if signature is absent).
        if !record.signature.is_empty()
            && !engine.dsa_verify_entry(&record.ciphertext, &record.signature)?
        {
            return Err(DiaryError::Crypto(format!(
                "signature verification failed for entry {}",
                uuid_hex
            )));
        }

        let decrypted = engine.decrypt(&record.iv, &record.ciphertext)?;
        let mut plaintext: EntryPlaintext = serde_json::from_slice(decrypted.as_ref())
            .map_err(|e| DiaryError::Entry(format!("deserialization failed: {e}")))?;
        let title = std::mem::take(&mut plaintext.title);
        let tags = std::mem::take(&mut plaintext.tags);
        let body = Zeroizing::new(std::mem::take(&mut plaintext.body));
        // plaintext drops here; ZeroizeOnDrop zeroes the now-empty fields.
        let meta = EntryMeta {
            uuid_hex,
            title,
            tags,
            created_at: record.created_at,
            updated_at: record.updated_at,
        };
        result.push((meta, body));
    }
    Ok(result)
}

/// Create a new entry in the vault and return its UUID.
///
/// Processing pipeline:
/// 1. Generate a UUID v4.
/// 2. Serialize `plaintext` to JSON bytes via `serde_json::to_vec`.
/// 3. Encrypt the JSON bytes with AES-256-GCM: `engine.encrypt()` → `(ciphertext, iv)`.
/// 4. Sign the ciphertext with ML-DSA-65: `engine.dsa_sign()` → `signature`.
/// 5. Compute HMAC-SHA256 over the ciphertext: `engine.hmac()` → `content_hmac`.
/// 6. Build an [`EntryRecord`] with `record_type=0x01`, `legacy_flag=0x00`,
///    `attachment_count=0`, and a random entry padding.
/// 7. Read the vault, append the new record, and write it back.
///
/// # Errors
///
/// Returns [`DiaryError::Io`] on vault I/O failure.
/// Returns [`DiaryError::Entry`] if JSON serialization fails.
/// Returns [`DiaryError::NotUnlocked`] if the engine is locked.
/// Returns [`DiaryError::Crypto`] on encryption or signing failure.
pub fn create_entry(
    vault_path: &Path,
    engine: &CryptoEngine,
    plaintext: &EntryPlaintext,
) -> Result<Uuid, DiaryError> {
    // Step 1: Generate UUID v4.
    let uuid = Uuid::new_v4();

    // Step 2: Serialize EntryPlaintext to JSON bytes (zeroized on drop).
    let json_bytes = Zeroizing::new(
        serde_json::to_vec(plaintext)
            .map_err(|e| DiaryError::Entry(format!("serialization failed: {e}")))?,
    );

    // Step 3: Encrypt.
    let (ciphertext, iv) = engine.encrypt(&json_bytes)?;

    // Step 4: Sign the ciphertext.
    let signature = engine.dsa_sign(&ciphertext)?;

    // Step 5: Compute HMAC over the ciphertext.
    let content_hmac = engine.hmac(&ciphertext)?;

    // Step 6: Capture current Unix timestamp.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| DiaryError::Entry(format!("system time error: {e}")))?
        .as_secs();

    // Step 7: Build EntryRecord.
    let record = EntryRecord {
        record_type: RECORD_TYPE_ENTRY,
        uuid: *uuid.as_bytes(),
        created_at: now,
        updated_at: now,
        iv,
        ciphertext,
        signature,
        content_hmac,
        legacy_flag: 0x00,
        legacy_key_block: vec![],
        attachment_count: 0,
        attachment_offset: 0,
        padding: generate_entry_padding(),
    };

    // Step 8: read-modify-write vault.
    let (header, mut entries) = read_vault(vault_path)?;
    entries.push(record);
    write_vault(vault_path, header, &entries)?;

    Ok(uuid)
}

/// Look up an entry by ID prefix and return the decrypted record and plaintext.
///
/// Processing:
/// 1. Read all [`EntryRecord`]s from the vault.
/// 2. Filter records whose UUID hex starts with `prefix`.
/// 3. Exactly one match:
///    a. Verify `content_hmac` (HMAC-SHA256 over the ciphertext).
///    b. Verify the ML-DSA-65 signature over the ciphertext.
///    c. Decrypt and deserialise.
/// 4. Zero matches: return a "not found" error.
/// 5. Multiple matches: return an error listing candidate UUID hexes.
///
/// # Errors
///
/// Returns [`DiaryError::Io`] on vault I/O failure.
/// Returns [`DiaryError::Crypto`] if HMAC or signature verification fails, or if
///   decryption fails.
/// Returns [`DiaryError::Entry`] if JSON deserialisation fails, no match is
///   found, or multiple matches are found.
/// Returns [`DiaryError::NotUnlocked`] if the engine is locked.
pub fn get_entry(
    vault_path: &Path,
    engine: &CryptoEngine,
    prefix: &IdPrefix,
) -> Result<(EntryRecord, EntryPlaintext), DiaryError> {
    let (_header, records) = read_vault(vault_path)?;

    let mut matches: Vec<EntryRecord> = records
        .into_iter()
        .filter(|r| r.record_type == RECORD_TYPE_ENTRY && prefix.matches(&r.uuid))
        .collect();

    match matches.len() {
        0 => Err(DiaryError::Entry("エントリが見つかりません".to_string())),
        1 => {
            let record = matches.remove(0);
            let uuid_hex: String = record.uuid.iter().map(|b| format!("{:02x}", b)).collect();

            // Verify HMAC over ciphertext before decryption.
            if !engine.hmac_verify(&record.ciphertext, &record.content_hmac)? {
                return Err(DiaryError::Crypto(format!(
                    "content HMAC verification failed for entry {}",
                    uuid_hex
                )));
            }

            // Verify ML-DSA-65 signature over ciphertext (skip if signature is absent).
            if !record.signature.is_empty()
                && !engine.dsa_verify_entry(&record.ciphertext, &record.signature)?
            {
                return Err(DiaryError::Crypto(format!(
                    "signature verification failed for entry {}",
                    uuid_hex
                )));
            }

            let decrypted = engine.decrypt(&record.iv, &record.ciphertext)?;
            let plaintext: EntryPlaintext = serde_json::from_slice(decrypted.as_ref())
                .map_err(|e| DiaryError::Entry(format!("deserialization failed: {e}")))?;
            Ok((record, plaintext))
        }
        _ => {
            let candidates = matches
                .iter()
                .map(|r| {
                    r.uuid
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
                .join(", ");
            Err(DiaryError::Entry(format!(
                "複数のエントリがマッチしました: {}",
                candidates
            )))
        }
    }
}

/// Update an existing entry in the vault.
///
/// Reads the vault, locates the record with the given `uuid`, re-encrypts
/// `plaintext`, updates `ciphertext`, `iv`, `signature`, `content_hmac`, and
/// `updated_at`, then writes the vault back.  `uuid` and `created_at` are
/// preserved unchanged.
///
/// # Errors
///
/// Returns [`DiaryError::Entry`] if no record with `uuid` is found.
/// Returns [`DiaryError::Io`] on vault I/O failure.
/// Returns [`DiaryError::Entry`] if JSON serialisation fails.
/// Returns [`DiaryError::Crypto`] on encryption or signing failure.
/// Returns [`DiaryError::NotUnlocked`] if the engine is locked.
pub fn update_entry(
    vault_path: &Path,
    engine: &CryptoEngine,
    uuid: [u8; 16],
    plaintext: &EntryPlaintext,
) -> Result<(), DiaryError> {
    let (header, mut entries) = read_vault(vault_path)?;

    let record = entries
        .iter_mut()
        .find(|r| r.uuid == uuid)
        .ok_or_else(|| DiaryError::Entry("エントリが見つかりません".to_string()))?;

    let json_bytes = Zeroizing::new(
        serde_json::to_vec(plaintext)
            .map_err(|e| DiaryError::Entry(format!("serialization failed: {e}")))?,
    );

    let (ciphertext, iv) = engine.encrypt(&json_bytes)?;
    let signature = engine.dsa_sign(&ciphertext)?;
    let content_hmac = engine.hmac(&ciphertext)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| DiaryError::Entry(format!("system time error: {e}")))?
        .as_secs();

    record.ciphertext = ciphertext;
    record.iv = iv;
    record.signature = signature;
    record.content_hmac = content_hmac;
    record.updated_at = now;

    write_vault(vault_path, header, &entries)?;
    Ok(())
}

/// Delete an entry from the vault by UUID.
///
/// Reads the vault, removes the record whose `uuid` matches, then writes the
/// vault back (entry padding is re-generated by [`write_vault`]).
///
/// # Errors
///
/// Returns [`DiaryError::Entry`] if no record with `uuid` is found.
/// Returns [`DiaryError::Io`] on vault I/O failure.
pub fn delete_entry(
    vault_path: &Path,
    _engine: &CryptoEngine,
    uuid: [u8; 16],
) -> Result<(), DiaryError> {
    let (header, mut entries) = read_vault(vault_path)?;

    if !entries.iter().any(|r| r.uuid == uuid) {
        return Err(DiaryError::Entry("エントリが見つかりません".to_string()));
    }

    entries.retain(|r| r.uuid != uuid);

    write_vault(vault_path, header, &entries)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // TC-A10-01: EntryPlaintext ZeroizeOnDrop
    // =========================================================================

    /// TC-A10-01: zeroize() clears all fields of EntryPlaintext.
    ///
    /// Uses `ManuallyDrop` to call `zeroize()` while the allocation is still live,
    /// avoiding undefined behavior from reading freed memory.
    #[test]
    fn tc_a10_01_entry_plaintext_zeroize_on_drop() {
        use std::mem::ManuallyDrop;

        let mut pt = ManuallyDrop::new(EntryPlaintext {
            title: "secret title".to_string(),
            tags: vec!["tag1".to_string(), "tag2".to_string()],
            body: "secret body content".to_string(),
        });

        let title_ptr = pt.title.as_ptr();
        let title_len = pt.title.len();
        let body_ptr = pt.body.as_ptr();
        let body_len = pt.body.len();

        pt.zeroize();

        // SAFETY: ManuallyDrop suppresses deallocation; allocations are still live.
        unsafe {
            for i in 0..title_len {
                assert_eq!(*title_ptr.add(i), 0u8, "title byte {i} not zeroed");
            }
            for i in 0..body_len {
                assert_eq!(*body_ptr.add(i), 0u8, "body byte {i} not zeroed");
            }
        }
        // Intentional leak — allocation is small and this is test code.
    }

    // =========================================================================
    // EntryPlaintext serde round-trip
    // =========================================================================

    /// TC-0027-01: ASCII-only round-trip via serde_json.
    #[test]
    fn test_entry_plaintext_serde_roundtrip_ascii() {
        let original = EntryPlaintext {
            title: "Test Entry".to_string(),
            tags: vec!["work".to_string(), "review".to_string()],
            body: "Hello, world!".to_string(),
        };
        let bytes = serde_json::to_vec(&original).expect("serialize");
        let restored: EntryPlaintext = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(original, restored);
    }

    /// TC-0027-02: Unicode (Japanese) round-trip via serde_json.
    #[test]
    fn test_entry_plaintext_serde_roundtrip_unicode() {
        let original = EntryPlaintext {
            title: "日記エントリ".to_string(),
            tags: vec!["仕事".to_string(), "設計/レビュー".to_string()],
            body: "本文テキスト。Markdown対応。".to_string(),
        };
        let bytes = serde_json::to_vec(&original).expect("serialize");
        let restored: EntryPlaintext = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(original, restored);
    }

    // =========================================================================
    // Tag validation — normal cases
    // =========================================================================

    /// TC-0027-03: Japanese unicode tag is accepted.
    #[test]
    fn test_tag_new_japanese() {
        let tag = Tag::new("日記").expect("should be Ok");
        assert_eq!(tag.as_str(), "日記");
    }

    /// TC-0027-04: Nested tag with slashes is accepted.
    #[test]
    fn test_tag_new_nested() {
        let tag = Tag::new("仕事/設計/レビュー").expect("should be Ok");
        assert_eq!(tag.as_str(), "仕事/設計/レビュー");
    }

    /// TC-0027-05: Underscore tag is accepted.
    #[test]
    fn test_tag_new_underscore() {
        let tag = Tag::new("work_log").expect("should be Ok");
        assert_eq!(tag.as_str(), "work_log");
    }

    /// TC-0027-06: Hyphen-containing tag is accepted.
    #[test]
    fn test_tag_new_hyphen() {
        let tag = Tag::new("2024-review").expect("should be Ok");
        assert_eq!(tag.as_str(), "2024-review");
    }

    /// TC-0027-07: Leading and trailing slashes are stripped.
    #[test]
    fn test_tag_new_leading_trailing_slash_stripped() {
        let tag = Tag::new("/日記/").expect("should be Ok");
        assert_eq!(tag.as_str(), "日記");
    }

    // =========================================================================
    // Tag validation — error cases
    // =========================================================================

    /// TC-0027-08: Empty string is rejected.
    #[test]
    fn test_tag_new_empty_is_err() {
        assert!(Tag::new("").is_err());
    }

    /// TC-0027-09: Spaces-only string is rejected.
    #[test]
    fn test_tag_new_spaces_only_is_err() {
        assert!(Tag::new("  ").is_err());
    }

    /// TC-0027-10: String containing a space is rejected.
    #[test]
    fn test_tag_new_contains_space_is_err() {
        assert!(Tag::new("my tag").is_err());
    }

    // =========================================================================
    // IdPrefix validation — normal cases
    // =========================================================================

    /// TC-0027-11: Minimum 4-character hex prefix is accepted.
    #[test]
    fn test_id_prefix_new_min_4() {
        let p = IdPrefix::new("abcd").expect("should be Ok");
        assert_eq!(p.as_str(), "abcd");
    }

    /// TC-0027-12: Full 16-character hex prefix is accepted.
    #[test]
    fn test_id_prefix_new_16_chars() {
        let p = IdPrefix::new("0123456789abcdef").expect("should be Ok");
        assert_eq!(p.as_str(), "0123456789abcdef");
    }

    /// TC-0027-13: Uppercase letters are normalized to lowercase.
    #[test]
    fn test_id_prefix_new_uppercase_normalized() {
        let p = IdPrefix::new("ABCD").expect("should be Ok");
        assert_eq!(p.as_str(), "abcd");
    }

    // =========================================================================
    // IdPrefix validation — error cases
    // =========================================================================

    /// TC-0027-14: 3-character string is rejected with the correct error.
    #[test]
    fn test_id_prefix_new_3_chars_is_err() {
        let err = IdPrefix::new("abc").expect_err("should be Err");
        assert!(matches!(err, DiaryError::InvalidArgument(_)));
    }

    /// TC-0027-15: Non-hex characters are rejected.
    #[test]
    fn test_id_prefix_new_non_hex_is_err() {
        assert!(IdPrefix::new("ghij").is_err());
    }

    /// TC-0027-16: Empty string is rejected.
    #[test]
    fn test_id_prefix_new_empty_is_err() {
        assert!(IdPrefix::new("").is_err());
    }

    // =========================================================================
    // IdPrefix matching
    // =========================================================================

    /// TC-0027-17: First 4 characters of UUID hex match the prefix.
    #[test]
    fn test_id_prefix_matches_prefix_true() {
        let uuid: [u8; 16] = [
            0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7,
            0xf8, 0x09,
        ];
        let prefix = IdPrefix::new("1a2b").expect("valid");
        assert!(prefix.matches(&uuid));
    }

    /// TC-0027-18: Mismatched prefix returns false.
    #[test]
    fn test_id_prefix_matches_prefix_false() {
        let uuid: [u8; 16] = [
            0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7,
            0xf8, 0x09,
        ];
        let prefix = IdPrefix::new("ffff").expect("valid");
        assert!(!prefix.matches(&uuid));
    }

    /// TC-0027-19: Full 32-character UUID hex matches.
    #[test]
    fn test_id_prefix_matches_full_uuid() {
        let uuid: [u8; 16] = [
            0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7,
            0xf8, 0x09,
        ];
        let full = IdPrefix::new("1a2b3c4d5e6f708192a3b4c5d6e7f809").expect("valid");
        assert!(full.matches(&uuid));
    }

    // =========================================================================
    // EntryMeta id_prefix
    // =========================================================================

    /// TC-0027-20: id_prefix truncates and clamps correctly.
    #[test]
    fn test_entry_meta_id_prefix() {
        let meta = EntryMeta {
            uuid_hex: "1a2b3c4d5e6f7081".to_string(),
            title: "Test".to_string(),
            tags: vec![],
            created_at: 0,
            updated_at: 0,
        };
        assert_eq!(meta.id_prefix(4), "1a2b");
        assert_eq!(meta.id_prefix(8), "1a2b3c4d");
        assert_eq!(meta.id_prefix(100), "1a2b3c4d5e6f7081");
    }

    // =========================================================================
    // Tag is_prefix_of
    // =========================================================================

    /// TC-0027-21: is_prefix_of respects hierarchy.
    #[test]
    fn test_tag_is_prefix_of_hierarchy() {
        let parent = Tag::new("仕事").expect("valid");
        let child = Tag::new("仕事/設計").expect("valid");
        let unrelated = Tag::new("仕事人").expect("valid");
        let same = Tag::new("仕事").expect("valid");

        assert!(parent.is_prefix_of(&child));
        assert!(!parent.is_prefix_of(&unrelated));
        assert!(parent.is_prefix_of(&same));
    }

    // =========================================================================
    // TASK-0028: is_prefix_of — exact match
    // =========================================================================

    /// TC-0028-01: Exact match returns true (Japanese).
    #[test]
    fn test_tag_is_prefix_of_exact_japanese() {
        let tag = Tag::new("日記").expect("valid");
        let other = Tag::new("日記").expect("valid");
        assert!(tag.is_prefix_of(&other));
    }

    /// TC-0028-02: Exact match returns true (ASCII).
    #[test]
    fn test_tag_is_prefix_of_exact_ascii() {
        let tag = Tag::new("work").expect("valid");
        let other = Tag::new("work").expect("valid");
        assert!(tag.is_prefix_of(&other));
    }

    // =========================================================================
    // TASK-0028: is_prefix_of — child tag
    // =========================================================================

    /// TC-0028-03: Direct child tag returns true (Japanese).
    #[test]
    fn test_tag_is_prefix_of_child_japanese() {
        let parent = Tag::new("日記").expect("valid");
        let child = Tag::new("日記/振り返り").expect("valid");
        assert!(parent.is_prefix_of(&child));
    }

    /// TC-0028-04: Direct child tag returns true (ASCII).
    #[test]
    fn test_tag_is_prefix_of_child_ascii() {
        let parent = Tag::new("work").expect("valid");
        let child = Tag::new("work/design").expect("valid");
        assert!(parent.is_prefix_of(&child));
    }

    // =========================================================================
    // TASK-0028: is_prefix_of — grandchild tag
    // =========================================================================

    /// TC-0028-05: Grandchild tag returns true.
    #[test]
    fn test_tag_is_prefix_of_grandchild() {
        let grandparent = Tag::new("仕事").expect("valid");
        let grandchild = Tag::new("仕事/設計/レビュー").expect("valid");
        assert!(grandparent.is_prefix_of(&grandchild));
    }

    // =========================================================================
    // TASK-0028: is_prefix_of — non-match (similar strings)
    // =========================================================================

    /// TC-0028-06: Similar Japanese string that is not a hierarchical child returns false.
    #[test]
    fn test_tag_is_prefix_of_similar_japanese_false() {
        let tag = Tag::new("仕事").expect("valid");
        let similar = Tag::new("仕事人").expect("valid");
        assert!(!tag.is_prefix_of(&similar));
    }

    /// TC-0028-07: Similar ASCII string that is not a hierarchical child returns false.
    #[test]
    fn test_tag_is_prefix_of_similar_ascii_false() {
        let tag = Tag::new("work").expect("valid");
        let similar = Tag::new("workflow").expect("valid");
        assert!(!tag.is_prefix_of(&similar));
    }

    /// TC-0028-08: Completely unrelated tag returns false.
    #[test]
    fn test_tag_is_prefix_of_unrelated_false() {
        let tag = Tag::new("日記").expect("valid");
        let other = Tag::new("仕事").expect("valid");
        assert!(!tag.is_prefix_of(&other));
    }

    // =========================================================================
    // TASK-0028: Unicode tag acceptance
    // =========================================================================

    /// TC-0028-09: Mixed Unicode and ASCII tag is accepted.
    #[test]
    fn test_tag_new_unicode_ascii_mixed() {
        let tag = Tag::new("プロジェクト/alpha").expect("should be Ok");
        assert_eq!(tag.as_str(), "プロジェクト/alpha");
    }

    /// TC-0028-10: Unicode tag with numeric suffix is accepted.
    #[test]
    fn test_tag_new_unicode_with_numbers() {
        let tag = Tag::new("日記/2024").expect("should be Ok");
        assert_eq!(tag.as_str(), "日記/2024");
    }

    /// TC-0028-11: Tag with underscore between Unicode characters is accepted.
    #[test]
    fn test_tag_new_unicode_underscore() {
        let tag = Tag::new("感想_メモ").expect("should be Ok");
        assert_eq!(tag.as_str(), "感想_メモ");
    }

    // =========================================================================
    // TASK-0028: Edge cases
    // =========================================================================

    /// TC-0028-12: Slashes-only string is rejected (becomes empty after normalization).
    #[test]
    fn test_tag_new_slashes_only_is_err() {
        assert!(Tag::new("///").is_err());
    }

    /// TC-0028-13: Digits-only string is rejected (Obsidian tag spec).
    #[test]
    fn test_tag_new_digits_only_is_err() {
        assert!(Tag::new("123").is_err());
    }

    /// TC-0028-14: Leading and trailing slash are stripped, yielding the inner segment.
    #[test]
    fn test_tag_new_leading_trailing_slash() {
        let tag = Tag::new("/leading/").expect("should be Ok");
        assert_eq!(tag.as_str(), "leading");
    }

    /// TC-0028-15: Consecutive slashes are normalized to a single slash.
    #[test]
    fn test_tag_new_consecutive_slashes_normalized() {
        let tag = Tag::new("work//design").expect("should be Ok");
        assert_eq!(tag.as_str(), "work/design");
    }

    /// TC-0028-16: Multiple consecutive slashes in nested tag are normalized.
    #[test]
    fn test_tag_new_multiple_consecutive_slashes() {
        let tag = Tag::new("a///b////c").expect("should be Ok");
        assert_eq!(tag.as_str(), "a/b/c");
    }

    // =========================================================================
    // TASK-0029: create_entry
    // =========================================================================

    use crate::{
        crypto::{dsa, CryptoEngine},
        vault::{format::VaultHeader, reader::read_vault, writer::write_vault},
    };
    use tempfile::tempdir;

    /// Build a CryptoEngine with a fresh DSA key pair for testing.
    fn make_test_engine() -> CryptoEngine {
        let kp = dsa::keygen().expect("dsa keygen");
        let sym_key = [0x42u8; 32];
        CryptoEngine::new_for_testing(sym_key, kp.signing_key.as_ref().to_vec())
    }

    /// Write an empty vault to `path`.
    fn init_test_vault(path: &Path) {
        write_vault(path, VaultHeader::new(), &[]).expect("write_vault");
    }

    /// TC-0029-01: create_entry round-trip — create, read back, decrypt, compare.
    #[test]
    fn test_create_entry_roundtrip() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        let plaintext = EntryPlaintext {
            title: "Test Entry".to_string(),
            tags: vec!["work".to_string(), "test".to_string()],
            body: "Hello, world!".to_string(),
        };

        let uuid = create_entry(&vault_path, &engine, &plaintext).expect("create_entry");

        let (_header, entries) = read_vault(&vault_path).expect("read_vault");
        assert_eq!(entries.len(), 1, "expected exactly 1 entry");

        let record = &entries[0];

        // UUID bytes in the record must match the returned UUID.
        assert_eq!(&record.uuid, uuid.as_bytes());

        // Decrypt and deserialize — must match the original plaintext.
        let decrypted = engine
            .decrypt(&record.iv, &record.ciphertext)
            .expect("decrypt");
        let restored: EntryPlaintext =
            serde_json::from_slice(decrypted.as_ref()).expect("from_slice");

        assert_eq!(restored.title, plaintext.title);
        assert_eq!(restored.tags, plaintext.tags);
        assert_eq!(restored.body, plaintext.body);
    }

    /// TC-0029-02: three consecutive create_entry calls produce exactly 3 entries,
    /// each decrypting to the correct plaintext.
    #[test]
    fn test_create_entry_multiple() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        let originals = vec![
            EntryPlaintext {
                title: "Entry 1".to_string(),
                tags: vec!["alpha".to_string()],
                body: "Body 1".to_string(),
            },
            EntryPlaintext {
                title: "Entry 2".to_string(),
                tags: vec!["beta".to_string()],
                body: "Body 2".to_string(),
            },
            EntryPlaintext {
                title: "Entry 3".to_string(),
                tags: vec!["gamma".to_string()],
                body: "Body 3".to_string(),
            },
        ];

        for pt in &originals {
            create_entry(&vault_path, &engine, pt).expect("create_entry");
        }

        let (_header, entries) = read_vault(&vault_path).expect("read_vault");
        assert_eq!(entries.len(), 3, "expected 3 entries");

        for (i, record) in entries.iter().enumerate() {
            let decrypted = engine
                .decrypt(&record.iv, &record.ciphertext)
                .expect("decrypt");
            let restored: EntryPlaintext =
                serde_json::from_slice(decrypted.as_ref()).expect("from_slice");
            assert_eq!(restored, originals[i], "entry {} mismatch", i);
        }
    }

    /// TC-0029-03: UUIDs returned by successive create_entry calls are all distinct.
    #[test]
    fn test_create_entry_uuid_uniqueness() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        let pt = EntryPlaintext {
            title: "UUID test".to_string(),
            tags: vec![],
            body: "body".to_string(),
        };

        let u1 = create_entry(&vault_path, &engine, &pt).expect("create 1");
        let u2 = create_entry(&vault_path, &engine, &pt).expect("create 2");
        let u3 = create_entry(&vault_path, &engine, &pt).expect("create 3");

        assert_ne!(u1, u2, "uuid1 and uuid2 must differ");
        assert_ne!(u2, u3, "uuid2 and uuid3 must differ");
        assert_ne!(u1, u3, "uuid1 and uuid3 must differ");
    }

    // =========================================================================
    // TASK-0030: list_entries
    // =========================================================================

    /// TC-0030-01: list_entries on an empty vault returns an empty Vec.
    #[test]
    fn test_list_entries_empty_vault() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        let metas = list_entries(&vault_path, &engine).expect("list_entries");
        assert!(metas.is_empty(), "expected empty Vec for empty vault");
    }

    /// TC-0030-02: list_entries returns exactly one EntryMeta with correct fields.
    #[test]
    fn test_list_entries_single_entry() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        let plaintext = EntryPlaintext {
            title: "Hello World".to_string(),
            tags: vec!["work".to_string(), "diary".to_string()],
            body: "Some body text.".to_string(),
        };
        let uuid = create_entry(&vault_path, &engine, &plaintext).expect("create_entry");

        let metas = list_entries(&vault_path, &engine).expect("list_entries");
        assert_eq!(metas.len(), 1, "expected exactly 1 meta");

        let meta = &metas[0];
        assert_eq!(meta.title, plaintext.title);
        assert_eq!(meta.tags, plaintext.tags);
        assert_eq!(
            meta.uuid_hex,
            uuid.as_bytes()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );
        assert!(meta.created_at > 0, "created_at must be positive");
        assert!(
            meta.updated_at >= meta.created_at,
            "updated_at must be >= created_at"
        );
    }

    /// TC-0030-03: list_entries returns all 3 entries with correct titles and tags.
    #[test]
    fn test_list_entries_multiple_entries() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        let originals = vec![
            EntryPlaintext {
                title: "First".to_string(),
                tags: vec!["alpha".to_string()],
                body: "Body 1".to_string(),
            },
            EntryPlaintext {
                title: "Second".to_string(),
                tags: vec!["beta".to_string(), "work".to_string()],
                body: "Body 2".to_string(),
            },
            EntryPlaintext {
                title: "Third".to_string(),
                tags: vec![],
                body: "Body 3".to_string(),
            },
        ];

        for pt in &originals {
            create_entry(&vault_path, &engine, pt).expect("create_entry");
        }

        let metas = list_entries(&vault_path, &engine).expect("list_entries");
        assert_eq!(metas.len(), 3, "expected 3 metas");

        for (i, meta) in metas.iter().enumerate() {
            assert_eq!(
                meta.title, originals[i].title,
                "title mismatch at index {}",
                i
            );
            assert_eq!(meta.tags, originals[i].tags, "tags mismatch at index {}", i);
        }
    }

    /// TC-0030-04: Full field validation — uuid_hex length, timestamps, id_prefix.
    #[test]
    fn test_list_entries_full_field_validation() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        let plaintext = EntryPlaintext {
            title: "Validation Test".to_string(),
            tags: vec!["qa".to_string()],
            body: "body".to_string(),
        };
        create_entry(&vault_path, &engine, &plaintext).expect("create_entry");

        let metas = list_entries(&vault_path, &engine).expect("list_entries");
        assert_eq!(metas.len(), 1);

        let meta = &metas[0];

        // uuid_hex must be exactly 32 lowercase hex characters.
        assert_eq!(meta.uuid_hex.len(), 32, "uuid_hex must be 32 chars");
        assert!(
            meta.uuid_hex
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
            "uuid_hex must be lowercase hex"
        );

        // Timestamps must be positive.
        assert!(meta.created_at > 0, "created_at must be > 0");
        assert!(
            meta.updated_at >= meta.created_at,
            "updated_at >= created_at"
        );

        // id_prefix(4) must match the first 4 characters of uuid_hex.
        assert_eq!(meta.id_prefix(4), &meta.uuid_hex[..4]);
    }

    /// TC-0029-04: created_at == updated_at and both fall within the current time window.
    #[test]
    fn test_create_entry_timestamps() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_secs();

        let pt = EntryPlaintext {
            title: "Timestamp test".to_string(),
            tags: vec![],
            body: "body".to_string(),
        };
        create_entry(&vault_path, &engine, &pt).expect("create_entry");

        let after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_secs();

        let (_header, entries) = read_vault(&vault_path).expect("read_vault");
        assert_eq!(entries.len(), 1);

        let record = &entries[0];
        assert_eq!(
            record.created_at, record.updated_at,
            "created_at must equal updated_at"
        );
        assert!(
            record.created_at >= before,
            "created_at ({}) must be >= before ({})",
            record.created_at,
            before
        );
        assert!(
            record.created_at <= after,
            "created_at ({}) must be <= after ({})",
            record.created_at,
            after
        );
    }

    // =========================================================================
    // TASK-0031: get_entry
    // =========================================================================

    /// TC-0031-01: get_entry with a 4-character prefix returns the correct entry.
    #[test]
    fn test_get_entry_unique_match() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        let plaintext = EntryPlaintext {
            title: "Unique Entry".to_string(),
            tags: vec!["test".to_string()],
            body: "Hello, world!".to_string(),
        };
        let uuid = create_entry(&vault_path, &engine, &plaintext).expect("create_entry");

        let uuid_hex: String = uuid
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let prefix = IdPrefix::new(&uuid_hex[..4]).expect("valid prefix");

        let (record, got) = get_entry(&vault_path, &engine, &prefix).expect("get_entry");
        assert_eq!(&record.uuid, uuid.as_bytes());
        assert_eq!(got.title, plaintext.title);
        assert_eq!(got.tags, plaintext.tags);
        assert_eq!(got.body, plaintext.body);
    }

    /// TC-0031-02: get_entry with a non-matching prefix returns DiaryError::Entry
    /// containing "エントリが見つかりません".
    #[test]
    fn test_get_entry_no_match() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        let pt = EntryPlaintext {
            title: "Some Entry".to_string(),
            tags: vec![],
            body: "body".to_string(),
        };
        create_entry(&vault_path, &engine, &pt).expect("create_entry");

        // Force UUID to start with 0x01,0x01 so "ffff" definitely won't match.
        {
            let (header, mut records) = read_vault(&vault_path).expect("read_vault");
            records[0].uuid[0] = 0x01;
            records[0].uuid[1] = 0x01;
            write_vault(&vault_path, header, &records).expect("write_vault");
        }

        let prefix = IdPrefix::new("ffff").expect("valid prefix");
        let err = get_entry(&vault_path, &engine, &prefix).expect_err("should be Err");
        assert!(matches!(err, DiaryError::Entry(_)));
        if let DiaryError::Entry(msg) = err {
            assert!(
                msg.contains("エントリが見つかりません"),
                "expected not-found message, got: {}",
                msg
            );
        }
    }

    /// TC-0031-03: get_entry with a prefix matching two entries returns DiaryError::Entry
    /// listing both candidate UUID hexes.
    #[test]
    fn test_get_entry_multiple_matches() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        let pt = EntryPlaintext {
            title: "Entry".to_string(),
            tags: vec![],
            body: "body".to_string(),
        };
        create_entry(&vault_path, &engine, &pt).expect("create 1");
        create_entry(&vault_path, &engine, &pt).expect("create 2");

        // Force both UUIDs to share hex prefix "0000" but differ afterwards.
        {
            let (header, mut records) = read_vault(&vault_path).expect("read_vault");
            records[0].uuid[0] = 0x00;
            records[0].uuid[1] = 0x00;
            records[0].uuid[2] = 0x01;
            records[1].uuid[0] = 0x00;
            records[1].uuid[1] = 0x00;
            records[1].uuid[2] = 0x02;
            write_vault(&vault_path, header, &records).expect("write_vault");
        }

        let prefix = IdPrefix::new("0000").expect("valid prefix");
        let err = get_entry(&vault_path, &engine, &prefix).expect_err("should be Err");
        assert!(matches!(err, DiaryError::Entry(_)));
        if let DiaryError::Entry(msg) = err {
            assert!(
                msg.contains("複数のエントリがマッチしました"),
                "expected multiple-match message, got: {}",
                msg
            );
            assert!(
                msg.contains("000001"),
                "first candidate UUID should appear, got: {}",
                msg
            );
            assert!(
                msg.contains("000002"),
                "second candidate UUID should appear, got: {}",
                msg
            );
        }
    }

    /// TC-0031-04: get_entry with a full 32-character UUID hex returns the correct entry.
    #[test]
    fn test_get_entry_full_uuid_prefix() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        let plaintext = EntryPlaintext {
            title: "Full UUID test".to_string(),
            tags: vec![],
            body: "exact match".to_string(),
        };
        let uuid = create_entry(&vault_path, &engine, &plaintext).expect("create_entry");

        let full_hex: String = uuid
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        assert_eq!(full_hex.len(), 32, "UUID hex must be 32 chars");

        let prefix = IdPrefix::new(&full_hex).expect("valid 32-char prefix");
        let (_record, got) = get_entry(&vault_path, &engine, &prefix).expect("get_entry");
        assert_eq!(got.title, plaintext.title);
        assert_eq!(got.body, plaintext.body);
    }

    // =========================================================================
    // TASK-0032: update_entry
    // =========================================================================

    /// TC-0032-01: update_entry reflects a changed title.
    #[test]
    fn test_update_entry_title() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        let original = EntryPlaintext {
            title: "Original Title".to_string(),
            tags: vec!["work".to_string()],
            body: "body".to_string(),
        };
        let uuid = create_entry(&vault_path, &engine, &original).expect("create_entry");

        let updated = EntryPlaintext {
            title: "Updated Title".to_string(),
            tags: original.tags.clone(),
            body: original.body.clone(),
        };
        update_entry(&vault_path, &engine, *uuid.as_bytes(), &updated).expect("update_entry");

        let prefix = IdPrefix::new(
            &uuid
                .as_bytes()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),
        )
        .expect("valid prefix");
        let (_record, got) = get_entry(&vault_path, &engine, &prefix).expect("get_entry");
        assert_eq!(got.title, "Updated Title");
    }

    /// TC-0032-02: update_entry reflects changed tags.
    #[test]
    fn test_update_entry_tags() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        let original = EntryPlaintext {
            title: "Tag Test".to_string(),
            tags: vec!["old-tag".to_string()],
            body: "body".to_string(),
        };
        let uuid = create_entry(&vault_path, &engine, &original).expect("create_entry");

        let updated = EntryPlaintext {
            title: original.title.clone(),
            tags: vec!["new-tag".to_string(), "extra".to_string()],
            body: original.body.clone(),
        };
        update_entry(&vault_path, &engine, *uuid.as_bytes(), &updated).expect("update_entry");

        let prefix = IdPrefix::new(
            &uuid
                .as_bytes()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),
        )
        .expect("valid prefix");
        let (_record, got) = get_entry(&vault_path, &engine, &prefix).expect("get_entry");
        assert_eq!(got.tags, vec!["new-tag".to_string(), "extra".to_string()]);
    }

    /// TC-0032-03: update_entry reflects a changed body.
    #[test]
    fn test_update_entry_body() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        let original = EntryPlaintext {
            title: "Body Test".to_string(),
            tags: vec![],
            body: "original body".to_string(),
        };
        let uuid = create_entry(&vault_path, &engine, &original).expect("create_entry");

        let updated = EntryPlaintext {
            title: original.title.clone(),
            tags: original.tags.clone(),
            body: "updated body".to_string(),
        };
        update_entry(&vault_path, &engine, *uuid.as_bytes(), &updated).expect("update_entry");

        let prefix = IdPrefix::new(
            &uuid
                .as_bytes()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>(),
        )
        .expect("valid prefix");
        let (_record, got) = get_entry(&vault_path, &engine, &prefix).expect("get_entry");
        assert_eq!(got.body, "updated body");
    }

    /// TC-0032-04: update_entry preserves created_at; updated_at >= created_at.
    #[test]
    fn test_update_entry_preserves_created_at() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        let original = EntryPlaintext {
            title: "Timestamp Test".to_string(),
            tags: vec![],
            body: "body".to_string(),
        };
        let uuid = create_entry(&vault_path, &engine, &original).expect("create_entry");

        // Record created_at before update.
        let (_, entries_before) = read_vault(&vault_path).expect("read_vault");
        let created_at_before = entries_before[0].created_at;

        let updated = EntryPlaintext {
            title: "Updated".to_string(),
            tags: vec![],
            body: "updated body".to_string(),
        };
        update_entry(&vault_path, &engine, *uuid.as_bytes(), &updated).expect("update_entry");

        let (_, entries_after) = read_vault(&vault_path).expect("read_vault");
        let record = &entries_after[0];
        assert_eq!(
            record.created_at, created_at_before,
            "created_at must not change"
        );
        assert!(
            record.updated_at >= record.created_at,
            "updated_at must be >= created_at"
        );
    }

    /// TC-0032-05: update_entry with a nonexistent UUID returns DiaryError::Entry.
    #[test]
    fn test_update_entry_not_found() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        let pt = EntryPlaintext {
            title: "Nonexistent".to_string(),
            tags: vec![],
            body: "body".to_string(),
        };
        let nonexistent_uuid = [0xffu8; 16];
        let err =
            update_entry(&vault_path, &engine, nonexistent_uuid, &pt).expect_err("should be Err");
        assert!(matches!(err, DiaryError::Entry(_)));
    }

    // =========================================================================
    // TASK-0032: delete_entry
    // =========================================================================

    /// TC-0032-06: delete_entry removes the entry; list shows 1 remaining; get returns error.
    #[test]
    fn test_delete_entry_removes_entry() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        let pt1 = EntryPlaintext {
            title: "Keep".to_string(),
            tags: vec![],
            body: "keep body".to_string(),
        };
        let pt2 = EntryPlaintext {
            title: "Delete".to_string(),
            tags: vec![],
            body: "delete body".to_string(),
        };
        let _uuid1 = create_entry(&vault_path, &engine, &pt1).expect("create 1");
        let uuid2 = create_entry(&vault_path, &engine, &pt2).expect("create 2");

        delete_entry(&vault_path, &engine, *uuid2.as_bytes()).expect("delete_entry");

        // list should show exactly 1 entry.
        let metas = list_entries(&vault_path, &engine).expect("list_entries");
        assert_eq!(metas.len(), 1, "expected 1 entry after deletion");
        assert_eq!(metas[0].title, "Keep");

        // get_entry on deleted UUID should return an error.
        let full_hex: String = uuid2
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let prefix = IdPrefix::new(&full_hex).expect("valid prefix");
        let err = get_entry(&vault_path, &engine, &prefix).expect_err("should be Err");
        assert!(matches!(err, DiaryError::Entry(_)));
    }

    /// TC-0032-07: delete_entry with a nonexistent UUID returns DiaryError::Entry.
    #[test]
    fn test_delete_entry_not_found() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        let nonexistent_uuid = [0xffu8; 16];
        let err = delete_entry(&vault_path, &engine, nonexistent_uuid).expect_err("should be Err");
        assert!(matches!(err, DiaryError::Entry(_)));
    }

    // =========================================================================
    // TASK-0082: 読み取り時 HMAC / 署名検証
    // =========================================================================

    /// Helper: build an IdPrefix from the first 8 hex chars of a Uuid.
    fn prefix_from_uuid(uuid: &uuid::Uuid) -> IdPrefix {
        let hex: String = uuid
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        IdPrefix::new(&hex[..8]).expect("valid prefix")
    }

    /// TC-S9-082-01: get_entry with a valid entry (correct HMAC and signature) succeeds.
    #[test]
    fn tc_s9_082_01_get_entry_valid_hmac_and_sig() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        let plaintext = EntryPlaintext {
            title: "Integrity Test".to_string(),
            tags: vec!["security".to_string()],
            body: "body text".to_string(),
        };
        let uuid = create_entry(&vault_path, &engine, &plaintext).expect("create_entry");
        let prefix = prefix_from_uuid(&uuid);

        let (_record, recovered) =
            get_entry(&vault_path, &engine, &prefix).expect("get_entry must succeed");
        assert_eq!(recovered.title, plaintext.title);
        assert_eq!(recovered.body, plaintext.body);
    }

    /// TC-S9-082-02: get_entry with a tampered ciphertext returns DiaryError::Crypto
    /// containing "content HMAC verification failed".
    #[test]
    fn tc_s9_082_02_get_entry_tampered_ciphertext_hmac_error() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        let plaintext = EntryPlaintext {
            title: "Tamper Ciphertext".to_string(),
            tags: vec![],
            body: "original body".to_string(),
        };
        let uuid = create_entry(&vault_path, &engine, &plaintext).expect("create_entry");

        // Tamper the ciphertext: flip a byte to invalidate the HMAC.
        {
            let (header, mut records) = read_vault(&vault_path).expect("read_vault");
            if let Some(b) = records[0].ciphertext.get_mut(5) {
                *b ^= 0xFF;
            }
            write_vault(&vault_path, header, &records).expect("write_vault");
        }

        let prefix = prefix_from_uuid(&uuid);
        let err = get_entry(&vault_path, &engine, &prefix).expect_err("must fail");
        assert!(
            matches!(err, DiaryError::Crypto(_)),
            "expected DiaryError::Crypto, got {:?}",
            err
        );
        if let DiaryError::Crypto(msg) = err {
            assert!(
                msg.contains("content HMAC verification failed"),
                "error message must mention HMAC failure, got: {}",
                msg
            );
        }
    }

    /// TC-S9-082-03: get_entry with a tampered signature returns DiaryError::Crypto
    /// containing "signature verification failed".
    #[test]
    fn tc_s9_082_03_get_entry_tampered_signature_error() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        let plaintext = EntryPlaintext {
            title: "Tamper Signature".to_string(),
            tags: vec![],
            body: "body text".to_string(),
        };
        let uuid = create_entry(&vault_path, &engine, &plaintext).expect("create_entry");

        // Tamper the signature: flip a byte (ciphertext is unchanged so HMAC passes).
        {
            let (header, mut records) = read_vault(&vault_path).expect("read_vault");
            if let Some(b) = records[0].signature.get_mut(100) {
                *b ^= 0xFF;
            }
            write_vault(&vault_path, header, &records).expect("write_vault");
        }

        let prefix = prefix_from_uuid(&uuid);
        let err = get_entry(&vault_path, &engine, &prefix).expect_err("must fail");
        assert!(
            matches!(err, DiaryError::Crypto(_)),
            "expected DiaryError::Crypto, got {:?}",
            err
        );
        if let DiaryError::Crypto(msg) = err {
            assert!(
                msg.contains("signature verification failed"),
                "error message must mention signature failure, got: {}",
                msg
            );
        }
    }

    /// TC-S9-082-04: list_entries_with_body with all valid entries returns every entry.
    #[test]
    fn tc_s9_082_04_list_entries_with_body_all_valid() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        let originals = [("Alpha", "body A"), ("Beta", "body B"), ("Gamma", "body C")];
        for (title, body) in &originals {
            let pt = EntryPlaintext {
                title: title.to_string(),
                tags: vec![],
                body: body.to_string(),
            };
            create_entry(&vault_path, &engine, &pt).expect("create_entry");
        }

        let entries = list_entries_with_body(&vault_path, &engine).expect("list_entries_with_body");
        assert_eq!(entries.len(), 3, "expected 3 entries");
        for (meta, body) in &entries {
            let found = originals
                .iter()
                .any(|(t, b)| *t == meta.title && *b == body.as_str());
            assert!(found, "unexpected entry: title={}", meta.title);
        }
    }

    /// TC-S9-082-05: list_entries_with_body with one tampered ciphertext returns DiaryError::Crypto.
    #[test]
    fn tc_s9_082_05_list_entries_with_body_tampered_entry_error() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        for i in 0..3 {
            let pt = EntryPlaintext {
                title: format!("Entry {i}"),
                tags: vec![],
                body: format!("body {i}"),
            };
            create_entry(&vault_path, &engine, &pt).expect("create_entry");
        }

        // Tamper the second entry's ciphertext.
        {
            let (header, mut records) = read_vault(&vault_path).expect("read_vault");
            if let Some(b) = records[1].ciphertext.get_mut(5) {
                *b ^= 0xFF;
            }
            write_vault(&vault_path, header, &records).expect("write_vault");
        }

        let err = match list_entries_with_body(&vault_path, &engine) {
            Ok(_) => panic!("list_entries_with_body must fail on tampered entry"),
            Err(e) => e,
        };
        assert!(
            matches!(err, DiaryError::Crypto(_)),
            "expected DiaryError::Crypto, got {:?}",
            err
        );
    }

    /// TC-S9-082-07: list_entries (metadata only) skips HMAC/signature verification
    /// and returns metadata normally.
    #[test]
    fn tc_s9_082_07_list_entries_metadata_skips_verification() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        let pt = EntryPlaintext {
            title: "Metadata Only".to_string(),
            tags: vec!["tag1".to_string()],
            body: "some body".to_string(),
        };
        create_entry(&vault_path, &engine, &pt).expect("create_entry");

        // list_entries must succeed and return the metadata.
        let metas = list_entries(&vault_path, &engine).expect("list_entries must succeed");
        assert_eq!(metas.len(), 1, "expected 1 meta");
        assert_eq!(metas[0].title, pt.title);
        assert_eq!(metas[0].tags, pt.tags);
    }

    /// TC-S9-082-08: create → get_entry round-trip still passes after adding verification.
    #[test]
    fn tc_s9_082_08_create_read_roundtrip_passes_verification() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        let plaintext = EntryPlaintext {
            title: "Roundtrip".to_string(),
            tags: vec!["integrity".to_string()],
            body: "intact body".to_string(),
        };
        let uuid = create_entry(&vault_path, &engine, &plaintext).expect("create_entry");
        let prefix = prefix_from_uuid(&uuid);

        let (_record, recovered) =
            get_entry(&vault_path, &engine, &prefix).expect("get_entry must succeed");
        assert_eq!(recovered.title, plaintext.title);
        assert_eq!(recovered.tags, plaintext.tags);
        assert_eq!(recovered.body, plaintext.body);
    }

    /// TC-S9-082-09: HMAC mismatch error message contains the entry UUID.
    #[test]
    fn tc_s9_082_09_hmac_error_message_contains_uuid() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        let pt = EntryPlaintext {
            title: "UUID in Error".to_string(),
            tags: vec![],
            body: "body".to_string(),
        };
        let uuid = create_entry(&vault_path, &engine, &pt).expect("create_entry");
        let uuid_hex: String = uuid
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        // Tamper ciphertext to trigger HMAC failure.
        {
            let (header, mut records) = read_vault(&vault_path).expect("read_vault");
            if let Some(b) = records[0].ciphertext.get_mut(3) {
                *b ^= 0xAB;
            }
            write_vault(&vault_path, header, &records).expect("write_vault");
        }

        let prefix = prefix_from_uuid(&uuid);
        let err = get_entry(&vault_path, &engine, &prefix).expect_err("must fail");
        if let DiaryError::Crypto(msg) = err {
            assert!(
                msg.contains(&uuid_hex),
                "error message must contain the UUID hex, got: {}",
                msg
            );
        } else {
            panic!("expected DiaryError::Crypto");
        }
    }

    /// TC-S9-082-10: Signature verification failure error message contains the entry UUID.
    #[test]
    fn tc_s9_082_10_signature_error_message_contains_uuid() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        let pt = EntryPlaintext {
            title: "UUID in Sig Error".to_string(),
            tags: vec![],
            body: "body".to_string(),
        };
        let uuid = create_entry(&vault_path, &engine, &pt).expect("create_entry");
        let uuid_hex: String = uuid
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        // Tamper signature to trigger signature verification failure.
        {
            let (header, mut records) = read_vault(&vault_path).expect("read_vault");
            if let Some(b) = records[0].signature.get_mut(50) {
                *b ^= 0xDE;
            }
            write_vault(&vault_path, header, &records).expect("write_vault");
        }

        let prefix = prefix_from_uuid(&uuid);
        let err = get_entry(&vault_path, &engine, &prefix).expect_err("must fail");
        if let DiaryError::Crypto(msg) = err {
            assert!(
                msg.contains(&uuid_hex),
                "error message must contain the UUID hex, got: {}",
                msg
            );
        } else {
            panic!("expected DiaryError::Crypto");
        }
    }
}
