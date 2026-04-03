//! Entry CRUD foundational types and operations.
//!
//! Provides [`EntryPlaintext`], [`EntryMeta`], [`Tag`], and [`IdPrefix`] types,
//! along with [`create_entry`] and other CRUD functions implemented in Sprint 4.

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
use zeroize::Zeroizing;

/// Entry plaintext payload serialized before AES-256-GCM encryption.
///
/// Encryption flow:
/// `EntryPlaintext` → `serde_json::to_vec()` → `CryptoEngine::encrypt()` → `EntryRecord.ciphertext`
///
/// Decryption flow:
/// `EntryRecord.ciphertext` → `CryptoEngine::decrypt()` → `serde_json::from_slice()` → `EntryPlaintext`
#[derive(Debug, Serialize, Deserialize, PartialEq)]
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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(record.created_at, record.updated_at, "created_at must equal updated_at");
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
}
