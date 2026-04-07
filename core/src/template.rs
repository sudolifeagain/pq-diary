//! Template CRUD operations.
//!
//! Provides [`TemplatePlaintext`], [`TemplateMeta`], and [`TemplateName`] types,
//! along with [`create_template`], [`list_templates`], [`get_template`], and
//! [`delete_template`] functions implemented in Sprint 5.
//!
//! Templates are stored as [`RECORD_TYPE_TEMPLATE`] (0x02) records in `vault.pqd`,
//! using the same encryption pipeline as journal entries.

use crate::{
    crypto::CryptoEngine,
    error::DiaryError,
    vault::{
        format::{generate_entry_padding, EntryRecord, RECORD_TYPE_TEMPLATE},
        reader::read_vault,
        writer::write_vault,
    },
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Template plaintext payload serialized before AES-256-GCM encryption.
///
/// Encryption flow:
/// `TemplatePlaintext` → `serde_json::to_vec()` → `CryptoEngine::encrypt()` → `EntryRecord.ciphertext`
///
/// Decryption flow:
/// `EntryRecord.ciphertext` → `CryptoEngine::decrypt()` → `serde_json::from_slice()` → `TemplatePlaintext`
///
/// The struct derives `Zeroize` and `ZeroizeOnDrop` because template content
/// is considered secret data that must be erased from memory when no longer needed.
#[derive(Debug, Serialize, Deserialize, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct TemplatePlaintext {
    /// Template name (unique identifier within a vault).
    pub name: String,
    /// Template body text (Markdown, may contain `{{var_name}}` variables).
    pub body: String,
}

/// Template metadata for list display.
///
/// Lightweight struct containing only the fields needed for the `template list` command.
/// The body is excluded as it is not needed for list operations.
pub struct TemplateMeta {
    /// UUID in hex format (32 characters, no dashes).
    pub uuid_hex: String,
    /// Template name.
    pub name: String,
    /// Creation time (Unix timestamp seconds).
    pub created_at: u64,
    /// Last update time (Unix timestamp seconds).
    pub updated_at: u64,
}

/// Validated template name.
///
/// Rules:
/// - 1 to 128 characters (inclusive).
/// - Must not contain space characters.
/// - Must not be empty.
#[derive(Debug)]
pub struct TemplateName(String);

impl TemplateName {
    /// Validates a string as a template name.
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::InvalidTemplateName`] if:
    /// - The string is empty.
    /// - The string exceeds 128 characters.
    /// - The string contains a space character.
    pub fn new(s: &str) -> Result<Self, DiaryError> {
        if s.is_empty() {
            return Err(DiaryError::InvalidTemplateName(
                "template name must not be empty".to_string(),
            ));
        }
        if s.chars().count() > 128 {
            return Err(DiaryError::InvalidTemplateName(
                "template name must not exceed 128 characters".to_string(),
            ));
        }
        if s.contains(' ') {
            return Err(DiaryError::InvalidTemplateName(
                "template name must not contain spaces".to_string(),
            ));
        }
        Ok(TemplateName(s.to_string()))
    }

    /// Returns a reference to the inner validated string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// =============================================================================
// CRUD functions
// =============================================================================

/// Create a new template in the vault and return its UUID.
///
/// Processing pipeline:
/// 1. Generate a UUID v4.
/// 2. Serialize `template` to JSON bytes via `serde_json::to_vec`.
/// 3. Encrypt the JSON bytes with AES-256-GCM: `engine.encrypt()` → `(ciphertext, iv)`.
/// 4. Sign the ciphertext with ML-DSA-65: `engine.dsa_sign()` → `signature`.
/// 5. Compute HMAC-SHA256 over the ciphertext: `engine.hmac()` → `content_hmac`.
/// 6. Build an [`EntryRecord`] with `record_type=0x02`.
/// 7. Read the vault, append the new record, and write it back.
///
/// # Errors
///
/// Returns [`DiaryError::Io`] on vault I/O failure.
/// Returns [`DiaryError::Template`] if JSON serialization fails.
/// Returns [`DiaryError::Crypto`] on encryption or signing failure.
pub fn create_template(
    vault_path: &Path,
    engine: &CryptoEngine,
    template: &TemplatePlaintext,
) -> Result<Uuid, DiaryError> {
    let uuid = Uuid::new_v4();

    let json_bytes = Zeroizing::new(
        serde_json::to_vec(template)
            .map_err(|e| DiaryError::Template(format!("serialization failed: {e}")))?,
    );

    let (ciphertext, iv) = engine.encrypt(&json_bytes)?;
    let signature = engine.dsa_sign(&ciphertext)?;
    let content_hmac = engine.hmac(&ciphertext)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| DiaryError::Template(format!("system time error: {e}")))?
        .as_secs();

    let record = EntryRecord {
        record_type: RECORD_TYPE_TEMPLATE,
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

    let (header, mut records) = read_vault(vault_path)?;
    records.push(record);
    write_vault(vault_path, header, &records)?;

    Ok(uuid)
}

/// List all templates in the vault and return their metadata.
///
/// Reads every [`EntryRecord`] from the vault, filters to `record_type == 0x02`,
/// decrypts each one, deserialises the JSON payload into [`TemplatePlaintext`],
/// and returns a flat [`Vec<TemplateMeta>`].
///
/// # Errors
///
/// Returns [`DiaryError::Io`] on vault I/O failure.
/// Returns [`DiaryError::Crypto`] if decryption fails for any template record.
/// Returns [`DiaryError::Template`] if JSON deserialisation fails for any record.
pub fn list_templates(
    vault_path: &Path,
    engine: &CryptoEngine,
) -> Result<Vec<TemplateMeta>, DiaryError> {
    let (_header, records) = read_vault(vault_path)?;
    let mut metas = Vec::new();
    for record in records {
        if record.record_type != RECORD_TYPE_TEMPLATE {
            continue;
        }
        let decrypted = engine.decrypt(&record.iv, &record.ciphertext)?;
        let plaintext: TemplatePlaintext = serde_json::from_slice(decrypted.as_ref())
            .map_err(|e| DiaryError::Template(format!("deserialization failed: {e}")))?;
        let uuid_hex: String = record.uuid.iter().map(|b| format!("{:02x}", b)).collect();
        metas.push(TemplateMeta {
            uuid_hex,
            name: plaintext.name.clone(),
            created_at: record.created_at,
            updated_at: record.updated_at,
        });
    }
    Ok(metas)
}

/// Look up a template by name and return the decrypted plaintext.
///
/// Scans all `RECORD_TYPE_TEMPLATE` records, decrypts each one, and returns
/// the first record whose name matches `name`.
///
/// # Errors
///
/// Returns [`DiaryError::TemplateNotFound`] if no template with the given name exists.
/// Returns [`DiaryError::Io`] on vault I/O failure.
/// Returns [`DiaryError::Crypto`] if decryption fails.
/// Returns [`DiaryError::Template`] if JSON deserialisation fails.
pub fn get_template(
    vault_path: &Path,
    engine: &CryptoEngine,
    name: &str,
) -> Result<TemplatePlaintext, DiaryError> {
    let (_header, records) = read_vault(vault_path)?;
    for record in records {
        if record.record_type != RECORD_TYPE_TEMPLATE {
            continue;
        }
        let decrypted = engine.decrypt(&record.iv, &record.ciphertext)?;
        let plaintext: TemplatePlaintext = serde_json::from_slice(decrypted.as_ref())
            .map_err(|e| DiaryError::Template(format!("deserialization failed: {e}")))?;
        if plaintext.name == name {
            return Ok(plaintext);
        }
    }
    Err(DiaryError::TemplateNotFound(name.to_string()))
}

/// Delete a template from the vault by name.
///
/// Reads the vault, finds the `RECORD_TYPE_TEMPLATE` record whose decrypted name
/// matches `name`, removes it, and writes the vault back.
///
/// # Errors
///
/// Returns [`DiaryError::TemplateNotFound`] if no template with the given name exists.
/// Returns [`DiaryError::Io`] on vault I/O failure.
/// Returns [`DiaryError::Crypto`] if decryption fails.
/// Returns [`DiaryError::Template`] if JSON deserialisation fails.
pub fn delete_template(
    vault_path: &Path,
    engine: &CryptoEngine,
    name: &str,
) -> Result<(), DiaryError> {
    let (header, mut records) = read_vault(vault_path)?;

    let mut target_uuid: Option<[u8; 16]> = None;
    for record in &records {
        if record.record_type != RECORD_TYPE_TEMPLATE {
            continue;
        }
        let decrypted = engine.decrypt(&record.iv, &record.ciphertext)?;
        let plaintext: TemplatePlaintext = serde_json::from_slice(decrypted.as_ref())
            .map_err(|e| DiaryError::Template(format!("deserialization failed: {e}")))?;
        if plaintext.name == name {
            target_uuid = Some(record.uuid);
            break;
        }
    }

    let uuid = target_uuid.ok_or_else(|| DiaryError::TemplateNotFound(name.to_string()))?;
    records.retain(|r| r.uuid != uuid);
    write_vault(vault_path, header, &records)?;
    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{dsa, CryptoEngine},
        entry::{create_entry, list_entries, EntryPlaintext},
        vault::{format::VaultHeader, writer::write_vault},
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

    // =========================================================================
    // TC-042-01: テンプレート作成・復号ラウンドトリップ
    // =========================================================================

    /// TC-042-01: create → list → get round-trip preserves name and body.
    #[test]
    fn tc_042_01_create_list_get_roundtrip() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        let template = TemplatePlaintext {
            name: "daily".to_string(),
            body: "## {{date}}".to_string(),
        };

        create_template(&vault_path, &engine, &template).expect("create_template");

        let metas = list_templates(&vault_path, &engine).expect("list_templates");
        assert_eq!(metas.len(), 1, "expected 1 template");
        assert_eq!(metas[0].name, "daily");

        let got = get_template(&vault_path, &engine, "daily").expect("get_template");
        assert_eq!(got.name, template.name);
        assert_eq!(got.body, template.body);
    }

    // =========================================================================
    // TC-042-02: テンプレート名バリデーション
    // =========================================================================

    /// TC-042-02: empty, over-128-char, and space-containing names are rejected.
    #[test]
    fn tc_042_02_template_name_validation() {
        // Empty string
        let err = TemplateName::new("").expect_err("empty must fail");
        assert!(matches!(err, DiaryError::InvalidTemplateName(_)));

        // 129-character string (exceeds 128 limit)
        let long_name = "a".repeat(129);
        let err = TemplateName::new(&long_name).expect_err("129-char must fail");
        assert!(matches!(err, DiaryError::InvalidTemplateName(_)));

        // String containing a space
        let err = TemplateName::new("has space").expect_err("space must fail");
        assert!(matches!(err, DiaryError::InvalidTemplateName(_)));

        // Exactly 128 characters should succeed
        let ok_name = "a".repeat(128);
        let name = TemplateName::new(&ok_name).expect("128-char must succeed");
        assert_eq!(name.as_str().len(), 128);

        // Single character should succeed
        TemplateName::new("x").expect("single char must succeed");
    }

    // =========================================================================
    // TC-042-03: 存在しないテンプレートのget
    // =========================================================================

    /// TC-042-03: get_template on a vault with no templates returns TemplateNotFound.
    #[test]
    fn tc_042_03_get_nonexistent_returns_not_found() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        let err = get_template(&vault_path, &engine, "nonexistent").expect_err("must fail");
        assert!(
            matches!(err, DiaryError::TemplateNotFound(ref n) if n == "nonexistent"),
            "expected TemplateNotFound(\"nonexistent\"), got {:?}",
            err
        );
    }

    // =========================================================================
    // TC-042-04: テンプレート削除
    // =========================================================================

    /// TC-042-04: delete_template removes the template; list returns empty.
    #[test]
    fn tc_042_04_delete_template() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        let template = TemplatePlaintext {
            name: "daily".to_string(),
            body: "## {{date}}".to_string(),
        };
        create_template(&vault_path, &engine, &template).expect("create_template");

        delete_template(&vault_path, &engine, "daily").expect("delete_template");

        let metas = list_templates(&vault_path, &engine).expect("list_templates");
        assert!(metas.is_empty(), "list must be empty after delete");
    }

    // =========================================================================
    // TC-042-05: TemplatePlaintext の zeroize 検証
    // =========================================================================

    /// TC-042-05: zeroize() clears all fields of TemplatePlaintext.
    ///
    /// Uses `ManuallyDrop` to call `zeroize()` while the allocation is still live,
    /// avoiding undefined behavior from reading freed memory.
    #[test]
    fn tc_042_05_template_plaintext_zeroize() {
        use std::mem::ManuallyDrop;

        let mut t = ManuallyDrop::new(TemplatePlaintext {
            name: "daily".to_string(),
            body: "## {{date}}".to_string(),
        });

        let name_ptr = t.name.as_ptr();
        let name_len = t.name.len();
        let body_ptr = t.body.as_ptr();
        let body_len = t.body.len();

        t.zeroize();

        // SAFETY: ManuallyDrop suppresses deallocation; allocations are still live.
        unsafe {
            for i in 0..name_len {
                assert_eq!(*name_ptr.add(i), 0u8, "name byte {i} not zeroed");
            }
            for i in 0..body_len {
                assert_eq!(*body_ptr.add(i), 0u8, "body byte {i} not zeroed");
            }
        }
        // Intentional leak — allocation is small and this is test code.
    }

    // =========================================================================
    // TC-042-06: エントリとテンプレートの共存
    // =========================================================================

    /// TC-042-06: entries and templates coexist; list_templates and list_entries
    /// each return only their respective record type.
    #[test]
    fn tc_042_06_entries_and_templates_coexist() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        // Create 3 entries
        for i in 0..3u8 {
            let plaintext = EntryPlaintext {
                title: format!("entry-{i}"),
                tags: vec![],
                body: format!("body {i}"),
            };
            create_entry(&vault_path, &engine, &plaintext).expect("create_entry");
        }

        // Create 2 templates
        for i in 0..2u8 {
            let template = TemplatePlaintext {
                name: format!("tpl-{i}"),
                body: format!("## template {i}"),
            };
            create_template(&vault_path, &engine, &template).expect("create_template");
        }

        let templates = list_templates(&vault_path, &engine).expect("list_templates");
        assert_eq!(templates.len(), 2, "expected 2 templates");

        let entries = list_entries(&vault_path, &engine).expect("list_entries");
        assert_eq!(entries.len(), 3, "expected 3 entries");
    }

    // =========================================================================
    // delete_template: not found
    // =========================================================================

    /// Deleting a non-existent template returns TemplateNotFound.
    #[test]
    fn tc_042_delete_nonexistent_returns_not_found() {
        let dir = tempdir().expect("tempdir");
        let vault_path = dir.path().join("vault.pqd");
        let engine = make_test_engine();
        init_test_vault(&vault_path);

        let err = delete_template(&vault_path, &engine, "ghost").expect_err("must fail");
        assert!(matches!(err, DiaryError::TemplateNotFound(_)));
    }
}
