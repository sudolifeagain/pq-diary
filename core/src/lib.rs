//! pq-diary-core — domain library for the post-quantum cryptography journal.
//!
//! This crate provides the core types and logic for pq-diary:
//! - [`DiaryError`]: unified error type for all operations
//! - [`SecureBuffer`]: zeroize-on-drop byte buffer for secret data
//! - [`DiaryCore`]: top-level API facade for vault lifecycle and entry operations
//!
//! Platform-dependent I/O (terminal, OS APIs) lives in the `cli/` crate only.

use std::path::PathBuf;

use secrecy::ExposeSecret;

/// Secure memory types: [`SecureBuffer`], [`ZeroizingKey`], [`MasterKey`], [`CryptoEngine`].
pub mod crypto;
/// Entry CRUD operations (implemented in Sprint 4).
pub mod entry;
/// Unified error type: [`DiaryError`].
pub mod error;
/// Git synchronisation operations (implemented in Sprint 8).
pub mod git;
/// Digital-legacy operations (implemented in Phase 2).
pub mod legacy;
/// `[[title]]` wiki-link parser (implemented in Sprint 5).
pub mod link;
/// Access-policy evaluation (implemented in Sprint 7).
pub mod policy;
/// Full-text regex search across vault entries (implemented in Sprint 6).
pub mod search;
/// Vault-wide statistics collection (implemented in Sprint 6).
pub mod stats;
/// Template CRUD operations (implemented in Sprint 5).
pub mod template;
/// Template variable extraction and expansion engine (implemented in Sprint 5).
pub mod template_engine;
/// Vault format read/write operations (implemented in Sprint 3).
pub mod vault;

/// Re-exported for convenience: see [`crypto::SecureBuffer`].
pub use crypto::SecureBuffer;
/// Re-exported entry types for external crate use.
pub use entry::{EntryMeta, EntryPlaintext, IdPrefix, Tag};
/// Re-exported for convenience: see [`error::DiaryError`].
pub use error::DiaryError;
/// Re-exported link types for external crate use.
pub use link::{BacklinkEntry, LinkIndex, ResolvedLink};
/// Re-exported template types for external crate use.
pub use template::{TemplateMeta, TemplateName, TemplatePlaintext};
/// Re-exported vault format type for external crate use.
pub use vault::format::EntryRecord;

/// Top-level facade for pq-diary-core.
///
/// Manages the lifecycle of a single vault: [`new`](DiaryCore::new) loads
/// configuration from `vault.toml`, [`unlock`](DiaryCore::unlock) derives the
/// master key and initialises the [`crypto::CryptoEngine`], and
/// [`lock`](DiaryCore::lock) securely erases the key material.
///
/// Entry operations (`new_entry`, `list_entries`, `get_entry`, `update_entry`,
/// `delete_entry`) require the vault to be unlocked and delegate to the
/// corresponding functions in the [`entry`] module.
pub struct DiaryCore {
    /// Path to the `vault.pqd` binary file.
    vault_path: PathBuf,
    /// Cryptographic engine; `None` when locked, `Some` when unlocked.
    engine: Option<crypto::CryptoEngine>,
    /// Per-vault configuration loaded from `vault.toml`.
    config: vault::config::VaultConfig,
    /// Forward and reverse link index; built at unlock time, dropped at lock time.
    link_index: Option<link::LinkIndex>,
}

impl DiaryCore {
    /// Create a new `DiaryCore` by loading `vault.toml` from the vault directory.
    ///
    /// `vault_path` must point to the `vault.pqd` binary file.  The
    /// corresponding `vault.toml` is expected at the same directory level
    /// (i.e. `<parent>/vault.toml`).
    ///
    /// The vault starts in the locked state; call [`unlock`](DiaryCore::unlock)
    /// before performing any entry operations.
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::Config`] if `vault.toml` is missing or cannot be
    /// parsed, or if `vault_path` has no parent directory component.
    /// Returns [`DiaryError::Io`] on I/O failure.
    pub fn new(vault_path: &str) -> Result<Self, DiaryError> {
        let vault_path = PathBuf::from(vault_path);
        let parent = vault_path
            .parent()
            .ok_or_else(|| DiaryError::Config("vault_path has no parent directory".to_string()))?;
        let config = vault::config::VaultConfig::from_file(&parent.join("vault.toml"))?;
        Ok(Self {
            vault_path,
            engine: None,
            config,
            link_index: None,
        })
    }

    /// Unlock the vault using the given password.
    ///
    /// Reads the `vault.pqd` header, derives the 32-byte symmetric key via
    /// Argon2id (parameters taken from `vault.toml`), and verifies the
    /// password against the stored verification token.  On success the
    /// [`crypto::CryptoEngine`] is initialised and entry operations become
    /// available.
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::Password`] for an empty password.
    /// Returns [`DiaryError::Crypto`] if the password is incorrect.
    /// Returns [`DiaryError::Vault`] if the vault file format is invalid.
    /// Returns [`DiaryError::Io`] on vault file read failure.
    pub fn unlock(&mut self, password: secrecy::SecretString) -> Result<(), DiaryError> {
        let mut file = std::fs::File::open(&self.vault_path)?;
        let header = vault::reader::read_header(&mut file)?;

        let params = crypto::kdf::Argon2Params {
            memory_cost_kb: self.config.argon2.memory_cost_kb,
            time_cost: self.config.argon2.time_cost,
            parallelism: self.config.argon2.parallelism,
        };

        let mut engine = crypto::CryptoEngine::new();
        engine.unlock_with_vault(
            password.expose_secret().as_bytes(),
            &header.kdf_salt,
            &params,
            header.verification_iv,
            &header.verification_ct,
            &header.kem_encrypted_sk,
            &header.dsa_encrypted_sk,
        )?;

        self.engine = Some(engine);

        // Build the link index from all current entries.
        let entries_with_body = {
            let e = self.require_engine()?;
            entry::list_entries_with_body(&self.vault_path, e)?
        };
        self.link_index = Some(link::LinkIndex::build(&entries_with_body));

        Ok(())
    }

    /// Lock the vault, securely erasing the master key from memory.
    ///
    /// After this call any entry operation will return
    /// [`DiaryError::NotUnlocked`].  The [`crypto::CryptoEngine`] is dropped
    /// and all key material is zeroed on drop via
    /// [`zeroize::ZeroizeOnDrop`].  The [`link::LinkIndex`] is also dropped,
    /// triggering its zeroize-on-drop implementation.
    pub fn lock(&mut self) {
        self.engine = None;
        self.link_index = None;
    }

    /// Returns a reference to the engine, or [`DiaryError::NotUnlocked`] if
    /// the vault is currently locked.
    fn require_engine(&self) -> Result<&crypto::CryptoEngine, DiaryError> {
        self.engine.as_ref().ok_or(DiaryError::NotUnlocked)
    }

    /// Create a new journal entry and return its UUID as a hex string.
    ///
    /// The returned string is a 32-character lowercase hex representation of
    /// the UUID v4 assigned to the new entry, suitable for use as an ID
    /// prefix in subsequent operations.
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::NotUnlocked`] if the vault is locked.
    /// Returns [`DiaryError::Entry`] if JSON serialisation fails.
    /// Returns [`DiaryError::Crypto`] on encryption or signing failure.
    /// Returns [`DiaryError::Io`] on vault file I/O failure.
    pub fn new_entry(
        &self,
        title: &str,
        body: &str,
        tags: Vec<String>,
    ) -> Result<String, DiaryError> {
        let engine = self.require_engine()?;
        let plaintext = entry::EntryPlaintext {
            title: title.to_string(),
            tags,
            body: body.to_string(),
        };
        let uuid = entry::create_entry(&self.vault_path, engine, &plaintext)?;
        Ok(uuid.as_simple().to_string())
    }

    /// List all entries, optionally filtered by a title query string.
    ///
    /// When `query` is `Some(q)`, only entries whose title contains `q` as a
    /// substring are returned.  Sorting is intentionally left to the caller.
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::NotUnlocked`] if the vault is locked.
    /// Returns [`DiaryError::Crypto`] if decryption fails for any record.
    /// Returns [`DiaryError::Entry`] if JSON deserialisation fails.
    /// Returns [`DiaryError::Io`] on vault file I/O failure.
    pub fn list_entries(&self, query: Option<&str>) -> Result<Vec<entry::EntryMeta>, DiaryError> {
        let engine = self.require_engine()?;
        let mut metas = entry::list_entries(&self.vault_path, engine)?;
        if let Some(q) = query {
            metas.retain(|m| m.title.contains(q));
        }
        Ok(metas)
    }

    /// Look up an entry by ID prefix and return the decrypted record and plaintext.
    ///
    /// `id` is validated as a lowercase hex prefix (minimum 4 characters)
    /// before the lookup.
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::NotUnlocked`] if the vault is locked.
    /// Returns [`DiaryError::InvalidArgument`] if `id` is not a valid hex prefix.
    /// Returns [`DiaryError::Entry`] if no match or multiple matches are found.
    /// Returns [`DiaryError::Crypto`] if decryption fails.
    /// Returns [`DiaryError::Io`] on vault file I/O failure.
    pub fn get_entry(
        &self,
        id: &str,
    ) -> Result<(vault::format::EntryRecord, entry::EntryPlaintext), DiaryError> {
        let engine = self.require_engine()?;
        let prefix = entry::IdPrefix::new(id)?;
        entry::get_entry(&self.vault_path, engine, &prefix)
    }

    /// Update an existing entry identified by `id`.
    ///
    /// The entry UUID and `created_at` timestamp are preserved; only the
    /// encrypted payload, signature, HMAC, and `updated_at` are changed.
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::NotUnlocked`] if the vault is locked.
    /// Returns [`DiaryError::InvalidArgument`] if `id` is not a valid hex prefix.
    /// Returns [`DiaryError::Entry`] if the entry is not found or multiple match.
    /// Returns [`DiaryError::Crypto`] on re-encryption failure.
    /// Returns [`DiaryError::Io`] on vault file I/O failure.
    pub fn update_entry(
        &self,
        id: &str,
        plaintext: &entry::EntryPlaintext,
    ) -> Result<(), DiaryError> {
        let engine = self.require_engine()?;
        let prefix = entry::IdPrefix::new(id)?;
        let (record, _) = entry::get_entry(&self.vault_path, engine, &prefix)?;
        entry::update_entry(&self.vault_path, engine, record.uuid, plaintext)
    }

    /// Delete an entry identified by `id`.
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::NotUnlocked`] if the vault is locked.
    /// Returns [`DiaryError::InvalidArgument`] if `id` is not a valid hex prefix.
    /// Returns [`DiaryError::Entry`] if the entry is not found or multiple match.
    /// Returns [`DiaryError::Io`] on vault file I/O failure.
    pub fn delete_entry(&self, id: &str) -> Result<(), DiaryError> {
        let engine = self.require_engine()?;
        let prefix = entry::IdPrefix::new(id)?;
        let (record, _) = entry::get_entry(&self.vault_path, engine, &prefix)?;
        entry::delete_entry(&self.vault_path, engine, record.uuid)
    }

    // =========================================================================
    // Template operations
    // =========================================================================

    /// Create a new template in the vault and return its UUID hex string.
    ///
    /// `name` is validated via [`template::TemplateName`] before the template
    /// is written.  The name must be non-empty, ≤128 characters, and must not
    /// contain spaces.
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::NotUnlocked`] if the vault is locked.
    /// Returns [`DiaryError::InvalidTemplateName`] if `name` is invalid.
    /// Returns [`DiaryError::Template`] if JSON serialisation fails.
    /// Returns [`DiaryError::Crypto`] on encryption or signing failure.
    /// Returns [`DiaryError::Io`] on vault file I/O failure.
    pub fn new_template(&self, name: &str, body: &str) -> Result<String, DiaryError> {
        let engine = self.require_engine()?;
        template::TemplateName::new(name)?;
        // Reject duplicate template names.
        let existing = template::list_templates(&self.vault_path, engine)?;
        if existing.iter().any(|m| m.name == name) {
            return Err(DiaryError::Template(format!(
                "template '{}' already exists",
                name
            )));
        }
        let plaintext = template::TemplatePlaintext {
            name: name.to_string(),
            body: body.to_string(),
        };
        let uuid = template::create_template(&self.vault_path, engine, &plaintext)?;
        Ok(uuid.as_simple().to_string())
    }

    /// List all templates stored in the vault.
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::NotUnlocked`] if the vault is locked.
    /// Returns [`DiaryError::Crypto`] if decryption fails for any record.
    /// Returns [`DiaryError::Template`] if JSON deserialisation fails.
    /// Returns [`DiaryError::Io`] on vault file I/O failure.
    pub fn list_templates(&self) -> Result<Vec<template::TemplateMeta>, DiaryError> {
        let engine = self.require_engine()?;
        template::list_templates(&self.vault_path, engine)
    }

    /// Retrieve a template by name and return the decrypted plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::NotUnlocked`] if the vault is locked.
    /// Returns [`DiaryError::TemplateNotFound`] if no template with `name` exists.
    /// Returns [`DiaryError::Crypto`] if decryption fails.
    /// Returns [`DiaryError::Template`] if JSON deserialisation fails.
    /// Returns [`DiaryError::Io`] on vault file I/O failure.
    pub fn get_template(&self, name: &str) -> Result<template::TemplatePlaintext, DiaryError> {
        let engine = self.require_engine()?;
        template::get_template(&self.vault_path, engine, name)
    }

    /// Delete a template from the vault by name.
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::NotUnlocked`] if the vault is locked.
    /// Returns [`DiaryError::TemplateNotFound`] if no template with `name` exists.
    /// Returns [`DiaryError::Crypto`] if decryption fails.
    /// Returns [`DiaryError::Template`] if JSON deserialisation fails.
    /// Returns [`DiaryError::Io`] on vault file I/O failure.
    pub fn delete_template(&self, name: &str) -> Result<(), DiaryError> {
        let engine = self.require_engine()?;
        template::delete_template(&self.vault_path, engine, name)
    }

    // =========================================================================
    // Link operations
    // =========================================================================

    /// Resolve all `[[title]]` link references found in `body`.
    ///
    /// Parses wiki-links from `body` and looks up each title in the
    /// [`link::LinkIndex`] built at unlock time.  Each [`link::ResolvedLink`]
    /// indicates whether the link is unresolved (0 matches), unique (1 match),
    /// or ambiguous (≥2 matches).
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::NotUnlocked`] if the vault is locked.
    pub fn resolve_links(&self, body: &str) -> Result<Vec<link::ResolvedLink>, DiaryError> {
        let index = self.link_index.as_ref().ok_or(DiaryError::NotUnlocked)?;
        let resolved = link::parse_links(body)
            .iter()
            .map(|l| index.resolve(&l.title))
            .collect();
        Ok(resolved)
    }

    /// Return all entries that contain a `[[title]]` link pointing to `title`.
    ///
    /// If multiple entries share the same `title`, backlinks for all of them
    /// are aggregated.  Returns an empty `Vec` when the title is unknown or has
    /// no incoming links.
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::NotUnlocked`] if the vault is locked.
    pub fn backlinks_for(&self, title: &str) -> Result<Vec<link::BacklinkEntry>, DiaryError> {
        let index = self.link_index.as_ref().ok_or(DiaryError::NotUnlocked)?;
        Ok(index.backlinks_for(title))
    }

    /// Return all known entry titles from the link index.
    ///
    /// Used by the CLI to generate a completion list for vim's `completefunc`.
    /// The order of the returned titles is unspecified.
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::NotUnlocked`] if the vault is locked.
    pub fn all_titles(&self) -> Result<Vec<String>, DiaryError> {
        let index = self.link_index.as_ref().ok_or(DiaryError::NotUnlocked)?;
        Ok(index.all_titles())
    }

    // =========================================================================
    // Stats operations
    // =========================================================================

    /// Collect vault-wide statistics.
    ///
    /// Iterates over all journal entry records, decrypts each one, and
    /// aggregates entry count, character statistics, tag distribution, and
    /// daily activity into a [`stats::VaultStats`] value.
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::NotUnlocked`] if the vault is locked.
    /// Returns [`DiaryError::Entry`] if JSON deserialisation fails.
    /// Returns [`DiaryError::Crypto`] on decryption failure.
    /// Returns [`DiaryError::Io`] on vault I/O failure.
    pub fn stats(&self) -> Result<stats::VaultStats, DiaryError> {
        let engine = self.require_engine()?;
        stats::collect_stats(&self.vault_path, engine)
    }

    // =========================================================================
    // Search operations
    // =========================================================================

    /// Search all journal entries and templates for `query.pattern`.
    ///
    /// Uses a streaming strategy: each record is decrypted, searched, and its
    /// plaintext is zeroed via [`zeroize::ZeroizeOnDrop`] before the next
    /// record is processed.
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::NotUnlocked`] if the vault is locked.
    /// Returns [`DiaryError::Search`] if `query.pattern` is not a valid regex.
    /// Returns [`DiaryError::Io`] on vault I/O failure.
    /// Returns [`DiaryError::Crypto`] on decryption failure.
    pub fn search(&self, query: &search::SearchQuery) -> Result<search::SearchResults, DiaryError> {
        let engine = self.require_engine()?;
        search::search_entries(&self.vault_path, engine, query)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::Argon2Params;
    use crate::vault::init::VaultManager;
    use secrecy::SecretBox;
    use tempfile::TempDir;

    /// Fast Argon2id parameters — avoids the slow 64 MiB default in tests.
    fn fast_params() -> Argon2Params {
        Argon2Params {
            memory_cost_kb: 8,
            time_cost: 1,
            parallelism: 1,
        }
    }

    /// Initialise a test vault and return the path to `vault.pqd`.
    fn setup_test_vault(dir: &TempDir) -> PathBuf {
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());
        mgr.init_vault("test", b"password").expect("init_vault");
        dir.path().join("test").join("vault.pqd")
    }

    /// Helper: build a `SecretString` from a literal string.
    fn secret(s: &str) -> secrecy::SecretString {
        SecretBox::new(s.into())
    }

    // =========================================================================
    // TC-0033-01: E2E lifecycle
    // =========================================================================

    /// TC-0033-01: Full lifecycle — new → unlock → CRUD → lock.
    ///
    /// Exercises every DiaryCore method in a single coherent flow:
    /// init → new → unlock → new_entry → list(1) → get → update → get →
    /// delete → list(0) → lock.
    #[test]
    fn tc_0033_01_e2e_lifecycle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_pqd = setup_test_vault(&dir);

        // Step 1: DiaryCore::new
        let mut core = DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");

        // Step 2: unlock
        core.unlock(secret("password")).expect("unlock");

        // Step 3: new_entry
        let id = core
            .new_entry("テスト日記", "本文です", vec!["日記".to_string()])
            .expect("new_entry");
        assert_eq!(id.len(), 32, "UUID hex must be 32 characters");

        // Step 4: list_entries → 1 entry
        let entries = core.list_entries(None).expect("list_entries");
        assert_eq!(entries.len(), 1, "must have exactly 1 entry");
        assert_eq!(entries[0].title, "テスト日記");

        // Step 5: get_entry — body matches
        let prefix = &id[..4];
        let (_record, plaintext) = core.get_entry(prefix).expect("get_entry");
        assert_eq!(plaintext.body, "本文です");
        assert_eq!(plaintext.tags, vec!["日記".to_string()]);

        // Step 6: update_entry — change title and body
        let updated = entry::EntryPlaintext {
            title: "更新後タイトル".to_string(),
            tags: vec!["日記".to_string()],
            body: "更新後本文".to_string(),
        };
        core.update_entry(prefix, &updated).expect("update_entry");

        // Step 7: get_entry — verify new title
        let (_, plaintext2) = core.get_entry(prefix).expect("get_entry after update");
        assert_eq!(plaintext2.title, "更新後タイトル");
        assert_eq!(plaintext2.body, "更新後本文");

        // Step 8: delete_entry
        core.delete_entry(prefix).expect("delete_entry");

        // Step 9: list_entries → 0 entries
        let entries2 = core.list_entries(None).expect("list_entries after delete");
        assert_eq!(entries2.len(), 0, "vault must be empty after delete");

        // Step 10: lock
        core.lock();
    }

    // =========================================================================
    // TC-0033-02: Locked vault rejects all entry operations
    // =========================================================================

    /// TC-0033-02: Entry operations on a locked vault return an error.
    ///
    /// Tests both the "never unlocked" and "re-locked" states.
    #[test]
    fn tc_0033_02_locked_operations_return_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_pqd = setup_test_vault(&dir);

        // Before unlock: new_entry must fail
        let core = DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");
        assert!(
            core.new_entry("title", "body", vec![]).is_err(),
            "new_entry on locked vault must return an error"
        );

        // After lock: list_entries must fail
        let mut core = DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");
        core.unlock(secret("password")).expect("unlock");
        core.lock();
        assert!(
            core.list_entries(None).is_err(),
            "list_entries on re-locked vault must return an error"
        );
    }

    // =========================================================================
    // TC-0033-03: unlock → lock → unlock cycle
    // =========================================================================

    /// TC-0033-03: Vault can be unlocked, locked, and unlocked again.
    ///
    /// After a lock/unlock cycle the previously written entry must still be
    /// accessible.
    #[test]
    fn tc_0033_03_unlock_lock_unlock_cycle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_pqd = setup_test_vault(&dir);

        let mut core = DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");

        // First unlock: create entry
        core.unlock(secret("password")).expect("first unlock");
        let _id = core
            .new_entry("entry1", "body1", vec![])
            .expect("new_entry");

        // Lock: new_entry must be rejected
        core.lock();
        assert!(
            core.new_entry("entry2", "body2", vec![]).is_err(),
            "locked vault must reject new_entry"
        );

        // Second unlock: previously created entry must still be present
        core.unlock(secret("password")).expect("second unlock");
        let entries = core
            .list_entries(None)
            .expect("list_entries after re-unlock");
        assert_eq!(entries.len(), 1, "must find 1 entry after re-unlock");
    }

    // =========================================================================
    // TC-046-01: unlock後にlink_indexが構築される
    // =========================================================================

    /// TC-046-01: After unlock, all_titles returns every entry title.
    #[test]
    fn tc_046_01_unlock_builds_link_index() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_pqd = setup_test_vault(&dir);

        let mut core = DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");
        core.unlock(secret("password")).expect("first unlock");

        // Create 3 entries
        core.new_entry("エントリA", "本文A", vec![])
            .expect("new_entry A");
        core.new_entry("エントリB", "本文B", vec![])
            .expect("new_entry B");
        core.new_entry("エントリC", "本文C", vec![])
            .expect("new_entry C");
        core.lock();

        // Re-unlock: LinkIndex must be built with the 3 entries
        core.unlock(secret("password")).expect("second unlock");
        let mut titles = core.all_titles().expect("all_titles");
        titles.sort();
        assert_eq!(titles.len(), 3, "must have 3 titles");
        assert_eq!(titles, vec!["エントリA", "エントリB", "エントリC"]);
    }

    // =========================================================================
    // TC-046-02: lock後にlink_indexがNone
    // =========================================================================

    /// TC-046-02: After lock, resolve_links returns DiaryError::NotUnlocked.
    #[test]
    fn tc_046_02_lock_clears_link_index() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_pqd = setup_test_vault(&dir);

        let mut core = DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");
        core.unlock(secret("password")).expect("unlock");
        core.lock();

        let err = core
            .resolve_links("[[test]]")
            .expect_err("must fail when locked");
        assert!(
            matches!(err, DiaryError::NotUnlocked),
            "expected NotUnlocked, got {:?}",
            err
        );
    }

    // =========================================================================
    // TC-046-03: テンプレートCRUDライフサイクル
    // =========================================================================

    /// TC-046-03: new_template → list_templates → get_template → delete_template lifecycle.
    #[test]
    fn tc_046_03_template_crud_lifecycle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_pqd = setup_test_vault(&dir);

        let mut core = DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");
        core.unlock(secret("password")).expect("unlock");

        // new_template
        let uuid_hex = core
            .new_template("daily", "## {{date}}")
            .expect("new_template");
        assert_eq!(uuid_hex.len(), 32, "UUID hex must be 32 chars");

        // list_templates
        let metas = core.list_templates().expect("list_templates");
        assert_eq!(metas.len(), 1);
        assert_eq!(metas[0].name, "daily");

        // get_template
        let got = core.get_template("daily").expect("get_template");
        assert_eq!(got.name, "daily");
        assert_eq!(got.body, "## {{date}}");

        // delete_template
        core.delete_template("daily").expect("delete_template");
        let metas2 = core.list_templates().expect("list_templates after delete");
        assert!(metas2.is_empty(), "list must be empty after delete");
    }

    // =========================================================================
    // TC-046-04: resolve_linksの動作
    // =========================================================================

    /// TC-046-04: resolve_links resolves [[A]] to entry A's UUID.
    #[test]
    fn tc_046_04_resolve_links() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_pqd = setup_test_vault(&dir);

        let mut core = DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");
        core.unlock(secret("password")).expect("first unlock");

        // Create entries A and B
        let id_a = core.new_entry("A", "本文A", vec![]).expect("new_entry A");
        core.new_entry("B", "本文B", vec![]).expect("new_entry B");
        core.lock();

        // Re-unlock so LinkIndex reflects the new entries
        core.unlock(secret("password")).expect("second unlock");

        let resolved = core.resolve_links("[[A]] を参照").expect("resolve_links");
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].title, "A");
        assert_eq!(resolved[0].matches.len(), 1, "must match exactly one entry");
        assert_eq!(
            resolved[0].matches[0].uuid_hex, id_a,
            "UUID must match entry A"
        );
    }

    // =========================================================================
    // TC-046-05: backlinks_forの動作
    // =========================================================================

    /// TC-046-05: backlinks_for("B") returns entry A as source when A links [[B]].
    #[test]
    fn tc_046_05_backlinks_for() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_pqd = setup_test_vault(&dir);

        let mut core = DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");
        core.unlock(secret("password")).expect("first unlock");

        // Entry A links to B
        core.new_entry("A", "[[B]]", vec![]).expect("new_entry A");
        core.new_entry("B", "本文B", vec![]).expect("new_entry B");
        core.lock();

        // Re-unlock so LinkIndex reflects the entries
        core.unlock(secret("password")).expect("second unlock");

        let backlinks = core.backlinks_for("B").expect("backlinks_for");
        assert_eq!(backlinks.len(), 1, "B must have 1 backlink");
        assert_eq!(backlinks[0].source_title, "A", "source must be entry A");
    }
}
