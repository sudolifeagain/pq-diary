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
/// Unified error type: [`DiaryError`].
pub mod error;
/// Entry CRUD operations (implemented in Sprint 4).
pub mod entry;
/// Template CRUD operations (implemented in Sprint 5).
pub mod template;
/// Template variable extraction and expansion engine (implemented in Sprint 5).
pub mod template_engine;
/// Git synchronisation operations (implemented in Sprint 8).
pub mod git;
/// Digital-legacy operations (implemented in Phase 2).
pub mod legacy;
/// Access-policy evaluation (implemented in Sprint 7).
pub mod policy;
/// Vault format read/write operations (implemented in Sprint 3).
pub mod vault;

/// Re-exported for convenience: see [`crypto::SecureBuffer`].
pub use crypto::SecureBuffer;
/// Re-exported for convenience: see [`error::DiaryError`].
pub use error::DiaryError;
/// Re-exported entry types for external crate use.
pub use entry::{EntryMeta, EntryPlaintext, IdPrefix, Tag};
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
        Ok(())
    }

    /// Lock the vault, securely erasing the master key from memory.
    ///
    /// After this call any entry operation will return
    /// [`DiaryError::NotUnlocked`].  The [`crypto::CryptoEngine`] is dropped
    /// and all key material is zeroed on drop via
    /// [`zeroize::ZeroizeOnDrop`].
    pub fn lock(&mut self) {
        self.engine = None;
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
        let mut core =
            DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");

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
        let core =
            DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");
        assert!(
            core.new_entry("title", "body", vec![]).is_err(),
            "new_entry on locked vault must return an error"
        );

        // After lock: list_entries must fail
        let mut core =
            DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");
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

        let mut core =
            DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");

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
}
