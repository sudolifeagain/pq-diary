//! Vault initialisation and `VaultManager` (directory creation, key generation).
//!
//! Provides [`VaultManager`], which manages the on-disk directory tree for all
//! pq-diary vaults under a single base directory (typically `~/.pq-diary/`).

use std::path::PathBuf;

use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::{
    crypto::{aead, dsa, kdf, kem},
    error::DiaryError,
    vault::{
        config::{AppConfig, VaultConfig},
        format::{generate_verification_token, VaultHeader, SCHEMA_VERSION},
        writer::write_vault,
    },
};

// =============================================================================
// VaultManager
// =============================================================================

/// Manages the on-disk directory tree of pq-diary vaults.
///
/// Each vault lives as a subdirectory of `base_dir`:
///
/// ```text
/// base_dir/
/// ├── config.toml            — application-wide defaults
/// └── {vault_name}/
///     ├── vault.pqd          — encrypted binary vault file
///     ├── vault.toml         — per-vault TOML configuration
///     └── entries/           — directory for future entry stubs
/// ```
pub struct VaultManager {
    /// Root directory for all vaults (e.g., `~/.pq-diary/`).
    base_dir: PathBuf,
    /// Application-wide configuration loaded from `config.toml` (or default).
    app_config: AppConfig,
    /// Argon2id parameters used for key derivation when creating new vaults.
    kdf_params: kdf::Argon2Params,
}

impl VaultManager {
    /// Create a new [`VaultManager`] rooted at `base_dir`.
    ///
    /// Creates `base_dir` if it does not already exist.  Loads
    /// `{base_dir}/config.toml` if it is present; otherwise uses
    /// [`AppConfig::default()`].
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::Io`] on filesystem failures.
    /// Returns [`DiaryError::Config`] if `config.toml` exists but cannot be parsed.
    pub fn new(base_dir: PathBuf) -> Result<Self, DiaryError> {
        std::fs::create_dir_all(&base_dir)?;

        let config_path = base_dir.join("config.toml");
        let app_config = if config_path.exists() {
            AppConfig::from_file(&config_path)?
        } else {
            AppConfig::default()
        };

        Ok(Self {
            base_dir,
            app_config,
            kdf_params: kdf::Argon2Params::default(),
        })
    }

    /// Override the Argon2id KDF parameters used when creating new vaults.
    ///
    /// Returns `self` to allow builder-style chaining.  Intended primarily
    /// for tests that need reduced memory / time cost.
    pub fn with_kdf_params(mut self, params: kdf::Argon2Params) -> Self {
        self.kdf_params = params;
        self
    }

    /// Initialise a new vault named `name` protected by `password`.
    ///
    /// Creates the following on disk:
    /// - `{base_dir}/{name}/`            — vault root directory
    /// - `{base_dir}/{name}/vault.pqd`   — binary vault file with initial header
    /// - `{base_dir}/{name}/vault.toml`  — per-vault TOML configuration
    /// - `{base_dir}/{name}/entries/`    — entries directory (initially empty)
    ///
    /// The vault header includes:
    /// - Random 32-byte Argon2id KDF salt and legacy-inheritance salt
    /// - AES-256-GCM verification token derived from `password`
    /// - IV-prepended AES-256-GCM-encrypted ML-KEM-768 decapsulation key seed
    /// - IV-prepended AES-256-GCM-encrypted ML-DSA-65 signing key seed
    /// - SHA-256 hash of the ML-DSA-65 verifying (public) key
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::Vault`] if a vault named `name` already exists.
    /// Returns [`DiaryError::Password`] if `password` is empty.
    /// Returns [`DiaryError::Io`] on filesystem failures.
    /// Returns [`DiaryError::Crypto`] on key derivation or encryption failures.
    pub fn init_vault(&self, name: &str, password: &[u8]) -> Result<(), DiaryError> {
        // Guard: refuse empty password.
        if password.is_empty() {
            return Err(DiaryError::Password(
                "password must not be empty".to_string(),
            ));
        }

        let vault_dir = self.base_dir.join(name);

        // Guard: refuse to clobber an existing vault directory.
        if vault_dir.exists() {
            return Err(DiaryError::Vault(format!(
                "vault '{}' already exists",
                name
            )));
        }

        // Create vault root and entries sub-directory in one shot.
        let entries_dir = vault_dir.join("entries");
        std::fs::create_dir_all(&entries_dir)?;

        // ── Cryptographic setup ───────────────────────────────────────────────

        // Generate random KDF salt and legacy-inheritance salt.
        let mut kdf_salt = [0u8; 32];
        let mut legacy_salt = [0u8; 32];
        OsRng.fill_bytes(&mut kdf_salt);
        OsRng.fill_bytes(&mut legacy_salt);

        // Derive the 32-byte symmetric key from the password via Argon2id.
        let sym_key = kdf::derive_key(password, &kdf_salt, &self.kdf_params)?;

        // Generate the AES-256-GCM verification token (stored in header).
        let (verification_iv, verification_ct) = generate_verification_token(sym_key.as_ref())?;

        // Generate ML-KEM-768 key pair.
        // The decapsulation key seed is AES-GCM-encrypted; IV is prepended.
        let kem_kp = kem::keygen()?;
        let (kem_ct, kem_iv) = aead::encrypt(sym_key.as_ref(), kem_kp.decapsulation_key.as_ref())?;
        let mut kem_encrypted_sk = Vec::with_capacity(kem_iv.len() + kem_ct.len());
        kem_encrypted_sk.extend_from_slice(&kem_iv);
        kem_encrypted_sk.extend_from_slice(&kem_ct);

        // Generate ML-DSA-65 key pair.
        // The signing key seed is AES-GCM-encrypted; IV is prepended.
        let dsa_kp = dsa::keygen()?;
        let (dsa_ct, dsa_iv) = aead::encrypt(sym_key.as_ref(), dsa_kp.signing_key.as_ref())?;
        let mut dsa_encrypted_sk = Vec::with_capacity(dsa_iv.len() + dsa_ct.len());
        dsa_encrypted_sk.extend_from_slice(&dsa_iv);
        dsa_encrypted_sk.extend_from_slice(&dsa_ct);

        // Compute SHA-256 of the ML-DSA-65 verifying (public) key.
        let mut hasher = Sha256::new();
        hasher.update(&dsa_kp.verifying_key);
        let dsa_pk_hash: [u8; 32] = hasher.finalize().into();

        // ── Assemble and write vault.pqd ──────────────────────────────────────

        let header = VaultHeader {
            schema_version: SCHEMA_VERSION,
            flags: 0,
            payload_size: 0,
            kdf_salt,
            legacy_salt,
            verification_iv,
            verification_ct,
            kem_pk_offset: [0u8; 32], // reserved: full public-key storage in future task
            dsa_pk_hash,
            kem_encrypted_sk,
            dsa_encrypted_sk,
        };

        let vault_pqd = vault_dir.join("vault.pqd");
        write_vault(&vault_pqd, header, &[])?;

        // ── Write vault.toml ──────────────────────────────────────────────────

        let mut vault_config = VaultConfig::default();
        vault_config.vault.name = name.to_owned();
        vault_config.argon2.memory_cost_kb = self.kdf_params.memory_cost_kb;
        vault_config.argon2.time_cost = self.kdf_params.time_cost;
        vault_config.argon2.parallelism = self.kdf_params.parallelism;
        let vault_toml = vault_dir.join("vault.toml");
        vault_config.to_file(&vault_toml)?;

        Ok(())
    }

    /// Return the names of all initialised vaults under `base_dir`.
    ///
    /// A directory is counted as a vault when it contains a `vault.pqd` file.
    /// Names are returned in ascending lexicographic order.
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::Io`] on filesystem failures.
    pub fn list_vaults(&self) -> Result<Vec<String>, DiaryError> {
        let mut vaults = Vec::new();

        for entry_result in std::fs::read_dir(&self.base_dir)? {
            let entry = entry_result?;
            let path = entry.path();
            if path.is_dir() && path.join("vault.pqd").exists() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    vaults.push(name.to_owned());
                }
            }
        }

        vaults.sort();
        Ok(vaults)
    }

    /// Return the filesystem path of vault `name`.
    ///
    /// Does **not** verify whether the vault exists.
    pub fn vault_path(&self, name: &str) -> PathBuf {
        self.base_dir.join(name)
    }

    /// Return the name of the default vault from `config.toml`.
    ///
    /// Returns `[defaults] vault` from `{base_dir}/config.toml`, defaulting to
    /// `"default"` when no `config.toml` is present.
    pub fn default_vault(&self) -> &str {
        &self.app_config.defaults.vault
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Fast Argon2id parameters — avoids the slow 64 MiB default during tests.
    fn fast_params() -> kdf::Argon2Params {
        kdf::Argon2Params {
            memory_cost_kb: 8,
            time_cost: 1,
            parallelism: 1,
        }
    }

    /// TC-006-01: init_vault creates the full directory + file structure.
    ///
    /// Given a VaultManager with a fresh temporary base directory, when
    /// `init_vault("myvault", b"password")` is called, the vault directory,
    /// `vault.pqd`, `vault.toml`, and `entries/` must all exist on disk.
    #[test]
    fn tc_006_01_init_vault_creates_directory_structure() {
        let dir = tempdir().expect("tempdir");
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());

        mgr.init_vault("myvault", b"test-password")
            .expect("init_vault");

        let vault_dir = dir.path().join("myvault");
        assert!(vault_dir.exists(), "vault directory must exist");
        assert!(vault_dir.join("vault.pqd").exists(), "vault.pqd must exist");
        assert!(
            vault_dir.join("vault.toml").exists(),
            "vault.toml must exist"
        );
        assert!(
            vault_dir.join("entries").exists(),
            "entries/ directory must exist"
        );
        assert!(
            vault_dir.join("entries").is_dir(),
            "entries must be a directory"
        );
    }

    /// TC-006-02: list_vaults returns the single created vault.
    ///
    /// Given one vault named "vault1", when `list_vaults()` is called, the
    /// result must contain exactly the string `"vault1"`.
    #[test]
    fn tc_006_02_list_vaults_returns_single_vault() {
        let dir = tempdir().expect("tempdir");
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());

        mgr.init_vault("vault1", b"password1").expect("init_vault");
        let vaults = mgr.list_vaults().expect("list_vaults");

        assert!(
            vaults.contains(&"vault1".to_owned()),
            "list_vaults must contain 'vault1', got {:?}",
            vaults
        );
    }

    /// TC-006-03: list_vaults returns all created vaults.
    ///
    /// Given three vaults named "alpha", "beta", and "gamma", when
    /// `list_vaults()` is called, all three names must appear in the result
    /// and the total count must be exactly 3.
    #[test]
    fn tc_006_03_list_vaults_returns_all_vaults() {
        let dir = tempdir().expect("tempdir");
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());

        mgr.init_vault("alpha", b"password")
            .expect("init_vault alpha");
        mgr.init_vault("beta", b"password")
            .expect("init_vault beta");
        mgr.init_vault("gamma", b"password")
            .expect("init_vault gamma");

        let vaults = mgr.list_vaults().expect("list_vaults");

        assert_eq!(
            vaults.len(),
            3,
            "must list exactly 3 vaults, got {:?}",
            vaults
        );
        assert!(vaults.contains(&"alpha".to_owned()), "missing 'alpha'");
        assert!(vaults.contains(&"beta".to_owned()), "missing 'beta'");
        assert!(vaults.contains(&"gamma".to_owned()), "missing 'gamma'");
    }

    /// TC-025-01: default_vault returns the vault name from config.toml.
    ///
    /// Given a `config.toml` with `[defaults] vault = "my_vault"`, when a
    /// `VaultManager` is created from the same directory, `default_vault()`
    /// must return `"my_vault"`.
    #[test]
    fn tc_025_01_default_vault_from_config_toml() {
        let dir = tempdir().expect("tempdir");

        // Write a custom config.toml before constructing the manager.
        let mut app_config = AppConfig::default();
        app_config.defaults.vault = "my_vault".to_owned();
        app_config
            .to_file(&dir.path().join("config.toml"))
            .expect("write config.toml");

        let mgr = VaultManager::new(dir.path().to_path_buf()).expect("VaultManager::new");

        assert_eq!(mgr.default_vault(), "my_vault");
    }

    /// TC-025-E01: init_vault with a duplicate name returns DiaryError::Vault.
    ///
    /// Given a vault named "dupe" that already exists, when `init_vault` is
    /// called again with the same name, it must return
    /// `Err(DiaryError::Vault(_))` without panicking.
    #[test]
    fn tc_025_e01_duplicate_vault_returns_vault_error() {
        let dir = tempdir().expect("tempdir");
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());

        mgr.init_vault("dupe", b"password")
            .expect("first init_vault");
        let result = mgr.init_vault("dupe", b"password");

        assert!(
            matches!(result, Err(DiaryError::Vault(_))),
            "expected DiaryError::Vault for duplicate vault name, got {:?}",
            result
        );
    }

    /// TC-A03-01: init_vault with empty password returns DiaryError::Password.
    ///
    /// Given an empty password byte slice, when `init_vault` is called, it must
    /// return `Err(DiaryError::Password(_))` without creating any files.
    #[test]
    fn tc_a03_01_empty_password_returns_password_error() {
        let dir = tempdir().expect("tempdir");
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());

        let result = mgr.init_vault("test", b"");

        assert!(
            matches!(result, Err(DiaryError::Password(_))),
            "expected DiaryError::Password for empty password, got {:?}",
            result
        );
        // Vault directory must not have been created.
        assert!(
            !dir.path().join("test").exists(),
            "vault directory must not be created for empty password"
        );
    }

    /// TC-A03-02: init_vault with non-empty password succeeds.
    ///
    /// Given a non-empty password, when `init_vault` is called, it must return
    /// `Ok(())` and create the vault on disk.
    #[test]
    fn tc_a03_02_nonempty_password_creates_vault() {
        let dir = tempdir().expect("tempdir");
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());

        let result = mgr.init_vault("test", b"secure-password-123");

        assert!(
            result.is_ok(),
            "expected Ok for non-empty password, got {:?}",
            result
        );
        assert!(
            dir.path().join("test").join("vault.pqd").exists(),
            "vault.pqd must exist after successful init"
        );
    }

    /// vault_path returns the expected PathBuf.
    ///
    /// Given a VaultManager with base_dir `/tmp/foo`, `vault_path("bar")` must
    /// equal `/tmp/foo/bar`.
    #[test]
    fn test_vault_path_returns_base_dir_joined_with_name() {
        let dir = tempdir().expect("tempdir");
        let base = dir.path().to_path_buf();
        let mgr = VaultManager::new(base.clone()).expect("VaultManager::new");

        assert_eq!(mgr.vault_path("bar"), base.join("bar"));
    }

    /// default_vault falls back to "default" when no config.toml is present.
    ///
    /// Given a fresh base directory without a `config.toml`, `default_vault()`
    /// must return `"default"` (the `AppConfig::default()` value).
    #[test]
    fn test_default_vault_falls_back_to_default() {
        let dir = tempdir().expect("tempdir");
        let mgr = VaultManager::new(dir.path().to_path_buf()).expect("VaultManager::new");

        assert_eq!(mgr.default_vault(), "default");
    }
}
