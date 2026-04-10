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
    policy::AccessPolicy,
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

    /// Validate a vault name for use as a filesystem directory name.
    ///
    /// Rejects empty strings, path-traversal patterns (`/`, `\`, `..`), and
    /// filesystem-invalid characters (`:`, `*`, `?`, `"`, `<`, `>`, `|`).
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::InvalidArgument`] if the name fails any check.
    pub fn validate_vault_name(name: &str) -> Result<(), DiaryError> {
        if name.is_empty() {
            return Err(DiaryError::InvalidArgument(
                "vault name must not be empty".into(),
            ));
        }
        if name.contains('/') || name.contains('\\') || name.contains("..") {
            return Err(DiaryError::InvalidArgument(
                "vault name contains invalid path characters".into(),
            ));
        }
        if name.contains(':')
            || name.contains('*')
            || name.contains('?')
            || name.contains('"')
            || name.contains('<')
            || name.contains('>')
            || name.contains('|')
        {
            return Err(DiaryError::InvalidArgument(
                "vault name contains filesystem-invalid characters".into(),
            ));
        }
        Ok(())
    }

    /// Create a new vault named `name` protected by `password` with `policy`.
    ///
    /// High-level wrapper around [`VaultManager::init_vault`] that additionally:
    /// 1. Validates the vault name via [`VaultManager::validate_vault_name`].
    /// 2. Rejects duplicate vault names.
    /// 3. Auto-creates the vaults base directory if absent.
    /// 4. Initialises the vault on disk.
    /// 5. Writes the requested access policy to `vault.toml`.
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::InvalidArgument`] if the name is invalid.
    /// Returns [`DiaryError::Vault`] if a vault with that name already exists.
    /// Returns [`DiaryError::Password`] if `password` is empty.
    /// Returns [`DiaryError::Io`] on filesystem failures.
    /// Returns [`DiaryError::Crypto`] on key derivation or encryption failures.
    pub fn create_vault(
        &self,
        name: &str,
        password: &[u8],
        policy: AccessPolicy,
    ) -> Result<(), DiaryError> {
        // Step 1: Validate the vault name.
        Self::validate_vault_name(name)?;

        // Step 2: Reject duplicates.
        let vault_path = self.base_dir.join(name);
        if vault_path.exists() {
            return Err(DiaryError::Vault(format!(
                "vault '{}' already exists",
                name
            )));
        }

        // Step 3: Ensure the base (vaults/) directory exists.
        std::fs::create_dir_all(&self.base_dir)?;

        // Step 4: Initialise the vault.
        self.init_vault(name, password)?;

        // Step 5: Apply the access policy by updating vault.toml.
        // (set_policy() will be implemented in TASK-0070; patched inline here.)
        let vault_toml_path = vault_path.join("vault.toml");
        let mut vault_config = VaultConfig::from_file(&vault_toml_path)?;
        vault_config.access.policy = policy;
        vault_config.to_file(&vault_toml_path)?;

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
    use crate::policy::AccessPolicy;
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

    // -------------------------------------------------------------------------
    // TASK-0069: validate_vault_name tests
    // -------------------------------------------------------------------------

    /// TC-VN-01: empty string is rejected.
    #[test]
    fn tc_vn_01_empty_name_rejected() {
        let result = VaultManager::validate_vault_name("");
        assert!(
            matches!(result, Err(DiaryError::InvalidArgument(_))),
            "expected InvalidArgument for empty name, got {:?}",
            result
        );
    }

    /// TC-VN-02: ".." is rejected as a path-traversal name.
    #[test]
    fn tc_vn_02_dotdot_rejected() {
        let result = VaultManager::validate_vault_name("..");
        assert!(
            matches!(result, Err(DiaryError::InvalidArgument(_))),
            "expected InvalidArgument for '..', got {:?}",
            result
        );
    }

    /// TC-VN-03: "../escape" is rejected as a path-traversal name.
    #[test]
    fn tc_vn_03_path_traversal_rejected() {
        let result = VaultManager::validate_vault_name("../escape");
        assert!(
            matches!(result, Err(DiaryError::InvalidArgument(_))),
            "expected InvalidArgument for '../escape', got {:?}",
            result
        );
    }

    /// TC-VN-04: "valid-name" is accepted.
    #[test]
    fn tc_vn_04_valid_name_accepted() {
        let result = VaultManager::validate_vault_name("valid-name");
        assert!(
            result.is_ok(),
            "expected Ok for 'valid-name', got {:?}",
            result
        );
    }

    /// TC-VN-05: "name_with_underscore" is accepted.
    #[test]
    fn tc_vn_05_underscore_name_accepted() {
        let result = VaultManager::validate_vault_name("name_with_underscore");
        assert!(
            result.is_ok(),
            "expected Ok for 'name_with_underscore', got {:?}",
            result
        );
    }

    // -------------------------------------------------------------------------
    // TASK-0069: create_vault tests
    // -------------------------------------------------------------------------

    /// TC-S7-030-01: create_vault with AccessPolicy::None stores "none" in vault.toml.
    ///
    /// Given a fresh vault manager, when create_vault is called with
    /// AccessPolicy::None, vault.toml must have policy = "none".
    #[test]
    fn tc_s7_030_01_create_vault_none_policy() {
        let dir = tempdir().expect("tempdir");
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());

        mgr.create_vault("test-vault", b"password", AccessPolicy::None)
            .expect("create_vault");

        let vault_toml = dir.path().join("test-vault").join("vault.toml");
        let config =
            crate::vault::config::VaultConfig::from_file(&vault_toml).expect("read vault.toml");
        assert_eq!(
            config.access.policy,
            AccessPolicy::None,
            "expected policy None, got {:?}",
            config.access.policy
        );
    }

    /// TC-S7-030-02: create_vault with AccessPolicy::WriteOnly stores "write_only" in vault.toml.
    ///
    /// Given a fresh vault manager, when create_vault is called with
    /// AccessPolicy::WriteOnly, vault.toml must have policy = "write_only".
    #[test]
    fn tc_s7_030_02_create_vault_write_only_policy() {
        let dir = tempdir().expect("tempdir");
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());

        mgr.create_vault("work-vault", b"password", AccessPolicy::WriteOnly)
            .expect("create_vault");

        let vault_toml = dir.path().join("work-vault").join("vault.toml");
        let config =
            crate::vault::config::VaultConfig::from_file(&vault_toml).expect("read vault.toml");
        assert_eq!(
            config.access.policy,
            AccessPolicy::WriteOnly,
            "expected policy WriteOnly, got {:?}",
            config.access.policy
        );
    }

    /// TC-S7-030-04: create_vault creates vault.pqd and entries/ on disk.
    ///
    /// After a successful create_vault call, both vault.pqd and the entries/
    /// directory must exist under the vault root.
    #[test]
    fn tc_s7_030_04_create_vault_creates_files() {
        let dir = tempdir().expect("tempdir");
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());

        mgr.create_vault("new-vault", b"password", AccessPolicy::None)
            .expect("create_vault");

        let vault_dir = dir.path().join("new-vault");
        assert!(vault_dir.join("vault.pqd").exists(), "vault.pqd must exist");
        assert!(
            vault_dir.join("entries").is_dir(),
            "entries/ must be a directory"
        );
    }

    /// TC-S7-030-05: create_vault auto-creates the vaults base directory when absent.
    ///
    /// If the base directory (vaults/) is removed after VaultManager is
    /// constructed, create_vault must recreate it and initialise the vault.
    #[test]
    fn tc_s7_030_05_create_vault_auto_creates_base_dir() {
        let root = tempdir().expect("tempdir");
        let vaults_dir = root.path().join("vaults");

        // VaultManager::new creates vaults_dir; then we remove it.
        let mgr = VaultManager::new(vaults_dir.clone())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());
        std::fs::remove_dir(&vaults_dir).expect("remove vaults_dir");
        assert!(!vaults_dir.exists(), "vaults/ must not exist before test");

        // create_vault must auto-create vaults_dir.
        mgr.create_vault("auto-vault", b"password", AccessPolicy::None)
            .expect("create_vault should auto-create base dir");

        assert!(vaults_dir.exists(), "vaults/ must be created automatically");
        assert!(
            vaults_dir.join("auto-vault").join("vault.pqd").exists(),
            "vault.pqd must exist after auto-creation"
        );
    }

    /// TC-S7-030-E01: creating a vault with a duplicate name returns DiaryError::Vault.
    ///
    /// When create_vault is called twice with the same name, the second call
    /// must return Err(DiaryError::Vault(_)) containing "already exists".
    #[test]
    fn tc_s7_030_e01_duplicate_vault_name_rejected() {
        let dir = tempdir().expect("tempdir");
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());

        mgr.create_vault("dupe", b"password", AccessPolicy::None)
            .expect("first create_vault");
        let result = mgr.create_vault("dupe", b"password", AccessPolicy::None);

        assert!(
            matches!(result, Err(DiaryError::Vault(_))),
            "expected DiaryError::Vault for duplicate name, got {:?}",
            result
        );
        if let Err(DiaryError::Vault(msg)) = &result {
            assert!(
                msg.contains("already exists"),
                "error message must contain 'already exists', got: {}",
                msg
            );
        }
    }

    /// TC-S7-030-E02: path-traversal vault name returns DiaryError::InvalidArgument.
    ///
    /// create_vault("../escape", ...) must return Err(DiaryError::InvalidArgument).
    #[test]
    fn tc_s7_030_e02_path_traversal_name_rejected() {
        let dir = tempdir().expect("tempdir");
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());

        let result = mgr.create_vault("../escape", b"password", AccessPolicy::None);
        assert!(
            matches!(result, Err(DiaryError::InvalidArgument(_))),
            "expected DiaryError::InvalidArgument for path traversal, got {:?}",
            result
        );
    }

    /// TC-S7-030-E03: empty vault name returns DiaryError::InvalidArgument.
    ///
    /// create_vault("", ...) must return Err(DiaryError::InvalidArgument).
    #[test]
    fn tc_s7_030_e03_empty_name_rejected() {
        let dir = tempdir().expect("tempdir");
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());

        let result = mgr.create_vault("", b"password", AccessPolicy::None);
        assert!(
            matches!(result, Err(DiaryError::InvalidArgument(_))),
            "expected DiaryError::InvalidArgument for empty name, got {:?}",
            result
        );
    }
}
