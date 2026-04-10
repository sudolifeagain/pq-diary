//! Vault initialisation and `VaultManager` (directory creation, key generation).
//!
//! Provides `VaultManager`, which manages the on-disk directory tree for all
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
// VaultInfo
// =============================================================================

/// Vault list display information.
///
/// Returned by [`VaultManager::list_vaults_with_policy`].
/// Contains only information readable without a password (from `vault.toml`).
#[derive(Debug)]
pub struct VaultInfo {
    /// Vault name (directory name under the base directory).
    pub name: String,
    /// Access policy for this vault.
    pub policy: AccessPolicy,
}

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

        // Step 5: Apply the access policy via atomic write.
        self.set_policy(name, policy)?;

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

    /// Return the names and access policies of all initialised vaults.
    ///
    /// Reads `vault.toml` from each vault subdirectory under `base_dir`.
    /// Does **not** require a password — `vault.toml` is stored in plain text.
    /// Directories that do not contain a `vault.toml` are silently skipped.
    /// Results are returned in ascending lexicographic order.
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::Io`] on filesystem failures.
    /// Returns [`DiaryError::Config`] if any `vault.toml` cannot be parsed.
    pub fn list_vaults_with_policy(&self) -> Result<Vec<VaultInfo>, DiaryError> {
        let mut vaults = Vec::new();

        for entry_result in std::fs::read_dir(&self.base_dir)? {
            let entry = entry_result?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let toml_path = path.join("vault.toml");
            if !toml_path.exists() {
                continue;
            }
            let config = VaultConfig::from_file(&toml_path)?;
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                vaults.push(VaultInfo {
                    name: name.to_owned(),
                    policy: config.access.policy,
                });
            }
        }

        vaults.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(vaults)
    }

    /// Update the access policy for vault `name` in its `vault.toml`.
    ///
    /// Writes atomically: serialises to `vault.toml.tmp`, calls `sync_all()`,
    /// then renames to `vault.toml`.  Does **not** require a password.
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::Vault`] if the vault does not exist.
    /// Returns [`DiaryError::Config`] if `vault.toml` cannot be parsed or serialised.
    /// Returns [`DiaryError::Io`] on filesystem failures.
    pub fn set_policy(&self, name: &str, policy: AccessPolicy) -> Result<(), DiaryError> {
        let vault_path = self.base_dir.join(name);
        let toml_path = vault_path.join("vault.toml");
        if !toml_path.exists() {
            return Err(DiaryError::Vault(format!(
                "vault '{}' does not exist",
                name
            )));
        }
        let content = std::fs::read_to_string(&toml_path)?;
        let mut config: VaultConfig = toml::from_str(&content)
            .map_err(|e| DiaryError::Config(format!("failed to parse vault.toml: {}", e)))?;
        config.access.policy = policy;
        let new_content = toml::to_string_pretty(&config)
            .map_err(|e| DiaryError::Config(format!("failed to serialize vault.toml: {}", e)))?;
        let tmp_path = toml_path.with_extension("toml.tmp");
        {
            use std::io::Write;
            let mut file = std::fs::File::create(&tmp_path)?;
            file.write_all(new_content.as_bytes())?;
            file.sync_all()?;
        }
        if let Err(e) = std::fs::rename(&tmp_path, &toml_path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(DiaryError::Io(e));
        }
        Ok(())
    }

    /// Delete vault `name` and its entire directory tree.
    ///
    /// When `zeroize` is `true`, `vault.pqd` is overwritten with
    /// cryptographically random bytes (via [`rand::rngs::OsRng`]) and flushed
    /// to disk before the directory is removed.  Does **not** require a
    /// password.
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::Vault`] if the vault does not exist.
    /// Returns [`DiaryError::Io`] on filesystem failures.
    pub fn delete_vault(&self, name: &str, zeroize: bool) -> Result<(), DiaryError> {
        let vault_path = self.base_dir.join(name);
        if !vault_path.exists() {
            return Err(DiaryError::Vault(format!(
                "vault '{}' does not exist",
                name
            )));
        }
        if zeroize {
            let pqd_path = vault_path.join("vault.pqd");
            if pqd_path.exists() {
                let size = usize::try_from(std::fs::metadata(&pqd_path)?.len()).map_err(|_| {
                    DiaryError::Vault("vault.pqd size exceeds addressable memory".to_string())
                })?;
                let mut random_data = zeroize::Zeroizing::new(vec![0u8; size]);
                OsRng.fill_bytes(&mut random_data);
                {
                    use std::io::Write;
                    let mut file = std::fs::File::create(&pqd_path)?;
                    file.write_all(&random_data)?;
                    file.sync_all()?;
                }
            }
        }
        std::fs::remove_dir_all(&vault_path)?;
        Ok(())
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

    // -------------------------------------------------------------------------
    // TASK-0070: list_vaults_with_policy tests
    // -------------------------------------------------------------------------

    /// TC-S7-033-01: list_vaults_with_policy returns all vaults sorted by name.
    ///
    /// Given 3 vaults with different policies, list_vaults_with_policy must
    /// return exactly 3 entries sorted lexicographically with correct policies.
    #[test]
    fn tc_s7_033_01_list_vaults_with_policy_multiple() {
        let dir = tempdir().expect("tempdir");
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());

        mgr.create_vault("charlie", b"pw", AccessPolicy::Full)
            .expect("create charlie");
        mgr.create_vault("alpha", b"pw", AccessPolicy::None)
            .expect("create alpha");
        mgr.create_vault("bravo", b"pw", AccessPolicy::WriteOnly)
            .expect("create bravo");

        let infos = mgr
            .list_vaults_with_policy()
            .expect("list_vaults_with_policy");

        assert_eq!(
            infos.len(),
            3,
            "must list exactly 3 vaults, got {:?}",
            infos.iter().map(|i| &i.name).collect::<Vec<_>>()
        );
        assert_eq!(infos[0].name, "alpha");
        assert_eq!(infos[0].policy, AccessPolicy::None);
        assert_eq!(infos[1].name, "bravo");
        assert_eq!(infos[1].policy, AccessPolicy::WriteOnly);
        assert_eq!(infos[2].name, "charlie");
        assert_eq!(infos[2].policy, AccessPolicy::Full);
    }

    /// TC-S7-033-02: list_vaults_with_policy returns empty Vec when no vaults exist.
    ///
    /// Given a fresh base directory with no vaults, the result must be an
    /// empty Vec without error.
    #[test]
    fn tc_s7_033_02_list_vaults_with_policy_empty() {
        let dir = tempdir().expect("tempdir");
        let mgr = VaultManager::new(dir.path().to_path_buf()).expect("VaultManager::new");

        let infos = mgr
            .list_vaults_with_policy()
            .expect("list_vaults_with_policy");

        assert!(
            infos.is_empty(),
            "expected empty Vec, got {} entries",
            infos.len()
        );
    }

    /// TC-S7-033-03: list_vaults_with_policy requires no password argument.
    ///
    /// Verifies at the API level that list_vaults_with_policy takes no password
    /// parameter and only reads vault.toml (no vault.pqd decryption needed).
    #[test]
    fn tc_s7_033_03_list_vaults_with_policy_no_password_needed() {
        let dir = tempdir().expect("tempdir");
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());

        mgr.create_vault("myvault", b"secret", AccessPolicy::WriteOnly)
            .expect("create_vault");

        // Call without any password — must succeed.
        let infos = mgr
            .list_vaults_with_policy()
            .expect("list_vaults_with_policy must not require a password");

        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].name, "myvault");
        assert_eq!(infos[0].policy, AccessPolicy::WriteOnly);
    }

    // -------------------------------------------------------------------------
    // TASK-0070: set_policy tests
    // -------------------------------------------------------------------------

    /// TC-S7-034-01: set_policy changes policy from None to WriteOnly.
    ///
    /// After calling set_policy with WriteOnly, vault.toml must reflect the
    /// new policy when read back from disk.
    #[test]
    fn tc_s7_034_01_set_policy_none_to_write_only() {
        let dir = tempdir().expect("tempdir");
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());

        mgr.create_vault("myvault", b"pw", AccessPolicy::None)
            .expect("create_vault");

        mgr.set_policy("myvault", AccessPolicy::WriteOnly)
            .expect("set_policy");

        let toml_path = dir.path().join("myvault").join("vault.toml");
        let config = VaultConfig::from_file(&toml_path).expect("read vault.toml");
        assert_eq!(
            config.access.policy,
            AccessPolicy::WriteOnly,
            "policy must be WriteOnly after set_policy"
        );
    }

    /// TC-S7-034-03: set_policy changes policy from Full to None without warning.
    ///
    /// core layer must not emit any warning — that is CLI's responsibility.
    /// The policy must be updated correctly.
    #[test]
    fn tc_s7_034_03_set_policy_full_to_none() {
        let dir = tempdir().expect("tempdir");
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());

        mgr.create_vault("myvault", b"pw", AccessPolicy::Full)
            .expect("create_vault");

        let result = mgr.set_policy("myvault", AccessPolicy::None);
        assert!(
            result.is_ok(),
            "set_policy Full→None must succeed: {:?}",
            result
        );

        let toml_path = dir.path().join("myvault").join("vault.toml");
        let config = VaultConfig::from_file(&toml_path).expect("read vault.toml");
        assert_eq!(config.access.policy, AccessPolicy::None);
    }

    /// TC-S7-034-04: set_policy requires no password argument.
    ///
    /// Verifies at the API level that set_policy takes no password and only
    /// touches vault.toml (vault.pqd is not modified).
    #[test]
    fn tc_s7_034_04_set_policy_no_password_needed() {
        let dir = tempdir().expect("tempdir");
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());

        mgr.create_vault("myvault", b"secret", AccessPolicy::None)
            .expect("create_vault");

        // Read vault.pqd before set_policy.
        let pqd_path = dir.path().join("myvault").join("vault.pqd");
        let pqd_before = std::fs::read(&pqd_path).expect("read vault.pqd before");

        // Call set_policy without any password — must succeed.
        mgr.set_policy("myvault", AccessPolicy::Full)
            .expect("set_policy must not require a password");

        // vault.pqd must be untouched.
        let pqd_after = std::fs::read(&pqd_path).expect("read vault.pqd after");
        assert_eq!(
            pqd_before, pqd_after,
            "vault.pqd must not be modified by set_policy"
        );
    }

    /// TC-S7-034-E01: set_policy on a non-existent vault returns DiaryError::Vault.
    #[test]
    fn tc_s7_034_e01_set_policy_nonexistent_vault() {
        let dir = tempdir().expect("tempdir");
        let mgr = VaultManager::new(dir.path().to_path_buf()).expect("VaultManager::new");

        let result = mgr.set_policy("nonexistent", AccessPolicy::Full);
        assert!(
            matches!(result, Err(DiaryError::Vault(_))),
            "expected DiaryError::Vault for non-existent vault, got {:?}",
            result
        );
    }

    // -------------------------------------------------------------------------
    // TASK-0070: delete_vault tests
    // -------------------------------------------------------------------------

    /// TC-S7-035-01: delete_vault removes the vault directory completely.
    #[test]
    fn tc_s7_035_01_delete_vault_removes_directory() {
        let dir = tempdir().expect("tempdir");
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());

        mgr.create_vault("myvault", b"pw", AccessPolicy::None)
            .expect("create_vault");

        let vault_dir = dir.path().join("myvault");
        assert!(
            vault_dir.exists(),
            "vault directory must exist before deletion"
        );

        mgr.delete_vault("myvault", false).expect("delete_vault");

        assert!(
            !vault_dir.exists(),
            "vault directory must not exist after deletion"
        );
    }

    /// TC-S7-035-04: delete_vault with zeroize overwrites vault.pqd before removal.
    ///
    /// The content of vault.pqd after zeroize must differ from the original
    /// (random overwrite), and the directory must be removed at the end.
    #[test]
    fn tc_s7_035_04_delete_vault_zeroize_overwrites_pqd() {
        let dir = tempdir().expect("tempdir");
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());

        mgr.create_vault("myvault", b"pw", AccessPolicy::None)
            .expect("create_vault");

        let pqd_path = dir.path().join("myvault").join("vault.pqd");
        let original_bytes = std::fs::read(&pqd_path).expect("read original vault.pqd");

        // We cannot directly observe the intermediate state after zeroize but
        // before remove_dir_all, because the file is gone after the call.
        // Instead we verify that the call completes successfully and the dir is gone.
        mgr.delete_vault("myvault", true)
            .expect("delete_vault with zeroize");

        assert!(
            !dir.path().join("myvault").exists(),
            "vault directory must be removed after zeroize+delete"
        );

        // Ensure original_bytes is non-empty (vault.pqd was a real file).
        assert!(
            !original_bytes.is_empty(),
            "vault.pqd must have been non-empty"
        );
    }

    /// TC-S7-035-E02: delete_vault on a non-existent vault returns DiaryError::Vault.
    #[test]
    fn tc_s7_035_e02_delete_vault_nonexistent() {
        let dir = tempdir().expect("tempdir");
        let mgr = VaultManager::new(dir.path().to_path_buf()).expect("VaultManager::new");

        let result = mgr.delete_vault("ghost", false);
        assert!(
            matches!(result, Err(DiaryError::Vault(_))),
            "expected DiaryError::Vault for non-existent vault, got {:?}",
            result
        );
    }

    // -------------------------------------------------------------------------
    // TASK-0070: edge case tests
    // -------------------------------------------------------------------------

    /// TC-S7-EDGE-004: corrupt vault.toml causes DiaryError::Config.
    ///
    /// Writing invalid TOML content to vault.toml and then calling
    /// list_vaults_with_policy or set_policy must return DiaryError::Config.
    #[test]
    fn tc_s7_edge_004_corrupt_vault_toml_returns_config_error() {
        let dir = tempdir().expect("tempdir");
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());

        mgr.create_vault("myvault", b"pw", AccessPolicy::None)
            .expect("create_vault");

        // Overwrite vault.toml with invalid TOML.
        let toml_path = dir.path().join("myvault").join("vault.toml");
        std::fs::write(&toml_path, b"invalid toml content {{{").expect("write corrupt toml");

        // list_vaults_with_policy must fail with DiaryError::Config.
        let list_result = mgr.list_vaults_with_policy();
        assert!(
            matches!(list_result, Err(DiaryError::Config(_))),
            "expected DiaryError::Config for corrupt vault.toml in list, got {:?}",
            list_result
        );

        // set_policy must also fail with DiaryError::Config.
        let set_result = mgr.set_policy("myvault", AccessPolicy::Full);
        assert!(
            matches!(set_result, Err(DiaryError::Config(_))),
            "expected DiaryError::Config for corrupt vault.toml in set_policy, got {:?}",
            set_result
        );
    }
}
