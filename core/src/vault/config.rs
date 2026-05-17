//! vault.toml and config.toml serde structs.
//!
//! Provides `VaultConfig` (per-vault settings stored in `vault.toml`) and
//! `AppConfig` (application-wide settings stored in `config.toml`) with
//! TOML serialisation/deserialisation and file I/O helpers.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::error::DiaryError;
use crate::policy::AccessPolicy;

// =============================================================================
// VaultConfig — vault.toml
// =============================================================================

/// Top-level structure for `vault.toml`.
///
/// Contains per-vault metadata, access-control policy, Git integration
/// settings, and Argon2id KDF parameters.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct VaultConfig {
    /// Basic vault settings.
    pub vault: VaultSection,
    /// Access-control settings.
    pub access: AccessSection,
    /// Git integration settings.
    pub git: GitSection,
    /// Argon2id KDF parameters.
    pub argon2: Argon2Section,
}

/// `[vault]` section of `vault.toml`.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct VaultSection {
    /// Vault name (matches the directory name under `~/.pq-diary/vaults/`).
    pub name: String,
    /// Schema version; must equal the `SCHEMA_VERSION` constant in `format.rs`.
    pub schema_version: u32,
}

/// `[access]` section of `vault.toml`.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AccessSection {
    /// Access policy controlling what Claude is permitted to do with this vault.
    pub policy: AccessPolicy,
}

/// `[git]` section of `vault.toml`.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct GitSection {
    /// Git commit author name.
    pub author_name: String,
    /// Git commit author email.
    pub author_email: String,
    /// Git commit message template.
    pub commit_message: String,
    /// Git privacy settings (timestamp fuzzing, extra padding).
    pub privacy: GitPrivacySection,
}

/// `[git.privacy]` section of `vault.toml`.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct GitPrivacySection {
    /// Timestamp fuzz range in hours (0 disables fuzzing).
    pub timestamp_fuzz_hours: u64,
    /// Maximum extra padding bytes added per commit (0 disables padding).
    pub extra_padding_bytes_max: usize,
}

/// `[argon2]` section of `vault.toml`.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Argon2Section {
    /// Memory cost in kilobytes (OWASP recommended: ≥ 64 MB = 65536 KB).
    pub memory_cost_kb: u32,
    /// Time cost (number of iterations; OWASP recommended: ≥ 3).
    pub time_cost: u32,
    /// Parallelism degree.
    pub parallelism: u32,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            vault: VaultSection {
                name: "default".to_owned(),
                schema_version: 4,
            },
            access: AccessSection {
                policy: AccessPolicy::None,
            },
            git: GitSection {
                author_name: String::new(),
                author_email: String::new(),
                commit_message: "Update vault".to_owned(),
                privacy: GitPrivacySection {
                    timestamp_fuzz_hours: 0,
                    extra_padding_bytes_max: 0,
                },
            },
            argon2: Argon2Section {
                memory_cost_kb: 65536,
                time_cost: 3,
                parallelism: 1,
            },
        }
    }
}

impl VaultConfig {
    /// Read and deserialise a [`VaultConfig`] from a TOML file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::Io`] on file-read failures and
    /// [`DiaryError::Config`] on TOML parse errors.
    pub fn from_file(path: &Path) -> Result<Self, DiaryError> {
        let content = std::fs::read_to_string(path)?;
        toml::from_str(&content).map_err(|e| DiaryError::Config(e.to_string()))
    }

    /// Serialise this [`VaultConfig`] as pretty TOML and write it to `path`.
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::Config`] on serialisation failures and
    /// [`DiaryError::Io`] on file-write failures.
    pub fn to_file(&self, path: &Path) -> Result<(), DiaryError> {
        let content =
            toml::to_string_pretty(self).map_err(|e| DiaryError::Config(e.to_string()))?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

// =============================================================================
// AppConfig — config.toml
// =============================================================================

/// Application-wide configuration stored in `~/.pq-diary/config.toml`.
///
/// Created by the `init` command and consulted by `sync`, `info`, and other
/// top-level commands. Contains the default vault name and the sync backend
/// identifier.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AppConfig {
    /// `[app]` section.
    pub app: AppSection,
}

/// `[app]` section of `config.toml`.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AppSection {
    /// Vault name used when `--vault` is not given on the command line.
    pub default_vault: String,
    /// Identifier of the sync backend (currently `"git"`; future values may
    /// include `"socket"`, `"kms"`, etc.).
    pub sync_backend: String,
}

impl Default for AppConfig {
    /// Returns the default configuration:
    /// `default_vault = "default"`, `sync_backend = "git"`.
    fn default() -> Self {
        Self {
            app: AppSection {
                default_vault: "default".to_owned(),
                sync_backend: "git".to_owned(),
            },
        }
    }
}

impl AppConfig {
    /// Resolve the directory that contains `config.toml` and `vaults/`.
    ///
    /// When the `PQ_DIARY_HOME` environment variable is set its value is
    /// returned as the configuration root verbatim (so tests can redirect
    /// the layout to a temporary directory). Otherwise the function falls
    /// back to `<home>/.pq-diary` via [`dirs::home_dir`].
    fn config_root() -> Result<PathBuf, DiaryError> {
        if let Some(override_root) = std::env::var_os("PQ_DIARY_HOME") {
            return Ok(PathBuf::from(override_root));
        }
        let home = dirs::home_dir()
            .ok_or_else(|| DiaryError::Config("Cannot determine home directory".to_string()))?;
        Ok(home.join(".pq-diary"))
    }

    /// Absolute path to the default application config file
    /// (`~/.pq-diary/config.toml`).
    ///
    /// `PQ_DIARY_HOME` overrides the `~/.pq-diary` prefix when set; the
    /// `config.toml` file name is always appended.
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::Config`] when the user's home directory cannot
    /// be determined (i.e. [`dirs::home_dir`] returns `None`).
    pub fn default_path() -> Result<PathBuf, DiaryError> {
        Ok(Self::config_root()?.join("config.toml"))
    }

    /// Absolute path to the directory that holds individual vaults
    /// (`~/.pq-diary/vaults/`).
    ///
    /// `PQ_DIARY_HOME` overrides the `~/.pq-diary` prefix when set; the
    /// `vaults` subdirectory is always appended.
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::Config`] when the user's home directory cannot
    /// be determined.
    pub fn default_vaults_dir() -> Result<PathBuf, DiaryError> {
        Ok(Self::config_root()?.join("vaults"))
    }

    /// Read and deserialise an [`AppConfig`] from a TOML file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::Io`] on file-read failures and
    /// [`DiaryError::Config`] on TOML parse errors.
    pub fn from_file(path: &Path) -> Result<Self, DiaryError> {
        let content = std::fs::read_to_string(path)?;
        toml::from_str(&content).map_err(|e| DiaryError::Config(e.to_string()))
    }

    /// Serialise this [`AppConfig`] as TOML and write it to `path`.
    ///
    /// On Unix the file permission is set to `0o600` after writing so that
    /// only the owner can read or modify the configuration (REQ-611).
    /// On Windows the default ACL (owner-only by default in the user's
    /// home directory) is left untouched.
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::Config`] on TOML serialisation failures and
    /// [`DiaryError::Io`] on file-write or permission-set failures.
    pub fn to_file(&self, path: &Path) -> Result<(), DiaryError> {
        let content = toml::to_string(self).map_err(|e| DiaryError::Config(e.to_string()))?;
        std::fs::write(path, content)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
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

    /// TC-004-01: VaultConfig serialise → deserialise roundtrip.
    ///
    /// Given a VaultConfig instance, when serialised to a TOML string and
    /// then deserialised, the result must equal the original.
    #[test]
    fn test_vault_config_roundtrip() {
        let config = VaultConfig::default();
        let toml_str = toml::to_string_pretty(&config).expect("serialise");
        let restored: VaultConfig = toml::from_str(&toml_str).expect("deserialise");
        assert_eq!(config, restored);
    }

    /// TC-004-02: VaultConfig::default() returns expected default values.
    ///
    /// Given no input, VaultConfig::default() must produce deterministic,
    /// sensible values matching the project-wide recommendations.
    #[test]
    fn test_vault_config_default_values() {
        let config = VaultConfig::default();
        assert_eq!(config.vault.name, "default");
        assert_eq!(config.vault.schema_version, 4);
        assert_eq!(config.access.policy, AccessPolicy::None);
        assert!(!config.git.commit_message.is_empty());
        assert_eq!(config.argon2.memory_cost_kb, 65536);
        assert_eq!(config.argon2.time_cost, 3);
        assert_eq!(config.argon2.parallelism, 1);
    }

    /// TC-005-01: AppConfig serialise → deserialise roundtrip.
    ///
    /// Given an AppConfig instance, when serialised to a TOML string and
    /// then deserialised, the result must equal the original.
    #[test]
    fn test_app_config_roundtrip() {
        let config = AppConfig::default();
        let toml_str = toml::to_string_pretty(&config).expect("serialise");
        let restored: AppConfig = toml::from_str(&toml_str).expect("deserialise");
        assert_eq!(config, restored);
    }

    /// TC-S7-001-07: S6-era vault.toml strings deserialise to the correct AccessPolicy variants.
    ///
    /// Verifies backward compatibility: pre-S7 vault.toml files that store the
    /// policy as a plain string ("none", "write_only", "full") are correctly
    /// deserialised by serde's rename_all = "snake_case" mapping.
    #[test]
    fn tc_s7_001_07_backward_compat_string_to_access_policy() {
        // "none" → AccessPolicy::None
        let toml_none = r#"
[vault]
name = "old-vault"
schema_version = 4

[access]
policy = "none"

[git]
author_name = ""
author_email = ""
commit_message = "Update vault"

[git.privacy]
timestamp_fuzz_hours = 0
extra_padding_bytes_max = 0

[argon2]
memory_cost_kb = 65536
time_cost = 3
parallelism = 1
"#;
        let config: VaultConfig = toml::from_str(toml_none).expect("parse none");
        assert_eq!(config.access.policy, AccessPolicy::None);

        // "write_only" → AccessPolicy::WriteOnly
        let toml_wo = toml_none.replace(r#"policy = "none""#, r#"policy = "write_only""#);
        let config_wo: VaultConfig = toml::from_str(&toml_wo).expect("parse write_only");
        assert_eq!(config_wo.access.policy, AccessPolicy::WriteOnly);

        // "full" → AccessPolicy::Full
        let toml_full = toml_none.replace(r#"policy = "none""#, r#"policy = "full""#);
        let config_full: VaultConfig = toml::from_str(&toml_full).expect("parse full");
        assert_eq!(config_full.access.policy, AccessPolicy::Full);
    }

    /// TC-004-E01: from_file with invalid TOML returns DiaryError::Config.
    ///
    /// Given a file containing malformed TOML, from_file must return
    /// DiaryError::Config (not a panic or DiaryError::Io).
    #[test]
    fn test_invalid_toml_returns_config_error() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "pq_diary_test_invalid_{}.toml",
            uuid::Uuid::new_v4()
        ));

        std::fs::write(&path, b"this is [[[not valid toml content").expect("write temp file");
        let result = VaultConfig::from_file(&path);
        let _ = std::fs::remove_file(&path);

        assert!(
            matches!(result, Err(DiaryError::Config(_))),
            "expected DiaryError::Config, got {:?}",
            result
        );
    }

    // -------------------------------------------------------------------------
    // TASK-0087: AppConfig (~/.pq-diary/config.toml) tests
    // -------------------------------------------------------------------------

    /// TC-S10-087-01: AppConfig::default() returns the documented default values.
    ///
    /// REQ-602: `default_vault` must be `"default"`.
    /// REQ-603: `sync_backend` must be `"git"`.
    #[test]
    fn tc_s10_087_01_app_config_default_values() {
        let config = AppConfig::default();
        assert_eq!(config.app.default_vault, "default");
        assert_eq!(config.app.sync_backend, "git");
    }

    /// TC-S10-087-02: to_file followed by from_file round-trips an AppConfig.
    ///
    /// Given an AppConfig written to a temporary file, when it is read back
    /// from the same path, the result must equal the original.
    #[test]
    fn tc_s10_087_02_app_config_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");

        let original = AppConfig::default();
        original.to_file(&path).expect("to_file");
        let restored = AppConfig::from_file(&path).expect("from_file");

        assert_eq!(original, restored);
    }

    /// TC-S10-087-03: default_path() returns a path ending in `.pq-diary/config.toml`.
    ///
    /// The exact prefix depends on the user's home directory (via
    /// `dirs::home_dir()`), so we only verify the trailing components.
    #[test]
    fn tc_s10_087_03_default_path_format() {
        let path = AppConfig::default_path().expect("default_path");
        assert!(
            path.ends_with(std::path::Path::new(".pq-diary").join("config.toml")),
            "expected path ending in `.pq-diary/config.toml`, got {:?}",
            path
        );
    }

    /// TC-S10-087-04: default_vaults_dir() returns a path ending in `.pq-diary/vaults`.
    #[test]
    fn tc_s10_087_04_default_vaults_dir_format() {
        let path = AppConfig::default_vaults_dir().expect("default_vaults_dir");
        assert!(
            path.ends_with(std::path::Path::new(".pq-diary").join("vaults")),
            "expected path ending in `.pq-diary/vaults`, got {:?}",
            path
        );
    }

    /// TC-S10-087-05: from_file with invalid TOML content returns DiaryError::Config.
    ///
    /// EDGE-005: Malformed config.toml must be rejected with a `Config`
    /// error (not a panic or `Io` error).
    #[test]
    fn tc_s10_087_05_invalid_toml() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, b"this is not valid = toml [").expect("write temp file");

        let result = AppConfig::from_file(&path);
        assert!(
            matches!(result, Err(DiaryError::Config(_))),
            "expected DiaryError::Config, got {:?}",
            result
        );
    }

    /// TC-S10-087-06: to_file on Unix sets file permission to 0o600.
    ///
    /// REQ-611: config.toml must be readable/writable only by the owner.
    #[cfg(unix)]
    #[test]
    fn tc_s10_087_06_unix_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        AppConfig::default().to_file(&path).expect("to_file");

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "expected file permission 0o600, got {:o}",
            mode
        );
    }
}
