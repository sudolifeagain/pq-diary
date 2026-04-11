//! vault.toml and config.toml serde structs.
//!
//! Provides `VaultConfig` (per-vault settings stored in `vault.toml`) and
//! `AppConfig` (application-wide settings stored in `config.toml`) with
//! TOML serialisation/deserialisation and file I/O helpers.

use serde::{Deserialize, Serialize};
use std::path::Path;

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

/// Top-level structure for `config.toml`.
///
/// Contains application-wide defaults and background-daemon settings.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AppConfig {
    /// Default vault and editor settings.
    pub defaults: DefaultsSection,
    /// Background daemon settings.
    pub daemon: DaemonSection,
}

/// `[defaults]` section of `config.toml`.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct DefaultsSection {
    /// Default vault name used when `--vault` is not specified.
    pub vault: String,
}

/// `[daemon]` section of `config.toml`.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct DaemonSection {
    /// Directory that holds the daemon Unix-domain socket.
    pub socket_dir: String,
    /// Session inactivity timeout in seconds (vault auto-locks after this).
    pub timeout_secs: u64,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            defaults: DefaultsSection {
                vault: "default".to_owned(),
            },
            daemon: DaemonSection {
                socket_dir: "~/.pq-diary/run".to_owned(),
                timeout_secs: 300,
            },
        }
    }
}

impl AppConfig {
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

    /// Serialise this [`AppConfig`] as pretty TOML and write it to `path`.
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
}
