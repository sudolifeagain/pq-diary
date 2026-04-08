//! Vault format read/write operations.
//!
//! Sub-modules:
//! - [`config`]: TOML configuration types for `vault.toml` and `config.toml`
//! - [`format`]: vault.pqd v4 binary format constants and structures
//! - [`init`]: vault initialisation and [`VaultManager`](init::VaultManager) directory management
//! - [`reader`]: vault.pqd deserialisation (header and entry-record parsing)
//! - [`writer`]: vault.pqd serialisation (header and entry-record writing)

/// Per-vault and application-wide TOML configuration (`vault.toml`, `config.toml`).
pub mod config;
/// vault.pqd v4 binary format constants and structures.
pub mod format;
/// Vault initialisation and [`VaultManager`](init::VaultManager) directory management.
pub mod init;
/// vault.pqd deserialisation: header and entry-record parsing.
pub mod reader;
/// vault.pqd serialisation: header and entry-record writing.
pub mod writer;

// =============================================================================
// Integration tests — TASK-0026 (E2E + performance)
// =============================================================================

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use crate::crypto::kdf;
    use crate::vault::{
        config::VaultConfig, format::SCHEMA_VERSION, init::VaultManager, reader::read_vault,
    };

    /// Fast Argon2id parameters — avoids the slow 64 MiB default during tests.
    fn fast_params() -> kdf::Argon2Params {
        kdf::Argon2Params {
            memory_cost_kb: 8,
            time_cost: 1,
            parallelism: 1,
        }
    }

    /// TC-026-01: E2E test — init_vault → write_vault → read_vault, all fields match.
    ///
    /// Calls `VaultManager::init_vault` (which internally calls `write_vault`),
    /// then reads the resulting `vault.pqd` back with `read_vault` and verifies
    /// that every header field is well-formed and consistent with the initialisation
    /// parameters.  Also verifies that `vault.toml` is parseable and contains the
    /// correct vault name.
    #[test]
    fn tc_026_01_e2e_init_write_read() {
        let dir = tempdir().expect("tempdir");
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());

        let password = b"e2e-test-password";
        mgr.init_vault("e2e_vault", password)
            .expect("init_vault must succeed");

        // Read the vault.pqd file back.
        let vault_pqd = dir.path().join("e2e_vault").join("vault.pqd");
        let (header, entries) = read_vault(&vault_pqd).expect("read_vault must succeed");

        // Schema version must be current.
        assert_eq!(
            header.schema_version, SCHEMA_VERSION,
            "schema_version must equal SCHEMA_VERSION"
        );

        // Flags are reserved and must be 0.
        assert_eq!(header.flags, 0, "flags must be 0 (reserved)");

        // Salts are randomly generated — verify they are non-zero.
        assert_ne!(
            header.kdf_salt, [0u8; 32],
            "kdf_salt must be randomly generated (non-zero)"
        );
        assert_ne!(
            header.legacy_salt, [0u8; 32],
            "legacy_salt must be randomly generated (non-zero)"
        );

        // Verification token must be present (IV + ciphertext written by init_vault).
        assert!(
            !header.verification_ct.is_empty(),
            "verification_ct must be non-empty after init_vault"
        );

        // Encrypted key material must be present.
        assert!(
            !header.kem_encrypted_sk.is_empty(),
            "kem_encrypted_sk must be non-empty after init_vault"
        );
        assert!(
            !header.dsa_encrypted_sk.is_empty(),
            "dsa_encrypted_sk must be non-empty after init_vault"
        );

        // DSA public-key hash must be non-zero (SHA-256 of the verifying key).
        assert_ne!(
            header.dsa_pk_hash, [0u8; 32],
            "dsa_pk_hash must be non-zero after init_vault"
        );

        // A freshly initialised vault has no entries.
        assert!(entries.is_empty(), "new vault must have zero entries");

        // Verify vault.toml is parseable and contains the correct vault name.
        let vault_toml = dir.path().join("e2e_vault").join("vault.toml");
        let vault_config =
            VaultConfig::from_file(&vault_toml).expect("vault.toml must parse without error");
        assert_eq!(
            vault_config.vault.name, "e2e_vault",
            "vault name in vault.toml must match the name passed to init_vault"
        );
        assert_eq!(
            vault_config.vault.schema_version, 4,
            "schema_version in vault.toml must be 4"
        );
    }

    /// TC-026-02: init_vault performance — completes within 5 seconds (CI-adjusted).
    ///
    /// Measures wall-clock time for `init_vault` with fast Argon2id parameters.
    /// Even with reduced parameters the full pipeline (KDF + KEM keygen + DSA keygen
    /// + AES-GCM encryption + file I/O) must complete in under 5 seconds on any
    /// CI runner.
    #[test]
    fn tc_026_02_init_performance_within_5_seconds() {
        use std::time::Instant;

        let dir = tempdir().expect("tempdir");
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());

        let start = Instant::now();
        mgr.init_vault("perf_vault", b"test-password-for-perf")
            .expect("init_vault must succeed");
        let elapsed = start.elapsed();

        assert!(
            elapsed.as_secs() < 5,
            "init_vault() took {:?}, expected < 5 seconds (CI-adjusted bound)",
            elapsed
        );
    }

    /// vault.toml parse time is below 100 milliseconds.
    ///
    /// A freshly written `vault.toml` file must be readable and deserialisable
    /// in well under 100 ms, satisfying the NFR-002 vault.toml parse performance
    /// requirement.
    #[test]
    fn tc_026_vault_toml_parse_within_100ms() {
        use std::time::Instant;

        let dir = tempdir().expect("tempdir");
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());
        mgr.init_vault("toml_perf_vault", b"password")
            .expect("init_vault must succeed");

        let vault_toml = dir.path().join("toml_perf_vault").join("vault.toml");

        let start = Instant::now();
        VaultConfig::from_file(&vault_toml).expect("vault.toml must parse without error");
        let elapsed = start.elapsed();

        assert!(
            elapsed.as_millis() < 100,
            "vault.toml parse took {:?}, expected < 100ms",
            elapsed
        );
    }
}
