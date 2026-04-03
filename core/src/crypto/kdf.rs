//! Argon2id key derivation.
//!
//! Derives a 32-byte master key from a password and salt using Argon2id.
//! Password strength parameters are validated against OWASP minimum thresholds.

use crate::{crypto::secure_mem::ZeroizingKey, error::DiaryError};
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroize;

/// Parameters for Argon2id key derivation.
///
/// Default values follow OWASP recommendations:
/// - `memory_cost_kb`: 65536 (64 MiB)
/// - `time_cost`: 3
/// - `parallelism`: 4
///
/// Minimum security thresholds (below → warning):
/// - `memory_cost_kb` >= 19456
/// - `time_cost` >= 2
pub struct Argon2Params {
    /// Memory cost in KiB (default: 65536 = 64 MiB).
    pub memory_cost_kb: u32,
    /// Number of iterations (default: 3).
    pub time_cost: u32,
    /// Degree of parallelism (default: 4).
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_cost_kb: 65536,
            time_cost: 3,
            parallelism: 4,
        }
    }
}

/// Derive a 32-byte master key from a password and salt using Argon2id.
///
/// Returns [`DiaryError::Password`] if the password is empty.
/// Returns [`DiaryError::Crypto`] if Argon2id parameter construction or hashing fails.
pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    params: &Argon2Params,
) -> Result<ZeroizingKey, DiaryError> {
    if password.is_empty() {
        return Err(DiaryError::Password("password must not be empty".into()));
    }

    let argon2_params = Params::new(
        params.memory_cost_kb,
        params.time_cost,
        params.parallelism,
        Some(32),
    )
    .map_err(|e| DiaryError::Crypto(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut key_bytes = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut key_bytes)
        .map_err(|e| DiaryError::Crypto(e.to_string()))?;

    let key = ZeroizingKey::new(key_bytes);
    key_bytes.zeroize();
    Ok(key)
}

/// Validate Argon2id parameters against minimum security thresholds.
///
/// Returns a list of warning messages for each parameter that falls below the minimum.
/// Returns an empty `Vec` if all parameters meet the requirements.
pub fn validate_params(params: &Argon2Params) -> Vec<String> {
    let mut warnings = Vec::new();

    if params.memory_cost_kb < 19456 {
        warnings.push(format!(
            "memory_cost_kb ({}) is below the minimum recommended value of 19456",
            params.memory_cost_kb
        ));
    }

    if params.time_cost < 2 {
        warnings.push(format!(
            "time_cost ({}) is below the minimum recommended value of 2",
            params.time_cost
        ));
    }

    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fast parameters for unit tests (avoids slow Argon2id in CI).
    fn fast_params() -> Argon2Params {
        Argon2Params {
            memory_cost_kb: 8,
            time_cost: 1,
            parallelism: 1,
        }
    }

    /// TC-002-01: same password + salt + params → identical key.
    #[test]
    fn tc_002_01_same_password_same_key() {
        let params = fast_params();
        let password = b"test-password";
        let salt = b"test-salt-16byte";

        let key1 = derive_key(password, salt, &params).unwrap();
        let key2 = derive_key(password, salt, &params).unwrap();

        assert_eq!(key1.as_ref(), key2.as_ref());
    }

    /// TC-002-02: different passwords → different keys.
    #[test]
    fn tc_002_02_different_passwords_different_keys() {
        let params = fast_params();
        let salt = b"test-salt-16byte";

        let key1 = derive_key(b"password-one!!!", salt, &params).unwrap();
        let key2 = derive_key(b"password-two!!!", salt, &params).unwrap();

        assert_ne!(key1.as_ref(), key2.as_ref());
    }

    /// TC-002-03: different salts → different keys.
    #[test]
    fn tc_002_03_different_salts_different_keys() {
        let params = fast_params();
        let password = b"test-password";

        let key1 = derive_key(password, b"salt-one-16bytes", &params).unwrap();
        let key2 = derive_key(password, b"salt-two-16bytes", &params).unwrap();

        assert_ne!(key1.as_ref(), key2.as_ref());
    }

    /// TC-002-04: output key is exactly 32 bytes.
    #[test]
    fn tc_002_04_output_is_32_bytes() {
        let params = fast_params();
        let key = derive_key(b"password", b"salt-for-testing", &params).unwrap();
        assert_eq!(key.as_ref().len(), 32);
    }

    /// TC-002-E01: empty password → DiaryError::Password.
    #[test]
    fn tc_002_e01_empty_password() {
        let params = fast_params();
        let result = derive_key(b"", b"salt-for-testing", &params);
        assert!(matches!(result, Err(DiaryError::Password(_))));
    }

    /// TC-002-E02: memory_cost_kb < 19456 → warning list is non-empty.
    #[test]
    fn tc_002_e02_low_memory_cost_warns() {
        let params = Argon2Params {
            memory_cost_kb: 10000,
            time_cost: 3,
            parallelism: 4,
        };
        let warnings = validate_params(&params);
        assert!(!warnings.is_empty());
    }

    /// Default params produce no warnings.
    #[test]
    fn validate_params_default_no_warnings() {
        let warnings = validate_params(&Argon2Params::default());
        assert!(warnings.is_empty());
    }

    /// time_cost < 2 → warning.
    #[test]
    fn validate_params_low_time_cost_warns() {
        let params = Argon2Params {
            memory_cost_kb: 65536,
            time_cost: 1,
            parallelism: 4,
        };
        let warnings = validate_params(&params);
        assert!(!warnings.is_empty());
    }

    /// Both below threshold → two warnings.
    #[test]
    fn validate_params_both_low_gives_two_warnings() {
        let params = Argon2Params {
            memory_cost_kb: 1024,
            time_cost: 1,
            parallelism: 1,
        };
        let warnings = validate_params(&params);
        assert_eq!(warnings.len(), 2);
    }
}
