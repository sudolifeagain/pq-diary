//! Password strength policy (audit High-2).
//!
//! The whole vault's confidentiality rests on the master password feeding
//! Argon2id, so a weak password defeats every other control regardless of how
//! quantum-resistant the primitives are. This module provides a *pure*
//! evaluation of a candidate password; the `cli/` crate displays it at every
//! point where a user *chooses* a password (`vault create`, `init`,
//! `change-password`). Existing passwords are never re-evaluated — only newly
//! chosen ones — so upgrading the binary never locks anyone out.
//!
//! The policy is intentionally minimal and offline (no breach-corpus lookup):
//! a recommended length floor plus a small list of trivially-guessable
//! passwords are marked weak. It intentionally avoids composition rules.

/// Recommended password length in Unicode scalar values (NIST SP 800-63B
/// Rev.4 single-factor password floor for user-chosen secrets).
pub const RECOMMENDED_MIN_LENGTH: usize = 15;

/// A small blacklist of trivially-guessable passwords, compared
/// case-insensitively. These are marked weak.
const COMMON_PASSWORDS: &[&str] = &[
    "password",
    "password1",
    "passw0rd",
    "12345678",
    "123456789",
    "1234567890",
    "qwerty123",
    "qwertyuiop",
    "iloveyou",
    "admin123",
    "letmein1",
    "11111111",
    "00000000",
    "welcome1",
    "abc12345",
    "changeme",
    "passwordpassword",
    "qwertyqwertyqwerty",
];

/// Coarse password strength displayed by the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strength {
    /// The password is usable if the user explicitly accepts the risk, but it
    /// is not recommended for a pq-diary vault.
    Weak,
    /// The password meets the local recommendation.
    Recommended,
}

impl Strength {
    /// User-facing label for CLI output.
    pub fn label(self) -> &'static str {
        match self {
            Strength::Weak => "weak",
            Strength::Recommended => "recommended",
        }
    }

    /// Whether this strength needs a non-recommended warning.
    pub fn is_weak(self) -> bool {
        matches!(self, Strength::Weak)
    }
}

/// Result of evaluating a candidate password against the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    /// Coarse strength displayed by the CLI.
    pub strength: Strength,
    /// Non-fatal advisories explaining weak ratings.
    pub warnings: Vec<String>,
}

/// Evaluate `password` against the strength policy.
///
/// This never mutates or stores the password and performs no allocation beyond
/// the returned advisory strings. Length is measured in Unicode scalar values
/// so multi-byte (e.g. Japanese) passwords are not unfairly penalised.
pub fn assess(password: &str) -> Assessment {
    let len = password.chars().count();
    let mut warnings = Vec::new();

    if len < RECOMMENDED_MIN_LENGTH {
        warnings.push(format!(
            "shorter than recommended — use at least {RECOMMENDED_MIN_LENGTH} characters (got {len})"
        ));
    }

    // Trivially-guessable passwords are marked weak regardless of length.
    let lowered = password.to_lowercase();
    if COMMON_PASSWORDS.contains(&lowered.as_str()) {
        warnings.push("this is a commonly-used password and is trivially guessable".to_string());
    }

    let strength = if warnings.is_empty() {
        Strength::Recommended
    } else {
        Strength::Weak
    };

    Assessment { strength, warnings }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TC-PWPOL-01: a password below the recommendation is marked weak.
    #[test]
    fn tc_pwpol_01_short_password_is_weak() {
        let a = assess("FourteenChars!"); // 14 chars
        assert_eq!(a.strength, Strength::Weak, "14-char password is weak");
        assert!(
            a.warnings
                .iter()
                .any(|w| w.contains("shorter than recommended")),
            "expected a length advisory, got {:?}",
            a.warnings
        );
    }

    /// TC-PWPOL-02: exactly RECOMMENDED_MIN_LENGTH clears the recommendation.
    #[test]
    fn tc_pwpol_02_recommended_min_length() {
        let a = assess("FifteenChars!!?"); // 15 chars
        assert_eq!(a.strength, Strength::Recommended);
        assert!(
            a.warnings.is_empty(),
            "must not warn at the recommendation: {:?}",
            a.warnings
        );
    }

    /// TC-PWPOL-03: composition rules are not applied to accepted passwords.
    #[test]
    fn tc_pwpol_03_single_class_accepted_without_advisory() {
        let a = assess("abcdefghijklmnop"); // 16 lowercase
        assert_eq!(a.strength, Strength::Recommended);
        assert!(
            a.warnings.is_empty(),
            "composition rules must not produce advisories, got {:?}",
            a.warnings
        );
    }

    /// TC-PWPOL-04: a passphrase longer than the recommendation is recommended.
    #[test]
    fn tc_pwpol_04_long_passphrase_accepted() {
        let a = assess("correct horse staple phrase");
        assert_eq!(a.strength, Strength::Recommended);
        assert!(a.warnings.is_empty(), "got {:?}", a.warnings);
    }

    /// TC-PWPOL-05: a recommended long password produces no warnings.
    #[test]
    fn tc_pwpol_05_strong_password_no_warnings() {
        let a = assess("Tr0ub4dour&3xtra");
        assert_eq!(a.strength, Strength::Recommended);
        assert!(
            a.warnings.is_empty(),
            "strong password must have no advisories, got {:?}",
            a.warnings
        );
    }

    /// TC-PWPOL-06: a blacklisted password is weak even when long enough.
    #[test]
    fn tc_pwpol_06_common_password_is_weak() {
        for pw in ["password", "PASSWORDPASSWORD", "qwertyqwertyqwerty"] {
            let a = assess(pw);
            assert_eq!(a.strength, Strength::Weak, "{pw:?} must be weak");
        }
    }

    /// TC-PWPOL-07: empty password is weak (callers still reject empty earlier).
    /// special-case empty earlier for a clearer message.
    #[test]
    fn tc_pwpol_07_empty_is_weak() {
        let a = assess("");
        assert_eq!(a.strength, Strength::Weak);
    }

    /// TC-PWPOL-08: a multibyte (Japanese) passphrase is measured by scalar
    /// count, not bytes, so a 15-character phrase clears the 15-char floor.
    #[test]
    fn tc_pwpol_08_multibyte_counts_by_char() {
        let a = assess("安全な長いパスフレーズ試験用語"); // 15 scalar values
        assert_eq!(a.strength, Strength::Recommended);
    }
}
