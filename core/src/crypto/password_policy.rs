//! Password strength policy (audit High-2).
//!
//! The whole vault's confidentiality rests on the master password feeding
//! Argon2id, so a weak password defeats every other control regardless of how
//! quantum-resistant the primitives are. This module provides a *pure*
//! evaluation of a candidate password; the `cli/` crate enforces it at every
//! point where a user *chooses* a password (`vault create`, `init`,
//! `change-password`). Existing passwords are never re-evaluated — only newly
//! chosen ones — so upgrading the binary never locks anyone out.
//!
//! The policy is intentionally minimal and offline (no breach-corpus lookup):
//! a hard length floor plus a small list of trivially-guessable passwords are
//! rejected outright; everything else short of the recommendation produces a
//! non-fatal advisory the CLI prints to stderr.

/// Minimum acceptable password length in Unicode scalar values (NIST SP
/// 800-63B floor for user-chosen secrets).
pub const MIN_LENGTH: usize = 8;

/// Recommended minimum length. Passwords between [`MIN_LENGTH`] and this length
/// are accepted but trigger an advisory.
pub const RECOMMENDED_LENGTH: usize = 12;

/// A small blacklist of trivially-guessable passwords, compared
/// case-insensitively. These are rejected outright (`acceptable == false`).
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
];

/// Result of evaluating a candidate password against the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    /// `true` when the password clears the hard policy floor (length +
    /// not-blacklisted). The CLI refuses to proceed when this is `false`.
    pub acceptable: bool,
    /// Non-fatal advisories. Present even when `acceptable` is `true` (e.g. a
    /// 9-character all-lowercase password is accepted but advised against).
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
    let mut acceptable = true;

    if len < MIN_LENGTH {
        acceptable = false;
        warnings.push(format!(
            "too short — use at least {MIN_LENGTH} characters (got {len})"
        ));
    } else if len < RECOMMENDED_LENGTH {
        warnings.push(format!(
            "consider using at least {RECOMMENDED_LENGTH} characters for stronger protection"
        ));
    }

    // Character-class diversity is only advisory and only meaningful once the
    // length floor is met (a short password is rejected on length alone).
    if len >= MIN_LENGTH && character_classes(password) < 2 {
        warnings.push(
            "mix character types (lowercase, uppercase, digits, symbols) for stronger protection"
                .to_string(),
        );
    }

    // Trivially-guessable passwords are rejected regardless of length.
    let lowered = password.to_lowercase();
    if COMMON_PASSWORDS.contains(&lowered.as_str()) {
        acceptable = false;
        warnings.push("this is a commonly-used password and is trivially guessable".to_string());
    }

    Assessment {
        acceptable,
        warnings,
    }
}

/// Count how many of {lowercase, uppercase, digit, other} appear in `s`.
fn character_classes(s: &str) -> u8 {
    let mut lower = false;
    let mut upper = false;
    let mut digit = false;
    let mut other = false;
    for c in s.chars() {
        if c.is_ascii_digit() {
            digit = true;
        } else if c.is_lowercase() {
            lower = true;
        } else if c.is_uppercase() {
            upper = true;
        } else {
            other = true;
        }
    }
    u8::from(lower) + u8::from(upper) + u8::from(digit) + u8::from(other)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TC-PWPOL-01: a password below the floor is rejected with a length warning.
    #[test]
    fn tc_pwpol_01_short_password_rejected() {
        let a = assess("New456!"); // 7 chars
        assert!(!a.acceptable, "7-char password must be rejected");
        assert!(
            a.warnings.iter().any(|w| w.contains("too short")),
            "expected a too-short advisory, got {:?}",
            a.warnings
        );
    }

    /// TC-PWPOL-02: exactly MIN_LENGTH clears the floor.
    #[test]
    fn tc_pwpol_02_min_length_accepted() {
        let a = assess("Test123!"); // 8 chars, 4 classes
        assert!(a.acceptable, "8-char strong password must be accepted");
        assert!(
            a.warnings.is_empty() || !a.warnings.iter().any(|w| w.contains("too short")),
            "must not warn about length at the floor: {:?}",
            a.warnings
        );
    }

    /// TC-PWPOL-03: an accepted-but-short password still advises a longer one.
    #[test]
    fn tc_pwpol_03_below_recommended_warns_but_accepts() {
        let a = assess("Ab3$xyzq"); // 8 chars, < RECOMMENDED_LENGTH
        assert!(a.acceptable);
        assert!(
            a.warnings.iter().any(|w| w.contains("at least 12")),
            "expected a recommend-12 advisory, got {:?}",
            a.warnings
        );
    }

    /// TC-PWPOL-04: a long single-class password is accepted but flagged for diversity.
    #[test]
    fn tc_pwpol_04_low_diversity_warns_but_accepts() {
        let a = assess("abcdefghijklmnop"); // 16 lowercase
        assert!(a.acceptable, "long password must clear the floor");
        assert!(
            a.warnings.iter().any(|w| w.contains("mix character types")),
            "expected a diversity advisory, got {:?}",
            a.warnings
        );
    }

    /// TC-PWPOL-05: a strong long password produces no warnings.
    #[test]
    fn tc_pwpol_05_strong_password_no_warnings() {
        let a = assess("Tr0ub4dour&3xtra");
        assert!(a.acceptable);
        assert!(
            a.warnings.is_empty(),
            "strong password must have no advisories, got {:?}",
            a.warnings
        );
    }

    /// TC-PWPOL-06: a blacklisted password is rejected even when long enough.
    #[test]
    fn tc_pwpol_06_common_password_rejected() {
        for pw in ["password", "PASSWORD", "Password1", "12345678", "changeme"] {
            let a = assess(pw);
            assert!(!a.acceptable, "{pw:?} must be rejected as common");
        }
    }

    /// TC-PWPOL-07: empty password is rejected (length floor); callers may
    /// special-case empty earlier for a clearer message.
    #[test]
    fn tc_pwpol_07_empty_rejected() {
        let a = assess("");
        assert!(!a.acceptable);
    }

    /// TC-PWPOL-08: a multibyte (Japanese) passphrase is measured by scalar
    /// count, not bytes, so a 9-character phrase clears the 8-char floor.
    #[test]
    fn tc_pwpol_08_multibyte_counts_by_char() {
        let a = assess("パスワード強度試験"); // 9 scalar values
        assert!(
            a.acceptable,
            "9-character multibyte passphrase must clear the floor"
        );
    }
}
