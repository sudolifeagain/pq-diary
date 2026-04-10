//! Access-policy evaluation engine for pq-diary.
//!
//! This module provides the 4-layer policy check used when pq-diary is invoked
//! with the `--claude` flag.  Without `--claude`, all operations are always
//! permitted regardless of the configured policy.
//!
//! # Evaluation order
//!
//! 1. `claude == false` → [`PolicyDecision::Allow`] (non-Claude environment)
//! 2. `policy == None` → [`PolicyDecision::DenyNoDecrypt`] (vault never decrypted)
//! 3. `policy == WriteOnly && op == Read` → [`PolicyDecision::DenyOperation`]
//! 4. `policy == WriteOnly && op == Write` → [`PolicyDecision::Allow`]
//! 5. `policy == Full` → [`PolicyDecision::Allow`]

use serde::{Deserialize, Serialize};

use crate::error::DiaryError;

// ============================================================================
// AccessPolicy
// ============================================================================

/// Access policy for a vault (`vault.toml` `[access].policy`).
///
/// Controls what operations Claude is allowed to perform when invoked with the
/// `--claude` flag.  Without `--claude`, all operations are always permitted
/// regardless of the configured policy.
///
/// `serde(rename_all = "snake_case")` ensures `vault.toml` compatibility:
/// - `None`      ↔ `"none"`
/// - `WriteOnly` ↔ `"write_only"`
/// - `Full`      ↔ `"full"`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessPolicy {
    /// All Claude access denied; vault is never decrypted (private diary).
    #[default]
    None,
    /// Only write operations permitted by Claude (business memo vault).
    WriteOnly,
    /// All Claude operations permitted (analysis vault).
    Full,
}

impl std::fmt::Display for AccessPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessPolicy::None => write!(f, "none"),
            AccessPolicy::WriteOnly => write!(f, "write_only"),
            AccessPolicy::Full => write!(f, "full"),
        }
    }
}

impl std::str::FromStr for AccessPolicy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(AccessPolicy::None),
            "write_only" => Ok(AccessPolicy::WriteOnly),
            "full" => Ok(AccessPolicy::Full),
            _ => Err(format!(
                "invalid policy '{}': expected 'none', 'write_only', or 'full'",
                s
            )),
        }
    }
}

// ============================================================================
// OperationType
// ============================================================================

/// Classification of a CLI operation as either a read or write.
///
/// Used in Layer 3 of the 4-layer access policy check to determine whether a
/// [`AccessPolicy::WriteOnly`] vault permits the requested operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationType {
    /// Read-only operations: `list`, `show`, `search`, `stats`,
    /// `template-show`, `template-list`.
    Read,
    /// Mutating operations: `new`, `edit`, `delete`, `sync`, `today`,
    /// `template-add`, `template-delete`, `import`.
    Write,
}

// ============================================================================
// PolicyDecision
// ============================================================================

/// Result of the 4-layer access policy evaluation.
///
/// Returned by [`check_access`].  Convert to a `Result` with
/// [`into_result`](PolicyDecision::into_result).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Operation is permitted; proceed with vault decryption and execution.
    Allow,

    /// Operation denied because the vault policy is [`AccessPolicy::None`].
    ///
    /// The vault **must not** be decrypted; return immediately with an error
    /// (REQ-022, REQ-101, NFR-101).
    DenyNoDecrypt {
        /// Name of the vault whose policy caused the denial.
        vault_name: String,
        /// The policy value that triggered the denial.
        policy: AccessPolicy,
    },

    /// Operation denied because a read operation was requested on a
    /// [`AccessPolicy::WriteOnly`] vault (REQ-023).
    DenyOperation {
        /// Name of the vault whose policy caused the denial.
        vault_name: String,
        /// The policy value that triggered the denial.
        policy: AccessPolicy,
        /// The operation type that was rejected.
        operation: OperationType,
    },
}

impl PolicyDecision {
    /// Convert this decision into a `Result<(), DiaryError>`.
    ///
    /// - [`PolicyDecision::Allow`] → `Ok(())`
    /// - [`PolicyDecision::DenyNoDecrypt`] → `Err(DiaryError::Policy(...))`
    /// - [`PolicyDecision::DenyOperation`] → `Err(DiaryError::Policy(...))`
    ///
    /// Error messages conform to REQ-050.
    pub fn into_result(self) -> Result<(), DiaryError> {
        match self {
            PolicyDecision::Allow => Ok(()),
            PolicyDecision::DenyNoDecrypt { vault_name, policy } => {
                Err(DiaryError::Policy(format!(
                    "Access denied: vault '{}' has policy '{}'. '--claude' requires 'write_only' or 'full'.",
                    vault_name, policy
                )))
            }
            PolicyDecision::DenyOperation {
                vault_name,
                policy,
                ..
            } => Err(DiaryError::Policy(format!(
                "Access denied: vault '{}' has policy '{}'. Read operations require 'full'.",
                vault_name, policy
            ))),
        }
    }
}

// ============================================================================
// classify_operation
// ============================================================================

/// Classify a CLI command name as a read or write operation.
///
/// | Command          | Classification |
/// |------------------|----------------|
/// | `list`           | Read           |
/// | `show`           | Read           |
/// | `search`         | Read           |
/// | `stats`          | Read           |
/// | `template-show`  | Read           |
/// | `template-list`  | Read           |
/// | `new`            | Write          |
/// | `edit`           | Write          |
/// | `delete`         | Write          |
/// | `sync`           | Write          |
/// | `today`          | Write          |
/// | `template-add`   | Write          |
/// | `template-delete`| Write          |
/// | `import`         | Write          |
/// | *(unknown)*      | Write (safe default) |
pub fn classify_operation(command: &str) -> OperationType {
    match command {
        "list" | "show" | "search" | "stats" | "template-show" | "template-list" => {
            OperationType::Read
        }
        _ => OperationType::Write,
    }
}

// ============================================================================
// check_access
// ============================================================================

/// Evaluate whether the given operation is permitted under the vault's policy.
///
/// This is a pure function implementing the 4-layer evaluation described in
/// REQ-020 through REQ-025.
///
/// # Parameters
///
/// - `claude`: `true` when the CLI was invoked with `--claude`.
/// - `policy`: the vault's configured [`AccessPolicy`].
/// - `operation`: the operation's read/write classification.
/// - `vault_name`: vault name used in error messages if access is denied.
///
/// # Returns
///
/// A [`PolicyDecision`] indicating whether to allow or deny the operation,
/// and (on denial) the reason.
pub fn check_access(
    claude: bool,
    policy: AccessPolicy,
    operation: OperationType,
    vault_name: &str,
) -> PolicyDecision {
    // Layer 1: non-Claude environment — all operations always permitted.
    if !claude {
        return PolicyDecision::Allow;
    }

    // Layer 2: None policy — reject before any decryption attempt.
    if policy == AccessPolicy::None {
        return PolicyDecision::DenyNoDecrypt {
            vault_name: vault_name.to_string(),
            policy,
        };
    }

    // Layer 3: WriteOnly + Read — reject the read operation.
    if policy == AccessPolicy::WriteOnly && operation == OperationType::Read {
        return PolicyDecision::DenyOperation {
            vault_name: vault_name.to_string(),
            policy,
            operation,
        };
    }

    // Layer 4: WriteOnly + Write, or Full — allow.
    PolicyDecision::Allow
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    // ------------------------------------------------------------------------
    // TC-S7-001-01~03: AccessPolicy serde roundtrip
    // ------------------------------------------------------------------------

    /// TC-S7-001-01: AccessPolicy::None serialises to "none" and round-trips.
    #[test]
    fn tc_s7_001_01_none_serde_roundtrip() {
        let serialised = serde_json::to_string(&AccessPolicy::None).expect("serialise");
        assert_eq!(serialised, r#""none""#);
        let deserialised: AccessPolicy = serde_json::from_str(&serialised).expect("deserialise");
        assert_eq!(deserialised, AccessPolicy::None);
    }

    /// TC-S7-001-02: AccessPolicy::WriteOnly serialises to "write_only" and round-trips.
    #[test]
    fn tc_s7_001_02_write_only_serde_roundtrip() {
        let serialised = serde_json::to_string(&AccessPolicy::WriteOnly).expect("serialise");
        assert_eq!(serialised, r#""write_only""#);
        let deserialised: AccessPolicy = serde_json::from_str(&serialised).expect("deserialise");
        assert_eq!(deserialised, AccessPolicy::WriteOnly);
    }

    /// TC-S7-001-03: AccessPolicy::Full serialises to "full" and round-trips.
    #[test]
    fn tc_s7_001_03_full_serde_roundtrip() {
        let serialised = serde_json::to_string(&AccessPolicy::Full).expect("serialise");
        assert_eq!(serialised, r#""full""#);
        let deserialised: AccessPolicy = serde_json::from_str(&serialised).expect("deserialise");
        assert_eq!(deserialised, AccessPolicy::Full);
    }

    // ------------------------------------------------------------------------
    // TC-S7-001-04~06: AccessPolicy Display / FromStr roundtrip
    // ------------------------------------------------------------------------

    /// TC-S7-001-04: AccessPolicy::None Display/FromStr round-trips.
    #[test]
    fn tc_s7_001_04_none_display_from_str_roundtrip() {
        let s = AccessPolicy::None.to_string();
        assert_eq!(s, "none");
        let parsed = AccessPolicy::from_str(&s).expect("from_str");
        assert_eq!(parsed, AccessPolicy::None);
    }

    /// TC-S7-001-05: AccessPolicy::WriteOnly Display/FromStr round-trips.
    #[test]
    fn tc_s7_001_05_write_only_display_from_str_roundtrip() {
        let s = AccessPolicy::WriteOnly.to_string();
        assert_eq!(s, "write_only");
        let parsed = AccessPolicy::from_str(&s).expect("from_str");
        assert_eq!(parsed, AccessPolicy::WriteOnly);
    }

    /// TC-S7-001-06: AccessPolicy::Full Display/FromStr round-trips.
    #[test]
    fn tc_s7_001_06_full_display_from_str_roundtrip() {
        let s = AccessPolicy::Full.to_string();
        assert_eq!(s, "full");
        let parsed = AccessPolicy::from_str(&s).expect("from_str");
        assert_eq!(parsed, AccessPolicy::Full);
    }

    // ------------------------------------------------------------------------
    // TC-S7-001-E01~E02: invalid serde input
    // ------------------------------------------------------------------------

    /// TC-S7-001-E01: Deserialising an invalid string returns an error.
    #[test]
    fn tc_s7_001_e01_invalid_string_serde_error() {
        let result = serde_json::from_str::<AccessPolicy>(r#""invalid_policy""#);
        assert!(result.is_err(), "expected error for invalid policy string");
    }

    /// TC-S7-001-E02: Deserialising an empty string returns an error.
    #[test]
    fn tc_s7_001_e02_empty_string_serde_error() {
        let result = serde_json::from_str::<AccessPolicy>(r#""""#);
        assert!(result.is_err(), "expected error for empty policy string");
    }

    // ------------------------------------------------------------------------
    // TC-S7-010-01~02: classify_operation
    // ------------------------------------------------------------------------

    /// TC-S7-010-01: All read command names classify as OperationType::Read.
    #[test]
    fn tc_s7_010_01_read_commands() {
        let read_commands = [
            "list",
            "show",
            "search",
            "stats",
            "template-show",
            "template-list",
        ];
        for cmd in &read_commands {
            assert_eq!(
                classify_operation(cmd),
                OperationType::Read,
                "command '{}' should be Read",
                cmd
            );
        }
    }

    /// TC-S7-010-02: All write command names classify as OperationType::Write.
    #[test]
    fn tc_s7_010_02_write_commands() {
        let write_commands = [
            "new",
            "edit",
            "delete",
            "sync",
            "today",
            "template-add",
            "template-delete",
            "import",
        ];
        for cmd in &write_commands {
            assert_eq!(
                classify_operation(cmd),
                OperationType::Write,
                "command '{}' should be Write",
                cmd
            );
        }
    }

    // ------------------------------------------------------------------------
    // TC-S7-020-01~06: check_access Allow cases
    // ------------------------------------------------------------------------

    /// TC-S7-020-01: Non-Claude environment always allows access.
    #[test]
    fn tc_s7_020_01_non_claude_allows() {
        let decision = check_access(false, AccessPolicy::Full, OperationType::Read, "myvault");
        assert_eq!(decision, PolicyDecision::Allow);
    }

    /// TC-S7-020-02: Claude + Full policy + Read → Allow.
    #[test]
    fn tc_s7_020_02_claude_full_read_allows() {
        let decision = check_access(true, AccessPolicy::Full, OperationType::Read, "myvault");
        assert_eq!(decision, PolicyDecision::Allow);
    }

    /// TC-S7-020-03: Claude + Full policy + Write → Allow.
    #[test]
    fn tc_s7_020_03_claude_full_write_allows() {
        let decision = check_access(true, AccessPolicy::Full, OperationType::Write, "myvault");
        assert_eq!(decision, PolicyDecision::Allow);
    }

    /// TC-S7-020-04: Claude + WriteOnly policy + Write → Allow.
    #[test]
    fn tc_s7_020_04_claude_write_only_write_allows() {
        let decision = check_access(
            true,
            AccessPolicy::WriteOnly,
            OperationType::Write,
            "myvault",
        );
        assert_eq!(decision, PolicyDecision::Allow);
    }

    /// TC-S7-020-05: Non-Claude + None policy → Allow (policy is ignored without --claude).
    #[test]
    fn tc_s7_020_05_non_claude_none_allows() {
        let decision = check_access(false, AccessPolicy::None, OperationType::Read, "myvault");
        assert_eq!(decision, PolicyDecision::Allow);
    }

    /// TC-S7-020-06: Non-Claude + WriteOnly + Read → Allow (policy is ignored without --claude).
    #[test]
    fn tc_s7_020_06_non_claude_write_only_read_allows() {
        let decision = check_access(
            false,
            AccessPolicy::WriteOnly,
            OperationType::Read,
            "myvault",
        );
        assert_eq!(decision, PolicyDecision::Allow);
    }

    // ------------------------------------------------------------------------
    // TC-S7-020-E01~E06: check_access Deny cases
    // ------------------------------------------------------------------------

    /// TC-S7-020-E01: Claude + None + Read → DenyNoDecrypt.
    #[test]
    fn tc_s7_020_e01_claude_none_read_denies() {
        let decision = check_access(true, AccessPolicy::None, OperationType::Read, "myvault");
        assert!(
            matches!(decision, PolicyDecision::DenyNoDecrypt { .. }),
            "expected DenyNoDecrypt, got {:?}",
            decision
        );
    }

    /// TC-S7-020-E02: Claude + None + Write → DenyNoDecrypt.
    #[test]
    fn tc_s7_020_e02_claude_none_write_denies() {
        let decision = check_access(true, AccessPolicy::None, OperationType::Write, "myvault");
        assert!(
            matches!(decision, PolicyDecision::DenyNoDecrypt { .. }),
            "expected DenyNoDecrypt, got {:?}",
            decision
        );
    }

    /// TC-S7-020-E03: Claude + WriteOnly + Read → DenyOperation.
    #[test]
    fn tc_s7_020_e03_claude_write_only_read_denies() {
        let decision = check_access(
            true,
            AccessPolicy::WriteOnly,
            OperationType::Read,
            "myvault",
        );
        assert!(
            matches!(decision, PolicyDecision::DenyOperation { .. }),
            "expected DenyOperation, got {:?}",
            decision
        );
    }

    /// TC-S7-020-E04: Claude + None + Read with a different vault name → DenyNoDecrypt.
    #[test]
    fn tc_s7_020_e04_claude_none_read_different_vault_denies() {
        let decision = check_access(true, AccessPolicy::None, OperationType::Read, "work");
        assert!(
            matches!(decision, PolicyDecision::DenyNoDecrypt { ref vault_name, .. } if vault_name == "work"),
            "expected DenyNoDecrypt with vault 'work', got {:?}",
            decision
        );
    }

    /// TC-S7-020-E05: Claude + None + Write with a different vault name → DenyNoDecrypt.
    #[test]
    fn tc_s7_020_e05_claude_none_write_different_vault_denies() {
        let decision = check_access(true, AccessPolicy::None, OperationType::Write, "private");
        assert!(
            matches!(decision, PolicyDecision::DenyNoDecrypt { ref vault_name, .. } if vault_name == "private"),
            "expected DenyNoDecrypt with vault 'private', got {:?}",
            decision
        );
    }

    /// TC-S7-020-E06: Claude + WriteOnly + Read with a different vault name → DenyOperation.
    #[test]
    fn tc_s7_020_e06_claude_write_only_read_different_vault_denies() {
        let decision = check_access(true, AccessPolicy::WriteOnly, OperationType::Read, "notes");
        assert!(
            matches!(decision, PolicyDecision::DenyOperation { ref vault_name, .. } if vault_name == "notes"),
            "expected DenyOperation with vault 'notes', got {:?}",
            decision
        );
    }

    // ------------------------------------------------------------------------
    // TC-S7-050-01~02: PolicyDecision::into_result error message format
    // ------------------------------------------------------------------------

    /// TC-S7-050-01: DenyNoDecrypt error message matches REQ-050 format.
    #[test]
    fn tc_s7_050_01_deny_no_decrypt_error_message() {
        let decision = check_access(true, AccessPolicy::None, OperationType::Read, "myvault");
        let err = decision
            .into_result()
            .expect_err("expected Err for DenyNoDecrypt");
        let msg = err.to_string();
        assert!(
            msg.contains("myvault"),
            "error message must contain vault name 'myvault': {}",
            msg
        );
        assert!(
            msg.contains("none"),
            "error message must contain policy 'none': {}",
            msg
        );
        assert!(
            msg.contains("'--claude'"),
            "error message must mention '--claude': {}",
            msg
        );
        assert!(
            msg.contains("'write_only' or 'full'"),
            "error message must mention required policies: {}",
            msg
        );
    }

    /// TC-S7-050-02: DenyOperation error message matches REQ-050 format.
    #[test]
    fn tc_s7_050_02_deny_operation_error_message() {
        let decision = check_access(
            true,
            AccessPolicy::WriteOnly,
            OperationType::Read,
            "myvault",
        );
        let err = decision
            .into_result()
            .expect_err("expected Err for DenyOperation");
        let msg = err.to_string();
        assert!(
            msg.contains("myvault"),
            "error message must contain vault name 'myvault': {}",
            msg
        );
        assert!(
            msg.contains("write_only"),
            "error message must contain policy 'write_only': {}",
            msg
        );
        assert!(
            msg.contains("Read operations require 'full'"),
            "error message must mention read operations: {}",
            msg
        );
    }
}
