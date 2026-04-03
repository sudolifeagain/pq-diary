//! Unified error type for pq-diary-core operations.
//!
//! All fallible functions in this crate return [`DiaryError`].
//! Error messages are in English. No secret material is included in messages.

use thiserror::Error;

/// Unified error type for pq-diary-core operations.
#[derive(Debug, Error)]
pub enum DiaryError {
    // --- Phase 1 ---
    /// I/O error from the underlying OS.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// vault.toml / config.toml parse or validation error.
    #[error("configuration error: {0}")]
    Config(String),

    /// Vault format read/write error.
    #[error("vault error: {0}")]
    Vault(String),

    /// Entry CRUD operation error.
    #[error("entry error: {0}")]
    Entry(String),

    /// Cryptographic operation error.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Operation attempted on a locked vault.
    #[error("vault is locked")]
    NotUnlocked,

    /// Git synchronisation error.
    #[error("git error: {0}")]
    Git(String),

    /// $EDITOR launch or interaction error.
    #[error("editor error: {0}")]
    Editor(String),

    // --- Phase 1 additional ---
    /// Full-text / tag search error.
    #[error("search error: {0}")]
    Search(String),

    /// Obsidian import conversion error.
    #[error("import error: {0}")]
    Import(String),

    /// Template expansion error.
    #[error("template error: {0}")]
    Template(String),

    // --- Phase 2 ---
    /// Digital-legacy operation error.
    #[error("legacy error: {0}")]
    Legacy(String),

    /// Access-policy evaluation error.
    #[error("policy error: {0}")]
    Policy(String),

    /// Background daemon error.
    #[error("daemon error: {0}")]
    Daemon(String),

    /// Password input / validation error.
    #[error("password error: {0}")]
    Password(String),

    /// CLI argument validation error.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as StdError;
    use std::io;

    /// TC-002-01: every variant produces a non-empty English Display string.
    #[test]
    fn test_all_variants_display_non_empty() {
        let errors: Vec<DiaryError> = vec![
            DiaryError::Io(io::Error::new(io::ErrorKind::NotFound, "test")),
            DiaryError::Config("bad config".into()),
            DiaryError::Vault("corrupt vault".into()),
            DiaryError::Entry("no such entry".into()),
            DiaryError::Crypto("decryption failed".into()),
            DiaryError::NotUnlocked,
            DiaryError::Git("git push failed".into()),
            DiaryError::Editor("editor exited".into()),
            DiaryError::Search("index missing".into()),
            DiaryError::Import("malformed wiki-link".into()),
            DiaryError::Template("missing template".into()),
            DiaryError::Legacy("legacy key expired".into()),
            DiaryError::Policy("access denied".into()),
            DiaryError::Daemon("daemon not running".into()),
            DiaryError::Password("too short".into()),
            DiaryError::InvalidArgument("unknown flag".into()),
        ];

        assert_eq!(errors.len(), 16, "expected exactly 16 variants");

        for e in &errors {
            let msg = format!("{}", e);
            assert!(!msg.is_empty(), "Display for {:?} must not be empty", e);
            // messages should be ASCII (English only)
            assert!(
                msg.is_ascii(),
                "Display for {:?} must be ASCII English, got: {}",
                e,
                msg
            );
        }
    }

    /// TC-002-02: std::io::Error converts into DiaryError::Io via From.
    #[test]
    fn test_from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let diary_err = DiaryError::from(io_err);
        assert!(
            matches!(diary_err, DiaryError::Io(_)),
            "expected DiaryError::Io, got {:?}",
            diary_err
        );
    }

    /// TC-002-03: source() returns the wrapped io::Error.
    #[test]
    fn test_source_chain_io() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "permission denied");
        let diary_err: DiaryError = io_err.into();
        let src = diary_err.source();
        assert!(
            src.is_some(),
            "DiaryError::Io must expose its source via source()"
        );
    }

    /// TC-002-B01: all 16 variants compile and produce non-empty Display strings.
    /// This is a compile-time exhaustiveness check + runtime Display check.
    #[test]
    fn test_all_16_variants_exhaustive() {
        fn check(e: &DiaryError) {
            assert!(!format!("{}", e).is_empty());
        }
        check(&DiaryError::Io(io::Error::new(io::ErrorKind::Other, "x")));
        check(&DiaryError::Config("x".into()));
        check(&DiaryError::Vault("x".into()));
        check(&DiaryError::Entry("x".into()));
        check(&DiaryError::Crypto("x".into()));
        check(&DiaryError::NotUnlocked);
        check(&DiaryError::Git("x".into()));
        check(&DiaryError::Editor("x".into()));
        check(&DiaryError::Search("x".into()));
        check(&DiaryError::Import("x".into()));
        check(&DiaryError::Template("x".into()));
        check(&DiaryError::Legacy("x".into()));
        check(&DiaryError::Policy("x".into()));
        check(&DiaryError::Daemon("x".into()));
        check(&DiaryError::Password("x".into()));
        check(&DiaryError::InvalidArgument("x".into()));
    }
}
