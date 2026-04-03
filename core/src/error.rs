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
