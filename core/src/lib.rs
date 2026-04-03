//! pq-diary-core — domain library for the post-quantum cryptography journal.
//!
//! This crate provides the core types and logic for pq-diary:
//! - [`DiaryError`]: unified error type for all operations
//! - [`SecureBuffer`]: zeroize-on-drop byte buffer for secret data
//! - [`DiaryCore`]: top-level API facade (methods added in subsequent sprints)
//!
//! Platform-dependent I/O (terminal, OS APIs) lives in the `cli/` crate only.

/// Secure memory types: [`SecureBuffer`], [`ZeroizingKey`], [`MasterKey`], [`CryptoEngine`].
pub mod crypto;
/// Unified error type: [`DiaryError`].
pub mod error;
/// Entry CRUD operations (implemented in Sprint 4).
pub mod entry;
/// Git synchronisation operations (implemented in Sprint 8).
pub mod git;
/// Digital-legacy operations (implemented in Phase 2).
pub mod legacy;
/// Access-policy evaluation (implemented in Sprint 7).
pub mod policy;
/// Vault format read/write operations (implemented in Sprint 3).
pub mod vault;

/// Re-exported for convenience: see [`crypto::SecureBuffer`].
pub use crypto::SecureBuffer;
/// Re-exported for convenience: see [`error::DiaryError`].
pub use error::DiaryError;

/// Top-level facade for pq-diary-core.
///
/// Individual methods (`unlock`, `lock`, `new_entry`, …) will be added
/// in subsequent sprints as the corresponding modules are implemented.
pub struct DiaryCore {}
