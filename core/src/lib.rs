pub mod crypto;
pub mod error;
pub mod entry;
pub mod git;
pub mod legacy;
pub mod policy;
pub mod vault;

/// Top-level facade for pq-diary-core.
///
/// Individual methods (`unlock`, `lock`, `new_entry`, …) will be added
/// in subsequent sprints as the corresponding modules are implemented.
pub struct DiaryCore {}
