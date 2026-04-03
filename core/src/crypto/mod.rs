//! Cryptographic types and operations for pq-diary.
//!
//! Sub-modules:
//! - [`secure_mem`]: secure memory types (SecureBuffer, ZeroizingKey, MasterKey, CryptoEngine)
//! - [`kdf`]: Argon2id key derivation
//! - [`aead`]: AES-256-GCM authenticated encryption
//! - [`kem`]: ML-KEM-768 key encapsulation
//! - [`dsa`]: ML-DSA-65 digital signatures
//! - [`hmac_util`]: HMAC-SHA256 message authentication

pub mod aead;
pub mod dsa;
pub mod hmac_util;
pub mod kdf;
pub mod kem;
pub mod secure_mem;

pub use secure_mem::{CryptoEngine, MasterKey, SecureBuffer, ZeroizingKey};
