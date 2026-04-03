use secrecy::SecretBox;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A byte buffer that is automatically zeroed on drop.
///
/// The internal storage uses `Box<[u8]>` (fixed-length) to eliminate
/// the risk of leftover data caused by reallocation.
pub struct SecureBuffer {
    inner: Box<[u8]>,
}

impl SecureBuffer {
    /// Create a new `SecureBuffer` from a `Vec<u8>`.
    ///
    /// The vector is converted to a boxed slice immediately so that
    /// no reallocation can occur after construction.
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            inner: data.into_boxed_slice(),
        }
    }

    /// Returns the number of bytes held in the buffer.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns `true` if the buffer contains no bytes.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl AsRef<[u8]> for SecureBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl Zeroize for SecureBuffer {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SecureBuffer {}

/// A 32-byte symmetric key that is automatically zeroed on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ZeroizingKey {
    inner: [u8; 32],
}

impl ZeroizingKey {
    /// Wrap a raw 32-byte key.
    pub fn new(key: [u8; 32]) -> Self {
        Self { inner: key }
    }
}

impl AsRef<[u8; 32]> for ZeroizingKey {
    fn as_ref(&self) -> &[u8; 32] {
        &self.inner
    }
}

/// The key material derived from the master password.
///
/// All fields are zeroed on drop via `ZeroizeOnDrop`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    /// AES-256-GCM symmetric key.
    pub sym_key: [u8; 32],
    /// ML-DSA-65 secret key.
    pub dsa_sk: Box<[u8]>,
    /// ML-KEM-768 secret key.
    pub kem_sk: Box<[u8]>,
}

/// Cryptographic engine responsible for key storage and lock/unlock state.
///
/// Starts in the locked state (`master_key` is `None`).
/// Unlock / lock operations will be added in Sprint 2.
pub struct CryptoEngine {
    master_key: Option<SecretBox<MasterKey>>,
    // Reserved for Sprint 2 legacy-key unlock path.
    #[allow(dead_code)]
    legacy_key: Option<SecretBox<[u8; 32]>>,
}

impl CryptoEngine {
    /// Create a new engine in the locked state.
    pub fn new() -> Self {
        Self {
            master_key: None,
            legacy_key: None,
        }
    }

    /// Returns `true` if the engine has been unlocked with a master key.
    pub fn is_unlocked(&self) -> bool {
        self.master_key.is_some()
    }
}

impl Default for CryptoEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_buffer_len_and_is_empty() {
        let buf = SecureBuffer::new(vec![1, 2, 3]);
        assert_eq!(buf.len(), 3);
        assert!(!buf.is_empty());

        let empty = SecureBuffer::new(vec![]);
        assert!(empty.is_empty());
    }

    #[test]
    fn secure_buffer_as_ref() {
        let buf = SecureBuffer::new(vec![0xAB, 0xCD]);
        assert_eq!(buf.as_ref(), &[0xAB, 0xCD]);
    }

    #[test]
    fn zeroizing_key_as_ref() {
        let key = ZeroizingKey::new([0x42u8; 32]);
        assert_eq!(key.as_ref(), &[0x42u8; 32]);
    }

    #[test]
    fn crypto_engine_starts_locked() {
        let engine = CryptoEngine::new();
        assert!(!engine.is_unlocked());
    }

    #[test]
    fn crypto_engine_default_is_locked() {
        let engine = CryptoEngine::default();
        assert!(!engine.is_unlocked());
    }

    #[test]
    fn secure_buffer_zeroize_on_drop() {
        // Verify that the Zeroize impl clears bytes in place.
        let mut buf = SecureBuffer::new(vec![0xFF; 8]);
        buf.zeroize();
        assert_eq!(buf.as_ref(), &[0u8; 8]);
    }

    #[test]
    fn zeroizing_key_zeroize_on_drop() {
        let mut key = ZeroizingKey::new([0xFFu8; 32]);
        key.zeroize();
        assert_eq!(key.as_ref(), &[0u8; 32]);
    }
}
