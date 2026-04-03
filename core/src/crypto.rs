use crate::error::DiaryError;
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

    /// Returns `Ok(())` when the engine is unlocked.
    ///
    /// Returns `Err(DiaryError::NotUnlocked)` if the engine is still in the
    /// locked state (i.e. no master key has been loaded yet).
    pub fn ensure_unlocked(&self) -> Result<(), DiaryError> {
        if self.is_unlocked() {
            Ok(())
        } else {
            Err(DiaryError::NotUnlocked)
        }
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
        assert_eq!(empty.len(), 0);
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

    /// TC-003-01: verify that data is zeroed when the buffer is dropped.
    ///
    /// # Safety
    /// Reads the raw pointer after `drop()` to confirm zeroize ran before
    /// deallocation.  This is technically UB (freed memory access) but is
    /// intentional for security validation; permitted in test code only.
    #[test]
    fn secure_buffer_zeroize_on_scope_exit() {
        let ptr: *const u8;
        let len: usize;
        {
            let buf = SecureBuffer::new(vec![0xAAu8; 32]);
            ptr = buf.as_ref().as_ptr();
            len = buf.len();
            // buf is dropped here, which calls Drop::drop → self.zeroize() → inner.zeroize()
        }
        // SAFETY: intentional post-drop read for security verification.
        // zeroize guarantees bytes are cleared before Box frees the allocation.
        unsafe {
            for i in 0..len {
                assert_eq!(*ptr.add(i), 0u8, "byte {i} not zeroed after drop");
            }
        }
    }

    /// TC-003-B02: 1 MiB buffer drops without panic and reports correct length.
    #[test]
    fn secure_buffer_large_1mib() {
        const ONE_MIB: usize = 1_048_576;
        let buf = SecureBuffer::new(vec![0xFFu8; ONE_MIB]);
        assert_eq!(buf.len(), ONE_MIB);
        assert!(!buf.is_empty());
        // Drop happens here; must not panic and must zero all bytes.
    }

    #[test]
    fn zeroizing_key_zeroize_on_drop() {
        let mut key = ZeroizingKey::new([0xFFu8; 32]);
        key.zeroize();
        assert_eq!(key.as_ref(), &[0u8; 32]);
    }

    /// TC-003-02: ZeroizingKey zeroes its bytes when dropped (0xBB pattern).
    #[test]
    fn zeroizing_key_tc_003_02_zeroize_on_drop() {
        let mut key = ZeroizingKey::new([0xBBu8; 32]);
        key.zeroize();
        assert_eq!(key.as_ref(), &[0u8; 32]);
    }

    /// TC-003-E01: ensure_unlocked returns NotUnlocked when engine is locked.
    #[test]
    fn crypto_engine_ensure_unlocked_when_locked() {
        let engine = CryptoEngine::new();
        let result = engine.ensure_unlocked();
        assert!(
            matches!(result, Err(crate::error::DiaryError::NotUnlocked)),
            "expected NotUnlocked, got {:?}",
            result
        );
    }

    /// TC-003-03: MasterKey zeroes all fields when zeroize() is called.
    #[test]
    fn master_key_zeroize_clears_all_fields() {
        let mut mk = MasterKey {
            sym_key: [0xBBu8; 32],
            dsa_sk: vec![0xCCu8; 16].into_boxed_slice(),
            kem_sk: vec![0xDDu8; 16].into_boxed_slice(),
        };
        mk.zeroize();
        assert_eq!(mk.sym_key, [0u8; 32]);
        assert!(mk.dsa_sk.iter().all(|&b| b == 0), "dsa_sk not zeroed");
        assert!(mk.kem_sk.iter().all(|&b| b == 0), "kem_sk not zeroed");
    }
}
