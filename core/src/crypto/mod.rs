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

use crate::error::DiaryError;
use secrecy::SecretBox;

impl CryptoEngine {
    /// Unlock the engine using the given password.
    ///
    /// Derives a 32-byte symmetric key from `password` and `salt` using
    /// Argon2id with `params`, then decrypts the verification token
    /// (`verification_iv`, `verification_ct`) to confirm the password is
    /// correct.  On success the derived key is stored as the master key and
    /// the engine transitions to the unlocked state.
    ///
    /// Returns [`DiaryError::Password`] for an empty password.
    /// Returns [`DiaryError::Crypto`] if decryption of the verification token
    /// fails (wrong password or corrupted token).
    pub fn unlock(
        &mut self,
        password: &[u8],
        salt: &[u8],
        params: &kdf::Argon2Params,
        verification_iv: [u8; aead::NONCE_SIZE],
        verification_ct: &[u8],
    ) -> Result<(), DiaryError> {
        if password.is_empty() {
            return Err(DiaryError::Password("password must not be empty".into()));
        }

        let sym_key = kdf::derive_key(password, salt, params)?;

        // Attempt to decrypt the verification token; any failure means wrong password.
        aead::decrypt(sym_key.as_ref(), verification_iv, verification_ct)
            .map_err(|_| DiaryError::Crypto("invalid password".into()))?;

        // Build the master key. In Sprint 2 only sym_key is populated;
        // dsa_sk and kem_sk are populated during vault init in Sprint 3.
        let master_key = MasterKey {
            sym_key: *sym_key.as_ref(),
            dsa_sk: vec![].into_boxed_slice(),
            kem_sk: vec![].into_boxed_slice(),
        };

        self.master_key = Some(SecretBox::new(Box::new(master_key)));
        Ok(())
    }

    /// Lock the engine, securely erasing the master key from memory.
    ///
    /// After this call [`is_unlocked`](CryptoEngine::is_unlocked) returns `false`.
    /// The [`MasterKey`] is dropped and all key material is zeroed on drop via
    /// [`ZeroizeOnDrop`](zeroize::ZeroizeOnDrop).
    pub fn lock(&mut self) {
        self.master_key.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns fast Argon2id parameters suitable for unit tests.
    fn fast_params() -> kdf::Argon2Params {
        kdf::Argon2Params {
            memory_cost_kb: 8,
            time_cost: 1,
            parallelism: 1,
        }
    }

    /// Build a verification token (iv, ciphertext) from the given password and salt.
    fn make_verification_token(
        password: &[u8],
        salt: &[u8],
        params: &kdf::Argon2Params,
    ) -> ([u8; aead::NONCE_SIZE], Vec<u8>) {
        let key = kdf::derive_key(password, salt, params).unwrap();
        let plaintext = [0u8; 32];
        let (ct, iv) = aead::encrypt(key.as_ref(), &plaintext).unwrap();
        (iv, ct)
    }

    /// TC-015-01: correct password → unlock succeeds, is_unlocked() == true.
    #[test]
    fn tc_015_01_correct_password_unlocks() {
        let params = fast_params();
        let password = b"correct-password";
        let salt = b"salt-16byte-long";
        let (iv, ct) = make_verification_token(password, salt, &params);

        let mut engine = CryptoEngine::new();
        assert!(!engine.is_unlocked());

        engine.unlock(password, salt, &params, iv, &ct).unwrap();
        assert!(engine.is_unlocked());
    }

    /// TC-015-02: unlock then lock → is_unlocked() == false.
    #[test]
    fn tc_015_02_lock_after_unlock() {
        let params = fast_params();
        let password = b"correct-password";
        let salt = b"salt-16byte-long";
        let (iv, ct) = make_verification_token(password, salt, &params);

        let mut engine = CryptoEngine::new();
        engine.unlock(password, salt, &params, iv, &ct).unwrap();
        assert!(engine.is_unlocked());

        engine.lock();
        assert!(!engine.is_unlocked());
    }

    /// TC-015-03: wrong password → DiaryError::Crypto.
    #[test]
    fn tc_015_03_wrong_password_returns_crypto_error() {
        let params = fast_params();
        let correct = b"correct-password";
        let wrong = b"wrong-password!!";
        let salt = b"salt-16byte-long";
        let (iv, ct) = make_verification_token(correct, salt, &params);

        let mut engine = CryptoEngine::new();
        let result = engine.unlock(wrong, salt, &params, iv, &ct);
        assert!(
            matches!(result, Err(DiaryError::Crypto(_))),
            "expected DiaryError::Crypto, got {:?}",
            result
        );
    }

    /// TC-015-04: empty password → DiaryError::Password.
    #[test]
    fn tc_015_04_empty_password_returns_password_error() {
        let params = fast_params();
        let salt = b"salt-16byte-long";
        let dummy_iv = [0u8; aead::NONCE_SIZE];
        let dummy_ct = [0u8; 1];

        let mut engine = CryptoEngine::new();
        let result = engine.unlock(b"", salt, &params, dummy_iv, &dummy_ct);
        assert!(
            matches!(result, Err(DiaryError::Password(_))),
            "expected DiaryError::Password, got {:?}",
            result
        );
    }

    /// TC-015-05: sym_key bytes are zeroed in memory after lock().
    ///
    /// # Safety
    /// Reads a raw pointer after the `SecretBox<MasterKey>` is dropped to confirm
    /// that `ZeroizeOnDrop` ran before deallocation.  Intentional for security
    /// validation; permitted in test code only.
    #[test]
    fn tc_015_05_lock_zeroizes_master_key() {
        use secrecy::ExposeSecret;

        let params = fast_params();
        let password = b"correct-password";
        let salt = b"salt-16byte-long";
        let (iv, ct) = make_verification_token(password, salt, &params);

        let mut engine = CryptoEngine::new();
        engine.unlock(password, salt, &params, iv, &ct).unwrap();

        // Capture a raw pointer to sym_key before locking.
        let ptr: *const u8;
        {
            let mk: &MasterKey = engine.master_key.as_ref().unwrap().expose_secret();
            ptr = mk.sym_key.as_ptr();
        }

        engine.lock();

        // SAFETY: intentional post-drop read for security verification.
        // ZeroizeOnDrop guarantees bytes are cleared before the Box frees the allocation.
        unsafe {
            for i in 0..32 {
                assert_eq!(*ptr.add(i), 0u8, "sym_key byte {i} not zeroed after lock");
            }
        }
    }
}
