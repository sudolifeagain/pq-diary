//! Cryptographic types and operations for pq-diary.
//!
//! Sub-modules:
//! - `secure_mem`: secure memory types (SecureBuffer, ZeroizingKey, MasterKey, CryptoEngine)
//! - `kdf`: Argon2id key derivation
//! - `aead`: AES-256-GCM authenticated encryption
//! - `kem`: ML-KEM-768 key encapsulation
//! - `dsa`: ML-DSA-65 digital signatures
//! - `hmac_util`: HMAC-SHA256 message authentication

/// AES-256-GCM authenticated encryption and decryption.
pub mod aead;
/// ML-DSA-65 digital signature algorithm (FIPS 204).
pub mod dsa;
/// HMAC-SHA256 message authentication code.
pub mod hmac_util;
/// Argon2id key derivation.
pub mod kdf;
/// ML-KEM-768 key encapsulation mechanism (FIPS 203).
pub mod kem;
/// Secure memory types: `SecureBuffer`, `ZeroizingKey`, `MasterKey`, `CryptoEngine`.
pub mod secure_mem;

pub use secure_mem::{CryptoEngine, MasterKey, SecureBuffer, ZeroizingKey};

use crate::error::DiaryError;
use secrecy::{ExposeSecret, SecretBox};

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

    /// Unlock the engine using the given password and load the full vault key material.
    ///
    /// Extends [`unlock`](CryptoEngine::unlock) by also decrypting and loading
    /// the ML-KEM-768 decapsulation key and ML-DSA-65 signing key from the vault
    /// header blobs.  Each blob has the format `IV (12 bytes) || AES-256-GCM ciphertext`.
    ///
    /// Returns [`DiaryError::Password`] for an empty password.
    /// Returns [`DiaryError::Crypto`] if the password is wrong or key decryption fails.
    #[allow(clippy::too_many_arguments)]
    pub fn unlock_with_vault(
        &mut self,
        password: &[u8],
        kdf_salt: &[u8],
        params: &kdf::Argon2Params,
        verification_iv: [u8; aead::NONCE_SIZE],
        verification_ct: &[u8],
        kem_encrypted_sk: &[u8],
        dsa_encrypted_sk: &[u8],
    ) -> Result<(), DiaryError> {
        if password.is_empty() {
            return Err(DiaryError::Password("password must not be empty".into()));
        }

        let sym_key = kdf::derive_key(password, kdf_salt, params)?;

        // Verify the password against the stored verification token.
        aead::decrypt(sym_key.as_ref(), verification_iv, verification_ct)
            .map_err(|_| DiaryError::Crypto("invalid password".into()))?;

        // Decrypt ML-KEM decapsulation key: strip the 12-byte IV prefix.
        let kem_sk = if kem_encrypted_sk.len() > aead::NONCE_SIZE {
            let iv: [u8; aead::NONCE_SIZE] = kem_encrypted_sk[..aead::NONCE_SIZE]
                .try_into()
                .map_err(|_| DiaryError::Crypto("invalid KEM key IV length".into()))?;
            let ct = &kem_encrypted_sk[aead::NONCE_SIZE..];
            aead::decrypt(sym_key.as_ref(), iv, ct)
                .map_err(|_| DiaryError::Crypto("failed to decrypt KEM key".into()))?
        } else {
            SecureBuffer::new(vec![])
        };

        // Decrypt ML-DSA signing key: strip the 12-byte IV prefix.
        let dsa_sk = if dsa_encrypted_sk.len() > aead::NONCE_SIZE {
            let iv: [u8; aead::NONCE_SIZE] = dsa_encrypted_sk[..aead::NONCE_SIZE]
                .try_into()
                .map_err(|_| DiaryError::Crypto("invalid DSA key IV length".into()))?;
            let ct = &dsa_encrypted_sk[aead::NONCE_SIZE..];
            aead::decrypt(sym_key.as_ref(), iv, ct)
                .map_err(|_| DiaryError::Crypto("failed to decrypt DSA key".into()))?
        } else {
            SecureBuffer::new(vec![])
        };

        let master_key = MasterKey {
            sym_key: *sym_key.as_ref(),
            kem_sk: kem_sk.as_ref().to_vec().into_boxed_slice(),
            dsa_sk: dsa_sk.as_ref().to_vec().into_boxed_slice(),
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

    /// Encrypt `plaintext` using the engine's internal symmetric key (AES-256-GCM).
    ///
    /// A fresh random nonce is generated via `OsRng` on every call.
    /// Returns `(ciphertext, nonce)`.
    ///
    /// Returns [`DiaryError::NotUnlocked`] if the engine has not been unlocked.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; aead::NONCE_SIZE]), DiaryError> {
        let mk = self.expose_master_key()?;
        aead::encrypt(&mk.sym_key, plaintext)
    }

    /// Decrypt `ciphertext` using the engine's internal symmetric key (AES-256-GCM).
    ///
    /// Returns the plaintext as a [`SecureBuffer`] that zeroes its memory on drop.
    ///
    /// Returns [`DiaryError::NotUnlocked`] if the engine has not been unlocked.
    pub fn decrypt(
        &self,
        nonce: &[u8; aead::NONCE_SIZE],
        ciphertext: &[u8],
    ) -> Result<SecureBuffer, DiaryError> {
        let mk = self.expose_master_key()?;
        aead::decrypt(&mk.sym_key, *nonce, ciphertext)
    }

    /// Generate a new ML-KEM-768 key pair.
    ///
    /// Returns [`DiaryError::NotUnlocked`] if the engine has not been unlocked.
    pub fn kem_keygen(&self) -> Result<kem::KemKeyPair, DiaryError> {
        self.ensure_unlocked()?;
        kem::keygen()
    }

    /// Encapsulate a fresh shared secret using the given public encapsulation key.
    ///
    /// Returns `(kem_ciphertext, shared_secret)`.
    ///
    /// Returns [`DiaryError::NotUnlocked`] if the engine has not been unlocked.
    pub fn kem_encapsulate(&self, ek: &[u8]) -> Result<(Vec<u8>, SecureBuffer), DiaryError> {
        self.ensure_unlocked()?;
        kem::encapsulate(ek)
    }

    /// Decapsulate `ct` using the engine's internal ML-KEM-768 secret key.
    ///
    /// Returns the shared secret as a [`SecureBuffer`].
    ///
    /// Returns [`DiaryError::NotUnlocked`] if the engine has not been unlocked.
    pub fn kem_decapsulate(&self, ct: &[u8]) -> Result<SecureBuffer, DiaryError> {
        let mk = self.expose_master_key()?;
        let dk = SecureBuffer::new(mk.kem_sk.to_vec());
        kem::decapsulate(&dk, ct)
    }

    /// Sign `message` using the engine's internal ML-DSA-65 secret key.
    ///
    /// Returns the encoded signature bytes.
    ///
    /// Returns [`DiaryError::NotUnlocked`] if the engine has not been unlocked.
    pub fn dsa_sign(&self, message: &[u8]) -> Result<Vec<u8>, DiaryError> {
        let mk = self.expose_master_key()?;
        let sk = SecureBuffer::new(mk.dsa_sk.to_vec());
        dsa::sign(&sk, message)
    }

    /// Verify `signature` on `message` using the given ML-DSA-65 public key.
    ///
    /// Returns `Ok(true)` if the signature is valid, `Ok(false)` otherwise.
    ///
    /// Returns [`DiaryError::NotUnlocked`] if the engine has not been unlocked.
    pub fn dsa_verify(
        &self,
        pk: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, DiaryError> {
        self.ensure_unlocked()?;
        dsa::verify(pk, message, signature)
    }

    /// Compute HMAC-SHA256 of `data` using the engine's internal symmetric key.
    ///
    /// Returns a 32-byte MAC value.
    ///
    /// Returns [`DiaryError::NotUnlocked`] if the engine has not been unlocked.
    pub fn hmac(&self, data: &[u8]) -> Result<[u8; 32], DiaryError> {
        let mk = self.expose_master_key()?;
        hmac_util::compute(&mk.sym_key, data)
    }

    /// Verify HMAC-SHA256 of `data` against `expected` using the engine's internal symmetric key.
    ///
    /// Uses constant-time comparison.
    ///
    /// Returns [`DiaryError::NotUnlocked`] if the engine has not been unlocked.
    pub fn hmac_verify(&self, data: &[u8], expected: &[u8; 32]) -> Result<bool, DiaryError> {
        let mk = self.expose_master_key()?;
        Ok(hmac_util::verify_hmac(&mk.sym_key, data, expected))
    }

    /// Expose the master key for internal use, returning [`DiaryError::NotUnlocked`] if locked.
    fn expose_master_key(&self) -> Result<&MasterKey, DiaryError> {
        self.master_key
            .as_ref()
            .map(|s| s.expose_secret())
            .ok_or(DiaryError::NotUnlocked)
    }
}

/// Test-only constructor for [`CryptoEngine`] with explicit key material.
///
/// Available only in test builds (`#[cfg(test)]`).
/// Use `unlock()` in production code.
#[cfg(test)]
impl CryptoEngine {
    /// Create a [`CryptoEngine`] pre-loaded with the given symmetric key and DSA signing key.
    pub fn new_for_testing(sym_key: [u8; 32], dsa_sk: Vec<u8>) -> Self {
        use secrecy::SecretBox;
        let master_key = MasterKey {
            sym_key,
            dsa_sk: dsa_sk.into_boxed_slice(),
            kem_sk: vec![].into_boxed_slice(),
        };
        Self {
            master_key: Some(SecretBox::new(Box::new(master_key))),
            legacy_key: None,
        }
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

    /// Unlock a fresh CryptoEngine with test credentials.
    fn unlocked_engine() -> CryptoEngine {
        let params = fast_params();
        let password = b"correct-password";
        let salt = b"salt-16byte-long";
        let (iv, ct) = make_verification_token(password, salt, &params);
        let mut engine = CryptoEngine::new();
        engine.unlock(password, salt, &params, iv, &ct).unwrap();
        engine
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

    // -------------------------------------------------------------------------
    // TASK-0016 tests
    // -------------------------------------------------------------------------

    /// TC-016-01: unlock → encrypt/decrypt round-trip succeeds.
    #[test]
    fn tc_016_01_encrypt_decrypt_after_unlock() {
        let engine = unlocked_engine();
        let plaintext = b"secret journal entry";

        let (ciphertext, nonce) = engine.encrypt(plaintext).unwrap();
        let recovered = engine.decrypt(&nonce, &ciphertext).unwrap();

        assert_eq!(recovered.as_ref(), plaintext);
    }

    /// TC-016-02: unlock → kem_keygen / kem_encapsulate / kem_decapsulate succeed.
    #[test]
    fn tc_016_02_kem_operations_after_unlock() {
        // Generate a real KEM key pair to serve as the engine's internal secret key.
        let kem_kp = kem::keygen().unwrap();
        let ek_bytes = kem_kp.encapsulation_key.clone();

        // Build a MasterKey with the real kem_sk seed.
        let master_key = MasterKey {
            sym_key: [0x42u8; 32],
            dsa_sk: vec![].into_boxed_slice(),
            kem_sk: kem_kp
                .decapsulation_key
                .as_ref()
                .to_vec()
                .into_boxed_slice(),
        };
        let mut engine = CryptoEngine::new();
        engine.master_key = Some(SecretBox::new(Box::new(master_key)));

        // kem_keygen should succeed when unlocked.
        let _new_kp = engine.kem_keygen().unwrap();

        // kem_encapsulate → kem_decapsulate: shared secrets must match.
        let (ct, ss_sender) = engine.kem_encapsulate(&ek_bytes).unwrap();
        let ss_receiver = engine.kem_decapsulate(&ct).unwrap();

        assert_eq!(ss_sender.as_ref(), ss_receiver.as_ref());
    }

    /// TC-016-03: unlock → dsa_sign / dsa_verify succeed.
    #[test]
    fn tc_016_03_dsa_operations_after_unlock() {
        // Generate a real DSA key pair to serve as the engine's internal signing key.
        let dsa_kp = dsa::keygen().unwrap();
        let vk_bytes = dsa_kp.verifying_key.clone();

        let master_key = MasterKey {
            sym_key: [0x42u8; 32],
            dsa_sk: dsa_kp.signing_key.as_ref().to_vec().into_boxed_slice(),
            kem_sk: vec![].into_boxed_slice(),
        };
        let mut engine = CryptoEngine::new();
        engine.master_key = Some(SecretBox::new(Box::new(master_key)));

        let message = b"test message for dsa";
        let sig = engine.dsa_sign(message).unwrap();
        let valid = engine.dsa_verify(&vk_bytes, message, &sig).unwrap();

        assert!(valid, "signature produced by dsa_sign must verify as true");
    }

    /// TC-016-04: unlock → hmac / hmac_verify succeed.
    #[test]
    fn tc_016_04_hmac_after_unlock() {
        let engine = unlocked_engine();
        let data = b"entry content";

        let mac = engine.hmac(data).unwrap();
        assert_eq!(mac.len(), 32);
        assert!(
            engine.hmac_verify(data, &mac).unwrap(),
            "hmac_verify must return true for the correct MAC"
        );
    }

    /// TC-016-E01: locked engine → encrypt returns DiaryError::NotUnlocked.
    #[test]
    fn tc_016_e01_encrypt_when_locked_returns_not_unlocked() {
        let engine = CryptoEngine::new();
        let result = engine.encrypt(b"test");
        assert!(
            matches!(result, Err(DiaryError::NotUnlocked)),
            "expected NotUnlocked, got {:?}",
            result
        );
    }

    /// TC-016-E02: locked engine → kem_keygen returns DiaryError::NotUnlocked.
    #[test]
    fn tc_016_e02_kem_keygen_when_locked_returns_not_unlocked() {
        let engine = CryptoEngine::new();
        let result = engine.kem_keygen();
        assert!(
            matches!(result, Err(DiaryError::NotUnlocked)),
            "expected NotUnlocked"
        );
    }

    /// TC-016-E03: locked engine → dsa_sign returns DiaryError::NotUnlocked.
    #[test]
    fn tc_016_e03_dsa_sign_when_locked_returns_not_unlocked() {
        let engine = CryptoEngine::new();
        let result = engine.dsa_sign(b"message");
        assert!(
            matches!(result, Err(DiaryError::NotUnlocked)),
            "expected NotUnlocked, got {:?}",
            result
        );
    }

    /// TC-016-E04: locked engine → hmac returns DiaryError::NotUnlocked.
    #[test]
    fn tc_016_e04_hmac_when_locked_returns_not_unlocked() {
        let engine = CryptoEngine::new();
        let result = engine.hmac(b"data");
        assert!(
            matches!(result, Err(DiaryError::NotUnlocked)),
            "expected NotUnlocked, got {:?}",
            result
        );
    }

    /// TC-016-E05: locked engine → hmac_verify returns DiaryError::NotUnlocked.
    #[test]
    fn tc_016_e05_hmac_verify_when_locked_returns_not_unlocked() {
        let engine = CryptoEngine::new();
        let result = engine.hmac_verify(b"data", &[0u8; 32]);
        assert!(
            matches!(result, Err(DiaryError::NotUnlocked)),
            "expected NotUnlocked, got {:?}",
            result
        );
    }

    // -------------------------------------------------------------------------
    // TASK-0017 tests: integration + performance
    // -------------------------------------------------------------------------

    /// TC-017-01: Full cryptographic pipeline end-to-end test.
    ///
    /// Exercises the complete pipeline in order:
    /// Argon2id key derivation → unlock → AES-256-GCM encryption →
    /// ML-DSA-65 signing → HMAC-SHA256 → ML-KEM-768 encapsulation/decapsulation →
    /// AES-256-GCM decryption → ML-DSA-65 verification → HMAC-SHA256 verification → lock.
    #[test]
    fn tc_017_01_e2e_crypto_pipeline() {
        let params = fast_params();
        let password = b"e2e-password-test";
        let salt = b"e2e-salt-16bytes";

        // Step 1: Argon2id key derivation via unlock
        let (iv, ct) = make_verification_token(password, salt, &params);
        let mut engine = CryptoEngine::new();
        engine.unlock(password, salt, &params, iv, &ct).unwrap();
        assert!(
            engine.is_unlocked(),
            "engine must be unlocked after unlock()"
        );

        // Step 2: Generate full key material (DSA + KEM)
        let dsa_kp = dsa::keygen().unwrap();
        let kem_kp = kem::keygen().unwrap();
        let vk_bytes = dsa_kp.verifying_key.clone();
        let ek_bytes = kem_kp.encapsulation_key.clone();

        // Derive sym_key and inject full MasterKey
        let sym_key = *kdf::derive_key(password, salt, &params).unwrap().as_ref();
        let master_key = MasterKey {
            sym_key,
            dsa_sk: dsa_kp.signing_key.as_ref().to_vec().into_boxed_slice(),
            kem_sk: kem_kp
                .decapsulation_key
                .as_ref()
                .to_vec()
                .into_boxed_slice(),
        };
        engine.master_key = Some(SecretBox::new(Box::new(master_key)));

        // Step 3: AES-256-GCM encryption
        let plaintext = b"E2E test: secret journal entry content.";
        let (ciphertext, nonce) = engine.encrypt(plaintext).unwrap();

        // Step 4: ML-DSA-65 signing
        let signature = engine.dsa_sign(plaintext).unwrap();

        // Step 5: HMAC-SHA256
        let mac = engine.hmac(plaintext).unwrap();
        assert_eq!(mac.len(), 32);

        // Step 6: ML-KEM-768 encapsulation → decapsulation (shared secrets must match)
        let (kem_ct, ss_sender) = engine.kem_encapsulate(&ek_bytes).unwrap();
        let ss_receiver = engine.kem_decapsulate(&kem_ct).unwrap();
        assert_eq!(
            ss_sender.as_ref(),
            ss_receiver.as_ref(),
            "KEM shared secrets must match"
        );

        // Step 7: AES-256-GCM decryption
        let recovered = engine.decrypt(&nonce, &ciphertext).unwrap();
        assert_eq!(
            recovered.as_ref(),
            plaintext,
            "decrypted plaintext must match original"
        );

        // Step 8: ML-DSA-65 signature verification
        let sig_valid = engine.dsa_verify(&vk_bytes, plaintext, &signature).unwrap();
        assert!(sig_valid, "DSA signature must verify as valid");

        // Step 9: HMAC-SHA256 verification
        let mac_valid = engine.hmac_verify(plaintext, &mac).unwrap();
        assert!(mac_valid, "HMAC must verify as valid");

        // Step 10: lock
        engine.lock();
        assert!(!engine.is_unlocked(), "engine must be locked after lock()");
    }

    /// TC-017-02: unlock() with default Argon2id params completes within 5 seconds.
    ///
    /// Measures wall-clock time for `unlock()` (which includes Argon2id key derivation).
    /// The 5-second upper bound accounts for CI environment variability while still
    /// providing a meaningful regression guard.
    #[test]
    fn tc_017_02_unlock_performance_within_5_seconds() {
        use std::time::Instant;

        let params = kdf::Argon2Params::default(); // 64 MiB, 3 iterations, 4 threads
        let password = b"perf-test-password";
        let salt = b"perf-salt-16byte";

        // Build verification token outside the timed region.
        let (iv, ct) = make_verification_token(password, salt, &params);

        let mut engine = CryptoEngine::new();
        let start = Instant::now();
        engine.unlock(password, salt, &params, iv, &ct).unwrap();
        let elapsed = start.elapsed();

        assert!(
            elapsed.as_secs() < 5,
            "unlock() took {:?}, expected < 5 seconds (CI-adjusted bound)",
            elapsed
        );
    }
}
