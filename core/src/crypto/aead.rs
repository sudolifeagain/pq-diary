//! AES-256-GCM authenticated encryption and decryption.
//!
//! Provides `encrypt` and `decrypt` operations using a 32-byte symmetric key.
//! Nonces are always generated from `OsRng` to prevent reuse.

use crate::{crypto::secure_mem::SecureBuffer, error::DiaryError};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::{rngs::OsRng, RngCore};

/// Length of the AES-GCM nonce in bytes.
pub const NONCE_SIZE: usize = 12;

/// Length of the AES-GCM authentication tag in bytes.
pub const TAG_SIZE: usize = 16;

/// Encrypt `plaintext` with AES-256-GCM using `key`.
///
/// A fresh random nonce is generated via `OsRng` on every call.
///
/// Returns `(ciphertext, nonce)` where `ciphertext` already includes the
/// 16-byte GCM authentication tag appended at the end.
pub fn encrypt(
    key: &[u8; 32],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; NONCE_SIZE]), DiaryError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| DiaryError::Crypto(e.to_string()))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| DiaryError::Crypto(e.to_string()))?;

    Ok((ciphertext, nonce_bytes))
}

/// Decrypt `ciphertext` with AES-256-GCM using `key` and `nonce`.
///
/// `ciphertext` must include the 16-byte GCM authentication tag appended at
/// the end (as produced by [`encrypt`]).  Authentication failure or any other
/// error is returned as [`DiaryError::Crypto`].
///
/// The plaintext is returned as a [`SecureBuffer`] that zeroes its memory on drop.
pub fn decrypt(
    key: &[u8; 32],
    nonce: [u8; NONCE_SIZE],
    ciphertext: &[u8],
) -> Result<SecureBuffer, DiaryError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| DiaryError::Crypto(e.to_string()))?;

    let nonce = Nonce::from_slice(&nonce);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| DiaryError::Crypto(e.to_string()))?;

    Ok(SecureBuffer::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0x42u8; 32]
    }

    /// TC-003-01: encrypt → decrypt round-trip produces the original plaintext.
    #[test]
    fn roundtrip_encrypt_decrypt() {
        let key = test_key();
        let plaintext = b"hello, pq-diary!";

        let (ciphertext, nonce) = encrypt(&key, plaintext).unwrap();
        let recovered = decrypt(&key, nonce, &ciphertext).unwrap();

        assert_eq!(recovered.as_ref(), plaintext);
    }

    /// TC-003-02: nonce returned by encrypt is exactly NONCE_SIZE bytes.
    #[test]
    fn nonce_is_twelve_bytes() {
        let key = test_key();
        let (_, nonce) = encrypt(&key, b"data").unwrap();
        assert_eq!(nonce.len(), NONCE_SIZE);
    }

    /// TC-003-03: ciphertext differs from plaintext.
    #[test]
    fn ciphertext_differs_from_plaintext() {
        let key = test_key();
        let plaintext = b"secret message";

        let (ciphertext, _) = encrypt(&key, plaintext).unwrap();

        assert_ne!(ciphertext.as_slice(), plaintext.as_slice());
    }

    /// TC-003-04: two encrypt calls on identical input produce different ciphertexts
    /// because each call generates a fresh random nonce.
    #[test]
    fn different_nonces_produce_different_ciphertexts() {
        let key = test_key();
        let plaintext = b"same plaintext";

        let (ct1, nonce1) = encrypt(&key, plaintext).unwrap();
        let (ct2, nonce2) = encrypt(&key, plaintext).unwrap();

        // Nonces are overwhelmingly unlikely to collide with 96-bit random values.
        assert_ne!(nonce1, nonce2);
        assert_ne!(ct1, ct2);
    }

    /// TC-003-E01: flipping one byte of the ciphertext causes decryption to fail.
    #[test]
    fn tampered_ciphertext_returns_error() {
        let key = test_key();
        let (mut ciphertext, nonce) = encrypt(&key, b"tamper me").unwrap();

        // Flip the first byte.
        ciphertext[0] ^= 0xFF;

        let result = decrypt(&key, nonce, &ciphertext);
        assert!(result.is_err(), "expected Err for tampered ciphertext");
    }

    /// TC-003-E02: decrypting with a wrong key returns an error.
    #[test]
    fn wrong_key_returns_error() {
        let key = test_key();
        let (ciphertext, nonce) = encrypt(&key, b"secret").unwrap();

        let wrong_key = [0xFFu8; 32];
        let result = decrypt(&wrong_key, nonce, &ciphertext);
        assert!(result.is_err(), "expected Err for wrong key");
    }

    /// TC-003-B01: empty plaintext encrypts and decrypts successfully.
    #[test]
    fn empty_plaintext_roundtrip() {
        let key = test_key();
        let (ciphertext, nonce) = encrypt(&key, b"").unwrap();

        // ciphertext should contain only the GCM tag (16 bytes).
        assert_eq!(ciphertext.len(), TAG_SIZE);

        let recovered = decrypt(&key, nonce, &ciphertext).unwrap();
        assert_eq!(recovered.as_ref(), b"");
    }

    /// TC-003-B02: 1 MiB plaintext encrypts and decrypts successfully.
    #[test]
    fn large_1mib_roundtrip() {
        const ONE_MIB: usize = 1_048_576;
        let key = test_key();
        let plaintext = vec![0xABu8; ONE_MIB];

        let (ciphertext, nonce) = encrypt(&key, &plaintext).unwrap();
        assert_eq!(ciphertext.len(), ONE_MIB + TAG_SIZE);

        let recovered = decrypt(&key, nonce, &ciphertext).unwrap();
        assert_eq!(recovered.as_ref(), plaintext.as_slice());
    }
}
