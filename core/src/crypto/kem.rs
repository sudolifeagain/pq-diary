//! ML-KEM-768 key encapsulation mechanism.
//!
//! Implements key generation, encapsulation, and decapsulation for post-quantum
//! key exchange using the ML-KEM-768 algorithm (FIPS 203).

use crate::{crypto::secure_mem::SecureBuffer, error::DiaryError};
use ml_kem::{
    Ciphertext, Decapsulate, DecapsulationKey768, Encapsulate, EncapsulationKey768, Kem, Key,
    KeyExport, MlKem768,
};

/// ML-KEM-768 key pair.
///
/// `encapsulation_key` (public) is safe to share freely.
/// `decapsulation_key` (private) is stored in a [`SecureBuffer`] that zeroes its memory on drop.
pub struct KemKeyPair {
    /// Serialized ML-KEM-768 encapsulation (public) key (1184 bytes).
    pub encapsulation_key: Vec<u8>,
    /// Serialized ML-KEM-768 decapsulation (private) key seed (64 bytes), zeroed on drop.
    pub decapsulation_key: SecureBuffer,
}

/// Generate a new ML-KEM-768 key pair using the system's secure RNG.
///
/// Returns [`DiaryError::Crypto`] if the key cannot be exported (should not occur in practice
/// for freshly generated keys).
pub fn keygen() -> Result<KemKeyPair, DiaryError> {
    let (dk, ek) = MlKem768::generate_keypair();

    let ek_bytes = ek.to_bytes().to_vec();

    let seed = dk
        .to_seed()
        .ok_or_else(|| DiaryError::Crypto("failed to export decapsulation key seed".into()))?;

    Ok(KemKeyPair {
        encapsulation_key: ek_bytes,
        decapsulation_key: SecureBuffer::new(seed.to_vec()),
    })
}

/// Encapsulate a fresh shared secret to the owner of `ek_bytes`.
///
/// Returns `(ciphertext, shared_secret)` where `shared_secret` is a 32-byte value stored in a
/// [`SecureBuffer`] that zeroes its memory on drop.
///
/// # Errors
/// Returns [`DiaryError::Crypto`] if `ek_bytes` has an incorrect length or invalid content.
pub fn encapsulate(ek_bytes: &[u8]) -> Result<(Vec<u8>, SecureBuffer), DiaryError> {
    let ek_key: Key<EncapsulationKey768> = ek_bytes.try_into().map_err(|_| {
        DiaryError::Crypto(format!(
            "invalid encapsulation key size: got {} bytes",
            ek_bytes.len()
        ))
    })?;

    let ek = EncapsulationKey768::new(&ek_key)
        .map_err(|_| DiaryError::Crypto("invalid encapsulation key content".into()))?;

    let (ct, shared_key) = ek.encapsulate();

    Ok((ct.to_vec(), SecureBuffer::new(shared_key.to_vec())))
}

/// Decapsulate `ct_bytes` using the private key seed `dk_bytes`.
///
/// Returns the shared secret as a [`SecureBuffer`] that zeroes its memory on drop.
///
/// # Errors
/// Returns [`DiaryError::Crypto`] if `dk_bytes` or `ct_bytes` have incorrect lengths.
///
/// Note: per FIPS 203, decapsulation of semantically invalid (but correctly sized) ciphertexts
/// returns a pseudorandom key (implicit rejection) rather than an error. An error is only returned
/// when the input cannot be parsed (wrong length).
pub fn decapsulate(dk_bytes: &SecureBuffer, ct_bytes: &[u8]) -> Result<SecureBuffer, DiaryError> {
    let seed: ml_kem::Seed = dk_bytes.as_ref().try_into().map_err(|_| {
        DiaryError::Crypto(format!(
            "invalid decapsulation key size: expected 64 bytes, got {}",
            dk_bytes.len()
        ))
    })?;

    let dk = DecapsulationKey768::from_seed(seed);

    let ct: Ciphertext<MlKem768> = ct_bytes.try_into().map_err(|_| {
        DiaryError::Crypto(format!(
            "invalid ciphertext size: got {} bytes",
            ct_bytes.len()
        ))
    })?;

    let shared_key = dk.decapsulate(&ct);

    Ok(SecureBuffer::new(shared_key.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DiaryError;

    /// TC-004-01: keygen returns a KemKeyPair with non-empty encapsulation and decapsulation keys.
    #[test]
    fn tc_004_01_keygen_returns_nonempty_keypair() {
        let kp = keygen().unwrap();
        assert!(!kp.encapsulation_key.is_empty());
        assert!(!kp.decapsulation_key.is_empty());
    }

    /// TC-004-02: encapsulate followed by decapsulate produces identical shared secrets.
    #[test]
    fn tc_004_02_encap_decap_shared_secret_matches() {
        let kp = keygen().unwrap();

        let (ct, ss_sender) = encapsulate(&kp.encapsulation_key).unwrap();
        let ss_receiver = decapsulate(&kp.decapsulation_key, &ct).unwrap();

        assert_eq!(ss_sender.as_ref(), ss_receiver.as_ref());
    }

    /// TC-004-03: DecapsulationKey (SecureBuffer) is zeroed by zeroize (called by Drop::drop).
    ///
    /// Uses `ManuallyDrop` to call `zeroize()` while the allocation is still live,
    /// avoiding undefined behavior from reading freed memory.
    #[test]
    fn tc_004_03_decapsulation_key_zeroize_on_drop() {
        use std::mem::ManuallyDrop;
        use zeroize::Zeroize;
        let mut kp = ManuallyDrop::new(keygen().unwrap());
        let ptr = kp.decapsulation_key.as_ref().as_ptr();
        let len = kp.decapsulation_key.len();
        kp.decapsulation_key.zeroize();
        // SAFETY: the allocation is still live because ManuallyDrop suppresses deallocation.
        unsafe {
            for i in 0..len {
                assert_eq!(*ptr.add(i), 0u8, "byte {i} not zeroed after zeroize");
            }
        }
    }

    /// TC-004-E01: incorrectly sized ciphertext returns DiaryError::Crypto.
    #[test]
    fn tc_004_e01_invalid_ciphertext_length_returns_error() {
        let kp = keygen().unwrap();
        let invalid_ct = b"too short";

        let result = decapsulate(&kp.decapsulation_key, invalid_ct);
        assert!(
            matches!(result, Err(DiaryError::Crypto(_))),
            "expected Crypto error for invalid ciphertext"
        );
    }
}
