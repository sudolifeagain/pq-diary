//! ML-DSA-65 digital signature algorithm.
//!
//! Post-quantum digital signatures using the ML-DSA-65 algorithm (FIPS 204).
//! The signing key is stored as a 32-byte seed in [`SecureBuffer`], zeroed on drop.

use crate::{crypto::secure_mem::SecureBuffer, error::DiaryError};
use ml_dsa::{
    EncodedVerifyingKey, KeyGen, MlDsa65, Signature, VerifyingKey,
    signature::{Keypair, Signer, Verifier},
};
use rand::RngCore;
use zeroize::Zeroizing;

/// ML-DSA-65 key pair.
///
/// `verifying_key` (public) is safe to share freely.
/// `signing_key` stores only the 32-byte seed and is zeroed on drop via [`SecureBuffer`].
pub struct DsaKeyPair {
    /// Serialized ML-DSA-65 verifying (public) key (1952 bytes).
    pub verifying_key: Vec<u8>,
    /// 32-byte signing key seed, zeroed on drop.
    pub signing_key: SecureBuffer,
}

/// Generate a new ML-DSA-65 key pair using the system's secure RNG.
///
/// # Errors
/// Returns [`DiaryError::Crypto`] if key generation fails (not expected in practice).
pub fn keygen() -> Result<DsaKeyPair, DiaryError> {
    let mut seed_bytes = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(&mut seed_bytes[..]);

    let seed = ml_dsa::Seed::from(*seed_bytes);
    let sk = MlDsa65::from_seed(&seed);
    let vk = sk.verifying_key();
    let vk_bytes = vk.encode().to_vec();

    Ok(DsaKeyPair {
        verifying_key: vk_bytes,
        signing_key: SecureBuffer::new(seed_bytes[..].to_vec()),
    })
}

/// Sign `message` using the private key seed `sk`.
///
/// Returns the encoded signature bytes.
///
/// # Errors
/// Returns [`DiaryError::Crypto`] if `sk` does not contain a valid 32-byte seed.
pub fn sign(sk: &SecureBuffer, message: &[u8]) -> Result<Vec<u8>, DiaryError> {
    let seed: ml_dsa::Seed = sk.as_ref().try_into().map_err(|_| {
        DiaryError::Crypto(format!(
            "invalid signing key size: expected 32 bytes, got {}",
            sk.len()
        ))
    })?;

    let signing_key = MlDsa65::from_seed(&seed);
    let sig: Signature<MlDsa65> = signing_key
        .try_sign(message)
        .map_err(|e| DiaryError::Crypto(e.to_string()))?;

    Ok(sig.encode().to_vec())
}

/// Verify `signature` on `message` using the verifying key `pk`.
///
/// Returns `Ok(true)` if the signature is valid, `Ok(false)` if not.
/// A malformed or unparseable signature also returns `Ok(false)` rather than an error.
///
/// # Errors
/// Returns [`DiaryError::Crypto`] only if `pk` has an incorrect length and cannot be parsed.
pub fn verify(pk: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, DiaryError> {
    let vk_enc: EncodedVerifyingKey<MlDsa65> = pk.try_into().map_err(|_| {
        DiaryError::Crypto(format!(
            "invalid verifying key size: got {} bytes",
            pk.len()
        ))
    })?;
    let vk = VerifyingKey::<MlDsa65>::decode(&vk_enc);

    let sig = match Signature::<MlDsa65>::try_from(signature) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };

    Ok(vk.verify(message, &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TC-005-01: keygen returns a DsaKeyPair with non-empty keys.
    #[test]
    fn tc_005_01_keygen_returns_nonempty_keypair() {
        let kp = keygen().unwrap();
        assert!(!kp.verifying_key.is_empty());
        assert!(!kp.signing_key.is_empty());
    }

    /// TC-005-02: sign followed by verify succeeds.
    #[test]
    fn tc_005_02_sign_and_verify_success() {
        let kp = keygen().unwrap();
        let message = b"Hello, pq-diary!";

        let sig = sign(&kp.signing_key, message).unwrap();
        let result = verify(&kp.verifying_key, message, &sig).unwrap();

        assert!(result, "expected valid signature to verify as true");
    }

    /// TC-005-03: signing key (SecureBuffer) is zeroed by zeroize (called by Drop::drop).
    ///
    /// Uses `ManuallyDrop` to call `zeroize()` while the allocation is still live,
    /// avoiding undefined behavior from reading freed memory.
    #[test]
    fn tc_005_03_signing_key_zeroize_on_drop() {
        use std::mem::ManuallyDrop;
        use zeroize::Zeroize;
        let mut kp = ManuallyDrop::new(keygen().unwrap());
        let ptr = kp.signing_key.as_ref().as_ptr();
        let len = kp.signing_key.len();
        kp.signing_key.zeroize();
        // SAFETY: the allocation is still live because ManuallyDrop suppresses deallocation.
        unsafe {
            for i in 0..len {
                assert_eq!(*ptr.add(i), 0u8, "byte {i} not zeroed after zeroize");
            }
        }
    }

    /// TC-005-E01: tampered message causes verify to return false.
    #[test]
    fn tc_005_e01_tampered_message_verify_returns_false() {
        let kp = keygen().unwrap();
        let message = b"Original message";
        let tampered = b"Tampered message";

        let sig = sign(&kp.signing_key, message).unwrap();
        let result = verify(&kp.verifying_key, tampered, &sig).unwrap();

        assert!(!result, "expected tampered message to fail verification");
    }

    /// TC-005-E02: tampered signature causes verify to return false.
    #[test]
    fn tc_005_e02_tampered_signature_verify_returns_false() {
        let kp = keygen().unwrap();
        let message = b"Some message";

        let mut sig = sign(&kp.signing_key, message).unwrap();
        // Flip bits in the middle of the signature
        if let Some(b) = sig.get_mut(100) {
            *b ^= 0xFF;
        }

        let result = verify(&kp.verifying_key, message, &sig).unwrap();
        assert!(!result, "expected tampered signature to fail verification");
    }
}
