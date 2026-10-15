//! Shared ciphertext construction for entry and template records.

use crate::{crypto::CryptoEngine, error::DiaryError};

/// Only sealed fields; plaintext ownership and record metadata stay with callers.
pub(crate) struct SealedPayload {
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) iv: [u8; crate::crypto::aead::NONCE_SIZE],
    pub(crate) signature: Vec<u8>,
    pub(crate) content_hmac: [u8; 32],
}

/// Encrypt with a fresh IV, then sign and HMAC exactly the ciphertext.
/// Nothing is persisted and no plaintext is retained by the returned payload.
pub(crate) fn seal(engine: &CryptoEngine, plaintext: &[u8]) -> Result<SealedPayload, DiaryError> {
    let (ciphertext, iv) = engine.encrypt(plaintext)?;
    let signature = engine.dsa_sign(&ciphertext)?;
    let content_hmac = engine.hmac(&ciphertext)?;
    Ok(SealedPayload {
        ciphertext,
        iv,
        signature,
        content_hmac,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::dsa;

    fn engine() -> CryptoEngine {
        let keys = dsa::keygen().expect("test signing keys");
        CryptoEngine::new_for_testing([0x42; 32], keys.signing_key.as_ref().to_vec())
    }

    #[test]
    fn sealed_payload_roundtrips_and_authenticates_ciphertext() {
        let engine = engine();
        for plaintext in [b"".as_slice(), b"entry or template body\0with bytes"] {
            let payload = seal(&engine, plaintext).expect("seal");
            let decrypted = engine
                .decrypt(&payload.iv, &payload.ciphertext)
                .expect("decrypt");
            assert_eq!(decrypted.as_ref(), plaintext);
            assert!(engine
                .dsa_verify_entry(&payload.ciphertext, &payload.signature)
                .expect("verify signature"));
            assert!(engine
                .hmac_verify(&payload.ciphertext, &payload.content_hmac)
                .expect("verify HMAC"));
        }
    }

    #[test]
    fn changed_ciphertext_fails_signature_hmac_and_decryption() {
        let engine = engine();
        let mut payload = seal(&engine, b"synthetic body").expect("seal");
        payload.ciphertext[0] ^= 1;
        assert!(!engine
            .dsa_verify_entry(&payload.ciphertext, &payload.signature)
            .expect("verify signature"));
        assert!(!engine
            .hmac_verify(&payload.ciphertext, &payload.content_hmac)
            .expect("verify HMAC"));
        assert!(engine.decrypt(&payload.iv, &payload.ciphertext).is_err());
    }

    #[test]
    fn locked_engine_preserves_not_unlocked_error() {
        assert!(matches!(
            seal(&CryptoEngine::default(), b"synthetic body"),
            Err(DiaryError::NotUnlocked)
        ));
        let mut engine = engine();
        engine.lock();
        assert!(matches!(
            seal(&engine, b"synthetic body"),
            Err(DiaryError::NotUnlocked)
        ));
    }
}
