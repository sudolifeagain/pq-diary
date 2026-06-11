//! HKDF-SHA256 helpers for domain-separated key derivation.
//!
//! S16 uses RFC 5869 Extract-then-Expand with SHA-256 for all MDK subkeys and
//! KEM-derived keyslot keys. Only 32-byte outputs are needed by the vault
//! format, so this module exposes a narrow helper instead of a generic KDF API.

use zeroize::Zeroizing;

use crate::{crypto::hmac_util, error::DiaryError};

const HASH_LEN: usize = 32;

/// Derive one 32-byte HKDF-SHA256 output from `ikm` and domain-separation `info`.
///
/// Uses the RFC 5869 default all-zero salt when no application salt is supplied:
/// `PRK = HMAC-SHA256(0x00 * 32, IKM)`, then
/// `OKM = HMAC-SHA256(PRK, info || 0x01)`.
pub fn derive_32(ikm: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>, DiaryError> {
    let zero_salt = [0u8; HASH_LEN];
    let prk = Zeroizing::new(hmac_util::compute(&zero_salt, ikm)?);

    let mut expand_input = Vec::with_capacity(info.len() + 1);
    expand_input.extend_from_slice(info);
    expand_input.push(1u8);

    Ok(Zeroizing::new(hmac_util::compute(
        prk.as_ref(),
        &expand_input,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_derive_32_is_deterministic_for_same_info() {
        let k1 = derive_32(b"input key material", b"pq-diary/test/v1").expect("derive k1");
        let k2 = derive_32(b"input key material", b"pq-diary/test/v1").expect("derive k2");

        assert_eq!(k1.as_ref(), k2.as_ref());
    }

    #[test]
    fn hkdf_derive_32_domain_separates_info_labels() {
        let k1 = derive_32(b"input key material", b"pq-diary/data/v1").expect("derive data");
        let k2 =
            derive_32(b"input key material", b"pq-diary/content-hmac/v1").expect("derive hmac");

        assert_ne!(k1.as_ref(), k2.as_ref());
    }

    #[test]
    fn hkdf_derive_32_output_is_32_bytes() {
        let k = derive_32(b"ikm", b"info").expect("derive");
        assert_eq!(k.as_ref().len(), 32);
    }
}
