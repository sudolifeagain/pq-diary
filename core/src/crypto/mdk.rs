//! Master Data Key (MDK) and HKDF subkey hierarchy.
//!
//! S16 separates the random 32-byte MDK from the credentials that unlock it.
//! The MDK is wrapped by keyslots on disk and is expanded in memory into
//! domain-separated subkeys for data encryption, per-record HMACs, and the
//! vault-wide integrity trailer.

use rand::{rngs::OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{crypto::hkdf, error::DiaryError};

/// HKDF info label for entry/template/attachment AES-256-GCM encryption.
pub const DATA_INFO: &[u8] = b"pq-diary/data/v1";
/// HKDF info label for per-record content HMACs.
pub const CONTENT_HMAC_INFO: &[u8] = b"pq-diary/content-hmac/v1";
/// HKDF info label for the vault-level integrity trailer.
pub const VAULT_INTEGRITY_INFO: &[u8] = b"pq-diary/vault-integrity/v1";

/// Random 32-byte master data key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterDataKey {
    inner: [u8; 32],
}

impl MasterDataKey {
    /// Generate a fresh MDK with the operating system CSPRNG.
    pub fn generate() -> Self {
        let mut inner = [0u8; 32];
        OsRng.fill_bytes(&mut inner);
        Self { inner }
    }

    /// Wrap a raw 32-byte MDK value.
    ///
    /// Intended for keyslot unwrap paths and tests. The returned type zeroizes
    /// the bytes on drop.
    pub fn from_bytes(inner: [u8; 32]) -> Self {
        Self { inner }
    }

    /// Derive a single 32-byte subkey for `info`.
    pub fn derive_subkey(&self, info: &[u8]) -> Result<Zeroizing<[u8; 32]>, DiaryError> {
        hkdf::derive_32(&self.inner, info)
    }

    /// Derive all S16 MDK subkeys.
    pub fn derive_subkeys(&self) -> Result<MdkSubkeys, DiaryError> {
        Ok(MdkSubkeys {
            data: self.derive_subkey(DATA_INFO)?,
            content_hmac: self.derive_subkey(CONTENT_HMAC_INFO)?,
            vault_integrity: self.derive_subkey(VAULT_INTEGRITY_INFO)?,
        })
    }
}

impl AsRef<[u8; 32]> for MasterDataKey {
    fn as_ref(&self) -> &[u8; 32] {
        &self.inner
    }
}

/// S16 MDK-derived subkeys.
pub struct MdkSubkeys {
    /// AES-256-GCM key for entry/template/attachment bodies.
    pub data: Zeroizing<[u8; 32]>,
    /// HMAC-SHA256 key for per-record `content_hmac`.
    pub content_hmac: Zeroizing<[u8; 32]>,
    /// HMAC-SHA256 key for the vault-wide integrity trailer.
    pub vault_integrity: Zeroizing<[u8; 32]>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::ManuallyDrop;

    #[test]
    fn tc_s16_mdk_02_subkeys_are_domain_separated() {
        let mdk = MasterDataKey::from_bytes([0x42u8; 32]);
        let subkeys = mdk.derive_subkeys().expect("derive_subkeys");

        assert_ne!(subkeys.data.as_ref(), subkeys.content_hmac.as_ref());
        assert_ne!(subkeys.data.as_ref(), subkeys.vault_integrity.as_ref());
        assert_ne!(
            subkeys.content_hmac.as_ref(),
            subkeys.vault_integrity.as_ref()
        );
    }

    #[test]
    fn tc_s16_mdk_03_subkey_derivation_is_deterministic() {
        let mdk = MasterDataKey::from_bytes([0xA5u8; 32]);

        let k1 = mdk.derive_subkey(DATA_INFO).expect("derive k1");
        let k2 = mdk.derive_subkey(DATA_INFO).expect("derive k2");
        let k3 = mdk.derive_subkey(CONTENT_HMAC_INFO).expect("derive hmac");

        assert_eq!(k1.as_ref(), k2.as_ref());
        assert_ne!(k1.as_ref(), k3.as_ref());
    }

    #[test]
    fn tc_s16_mdk_e01_master_data_key_zeroizes() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<MasterDataKey>();

        let mut mdk = ManuallyDrop::new(MasterDataKey::from_bytes([0xAAu8; 32]));
        let ptr = mdk.as_ref().as_ptr();
        mdk.zeroize();

        // SAFETY: ManuallyDrop keeps the allocation alive while we inspect the
        // in-place zeroize effect. This is test-only memory inspection.
        unsafe {
            for i in 0..32 {
                assert_eq!(*ptr.add(i), 0u8, "MDK byte {i} was not zeroized");
            }
        }
    }
}
