//! HMAC-SHA256 message authentication code.
//!
//! Provides HMAC-SHA256 computation and constant-time verification
//! for use as the `content_hmac` integrity check on journal entries.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256 of `data` under `key`.
///
/// Any key length is accepted; the HMAC construction handles padding internally.
/// Returns a 32-byte fixed-size MAC value.
pub fn compute(key: &[u8], data: &[u8]) -> [u8; 32] {
    // HmacSha256 accepts keys of any length; new_from_slice never fails here.
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        // Unreachable: HMAC-SHA256 accepts all key lengths.
        return [0u8; 32];
    };
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Verify that `expected` equals the HMAC-SHA256 of `data` under `key`.
///
/// Uses constant-time comparison via [`hmac::Mac::verify_slice`] to prevent
/// timing side-channel attacks.
/// Returns `true` if the MAC matches, `false` otherwise.
pub fn verify_hmac(key: &[u8], data: &[u8], expected: &[u8; 32]) -> bool {
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return false;
    };
    mac.update(data);
    mac.verify_slice(expected).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> &'static [u8] {
        b"test-key-for-hmac-sha256-verification"
    }

    /// TC-006-01: correct key and data → 32-byte MAC.
    #[test]
    fn tc_006_01_output_is_32_bytes() {
        let mac = compute(test_key(), b"hello, pq-diary!");
        assert_eq!(mac.len(), 32);
    }

    /// TC-006-02: different data → different MACs.
    #[test]
    fn tc_006_02_different_data_different_mac() {
        let mac1 = compute(test_key(), b"data-one");
        let mac2 = compute(test_key(), b"data-two");
        assert_ne!(mac1, mac2);
    }

    /// TC-006-03: verify_hmac returns true for the correct MAC.
    #[test]
    fn tc_006_03_verify_correct_mac_returns_true() {
        let data = b"journal entry content";
        let mac = compute(test_key(), data);
        assert!(verify_hmac(test_key(), data, &mac));
    }

    /// TC-006-E01: tampered data → verify_hmac returns false.
    #[test]
    fn tc_006_e01_tampered_data_returns_false() {
        let data = b"original content";
        let mac = compute(test_key(), data);
        // Tamper the data.
        assert!(!verify_hmac(test_key(), b"tampered content", &mac));
    }

    /// Same key + data always produces the same MAC (deterministic).
    #[test]
    fn deterministic_output() {
        let mac1 = compute(test_key(), b"same data");
        let mac2 = compute(test_key(), b"same data");
        assert_eq!(mac1, mac2);
    }

    /// Different key → different MAC even for the same data.
    #[test]
    fn different_key_different_mac() {
        let mac1 = compute(b"key-one", b"data");
        let mac2 = compute(b"key-two", b"data");
        assert_ne!(mac1, mac2);
    }

    /// Wrong key → verify_hmac returns false.
    #[test]
    fn wrong_key_returns_false() {
        let data = b"content";
        let mac = compute(test_key(), data);
        assert!(!verify_hmac(b"wrong-key", data, &mac));
    }

    /// Empty key is accepted (any key length is valid for HMAC).
    #[test]
    fn empty_key_is_accepted() {
        let mac = compute(b"", b"data");
        assert_eq!(mac.len(), 32);
        assert!(verify_hmac(b"", b"data", &mac));
    }

    /// Empty data is accepted.
    #[test]
    fn empty_data_is_accepted() {
        let mac = compute(test_key(), b"");
        assert_eq!(mac.len(), 32);
        assert!(verify_hmac(test_key(), b"", &mac));
    }
}
