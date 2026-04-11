//! HMAC-SHA256 message authentication code.
//!
//! Provides HMAC-SHA256 computation and constant-time verification
//! for use as the `content_hmac` integrity check on journal entries.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::DiaryError;

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256 of `data` under `key`.
///
/// Any key length is accepted; the HMAC construction handles padding internally.
/// Returns `Ok([u8; 32])` on success.
///
/// # Errors
///
/// Returns [`DiaryError::Crypto`] if the key is rejected by the HMAC implementation
/// (this is unreachable in practice since HMAC-SHA256 accepts all key lengths).
pub fn compute(key: &[u8], data: &[u8]) -> Result<[u8; 32], DiaryError> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| DiaryError::Crypto(format!("HMAC key error: {e}")))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

/// Verify that `expected` equals the HMAC-SHA256 of `data` under `key`.
///
/// Uses constant-time comparison via [`hmac::Mac::verify_slice`] to prevent
/// timing side-channel attacks.
/// Returns `Ok(true)` if the MAC matches, `Ok(false)` otherwise.
///
/// # Errors
///
/// Returns [`DiaryError::Crypto`] if the key is rejected by the HMAC implementation
/// (this is unreachable in practice since HMAC-SHA256 accepts all key lengths).
pub fn verify_hmac(key: &[u8], data: &[u8], expected: &[u8; 32]) -> Result<bool, DiaryError> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| DiaryError::Crypto(format!("HMAC key error: {e}")))?;
    mac.update(data);
    Ok(mac.verify_slice(expected).is_ok())
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
        let mac = compute(test_key(), b"hello, pq-diary!").expect("compute");
        assert_eq!(mac.len(), 32);
    }

    /// TC-006-02: different data → different MACs.
    #[test]
    fn tc_006_02_different_data_different_mac() {
        let mac1 = compute(test_key(), b"data-one").expect("mac1");
        let mac2 = compute(test_key(), b"data-two").expect("mac2");
        assert_ne!(mac1, mac2);
    }

    /// TC-006-03: verify_hmac returns Ok(true) for the correct MAC.
    #[test]
    fn tc_006_03_verify_correct_mac_returns_true() {
        let data = b"journal entry content";
        let mac = compute(test_key(), data).expect("compute");
        assert!(verify_hmac(test_key(), data, &mac).expect("verify_hmac"));
    }

    /// TC-006-E01: tampered data → verify_hmac returns Ok(false).
    #[test]
    fn tc_006_e01_tampered_data_returns_false() {
        let data = b"original content";
        let mac = compute(test_key(), data).expect("compute");
        // Tamper the data.
        assert!(!verify_hmac(test_key(), b"tampered content", &mac).expect("verify_hmac"));
    }

    /// TC-A09-01: compute() returns Result<[u8; 32], DiaryError>.
    ///
    /// Verifies that the return type is Result and that a successful call
    /// returns Ok with a 32-byte MAC.
    #[test]
    fn tc_a09_01_compute_returns_result() {
        let result: Result<[u8; 32], crate::error::DiaryError> = compute(test_key(), b"test data");
        assert!(result.is_ok(), "compute should return Ok for valid key");
        let mac = result.expect("Ok");
        assert_eq!(mac.len(), 32);
    }

    /// Same key + data always produces the same MAC (deterministic).
    #[test]
    fn deterministic_output() {
        let mac1 = compute(test_key(), b"same data").expect("mac1");
        let mac2 = compute(test_key(), b"same data").expect("mac2");
        assert_eq!(mac1, mac2);
    }

    /// Different key → different MAC even for the same data.
    #[test]
    fn different_key_different_mac() {
        let mac1 = compute(b"key-one", b"data").expect("mac1");
        let mac2 = compute(b"key-two", b"data").expect("mac2");
        assert_ne!(mac1, mac2);
    }

    /// Wrong key → verify_hmac returns Ok(false).
    #[test]
    fn wrong_key_returns_false() {
        let data = b"content";
        let mac = compute(test_key(), data).expect("compute");
        assert!(!verify_hmac(b"wrong-key", data, &mac).expect("verify_hmac"));
    }

    /// Empty key is accepted (any key length is valid for HMAC).
    #[test]
    fn empty_key_is_accepted() {
        let mac = compute(b"", b"data").expect("compute");
        assert_eq!(mac.len(), 32);
        assert!(verify_hmac(b"", b"data", &mac).expect("verify_hmac"));
    }

    /// Empty data is accepted.
    #[test]
    fn empty_data_is_accepted() {
        let mac = compute(test_key(), b"").expect("compute");
        assert_eq!(mac.len(), 32);
        assert!(verify_hmac(test_key(), b"", &mac).expect("verify_hmac"));
    }

    // -------------------------------------------------------------------------
    // TASK-0080 tests: M-5 verify_hmac Result化
    // -------------------------------------------------------------------------

    /// TC-S9-080-07: verify_hmac returns Ok(true) for correct HMAC.
    #[test]
    fn tc_s9_080_07_verify_hmac_ok_true_for_correct_mac() {
        let key = b"known-key-for-tc-s9-080";
        let data = b"known data content";
        let mac = compute(key, data).expect("compute");
        let result = verify_hmac(key, data, &mac);
        assert!(result.is_ok(), "verify_hmac must return Ok for valid key");
        assert!(
            result.unwrap(),
            "verify_hmac must return Ok(true) for matching MAC"
        );
    }

    /// TC-S9-080-08: verify_hmac returns Ok(false) for tampered HMAC.
    #[test]
    fn tc_s9_080_08_verify_hmac_ok_false_for_wrong_mac() {
        let key = b"known-key-for-tc-s9-080";
        let data = b"known data content";
        let mut wrong_mac = compute(key, data).expect("compute");
        // Tamper one byte.
        wrong_mac[0] ^= 0xff;
        let result = verify_hmac(key, data, &wrong_mac);
        assert!(
            result.is_ok(),
            "verify_hmac must return Ok even for mismatched MAC"
        );
        assert!(
            !result.unwrap(),
            "verify_hmac must return Ok(false) for mismatched MAC"
        );
    }

    /// TC-S9-080-09: verify_hmac returns Result<bool, DiaryError> (type-level check).
    ///
    /// Note: HmacSha256::new_from_slice accepts any key length, so the
    /// Err(DiaryError::Crypto) path cannot be triggered at runtime for HMAC-SHA256.
    /// This test verifies the function signature compiles as Result and that
    /// edge-case keys (empty, very short) are handled correctly via Ok(…).
    #[test]
    fn tc_s9_080_09_verify_hmac_result_type_and_edge_keys() {
        // Type annotation confirms the return type is Result<bool, DiaryError>.
        let _: Result<bool, crate::error::DiaryError> = verify_hmac(b"k", b"d", &[0u8; 32]);

        // Empty key returns Ok (HMAC accepts any key length).
        let mac_empty_key = compute(b"", b"data").expect("compute");
        let r = verify_hmac(b"", b"data", &mac_empty_key);
        assert!(r.is_ok(), "empty key must return Ok, not Err");

        // Single-byte key returns Ok.
        let mac_short_key = compute(b"x", b"data").expect("compute");
        let r2 = verify_hmac(b"x", b"data", &mac_short_key);
        assert!(r2.is_ok(), "single-byte key must return Ok, not Err");
    }
}
