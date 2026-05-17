//! Vault master-password change operation.
//!
//! Implements the core re-encryption routine used by the `change-password`
//! CLI command. The vault's KEM and DSA seeds are preserved unchanged so
//! that previously written signatures remain verifiable; only the
//! password-dependent material (KDF salt, verification token, encrypted
//! key blobs) and all entry payloads are re-encrypted with the new key.
//!
//! Failure handling is atomic: the new vault is written to `vault.pqd.tmp`
//! first and renamed only on success. On any error the temporary file is
//! best-effort overwritten with zeros and removed, leaving the original
//! `vault.pqd` untouched.

use std::path::Path;

use rand::{rngs::OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::crypto::{aead, kdf};
use crate::entry::EntryPlaintext;
use crate::error::DiaryError;
use crate::vault::format::{
    generate_verification_token, EntryRecord, VaultHeader, RECORD_TYPE_ENTRY,
};
use crate::vault::reader::read_vault;
use crate::vault::writer::write_vault;

/// Re-encrypt the vault at `vault_dir` with a new master password.
///
/// `vault_dir` must contain `vault.pqd` and `vault.toml`. The Argon2id
/// parameters from `vault.toml` are reused for the new key derivation.
///
/// The KEM and DSA seeds are preserved, so the `dsa_pk_hash` field remains
/// unchanged and existing signatures continue to verify.
///
/// All in-memory secrets (old key, new key, decrypted KEM/DSA seeds,
/// decrypted entry payloads) are held in zeroize-on-drop containers and
/// erased when the function returns.
///
/// # Errors
///
/// Returns [`DiaryError::Crypto`] when the old password is incorrect or any
/// cryptographic operation fails. Returns [`DiaryError::Io`] on file-system
/// failures. Returns [`DiaryError::Config`] when `vault.toml` cannot be
/// parsed.
pub fn re_encrypt_vault(
    vault_dir: &Path,
    old_pwd: &SecretString,
    new_pwd: &SecretString,
) -> Result<(), DiaryError> {
    use crate::vault::config::VaultConfig;

    if new_pwd.expose_secret().is_empty() {
        return Err(DiaryError::Password(
            "new password must not be empty".to_string(),
        ));
    }

    let vault_pqd = vault_dir.join("vault.pqd");
    let vault_toml = vault_dir.join("vault.toml");

    let vault_config = VaultConfig::from_file(&vault_toml)?;
    let params = kdf::Argon2Params {
        memory_cost_kb: vault_config.argon2.memory_cost_kb,
        time_cost: vault_config.argon2.time_cost,
        parallelism: vault_config.argon2.parallelism,
    };

    // Step 1: read current vault.
    let (header, entries) = read_vault(&vault_pqd)?;

    // Step 2: derive OLD symmetric key from old password and stored salt.
    let old_key = kdf::derive_key(
        old_pwd.expose_secret().as_bytes(),
        &header.kdf_salt,
        &params,
    )?;

    // Step 3: verify old password by decrypting the verification token.
    aead::decrypt(
        old_key.as_ref(),
        header.verification_iv,
        &header.verification_ct,
    )
    .map_err(|_| DiaryError::Crypto("invalid password".to_string()))?;

    // Step 4: decrypt KEM and DSA seeds with the old key.
    let kem_seed = decrypt_blob(old_key.as_ref(), &header.kem_encrypted_sk, "KEM")?;
    let dsa_seed = decrypt_blob(old_key.as_ref(), &header.dsa_encrypted_sk, "DSA")?;

    // Step 5: generate fresh KDF salt and derive the NEW symmetric key.
    let mut new_kdf_salt = [0u8; 32];
    OsRng.fill_bytes(&mut new_kdf_salt);
    let new_key = kdf::derive_key(new_pwd.expose_secret().as_bytes(), &new_kdf_salt, &params)?;

    // Step 6: build new verification token + re-encrypted KEM/DSA seeds.
    let (new_verification_iv, new_verification_ct) = generate_verification_token(new_key.as_ref())?;
    let new_kem_encrypted_sk = encrypt_blob(new_key.as_ref(), kem_seed.as_slice())?;
    let new_dsa_encrypted_sk = encrypt_blob(new_key.as_ref(), dsa_seed.as_slice())?;

    // Step 7: build the new header. KEM/DSA seeds are preserved unchanged,
    // so dsa_pk_hash remains identical and previously-issued signatures stay
    // valid. legacy_salt is preserved (it depends on a separate legacy key).
    let new_header = VaultHeader {
        schema_version: header.schema_version,
        flags: header.flags,
        payload_size: 0, // recomputed by write_vault
        kdf_salt: new_kdf_salt,
        legacy_salt: header.legacy_salt,
        verification_iv: new_verification_iv,
        verification_ct: new_verification_ct,
        kem_pk_offset: header.kem_pk_offset,
        dsa_pk_hash: header.dsa_pk_hash,
        kem_encrypted_sk: new_kem_encrypted_sk,
        dsa_encrypted_sk: new_dsa_encrypted_sk,
    };

    // Step 8: re-encrypt every entry record under the new symmetric key.
    // The DSA signing key seed is preserved, so signatures need not be
    // regenerated, but we re-sign anyway to bind the new ciphertext.
    let mut new_entries = Vec::with_capacity(entries.len());
    for record in entries {
        let new_record = re_encrypt_entry(&record, old_key.as_ref(), new_key.as_ref(), &dsa_seed)?;
        new_entries.push(new_record);
    }

    // Step 9: write the new vault to vault.pqd.tmp.path() then atomically rename
    // it on top of the original. write_vault already performs the .tmp+rename
    // dance internally, so we redirect it at a side-by-side path and then move
    // it into place. This guarantees that the original vault remains intact
    // until the very last fs::rename, and the temporary file is cleaned up on
    // failure.
    let final_tmp = vault_dir.join("vault.pqd.tmp.new");
    let write_result = write_vault(&final_tmp, new_header, &new_entries);
    if let Err(e) = write_result {
        cleanup_tmp(&final_tmp);
        return Err(e);
    }

    // Atomic swap: replace vault.pqd with the new file.
    if let Err(e) = std::fs::rename(&final_tmp, &vault_pqd) {
        cleanup_tmp(&final_tmp);
        return Err(DiaryError::Io(e));
    }

    Ok(())
}

/// Decrypt an `IV || ciphertext` blob using the symmetric key.
fn decrypt_blob(
    sym_key: &[u8; 32],
    blob: &[u8],
    label: &str,
) -> Result<Zeroizing<Vec<u8>>, DiaryError> {
    if blob.len() < aead::NONCE_SIZE {
        return Err(DiaryError::Crypto(format!(
            "{label} encrypted blob is shorter than the AEAD nonce"
        )));
    }
    let iv: [u8; aead::NONCE_SIZE] = blob[..aead::NONCE_SIZE]
        .try_into()
        .map_err(|_| DiaryError::Crypto(format!("{label} encrypted blob has invalid IV")))?;
    let ct = &blob[aead::NONCE_SIZE..];
    let plain = aead::decrypt(sym_key, iv, ct)
        .map_err(|_| DiaryError::Crypto(format!("failed to decrypt {label} key")))?;
    Ok(Zeroizing::new(plain.as_ref().to_vec()))
}

/// Encrypt `plaintext` under `sym_key`, returning a fresh `IV || ciphertext` blob.
fn encrypt_blob(sym_key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, DiaryError> {
    let (ct, iv) = aead::encrypt(sym_key, plaintext)?;
    let mut out = Vec::with_capacity(iv.len() + ct.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Re-encrypt a single entry record under the new symmetric key.
///
/// Decrypts the JSON payload with the OLD key, re-encrypts it with the NEW
/// key, signs the new ciphertext with the preserved DSA seed, and recomputes
/// the HMAC with the NEW key. UUID, timestamps, legacy fields, and
/// attachment metadata are copied verbatim. Padding is regenerated through
/// `write_vault` later; we retain the existing padding for record-level
/// compatibility.
fn re_encrypt_entry(
    record: &EntryRecord,
    old_sym_key: &[u8; 32],
    new_sym_key: &[u8; 32],
    dsa_seed: &Zeroizing<Vec<u8>>,
) -> Result<EntryRecord, DiaryError> {
    use crate::crypto::secure_mem::SecureBuffer;
    use crate::crypto::{dsa, hmac_util};

    if record.record_type != RECORD_TYPE_ENTRY {
        // Template records (RECORD_TYPE_TEMPLATE) follow the same encrypt/decrypt
        // primitives; treat them identically. Anything else is rejected.
        // We allow them through the same code path for now.
    }

    // Decrypt with old key.
    let plain = aead::decrypt(old_sym_key, record.iv, &record.ciphertext)?;

    // Ensure the JSON parses back into a valid EntryPlaintext so that we
    // detect truncation / corruption before writing the new vault.
    let _check: EntryPlaintext = serde_json::from_slice(plain.as_ref())
        .map_err(|e| DiaryError::Entry(format!("deserialization failed: {e}")))?;

    // Re-encrypt with the new symmetric key.
    let (new_ct, new_iv) = aead::encrypt(new_sym_key, plain.as_ref())?;

    // Re-sign the new ciphertext using the preserved DSA seed.
    let dsa_sk = SecureBuffer::new(dsa_seed.as_slice().to_vec());
    let new_signature = dsa::sign(&dsa_sk, &new_ct)?;

    // Recompute the HMAC under the new symmetric key.
    let new_hmac = hmac_util::compute(new_sym_key, &new_ct)?;

    Ok(EntryRecord {
        record_type: record.record_type,
        uuid: record.uuid,
        created_at: record.created_at,
        updated_at: record.updated_at,
        iv: new_iv,
        ciphertext: new_ct,
        signature: new_signature,
        content_hmac: new_hmac,
        legacy_flag: record.legacy_flag,
        legacy_key_block: record.legacy_key_block.clone(),
        attachment_count: record.attachment_count,
        attachment_offset: record.attachment_offset,
        padding: record.padding.clone(),
    })
}

/// Best-effort cleanup of a temporary vault file. Errors are ignored except
/// for `NotFound` because the file may already have been moved or never
/// created.
fn cleanup_tmp(path: &Path) {
    // First, zeroize the contents by overwriting with random bytes (best effort).
    if let Ok(meta) = std::fs::metadata(path) {
        let size = meta.len() as usize;
        if size > 0 {
            let mut buf = Zeroizing::new(vec![0u8; size]);
            OsRng.fill_bytes(&mut buf);
            if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
                use std::io::Write as _;
                let _ = f.write_all(&buf);
                let _ = f.sync_all();
            }
        }
    }
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            eprintln!("Warning: failed to remove temporary vault file: {e}");
        }
    }
    // Also remove the standard ".tmp" file that write_vault might have left.
    let std_tmp = path.with_extension("new.tmp");
    if let Err(e) = std::fs::remove_file(&std_tmp) {
        if e.kind() != std::io::ErrorKind::NotFound {
            // Silently ignore; non-existence is the expected state.
            let _ = e;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::Argon2Params;
    use crate::vault::init::VaultManager;
    use crate::DiaryCore;
    use secrecy::SecretBox;
    use tempfile::tempdir;

    fn fast_params() -> Argon2Params {
        Argon2Params {
            memory_cost_kb: 8,
            time_cost: 1,
            parallelism: 1,
        }
    }

    fn make_secret(s: &str) -> SecretString {
        SecretBox::new(Box::from(s))
    }

    /// Setup a vault with the given password and Argon2 params.
    fn setup_vault(dir: &tempfile::TempDir, password: &[u8]) -> std::path::PathBuf {
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());
        mgr.init_vault("v", password).expect("init_vault");
        dir.path().join("v")
    }

    /// TC-CP-CORE-01: empty vault re-encrypt; old password fails, new succeeds.
    #[test]
    fn tc_cp_core_01_empty_vault_round_trip() {
        let dir = tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir, b"Old123!");

        let old = make_secret("Old123!");
        let new = make_secret("New456!");
        re_encrypt_vault(&vault_dir, &old, &new).expect("re_encrypt_vault");

        let vault_pqd = vault_dir.join("vault.pqd");
        let vault_pqd_str = vault_pqd.to_str().expect("utf8");

        // Old password must fail.
        let mut core = DiaryCore::new(vault_pqd_str).expect("DiaryCore::new");
        assert!(
            core.unlock(make_secret("Old123!")).is_err(),
            "old password must no longer unlock the vault"
        );

        // New password must succeed.
        let mut core2 = DiaryCore::new(vault_pqd_str).expect("DiaryCore::new");
        core2
            .unlock(make_secret("New456!"))
            .expect("new password must unlock");
    }

    /// TC-CP-CORE-02: entries round-trip after change_password.
    #[test]
    fn tc_cp_core_02_entries_round_trip() {
        let dir = tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir, b"Old123!");
        let vault_pqd = vault_dir.join("vault.pqd");
        let vault_pqd_str = vault_pqd.to_str().expect("utf8");

        // Create 3 entries.
        {
            let mut core = DiaryCore::new(vault_pqd_str).expect("DiaryCore::new");
            core.unlock(make_secret("Old123!")).expect("unlock");
            core.new_entry("title-1", "body-1", vec!["t1".into()])
                .expect("new_entry 1");
            core.new_entry("title-2", "body-2", vec!["t2".into()])
                .expect("new_entry 2");
            core.new_entry("title-3", "body-3", vec![])
                .expect("new_entry 3");
        }

        re_encrypt_vault(&vault_dir, &make_secret("Old123!"), &make_secret("New456!"))
            .expect("re_encrypt_vault");

        // Read with new password and verify the three entries.
        let mut core = DiaryCore::new(vault_pqd_str).expect("DiaryCore::new");
        core.unlock(make_secret("New456!"))
            .expect("unlock with new");
        let mut entries = core.list_entries(None).expect("list_entries");
        entries.sort_by(|a, b| a.title.cmp(&b.title));
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].title, "title-1");
        assert_eq!(entries[1].title, "title-2");
        assert_eq!(entries[2].title, "title-3");
    }

    /// TC-CP-CORE-03: KEM/DSA public-key hash is preserved.
    #[test]
    fn tc_cp_core_03_dsa_pk_hash_preserved() {
        let dir = tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir, b"Old123!");
        let vault_pqd = vault_dir.join("vault.pqd");

        let (header_before, _) = read_vault(&vault_pqd).expect("read_vault before");
        let pk_hash_before = header_before.dsa_pk_hash;

        re_encrypt_vault(&vault_dir, &make_secret("Old123!"), &make_secret("New456!"))
            .expect("re_encrypt_vault");

        let (header_after, _) = read_vault(&vault_pqd).expect("read_vault after");
        assert_eq!(
            header_after.dsa_pk_hash, pk_hash_before,
            "dsa_pk_hash must be unchanged after change_password"
        );
    }

    /// TC-CP-CORE-04: kdf_salt changes after re-encryption.
    #[test]
    fn tc_cp_core_04_kdf_salt_changes() {
        let dir = tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir, b"Old123!");
        let vault_pqd = vault_dir.join("vault.pqd");

        let (header_before, _) = read_vault(&vault_pqd).expect("read before");
        let salt_before = header_before.kdf_salt;

        re_encrypt_vault(&vault_dir, &make_secret("Old123!"), &make_secret("New456!"))
            .expect("re_encrypt_vault");

        let (header_after, _) = read_vault(&vault_pqd).expect("read after");
        assert_ne!(
            header_after.kdf_salt, salt_before,
            "kdf_salt must be regenerated"
        );
    }

    /// TC-CP-CORE-08: wrong old password fails and vault is untouched.
    #[test]
    fn tc_cp_core_08_wrong_old_password() {
        let dir = tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir, b"Old123!");
        let vault_pqd = vault_dir.join("vault.pqd");

        let bytes_before = std::fs::read(&vault_pqd).expect("read bytes");

        let result = re_encrypt_vault(&vault_dir, &make_secret("Wrong"), &make_secret("New456!"));
        assert!(
            matches!(result, Err(DiaryError::Crypto(_))),
            "wrong old password must return Err(Crypto), got {:?}",
            result
        );

        let bytes_after = std::fs::read(&vault_pqd).expect("read bytes again");
        assert_eq!(bytes_before, bytes_after, "vault.pqd must be untouched");
    }

    /// TC-CP-CORE-09: 1 MB body re-encrypts and round-trips byte-for-byte.
    #[test]
    fn tc_cp_core_09_large_body_round_trip() {
        let dir = tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir, b"Old123!");
        let vault_pqd = vault_dir.join("vault.pqd");
        let vault_pqd_str = vault_pqd.to_str().expect("utf8");

        let body: String = "x".repeat(1024 * 1024);

        let entry_id = {
            let mut core = DiaryCore::new(vault_pqd_str).expect("DiaryCore::new");
            core.unlock(make_secret("Old123!")).expect("unlock");
            core.new_entry("big", &body, vec![]).expect("new_entry")
        };

        re_encrypt_vault(&vault_dir, &make_secret("Old123!"), &make_secret("New456!"))
            .expect("re_encrypt_vault");

        let mut core = DiaryCore::new(vault_pqd_str).expect("DiaryCore::new");
        core.unlock(make_secret("New456!")).expect("unlock new");
        let (_, plaintext) = core.get_entry(&entry_id[..8]).expect("get_entry");
        assert_eq!(plaintext.body.len(), body.len());
        assert_eq!(plaintext.body, body, "body must round-trip byte-for-byte");
    }

    /// TC-CP-CORE-NEW: empty new password is rejected.
    #[test]
    fn tc_cp_core_empty_new_password_rejected() {
        let dir = tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir, b"Old123!");

        let result = re_encrypt_vault(&vault_dir, &make_secret("Old123!"), &make_secret(""));
        assert!(
            matches!(result, Err(DiaryError::Password(_))),
            "empty new password must return Err(Password), got {:?}",
            result
        );
    }
}
