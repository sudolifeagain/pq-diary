//! Vault master-password change operation.
//!
//! Implements the core re-encryption routine used by the `change-password`
//! CLI command. The vault's KEM and DSA seeds are preserved unchanged so
//! that previously written signatures remain verifiable; only the
//! password-dependent material (KDF salt, verification token, encrypted
//! key blobs) and all entry payloads are re-encrypted with the new key.
//!
//! The authenticated writer owns a uniquely created sibling and atomically
//! replaces `vault.pqd` only after writing and syncing succeed. Pre-commit
//! failures preserve the original and clean up only that owned sibling.
//! This does not guarantee physical erasure or crash durability.

use std::path::Path;

use rand::{rngs::OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::crypto::{aead, kdf};
use crate::entry::EntryPlaintext;
use crate::error::DiaryError;
use crate::template::TemplatePlaintext;
use crate::vault::format::{
    generate_verification_token, EntryRecord, VaultHeader, RECORD_TYPE_ENTRY, RECORD_TYPE_TEMPLATE,
};

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

    // Step 1: read current vault (entries + attachments).
    let vault_bytes = std::fs::read(&vault_pqd)?;
    let (header, entries, attachments) =
        crate::vault::reader::read_vault_with_attachments_from_bytes(&vault_bytes)?;

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

    // Authenticate metadata and record ordering before re-encryption can
    // endorse modified data with a fresh key and MAC.
    let old_mac_key = crate::crypto::derive_vault_mac_key(old_key.as_ref())?;
    crate::vault::reader::verify_vault_integrity_bytes(&vault_bytes, &old_mac_key)?;
    drop(vault_bytes);

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

    // S13: re-encrypt attachment metadata. The `.attachments/<uuid>.bin` body
    // files are NOT touched — design Q4 keeps a per-blob FileKey inside the
    // encrypted metadata so password rotation never has to read or rewrite the
    // possibly-gigabyte binaries.
    let new_attachments = crate::attachment::reencrypt_attachments_for_change_password(
        &attachments,
        old_key.as_ref(),
        new_key.as_ref(),
        &dsa_seed,
    )?;

    // Step 9: the authenticated writer owns staging and the atomic commit.
    // All records are prepared above; no outer temporary path is needed.
    let mac_key = crate::crypto::derive_vault_mac_key(new_key.as_ref())?;
    crate::vault::writer::write_vault_with_attachments_authenticated(
        &vault_pqd,
        new_header,
        &new_entries,
        &new_attachments,
        &mac_key,
    )
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

    // Decrypt with old key.
    let plain = aead::decrypt(old_sym_key, record.iv, &record.ciphertext)?;

    // Entries and templates share encryption but have different payload schemas.
    // Validate the appropriate schema before replacing any on-disk data.
    match record.record_type {
        RECORD_TYPE_ENTRY => {
            let _check: EntryPlaintext = serde_json::from_slice(plain.as_ref())
                .map_err(|e| DiaryError::Entry(format!("deserialization failed: {e}")))?;
        }
        RECORD_TYPE_TEMPLATE => {
            let _check: TemplatePlaintext = serde_json::from_slice(plain.as_ref())
                .map_err(|e| DiaryError::Template(format!("deserialization failed: {e}")))?;
        }
        other => {
            return Err(DiaryError::Vault(format!(
                "unsupported record type: {other}"
            )))
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::Argon2Params;
    use crate::vault::init::VaultManager;
    use crate::vault::reader::read_vault;
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

    #[test]
    fn password_rotation_preserves_unowned_staging_file() {
        let dir = tempdir().unwrap();
        let vault_dir = setup_vault(&dir, b"Old123!");
        let staging = vault_dir.join("vault.pqd.tmp.new");
        std::fs::write(&staging, b"unowned staging data").unwrap();

        re_encrypt_vault(&vault_dir, &make_secret("Old123!"), &make_secret("New456!"))
            .unwrap();

        assert_eq!(std::fs::read(&staging).unwrap(), b"unowned staging data");
        let path = vault_dir.join("vault.pqd");
        let mut core = DiaryCore::new(path.to_str().unwrap()).unwrap();
        core.unlock(make_secret("New456!")).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn password_rotation_preserves_unowned_staging_symlinks() {
        for dangling in [false, true] {
            let dir = tempdir().unwrap();
            let vault_dir = setup_vault(&dir, b"Old123!");
            let staging = vault_dir.join("vault.pqd.tmp.new");
            let target = dir.path().join("unrelated");
            if !dangling {
                std::fs::write(&target, b"unrelated data").unwrap();
            }
            std::os::unix::fs::symlink(&target, &staging).unwrap();

            re_encrypt_vault(&vault_dir, &make_secret("Old123!"), &make_secret("New456!"))
                .unwrap();

            assert_eq!(std::fs::read_link(&staging).unwrap(), target);
            if dangling {
                assert!(!target.exists());
            } else {
                assert_eq!(std::fs::read(&target).unwrap(), b"unrelated data");
            }
            let path = vault_dir.join("vault.pqd");
            let mut core = DiaryCore::new(path.to_str().unwrap()).unwrap();
            core.unlock(make_secret("New456!")).unwrap();
        }
    }

    // Inject a real partial-write failure only in a subprocess, without unsafe
    // calls or changing the parent harness's environment or resource limits.
    #[cfg(target_os = "linux")]
    #[test]
    fn password_rotation_write_failure_preserves_original_and_unowned_staging() {
        const CHILD_PATH: &str = "PQ_DIARY_ROTATION_FAILURE_TEST_PATH";
        if let Some(path) = std::env::var_os(CHILD_PATH) {
            let vault_dir = std::path::PathBuf::from(path);
            let result =
                re_encrypt_vault(&vault_dir, &make_secret("Old123!"), &make_secret("New456!"));
            assert!(matches!(result, Err(DiaryError::Io(_))), "{result:?}");
            return;
        }

        for symlink in [false, true] {
            let dir = tempdir().unwrap();
            let vault_dir = setup_vault(&dir, b"Old123!");
            let path = vault_dir.join("vault.pqd");
            let mut core = DiaryCore::new(path.to_str().unwrap()).unwrap();
            core.unlock(make_secret("Old123!")).unwrap();
            let body = "synthetic body".repeat(1024);
            let id = core.new_entry("original", &body, vec![]).unwrap();
            drop(core);
            let before = std::fs::read(&path).unwrap();
            let config_before = std::fs::read(vault_dir.join("vault.toml")).unwrap();
            let staging = vault_dir.join("vault.pqd.tmp.new");
            let target = dir.path().join("unrelated");
            std::fs::write(&target, b"unowned staging data").unwrap();
            if symlink {
                std::os::unix::fs::symlink(&target, &staging).unwrap();
            } else {
                std::fs::write(&staging, b"unowned staging data").unwrap();
            }

            let output = std::process::Command::new("sh")
                .args([
                    "-c",
                    "ulimit -f 1; trap '' XFSZ; exec \"$@\"",
                    "rotation-test",
                ])
                .arg(std::env::current_exe().unwrap())
                .args([
                    "vault::change_password::tests::password_rotation_write_failure_preserves_original_and_unowned_staging",
                    "--exact",
                    "--nocapture",
                ])
                .env(CHILD_PATH, &vault_dir)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "child failed: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(std::fs::read(&path).unwrap(), before);
            assert_eq!(
                std::fs::read(vault_dir.join("vault.toml")).unwrap(),
                config_before
            );
            assert_eq!(std::fs::read(&staging).unwrap(), b"unowned staging data");
            assert_eq!(std::fs::read(&target).unwrap(), b"unowned staging data");
            if symlink {
                assert_eq!(std::fs::read_link(&staging).unwrap(), target);
            }
            assert!(std::fs::read_dir(&vault_dir).unwrap().all(|entry| {
                let name = entry.unwrap().file_name();
                !name.to_string_lossy().starts_with("vault.pqd.tmp.")
                    || name == "vault.pqd.tmp.new"
            }));
            let mut core = DiaryCore::new(path.to_str().unwrap()).unwrap();
            core.unlock(make_secret("Old123!")).unwrap();
            assert_eq!(core.get_entry(&id).unwrap().1.body, body);
            drop(core);

            re_encrypt_vault(&vault_dir, &make_secret("Old123!"), &make_secret("New456!"))
                .unwrap();
            let mut core = DiaryCore::new(path.to_str().unwrap()).unwrap();
            core.unlock(make_secret("New456!")).unwrap();
            assert_eq!(core.get_entry(&id).unwrap().1.body, body);
        }
    }

    #[test]
    fn password_rotation_preserves_templates_and_entries() {
        let dir = tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir, b"Old123!");
        let vault_path = vault_dir.join("vault.pqd");
        let path = vault_path.to_str().expect("utf8");
        let entry_id = {
            let mut core = DiaryCore::new(path).expect("open");
            core.unlock(make_secret("Old123!")).expect("unlock");
            core.new_template("daily", "## {{date}}\n今日の日記")
                .expect("template");
            core.new_entry("日記", "本文", vec!["daily".into()])
                .expect("entry")
        };

        re_encrypt_vault(&vault_dir, &make_secret("Old123!"), &make_secret("New456!"))
            .expect("rotate mixed records");

        let mut old = DiaryCore::new(path).expect("open old");
        assert!(old.unlock(make_secret("Old123!")).is_err());
        let mut core = DiaryCore::new(path).expect("reopen");
        core.unlock(make_secret("New456!")).expect("unlock new");
        let template = core.get_template("daily").expect("read template");
        assert_eq!(template.name, "daily");
        assert_eq!(template.body, "## {{date}}\n今日の日記");
        let (_, entry) = core.get_entry(&entry_id).expect("read entry");
        assert_eq!(entry.title, "日記");
        assert_eq!(entry.body, "本文");
        assert_eq!(entry.tags, vec!["daily"]);
    }

    #[test]
    fn password_rotation_rejects_tampered_vault_without_rewriting() {
        let dir = tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir, b"Old123!");
        let vault_path = vault_dir.join("vault.pqd");
        let path = vault_path.to_str().expect("utf8");
        let mut core = DiaryCore::new(path).expect("open");
        core.unlock(make_secret("Old123!")).expect("unlock");
        core.new_entry("diary", "body", vec![]).expect("entry");
        drop(core);

        // A changed authenticated header field still parses and decrypts.
        // Rotation must reject it rather than certify it with a fresh MAC.
        let mut tampered = std::fs::read(&vault_path).expect("read");
        tampered[140] ^= 1;
        std::fs::write(&vault_path, &tampered).expect("tamper");
        let config_before = std::fs::read(vault_dir.join("vault.toml")).expect("config");

        let result = re_encrypt_vault(&vault_dir, &make_secret("Old123!"), &make_secret("New456!"));
        assert!(matches!(result, Err(DiaryError::Crypto(_))));
        assert_eq!(std::fs::read(&vault_path).expect("read again"), tampered);
        assert_eq!(
            std::fs::read(vault_dir.join("vault.toml")).expect("config again"),
            config_before
        );
        assert!(!vault_dir.join("vault.pqd.tmp.new").exists());
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

    #[test]
    fn password_change_rejects_tampered_vault_without_side_effects() {
        for tamper_timestamp in [false, true] {
            let dir = tempdir().unwrap();
            let vault_dir = setup_vault(&dir, b"Old123!");
            let vault_path = vault_dir.join("vault.pqd");
            let mut core = DiaryCore::new(vault_path.to_str().unwrap()).unwrap();
            core.unlock(make_secret("Old123!")).unwrap();
            core.new_entry("title", "body", vec![]).unwrap();
            drop(core);

            let config_before = std::fs::read(vault_dir.join("vault.toml")).unwrap();
            let mut bytes = std::fs::read(&vault_path).unwrap();
            let mut cursor = std::io::Cursor::new(&bytes);
            let header = crate::vault::reader::read_header(&mut cursor).unwrap();
            let key = kdf::derive_key(b"Old123!", &header.kdf_salt, &fast_params()).unwrap();
            let mac_key = crate::crypto::derive_vault_mac_key(key.as_ref()).unwrap();
            crate::vault::reader::verify_vault_integrity(&vault_path, &mac_key).unwrap();
            let offset = if tamper_timestamp {
                // First entry: length prefix + record type + UUID + created_at.
                cursor.position() as usize + 4 + 1 + 16 + 8
            } else {
                bytes.len() - 1
            };
            bytes[offset] ^= 1;
            std::fs::write(&vault_path, &bytes).unwrap();
            assert!(crate::vault::reader::verify_vault_integrity(&vault_path, &mac_key).is_err());

            let result =
                re_encrypt_vault(&vault_dir, &make_secret("Old123!"), &make_secret("New456!"));
            assert!(
                matches!(&result, Err(DiaryError::Crypto(message)) if message.contains("vault integrity")),
                "password change accepted or misclassified corruption: {result:?}"
            );
            assert_eq!(std::fs::read(&vault_path).unwrap(), bytes);
            assert_eq!(
                std::fs::read(vault_dir.join("vault.toml")).unwrap(),
                config_before
            );
            assert!(!vault_dir.join("vault.pqd.tmp.new").exists());
            assert!(!std::fs::read_dir(&vault_dir).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("vault.pqd.tmp.new.tmp")
            }));
        }
    }
}
