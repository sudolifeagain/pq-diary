//! Attachment CRUD + S12 legacy integration (S13).
//!
//! `AttachmentRecord.ciphertext` holds the [`AttachmentPlaintext`] — the only
//! place filename / MIME / size / SHA-256 / FileKey live encrypted in
//! `vault.pqd`. The binary body lives in
//! `<vault_dir>/.attachments/<blob_uuid>.bin` as a chunked AES-256-GCM stream
//! (see [`crate::crypto::streaming`]). Multiple records can share a blob via
//! SHA-256 deduplication; deletion is reference-counted.
//!
//! Five public entry points wire CLI commands to vault I/O:
//! [`add_attachment`], [`list_attachments`], [`extract_attachment`],
//! [`delete_attachment`], [`set_attachment_legacy_flag`].

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use rand::{rngs::OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{aead, dsa, hmac_util, kdf, secure_mem::SecureBuffer, streaming};
use crate::error::DiaryError;
use crate::legacy::LegacyFlag;
use crate::vault::config::VaultConfig;
use crate::vault::format::{
    generate_entry_padding, AttachmentRecord, EntryRecord, VaultHeader, MAX_ATTACHMENTS_PER_ENTRY,
    MAX_ATTACHMENT_SIZE_BYTES, RECORD_TYPE_ATTACHMENT, RECORD_TYPE_ENTRY,
};
use crate::vault::reader::read_vault_with_attachments;
use crate::vault::writer::write_vault_with_attachments_authenticated;

// ============================================================================
// Public types
// ============================================================================

/// Decrypted attachment metadata. Held in memory only while a vault is unlocked.
#[derive(Debug, Clone)]
pub struct AttachmentPlaintext {
    pub entry_uuid: [u8; 16],
    pub blob_uuid: [u8; 16],
    pub created_at: u64,
    pub filename: String,
    pub mime_type: String,
    pub size_bytes: u64,
    pub chunk_count: u32,
    pub sha256: [u8; 32],
    /// Per-blob AES-256-GCM key used to encrypt `<vault_dir>/.attachments/<blob_uuid>.bin`.
    /// Wrapped in `Zeroizing` because it never has another safe home: callers must take
    /// care not to clone it without re-wrapping.
    pub file_key: Zeroizing<[u8; 32]>,
}

/// CLI-friendly view of an attachment. Excludes `file_key` so logs and
/// formatted output never accidentally print key material.
#[derive(Debug, Clone)]
pub struct AttachmentMeta {
    pub uuid: Uuid,
    pub entry_uuid: [u8; 16],
    pub blob_uuid: [u8; 16],
    pub filename: String,
    pub mime_type: String,
    pub size_bytes: u64,
    pub sha256: [u8; 32],
    pub created_at: u64,
    pub legacy_flag: LegacyFlag,
}

/// Plaintext stored in `AttachmentRecord.legacy_key_block` (encrypted under
/// K_legacy) when `legacy_flag == LegacyFlag::Inherit`. The heir uses this
/// during `legacy-access` to:
/// 1. determine the parent entry (`entry_uuid` — needed to enforce REQ-504,
///    "entry DESTROY cascades to attachments"),
/// 2. reconstruct the AttachmentPlaintext under the new K_master (= K_legacy),
/// 3. decrypt the `.attachments/<blob_uuid>.bin` body (`file_key`).
#[derive(Debug, Clone)]
pub(crate) struct AttachmentLegacyPlaintext {
    pub entry_uuid: [u8; 16],
    pub blob_uuid: [u8; 16],
    pub file_key: Zeroizing<[u8; 32]>,
    pub filename: String,
    pub mime_type: String,
    pub size_bytes: u64,
    pub chunk_count: u32,
    pub sha256: [u8; 32],
}

// ============================================================================
// AttachmentPlaintext serialisation
// ============================================================================
//
// Canonical layout (LE integers, length-prefixed UTF-8 strings):
//
//   [entry_uuid: 16B]
//   [blob_uuid: 16B]
//   [created_at: u64]
//   [filename_len: u16][filename: utf-8]
//   [mime_type_len: u16][mime_type: utf-8]
//   [size_bytes: u64]
//   [chunk_count: u32]
//   [sha256: 32B]
//   [file_key: 32B]

impl AttachmentPlaintext {
    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, DiaryError> {
        let mut out = Zeroizing::new(Vec::<u8>::with_capacity(192 + self.filename.len()));
        out.extend_from_slice(&self.entry_uuid);
        out.extend_from_slice(&self.blob_uuid);
        out.extend_from_slice(&self.created_at.to_le_bytes());
        write_short_string(&mut out, &self.filename, "filename")?;
        write_short_string(&mut out, &self.mime_type, "mime_type")?;
        out.extend_from_slice(&self.size_bytes.to_le_bytes());
        out.extend_from_slice(&self.chunk_count.to_le_bytes());
        out.extend_from_slice(&self.sha256);
        out.extend_from_slice(self.file_key.as_ref());
        Ok(out)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DiaryError> {
        let mut cur = ByteCursor::new(bytes);
        let entry_uuid = cur.read_array::<16>()?;
        let blob_uuid = cur.read_array::<16>()?;
        let created_at = cur.read_u64()?;
        let filename = cur.read_short_string("filename")?;
        let mime_type = cur.read_short_string("mime_type")?;
        let size_bytes = cur.read_u64()?;
        let chunk_count = cur.read_u32()?;
        let sha256 = cur.read_array::<32>()?;
        let file_key_arr = cur.read_array::<32>()?;
        cur.expect_eof()?;
        Ok(Self {
            entry_uuid,
            blob_uuid,
            created_at,
            filename,
            mime_type,
            size_bytes,
            chunk_count,
            sha256,
            file_key: Zeroizing::new(file_key_arr),
        })
    }
}

impl AttachmentLegacyPlaintext {
    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, DiaryError> {
        let mut out = Zeroizing::new(Vec::<u8>::with_capacity(
            160 + self.filename.len() + self.mime_type.len(),
        ));
        out.extend_from_slice(&self.entry_uuid);
        out.extend_from_slice(&self.blob_uuid);
        out.extend_from_slice(self.file_key.as_ref());
        write_short_string(&mut out, &self.filename, "filename")?;
        write_short_string(&mut out, &self.mime_type, "mime_type")?;
        out.extend_from_slice(&self.size_bytes.to_le_bytes());
        out.extend_from_slice(&self.chunk_count.to_le_bytes());
        out.extend_from_slice(&self.sha256);
        Ok(out)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DiaryError> {
        let mut cur = ByteCursor::new(bytes);
        let entry_uuid = cur.read_array::<16>()?;
        let blob_uuid = cur.read_array::<16>()?;
        let file_key_arr = cur.read_array::<32>()?;
        let filename = cur.read_short_string("filename")?;
        let mime_type = cur.read_short_string("mime_type")?;
        let size_bytes = cur.read_u64()?;
        let chunk_count = cur.read_u32()?;
        let sha256 = cur.read_array::<32>()?;
        cur.expect_eof()?;
        Ok(Self {
            entry_uuid,
            blob_uuid,
            file_key: Zeroizing::new(file_key_arr),
            filename,
            mime_type,
            size_bytes,
            chunk_count,
            sha256,
        })
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Add a binary file as an attachment to the entry identified by `entry_id_prefix`.
/// Returns the new [`AttachmentRecord::uuid`].
pub fn add_attachment(
    vault_dir: &Path,
    master_pwd: &SecretString,
    entry_id_prefix: &str,
    source_path: &Path,
) -> Result<Uuid, DiaryError> {
    let vault_pqd = vault_dir.join("vault.pqd");
    let vault_toml = vault_dir.join("vault.toml");
    let config = VaultConfig::from_file(&vault_toml)?;
    let (mut header, mut entries, mut attachments) = read_vault_with_attachments(&vault_pqd)?;
    let params = argon2_params_from(&config);
    let k_master = verify_master(&header, master_pwd, &params)?;
    let dsa_seed = decrypt_blob(&k_master, &header.dsa_encrypted_sk, "DSA")?;

    // Resolve entry by ID prefix.
    let entry_idx = find_unique_entry(&entries, entry_id_prefix)?;
    if entries[entry_idx].attachment_count >= MAX_ATTACHMENTS_PER_ENTRY {
        return Err(DiaryError::InvalidArgument(format!(
            "entry already has the maximum {MAX_ATTACHMENTS_PER_ENTRY} attachments"
        )));
    }
    let entry_uuid = entries[entry_idx].uuid;

    // Pre-check size + filename. The 1 GiB cap mirrors PRD §10 / REQ-104.
    let metadata = std::fs::metadata(source_path)?;
    if !metadata.is_file() {
        return Err(DiaryError::InvalidArgument(format!(
            "attachment source must be a regular file: {}",
            source_path.display()
        )));
    }
    if metadata.len() > MAX_ATTACHMENT_SIZE_BYTES {
        return Err(DiaryError::InvalidArgument(format!(
            "attachment size {} exceeds the {} byte limit",
            metadata.len(),
            MAX_ATTACHMENT_SIZE_BYTES
        )));
    }
    let filename = source_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| {
            DiaryError::InvalidArgument(format!(
                "attachment source has no valid filename: {}",
                source_path.display()
            ))
        })?
        .to_string();

    // Pre-compute the SHA-256 of the source so we can dedup against existing
    // blobs without a full re-encrypt.
    let source_sha = sha256_of_file(source_path)?;

    // Reject same-filename-different-content on the same entry (TC-S13-EDGE-03).
    for existing in attachment_plaintexts_for_entry(&attachments, &k_master, Some(&entry_uuid))? {
        if existing.plaintext.filename == filename {
            if existing.plaintext.sha256 == source_sha {
                // Same name + same content: idempotent no-op for ergonomics.
                return Ok(Uuid::from_bytes(existing.record_uuid));
            }
            return Err(DiaryError::InvalidArgument(format!(
                "an attachment named '{filename}' already exists on this entry; \
                 rename the file or remove the old attachment first"
            )));
        }
    }

    // Decide whether to reuse an existing blob (SHA-256 dedup, vault-wide).
    let all_plaintexts = attachment_plaintexts_for_entry(&attachments, &k_master, None)?;
    let dedup = all_plaintexts
        .iter()
        .find(|d| d.plaintext.sha256 == source_sha);

    let (blob_uuid, file_key, size_bytes, chunk_count, sha256) = if let Some(d) = dedup {
        // Reuse blob, reuse FileKey from the canonical decrypted plaintext.
        (
            d.plaintext.blob_uuid,
            d.plaintext.file_key.clone(),
            d.plaintext.size_bytes,
            d.plaintext.chunk_count,
            d.plaintext.sha256,
        )
    } else {
        // Generate a fresh blob.
        let mut new_blob = [0u8; 16];
        OsRng.fill_bytes(&mut new_blob);
        let mut new_key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut new_key_bytes);
        let new_key = Zeroizing::new(new_key_bytes);

        std::fs::create_dir_all(attachments_dir(vault_dir))?;
        let bin_path = blob_path(vault_dir, &new_blob);
        let bin_tmp_path = with_extension(&bin_path, "tmp");

        let write_result = (|| -> Result<(u64, [u8; 32]), DiaryError> {
            let mut src = std::fs::File::open(source_path)?;
            let mut tmp = std::fs::File::create(&bin_tmp_path)?;
            let (size, sha) = streaming::encrypt_stream(&new_key, &new_blob, &mut src, &mut tmp)?;
            tmp.sync_all()?;
            Ok((size, sha))
        })();

        let (size, sha) = match write_result {
            Ok(t) => t,
            Err(e) => {
                cleanup_sensitive_file(&bin_tmp_path);
                return Err(e);
            }
        };
        if sha != source_sha {
            cleanup_sensitive_file(&bin_tmp_path);
            return Err(DiaryError::Crypto(
                "internal sha256 mismatch during attachment write".to_string(),
            ));
        }
        if let Err(e) = std::fs::rename(&bin_tmp_path, &bin_path) {
            cleanup_sensitive_file(&bin_tmp_path);
            return Err(DiaryError::Io(e));
        }
        let chunk_count = streaming::chunk_count_for_size(size);
        (new_blob, new_key, size, chunk_count, sha)
    };

    let now = unix_seconds()?;
    let mime_type = guess_mime_type(&filename);

    let record_uuid_bytes = *Uuid::new_v4().as_bytes();
    let plaintext = AttachmentPlaintext {
        entry_uuid,
        blob_uuid,
        created_at: now,
        filename: filename.clone(),
        mime_type,
        size_bytes,
        chunk_count,
        sha256,
        file_key,
    };
    let new_record = build_attachment_record(
        record_uuid_bytes,
        &plaintext,
        LegacyFlag::Destroy,
        Vec::new(),
        &k_master,
        &dsa_seed,
    )?;

    attachments.push(new_record);
    let entry_record = &mut entries[entry_idx];
    entry_record.attachment_count = entry_record
        .attachment_count
        .checked_add(1)
        .ok_or_else(|| DiaryError::Vault("attachment_count overflow".to_string()))?;
    entry_record.padding = generate_entry_padding();

    // Header is touched only via payload_size recalculation inside writer.
    header.payload_size = 0;
    let mac_key = crate::crypto::derive_vault_mac_key(&k_master)?;
    write_vault_with_attachments_authenticated(
        &vault_pqd,
        header,
        &entries,
        &attachments,
        &mac_key,
    )?;

    Ok(Uuid::from_bytes(record_uuid_bytes))
}

/// List attachments for the entry whose UUID hex starts with `entry_id_prefix`
/// (or all attachments when `entry_id_prefix == None`).
pub fn list_attachments(
    vault_dir: &Path,
    master_pwd: &SecretString,
    entry_id_prefix: Option<&str>,
) -> Result<Vec<AttachmentMeta>, DiaryError> {
    let vault_pqd = vault_dir.join("vault.pqd");
    let vault_toml = vault_dir.join("vault.toml");
    let config = VaultConfig::from_file(&vault_toml)?;
    let (header, entries, attachments) = read_vault_with_attachments(&vault_pqd)?;
    let params = argon2_params_from(&config);
    let k_master = verify_master(&header, master_pwd, &params)?;

    let filter_uuid = match entry_id_prefix {
        Some(p) => Some(find_unique_entry(&entries, p).map(|i| entries[i].uuid)?),
        None => None,
    };

    let mut out = Vec::with_capacity(attachments.len());
    for rec in &attachments {
        verify_hmac(&rec.content_hmac, &rec.ciphertext, &k_master)?;
        let plain = aead::decrypt(&k_master, rec.iv, &rec.ciphertext)?;
        let parsed = AttachmentPlaintext::decode(plain.as_ref())?;
        if let Some(uuid) = filter_uuid {
            if parsed.entry_uuid != uuid {
                continue;
            }
        }
        out.push(AttachmentMeta {
            uuid: Uuid::from_bytes(rec.uuid),
            entry_uuid: parsed.entry_uuid,
            blob_uuid: parsed.blob_uuid,
            filename: parsed.filename,
            mime_type: parsed.mime_type,
            size_bytes: parsed.size_bytes,
            sha256: parsed.sha256,
            created_at: parsed.created_at,
            legacy_flag: LegacyFlag::from_byte(rec.legacy_flag)?,
        });
    }
    Ok(out)
}

/// Extract the attachment named `filename` on entry `entry_id_prefix` and
/// write the decrypted plaintext to `out_path`.
pub fn extract_attachment(
    vault_dir: &Path,
    master_pwd: &SecretString,
    entry_id_prefix: &str,
    filename: &str,
    out_path: &Path,
) -> Result<(), DiaryError> {
    let vault_pqd = vault_dir.join("vault.pqd");
    let vault_toml = vault_dir.join("vault.toml");
    let config = VaultConfig::from_file(&vault_toml)?;
    let (header, entries, attachments) = read_vault_with_attachments(&vault_pqd)?;
    let params = argon2_params_from(&config);
    let k_master = verify_master(&header, master_pwd, &params)?;

    let entry_idx = find_unique_entry(&entries, entry_id_prefix)?;
    let entry_uuid = entries[entry_idx].uuid;

    let decoded = decode_named_attachment(&attachments, &k_master, &entry_uuid, filename)?;

    let bin_path = blob_path(vault_dir, &decoded.plaintext.blob_uuid);
    let tmp_path = with_extension(out_path, "pq-diary.tmp");

    let result = (|| -> Result<(), DiaryError> {
        let mut src = std::fs::File::open(&bin_path)?;
        let mut tmp = std::fs::File::create(&tmp_path)?;
        streaming::decrypt_stream(
            &decoded.plaintext.file_key,
            &decoded.plaintext.blob_uuid,
            decoded.plaintext.size_bytes,
            &decoded.plaintext.sha256,
            &mut src,
            &mut tmp,
        )?;
        tmp.sync_all()?;
        Ok(())
    })();

    if let Err(e) = result {
        cleanup_sensitive_file(&tmp_path);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp_path, out_path) {
        cleanup_sensitive_file(&tmp_path);
        return Err(DiaryError::Io(e));
    }
    Ok(())
}

/// Delete the attachment named `filename` on entry `entry_id_prefix`. The
/// `.bin` body is zeroize-overwritten and removed only when no other record
/// references its `blob_uuid` (REQ-302 + design Q5 reference counting).
pub fn delete_attachment(
    vault_dir: &Path,
    master_pwd: &SecretString,
    entry_id_prefix: &str,
    filename: &str,
) -> Result<(), DiaryError> {
    let vault_pqd = vault_dir.join("vault.pqd");
    let vault_toml = vault_dir.join("vault.toml");
    let config = VaultConfig::from_file(&vault_toml)?;
    let (header, mut entries, mut attachments) = read_vault_with_attachments(&vault_pqd)?;
    let params = argon2_params_from(&config);
    let k_master = verify_master(&header, master_pwd, &params)?;

    let entry_idx = find_unique_entry(&entries, entry_id_prefix)?;
    let entry_uuid = entries[entry_idx].uuid;
    let decoded = decode_named_attachment(&attachments, &k_master, &entry_uuid, filename)?;

    // Remove the AttachmentRecord.
    let to_remove_pos = attachments
        .iter()
        .position(|r| r.uuid == decoded.record_uuid)
        .ok_or_else(|| DiaryError::Entry("attachment record vanished mid-delete".to_string()))?;
    attachments.remove(to_remove_pos);

    // Decrement the entry's attachment_count.
    entries[entry_idx].attachment_count = entries[entry_idx].attachment_count.saturating_sub(1);
    entries[entry_idx].padding = generate_entry_padding();

    // Reference-count the blob.
    let remaining_refs = attachments
        .iter()
        .map(|r| {
            aead::decrypt(&k_master, r.iv, &r.ciphertext)
                .and_then(|pt| AttachmentPlaintext::decode(pt.as_ref()))
                .map(|p| p.blob_uuid == decoded.plaintext.blob_uuid)
        })
        .collect::<Result<Vec<_>, DiaryError>>()?
        .into_iter()
        .filter(|b| *b)
        .count();

    let mac_key = crate::crypto::derive_vault_mac_key(&k_master)?;
    write_vault_with_attachments_authenticated(
        &vault_pqd,
        header,
        &entries,
        &attachments,
        &mac_key,
    )?;

    if remaining_refs == 0 {
        let bin_path = blob_path(vault_dir, &decoded.plaintext.blob_uuid);
        zeroize_and_delete(&bin_path)?;
    }
    Ok(())
}

/// Set the legacy disposition (INHERIT / DESTROY) of an attachment. INHERIT
/// re-encrypts the [`AttachmentLegacyPlaintext`] under K_legacy and stores it
/// in `legacy_key_block`; DESTROY clears the block.
pub fn set_attachment_legacy_flag(
    vault_dir: &Path,
    master_pwd: &SecretString,
    legacy_code_opt: Option<&SecretString>,
    entry_id_prefix: &str,
    filename: &str,
    flag: LegacyFlag,
    deriver: &dyn crate::legacy::LegacyKeyDeriver,
) -> Result<(), DiaryError> {
    let vault_pqd = vault_dir.join("vault.pqd");
    let vault_toml = vault_dir.join("vault.toml");
    let config = VaultConfig::from_file(&vault_toml)?;
    if !config.legacy.initialized {
        return Err(DiaryError::Vault(
            "legacy not initialized — run `pq-diary legacy init` first".to_string(),
        ));
    }
    let (header, entries, mut attachments) = read_vault_with_attachments(&vault_pqd)?;
    let params = argon2_params_from(&config);
    let _k_master = verify_master(&header, master_pwd, &params)?;

    let entry_idx = find_unique_entry(&entries, entry_id_prefix)?;
    let entry_uuid = entries[entry_idx].uuid;
    let decoded = decode_named_attachment(&attachments, &_k_master, &entry_uuid, filename)?;
    let record_pos = attachments
        .iter()
        .position(|r| r.uuid == decoded.record_uuid)
        .ok_or_else(|| DiaryError::Entry("attachment record vanished".to_string()))?;

    match flag {
        LegacyFlag::Destroy => {
            attachments[record_pos].legacy_flag = LegacyFlag::Destroy.to_byte();
            attachments[record_pos].legacy_key_block = Vec::new();
        }
        LegacyFlag::Inherit => {
            let legacy_code = legacy_code_opt.ok_or_else(|| {
                DiaryError::InvalidArgument(
                    "legacy code is required when setting --inherit".to_string(),
                )
            })?;
            let k_legacy =
                deriver.derive(legacy_code.expose_secret().as_bytes(), &header.legacy_salt)?;
            crate::legacy::verify_legacy_code(&config, &k_legacy)?;

            let lpt = AttachmentLegacyPlaintext {
                entry_uuid,
                blob_uuid: decoded.plaintext.blob_uuid,
                file_key: decoded.plaintext.file_key.clone(),
                filename: decoded.plaintext.filename.clone(),
                mime_type: decoded.plaintext.mime_type.clone(),
                size_bytes: decoded.plaintext.size_bytes,
                chunk_count: decoded.plaintext.chunk_count,
                sha256: decoded.plaintext.sha256,
            };
            let encoded = lpt.encode()?;
            let (ct, iv) = aead::encrypt(&k_legacy, encoded.as_ref())?;
            let mut block = Vec::with_capacity(iv.len() + ct.len());
            block.extend_from_slice(&iv);
            block.extend_from_slice(&ct);
            attachments[record_pos].legacy_flag = LegacyFlag::Inherit.to_byte();
            attachments[record_pos].legacy_key_block = block;
        }
    }

    let mac_key = crate::crypto::derive_vault_mac_key(&_k_master)?;
    write_vault_with_attachments_authenticated(
        &vault_pqd,
        header,
        &entries,
        &attachments,
        &mac_key,
    )?;
    Ok(())
}

// ============================================================================
// Helpers used by attachment.rs and re-exported pub(crate) for legacy.rs / change_password.rs
// ============================================================================

pub(crate) struct DecodedAttachment {
    pub record_uuid: [u8; 16],
    pub plaintext: AttachmentPlaintext,
}

/// Decode every attachment whose `entry_uuid` matches `filter_entry_uuid`
/// (or all of them when `None`).
pub(crate) fn attachment_plaintexts_for_entry(
    attachments: &[AttachmentRecord],
    k_master: &[u8; 32],
    filter_entry_uuid: Option<&[u8; 16]>,
) -> Result<Vec<DecodedAttachment>, DiaryError> {
    let mut out = Vec::with_capacity(attachments.len());
    for rec in attachments {
        let plain = aead::decrypt(k_master, rec.iv, &rec.ciphertext)?;
        let pt = AttachmentPlaintext::decode(plain.as_ref())?;
        if let Some(uuid) = filter_entry_uuid {
            if &pt.entry_uuid != uuid {
                continue;
            }
        }
        out.push(DecodedAttachment {
            record_uuid: rec.uuid,
            plaintext: pt,
        });
    }
    Ok(out)
}

/// Decrypt `legacy_key_block` for an INHERIT attachment under K_legacy.
/// Returns the parsed [`AttachmentLegacyPlaintext`].
pub(crate) fn decrypt_attachment_legacy_block(
    record: &AttachmentRecord,
    k_legacy: &[u8; 32],
) -> Result<AttachmentLegacyPlaintext, DiaryError> {
    if record.legacy_flag != LegacyFlag::Inherit.to_byte() {
        return Err(DiaryError::Vault(
            "attachment is not INHERIT — no legacy block to decrypt".to_string(),
        ));
    }
    if record.legacy_key_block.len() < aead::NONCE_SIZE {
        return Err(DiaryError::Vault(
            "attachment legacy_key_block is shorter than the AEAD nonce".to_string(),
        ));
    }
    let iv: [u8; aead::NONCE_SIZE] = record.legacy_key_block[..aead::NONCE_SIZE]
        .try_into()
        .map_err(|_| DiaryError::Vault("invalid legacy_key_block IV".to_string()))?;
    let ct = &record.legacy_key_block[aead::NONCE_SIZE..];
    let plain = aead::decrypt(k_legacy, iv, ct)
        .map_err(|_| DiaryError::Crypto("failed to decrypt attachment legacy block".to_string()))?;
    AttachmentLegacyPlaintext::decode(plain.as_ref())
}

/// Build a fresh AttachmentRecord for the heir's new vault. K_legacy plays
/// the role of K_master in the new vault, so we encrypt the AttachmentPlaintext
/// under K_legacy and sign with the new DSA seed. `legacy_flag` is reset to
/// DESTROY (the heir starts from a clean slate; they can re-mark INHERIT
/// later if they want to nominate their own heir).
pub(crate) fn rebuild_attachment_record_for_heir(
    record_uuid: [u8; 16],
    lpt: &AttachmentLegacyPlaintext,
    inherited_at: u64,
    new_k_master: &[u8; 32],
    new_dsa_seed: &Zeroizing<Vec<u8>>,
) -> Result<AttachmentRecord, DiaryError> {
    let pt = AttachmentPlaintext {
        entry_uuid: lpt.entry_uuid,
        blob_uuid: lpt.blob_uuid,
        created_at: inherited_at,
        filename: lpt.filename.clone(),
        mime_type: lpt.mime_type.clone(),
        size_bytes: lpt.size_bytes,
        chunk_count: lpt.chunk_count,
        sha256: lpt.sha256,
        file_key: lpt.file_key.clone(),
    };
    build_attachment_record(
        record_uuid,
        &pt,
        LegacyFlag::Destroy,
        Vec::new(),
        new_k_master,
        new_dsa_seed,
    )
}

/// Re-encrypt every attachment record under a new K_master. The `.bin` bodies
/// are NOT touched (FileKey is preserved inside the new ciphertext) — that's
/// the whole point of design Q4.
pub(crate) fn reencrypt_attachments_for_change_password(
    attachments: &[AttachmentRecord],
    old_k_master: &[u8; 32],
    new_k_master: &[u8; 32],
    dsa_seed: &Zeroizing<Vec<u8>>,
) -> Result<Vec<AttachmentRecord>, DiaryError> {
    let mut out = Vec::with_capacity(attachments.len());
    for rec in attachments {
        let plain = aead::decrypt(old_k_master, rec.iv, &rec.ciphertext)?;
        let pt = AttachmentPlaintext::decode(plain.as_ref())?;
        let new_rec = build_attachment_record(
            rec.uuid,
            &pt,
            LegacyFlag::from_byte(rec.legacy_flag)?,
            rec.legacy_key_block.clone(),
            new_k_master,
            dsa_seed,
        )?;
        out.push(new_rec);
    }
    Ok(out)
}

fn build_attachment_record(
    record_uuid: [u8; 16],
    plaintext: &AttachmentPlaintext,
    legacy_flag: LegacyFlag,
    legacy_key_block: Vec<u8>,
    k_master: &[u8; 32],
    dsa_seed: &Zeroizing<Vec<u8>>,
) -> Result<AttachmentRecord, DiaryError> {
    let encoded = plaintext.encode()?;
    let (ciphertext, iv) = aead::encrypt(k_master, encoded.as_ref())?;
    let dsa_sk = SecureBuffer::new(dsa_seed.as_slice().to_vec());
    let signature = dsa::sign(&dsa_sk, &ciphertext)?;
    let content_hmac = hmac_util::compute(k_master, &ciphertext)?;

    Ok(AttachmentRecord {
        record_type: RECORD_TYPE_ATTACHMENT,
        uuid: record_uuid,
        iv,
        ciphertext,
        signature,
        content_hmac,
        legacy_flag: legacy_flag.to_byte(),
        legacy_key_block,
        padding: generate_entry_padding(),
    })
}

fn decode_named_attachment(
    attachments: &[AttachmentRecord],
    k_master: &[u8; 32],
    entry_uuid: &[u8; 16],
    filename: &str,
) -> Result<DecodedAttachment, DiaryError> {
    let decoded = attachment_plaintexts_for_entry(attachments, k_master, Some(entry_uuid))?;
    let mut matches: Vec<DecodedAttachment> = decoded
        .into_iter()
        .filter(|d| d.plaintext.filename == filename)
        .collect();
    match matches.len() {
        0 => Err(DiaryError::Entry(format!(
            "attachment '{filename}' not found on entry"
        ))),
        1 => Ok(matches.remove(0)),
        _ => Err(DiaryError::Entry(format!(
            "multiple attachments named '{filename}' on this entry — vault is in an inconsistent state"
        ))),
    }
}

fn find_unique_entry(entries: &[EntryRecord], prefix: &str) -> Result<usize, DiaryError> {
    let prefix_lower = prefix.to_ascii_lowercase();
    if prefix_lower.is_empty() {
        return Err(DiaryError::Entry(
            "entry ID prefix must not be empty".to_string(),
        ));
    }
    let matches: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| {
            e.record_type == RECORD_TYPE_ENTRY && hex_lower(&e.uuid).starts_with(&prefix_lower)
        })
        .map(|(i, _)| i)
        .collect();
    match matches.len() {
        0 => Err(DiaryError::Entry(format!(
            "no entry matches prefix '{prefix}'"
        ))),
        1 => Ok(matches[0]),
        _ => {
            let candidates: Vec<String> = matches
                .iter()
                .map(|&i| hex_lower(&entries[i].uuid))
                .collect();
            Err(DiaryError::Entry(format!(
                "multiple entries match prefix '{prefix}': {}",
                candidates.join(", ")
            )))
        }
    }
}

fn argon2_params_from(config: &VaultConfig) -> kdf::Argon2Params {
    kdf::Argon2Params {
        memory_cost_kb: config.argon2.memory_cost_kb,
        time_cost: config.argon2.time_cost,
        parallelism: config.argon2.parallelism,
    }
}

fn verify_master(
    header: &VaultHeader,
    master_pwd: &SecretString,
    params: &kdf::Argon2Params,
) -> Result<[u8; 32], DiaryError> {
    let key = kdf::derive_key(
        master_pwd.expose_secret().as_bytes(),
        &header.kdf_salt,
        params,
    )?;
    aead::decrypt(
        key.as_ref(),
        header.verification_iv,
        &header.verification_ct,
    )
    .map_err(|_| DiaryError::Crypto("invalid master password".to_string()))?;
    Ok(*key.as_ref())
}

fn verify_hmac(expected: &[u8; 32], data: &[u8], key: &[u8; 32]) -> Result<(), DiaryError> {
    let actual = hmac_util::compute(key, data)?;
    if &actual != expected {
        return Err(DiaryError::Crypto(
            "attachment content_hmac mismatch".to_string(),
        ));
    }
    Ok(())
}

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

pub(crate) fn attachments_dir(vault_dir: &Path) -> PathBuf {
    vault_dir.join(".attachments")
}

pub(crate) fn blob_path(vault_dir: &Path, blob_uuid: &[u8; 16]) -> PathBuf {
    attachments_dir(vault_dir).join(format!("{}.bin", hex_lower(blob_uuid)))
}

fn with_extension(path: &Path, ext: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(ext);
    path.with_file_name(name)
}

fn sha256_of_file(path: &Path) -> Result<[u8; 32], DiaryError> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = Zeroizing::new(vec![0u8; 64 * 1024]);
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

fn unix_seconds() -> Result<u64, DiaryError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| DiaryError::Entry(format!("system clock before UNIX epoch: {e}")))
}

fn hex_lower(uuid: &[u8; 16]) -> String {
    uuid.iter().map(|b| format!("{b:02x}")).collect()
}

/// Best-effort secure delete: overwrite with random bytes, fsync, unlink.
pub(crate) fn zeroize_and_delete(path: &Path) -> Result<(), DiaryError> {
    if let Ok(meta) = std::fs::metadata(path) {
        let size = meta.len() as usize;
        if size > 0 {
            let mut buf = Zeroizing::new(vec![0u8; size.min(1024 * 1024)]);
            if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
                let mut remaining = size;
                while remaining > 0 {
                    let chunk = std::cmp::min(remaining, buf.len());
                    OsRng.fill_bytes(&mut buf[..chunk]);
                    f.write_all(&buf[..chunk])?;
                    remaining -= chunk;
                }
                f.sync_all()?;
            }
        }
    }
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(DiaryError::Io(e));
        }
    }
    Ok(())
}

fn cleanup_sensitive_file(path: &Path) {
    let _ = zeroize_and_delete(path);
}

fn guess_mime_type(filename: &str) -> String {
    let ext = filename
        .rsplit('.')
        .next()
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        "md" | "markdown" => "text/markdown",
        "json" => "application/json",
        "html" | "htm" => "text/html",
        "mp3" => "audio/mpeg",
        "m4a" => "audio/mp4",
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
    .to_string()
}

// ============================================================================
// ByteCursor — tiny binary reader for canonical encodings
// ============================================================================

fn write_short_string(out: &mut Vec<u8>, s: &str, name: &str) -> Result<(), DiaryError> {
    let bytes = s.as_bytes();
    if bytes.len() > u16::MAX as usize {
        return Err(DiaryError::Vault(format!(
            "{name} length exceeds u16 maximum"
        )));
    }
    out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

struct ByteCursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], DiaryError> {
        if self.pos + n > self.buf.len() {
            return Err(DiaryError::Vault(
                "unexpected EOF decoding AttachmentPlaintext".to_string(),
            ));
        }
        let slice = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DiaryError> {
        let s = self.read_bytes(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(s);
        Ok(out)
    }

    fn read_u16(&mut self) -> Result<u16, DiaryError> {
        Ok(u16::from_le_bytes(self.read_array::<2>()?))
    }

    fn read_u32(&mut self) -> Result<u32, DiaryError> {
        Ok(u32::from_le_bytes(self.read_array::<4>()?))
    }

    fn read_u64(&mut self) -> Result<u64, DiaryError> {
        Ok(u64::from_le_bytes(self.read_array::<8>()?))
    }

    fn read_short_string(&mut self, name: &str) -> Result<String, DiaryError> {
        let len = self.read_u16()? as usize;
        let bytes = self.read_bytes(len)?.to_vec();
        String::from_utf8(bytes)
            .map_err(|e| DiaryError::Vault(format!("invalid UTF-8 in {name}: {e}")))
    }

    fn expect_eof(&self) -> Result<(), DiaryError> {
        if self.pos != self.buf.len() {
            return Err(DiaryError::Vault(format!(
                "trailing bytes after AttachmentPlaintext: pos={} len={}",
                self.pos,
                self.buf.len()
            )));
        }
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::Argon2Params;
    use crate::legacy::Argon2LegacyDeriver;
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

    fn fast_deriver() -> Argon2LegacyDeriver {
        Argon2LegacyDeriver::new(fast_params())
    }

    fn secret(s: &str) -> SecretString {
        SecretBox::new(Box::from(s))
    }

    fn setup_vault(dir: &tempfile::TempDir, password: &[u8]) -> std::path::PathBuf {
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());
        mgr.init_vault("v", password).expect("init_vault");
        dir.path().join("v")
    }

    fn vault_with_entry(dir: &tempfile::TempDir) -> (std::path::PathBuf, String) {
        let vault_dir = setup_vault(dir, b"master-pw");
        let vault_pqd = vault_dir.join("vault.pqd").to_str().unwrap().to_string();
        let mut core = DiaryCore::new(&vault_pqd).unwrap();
        core.unlock(secret("master-pw")).unwrap();
        let id = core.new_entry("title", "body", vec![]).unwrap();
        (vault_dir, id)
    }

    fn write_source(dir: &tempfile::TempDir, name: &str, contents: &[u8]) -> std::path::PathBuf {
        let p = dir.path().join(name);
        std::fs::write(&p, contents).unwrap();
        p
    }

    /// TC-S13-004-01: AttachmentPlaintext encode → decode round-trip.
    #[test]
    fn tc_s13_004_01_plaintext_codec_roundtrip() {
        let pt = AttachmentPlaintext {
            entry_uuid: [0x11; 16],
            blob_uuid: [0x22; 16],
            created_at: 1_700_000_000,
            filename: "ファイル.png".to_string(),
            mime_type: "image/png".to_string(),
            size_bytes: 12345,
            chunk_count: 1,
            sha256: [0x33; 32],
            file_key: Zeroizing::new([0x44; 32]),
        };
        let encoded = pt.encode().unwrap();
        let decoded = AttachmentPlaintext::decode(encoded.as_ref()).unwrap();
        assert_eq!(decoded.entry_uuid, pt.entry_uuid);
        assert_eq!(decoded.blob_uuid, pt.blob_uuid);
        assert_eq!(decoded.created_at, pt.created_at);
        assert_eq!(decoded.filename, pt.filename);
        assert_eq!(decoded.mime_type, pt.mime_type);
        assert_eq!(decoded.size_bytes, pt.size_bytes);
        assert_eq!(decoded.chunk_count, pt.chunk_count);
        assert_eq!(decoded.sha256, pt.sha256);
        assert_eq!(decoded.file_key.as_ref(), pt.file_key.as_ref());
    }

    /// TC-S13-004-02: AttachmentLegacyPlaintext codec round-trip.
    #[test]
    fn tc_s13_004_02_legacy_codec_roundtrip() {
        let lpt = AttachmentLegacyPlaintext {
            entry_uuid: [0x12; 16],
            blob_uuid: [0xAB; 16],
            file_key: Zeroizing::new([0xCD; 32]),
            filename: "secret.pdf".to_string(),
            mime_type: "application/pdf".to_string(),
            size_bytes: 999,
            chunk_count: 1,
            sha256: [0xEF; 32],
        };
        let encoded = lpt.encode().unwrap();
        let decoded = AttachmentLegacyPlaintext::decode(encoded.as_ref()).unwrap();
        assert_eq!(decoded.entry_uuid, lpt.entry_uuid);
        assert_eq!(decoded.blob_uuid, lpt.blob_uuid);
        assert_eq!(decoded.file_key.as_ref(), lpt.file_key.as_ref());
        assert_eq!(decoded.filename, lpt.filename);
        assert_eq!(decoded.mime_type, lpt.mime_type);
    }

    /// TC-S13-004-03: add → list → extract → SHA-256 verified.
    #[test]
    fn tc_s13_004_03_add_list_extract() {
        let dir = tempdir().unwrap();
        let (vault_dir, entry_id) = vault_with_entry(&dir);
        let src = write_source(&dir, "photo.png", b"\x89PNG\r\n\x1a\nfake content");

        let added = add_attachment(&vault_dir, &secret("master-pw"), &entry_id[..8], &src).unwrap();
        let metas =
            list_attachments(&vault_dir, &secret("master-pw"), Some(&entry_id[..8])).unwrap();
        assert_eq!(metas.len(), 1);
        assert_eq!(metas[0].uuid, added);
        assert_eq!(metas[0].filename, "photo.png");
        assert_eq!(metas[0].mime_type, "image/png");
        assert_eq!(metas[0].size_bytes, 20);

        let out = dir.path().join("photo-restored.png");
        extract_attachment(
            &vault_dir,
            &secret("master-pw"),
            &entry_id[..8],
            "photo.png",
            &out,
        )
        .unwrap();
        let restored = std::fs::read(&out).unwrap();
        assert_eq!(restored, b"\x89PNG\r\n\x1a\nfake content");
    }

    /// TC-S13-004-04: oversize file rejected.
    #[test]
    fn tc_s13_004_04_oversize_rejected() {
        let dir = tempdir().unwrap();
        let (vault_dir, entry_id) = vault_with_entry(&dir);
        // Forge a fake 1 GiB + 1 byte file via sparse write (Windows / Linux both honour this).
        let src = dir.path().join("huge.bin");
        let f = std::fs::File::create(&src).unwrap();
        f.set_len(MAX_ATTACHMENT_SIZE_BYTES + 1).unwrap();

        let result = add_attachment(&vault_dir, &secret("master-pw"), &entry_id[..8], &src);
        assert!(matches!(result, Err(DiaryError::InvalidArgument(_))));
    }

    /// TC-S13-004-05: deduplication: two records share one blob.
    #[test]
    fn tc_s13_004_05_dedup_same_sha() {
        let dir = tempdir().unwrap();
        let (vault_dir, entry_id) = vault_with_entry(&dir);
        let mut core = DiaryCore::new(vault_dir.join("vault.pqd").to_str().unwrap()).unwrap();
        core.unlock(secret("master-pw")).unwrap();
        let id2 = core.new_entry("title2", "body2", vec![]).unwrap();
        drop(core);

        let src = write_source(&dir, "shared.txt", b"shared payload");
        add_attachment(&vault_dir, &secret("master-pw"), &entry_id[..8], &src).unwrap();
        // Adding the same SHA-256 to entry 2 must not create a second .bin file.
        let src2 = write_source(&dir, "shared-copy.txt", b"shared payload");
        add_attachment(&vault_dir, &secret("master-pw"), &id2[..8], &src2).unwrap();

        let metas = list_attachments(&vault_dir, &secret("master-pw"), None).unwrap();
        assert_eq!(metas.len(), 2, "two attachment records");
        let blobs: std::collections::HashSet<[u8; 16]> =
            metas.iter().map(|m| m.blob_uuid).collect();
        assert_eq!(blobs.len(), 1, "but only one shared blob_uuid");
        let bin_count = std::fs::read_dir(attachments_dir(&vault_dir))
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "bin"))
            .count();
        assert_eq!(bin_count, 1, "only one .bin on disk");
    }

    /// TC-S13-004-06: same name + same content on the same entry is idempotent.
    #[test]
    fn tc_s13_004_06_same_name_same_content_idempotent() {
        let dir = tempdir().unwrap();
        let (vault_dir, entry_id) = vault_with_entry(&dir);
        let src = write_source(&dir, "doc.txt", b"hello");
        let id1 = add_attachment(&vault_dir, &secret("master-pw"), &entry_id[..8], &src).unwrap();
        // Re-add the exact same source: returns the same record uuid.
        let id2 = add_attachment(&vault_dir, &secret("master-pw"), &entry_id[..8], &src).unwrap();
        assert_eq!(id1, id2);
        let metas =
            list_attachments(&vault_dir, &secret("master-pw"), Some(&entry_id[..8])).unwrap();
        assert_eq!(metas.len(), 1);
    }

    /// TC-S13-004-07: same name, different content on the same entry → rejected.
    #[test]
    fn tc_s13_004_07_same_name_different_content_rejected() {
        let dir = tempdir().unwrap();
        let (vault_dir, entry_id) = vault_with_entry(&dir);
        let src_a = write_source(&dir, "note.txt", b"alpha");
        add_attachment(&vault_dir, &secret("master-pw"), &entry_id[..8], &src_a).unwrap();
        // Overwrite the source with different bytes, same filename.
        std::fs::write(&src_a, b"beta").unwrap();
        let result = add_attachment(&vault_dir, &secret("master-pw"), &entry_id[..8], &src_a);
        assert!(matches!(result, Err(DiaryError::InvalidArgument(_))));
    }

    /// TC-S13-004-08: delete: zeroize .bin when no refs remain; keep when shared.
    #[test]
    fn tc_s13_004_08_delete_refcount() {
        let dir = tempdir().unwrap();
        let (vault_dir, entry_id) = vault_with_entry(&dir);
        let mut core = DiaryCore::new(vault_dir.join("vault.pqd").to_str().unwrap()).unwrap();
        core.unlock(secret("master-pw")).unwrap();
        let id2 = core.new_entry("title2", "body2", vec![]).unwrap();
        drop(core);

        let src = write_source(&dir, "shared.txt", b"shared");
        add_attachment(&vault_dir, &secret("master-pw"), &entry_id[..8], &src).unwrap();
        let src_dup = write_source(&dir, "shared-copy.txt", b"shared");
        add_attachment(&vault_dir, &secret("master-pw"), &id2[..8], &src_dup).unwrap();

        // Determine which filename ended up where so we delete a valid one.
        let m1 = list_attachments(&vault_dir, &secret("master-pw"), Some(&entry_id[..8])).unwrap();
        let m2 = list_attachments(&vault_dir, &secret("master-pw"), Some(&id2[..8])).unwrap();
        assert_eq!(m1.len(), 1);
        assert_eq!(m2.len(), 1);
        let bin_path = blob_path(&vault_dir, &m1[0].blob_uuid);

        // First delete: blob still has a ref from entry 2 → .bin must remain.
        delete_attachment(
            &vault_dir,
            &secret("master-pw"),
            &entry_id[..8],
            &m1[0].filename,
        )
        .unwrap();
        assert!(bin_path.exists(), ".bin must remain while still referenced");

        // Second delete: no refs → .bin is gone.
        delete_attachment(&vault_dir, &secret("master-pw"), &id2[..8], &m2[0].filename).unwrap();
        assert!(
            !bin_path.exists(),
            ".bin must be removed when last ref dropped"
        );
    }

    /// TC-S13-004-09: extract fails on a flipped .bin byte.
    #[test]
    fn tc_s13_004_09_extract_detects_tamper() {
        let dir = tempdir().unwrap();
        let (vault_dir, entry_id) = vault_with_entry(&dir);
        let src = write_source(&dir, "x.txt", b"abcdef");
        add_attachment(&vault_dir, &secret("master-pw"), &entry_id[..8], &src).unwrap();

        // Flip a byte in the only .bin file.
        let bin = std::fs::read_dir(attachments_dir(&vault_dir))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let mut data = std::fs::read(&bin).unwrap();
        let last = data.len() - 1;
        data[last] ^= 0xFF;
        std::fs::write(&bin, &data).unwrap();

        let out = dir.path().join("restored.txt");
        let result = extract_attachment(
            &vault_dir,
            &secret("master-pw"),
            &entry_id[..8],
            "x.txt",
            &out,
        );
        assert!(matches!(result, Err(DiaryError::Crypto(_))));
        assert!(!out.exists(), "tmp file must not be promoted on failure");
    }

    /// TC-S13-004-10: legacy write paths preserve attachment records.
    #[test]
    fn tc_s13_004_10_write_vault_preserves_attachments() {
        let dir = tempdir().unwrap();
        let (vault_dir, entry_id) = vault_with_entry(&dir);
        let src = write_source(&dir, "keep.txt", b"keep me");
        add_attachment(&vault_dir, &secret("master-pw"), &entry_id[..8], &src).unwrap();

        let mut core = DiaryCore::new(vault_dir.join("vault.pqd").to_str().unwrap()).unwrap();
        core.unlock(secret("master-pw")).unwrap();
        core.new_entry("second", "body", vec![]).unwrap();
        drop(core);

        let metas =
            list_attachments(&vault_dir, &secret("master-pw"), Some(&entry_id[..8])).unwrap();
        assert_eq!(metas.len(), 1);
        assert_eq!(metas[0].filename, "keep.txt");
    }

    /// TC-S13-004-11: deleting an entry cascades to its attachment records and blobs.
    #[test]
    fn tc_s13_004_11_delete_entry_removes_own_attachments() {
        let dir = tempdir().unwrap();
        let (vault_dir, entry_id) = vault_with_entry(&dir);
        let mut core = DiaryCore::new(vault_dir.join("vault.pqd").to_str().unwrap()).unwrap();
        core.unlock(secret("master-pw")).unwrap();
        let id2 = core.new_entry("second", "body", vec![]).unwrap();
        drop(core);

        let src1 = write_source(&dir, "one.txt", b"one");
        let src2 = write_source(&dir, "two.txt", b"two");
        add_attachment(&vault_dir, &secret("master-pw"), &entry_id[..8], &src1).unwrap();
        add_attachment(&vault_dir, &secret("master-pw"), &id2[..8], &src2).unwrap();
        let first_meta =
            list_attachments(&vault_dir, &secret("master-pw"), Some(&entry_id[..8])).unwrap();
        let first_blob = blob_path(&vault_dir, &first_meta[0].blob_uuid);

        let mut core = DiaryCore::new(vault_dir.join("vault.pqd").to_str().unwrap()).unwrap();
        core.unlock(secret("master-pw")).unwrap();
        core.delete_entry(&entry_id[..8]).unwrap();
        drop(core);

        assert!(
            !first_blob.exists(),
            "deleted entry's private blob is removed"
        );
        let remaining = list_attachments(&vault_dir, &secret("master-pw"), None).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].filename, "two.txt");
    }

    /// TC-S13-004-12: extract cleans up decrypted temp output if final rename fails.
    #[test]
    fn tc_s13_004_12_extract_rename_failure_cleans_tmp() {
        let dir = tempdir().unwrap();
        let (vault_dir, entry_id) = vault_with_entry(&dir);
        let src = write_source(&dir, "x.txt", b"abcdef");
        add_attachment(&vault_dir, &secret("master-pw"), &entry_id[..8], &src).unwrap();

        let out_dir = dir.path().join("existing-dir");
        std::fs::create_dir(&out_dir).unwrap();
        let tmp_path = with_extension(&out_dir, "pq-diary.tmp");
        let result = extract_attachment(
            &vault_dir,
            &secret("master-pw"),
            &entry_id[..8],
            "x.txt",
            &out_dir,
        );

        assert!(matches!(result, Err(DiaryError::Io(_))));
        assert!(
            !tmp_path.exists(),
            "decrypted temp file must be removed after rename failure"
        );
    }

    /// TC-S13-004-13: 256 attachments per entry max.
    #[test]
    #[ignore = "slow: 257 small attachments take ~minutes on a CI runner"]
    fn tc_s13_004_13_max_attachments_per_entry() {
        let dir = tempdir().unwrap();
        let (vault_dir, entry_id) = vault_with_entry(&dir);
        for i in 0..MAX_ATTACHMENTS_PER_ENTRY {
            let src = write_source(&dir, &format!("f{i}.bin"), &i.to_le_bytes());
            add_attachment(&vault_dir, &secret("master-pw"), &entry_id[..8], &src).unwrap();
        }
        let extra = write_source(&dir, "overflow.bin", b"too much");
        let result = add_attachment(&vault_dir, &secret("master-pw"), &entry_id[..8], &extra);
        assert!(matches!(result, Err(DiaryError::InvalidArgument(_))));
    }

    /// TC-S13-004-14: set_attachment_legacy_flag INHERIT/DESTROY round-trip.
    #[test]
    fn tc_s13_004_14_set_legacy_flag() {
        let dir = tempdir().unwrap();
        let (vault_dir, entry_id) = vault_with_entry(&dir);
        crate::legacy::initialize_legacy(
            &vault_dir,
            &secret("master-pw"),
            &secret("legacy-code"),
            crate::vault::config::ConfirmationMode::Yn,
            &fast_deriver(),
        )
        .unwrap();
        let src = write_source(&dir, "doc.txt", b"hello");
        add_attachment(&vault_dir, &secret("master-pw"), &entry_id[..8], &src).unwrap();

        set_attachment_legacy_flag(
            &vault_dir,
            &secret("master-pw"),
            Some(&secret("legacy-code")),
            &entry_id[..8],
            "doc.txt",
            LegacyFlag::Inherit,
            &fast_deriver(),
        )
        .unwrap();
        let metas =
            list_attachments(&vault_dir, &secret("master-pw"), Some(&entry_id[..8])).unwrap();
        assert_eq!(metas[0].legacy_flag, LegacyFlag::Inherit);

        set_attachment_legacy_flag(
            &vault_dir,
            &secret("master-pw"),
            None,
            &entry_id[..8],
            "doc.txt",
            LegacyFlag::Destroy,
            &fast_deriver(),
        )
        .unwrap();
        let metas2 =
            list_attachments(&vault_dir, &secret("master-pw"), Some(&entry_id[..8])).unwrap();
        assert_eq!(metas2[0].legacy_flag, LegacyFlag::Destroy);
    }
}
