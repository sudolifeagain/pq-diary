//! Digital-legacy (S12) operations.
//!
//! Implements the post-mortem access workflow defined in `requirements.md` §7
//! and `docs/design/s12-legacy/`. Each vault entry carries a `legacy_flag`
//! (INHERIT / DESTROY); INHERIT entries also store a `legacy_key_block` —
//! the entry plaintext re-encrypted under K_legacy (derived from the
//! post-mortem access code). Running `pq-diary legacy-access` later derives
//! K_legacy without K_master, drops every DESTROY entry, and rebuilds the
//! vault around the INHERIT entries.
//!
//! Module layout:
//! - `LegacyKeyDeriver` / `Argon2LegacyDeriver` — K_legacy derivation
//!   (abstracted so that a future `ShamirLegacyDeriver` can implement M-of-N
//!   secret sharing without touching the rest of the codebase).
//! - `LegacyFlag` — typed wrapper over the 1-byte on-disk field.
//! - Five public entry points wire CLI commands to vault I/O:
//!   `initialize_legacy`, `set_entry_flag`, `list_legacy_status`,
//!   `rotate_legacy_code`, `execute_legacy_access`.

use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand::{rngs::OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::{aead, dsa, kdf, kem};
use crate::entry::EntryPlaintext;
use crate::error::DiaryError;
use crate::vault::config::{ConfirmationMode, VaultConfig};
use crate::vault::format::{
    generate_verification_token, EntryRecord, VaultHeader, RECORD_TYPE_ENTRY, SCHEMA_VERSION,
};
use crate::vault::reader::read_vault_with_attachments_from_bytes;

// ============================================================================
// LegacyKeyDeriver trait + default Argon2 implementation
// ============================================================================

/// Derive K_legacy from a post-mortem access code and the vault's `legacy_salt`.
///
/// Phase 1 (S12) only ships [`Argon2LegacyDeriver`]. The trait exists so a
/// future Phase-3 `ShamirLegacyDeriver` can fold M-of-N shares into the same
/// 32-byte output without changing call sites. (NFR-102; design Q7.)
pub trait LegacyKeyDeriver: Send + Sync {
    /// Derive a 32-byte K_legacy from the raw `code` and 32-byte `salt`.
    fn derive(&self, code: &[u8], salt: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, DiaryError>;
}

/// Default deriver: Argon2id with the parameters from the vault's `[argon2]`
/// section (reused so the legacy code attains the same brute-force resistance
/// as the master password; design Q3).
pub struct Argon2LegacyDeriver {
    pub params: kdf::Argon2Params,
}

impl Argon2LegacyDeriver {
    pub fn new(params: kdf::Argon2Params) -> Self {
        Self { params }
    }
}

impl LegacyKeyDeriver for Argon2LegacyDeriver {
    fn derive(&self, code: &[u8], salt: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, DiaryError> {
        let key = kdf::derive_key(code, salt, &self.params)?;
        Ok(Zeroizing::new(*key.as_ref()))
    }
}

// ============================================================================
// LegacyFlag (typed wrapper over the 1-byte on-disk field)
// ============================================================================

/// Entry-level legacy disposition. Maps to the `legacy_flag` byte in the
/// on-disk record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LegacyFlag {
    /// Default: entry is destroyed during `legacy-access`.
    Destroy = 0x00,
    /// Entry survives `legacy-access` (re-encrypted under K_legacy).
    Inherit = 0x01,
}

impl LegacyFlag {
    pub fn from_byte(b: u8) -> Result<Self, DiaryError> {
        match b {
            0x00 => Ok(LegacyFlag::Destroy),
            0x01 => Ok(LegacyFlag::Inherit),
            other => Err(DiaryError::Vault(format!(
                "unknown legacy flag byte: 0x{other:02x}"
            ))),
        }
    }

    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

// ============================================================================
// Status / report structs
// ============================================================================

/// Per-entry status row used by `legacy list`.
#[derive(Debug, Clone)]
pub struct LegacyEntryStatus {
    pub uuid_prefix: String,
    pub title: String,
    pub flag: LegacyFlag,
    pub updated_at: u64,
}

/// Summary returned by [`execute_legacy_access`].
///
/// The `inherited` / `destroyed` counters report diary entries; the
/// `_attachments` variants report attachment records (S13).
#[derive(Debug, Clone, Copy, Default)]
pub struct LegacyAccessReport {
    /// Entries that survived (carried into the heir's vault).
    pub inherited: usize,
    /// Entries that were destroyed.
    pub destroyed: usize,
    /// Attachments carried into the heir's vault (S13).
    pub inherited_attachments: usize,
    /// Attachment records omitted from the committed heir vault (S13).
    /// Unreferenced blob cleanup follows the commit and can fail separately
    /// with `DiaryError::LegacyCleanupIncomplete`.
    pub destroyed_attachments: usize,
}

// ============================================================================
// initialize_legacy: bootstrap the [legacy] section
// ============================================================================

/// Initialize the digital-legacy feature for a vault.
///
/// Verifies `master_pwd` (so accidental init on the wrong vault fails), derives
/// K_legacy from `legacy_code` and the existing `legacy_salt`, generates a
/// verification token under K_legacy, and writes the `[legacy]` section into
/// `vault.toml`. Idempotent only across failures — running this against an
/// already-initialized vault returns `DiaryError::Vault("already initialized")`.
pub fn initialize_legacy(
    vault_dir: &Path,
    master_pwd: &SecretString,
    legacy_code: &SecretString,
    confirmation: ConfirmationMode,
    deriver: &dyn LegacyKeyDeriver,
) -> Result<(), DiaryError> {
    if legacy_code.expose_secret().is_empty() {
        return Err(DiaryError::Password(
            "legacy code must not be empty".to_string(),
        ));
    }

    let vault_pqd = vault_dir.join("vault.pqd");
    let vault_toml = vault_dir.join("vault.toml");

    let mut config = VaultConfig::from_file(&vault_toml)?;
    if config.legacy.initialized {
        return Err(DiaryError::Vault(
            "legacy is already initialized for this vault".to_string(),
        ));
    }

    let vault_bytes = std::fs::read(&vault_pqd)?;
    let (header, _entries, _attachments) = read_vault_with_attachments_from_bytes(&vault_bytes)?;

    // 1) verify the master password against the vault's verification token —
    //    refuse to initialize on a vault the caller cannot already unlock.
    let params = argon2_params_from(&config);
    verify_master(&vault_bytes, &header, master_pwd, &params)?;
    drop(vault_bytes);

    // 2) derive K_legacy and stamp a fresh verification token under it.
    let k_legacy = deriver.derive(legacy_code.expose_secret().as_bytes(), &header.legacy_salt)?;
    let (iv, ct) = generate_verification_token(&k_legacy)?;

    config.legacy.initialized = true;
    config.legacy.destroy_confirmation = confirmation;
    config.legacy.verification_iv_b64 = Some(B64.encode(iv));
    config.legacy.verification_ct_b64 = Some(B64.encode(&ct));

    write_vault_toml_atomic(&vault_toml, &config)?;
    Ok(())
}

// ============================================================================
// set_entry_flag: write the per-entry legacy disposition
// ============================================================================

/// Set the legacy disposition of a single entry. For [`LegacyFlag::Inherit`]
/// the entry plaintext is re-encrypted under K_legacy and stored in
/// `legacy_key_block`. For [`LegacyFlag::Destroy`] the block is dropped.
pub fn set_entry_flag(
    vault_dir: &Path,
    master_pwd: &SecretString,
    legacy_code_opt: Option<&SecretString>,
    id_prefix: &str,
    flag: LegacyFlag,
    deriver: &dyn LegacyKeyDeriver,
) -> Result<(), DiaryError> {
    let vault_pqd = vault_dir.join("vault.pqd");
    let vault_toml = vault_dir.join("vault.toml");
    let config = VaultConfig::from_file(&vault_toml)?;

    if !config.legacy.initialized {
        return Err(DiaryError::Vault(
            "legacy not initialized — run `pq-diary legacy init` first".to_string(),
        ));
    }

    let vault_bytes = std::fs::read(&vault_pqd)?;
    let (header, mut entries, attachments) = read_vault_with_attachments_from_bytes(&vault_bytes)?;
    let params = argon2_params_from(&config);
    let k_master = verify_master(&vault_bytes, &header, master_pwd, &params)?;
    drop(vault_bytes);

    // Locate the unique entry matching `id_prefix`.
    let prefix_lower = id_prefix.to_ascii_lowercase();
    if prefix_lower.is_empty() {
        return Err(DiaryError::Entry("ID prefix must not be empty".to_string()));
    }

    let matches: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, r)| {
            r.record_type == RECORD_TYPE_ENTRY && hex_lower(&r.uuid).starts_with(&prefix_lower)
        })
        .map(|(i, _)| i)
        .collect();
    let idx = match matches.len() {
        0 => {
            return Err(DiaryError::Entry(format!(
                "no entry matches prefix '{id_prefix}'"
            )))
        }
        1 => matches[0],
        _ => {
            let candidates: Vec<String> = matches
                .iter()
                .map(|&i| hex_lower(&entries[i].uuid))
                .collect();
            return Err(DiaryError::Entry(format!(
                "multiple entries match prefix '{}': {}",
                id_prefix,
                candidates.join(", ")
            )));
        }
    };

    match flag {
        LegacyFlag::Destroy => {
            entries[idx].legacy_flag = LegacyFlag::Destroy.to_byte();
            entries[idx].legacy_key_block = Vec::new();
        }
        LegacyFlag::Inherit => {
            let legacy_code = legacy_code_opt.ok_or_else(|| {
                DiaryError::InvalidArgument(
                    "legacy code is required when setting --inherit".to_string(),
                )
            })?;
            let k_legacy =
                deriver.derive(legacy_code.expose_secret().as_bytes(), &header.legacy_salt)?;
            verify_legacy_code(&config, &k_legacy)?;

            // Decrypt the entry plaintext under K_master, then re-encrypt the
            // plaintext under K_legacy. (Architecture: legacy_key_block stores
            // the entire entry payload, not a per-entry DEK.)
            let plain = aead::decrypt(&k_master, entries[idx].iv, &entries[idx].ciphertext)?;
            let _check: EntryPlaintext = serde_json::from_slice(plain.as_ref()).map_err(|e| {
                DiaryError::Entry(format!("entry plaintext is not valid JSON: {e}"))
            })?;
            let block = encrypt_legacy_block(&k_legacy, plain.as_ref())?;

            entries[idx].legacy_flag = LegacyFlag::Inherit.to_byte();
            entries[idx].legacy_key_block = block;
        }
    }

    // Vault stays encrypted under the master key, so the integrity MAC keys on it.
    let mac_key = crate::crypto::derive_vault_mac_key(&k_master)?;
    crate::vault::writer::write_vault_with_attachments_authenticated(
        &vault_pqd,
        header,
        &entries,
        &attachments,
        &mac_key,
    )?;
    Ok(())
}

// ============================================================================
// list_legacy_status: per-entry status table
// ============================================================================

/// List the legacy disposition of every entry in the vault.
pub fn list_legacy_status(
    vault_dir: &Path,
    master_pwd: &SecretString,
) -> Result<Vec<LegacyEntryStatus>, DiaryError> {
    let vault_pqd = vault_dir.join("vault.pqd");
    let vault_toml = vault_dir.join("vault.toml");
    let config = VaultConfig::from_file(&vault_toml)?;

    let vault_bytes = std::fs::read(&vault_pqd)?;
    let (header, entries, _attachments) = read_vault_with_attachments_from_bytes(&vault_bytes)?;
    let params = argon2_params_from(&config);
    let k_master = verify_master(&vault_bytes, &header, master_pwd, &params)?;
    drop(vault_bytes);

    let mut out = Vec::with_capacity(entries.len());
    for record in &entries {
        if record.record_type != RECORD_TYPE_ENTRY {
            continue;
        }
        let plain = aead::decrypt(&k_master, record.iv, &record.ciphertext)?;
        let plaintext: EntryPlaintext = serde_json::from_slice(plain.as_ref())
            .map_err(|e| DiaryError::Entry(format!("entry plaintext is not valid JSON: {e}")))?;
        let flag = LegacyFlag::from_byte(record.legacy_flag)?;
        out.push(LegacyEntryStatus {
            uuid_prefix: hex_lower(&record.uuid)[..8].to_string(),
            title: plaintext.title.clone(),
            flag,
            updated_at: record.updated_at,
        });
    }
    Ok(out)
}

// ============================================================================
// rotate_legacy_code: re-encrypt every INHERIT block under a new K_legacy
// ============================================================================

/// Rotate the post-mortem access code. Every INHERIT entry's `legacy_key_block`
/// is decrypted under the old K_legacy and re-encrypted under the new one. The
/// `vault.toml` verification token is replaced. Returns the number of INHERIT
/// blocks that were re-encrypted.
pub fn rotate_legacy_code(
    vault_dir: &Path,
    master_pwd: &SecretString,
    old_code: &SecretString,
    new_code: &SecretString,
    deriver: &dyn LegacyKeyDeriver,
) -> Result<usize, DiaryError> {
    if new_code.expose_secret().is_empty() {
        return Err(DiaryError::Password(
            "new legacy code must not be empty".to_string(),
        ));
    }

    let vault_pqd = vault_dir.join("vault.pqd");
    let vault_toml = vault_dir.join("vault.toml");
    let mut config = VaultConfig::from_file(&vault_toml)?;

    if !config.legacy.initialized {
        return Err(DiaryError::Vault(
            "legacy not initialized — run `pq-diary legacy init` first".to_string(),
        ));
    }

    let vault_bytes = std::fs::read(&vault_pqd)?;
    let (header, mut entries, mut attachments) =
        read_vault_with_attachments_from_bytes(&vault_bytes)?;
    let params = argon2_params_from(&config);
    let _k_master = verify_master(&vault_bytes, &header, master_pwd, &params)?;
    drop(vault_bytes);

    let k_legacy_old = deriver.derive(old_code.expose_secret().as_bytes(), &header.legacy_salt)?;
    verify_legacy_code(&config, &k_legacy_old)?;
    let k_legacy_new = deriver.derive(new_code.expose_secret().as_bytes(), &header.legacy_salt)?;

    let mut rotated = 0_usize;
    for record in entries.iter_mut() {
        if record.record_type != RECORD_TYPE_ENTRY {
            continue;
        }
        if LegacyFlag::from_byte(record.legacy_flag)? != LegacyFlag::Inherit {
            continue;
        }
        let plain = decrypt_legacy_block(&k_legacy_old, &record.legacy_key_block)?;
        record.legacy_key_block = encrypt_legacy_block(&k_legacy_new, plain.as_ref())?;
        rotated += 1;
    }

    // S13: also rotate INHERIT attachment legacy blocks.
    for record in attachments.iter_mut() {
        if LegacyFlag::from_byte(record.legacy_flag)? != LegacyFlag::Inherit {
            continue;
        }
        let plain = decrypt_legacy_block(&k_legacy_old, &record.legacy_key_block)?;
        record.legacy_key_block = encrypt_legacy_block(&k_legacy_new, plain.as_ref())?;
        rotated += 1;
    }

    // Refresh the verification token under K_legacy_new.
    let (iv, ct) = generate_verification_token(&k_legacy_new)?;
    config.legacy.verification_iv_b64 = Some(B64.encode(iv));
    config.legacy.verification_ct_b64 = Some(B64.encode(&ct));

    let vault_tmp = OwnedLegacyFile::create(sidecar_path(&vault_pqd, ".tmp.rotate")?)?;
    let toml_tmp = OwnedLegacyFile::create(sidecar_path(&vault_toml, ".tmp.rotate")?)?;

    // Master ciphertext is unchanged (only legacy_key_blocks rotate), so the
    // integrity MAC keys on the existing master key.
    let mac_key = crate::crypto::derive_vault_mac_key(&_k_master)?;
    crate::vault::writer::write_vault_with_attachments_authenticated(
        &vault_tmp.path,
        header,
        &entries,
        &attachments,
        &mac_key,
    )?;
    write_vault_toml_sidecar(&toml_tmp.path, &config)?;
    replace_vault_and_toml(
        &vault_pqd,
        &vault_tmp.path,
        &vault_toml,
        &toml_tmp.path,
        ".bak.rotate",
    )?;

    Ok(rotated)
}

// ============================================================================
// execute_legacy_access: the irreversible "open the time capsule" path
// ============================================================================

/// Execute `pq-diary legacy-access`. Decrypts every INHERIT entry under
/// K_legacy, generates a fresh ML-KEM-768 / ML-DSA-65 keypair, and writes a
/// new vault where K_legacy is the master key. The DESTROY entries (and any
/// uninitialized entries) are not carried over — they vanish when the old
/// `vault.pqd` is overwritten via the atomic rename inside `write_vault`.
///
/// `confirm_callback` lets the CLI layer render the timer30 / yn / phrase
/// UX without coupling the core to a TTY.
///
/// `LegacyCleanupIncomplete` means the heir vault and configuration have already
/// been committed, but attachment cleanup failed. Its report describes that
/// committed recovery; callers must not retry legacy access as though it rolled back.
pub fn execute_legacy_access<F>(
    vault_dir: &Path,
    legacy_code: &SecretString,
    deriver: &dyn LegacyKeyDeriver,
    confirm_callback: F,
) -> Result<LegacyAccessReport, DiaryError>
where
    F: FnOnce(ConfirmationMode) -> Result<bool, DiaryError>,
{
    let vault_pqd = vault_dir.join("vault.pqd");
    let vault_toml = vault_dir.join("vault.toml");
    let mut config = VaultConfig::from_file(&vault_toml)?;

    if !config.legacy.initialized {
        return Err(DiaryError::Vault(
            "legacy is not initialized for this vault".to_string(),
        ));
    }

    let (old_header, old_entries, old_attachments) =
        crate::vault::reader::read_vault_with_attachments(&vault_pqd)?;
    let k_legacy = deriver.derive(
        legacy_code.expose_secret().as_bytes(),
        &old_header.legacy_salt,
    )?;
    verify_legacy_code(&config, &k_legacy)?;

    // Confirm only AFTER the K_legacy proof — refusing to spend Argon2 cycles
    // for a wrong code is wasteful, but refusing to confirm for a wrong code
    // is dangerous (the user might say "yes" expecting nothing to happen).
    if !confirm_callback(config.legacy.destroy_confirmation)? {
        return Err(DiaryError::InvalidArgument(
            "legacy-access cancelled by user".to_string(),
        ));
    }

    // Decrypt every INHERIT block; everything else is dropped on the floor.
    // Non-entry records are omitted from the heir's vault, but they are not
    // counted as destroyed diary entries in the user-facing report.
    let mut inherited_plaintexts: Vec<(EntryRecord, Zeroizing<Vec<u8>>)> = Vec::new();
    let mut destroyed = 0_usize;
    let mut inherited_entry_uuids: std::collections::HashSet<[u8; 16]> = Default::default();
    for record in old_entries {
        if record.record_type != RECORD_TYPE_ENTRY {
            continue;
        }
        match LegacyFlag::from_byte(record.legacy_flag)? {
            LegacyFlag::Inherit => {
                let plain = decrypt_legacy_block(&k_legacy, &record.legacy_key_block)?;
                inherited_entry_uuids.insert(record.uuid);
                inherited_plaintexts.push((record, plain));
            }
            LegacyFlag::Destroy => {
                destroyed += 1;
            }
        }
    }

    // Build the new vault: K_legacy becomes the master key, with fresh KEM/DSA
    // keypairs (since the heir has no access to the original seeds). The new
    // kdf_salt MUST equal the vault's original legacy_salt — only then does
    // `unlock(legacy_code)` re-derive the same K_legacy we used to encrypt.
    let new_header = build_new_header(&k_legacy, old_header.legacy_salt)?;
    let dsa_seed_zeroized = decrypt_blob(&k_legacy, &new_header.dsa_encrypted_sk, "DSA")?;

    let mut new_entries = Vec::with_capacity(inherited_plaintexts.len());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| DiaryError::Entry(format!("system time error: {e}")))?
        .as_secs();
    for (record, plain) in inherited_plaintexts {
        let new_record =
            reencrypt_for_new_vault(&record, &k_legacy, &dsa_seed_zeroized, plain.as_ref(), now)?;
        new_entries.push(new_record);
    }
    let inherited = new_entries.len();

    // Attachment processing (S13).
    //
    // Rules:
    // - INHERIT attachment + INHERIT parent entry → carry over to new vault.
    // - INHERIT attachment + DESTROY parent entry → destroyed (REQ-504 cascade).
    // - DESTROY attachment → destroyed regardless of parent.
    //
    // For destroyed attachments we track the blob_uuid as "queued for delete";
    // for inherited attachments we track it as "surviving". A blob is only
    // physically removed if it's in queued-for-delete AND not in surviving
    // (reference-counting per design Q5).
    let mut new_attachments = Vec::with_capacity(old_attachments.len());
    let mut inherited_attachments = 0_usize;
    let mut destroyed_attachments = 0_usize;
    let mut surviving_blobs: std::collections::HashSet<[u8; 16]> = Default::default();
    // entry_uuid → number of inherited attachments tied to that entry.
    let mut per_entry_attach_count: std::collections::HashMap<[u8; 16], u16> = Default::default();

    for record in &old_attachments {
        let is_inherit = LegacyFlag::from_byte(record.legacy_flag)? == LegacyFlag::Inherit;
        if !is_inherit {
            // DESTROY records have no decryptable legacy_key_block, so we
            // cannot recover the blob_uuid here. The blob is only removed
            // when a parallel INHERIT sibling identifies it — otherwise
            // it persists, awaiting an explicit `pq-diary attachment
            // delete` from the heir.
            destroyed_attachments += 1;
            continue;
        }
        // Corruption is not a DESTROY decision: abort before replacing the
        // vault or sweeping blobs still recoverable with the master password.
        let lpt = crate::attachment::decrypt_attachment_legacy_block(record, &k_legacy)?;
        if !inherited_entry_uuids.contains(&lpt.entry_uuid) {
            // REQ-504: parent entry is DESTROY → cascade to attachment.
            destroyed_attachments += 1;
            continue;
        }
        let entry_uuid_copy = lpt.entry_uuid;
        let new_rec = crate::attachment::rebuild_attachment_record_for_heir(
            record.uuid,
            &lpt,
            now,
            &k_legacy,
            &dsa_seed_zeroized,
        )?;
        new_attachments.push(new_rec);
        surviving_blobs.insert(lpt.blob_uuid);
        inherited_attachments += 1;
        *per_entry_attach_count.entry(entry_uuid_copy).or_insert(0) += 1;
    }

    // Refresh attachment_count on each inherited entry to match what we're
    // actually writing into the heir's vault.
    for entry in new_entries.iter_mut() {
        entry.attachment_count = *per_entry_attach_count.get(&entry.uuid).unwrap_or(&0);
    }

    // Reset the legacy section — the heir starts from a clean slate and can
    // run `pq-diary legacy init` again to nominate their own heir.
    config.legacy.initialized = false;
    config.legacy.verification_iv_b64 = None;
    config.legacy.verification_ct_b64 = None;

    let vault_tmp = OwnedLegacyFile::create(sidecar_path(&vault_pqd, ".tmp.legacy")?)?;
    let toml_tmp = OwnedLegacyFile::create(sidecar_path(&vault_toml, ".tmp.legacy")?)?;

    // The heir's vault is encrypted under K_legacy (now its master key), so the
    // integrity MAC must key on K_legacy for a later `unlock(legacy_code)` to verify.
    let mac_key = crate::crypto::derive_vault_mac_key(&k_legacy)?;
    crate::vault::writer::write_vault_with_attachments_authenticated(
        &vault_tmp.path,
        new_header,
        &new_entries,
        &new_attachments,
        &mac_key,
    )?;
    write_vault_toml_sidecar(&toml_tmp.path, &config)?;

    // Keep the original vault intact until both replacements succeed. The
    // transaction helper then wipes the entire old vault through its renamed
    // backup, including any hard links to that inode. Wiping here would corrupt
    // the original that rollback must restore if a later rename fails.
    replace_vault_and_toml(
        &vault_pqd,
        &vault_tmp.path,
        &vault_toml,
        &toml_tmp.path,
        ".bak.legacy",
    )?;

    // After the atomic swap, sweep .attachments/ for blobs that no surviving
    // INHERIT record refers to. We collect on-disk filenames and prune the
    // ones not in `surviving_blobs`. This zeroizes-and-deletes orphaned
    // bodies regardless of whether they were originally INHERIT (parent
    // entry destroyed) or DESTROY records — matching REQ-302 and REQ-503.
    let report = LegacyAccessReport {
        inherited,
        destroyed,
        inherited_attachments,
        destroyed_attachments,
    };
    cleanup_legacy_blobs(vault_dir, &surviving_blobs, report)?;
    Ok(report)
}

fn cleanup_legacy_blobs(
    vault_dir: &Path,
    surviving_blobs: &std::collections::HashSet<[u8; 16]>,
    report: LegacyAccessReport,
) -> Result<(), DiaryError> {
    let attachments_dir = crate::attachment::attachments_dir(vault_dir);
    let incomplete = |path: PathBuf, source: DiaryError| DiaryError::LegacyCleanupIncomplete {
        report,
        path,
        source: Box::new(source),
    };
    match std::fs::symlink_metadata(&attachments_dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(incomplete(attachments_dir, error.into())),
        Ok(metadata) if !metadata.is_dir() => {
            return Err(incomplete(
                attachments_dir,
                std::io::Error::other("attachment directory is not a directory or is a symlink")
                    .into(),
            ));
        }
        Ok(_) => {}
    }
    let entries = std::fs::read_dir(&attachments_dir)
        .map_err(|error| incomplete(attachments_dir.clone(), error.into()))?;
    cleanup_legacy_blob_entries(
        entries.map(|entry| entry.map(|entry| entry.path())),
        &attachments_dir,
        surviving_blobs,
        report,
    )
}

fn cleanup_legacy_blob_entries(
    entries: impl Iterator<Item = std::io::Result<PathBuf>>,
    attachments_dir: &Path,
    surviving_blobs: &std::collections::HashSet<[u8; 16]>,
    report: LegacyAccessReport,
) -> Result<(), DiaryError> {
    let incomplete = |path: PathBuf, source: DiaryError| DiaryError::LegacyCleanupIncomplete {
        report,
        path,
        source: Box::new(source),
    };
    for entry in entries {
        let path =
            entry.map_err(|error| incomplete(attachments_dir.to_path_buf(), error.into()))?;
        if path.extension().and_then(|s| s.to_str()) != Some("bin") {
            continue;
        }
        let Some(uuid_bytes) = path
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(parse_hex_uuid)
        else {
            continue;
        };
        if !surviving_blobs.contains(&uuid_bytes) {
            crate::attachment::zeroize_and_delete(&path)
                .map_err(|source| incomplete(path, source))?;
        }
    }
    Ok(())
}

fn parse_hex_uuid(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 || !s.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

// ============================================================================
// Helpers (private)
// ============================================================================

fn argon2_params_from(config: &VaultConfig) -> kdf::Argon2Params {
    kdf::Argon2Params {
        memory_cost_kb: config.argon2.memory_cost_kb,
        time_cost: config.argon2.time_cost,
        parallelism: config.argon2.parallelism,
    }
}

fn verify_master(
    vault_bytes: &[u8],
    header: &VaultHeader,
    master_pwd: &SecretString,
    params: &kdf::Argon2Params,
) -> Result<Zeroizing<[u8; 32]>, DiaryError> {
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
    // Direct module callers must authenticate the vault before trusting its
    // records or creating side effects; they do not pass through DiaryCore::unlock.
    let mac_key = crate::crypto::derive_vault_mac_key(key.as_ref())?;
    crate::vault::reader::verify_vault_integrity_bytes(vault_bytes, &mac_key)?;
    Ok(Zeroizing::new(*key.as_ref()))
}

pub(crate) fn verify_legacy_code(
    config: &VaultConfig,
    k_legacy: &[u8; 32],
) -> Result<(), DiaryError> {
    let iv_b64 = config
        .legacy
        .verification_iv_b64
        .as_deref()
        .ok_or_else(|| {
            DiaryError::Config("vault.toml [legacy] verification_iv_b64 missing".to_string())
        })?;
    let ct_b64 = config
        .legacy
        .verification_ct_b64
        .as_deref()
        .ok_or_else(|| {
            DiaryError::Config("vault.toml [legacy] verification_ct_b64 missing".to_string())
        })?;
    let iv_bytes = B64
        .decode(iv_b64)
        .map_err(|e| DiaryError::Config(format!("invalid verification_iv_b64: {e}")))?;
    let iv: [u8; aead::NONCE_SIZE] = iv_bytes.as_slice().try_into().map_err(|_| {
        DiaryError::Config("verification_iv_b64 must decode to 12 bytes".to_string())
    })?;
    let ct = B64
        .decode(ct_b64)
        .map_err(|e| DiaryError::Config(format!("invalid verification_ct_b64: {e}")))?;
    aead::decrypt(k_legacy, iv, &ct)
        .map_err(|_| DiaryError::Crypto("invalid legacy code".to_string()))?;
    Ok(())
}

fn write_vault_toml_atomic(path: &Path, config: &VaultConfig) -> Result<(), DiaryError> {
    let mut tmp_name = path
        .file_name()
        .ok_or_else(|| DiaryError::Config("vault.toml path has no file name".to_string()))?
        .to_os_string();
    tmp_name.push(".tmp");
    let tmp_path = path.with_file_name(tmp_name);

    config.to_file(&tmp_path)?;
    std::fs::rename(&tmp_path, path).map_err(DiaryError::Io)?;
    Ok(())
}

fn write_vault_toml_sidecar(path: &Path, config: &VaultConfig) -> Result<(), DiaryError> {
    config.to_file(path)?;
    Ok(())
}

fn sidecar_path(path: &Path, suffix: &str) -> Result<PathBuf, DiaryError> {
    let mut name = path
        .file_name()
        .ok_or_else(|| DiaryError::Vault("path has no file name".to_string()))?
        .to_os_string();
    name.push(suffix);
    Ok(path.with_file_name(name))
}

/// Owns a sidecar only after exclusive creation. The parent directory must
/// remain under the caller's control, as for the shared atomic writer.
struct OwnedLegacyFile {
    path: PathBuf,
    cleanup_on_drop: bool,
}

impl OwnedLegacyFile {
    fn create(path: PathBuf) -> Result<Self, DiaryError> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        // Close the reservation before replacement, including on Windows.
        drop(options.open(&path)?);
        Ok(Self {
            path,
            cleanup_on_drop: true,
        })
    }
}

impl Drop for OwnedLegacyFile {
    fn drop(&mut self) {
        if self.cleanup_on_drop {
            cleanup_sensitive_file(&self.path);
        }
    }
}

fn replace_vault_and_toml(
    vault_path: &Path,
    vault_tmp: &Path,
    toml_path: &Path,
    toml_tmp: &Path,
    backup_suffix: &str,
) -> Result<(), DiaryError> {
    replace_vault_and_toml_with(
        vault_path,
        vault_tmp,
        toml_path,
        toml_tmp,
        backup_suffix,
        |from, to| std::fs::rename(from, to),
    )
}

fn replace_vault_and_toml_with(
    vault_path: &Path,
    vault_tmp: &Path,
    toml_path: &Path,
    toml_tmp: &Path,
    backup_suffix: &str,
    mut rename: impl FnMut(&Path, &Path) -> std::io::Result<()>,
) -> Result<(), DiaryError> {
    // Claim both destinations before moving either original. Existing recovery
    // data (including symlinks) is never overwritten or cleaned up.
    let mut vault_bak = OwnedLegacyFile::create(sidecar_path(vault_path, backup_suffix)?)?;
    let mut toml_bak = OwnedLegacyFile::create(sidecar_path(toml_path, backup_suffix)?)?;
    let mut vault_backed_up = false;
    let mut toml_backed_up = false;

    let result = (|| -> Result<(), DiaryError> {
        rename(vault_path, &vault_bak.path)?;
        // From this point the backup owns the original: preserve it on error
        // or unwind until recovery or the complete two-file commit succeeds.
        vault_bak.cleanup_on_drop = false;
        vault_backed_up = true;
        rename(toml_path, &toml_bak.path)?;
        toml_bak.cleanup_on_drop = false;
        toml_backed_up = true;
        rename(vault_tmp, vault_path)?;
        rename(toml_tmp, toml_path)?;
        Ok(())
    })();

    if let Err(error) = result {
        let mut recovery_errors = Vec::new();
        if toml_backed_up {
            if let Err(recovery) = rename(&toml_bak.path, toml_path) {
                recovery_errors.push(format!("{:?}: {recovery}", toml_bak.path));
            }
        }
        if vault_backed_up {
            if let Err(recovery) = rename(&vault_bak.path, vault_path) {
                recovery_errors.push(format!("{:?}: {recovery}", vault_bak.path));
            }
        }
        if !recovery_errors.is_empty() {
            return Err(DiaryError::Vault(format!(
                "legacy transaction failed: {error}; rollback incomplete; preserve recovery backups and inspect before retrying: {}",
                recovery_errors.join("; ")
            )));
        }
        return Err(error);
    }

    // Both replacements committed. Only now may Drop wipe our renamed
    // originals, including their hard links; cleanup cannot turn success into Err.
    vault_bak.cleanup_on_drop = true;
    toml_bak.cleanup_on_drop = true;
    Ok(())
}

fn cleanup_sensitive_file(path: &Path) {
    cleanup_sensitive_file_with_writer(path, &mut std::io::stderr().lock());
}

fn cleanup_sensitive_file_with_writer(path: &Path, warnings: &mut impl std::io::Write) {
    if path.is_dir() {
        return;
    }
    if path.is_file() {
        if let Err(error) = zeroize_file(path) {
            // Secondary diagnostics must not panic or hide the primary error.
            let _ = writeln!(
                warnings,
                "Warning: failed to zeroize temporary file {path:?}: {error}"
            );
        }
    }
    if let Err(error) = std::fs::remove_file(path) {
        if error.kind() != std::io::ErrorKind::NotFound {
            let _ = writeln!(
                warnings,
                "Warning: failed to remove temporary file {path:?}: {error}"
            );
        }
    }
}

fn zeroize_file(path: &Path) -> Result<(), DiaryError> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?;
    let len = file.metadata()?.len();
    zeroize_file_range(&mut file, 0, len)?;
    file.sync_all()?;
    Ok(())
}

fn zeroize_file_range(file: &mut std::fs::File, offset: u64, len: u64) -> Result<(), DiaryError> {
    use std::io::{Seek as _, Write as _};

    file.seek(std::io::SeekFrom::Start(offset))?;
    let zeros = [0u8; 8192];
    let mut remaining = len;
    while remaining > 0 {
        let chunk_len = remaining.min(zeros.len() as u64) as usize;
        file.write_all(&zeros[..chunk_len])?;
        remaining -= chunk_len as u64;
    }
    Ok(())
}

fn encrypt_legacy_block(k_legacy: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, DiaryError> {
    let (ct, iv) = aead::encrypt(k_legacy, plaintext)?;
    let mut out = Vec::with_capacity(iv.len() + ct.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt_legacy_block(
    k_legacy: &[u8; 32],
    block: &[u8],
) -> Result<Zeroizing<Vec<u8>>, DiaryError> {
    if block.len() < aead::NONCE_SIZE {
        return Err(DiaryError::Vault(
            "legacy_key_block is shorter than the AEAD nonce".to_string(),
        ));
    }
    let iv: [u8; aead::NONCE_SIZE] = block[..aead::NONCE_SIZE]
        .try_into()
        .map_err(|_| DiaryError::Vault("legacy_key_block has invalid IV".to_string()))?;
    let ct = &block[aead::NONCE_SIZE..];
    let plain = aead::decrypt(k_legacy, iv, ct)
        .map_err(|_| DiaryError::Crypto("failed to decrypt legacy block".to_string()))?;
    Ok(Zeroizing::new(plain.as_ref().to_vec()))
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

fn encrypt_blob(sym_key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, DiaryError> {
    let (ct, iv) = aead::encrypt(sym_key, plaintext)?;
    let mut out = Vec::with_capacity(iv.len() + ct.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn hex_lower(uuid: &[u8; 16]) -> String {
    uuid.iter().map(|b| format!("{b:02x}")).collect()
}

/// Build the header of the freshly-minted vault that `legacy-access` produces.
/// `kdf_salt` is set to the original vault's `legacy_salt` so the heir can
/// re-derive K_legacy with `legacy_code` (now playing the role of master
/// password). A fresh `legacy_salt` is generated for the heir's own future
/// use, and new KEM/DSA seeds are created under K_legacy.
fn build_new_header(
    k_legacy: &[u8; 32],
    original_legacy_salt: [u8; 32],
) -> Result<VaultHeader, DiaryError> {
    let new_kdf_salt = original_legacy_salt;
    let mut new_legacy_salt = [0u8; 32];
    OsRng.fill_bytes(&mut new_legacy_salt);

    let (verification_iv, verification_ct) = generate_verification_token(k_legacy)?;

    let kem_kp = kem::keygen()?;
    let kem_encrypted_sk = encrypt_blob(k_legacy, kem_kp.decapsulation_key.as_ref())?;

    let dsa_kp = dsa::keygen()?;
    let dsa_encrypted_sk = encrypt_blob(k_legacy, dsa_kp.signing_key.as_ref())?;

    let mut hasher = Sha256::new();
    hasher.update(&dsa_kp.verifying_key);
    let dsa_pk_hash: [u8; 32] = hasher.finalize().into();

    Ok(VaultHeader {
        schema_version: SCHEMA_VERSION,
        flags: 0,
        payload_size: 0,
        kdf_salt: new_kdf_salt,
        legacy_salt: new_legacy_salt,
        verification_iv,
        verification_ct,
        kem_pk_offset: [0u8; 32],
        dsa_pk_hash,
        kem_encrypted_sk,
        dsa_encrypted_sk,
    })
}

/// Re-encrypt an inherited entry's plaintext under K_legacy and sign it with
/// the new DSA seed. `legacy_flag` is reset to DESTROY (the heir starts from
/// a clean slate; they can run `legacy set --inherit` if they want).
fn reencrypt_for_new_vault(
    src: &EntryRecord,
    k_legacy: &[u8; 32],
    dsa_seed: &Zeroizing<Vec<u8>>,
    plaintext_json: &[u8],
    inherited_at: u64,
) -> Result<EntryRecord, DiaryError> {
    use crate::crypto::{hmac_util, secure_mem::SecureBuffer};

    let (ciphertext, iv) = aead::encrypt(k_legacy, plaintext_json)?;
    let dsa_sk = SecureBuffer::new(dsa_seed.as_slice().to_vec());
    let signature = dsa::sign(&dsa_sk, &ciphertext)?;
    let content_hmac = hmac_util::compute(k_legacy, &ciphertext)?;

    Ok(EntryRecord {
        record_type: src.record_type,
        uuid: src.uuid,
        created_at: src.created_at,
        updated_at: inherited_at,
        iv,
        ciphertext,
        signature,
        content_hmac,
        legacy_flag: LegacyFlag::Destroy.to_byte(),
        legacy_key_block: Vec::new(),
        attachment_count: 0,
        attachment_offset: 0,
        padding: Vec::new(), // write_vault regenerates entry-level padding.
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::Argon2Params;
    use crate::vault::init::VaultManager;
    use crate::vault::reader::read_vault;
    use crate::DiaryCore;
    use secrecy::SecretBox;
    use tempfile::tempdir;

    fn assert_legacy_sidecar_collisions_preserved(create_collision: impl Fn(&Path, &Path)) {
        for operation in ["rotate", "access"] {
            let suffix = if operation == "rotate" {
                "rotate"
            } else {
                "legacy"
            };
            for name in [
                format!("vault.pqd.tmp.{suffix}"),
                format!("vault.toml.tmp.{suffix}"),
                format!("vault.pqd.bak.{suffix}"),
                format!("vault.toml.bak.{suffix}"),
            ] {
                let dir = tempdir().unwrap();
                let (vault_dir, _) = vault_with_one_entry(&dir, 1);
                let vault_path = vault_dir.join("vault.pqd");
                let config_path = vault_dir.join("vault.toml");
                let vault_before = std::fs::read(&vault_path).unwrap();
                let config_before = std::fs::read(&config_path).unwrap();
                let collision = vault_dir.join(&name);
                let unrelated = dir.path().join("unrelated");
                std::fs::write(&unrelated, b"existing recovery data").unwrap();
                create_collision(&collision, &unrelated);
                let metadata_before = std::fs::symlink_metadata(&collision).unwrap();
                let link_before = std::fs::read_link(&collision).ok();
                let dangling_target = unrelated.with_extension("absent");

                let result = if operation == "rotate" {
                    rotate_legacy_code(
                        &vault_dir,
                        &secret("master-pw"),
                        &secret("legacy-code"),
                        &secret("new-code"),
                        &fast_deriver(),
                    )
                    .map(|_| ())
                } else {
                    execute_legacy_access(
                        &vault_dir,
                        &secret("legacy-code"),
                        &fast_deriver(),
                        always_confirm,
                    )
                    .map(|_| ())
                };
                assert!(
                    matches!(result, Err(DiaryError::Io(_))),
                    "{operation}: existing {name} must fail closed: {result:?}"
                );
                assert_eq!(std::fs::read(&vault_path).unwrap(), vault_before);
                assert_eq!(std::fs::read(&config_path).unwrap(), config_before);
                assert_eq!(
                    std::fs::read(&unrelated).unwrap(),
                    b"existing recovery data"
                );
                let metadata_after = std::fs::symlink_metadata(&collision).unwrap();
                assert_eq!(metadata_after.file_type(), metadata_before.file_type());
                assert_eq!(std::fs::read_link(&collision).ok(), link_before);
                assert!(!dangling_target.exists());
                if metadata_before.is_dir() {
                    assert_eq!(
                        std::fs::read(collision.join("sentinel")).unwrap(),
                        b"directory contents"
                    );
                }
                if metadata_before.is_file() {
                    assert_eq!(
                        std::fs::read(&collision).unwrap(),
                        b"existing recovery data"
                    );
                }
                let mut core = DiaryCore::new(&vault_pqd_str(&vault_dir)).unwrap();
                core.unlock(secret("master-pw")).unwrap();
                assert_eq!(core.list_entries(None).unwrap().len(), 1);
            }
        }
    }

    #[test]
    fn legacy_transactions_preserve_existing_sidecar_files() {
        assert_legacy_sidecar_collisions_preserved(|path, _| {
            std::fs::write(path, b"existing recovery data").unwrap();
        });
    }

    #[test]
    fn legacy_transactions_preserve_existing_sidecar_directories() {
        assert_legacy_sidecar_collisions_preserved(|path, _| {
            std::fs::create_dir(path).unwrap();
            std::fs::write(path.join("sentinel"), b"directory contents").unwrap();
        });
    }

    #[cfg(unix)]
    #[test]
    fn legacy_transactions_preserve_existing_sidecar_symlinks() {
        assert_legacy_sidecar_collisions_preserved(|path, target| {
            std::os::unix::fs::symlink(target, path).unwrap();
        });
        assert_legacy_sidecar_collisions_preserved(|path, target| {
            std::os::unix::fs::symlink(target.with_extension("absent"), path).unwrap();
        });
    }

    fn transaction_fixture(dir: &Path) -> [PathBuf; 4] {
        let paths = [
            dir.join("vault.pqd"),
            dir.join("vault.pqd.tmp"),
            dir.join("vault.toml"),
            dir.join("vault.toml.tmp"),
        ];
        for (path, bytes) in paths.iter().zip([
            &b"original vault"[..],
            &b"new vault"[..],
            &b"original config"[..],
            &b"new config"[..],
        ]) {
            std::fs::write(path, bytes).unwrap();
        }
        paths
    }

    #[test]
    fn legacy_transaction_restores_both_originals_after_each_rename_failure() {
        for fail_at in 1..=4 {
            let dir = tempdir().unwrap();
            let [vault, vault_tmp, config, config_tmp] = transaction_fixture(dir.path());
            let mut calls = 0;
            let result = replace_vault_and_toml_with(
                &vault,
                &vault_tmp,
                &config,
                &config_tmp,
                ".bak",
                |from, to| {
                    calls += 1;
                    if calls == fail_at {
                        return Err(std::io::Error::other("injected forward rename failure"));
                    }
                    std::fs::rename(from, to)
                },
            );
            assert!(
                matches!(result, Err(DiaryError::Io(ref e))
                    if e.to_string() == "injected forward rename failure"),
                "rename {fail_at}: {result:?}"
            );
            assert_eq!(std::fs::read(&vault).unwrap(), b"original vault");
            assert_eq!(std::fs::read(&config).unwrap(), b"original config");
            assert!(!sidecar_path(&vault, ".bak").unwrap().exists());
            assert!(!sidecar_path(&config, ".bak").unwrap().exists());
        }
    }

    #[test]
    fn legacy_transaction_retains_backups_and_attempts_both_failed_restores() {
        for failures in [vec![5], vec![6], vec![5, 6]] {
            let dir = tempdir().unwrap();
            let [vault, vault_tmp, config, config_tmp] = transaction_fixture(dir.path());
            let vault_bak = sidecar_path(&vault, ".bak").unwrap();
            let config_bak = sidecar_path(&config, ".bak").unwrap();
            let mut calls = 0;
            let result = replace_vault_and_toml_with(
                &vault,
                &vault_tmp,
                &config,
                &config_tmp,
                ".bak",
                |from, to| {
                    calls += 1;
                    if calls == 4 {
                        return Err(std::io::Error::other("injected commit failure"));
                    }
                    if failures.contains(&calls) {
                        return Err(std::io::Error::other("injected recovery failure"));
                    }
                    std::fs::rename(from, to)
                },
            );
            assert_eq!(calls, 6, "must attempt both restores");
            let error = result.expect_err("failed recovery must be reported");
            let message = error.to_string();
            assert!(matches!(error, DiaryError::Vault(_)));
            assert!(message.contains("injected commit failure"));
            assert!(message.contains("injected recovery failure"));
            assert!(message.contains("rollback incomplete"));
            for (call, backup, original, bytes) in [
                (5, &config_bak, &config, &b"original config"[..]),
                (6, &vault_bak, &vault, &b"original vault"[..]),
            ] {
                if failures.contains(&call) {
                    assert_eq!(std::fs::read(backup).unwrap(), bytes);
                    assert!(message.contains(&format!("{backup:?}")));
                } else {
                    assert_eq!(std::fs::read(original).unwrap(), bytes);
                    assert!(!backup.exists());
                }
            }
        }
    }

    #[test]
    fn legacy_transaction_replaces_closed_reservations_and_cleans_backups() {
        let dir = tempdir().unwrap();
        let [vault, vault_tmp, config, config_tmp] = transaction_fixture(dir.path());
        replace_vault_and_toml(&vault, &vault_tmp, &config, &config_tmp, ".bak").unwrap();
        assert_eq!(std::fs::read(&vault).unwrap(), b"new vault");
        assert_eq!(std::fs::read(&config).unwrap(), b"new config");
        assert!(!sidecar_path(&vault, ".bak").unwrap().exists());
        assert!(!sidecar_path(&config, ".bak").unwrap().exists());
    }

    #[test]
    fn legacy_transaction_retains_original_backups_on_unwind() {
        let dir = tempdir().unwrap();
        let [vault, vault_tmp, config, config_tmp] = transaction_fixture(dir.path());
        let result = std::panic::catch_unwind(|| {
            let mut calls = 0;
            let _ = replace_vault_and_toml_with(
                &vault,
                &vault_tmp,
                &config,
                &config_tmp,
                ".bak",
                |from, to| {
                    calls += 1;
                    assert_ne!(calls, 4, "injected unwind before second replacement");
                    std::fs::rename(from, to)
                },
            );
        });
        assert!(result.is_err());
        assert_eq!(
            std::fs::read(sidecar_path(&vault, ".bak").unwrap()).unwrap(),
            b"original vault"
        );
        assert_eq!(
            std::fs::read(sidecar_path(&config, ".bak").unwrap()).unwrap(),
            b"original config"
        );
    }

    #[test]
    fn owned_legacy_sidecar_is_private_and_cleaned_on_unwind() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("owned.tmp");
        let result = std::panic::catch_unwind(|| {
            let owned = OwnedLegacyFile::create(path.clone()).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                assert_eq!(
                    std::fs::metadata(&owned.path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
            std::fs::write(&owned.path, b"owned temporary bytes").unwrap();
            panic!("injected unwind");
        });
        assert!(result.is_err());
        assert!(!path.exists());
    }

    #[test]
    fn legacy_cleanup_warning_write_failure_does_not_panic() {
        struct BrokenWarnings {
            attempts: usize,
        }
        impl std::io::Write for BrokenWarnings {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                self.attempts += 1;
                Err(std::io::ErrorKind::BrokenPipe.into())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
        }
        let dir = tempdir().unwrap();
        let blocker = dir.path().join("not-a-directory");
        std::fs::write(&blocker, b"unrelated data").unwrap();
        let mut warnings = BrokenWarnings { attempts: 0 };
        cleanup_sensitive_file_with_writer(&blocker.join("child"), &mut warnings);
        assert!(warnings.attempts > 0);
        assert_eq!(std::fs::read(blocker).unwrap(), b"unrelated data");
    }

    #[test]
    fn attachment_uuid_parser_accepts_only_ascii_hex() {
        assert_eq!(
            parse_hex_uuid("00112233445566778899aAbBcCdDeEfF"),
            Some([
                0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ])
        );
        for invalid in [
            format!("€{}", "a".repeat(29)),
            "é".repeat(16),
            "a".repeat(31),
            "g".repeat(32),
            format!("+1{}", "a".repeat(30)),
        ] {
            assert_eq!(parse_hex_uuid(&invalid), None);
        }
    }

    #[test]
    fn legacy_access_preserves_unrelated_unicode_attachment_filename() {
        let dir = tempdir().unwrap();
        let (vault_dir, _) = vault_with_one_entry(&dir, 1);
        let attachments = crate::attachment::attachments_dir(&vault_dir);
        std::fs::create_dir_all(&attachments).unwrap();
        let unrelated = attachments.join(format!("€{}.bin", "a".repeat(29)));
        std::fs::write(&unrelated, b"unrelated synthetic data").unwrap();
        execute_legacy_access(
            &vault_dir,
            &secret("legacy-code"),
            &fast_deriver(),
            always_confirm,
        )
        .unwrap();
        assert_eq!(
            std::fs::read(unrelated).unwrap(),
            b"unrelated synthetic data"
        );
        let mut heir = DiaryCore::new(&vault_pqd_str(&vault_dir)).unwrap();
        heir.unlock(secret("legacy-code")).unwrap();
    }

    fn assert_cleanup_failure_commits_reopenable_vault(prepare: impl FnOnce(&Path) -> PathBuf) {
        use std::error::Error;
        let dir = tempdir().unwrap();
        let (vault_dir, ids) = vault_with_one_entry(&dir, 1);
        set_entry_flag(
            &vault_dir,
            &secret("master-pw"),
            Some(&secret("legacy-code")),
            &ids[0],
            LegacyFlag::Inherit,
            &fast_deriver(),
        )
        .unwrap();
        let obstacle = prepare(&vault_dir);
        let error = execute_legacy_access(
            &vault_dir,
            &secret("legacy-code"),
            &fast_deriver(),
            always_confirm,
        )
        .unwrap_err();
        assert!(error.to_string().contains("recovery committed"));
        assert!(error.source().is_some());
        match error {
            DiaryError::LegacyCleanupIncomplete {
                report,
                path,
                source,
            } => {
                assert_eq!(report.inherited, 1);
                assert_eq!(report.destroyed, 0);
                assert_eq!(path, obstacle);
                assert!(matches!(*source, DiaryError::Io(_)));
            }
            other => panic!("unexpected error: {other}"),
        }
        assert!(std::fs::symlink_metadata(&obstacle).is_ok());
        if obstacle.is_dir() && !obstacle.is_symlink() {
            assert_eq!(
                std::fs::read(obstacle.join("unrelated")).unwrap(),
                b"keep me"
            );
        } else if !obstacle.is_symlink() {
            assert_eq!(std::fs::read(&obstacle).unwrap(), b"keep me");
        }
        let config = VaultConfig::from_file(&vault_dir.join("vault.toml")).unwrap();
        assert!(!config.legacy.initialized);
        let mut heir = DiaryCore::new(&vault_pqd_str(&vault_dir)).unwrap();
        heir.unlock(secret("legacy-code")).unwrap();
        assert_eq!(heir.list_entries(None).unwrap().len(), 1);
    }

    #[test]
    fn legacy_cleanup_failure_reports_committed_recovery() {
        assert_cleanup_failure_commits_reopenable_vault(|vault_dir| {
            let obstacle = crate::attachment::attachments_dir(vault_dir)
                .join(format!("{}.bin", "a".repeat(32)));
            std::fs::create_dir_all(&obstacle).unwrap();
            std::fs::write(obstacle.join("unrelated"), b"keep me").unwrap();
            obstacle
        });
    }

    #[test]
    fn legacy_cleanup_reports_invalid_attachment_directory() {
        assert_cleanup_failure_commits_reopenable_vault(|vault_dir| {
            let obstacle = crate::attachment::attachments_dir(vault_dir);
            std::fs::write(&obstacle, b"keep me").unwrap();
            obstacle
        });
    }

    #[test]
    fn legacy_cleanup_reports_directory_iteration_error() {
        use std::error::Error;
        let path = Path::new("synthetic-attachments");
        let error = cleanup_legacy_blob_entries(
            std::iter::once(Err(std::io::Error::other("synthetic iteration failure"))),
            path,
            &Default::default(),
            LegacyAccessReport {
                inherited: 7,
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(error.source().is_some());
        match error {
            DiaryError::LegacyCleanupIncomplete {
                report,
                path: context,
                ..
            } => {
                assert_eq!(report.inherited, 7);
                assert_eq!(context, path);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn legacy_cleanup_preserves_symlink_and_external_target() {
        for link_directory in [false, true] {
            let outside = tempdir().unwrap();
            let target = outside.path().join(format!("{}.bin", "b".repeat(32)));
            std::fs::write(&target, b"outside synthetic data").unwrap();
            assert_cleanup_failure_commits_reopenable_vault(|vault_dir| {
                let attachments = crate::attachment::attachments_dir(vault_dir);
                if link_directory {
                    std::os::unix::fs::symlink(outside.path(), &attachments).unwrap();
                    attachments
                } else {
                    std::fs::create_dir_all(&attachments).unwrap();
                    let link = attachments.join(target.file_name().unwrap());
                    std::os::unix::fs::symlink(&target, &link).unwrap();
                    link
                }
            });
            assert_eq!(std::fs::read(&target).unwrap(), b"outside synthetic data");
        }
    }

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

    fn vault_pqd_str(vault_dir: &Path) -> String {
        vault_dir.join("vault.pqd").to_str().unwrap().to_string()
    }

    fn always_confirm(_: ConfirmationMode) -> Result<bool, DiaryError> {
        Ok(true)
    }

    fn always_reject(_: ConfirmationMode) -> Result<bool, DiaryError> {
        Ok(false)
    }

    fn assert_tampered_vault_rejected(tamper_timestamp: bool) {
        for operation in ["set flag", "rotate", "initialize", "list"] {
            let dir = tempdir().unwrap();
            let (vault_dir, ids) = vault_with_one_entry(&dir, 1);
            let pwd = secret("master-pw");
            if operation == "initialize" {
                let config_path = vault_dir.join("vault.toml");
                let mut config = VaultConfig::from_file(&config_path).unwrap();
                config.legacy.initialized = false;
                config.to_file(&config_path).unwrap();
            } else {
                set_entry_flag(
                    &vault_dir,
                    &pwd,
                    Some(&secret("legacy-code")),
                    &ids[0],
                    LegacyFlag::Inherit,
                    &fast_deriver(),
                )
                .unwrap();
            }

            let vault_path = vault_dir.join("vault.pqd");
            let config_before = std::fs::read(vault_dir.join("vault.toml")).unwrap();
            let mut bytes = std::fs::read(&vault_path).unwrap();
            let mut cursor = std::io::Cursor::new(&bytes);
            let header = crate::vault::reader::read_header(&mut cursor).unwrap();
            let key = kdf::derive_key(b"master-pw", &header.kdf_salt, &fast_params()).unwrap();
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

            let result = match operation {
                "set flag" => set_entry_flag(
                    &vault_dir,
                    &pwd,
                    None,
                    &ids[0],
                    LegacyFlag::Destroy,
                    &fast_deriver(),
                ),
                "rotate" => rotate_legacy_code(
                    &vault_dir,
                    &pwd,
                    &secret("legacy-code"),
                    &secret("new-code"),
                    &fast_deriver(),
                )
                .map(|_| ()),
                "initialize" => initialize_legacy(
                    &vault_dir,
                    &pwd,
                    &secret("legacy-code"),
                    ConfirmationMode::Yn,
                    &fast_deriver(),
                ),
                "list" => list_legacy_status(&vault_dir, &pwd).map(|_| ()),
                _ => unreachable!(),
            };
            assert!(
                matches!(&result, Err(DiaryError::Crypto(message)) if message.contains("vault integrity")),
                "{operation} accepted or misclassified corruption: {result:?}; post-operation MAC valid: {}",
                crate::vault::reader::verify_vault_integrity(&vault_path, &mac_key).is_ok()
            );
            assert_eq!(std::fs::read(&vault_path).unwrap(), bytes, "{operation}");
            assert_eq!(
                std::fs::read(vault_dir.join("vault.toml")).unwrap(),
                config_before,
                "{operation}"
            );
            assert!(!std::fs::read_dir(&vault_dir).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("vault.pqd.tmp.")
            }));
            for sidecar in [
                "vault.pqd.tmp",
                "vault.pqd.tmp.rotate",
                "vault.toml.tmp",
                "vault.toml.tmp.rotate",
                "vault.pqd.bak.rotate",
                "vault.toml.bak.rotate",
            ] {
                assert!(!vault_dir.join(sidecar).exists(), "{operation}: {sidecar}");
            }
        }
    }

    #[test]
    fn legacy_apis_reject_tampered_mac_without_side_effects() {
        assert_tampered_vault_rejected(false);
    }

    #[test]
    fn legacy_apis_reject_tampered_timestamp_without_side_effects() {
        assert_tampered_vault_rejected(true);
    }

    #[test]
    fn set_flag_preserves_attachments_from_authenticated_snapshot() {
        struct ReplacingDeriver {
            path: PathBuf,
            replacement: Vec<u8>,
        }

        impl LegacyKeyDeriver for ReplacingDeriver {
            fn derive(
                &self,
                code: &[u8],
                salt: &[u8; 32],
            ) -> Result<Zeroizing<[u8; 32]>, DiaryError> {
                // set_entry_flag calls this after master-password/MAC verification.
                std::fs::write(&self.path, &self.replacement)?;
                fast_deriver().derive(code, salt)
            }
        }

        let dir = tempdir().unwrap();
        let (vault_dir, ids) = vault_with_one_entry(&dir, 1);
        let pwd = secret("master-pw");
        let source = dir.path().join("original.txt");
        std::fs::write(&source, b"original attachment").unwrap();
        crate::attachment::add_attachment(&vault_dir, &pwd, &ids[0], &source).unwrap();
        let vault_path = vault_dir.join("vault.pqd");
        let (header, entries, mut attachments) =
            crate::vault::reader::read_vault_with_attachments(&vault_path).unwrap();
        assert_eq!(attachments[0].legacy_flag, LegacyFlag::Destroy.to_byte());
        let original = attachments[0].clone();
        attachments[0].legacy_flag = LegacyFlag::Inherit.to_byte();
        let replacement_path = dir.path().join("replacement.pqd");
        crate::vault::writer::write_vault_with_attachments(
            &replacement_path,
            header,
            &entries,
            &attachments,
        )
        .unwrap();
        let deriver = ReplacingDeriver {
            path: vault_path.clone(),
            replacement: std::fs::read(replacement_path).unwrap(),
        };

        set_entry_flag(
            &vault_dir,
            &pwd,
            Some(&secret("legacy-code")),
            &ids[0],
            LegacyFlag::Inherit,
            &deriver,
        )
        .unwrap();

        let (_, _, final_attachments) =
            crate::vault::reader::read_vault_with_attachments(&vault_path).unwrap();
        assert_eq!(final_attachments.len(), 1);
        assert_eq!(final_attachments[0].legacy_flag, original.legacy_flag);
        assert_eq!(final_attachments[0].ciphertext, original.ciphertext);
        assert_eq!(
            final_attachments[0].legacy_key_block,
            original.legacy_key_block
        );
        let (_, final_entries) = read_vault(&vault_path).unwrap();
        assert_eq!(final_entries[0].legacy_flag, LegacyFlag::Inherit.to_byte());
        let mut core = DiaryCore::new(vault_path.to_str().unwrap()).unwrap();
        core.unlock(secret("master-pw")).unwrap();
        assert_eq!(core.list_entries(None).unwrap().len(), 1);
    }

    /// Editing without the legacy key must not leave a stale recovery payload.
    #[test]
    fn inherit_edit_rejected_preserves_vault_and_legacy_recovery() {
        let dir = tempdir().unwrap();
        let vault_dir = setup_vault(&dir, b"password");
        let vault_path = vault_dir.join("vault.pqd");
        let config_path = vault_dir.join("vault.toml");
        let mut core = DiaryCore::new(&vault_pqd_str(&vault_dir)).unwrap();
        core.unlock(secret("password")).unwrap();
        let original = EntryPlaintext {
            title: "original title".into(),
            body: "original body".into(),
            tags: vec!["original".into()],
        };
        let id = core
            .new_entry(&original.title, &original.body, original.tags.clone())
            .unwrap();
        let destroy_id = core
            .new_entry("destroy title", "destroy body", vec![])
            .unwrap();
        let deriver = fast_deriver();
        initialize_legacy(
            &vault_dir,
            &secret("password"),
            &secret("heir-code"),
            ConfirmationMode::Yn,
            &deriver,
        )
        .unwrap();
        set_entry_flag(
            &vault_dir,
            &secret("password"),
            Some(&secret("heir-code")),
            &id,
            LegacyFlag::Inherit,
            &deriver,
        )
        .unwrap();
        let revision = EntryPlaintext {
            title: "latest title".into(),
            body: "latest body".into(),
            tags: vec!["latest".into()],
        };

        // A normal DESTROY entry remains editable in the same legacy-enabled vault.
        core.update_entry(&destroy_id, &revision).unwrap();
        let (destroy_record, destroy_plaintext) = core.get_entry(&destroy_id).unwrap();
        assert_eq!(destroy_plaintext, revision);
        assert_eq!(destroy_record.legacy_flag, LegacyFlag::Destroy.to_byte());
        assert!(destroy_record.legacy_key_block.is_empty());

        let vault_before = std::fs::read(&vault_path).unwrap();
        let config_before = std::fs::read(&config_path).unwrap();
        let error = core.update_entry(&id, &revision).unwrap_err();
        assert!(matches!(error, DiaryError::Entry(_)));
        assert!(error.to_string().contains("INHERIT"));
        assert!(error.to_string().contains("separate entry"));
        assert_eq!(std::fs::read(&vault_path).unwrap(), vault_before);
        assert_eq!(std::fs::read(&config_path).unwrap(), config_before);
        let (record, plaintext) = core.get_entry(&id).unwrap();
        assert_eq!(plaintext, original);
        assert_eq!(record.legacy_flag, LegacyFlag::Inherit.to_byte());
        core.lock();

        // Reopen under the owner password, then perform real legacy recovery.
        core.unlock(secret("password")).unwrap();
        assert_eq!(core.get_entry(&id).unwrap().1, original);
        assert_eq!(core.get_entry(&destroy_id).unwrap().1, revision);
        core.lock();
        execute_legacy_access(&vault_dir, &secret("heir-code"), &deriver, always_confirm).unwrap();
        let mut recovered = DiaryCore::new(&vault_pqd_str(&vault_dir)).unwrap();
        recovered.unlock(secret("heir-code")).unwrap();
        assert_eq!(recovered.get_entry(&id).unwrap().1, original);
        assert!(recovered.get_entry(&destroy_id).is_err());
    }

    // ── LegacyKeyDeriver / Argon2LegacyDeriver ────────────────────────────

    /// TC-S12-002-01: same code+salt → identical K_legacy.
    #[test]
    fn tc_s12_002_01_argon2_deriver_deterministic() {
        let d = fast_deriver();
        let salt = [0x11u8; 32];
        let k1 = d.derive(b"code", &salt).unwrap();
        let k2 = d.derive(b"code", &salt).unwrap();
        assert_eq!(*k1, *k2);
    }

    /// TC-S12-002-02: different codes → different keys.
    #[test]
    fn tc_s12_002_02_argon2_deriver_different_codes() {
        let d = fast_deriver();
        let salt = [0x22u8; 32];
        let k1 = d.derive(b"alpha", &salt).unwrap();
        let k2 = d.derive(b"beta", &salt).unwrap();
        assert_ne!(*k1, *k2);
    }

    /// TC-S12-002-03: LegacyFlag::from_byte rejects unknown bytes.
    #[test]
    fn tc_s12_002_03_legacy_flag_from_byte() {
        assert_eq!(LegacyFlag::from_byte(0x00).unwrap(), LegacyFlag::Destroy);
        assert_eq!(LegacyFlag::from_byte(0x01).unwrap(), LegacyFlag::Inherit);
        assert!(matches!(
            LegacyFlag::from_byte(0xFF),
            Err(DiaryError::Vault(_))
        ));
    }

    /// TC-S12-002-04: LegacyFlag::to_byte round-trips.
    #[test]
    fn tc_s12_002_04_legacy_flag_to_byte() {
        assert_eq!(LegacyFlag::Destroy.to_byte(), 0x00);
        assert_eq!(LegacyFlag::Inherit.to_byte(), 0x01);
    }

    // ── initialize_legacy ─────────────────────────────────────────────────

    /// TC-S12-003-01: initialize_legacy stamps vault.toml with initialized=true
    /// and a verification token.
    #[test]
    fn tc_s12_003_01_initialize_legacy_writes_toml() {
        let dir = tempdir().unwrap();
        let vault_dir = setup_vault(&dir, b"master-pw");
        initialize_legacy(
            &vault_dir,
            &secret("master-pw"),
            &secret("legacy-code"),
            ConfirmationMode::Timer30,
            &fast_deriver(),
        )
        .unwrap();
        let cfg = VaultConfig::from_file(&vault_dir.join("vault.toml")).unwrap();
        assert!(cfg.legacy.initialized);
        assert_eq!(cfg.legacy.destroy_confirmation, ConfirmationMode::Timer30);
        assert!(cfg.legacy.verification_iv_b64.is_some());
        assert!(cfg.legacy.verification_ct_b64.is_some());
    }

    /// TC-S12-003-02: initialize_legacy twice → error.
    #[test]
    fn tc_s12_003_02_initialize_legacy_idempotent_error() {
        let dir = tempdir().unwrap();
        let vault_dir = setup_vault(&dir, b"master-pw");
        initialize_legacy(
            &vault_dir,
            &secret("master-pw"),
            &secret("legacy-code"),
            ConfirmationMode::Yn,
            &fast_deriver(),
        )
        .unwrap();
        let result = initialize_legacy(
            &vault_dir,
            &secret("master-pw"),
            &secret("legacy-code"),
            ConfirmationMode::Yn,
            &fast_deriver(),
        );
        assert!(matches!(result, Err(DiaryError::Vault(_))));
    }

    /// TC-S12-003-03: wrong master password → DiaryError::Crypto.
    #[test]
    fn tc_s12_003_03_initialize_legacy_wrong_master() {
        let dir = tempdir().unwrap();
        let vault_dir = setup_vault(&dir, b"master-pw");
        let result = initialize_legacy(
            &vault_dir,
            &secret("WRONG"),
            &secret("legacy-code"),
            ConfirmationMode::Timer30,
            &fast_deriver(),
        );
        assert!(matches!(result, Err(DiaryError::Crypto(_))));
    }

    /// TC-S12-003-04: empty legacy code → DiaryError::Password.
    #[test]
    fn tc_s12_003_04_initialize_legacy_empty_code() {
        let dir = tempdir().unwrap();
        let vault_dir = setup_vault(&dir, b"master-pw");
        let result = initialize_legacy(
            &vault_dir,
            &secret("master-pw"),
            &secret(""),
            ConfirmationMode::Timer30,
            &fast_deriver(),
        );
        assert!(matches!(result, Err(DiaryError::Password(_))));
    }

    // ── set_entry_flag ────────────────────────────────────────────────────

    /// Helper: create a vault with one entry and initialize legacy. Returns
    /// (vault_dir, entry_id_hex).
    fn vault_with_one_entry(
        dir: &tempfile::TempDir,
        n_entries: usize,
    ) -> (std::path::PathBuf, Vec<String>) {
        let vault_dir = setup_vault(dir, b"master-pw");
        let vault_pqd = vault_pqd_str(&vault_dir);
        let mut core = DiaryCore::new(&vault_pqd).unwrap();
        core.unlock(secret("master-pw")).unwrap();
        let mut ids = Vec::new();
        for i in 0..n_entries {
            let id = core
                .new_entry(&format!("title-{i}"), &format!("body-{i}"), vec![])
                .unwrap();
            ids.push(id);
        }
        drop(core);
        initialize_legacy(
            &vault_dir,
            &secret("master-pw"),
            &secret("legacy-code"),
            ConfirmationMode::Yn,
            &fast_deriver(),
        )
        .unwrap();
        (vault_dir, ids)
    }

    /// TC-S12-004-01: set --inherit then --destroy round-trips the legacy block.
    #[test]
    fn tc_s12_004_01_set_inherit_then_destroy() {
        let dir = tempdir().unwrap();
        let (vault_dir, ids) = vault_with_one_entry(&dir, 1);
        let entry_id = &ids[0];

        set_entry_flag(
            &vault_dir,
            &secret("master-pw"),
            Some(&secret("legacy-code")),
            &entry_id[..8],
            LegacyFlag::Inherit,
            &fast_deriver(),
        )
        .unwrap();
        let statuses = list_legacy_status(&vault_dir, &secret("master-pw")).unwrap();
        assert_eq!(statuses[0].flag, LegacyFlag::Inherit);

        set_entry_flag(
            &vault_dir,
            &secret("master-pw"),
            None,
            &entry_id[..8],
            LegacyFlag::Destroy,
            &fast_deriver(),
        )
        .unwrap();
        let statuses = list_legacy_status(&vault_dir, &secret("master-pw")).unwrap();
        assert_eq!(statuses[0].flag, LegacyFlag::Destroy);
    }

    /// TC-S12-004-02: --inherit without legacy code → InvalidArgument.
    #[test]
    fn tc_s12_004_02_inherit_requires_legacy_code() {
        let dir = tempdir().unwrap();
        let (vault_dir, ids) = vault_with_one_entry(&dir, 1);
        let result = set_entry_flag(
            &vault_dir,
            &secret("master-pw"),
            None,
            &ids[0][..8],
            LegacyFlag::Inherit,
            &fast_deriver(),
        );
        assert!(matches!(result, Err(DiaryError::InvalidArgument(_))));
    }

    /// TC-S12-004-03: unknown prefix → Entry error.
    #[test]
    fn tc_s12_004_03_unknown_prefix() {
        let dir = tempdir().unwrap();
        let (vault_dir, _ids) = vault_with_one_entry(&dir, 1);
        let result = set_entry_flag(
            &vault_dir,
            &secret("master-pw"),
            None,
            "deadbeef",
            LegacyFlag::Destroy,
            &fast_deriver(),
        );
        assert!(matches!(result, Err(DiaryError::Entry(_))));
    }

    /// TC-S12-004-04: wrong legacy code → Crypto error.
    #[test]
    fn tc_s12_004_04_wrong_legacy_code() {
        let dir = tempdir().unwrap();
        let (vault_dir, ids) = vault_with_one_entry(&dir, 1);
        let result = set_entry_flag(
            &vault_dir,
            &secret("master-pw"),
            Some(&secret("WRONG-CODE")),
            &ids[0][..8],
            LegacyFlag::Inherit,
            &fast_deriver(),
        );
        assert!(matches!(result, Err(DiaryError::Crypto(_))));
    }

    /// TC-S12-004-05: set on uninitialized vault → Vault error.
    #[test]
    fn tc_s12_004_05_set_before_init() {
        let dir = tempdir().unwrap();
        let vault_dir = setup_vault(&dir, b"master-pw");
        // Create an entry without calling initialize_legacy.
        let mut core = DiaryCore::new(&vault_pqd_str(&vault_dir)).unwrap();
        core.unlock(secret("master-pw")).unwrap();
        let id = core.new_entry("t", "b", vec![]).unwrap();
        drop(core);

        let result = set_entry_flag(
            &vault_dir,
            &secret("master-pw"),
            None,
            &id[..8],
            LegacyFlag::Destroy,
            &fast_deriver(),
        );
        assert!(matches!(result, Err(DiaryError::Vault(_))));
    }

    // ── list_legacy_status ────────────────────────────────────────────────

    /// TC-S12-005-01: list returns one row per entry with correct flags.
    #[test]
    fn tc_s12_005_01_list_returns_all_entries() {
        let dir = tempdir().unwrap();
        let (vault_dir, ids) = vault_with_one_entry(&dir, 3);
        // Mark the first INHERIT, leave the rest at DESTROY default.
        set_entry_flag(
            &vault_dir,
            &secret("master-pw"),
            Some(&secret("legacy-code")),
            &ids[0][..8],
            LegacyFlag::Inherit,
            &fast_deriver(),
        )
        .unwrap();

        let mut statuses = list_legacy_status(&vault_dir, &secret("master-pw")).unwrap();
        assert_eq!(statuses.len(), 3);
        statuses.sort_by(|a, b| a.title.cmp(&b.title));
        assert_eq!(statuses[0].title, "title-0");
        assert_eq!(statuses[0].flag, LegacyFlag::Inherit);
        assert_eq!(statuses[1].flag, LegacyFlag::Destroy);
        assert_eq!(statuses[2].flag, LegacyFlag::Destroy);
    }

    /// TC-S12-005-02: empty vault yields empty Vec.
    #[test]
    fn tc_s12_005_02_list_empty() {
        let dir = tempdir().unwrap();
        let vault_dir = setup_vault(&dir, b"master-pw");
        initialize_legacy(
            &vault_dir,
            &secret("master-pw"),
            &secret("legacy-code"),
            ConfirmationMode::Yn,
            &fast_deriver(),
        )
        .unwrap();
        let statuses = list_legacy_status(&vault_dir, &secret("master-pw")).unwrap();
        assert!(statuses.is_empty());
    }

    // ── rotate_legacy_code ────────────────────────────────────────────────

    /// TC-S12-006-01: rotate re-encrypts every INHERIT block; old code stops
    /// working and the new code unlocks the same content.
    #[test]
    fn tc_s12_006_01_rotate_legacy_code_round_trip() {
        let dir = tempdir().unwrap();
        let (vault_dir, ids) = vault_with_one_entry(&dir, 2);
        set_entry_flag(
            &vault_dir,
            &secret("master-pw"),
            Some(&secret("legacy-code")),
            &ids[0][..8],
            LegacyFlag::Inherit,
            &fast_deriver(),
        )
        .unwrap();

        let rotated = rotate_legacy_code(
            &vault_dir,
            &secret("master-pw"),
            &secret("legacy-code"),
            &secret("rotated-code"),
            &fast_deriver(),
        )
        .unwrap();
        assert_eq!(rotated, 1);
        assert!(!vault_dir.join("vault.pqd.bak.rotate").exists());
        assert!(!vault_dir.join("vault.toml.bak.rotate").exists());

        // execute_legacy_access must accept the new code, not the old one.
        let bad = execute_legacy_access(
            &vault_dir,
            &secret("legacy-code"),
            &fast_deriver(),
            always_confirm,
        );
        assert!(matches!(bad, Err(DiaryError::Crypto(_))));
    }

    /// TC-S12-006-02: rotate before init → Vault error.
    #[test]
    fn tc_s12_006_02_rotate_before_init() {
        let dir = tempdir().unwrap();
        let vault_dir = setup_vault(&dir, b"master-pw");
        let result = rotate_legacy_code(
            &vault_dir,
            &secret("master-pw"),
            &secret("legacy-code"),
            &secret("new-code"),
            &fast_deriver(),
        );
        assert!(matches!(result, Err(DiaryError::Vault(_))));
    }

    /// TC-S12-006-03: rotate with wrong old code → Crypto error.
    #[test]
    fn tc_s12_006_03_rotate_wrong_old_code() {
        let dir = tempdir().unwrap();
        let (vault_dir, _ids) = vault_with_one_entry(&dir, 1);
        let result = rotate_legacy_code(
            &vault_dir,
            &secret("master-pw"),
            &secret("WRONG-OLD"),
            &secret("new-code"),
            &fast_deriver(),
        );
        assert!(matches!(result, Err(DiaryError::Crypto(_))));
    }

    /// TC-S12-006-04: rotate with empty new code → Password error.
    #[test]
    fn tc_s12_006_04_rotate_empty_new() {
        let dir = tempdir().unwrap();
        let (vault_dir, _ids) = vault_with_one_entry(&dir, 1);
        let result = rotate_legacy_code(
            &vault_dir,
            &secret("master-pw"),
            &secret("legacy-code"),
            &secret(""),
            &fast_deriver(),
        );
        assert!(matches!(result, Err(DiaryError::Password(_))));
    }

    // ── execute_legacy_access ─────────────────────────────────────────────

    /// TC-S12-007-01: legacy-access preserves INHERIT bodies, drops DESTROY,
    /// and resets the [legacy] section.
    #[test]
    fn tc_s12_007_01_execute_preserves_inherit_drops_destroy() {
        let dir = tempdir().unwrap();
        let (vault_dir, ids) = vault_with_one_entry(&dir, 3);
        // title-0 INHERIT, title-1 INHERIT, title-2 DESTROY (default).
        set_entry_flag(
            &vault_dir,
            &secret("master-pw"),
            Some(&secret("legacy-code")),
            &ids[0][..8],
            LegacyFlag::Inherit,
            &fast_deriver(),
        )
        .unwrap();
        set_entry_flag(
            &vault_dir,
            &secret("master-pw"),
            Some(&secret("legacy-code")),
            &ids[1][..8],
            LegacyFlag::Inherit,
            &fast_deriver(),
        )
        .unwrap();

        let report = execute_legacy_access(
            &vault_dir,
            &secret("legacy-code"),
            &fast_deriver(),
            always_confirm,
        )
        .unwrap();
        assert_eq!(report.inherited, 2);
        assert_eq!(report.destroyed, 1);

        // The heir unlocks the new vault with the legacy code.
        let mut core = DiaryCore::new(&vault_pqd_str(&vault_dir)).unwrap();
        core.unlock(secret("legacy-code")).unwrap();
        let mut entries = core.list_entries(None).unwrap();
        entries.sort_by(|a, b| a.title.cmp(&b.title));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].title, "title-0");
        assert_eq!(entries[1].title, "title-1");

        // Old master password no longer works against the new vault.
        let mut core_bad = DiaryCore::new(&vault_pqd_str(&vault_dir)).unwrap();
        assert!(core_bad.unlock(secret("master-pw")).is_err());

        // vault.toml [legacy] is reset for the heir.
        let cfg = VaultConfig::from_file(&vault_dir.join("vault.toml")).unwrap();
        assert!(!cfg.legacy.initialized);
        assert!(!vault_dir.join("vault.pqd.bak.legacy").exists());
        assert!(!vault_dir.join("vault.toml.bak.legacy").exists());
    }

    /// TC-S12-007-02: user cancellation leaves the vault unchanged.
    #[test]
    fn tc_s12_007_02_user_cancel_keeps_vault() {
        let dir = tempdir().unwrap();
        let (vault_dir, ids) = vault_with_one_entry(&dir, 1);
        set_entry_flag(
            &vault_dir,
            &secret("master-pw"),
            Some(&secret("legacy-code")),
            &ids[0][..8],
            LegacyFlag::Inherit,
            &fast_deriver(),
        )
        .unwrap();
        let bytes_before = std::fs::read(vault_dir.join("vault.pqd")).unwrap();

        let result = execute_legacy_access(
            &vault_dir,
            &secret("legacy-code"),
            &fast_deriver(),
            always_reject,
        );
        assert!(matches!(result, Err(DiaryError::InvalidArgument(_))));

        let bytes_after = std::fs::read(vault_dir.join("vault.pqd")).unwrap();
        assert_eq!(bytes_before, bytes_after);
        // Original master password still works.
        let mut core = DiaryCore::new(&vault_pqd_str(&vault_dir)).unwrap();
        core.unlock(secret("master-pw")).unwrap();
    }

    /// TC-S12-007-03: wrong legacy code → Crypto error, vault unchanged.
    #[test]
    fn tc_s12_007_03_wrong_legacy_code() {
        let dir = tempdir().unwrap();
        let (vault_dir, _ids) = vault_with_one_entry(&dir, 1);
        let bytes_before = std::fs::read(vault_dir.join("vault.pqd")).unwrap();
        let result = execute_legacy_access(
            &vault_dir,
            &secret("WRONG-CODE"),
            &fast_deriver(),
            always_confirm,
        );
        assert!(matches!(result, Err(DiaryError::Crypto(_))));
        let bytes_after = std::fs::read(vault_dir.join("vault.pqd")).unwrap();
        assert_eq!(bytes_before, bytes_after);
    }

    /// TC-S12-007-04: legacy-access on uninitialized vault → Vault error.
    #[test]
    fn tc_s12_007_04_execute_before_init() {
        let dir = tempdir().unwrap();
        let vault_dir = setup_vault(&dir, b"master-pw");
        let result = execute_legacy_access(
            &vault_dir,
            &secret("legacy-code"),
            &fast_deriver(),
            always_confirm,
        );
        assert!(matches!(result, Err(DiaryError::Vault(_))));
    }

    /// TC-S12-007-05: after committing legacy-access, the renamed original is
    /// zeroized in full, including hard links, while the heir's vault is intact.
    #[test]
    fn tc_s12_007_05_committed_backup_zeroizes_original_hardlink() {
        let dir = tempdir().unwrap();
        let (vault_dir, ids) = vault_with_one_entry(&dir, 2);
        set_entry_flag(
            &vault_dir,
            &secret("master-pw"),
            Some(&secret("legacy-code")),
            &ids[0][..8],
            LegacyFlag::Inherit,
            &fast_deriver(),
        )
        .unwrap();

        let vault_pqd = vault_dir.join("vault.pqd");
        let old_hardlink = dir.path().join("original-vault.pqd");
        std::fs::hard_link(&vault_pqd, &old_hardlink).unwrap();
        let original_len = std::fs::metadata(&old_hardlink).unwrap().len();
        assert!(original_len > 0);

        let report = execute_legacy_access(
            &vault_dir,
            &secret("legacy-code"),
            &fast_deriver(),
            always_confirm,
        )
        .unwrap();
        assert_eq!(report.inherited, 1);
        assert_eq!(report.destroyed, 1);

        let wiped = std::fs::read(&old_hardlink).unwrap();
        assert_eq!(wiped.len() as u64, original_len);
        assert!(wiped.iter().all(|&b| b == 0));
        assert!(!vault_dir.join("vault.pqd.bak.legacy").exists());
        assert!(!vault_dir.join("vault.toml.bak.legacy").exists());

        let mut heir = DiaryCore::new(&vault_pqd_str(&vault_dir)).unwrap();
        heir.unlock(secret("legacy-code")).unwrap();
        assert_eq!(heir.list_entries(None).unwrap().len(), 1);
        let (_, inherited) = heir.get_entry(&ids[0]).unwrap();
        assert_eq!(inherited.title, "title-0");
        assert!(heir.get_entry(&ids[1]).is_err());
    }

    /// TC-S12-007-06: if the reset vault.toml sidecar cannot be written, the
    /// original vault is left untouched because destructive zeroize has not run.
    #[test]
    fn tc_s12_007_06_toml_sidecar_failure_keeps_vault() {
        let dir = tempdir().unwrap();
        let (vault_dir, ids) = vault_with_one_entry(&dir, 1);
        set_entry_flag(
            &vault_dir,
            &secret("master-pw"),
            Some(&secret("legacy-code")),
            &ids[0][..8],
            LegacyFlag::Inherit,
            &fast_deriver(),
        )
        .unwrap();
        let bytes_before = std::fs::read(vault_dir.join("vault.pqd")).unwrap();

        let blocked_toml_tmp = vault_dir.join("vault.toml.tmp.legacy");
        std::fs::create_dir(&blocked_toml_tmp).unwrap();
        let result = execute_legacy_access(
            &vault_dir,
            &secret("legacy-code"),
            &fast_deriver(),
            always_confirm,
        );
        assert!(matches!(result, Err(DiaryError::Io(_))));

        let bytes_after = std::fs::read(vault_dir.join("vault.pqd")).unwrap();
        assert_eq!(bytes_before, bytes_after);
        assert!(!vault_dir.join("vault.pqd.tmp.legacy").exists());
    }

    fn assert_backup_failure_preserves_original(blocked_backup: &str) {
        let dir = tempdir().unwrap();
        let (vault_dir, ids) = vault_with_one_entry(&dir, 2);
        set_entry_flag(
            &vault_dir,
            &secret("master-pw"),
            Some(&secret("legacy-code")),
            &ids[0][..8],
            LegacyFlag::Inherit,
            &fast_deriver(),
        )
        .unwrap();

        // Keep one DESTROY entry: its ciphertext must remain recoverable if
        // either backup rename fails, including after the vault was moved.
        let vault_before = std::fs::read(vault_dir.join("vault.pqd")).unwrap();
        let config_before = std::fs::read(vault_dir.join("vault.toml")).unwrap();
        std::fs::create_dir(vault_dir.join(blocked_backup)).unwrap();

        let result = execute_legacy_access(
            &vault_dir,
            &secret("legacy-code"),
            &fast_deriver(),
            always_confirm,
        );
        assert!(matches!(result, Err(DiaryError::Io(_))));
        assert!(
            vault_before == std::fs::read(vault_dir.join("vault.pqd")).unwrap(),
            "failed backup rename must leave the original vault byte-for-byte intact"
        );
        assert_eq!(
            config_before,
            std::fs::read(vault_dir.join("vault.toml")).unwrap()
        );
        assert!(!vault_dir.join("vault.pqd.tmp.legacy").exists());
        assert!(!vault_dir.join("vault.toml.tmp.legacy").exists());

        let mut core = DiaryCore::new(&vault_pqd_str(&vault_dir)).unwrap();
        core.unlock(secret("master-pw")).unwrap();
        assert_eq!(core.list_entries(None).unwrap().len(), 2);
        for id in ids {
            core.get_entry(&id).unwrap();
        }
    }

    /// A failed first backup rename must not destroy the original records.
    #[test]
    fn tc_s12_007_08_vault_backup_failure_keeps_original() {
        assert_backup_failure_preserves_original("vault.pqd.bak.legacy");
    }

    /// A failed second backup rename must restore the untouched vault backup.
    #[test]
    fn tc_s12_007_09_toml_backup_failure_keeps_original() {
        assert_backup_failure_preserves_original("vault.toml.bak.legacy");
    }

    /// TC-S12-007-07: non-entry records are dropped during legacy-access but
    /// not counted as destroyed diary entries.
    #[test]
    fn tc_s12_007_07_templates_dropped_not_counted_as_destroyed_entries() {
        let dir = tempdir().unwrap();
        let vault_dir = setup_vault(&dir, b"master-pw");
        let vault_pqd = vault_pqd_str(&vault_dir);
        let mut core = DiaryCore::new(&vault_pqd).unwrap();
        core.unlock(secret("master-pw")).unwrap();
        core.new_entry("entry", "body", vec![]).unwrap();
        core.new_template("daily", "template body").unwrap();
        drop(core);

        initialize_legacy(
            &vault_dir,
            &secret("master-pw"),
            &secret("legacy-code"),
            ConfirmationMode::Yn,
            &fast_deriver(),
        )
        .unwrap();

        let report = execute_legacy_access(
            &vault_dir,
            &secret("legacy-code"),
            &fast_deriver(),
            always_confirm,
        )
        .unwrap();
        assert_eq!(report.inherited, 0);
        assert_eq!(report.destroyed, 1);

        let mut heir = DiaryCore::new(&vault_pqd).unwrap();
        heir.unlock(secret("legacy-code")).unwrap();
        assert!(heir.list_entries(None).unwrap().is_empty());
        assert!(heir.list_templates().unwrap().is_empty());
    }

    fn assert_invalid_inherit_attachment_preserves_vault(case: &str) {
        let dir = tempdir().unwrap();
        let (vault_dir, ids) = vault_with_one_entry(&dir, 1);
        let source = dir.path().join("keep.txt");
        std::fs::write(&source, b"recoverable attachment").unwrap();
        crate::attachment::add_attachment(&vault_dir, &secret("master-pw"), &ids[0], &source)
            .unwrap();
        set_entry_flag(
            &vault_dir,
            &secret("master-pw"),
            Some(&secret("legacy-code")),
            &ids[0],
            LegacyFlag::Inherit,
            &fast_deriver(),
        )
        .unwrap();
        crate::attachment::set_attachment_legacy_flag(
            &vault_dir,
            &secret("master-pw"),
            Some(&secret("legacy-code")),
            &ids[0],
            "keep.txt",
            LegacyFlag::Inherit,
            &fast_deriver(),
        )
        .unwrap();

        let metas =
            crate::attachment::list_attachments(&vault_dir, &secret("master-pw"), Some(&ids[0]))
                .unwrap();
        let blob_path = crate::attachment::blob_path(&vault_dir, &metas[0].blob_uuid);
        let vault_path = vault_dir.join("vault.pqd");
        let config_path = vault_dir.join("vault.toml");
        let (header, entries, mut attachments) =
            crate::vault::reader::read_vault_with_attachments(&vault_path).unwrap();
        assert_eq!(attachments.len(), 1);
        let legacy_key = fast_deriver()
            .derive(b"legacy-code", &header.legacy_salt)
            .unwrap();
        match case {
            "short nonce" => {
                attachments[0].legacy_key_block = vec![0; aead::NONCE_SIZE - 1];
            }
            "invalid tag" => {
                attachments[0].legacy_key_block[aead::NONCE_SIZE] ^= 1;
            }
            "invalid plaintext" => {
                attachments[0].legacy_key_block =
                    encrypt_legacy_block(&legacy_key, b"invalid attachment payload").unwrap();
            }
            _ => panic!("unknown corruption case"),
        }
        let expected_error =
            crate::attachment::decrypt_attachment_legacy_block(&attachments[0], &legacy_key)
                .expect_err("fixture must fail attachment legacy-block validation");
        let master_key = kdf::derive_key(b"master-pw", &header.kdf_salt, &fast_params()).unwrap();
        let mac_key = crate::crypto::derive_vault_mac_key(master_key.as_ref()).unwrap();
        // Keep the whole-vault MAC valid: only legacy access to this attachment
        // is broken, while the master password can still recover its contents.
        crate::vault::writer::write_vault_with_attachments_authenticated(
            &vault_path,
            header,
            &entries,
            &attachments,
            &mac_key,
        )
        .unwrap();
        crate::vault::reader::verify_vault_integrity(&vault_path, &mac_key).unwrap();
        let vault_before = std::fs::read(&vault_path).unwrap();
        let config_before = std::fs::read(&config_path).unwrap();
        let blob_before = std::fs::read(&blob_path).unwrap();

        let result = execute_legacy_access(
            &vault_dir,
            &secret("legacy-code"),
            &fast_deriver(),
            always_confirm,
        );
        let error = result.expect_err("invalid INHERIT attachment must abort before commit");
        assert_eq!(
            std::mem::discriminant(&error),
            std::mem::discriminant(&expected_error),
            "{case}: must preserve the original error category"
        );
        assert_eq!(error.to_string(), expected_error.to_string(), "{case}");
        assert_eq!(std::fs::read(&vault_path).unwrap(), vault_before, "{case}");
        assert_eq!(
            std::fs::read(&config_path).unwrap(),
            config_before,
            "{case}"
        );
        assert_eq!(std::fs::read(&blob_path).unwrap(), blob_before, "{case}");
        crate::vault::reader::verify_vault_integrity(&vault_path, &mac_key).unwrap();
        for sidecar in [
            "vault.pqd.tmp.legacy",
            "vault.toml.tmp.legacy",
            "vault.pqd.bak.legacy",
            "vault.toml.bak.legacy",
        ] {
            assert!(!vault_dir.join(sidecar).exists(), "{case}: {sidecar}");
        }

        let restored = dir.path().join("restored.txt");
        crate::attachment::extract_attachment(
            &vault_dir,
            &secret("master-pw"),
            &ids[0],
            "keep.txt",
            &restored,
        )
        .unwrap();
        assert_eq!(std::fs::read(restored).unwrap(), b"recoverable attachment");
    }

    #[test]
    fn legacy_access_rejects_short_inherit_attachment_block_without_mutation() {
        assert_invalid_inherit_attachment_preserves_vault("short nonce");
    }

    #[test]
    fn legacy_access_rejects_invalid_inherit_attachment_tag_without_mutation() {
        assert_invalid_inherit_attachment_preserves_vault("invalid tag");
    }

    #[test]
    fn legacy_access_rejects_invalid_inherit_attachment_payload_without_mutation() {
        assert_invalid_inherit_attachment_preserves_vault("invalid plaintext");
    }

    /// TC-S13-LEGACY-01: legacy-access carries INHERIT attachments only when
    /// their parent entry is also INHERIT, and destroys cascaded blobs.
    #[test]
    fn tc_s13_legacy_access_attachment_inherit_and_parent_cascade() {
        let dir = tempdir().unwrap();
        let (vault_dir, ids) = vault_with_one_entry(&dir, 2);

        let keep_src = dir.path().join("keep.txt");
        let drop_src = dir.path().join("drop.txt");
        std::fs::write(&keep_src, b"keep payload").unwrap();
        std::fs::write(&drop_src, b"drop payload").unwrap();

        crate::attachment::add_attachment(
            &vault_dir,
            &secret("master-pw"),
            &ids[0][..8],
            &keep_src,
        )
        .unwrap();
        crate::attachment::add_attachment(
            &vault_dir,
            &secret("master-pw"),
            &ids[1][..8],
            &drop_src,
        )
        .unwrap();

        set_entry_flag(
            &vault_dir,
            &secret("master-pw"),
            Some(&secret("legacy-code")),
            &ids[0][..8],
            LegacyFlag::Inherit,
            &fast_deriver(),
        )
        .unwrap();
        crate::attachment::set_attachment_legacy_flag(
            &vault_dir,
            &secret("master-pw"),
            Some(&secret("legacy-code")),
            &ids[0][..8],
            "keep.txt",
            LegacyFlag::Inherit,
            &fast_deriver(),
        )
        .unwrap();
        crate::attachment::set_attachment_legacy_flag(
            &vault_dir,
            &secret("master-pw"),
            Some(&secret("legacy-code")),
            &ids[1][..8],
            "drop.txt",
            LegacyFlag::Inherit,
            &fast_deriver(),
        )
        .unwrap();

        let dropped = crate::attachment::list_attachments(
            &vault_dir,
            &secret("master-pw"),
            Some(&ids[1][..8]),
        )
        .unwrap();
        let dropped_blob = crate::attachment::blob_path(&vault_dir, &dropped[0].blob_uuid);

        let report = execute_legacy_access(
            &vault_dir,
            &secret("legacy-code"),
            &fast_deriver(),
            always_confirm,
        )
        .unwrap();
        assert_eq!(report.inherited, 1);
        assert_eq!(report.destroyed, 1);
        assert_eq!(report.inherited_attachments, 1);
        assert_eq!(report.destroyed_attachments, 1);
        assert!(
            !dropped_blob.exists(),
            "attachment whose parent entry is DESTROY must be physically removed"
        );

        let metas = crate::attachment::list_attachments(
            &vault_dir,
            &secret("legacy-code"),
            Some(&ids[0][..8]),
        )
        .unwrap();
        assert_eq!(metas.len(), 1);
        assert_eq!(metas[0].filename, "keep.txt");

        let restored = dir.path().join("restored.txt");
        crate::attachment::extract_attachment(
            &vault_dir,
            &secret("legacy-code"),
            &ids[0][..8],
            "keep.txt",
            &restored,
        )
        .unwrap();
        assert_eq!(std::fs::read(restored).unwrap(), b"keep payload");
    }
}
