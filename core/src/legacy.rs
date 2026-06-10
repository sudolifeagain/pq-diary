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
    generate_verification_token, EntryRecord, VaultHeader, HEADER_SIZE, RECORD_TYPE_ATTACHMENT,
    RECORD_TYPE_ENTRY, RECORD_TYPE_TEMPLATE, SCHEMA_VERSION,
};
use crate::vault::reader::read_vault;
use crate::vault::writer::write_vault_authenticated;

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
    /// Attachments destroyed during legacy-access (S13). Blob files are
    /// only zeroize-deleted once their reference count drops to zero.
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

    let (header, _entries) = read_vault(&vault_pqd)?;

    // 1) verify the master password against the vault's verification token —
    //    refuse to initialize on a vault the caller cannot already unlock.
    let params = argon2_params_from(&config);
    verify_master(&header, master_pwd, &params)?;

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

    let (header, mut entries) = read_vault(&vault_pqd)?;
    let params = argon2_params_from(&config);
    let k_master = verify_master(&header, master_pwd, &params)?;

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
    write_vault_authenticated(&vault_pqd, header, &entries, &mac_key)?;
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

    let (header, entries) = read_vault(&vault_pqd)?;
    let params = argon2_params_from(&config);
    let k_master = verify_master(&header, master_pwd, &params)?;

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

    let (header, mut entries, mut attachments) =
        crate::vault::reader::read_vault_with_attachments(&vault_pqd)?;
    let params = argon2_params_from(&config);
    let _k_master = verify_master(&header, master_pwd, &params)?;

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

    let vault_tmp = sidecar_path(&vault_pqd, ".tmp.rotate")?;
    let toml_tmp = sidecar_path(&vault_toml, ".tmp.rotate")?;
    cleanup_sensitive_file(&vault_tmp);
    cleanup_sensitive_file(&writer_tmp_path(&vault_tmp));
    cleanup_sensitive_file(&toml_tmp);

    // Master ciphertext is unchanged (only legacy_key_blocks rotate), so the
    // integrity MAC keys on the existing master key.
    let mac_key = crate::crypto::derive_vault_mac_key(&_k_master)?;
    if let Err(e) = crate::vault::writer::write_vault_with_attachments_authenticated(
        &vault_tmp,
        header,
        &entries,
        &attachments,
        &mac_key,
    ) {
        cleanup_sensitive_file(&vault_tmp);
        cleanup_sensitive_file(&writer_tmp_path(&vault_tmp));
        return Err(e);
    }
    if let Err(e) = write_vault_toml_sidecar(&toml_tmp, &config) {
        cleanup_sensitive_file(&vault_tmp);
        cleanup_sensitive_file(&toml_tmp);
        return Err(e);
    }
    replace_vault_and_toml(
        &vault_pqd,
        &vault_tmp,
        &vault_toml,
        &toml_tmp,
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
        let lpt = match crate::attachment::decrypt_attachment_legacy_block(record, &k_legacy) {
            Ok(v) => v,
            Err(_) => {
                // Corrupted legacy block on an INHERIT record — treat as destroy.
                destroyed_attachments += 1;
                continue;
            }
        };
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

    let vault_tmp = sidecar_path(&vault_pqd, ".tmp.legacy")?;
    let toml_tmp = sidecar_path(&vault_toml, ".tmp.legacy")?;
    cleanup_sensitive_file(&vault_tmp);
    cleanup_sensitive_file(&writer_tmp_path(&vault_tmp));
    cleanup_sensitive_file(&toml_tmp);

    // The heir's vault is encrypted under K_legacy (now its master key), so the
    // integrity MAC must key on K_legacy for a later `unlock(legacy_code)` to verify.
    let mac_key = crate::crypto::derive_vault_mac_key(&k_legacy)?;
    if let Err(e) = crate::vault::writer::write_vault_with_attachments_authenticated(
        &vault_tmp,
        new_header,
        &new_entries,
        &new_attachments,
        &mac_key,
    ) {
        cleanup_sensitive_file(&vault_tmp);
        cleanup_sensitive_file(&writer_tmp_path(&vault_tmp));
        return Err(e);
    }
    if let Err(e) = write_vault_toml_sidecar(&toml_tmp, &config) {
        cleanup_sensitive_file(&vault_tmp);
        cleanup_sensitive_file(&toml_tmp);
        return Err(e);
    }

    let keep_record_uuids: std::collections::HashSet<[u8; 16]> = new_entries
        .iter()
        .map(|r| r.uuid)
        .chain(new_attachments.iter().map(|r| r.uuid))
        .collect();
    zeroize_non_inherited_record_ciphertexts(&vault_pqd, &old_header, &keep_record_uuids)?;
    replace_vault_and_toml(
        &vault_pqd,
        &vault_tmp,
        &vault_toml,
        &toml_tmp,
        ".bak.legacy",
    )?;

    // After the atomic swap, sweep .attachments/ for blobs that no surviving
    // INHERIT record refers to. We collect on-disk filenames and prune the
    // ones not in `surviving_blobs`. This zeroizes-and-deletes orphaned
    // bodies regardless of whether they were originally INHERIT (parent
    // entry destroyed) or DESTROY records — matching REQ-302 and REQ-503.
    let attachments_dir = crate::attachment::attachments_dir(vault_dir);
    if attachments_dir.is_dir() {
        if let Ok(read_dir) = std::fs::read_dir(&attachments_dir) {
            for entry in read_dir.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) != Some("bin") {
                    continue;
                }
                let stem = match path.file_stem().and_then(|s| s.to_str()) {
                    Some(s) => s,
                    None => continue,
                };
                let uuid_bytes = match parse_hex_uuid(stem) {
                    Some(u) => u,
                    None => continue,
                };
                if !surviving_blobs.contains(&uuid_bytes) {
                    let _ = crate::attachment::zeroize_and_delete(&path);
                }
            }
        }
    }

    Ok(LegacyAccessReport {
        inherited,
        destroyed,
        inherited_attachments,
        destroyed_attachments,
    })
}

fn parse_hex_uuid(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
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

fn writer_tmp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".tmp");
    path.with_file_name(name)
}

fn replace_vault_and_toml(
    vault_path: &Path,
    vault_tmp: &Path,
    toml_path: &Path,
    toml_tmp: &Path,
    backup_suffix: &str,
) -> Result<(), DiaryError> {
    let vault_bak = sidecar_path(vault_path, backup_suffix)?;
    let toml_bak = sidecar_path(toml_path, backup_suffix)?;
    cleanup_sensitive_file(&vault_bak);
    cleanup_sensitive_file(&toml_bak);

    let mut vault_backed_up = false;
    let mut toml_backed_up = false;
    let mut vault_replaced = false;

    let result = (|| -> Result<(), DiaryError> {
        std::fs::rename(vault_path, &vault_bak).map_err(DiaryError::Io)?;
        vault_backed_up = true;
        std::fs::rename(toml_path, &toml_bak).map_err(DiaryError::Io)?;
        toml_backed_up = true;
        std::fs::rename(vault_tmp, vault_path).map_err(DiaryError::Io)?;
        vault_replaced = true;
        std::fs::rename(toml_tmp, toml_path).map_err(DiaryError::Io)?;
        Ok(())
    })();

    if let Err(e) = result {
        if vault_replaced {
            cleanup_sensitive_file(vault_path);
        }
        if toml_backed_up {
            restore_backup(&toml_bak, toml_path);
        }
        if vault_backed_up {
            restore_backup(&vault_bak, vault_path);
        }
        cleanup_sensitive_file(vault_tmp);
        cleanup_sensitive_file(toml_tmp);
        return Err(e);
    }

    cleanup_sensitive_file(&vault_bak);
    cleanup_sensitive_file(&toml_bak);
    Ok(())
}

fn restore_backup(backup: &Path, target: &Path) {
    if let Err(e) = std::fs::rename(backup, target) {
        eprintln!("Warning: failed to restore backup {backup:?} to {target:?}: {e}");
    }
}

fn cleanup_sensitive_file(path: &Path) {
    if path.is_dir() {
        return;
    }
    if path.is_file() {
        if let Err(e) = zeroize_file(path) {
            eprintln!("Warning: failed to zeroize temporary file {path:?}: {e}");
        }
    }
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            eprintln!("Warning: failed to remove temporary file {path:?}: {e}");
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

fn zeroize_non_inherited_record_ciphertexts(
    vault_path: &Path,
    header: &VaultHeader,
    keep_record_uuids: &std::collections::HashSet<[u8; 16]>,
) -> Result<(), DiaryError> {
    use std::io::{Read as _, Seek as _};

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(vault_path)?;
    let entries_start = HEADER_SIZE as u64
        + 4
        + u64::try_from(header.kem_encrypted_sk.len())
            .map_err(|_| DiaryError::Vault("KEM key length overflow".to_string()))?
        + 4
        + u64::try_from(header.dsa_encrypted_sk.len())
            .map_err(|_| DiaryError::Vault("DSA key length overflow".to_string()))?;

    file.seek(std::io::SeekFrom::Start(entries_start))?;
    loop {
        let record_len_pos = file.stream_position()?;
        let mut len_buf = [0u8; 4];
        file.read_exact(&mut len_buf)?;
        let record_len = u32::from_le_bytes(len_buf);
        if record_len == 0 {
            break;
        }

        let payload_start = record_len_pos + 4;
        let mut payload = vec![0u8; record_len as usize];
        file.read_exact(&mut payload)?;
        let parsed = parse_record_offsets_for_zeroize(&payload)?;
        let should_zeroize = !keep_record_uuids.contains(&parsed.uuid);
        if should_zeroize && parsed.ciphertext_len > 0 {
            zeroize_file_range(
                &mut file,
                payload_start + parsed.ciphertext_offset as u64,
                parsed.ciphertext_len as u64,
            )?;
        }
        file.seek(std::io::SeekFrom::Start(
            payload_start + u64::from(record_len),
        ))?;
    }
    file.sync_all()?;
    Ok(())
}

struct RecordOffsets {
    uuid: [u8; 16],
    ciphertext_offset: usize,
    ciphertext_len: usize,
}

fn parse_record_offsets_for_zeroize(payload: &[u8]) -> Result<RecordOffsets, DiaryError> {
    const UUID_OFFSET: usize = 1;
    const UUID_END: usize = UUID_OFFSET + 16;

    if payload.len() < UUID_END {
        return Err(DiaryError::Vault(
            "record payload is too short for record uuid".to_string(),
        ));
    }
    let record_type = payload[0];
    let uuid: [u8; 16] = payload[UUID_OFFSET..UUID_END]
        .try_into()
        .map_err(|_| DiaryError::Vault("record payload has invalid uuid".to_string()))?;
    let ct_len_offset = match record_type {
        RECORD_TYPE_ENTRY | RECORD_TYPE_TEMPLATE => 1 + 16 + 8 + 8 + aead::NONCE_SIZE,
        RECORD_TYPE_ATTACHMENT => 1 + 16 + aead::NONCE_SIZE,
        other => {
            return Err(DiaryError::Vault(format!(
                "unknown record_type 0x{other:02x} while zeroizing legacy vault"
            )))
        }
    };
    let ct_offset = checked_add(ct_len_offset, 4, "ciphertext offset")?;
    if payload.len() < ct_offset {
        return Err(DiaryError::Vault(
            "record payload is too short for ciphertext length".to_string(),
        ));
    }
    let ct_len = read_u32_at(payload, ct_len_offset, "ciphertext length")? as usize;
    let sig_len_offset = checked_add(ct_offset, ct_len, "ciphertext end")?;
    let sig_len = read_u32_at(payload, sig_len_offset, "signature length")? as usize;
    let sig_offset = checked_add(sig_len_offset, 4, "signature offset")?;
    let hmac_offset = checked_add(sig_offset, sig_len, "signature end")?;
    let legacy_flag_offset = checked_add(hmac_offset, 32, "content_hmac end")?;
    let _flag_byte = *payload
        .get(legacy_flag_offset)
        .ok_or_else(|| DiaryError::Vault("record payload is missing legacy flag".to_string()))?;

    Ok(RecordOffsets {
        uuid,
        ciphertext_offset: ct_offset,
        ciphertext_len: ct_len,
    })
}

fn read_u32_at(payload: &[u8], offset: usize, label: &str) -> Result<u32, DiaryError> {
    let end = checked_add(offset, 4, label)?;
    let bytes: [u8; 4] = payload
        .get(offset..end)
        .ok_or_else(|| DiaryError::Vault(format!("record payload is missing {label}")))?
        .try_into()
        .map_err(|_| DiaryError::Vault(format!("record payload has invalid {label}")))?;
    Ok(u32::from_le_bytes(bytes))
}

fn checked_add(a: usize, b: usize, label: &str) -> Result<usize, DiaryError> {
    a.checked_add(b)
        .ok_or_else(|| DiaryError::Vault(format!("record payload offset overflow at {label}")))
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

    fn vault_pqd_str(vault_dir: &Path) -> String {
        vault_dir.join("vault.pqd").to_str().unwrap().to_string()
    }

    fn hex_to_uuid(hex: &str) -> [u8; 16] {
        let mut out = [0u8; 16];
        for i in 0..16 {
            out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    fn always_confirm(_: ConfirmationMode) -> Result<bool, DiaryError> {
        Ok(true)
    }

    fn always_reject(_: ConfirmationMode) -> Result<bool, DiaryError> {
        Ok(false)
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

    /// TC-S12-007-05: legacy-access physical deletion step zeroizes
    /// non-INHERIT ciphertext bytes while leaving INHERIT ciphertext intact.
    #[test]
    fn tc_s12_007_05_zeroize_non_inherited_ciphertexts() {
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
        let (header, records_before) = read_vault(&vault_pqd).unwrap();
        let inherit_before = records_before
            .iter()
            .find(|r| hex_lower(&r.uuid) == ids[0])
            .unwrap()
            .ciphertext
            .clone();
        let destroy_before = records_before
            .iter()
            .find(|r| hex_lower(&r.uuid) == ids[1])
            .unwrap()
            .ciphertext
            .clone();
        assert!(destroy_before.iter().any(|&b| b != 0));

        let keep_record_uuids = std::collections::HashSet::from([hex_to_uuid(&ids[0])]);
        zeroize_non_inherited_record_ciphertexts(&vault_pqd, &header, &keep_record_uuids).unwrap();

        let (_header_after, records_after) = read_vault(&vault_pqd).unwrap();
        let inherit_after = records_after
            .iter()
            .find(|r| hex_lower(&r.uuid) == ids[0])
            .unwrap();
        let destroy_after = records_after
            .iter()
            .find(|r| hex_lower(&r.uuid) == ids[1])
            .unwrap();

        assert_eq!(inherit_after.ciphertext, inherit_before);
        assert!(destroy_after.ciphertext.iter().all(|&b| b == 0));
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
