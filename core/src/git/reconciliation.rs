//! Read-only planning for a future three-way pull. The existing pull remains unchanged.
//!
//! This is an entry/template-only planner, not an apply transaction. A subsequent
//! pull integration must authenticate the working snapshot, reject local attachment
//! blobs, collect explicit choices (including an absent side), revalidate tips and
//! local bytes after prompting, then apply with isolated index/ancestry handling.
//! Divergent edits/additions remain explicit conflicts here; adopting any automatic
//! winner policy is a separate caller decision. Encrypted template names cannot be
//! compared across different UUIDs with only a MAC key.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::{parse_sync_config, reject_attachment_records};
use crate::error::DiaryError;
use crate::vault::format::{
    EntryRecord, VaultHeader, FLAG_INTEGRITY, RECORD_TYPE_ENTRY, RECORD_TYPE_TEMPLATE,
};
use crate::vault::reader::{read_vault_with_attachments_from_bytes, verify_vault_integrity_bytes};

// Legacy graft files rewrite ancestry independently of replacement objects.
// An empty graft path disables both the default file and an inherited override.
// Keep these environment overrides on Command, never in the parent process.
fn run_git_command(repository: &Path, args: &[&str]) -> Result<std::process::Output, DiaryError> {
    std::process::Command::new("git")
        .current_dir(repository)
        .env("GIT_GRAFT_FILE", "")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .args(args)
        .output()
        .map_err(|error| DiaryError::Git(format!("failed to read Git snapshot: {error}")))
}

fn git_stdout(repository: &Path, args: &[&str]) -> Result<Vec<u8>, DiaryError> {
    let output = run_git_command(repository, args)?;
    if !output.status.success() {
        return Err(DiaryError::Git(format!(
            "failed to read Git snapshot: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(output.stdout)
}

/// An authenticated, attachment-free snapshot. Construction requires a whole-vault
/// MAC: legacy files accepted by the general reader cannot prove record absence.
/// Config is compared semantically, including unknown TOML fields.
#[derive(Debug)]
pub struct AuthenticatedSnapshot {
    header: VaultHeader,
    entries: Vec<EntryRecord>,
    config: toml::Value,
}

impl AuthenticatedSnapshot {
    /// Authenticate and parse the same bytes, without reopening a file.
    /// This does not validate external attachment blobs; the committed reader
    /// checks their trees, and working-tree callers must check their own blobs.
    pub fn from_bytes(vault: &[u8], config: &[u8], mac_key: &[u8; 32]) -> Result<Self, DiaryError> {
        // Checking this flag is mandatory: the compatibility verifier deliberately
        // permits old flag-clear vaults, which provide no authenticated absence.
        if vault.get(9).is_none_or(|flags| flags & FLAG_INTEGRITY == 0) {
            return Err(DiaryError::Git(
                "three-way planning requires whole-vault integrity authentication".into(),
            ));
        }
        verify_vault_integrity_bytes(vault, mac_key)?;
        let (header, entries, attachments) = read_vault_with_attachments_from_bytes(vault)?;
        reject_attachment_records(&entries, &attachments)?;
        index_records(&entries)?;
        Ok(Self {
            header,
            entries,
            config: parse_sync_config(config)?,
        })
    }
}

/// Pinned committed inputs. Reading them never fetches, writes, stages, or commits.
/// Working-tree edits are intentionally not represented here.
#[derive(Debug)]
pub struct CommittedInputs {
    pub local_commit: String,
    pub remote_commit: String,
    pub base_commit: String,
    pub base: AuthenticatedSnapshot,
    pub local: AuthenticatedSnapshot,
    pub remote: AuthenticatedSnapshot,
}

/// Read both tips and their unique common base as authenticated snapshots.
/// The caller fetches first if needed. Refs are resolved once; every subsequent
/// tree read uses the resulting immutable object IDs. Shallow histories and
/// ambiguous/missing bases fail closed rather than guessing deletion evidence.
pub fn read_committed_inputs(
    repository: &Path,
    local_ref: &str,
    remote_ref: &str,
    mac_key: &[u8; 32],
) -> Result<CommittedInputs, DiaryError> {
    if git_stdout(repository, &["rev-parse", "--is-shallow-repository"])? != b"false\n" {
        return Err(DiaryError::Git(
            "three-way planning requires a complete Git history".into(),
        ));
    }
    let local_commit = pin_commit(repository, local_ref)?;
    let remote_commit = pin_commit(repository, remote_ref)?;
    let bases = run_git_command(
        repository,
        &[
            "--no-replace-objects",
            "merge-base",
            "--all",
            &local_commit,
            &remote_commit,
        ],
    )?;
    if bases.status.code() == Some(1) {
        return Err(DiaryError::Git(
            "three-way planning requires a common base".into(),
        ));
    }
    if !bases.status.success() {
        return Err(DiaryError::Git("cannot determine the common base".into()));
    }
    let bases = std::str::from_utf8(&bases.stdout)
        .map_err(|_| DiaryError::Git("invalid merge-base object ID".into()))?;
    let mut bases = bases.split_whitespace();
    let base_commit = bases
        .next()
        .ok_or_else(|| DiaryError::Git("three-way planning requires a common base".into()))?;
    if bases.next().is_some() || !valid_object_id(base_commit) {
        return Err(DiaryError::Git(
            "three-way planning requires exactly one common base".into(),
        ));
    }
    let base = read_commit(repository, base_commit, mac_key)?;
    let local = read_commit(repository, &local_commit, mac_key)?;
    let remote = read_commit(repository, &remote_commit, mac_key)?;
    validate_compatibility(&base, &local, &remote)?;
    Ok(CommittedInputs {
        local_commit,
        remote_commit,
        base_commit: base_commit.to_owned(),
        base,
        local,
        remote,
    })
}

fn valid_object_id(id: &str) -> bool {
    matches!(id.len(), 40 | 64) && id.bytes().all(|b| b.is_ascii_hexdigit())
}

fn pin_commit(repository: &Path, reference: &str) -> Result<String, DiaryError> {
    let bytes = git_stdout(
        repository,
        &[
            "--no-replace-objects",
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{reference}^{{commit}}"),
        ],
    )?;
    let id = std::str::from_utf8(&bytes)
        .map_err(|_| DiaryError::Git("invalid commit object ID".into()))?
        .trim();
    if !valid_object_id(id) {
        return Err(DiaryError::Git("invalid commit object ID".into()));
    }
    Ok(id.to_owned())
}

fn read_commit(
    repository: &Path,
    commit: &str,
    mac_key: &[u8; 32],
) -> Result<AuthenticatedSnapshot, DiaryError> {
    if !git_stdout(
        repository,
        &[
            "--no-replace-objects",
            "ls-tree",
            commit,
            "--",
            ".attachments",
        ],
    )?
    .is_empty()
    {
        return Err(DiaryError::Git(
            "attachment blob sync is not supported".into(),
        ));
    }
    let vault = git_stdout(
        repository,
        &[
            "--no-replace-objects",
            "show",
            &format!("{commit}:vault.pqd"),
        ],
    )?;
    let config = git_stdout(
        repository,
        &[
            "--no-replace-objects",
            "show",
            &format!("{commit}:vault.toml"),
        ],
    )?;
    AuthenticatedSnapshot::from_bytes(&vault, &config, mac_key)
}

/// Plan only; no filesystem mutation or timestamp-based winner selection.
/// All three snapshots must share the same format, encryption context and config.
/// This pure function cannot establish ancestry: callers must supply the actual
/// common base, for example from [read_committed_inputs], never an arbitrary snapshot.
/// The result is not directly writable when conflicts remain. Applying it later
/// requires explicit choices plus revalidation of the pinned tips/local bytes.
pub fn plan_merge(
    base: &AuthenticatedSnapshot,
    local: &AuthenticatedSnapshot,
    remote: &AuthenticatedSnapshot,
) -> Result<MergePlan, DiaryError> {
    validate_compatibility(base, local, remote)?;
    plan_records(&base.entries, &local.entries, &remote.entries)
}

fn validate_compatibility(
    base: &AuthenticatedSnapshot,
    local: &AuthenticatedSnapshot,
    remote: &AuthenticatedSnapshot,
) -> Result<(), DiaryError> {
    for snapshot in [local, remote] {
        if !same_header_context(&base.header, &snapshot.header) {
            return Err(DiaryError::Git(
                "vault header/key changes cannot be planned automatically".into(),
            ));
        }
        if base.config != snapshot.config {
            return Err(DiaryError::Git(
                "vault.toml changes cannot be planned automatically".into(),
            ));
        }
    }
    Ok(())
}

fn same_header_context(left: &VaultHeader, right: &VaultHeader) -> bool {
    // Exhaustive destructuring makes newly added format fields require a decision.
    let VaultHeader {
        schema_version,
        flags,
        payload_size: _,
        kdf_salt,
        legacy_salt,
        verification_iv,
        verification_ct,
        kem_pk_offset,
        dsa_pk_hash,
        kem_encrypted_sk,
        dsa_encrypted_sk,
    } = left;
    *schema_version == right.schema_version
        && *flags == right.flags
        && *kdf_salt == right.kdf_salt
        && *legacy_salt == right.legacy_salt
        && *verification_iv == right.verification_iv
        && *verification_ct == right.verification_ct
        && *kem_pk_offset == right.kem_pk_offset
        && *dsa_pk_hash == right.dsa_pk_hash
        && *kem_encrypted_sk == right.kem_encrypted_sk
        && *dsa_encrypted_sk == right.dsa_encrypted_sk
}

/// A conflict preserves absence as a possible choice (including delete/edit).
#[derive(Debug)]
pub struct RecordConflict {
    pub uuid: [u8; 16],
    pub base: Option<EntryRecord>,
    pub local: Option<EntryRecord>,
    pub remote: Option<EntryRecord>,
}

/// Unambiguous records and unresolved choices, ordered by UUID.
/// Conflicted UUIDs are never silently included in records.
#[derive(Debug, Default)]
pub struct MergePlan {
    pub records: Vec<EntryRecord>,
    pub deleted: Vec<[u8; 16]>,
    pub conflicts: Vec<RecordConflict>,
}

fn index_records(entries: &[EntryRecord]) -> Result<BTreeMap<[u8; 16], &EntryRecord>, DiaryError> {
    let mut records = BTreeMap::new();
    for record in entries {
        if !matches!(record.record_type, RECORD_TYPE_ENTRY | RECORD_TYPE_TEMPLATE) {
            return Err(DiaryError::Git(
                "unsupported record type in merge input".into(),
            ));
        }
        if records.insert(record.uuid, record).is_some() {
            return Err(DiaryError::Git(
                "duplicate record UUID in merge input".into(),
            ));
        }
    }
    Ok(records)
}

fn same_record(left: &EntryRecord, right: &EntryRecord) -> bool {
    // Ignore only random padding. Metadata and ciphertext changes are real changes
    // even with equal HMACs/timestamps; never use timestamps to infer ancestry.
    let EntryRecord {
        record_type,
        uuid,
        created_at,
        updated_at,
        iv,
        ciphertext,
        signature,
        content_hmac,
        legacy_flag,
        legacy_key_block,
        attachment_count,
        attachment_offset,
        padding: _,
    } = left;
    *record_type == right.record_type
        && *uuid == right.uuid
        && *created_at == right.created_at
        && *updated_at == right.updated_at
        && *iv == right.iv
        && *ciphertext == right.ciphertext
        && *signature == right.signature
        && *content_hmac == right.content_hmac
        && *legacy_flag == right.legacy_flag
        && *legacy_key_block == right.legacy_key_block
        && *attachment_count == right.attachment_count
        && *attachment_offset == right.attachment_offset
}

fn same_state(left: Option<&EntryRecord>, right: Option<&EntryRecord>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => same_record(left, right),
        _ => false,
    }
}

fn plan_records(
    base: &[EntryRecord],
    local: &[EntryRecord],
    remote: &[EntryRecord],
) -> Result<MergePlan, DiaryError> {
    let base = index_records(base)?;
    let local = index_records(local)?;
    let remote = index_records(remote)?;
    let ids: BTreeSet<_> = base
        .keys()
        .chain(local.keys())
        .chain(remote.keys())
        .copied()
        .collect();
    let mut plan = MergePlan::default();
    for uuid in ids {
        let b = base.get(&uuid).copied();
        let l = local.get(&uuid).copied();
        let r = remote.get(&uuid).copied();
        let mut types = [b, l, r]
            .into_iter()
            .flatten()
            .map(|record| record.record_type);
        if let Some(first) = types.next() {
            if types.any(|kind| kind != first) {
                return Err(DiaryError::Git(
                    "record UUID changes type across merge inputs".into(),
                ));
            }
        }
        let selected = if same_state(l, r) {
            l // Preserve local representation, including padding, when equal.
        } else if same_state(l, b) {
            r
        } else if same_state(r, b) {
            l
        } else {
            plan.conflicts.push(RecordConflict {
                uuid,
                base: b.cloned(),
                local: l.cloned(),
                remote: r.cloned(),
            });
            continue;
        };
        if let Some(record) = selected {
            plan.records.push(record.clone());
        } else if b.is_some() {
            plan.deleted.push(uuid);
        }
    }
    Ok(plan)
}

#[cfg(test)]
mod tests;
