use super::*;
use reconciliation::{
    pin_commit, plan_merge, read_committed_inputs, same_record, AuthenticatedSnapshot,
};
use std::collections::BTreeMap;

pub(super) fn merge(
    dir: &Path,
    config: &VaultConfig,
    path: &Path,
    key: &[u8; 32],
    resolver: &mut impl FnMut(&MergeConflict) -> Result<Option<ConflictResolution>, DiaryError>,
) -> Result<MergeResult, DiaryError> {
    timestamp_fuzz_seconds(config.git.privacy.timestamp_fuzz_hours)?;
    if !dir.join(".git").exists() {
        return Err(DiaryError::Git(
            "git repository is not initialized: .git directory not found".into(),
        ));
    }
    if !path.exists() {
        return Err(DiaryError::Git("vault.pqd does not exist".into()));
    }
    if std::fs::canonicalize(path)? != std::fs::canonicalize(dir.join("vault.pqd"))? {
        return Err(DiaryError::Git(
            "git pull requires the repository's vault.pqd".into(),
        ));
    }
    let vault_bytes = std::fs::read(path)?;
    let config_bytes = std::fs::read(dir.join("vault.toml"))?;
    let working = AuthenticatedSnapshot::from_bytes(&vault_bytes, &config_bytes, key)?;
    reject_local_attachment_blobs(dir)?;
    let local_commit = pin_commit(dir, "HEAD")?;
    super::git_stdout(dir, &["fetch", "origin"])?;
    let tracking = get_tracking_ref(dir)?;
    let remote_commit = pin_commit(dir, &tracking)?;
    // Even a no-op must have authenticated history. Never let rev-list count==0
    // turn missing/MAC-free deletion evidence into an apparently successful sync.
    let committed=read_committed_inputs(dir,&local_commit,&remote_commit,key).map_err(|error|
        DiaryError::Git(format!("Cannot safely reconcile Git history: {error}. Synchronization stopped; preserve both copies and review the history manually before retrying. No vault data was changed.")))?;
    transaction::validate_remote_tree(dir, &committed.base_commit, &remote_commit)?;
    let mut plan = plan_merge(&committed.base, &working, &committed.remote)?;
    let ts = fuzz_timestamp(
        get_last_commit_timestamp(dir),
        config.git.privacy.timestamp_fuzz_hours,
    )?
    .to_rfc3339();
    let mut records: BTreeMap<_, _> = plan.records.drain(..).map(|r| (r.uuid, r)).collect();
    let mut unresolved = Vec::new();
    let mut local_lww = 0;
    for conflict in plan.conflicts {
        let choice = match (&conflict.local, &conflict.remote) {
            (Some(l), Some(r)) if l.updated_at > r.updated_at => {
                local_lww += 1;
                Some(ConflictResolution::KeepLocal)
            }
            (Some(l), Some(r)) if r.updated_at > l.updated_at => {
                Some(ConflictResolution::KeepRemote)
            }
            _ => resolver(&conflict)?,
        };
        match choice {
            Some(ConflictResolution::KeepLocal) => {
                if let Some(r) = conflict.local {
                    records.insert(r.uuid, r);
                }
            }
            Some(ConflictResolution::KeepRemote) => {
                if let Some(r) = conflict.remote {
                    records.insert(r.uuid, r);
                }
            }
            None => unresolved.push(conflict),
        }
    }
    if !unresolved.is_empty() {
        return Ok(MergeResult {
            added: 0,
            updated: 0,
            deleted: 0,
            conflicts: unresolved,
        });
    }
    let original: BTreeMap<_, _> = working.entries.iter().map(|r| (r.uuid, r)).collect();
    let added = records
        .keys()
        .filter(|id| !original.contains_key(*id))
        .count();
    let updated = local_lww
        + records
            .iter()
            .filter(|(id, r)| original.get(*id).is_some_and(|old| !same_record(old, r)))
            .count();
    let deleted = original
        .keys()
        .filter(|id| !records.contains_key(*id))
        .count();
    let result = MergeResult {
        added,
        updated,
        deleted,
        conflicts: vec![],
    };
    revalidate(
        dir,
        path,
        &tracking,
        &local_commit,
        &remote_commit,
        &vault_bytes,
        &config_bytes,
    )?;
    let records: Vec<_> = records.into_values().collect();
    // The order is not meaningful, but avoid rewriting identical selected records
    // solely because a fetch or transport-padding commit happened.
    let unchanged = records.len() == working.entries.len()
        && records
            .iter()
            .all(|r| original.get(&r.uuid).is_some_and(|old| same_record(old, r)));
    let merge = transaction::ancestry_needed(dir, &local_commit, &remote_commit)?;
    if unchanged && !merge {
        return Ok(result);
    }
    transaction::apply(
        transaction::Commit {
            dir,
            path,
            local: &local_commit,
            remote: &remote_commit,
            config,
            timestamp: &ts,
            original: &vault_bytes,
            merge,
        },
        || {
            revalidate(
                dir,
                path,
                &tracking,
                &local_commit,
                &remote_commit,
                &vault_bytes,
                &config_bytes,
            )
        },
        || {
            if !unchanged {
                write_vault_with_attachments_authenticated(
                    path,
                    working.header,
                    &records,
                    &[],
                    key,
                )?;
            }
            Ok(())
        },
    )?;
    Ok(result)
}

fn revalidate(
    dir: &Path,
    path: &Path,
    tracking: &str,
    local: &str,
    remote: &str,
    vault: &[u8],
    config: &[u8],
) -> Result<(), DiaryError> {
    if pin_commit(dir, "HEAD")? != local
        || pin_commit(dir, tracking)? != remote
        || std::fs::read(path)? != vault
        || std::fs::read(dir.join("vault.toml"))? != config
    {
        return Err(DiaryError::Git(
            "merge inputs changed while choosing; no merge was applied; retry git-pull".into(),
        ));
    }
    reject_local_attachment_blobs(dir)
}
