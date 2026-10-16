use super::*;
use crate::vault::format::{RECORD_TYPE_ENTRY, RECORD_TYPE_TEMPLATE};

fn record(id: u8, version: u8) -> EntryRecord {
    EntryRecord {
        record_type: RECORD_TYPE_ENTRY,
        uuid: [id; 16],
        created_at: 100,
        updated_at: 200,
        iv: [version; 12],
        ciphertext: vec![version; 16],
        signature: vec![version],
        content_hmac: [version; 32],
        legacy_flag: 0,
        legacy_key_block: vec![],
        attachment_count: 0,
        attachment_offset: 0,
        padding: vec![],
    }
}

#[test]
fn three_way_presence_and_change_matrix() {
    let old = record(1, 1);
    let edit = record(1, 2);
    let other = record(1, 3);
    // base, local, remote, selected, deletion, conflict
    let cases = [
        (None, None, None, None, false, false),
        (None, Some(&old), None, Some(&old), false, false),
        (None, None, Some(&old), Some(&old), false, false),
        (None, Some(&old), Some(&old), Some(&old), false, false),
        (None, Some(&old), Some(&edit), None, false, true),
        (Some(&old), Some(&old), Some(&old), Some(&old), false, false),
        (Some(&old), None, None, None, true, false),
        (Some(&old), None, Some(&old), None, true, false),
        (Some(&old), Some(&old), None, None, true, false),
        (
            Some(&old),
            Some(&edit),
            Some(&old),
            Some(&edit),
            false,
            false,
        ),
        (
            Some(&old),
            Some(&old),
            Some(&edit),
            Some(&edit),
            false,
            false,
        ),
        (
            Some(&old),
            Some(&edit),
            Some(&edit),
            Some(&edit),
            false,
            false,
        ),
        (Some(&old), Some(&edit), Some(&other), None, false, true),
        (Some(&old), None, Some(&edit), None, false, true),
        (Some(&old), Some(&edit), None, None, false, true),
    ];
    for (base, local, remote, selected, deleted, conflict) in cases {
        let b: Vec<_> = base.into_iter().cloned().collect();
        let l: Vec<_> = local.into_iter().cloned().collect();
        let r: Vec<_> = remote.into_iter().cloned().collect();
        let plan = plan_records(&b, &l, &r).unwrap();
        assert_eq!(
            plan.records,
            selected.into_iter().cloned().collect::<Vec<_>>()
        );
        assert_eq!(plan.deleted, if deleted { vec![[1; 16]] } else { vec![] });
        assert_eq!(plan.conflicts.len(), usize::from(conflict));
        if conflict {
            let c = &plan.conflicts[0];
            assert_eq!(c.uuid, [1; 16]);
            assert_eq!(c.base.as_ref(), base);
            assert_eq!(c.local.as_ref(), local);
            assert_eq!(c.remote.as_ref(), remote);
        }
    }
}

#[test]
fn metadata_and_crypto_fields_are_changes_even_when_hmac_matches() {
    let old = record(1, 1);
    let mut variants = vec![];
    macro_rules! changed {
        ($field:ident, $value:expr) => {{
            let mut r = old.clone();
            r.$field = $value;
            variants.push(r);
        }};
    }
    changed!(created_at, 101);
    changed!(updated_at, 201);
    changed!(iv, [2; 12]);
    changed!(ciphertext, vec![2; 16]);
    changed!(signature, vec![2]);
    changed!(content_hmac, [2; 32]);
    changed!(legacy_flag, 1);
    changed!(legacy_key_block, vec![2]);
    for edit in variants {
        let plan =
            plan_records(std::slice::from_ref(&old), &[], std::slice::from_ref(&edit)).unwrap();
        assert_eq!(
            plan.conflicts.len(),
            1,
            "field change must conflict with deletion"
        );
    }
    let mut padded = old.clone();
    padded.padding = vec![9; 64];
    let plan = plan_records(&[old], &[], &[padded]).unwrap();
    assert_eq!(plan.deleted, vec![[1; 16]]);
    assert!(plan.conflicts.is_empty());
}

#[test]
fn rejects_duplicate_ids_and_cross_snapshot_type_changes() {
    let entry = record(1, 1);
    let mut template = entry.clone();
    template.record_type = RECORD_TYPE_TEMPLATE;
    for records in [
        vec![entry.clone(), entry.clone()],
        vec![entry.clone(), template.clone()],
    ] {
        assert!(plan_records(&records, &[], &[]).is_err());
        assert!(plan_records(&[], &records, &[]).is_err());
        assert!(plan_records(&[], &[], &records).is_err());
    }
    assert!(plan_records(
        std::slice::from_ref(&entry),
        std::slice::from_ref(&template),
        &[]
    )
    .is_err());
    assert!(plan_records(&[], &[entry], &[template]).is_err());
}

#[test]
fn output_is_uuid_sorted_independent_of_input_order_and_timestamps() {
    let a = record(1, 1);
    let mut b = record(2, 1);
    b.updated_at = u64::MAX;
    let c = record(3, 1);
    let first = plan_records(&[], &[c.clone(), a.clone()], std::slice::from_ref(&b)).unwrap();
    let second = plan_records(&[], &[a.clone(), c.clone()], std::slice::from_ref(&b)).unwrap();
    assert_eq!(first.records, vec![a, b, c]);
    assert_eq!(first.records, second.records);
}

const KEY: [u8; 32] = [7; 32];

fn vault_bytes(header: VaultHeader, entries: &[EntryRecord], authenticated: bool) -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.pqd");
    if authenticated {
        crate::vault::writer::write_vault_authenticated(&path, header, entries, &KEY).unwrap();
    } else {
        crate::vault::writer::write_vault(&path, header, entries).unwrap();
    }
    std::fs::read(path).unwrap()
}

fn snapshot(entries: &[EntryRecord]) -> AuthenticatedSnapshot {
    AuthenticatedSnapshot::from_bytes(
        &vault_bytes(VaultHeader::new(), entries, true),
        b"x = 1\n",
        &KEY,
    )
    .unwrap()
}

#[test]
fn requires_actual_mac_and_parses_only_authenticated_bytes() {
    let entries = vec![record(1, 1)];
    let bytes = vault_bytes(VaultHeader::new(), &entries, true);
    let snapshot = AuthenticatedSnapshot::from_bytes(&bytes, b"x=1", &KEY).unwrap();
    assert_eq!(snapshot.entries, entries);
    assert!(AuthenticatedSnapshot::from_bytes(&bytes, b"x=1", &[8; 32]).is_err());
    let mut corrupt = bytes.clone();
    corrupt[16] ^= 1;
    assert!(AuthenticatedSnapshot::from_bytes(&corrupt, b"x=1", &KEY).is_err());
    let mut downgrade = bytes.clone();
    downgrade[9] &= !FLAG_INTEGRITY;
    assert!(AuthenticatedSnapshot::from_bytes(&downgrade, b"x=1", &KEY).is_err());
    let legacy = vault_bytes(VaultHeader::new(), &entries, false);
    // Preserve the compatibility reader's behavior; only this planner is strict.
    verify_vault_integrity_bytes(&legacy, &KEY).unwrap();
    assert!(AuthenticatedSnapshot::from_bytes(&legacy, b"x=1", &KEY).is_err());
    for bytes in [&[][..], &bytes[..9], &bytes[..bytes.len() - 1]] {
        assert!(AuthenticatedSnapshot::from_bytes(bytes, b"x=1", &KEY).is_err());
    }
}

#[test]
fn authenticated_duplicates_and_attachment_metadata_are_rejected() {
    let entry = record(1, 1);
    let duplicates = vault_bytes(VaultHeader::new(), &[entry.clone(), entry.clone()], true);
    assert!(AuthenticatedSnapshot::from_bytes(&duplicates, b"x=1", &KEY).is_err());
    for offset in [false, true] {
        let mut attached = entry.clone();
        if offset {
            attached.attachment_offset = 1;
        } else {
            attached.attachment_count = 1;
        }
        let bytes = vault_bytes(VaultHeader::new(), &[attached], true);
        assert!(AuthenticatedSnapshot::from_bytes(&bytes, b"x=1", &KEY).is_err());
    }
}

#[test]
fn all_header_context_and_config_changes_fail_closed() {
    let base = snapshot(&[record(1, 1)]);
    let local = snapshot(&[]);
    let remote = snapshot(&[record(1, 1)]);
    // Different payload lengths are normal, including deletion of the last record.
    assert_eq!(
        plan_merge(&base, &local, &remote).unwrap().deleted,
        vec![[1; 16]]
    );
    macro_rules! rejects {
        ($field:ident, $value:expr) => {{
            let mut changed = snapshot(&[record(1, 1)]);
            changed.header.$field = $value;
            assert!(plan_merge(&base, &changed, &remote).is_err());
            assert!(plan_merge(&base, &local, &changed).is_err());
        }};
    }
    rejects!(schema_version, 4);
    rejects!(flags, FLAG_INTEGRITY | 2);
    rejects!(kdf_salt, [1; 32]);
    rejects!(legacy_salt, [1; 32]);
    rejects!(verification_iv, [1; 12]);
    rejects!(verification_ct, vec![1; 48]);
    rejects!(kem_pk_offset, [1; 32]);
    rejects!(dsa_pk_hash, [1; 32]);
    rejects!(kem_encrypted_sk, vec![1]);
    rejects!(dsa_encrypted_sk, vec![1]);
    let mut changed = snapshot(&[]);
    changed.config = parse_sync_config(b"x=1\nfuture=true").unwrap();
    assert!(plan_merge(&base, &changed, &remote).is_err());
    assert!(plan_merge(&base, &local, &changed).is_err());
    changed.config = parse_sync_config(b"# comment\nx = 1\n").unwrap();
    assert!(plan_merge(&base, &changed, &remote).is_ok());
}

#[test]
fn older_one_sided_edit_and_template_changes_are_preserved() {
    let mut base = record(1, 1);
    base.record_type = RECORD_TYPE_TEMPLATE;
    let mut edit = base.clone();
    edit.updated_at = 0;
    edit.legacy_flag = 1;
    let plan = plan_records(
        std::slice::from_ref(&base),
        std::slice::from_ref(&base),
        std::slice::from_ref(&edit),
    )
    .unwrap();
    assert_eq!(plan.records, vec![edit.clone()]);
    let mut padded = edit.clone();
    padded.padding = vec![9];
    let plan = plan_records(&[base], std::slice::from_ref(&padded), &[edit]).unwrap();
    assert_eq!(plan.records, vec![padded]);
}

struct Repo {
    dir: tempfile::TempDir,
}

impl Repo {
    fn new() -> Self {
        let this = Self {
            dir: tempfile::tempdir().unwrap(),
        };
        this.git(&["init", "-b", "main"]);
        this
    }

    fn git(&self, args: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .current_dir(self.dir.path())
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@localhost")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@localhost")
            .env("GIT_AUTHOR_DATE", "2025-01-01T00:00:00Z")
            .env("GIT_COMMITTER_DATE", "2025-01-01T00:00:00Z")
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn commit(&self, entries: &[EntryRecord], parents: &[&str], message: &str) -> String {
        let bytes = vault_bytes(VaultHeader::new(), entries, true);
        self.commit_bytes(&bytes, parents, message)
    }

    fn commit_bytes(&self, bytes: &[u8], parents: &[&str], message: &str) -> String {
        std::fs::write(self.dir.path().join("vault.pqd"), bytes).unwrap();
        std::fs::write(self.dir.path().join("vault.toml"), b"x=1\n").unwrap();
        self.git(&["add", "vault.pqd", "vault.toml"]);
        let tree = self.git(&["write-tree"]);
        let mut args = vec!["commit-tree", &tree, "-m", message];
        for parent in parents {
            args.extend(["-p", parent]);
        }
        self.git(&args)
    }
}

#[test]
fn reads_pinned_nonempty_common_base_without_mutating_repository() {
    let repo = Repo::new();
    let old = record(1, 1);
    let base = repo.commit(std::slice::from_ref(&old), &[], "base");
    let local = repo.commit(&[], &[&base], "local deletion");
    let remote = repo.commit(std::slice::from_ref(&old), &[&base], "remote unchanged");
    repo.git(&["update-ref", "refs/heads/main", &local]);
    repo.git(&["update-ref", "refs/heads/remote", &remote]);
    let index_before = std::fs::read(repo.dir.path().join(".git/index")).unwrap();
    let vault_before = std::fs::read(repo.dir.path().join("vault.pqd")).unwrap();
    let config_before = std::fs::read(repo.dir.path().join("vault.toml")).unwrap();
    let inputs = read_committed_inputs(repo.dir.path(), "HEAD", "remote", &KEY).unwrap();
    assert_eq!(inputs.base_commit, base);
    assert_eq!(inputs.local_commit, local);
    assert_eq!(inputs.remote_commit, remote);
    assert_eq!(
        plan_merge(&inputs.base, &inputs.local, &inputs.remote)
            .unwrap()
            .deleted,
        vec![[1; 16]]
    );
    assert_eq!(
        std::fs::read(repo.dir.path().join(".git/index")).unwrap(),
        index_before
    );
    assert_eq!(
        std::fs::read(repo.dir.path().join("vault.pqd")).unwrap(),
        vault_before
    );
    assert_eq!(
        std::fs::read(repo.dir.path().join("vault.toml")).unwrap(),
        config_before
    );
    assert_eq!(repo.git(&["rev-parse", "HEAD"]), local);
    // Moving a ref later cannot change the already materialized snapshots.
    repo.git(&["update-ref", "refs/heads/remote", &local]);
    assert_eq!(inputs.remote_commit, remote);
    assert_eq!(inputs.remote.entries, vec![old]);
}

#[test]
fn rejects_unrelated_shallow_and_multiple_base_histories() {
    let repo = Repo::new();
    let base = repo.commit(&[record(1, 1)], &[], "base");
    let unrelated = repo.commit(&[record(2, 1)], &[], "unrelated");
    assert!(read_committed_inputs(repo.dir.path(), &base, &unrelated, &KEY).is_err());
    let a = repo.commit(&[record(1, 2)], &[&base], "a");
    let b = repo.commit(&[record(1, 3)], &[&base], "b");
    let ab = repo.commit(&[record(1, 4)], &[&a, &b], "ab");
    let ba = repo.commit(&[record(1, 5)], &[&b, &a], "ba");
    let error = read_committed_inputs(repo.dir.path(), &ab, &ba, &KEY).unwrap_err();
    assert!(error.to_string().contains("exactly one common base"));
    std::fs::write(repo.dir.path().join(".git/shallow"), format!("{base}\n")).unwrap();
    let error = read_committed_inputs(repo.dir.path(), &a, &b, &KEY).unwrap_err();
    assert!(error.to_string().contains("complete Git history"));
}

#[test]
fn rejects_unauthenticated_or_bad_mac_common_base_and_tracked_blobs() {
    for authenticated in [false, true] {
        let repo = Repo::new();
        let mut bytes = vault_bytes(VaultHeader::new(), &[record(1, 1)], authenticated);
        if authenticated {
            bytes[16] ^= 1;
        }
        let base = repo.commit_bytes(&bytes, &[], "untrusted base");
        let tip = repo.commit(&[], &[&base], "authenticated tip");
        assert!(read_committed_inputs(repo.dir.path(), &base, &tip, &KEY).is_err());
    }
    let repo = Repo::new();
    let base = repo.commit(&[record(1, 1)], &[], "base");
    std::fs::create_dir(repo.dir.path().join(".attachments")).unwrap();
    std::fs::write(repo.dir.path().join(".attachments/blob"), b"encrypted blob").unwrap();
    repo.git(&["add", ".attachments"]);
    let tip = repo.commit(&[], &[&base], "blob");
    let error = read_committed_inputs(repo.dir.path(), &base, &tip, &KEY).unwrap_err();
    assert!(error.to_string().contains("attachment blob sync"));
}

#[test]
fn pinned_reads_ignore_replace_refs_and_reject_missing_vaults() {
    let repo = Repo::new();
    let base = repo.commit(&[record(1, 1)], &[], "base");
    let tip = repo.commit(&[], &[&base], "deletion");
    let replacement = repo.commit(&[record(2, 1)], &[], "replacement");
    repo.git(&["replace", &base, &replacement]);
    let inputs = read_committed_inputs(repo.dir.path(), &base, &tip, &KEY).unwrap();
    assert_eq!(inputs.base.entries, vec![record(1, 1)]);
    assert_eq!(
        plan_merge(&inputs.base, &inputs.local, &inputs.remote)
            .unwrap()
            .deleted,
        vec![[1; 16]]
    );
    repo.git(&["update-index", "--force-remove", "vault.pqd"]);
    let tree = repo.git(&["write-tree"]);
    let missing = repo.git(&["commit-tree", &tree, "-p", &tip, "-m", "missing"]);
    assert!(read_committed_inputs(repo.dir.path(), &tip, &missing, &KEY).is_err());
    assert!(read_committed_inputs(repo.dir.path(), "--all", &tip, &KEY).is_err());
}

#[test]
fn padding_does_not_hide_conflicts_and_all_outputs_are_sorted() {
    let mut base = vec![record(3, 1), record(2, 1), record(1, 1)];
    let local = vec![record(3, 2), record(2, 2), record(1, 2)];
    let mut remote = vec![record(3, 3), record(2, 3), record(1, 3)];
    for entry in &mut remote {
        entry.updated_at = u64::MAX;
    }
    let plan = plan_records(&base, &local, &remote).unwrap();
    assert_eq!(
        plan.conflicts.iter().map(|c| c.uuid).collect::<Vec<_>>(),
        vec![[1; 16], [2; 16], [3; 16]]
    );
    base.reverse();
    assert_eq!(
        plan_records(&base, &[], &[]).unwrap().deleted,
        vec![[1; 16], [2; 16], [3; 16]]
    );
    let mut attached = record(1, 1);
    attached.attachment_count = 1;
    assert!(!same_record(&record(1, 1), &attached));
    attached.attachment_count = 0;
    attached.attachment_offset = 1;
    assert!(!same_record(&record(1, 1), &attached));
}
