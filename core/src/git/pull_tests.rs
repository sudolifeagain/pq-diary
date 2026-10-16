use super::*;
use crate::vault::format::RECORD_TYPE_ENTRY;
use crate::vault::reader::read_vault;
use crate::vault::writer::write_vault_authenticated;

const KEY: [u8; 32] = [19; 32];
fn record(id: u8, version: u8) -> EntryRecord {
    EntryRecord {
        record_type: RECORD_TYPE_ENTRY,
        uuid: [id; 16],
        created_at: 10,
        updated_at: 20,
        iv: [version; 12],
        ciphertext: vec![version; 16],
        signature: vec![],
        content_hmac: [version; 32],
        legacy_flag: 0,
        legacy_key_block: vec![],
        attachment_count: 0,
        attachment_offset: 0,
        padding: vec![],
    }
}
fn git(dir: &Path, args: &[&str]) -> Vec<u8> {
    let out = std::process::Command::new("git")
        .current_dir(dir)
        .args(args)
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "test@localhost")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "test@localhost")
        .env("GIT_AUTHOR_DATE", "2025-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2025-01-01T00:00:00Z")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}
struct Fixture {
    _dir: tempfile::TempDir,
    local: PathBuf,
    remote: PathBuf,
    config: VaultConfig,
}
impl Fixture {
    fn new(base: &[EntryRecord]) -> Self {
        Self::with_integrity(base, true)
    }
    fn with_integrity(base: &[EntryRecord], authenticated: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let bare = dir.path().join("bare.git");
        git(
            dir.path(),
            &[
                "init",
                "--bare",
                "--initial-branch=main",
                bare.to_str().unwrap(),
            ],
        );
        let local = dir.path().join("local");
        let remote = dir.path().join("remote");
        git(
            dir.path(),
            &["clone", bare.to_str().unwrap(), local.to_str().unwrap()],
        );
        let mut config = VaultConfig::default();
        config.git.author_name = "test".into();
        config.git.author_email = "test@localhost".into();
        config.git.privacy.timestamp_fuzz_hours = 0;
        config.to_file(&local.join("vault.toml")).unwrap();
        if authenticated {
            write_vault_authenticated(&local.join("vault.pqd"), VaultHeader::new(), base, &KEY)
                .unwrap();
        } else {
            crate::vault::writer::write_vault(&local.join("vault.pqd"), VaultHeader::new(), base)
                .unwrap();
        }
        git(&local, &["add", "vault.pqd", "vault.toml"]);
        git(&local, &["commit", "-m", "base"]);
        git(&local, &["push", "-u", "origin", "main"]);
        git(
            dir.path(),
            &["clone", bare.to_str().unwrap(), remote.to_str().unwrap()],
        );
        Self {
            _dir: dir,
            local,
            remote,
            config,
        }
    }
    fn publish(&self, entries: &[EntryRecord]) {
        write_vault_authenticated(
            &self.remote.join("vault.pqd"),
            VaultHeader::new(),
            entries,
            &KEY,
        )
        .unwrap();
        git(&self.remote, &["add", "vault.pqd"]);
        git(&self.remote, &["commit", "-m", "remote"]);
        git(&self.remote, &["push"]);
    }
    fn local(&self, entries: &[EntryRecord]) {
        write_vault_authenticated(
            &self.local.join("vault.pqd"),
            VaultHeader::new(),
            entries,
            &KEY,
        )
        .unwrap();
    }
    fn pull(&self) -> Result<MergeResult, DiaryError> {
        git_pull_merge(
            &self.local,
            &self.config,
            &self.local.join("vault.pqd"),
            &KEY,
            false,
        )
    }
}
#[test]
fn remote_deletion_removes_unchanged_base_record() {
    let fixture = Fixture::new(&[record(1, 1), record(2, 1)]);
    fixture.publish(&[record(2, 1)]);
    let result = fixture.pull().unwrap();
    assert_eq!(result.deleted, 1);
    assert_eq!(
        read_vault(&fixture.local.join("vault.pqd")).unwrap().1,
        vec![record(2, 1)]
    );
}
#[test]
fn local_deletion_is_not_resurrected_and_older_remote_edit_is_applied() {
    let fixture = Fixture::new(&[record(1, 1), record(2, 1)]);
    fixture.local(&[record(2, 1)]);
    let mut edit = record(2, 2);
    edit.updated_at = 1;
    fixture.publish(&[record(1, 1), edit.clone()]);
    fixture.pull().unwrap();
    assert_eq!(
        read_vault(&fixture.local.join("vault.pqd")).unwrap().1,
        vec![edit]
    );
}

#[derive(Debug, PartialEq, Eq)]
struct State {
    vault: Vec<u8>,
    config: Vec<u8>,
    head: Vec<u8>,
    index: Vec<u8>,
}
fn state(f: &Fixture) -> State {
    State {
        vault: std::fs::read(f.local.join("vault.pqd")).unwrap(),
        config: std::fs::read(f.local.join("vault.toml")).unwrap(),
        head: git(&f.local, &["rev-parse", "HEAD"]),
        index: std::fs::read(f.local.join(".git/index")).unwrap(),
    }
}
fn resolve(
    f: &Fixture,
    callback: &mut impl FnMut(&MergeConflict) -> Result<Option<ConflictResolution>, DiaryError>,
) -> Result<MergeResult, DiaryError> {
    git_pull_merge_with_resolver(
        &f.local,
        &f.config,
        &f.local.join("vault.pqd"),
        &KEY,
        callback,
    )
}
#[test]
fn delete_edit_choices_are_explicit_on_both_sides() {
    for local_deleted in [true, false] {
        for remote_choice in [true, false] {
            let f = Fixture::new(&[record(1, 1)]);
            if local_deleted {
                f.local(&[]);
                f.publish(&[record(1, 2)]);
            } else {
                f.local(&[record(1, 2)]);
                f.publish(&[]);
            }
            let before = state(&f);
            let deferred = f.pull().unwrap();
            assert_eq!(deferred.conflicts.len(), 1);
            assert_eq!(state(&f), before);
            assert!(
                git_pull_merge(&f.local, &f.config, &f.local.join("vault.pqd"), &KEY, true)
                    .is_err()
            );
            assert_eq!(state(&f), before);
            let mut called = 0;
            let result = resolve(&f, &mut |conflict| {
                called += 1;
                assert_eq!(conflict.local.is_none(), local_deleted);
                assert_eq!(conflict.remote.is_none(), !local_deleted);
                assert_eq!(state(&f), before);
                assert!(!f.local.join("vault.pqd.bak").exists());
                Ok(Some(if remote_choice {
                    ConflictResolution::KeepRemote
                } else {
                    ConflictResolution::KeepLocal
                }))
            })
            .unwrap();
            assert_eq!(called, 1);
            assert!(result.conflicts.is_empty());
            let deleted = if remote_choice {
                !local_deleted
            } else {
                local_deleted
            };
            let expected = if deleted { vec![] } else { vec![record(1, 2)] };
            assert_eq!(read_vault(&f.local.join("vault.pqd")).unwrap().1, expected);
        }
    }
}
#[test]
fn resolver_failure_and_changed_inputs_never_apply_the_merge() {
    for change in [
        "error",
        "vault",
        "metadata",
        "invalid_mac",
        "config",
        "head",
        "tracking",
        "attachment",
    ] {
        let f = Fixture::new(&[record(1, 1)]);
        if matches!(change, "metadata" | "invalid_mac") {
            f.local(&[record(1, 2)]);
            f.publish(&[]);
        } else {
            f.local(&[]);
            f.publish(&[record(1, 2)]);
        }
        let before = state(&f);
        let mut after = None;
        let result = resolve(&f, &mut |_| {
            match change {
                "error" => return Err(DiaryError::Git("prompt failed".into())),
                "vault" => f.local(&[record(2, 1)]),
                "metadata" => {
                    let mut changed = record(1, 2);
                    changed.legacy_flag = 1;
                    f.local(&[changed]);
                }
                "invalid_mac" => {
                    let path = f.local.join("vault.pqd");
                    let mut bytes = std::fs::read(&path).unwrap();
                    bytes[16] ^= 1;
                    std::fs::write(path, bytes).unwrap();
                }
                "config" => {
                    let mut bytes = before.config.clone();
                    bytes.extend_from_slice(b"\n# changed");
                    std::fs::write(f.local.join("vault.toml"), bytes).unwrap();
                }
                "head" => {
                    git(&f.local, &["commit", "--allow-empty", "-m", "concurrent"]);
                }
                "tracking" => {
                    let head = String::from_utf8(before.head.clone()).unwrap();
                    git(
                        &f.local,
                        &["update-ref", "refs/remotes/origin/main", head.trim()],
                    );
                }
                "attachment" => {
                    std::fs::create_dir(f.local.join(".attachments")).unwrap();
                    std::fs::write(f.local.join(".attachments/blob"), b"keep").unwrap();
                }
                _ => unreachable!(),
            }
            after = Some(state(&f));
            Ok(Some(ConflictResolution::KeepRemote))
        });
        assert!(result.is_err(), "{change}");
        assert_eq!(state(&f), after.unwrap_or(before), "{change}");
        assert!(!f.local.join("vault.pqd.bak").exists());
    }
}
#[test]
fn unverified_common_base_stops_with_manual_guidance_before_choices() {
    let f = Fixture::with_integrity(&[record(1, 1)], false);
    f.local(&[record(1, 1)]);
    git(&f.local, &["add", "vault.pqd"]);
    git(&f.local, &["commit", "-m", "authenticated local"]);
    f.publish(&[]);
    let before = state(&f);
    let error = resolve(&f, &mut |_| panic!("unverified history must not prompt")).unwrap_err();
    assert!(error.to_string().contains("preserve both copies"));
    assert!(error.to_string().contains("integrity"));
    assert_eq!(state(&f), before);
    assert!(!f.local.join("vault.pqd.bak").exists());
}
#[test]
fn resolved_commit_preserves_staging_and_rolls_back_on_hook_failure() {
    for reject in [false, true] {
        let f = Fixture::new(&[record(1, 1)]);
        f.local(&[]);
        f.publish(&[record(1, 2)]);
        std::fs::write(f.local.join("sentinel"), b"staged").unwrap();
        git(&f.local, &["add", "sentinel"]);
        if reject {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let hook = f.local.join(".git/hooks/pre-commit");
                std::fs::write(&hook, b"#!/bin/sh\nexit 1\n").unwrap();
                std::fs::set_permissions(hook, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            #[cfg(not(unix))]
            {
                continue;
            }
        }
        let before = state(&f);
        let result = resolve(&f, &mut |_| Ok(Some(ConflictResolution::KeepRemote)));
        if reject {
            assert!(result.is_err());
            assert_eq!(state(&f), before);
            assert_eq!(
                std::fs::read(f.local.join("vault.pqd.bak")).unwrap(),
                before.vault
            );
        } else {
            result.unwrap();
            assert_eq!(git(&f.local, &["show", ":sentinel"]), b"staged");
            assert_eq!(std::fs::read(f.local.join("sentinel")).unwrap(), b"staged");
            assert_eq!(
                git(&f.local, &["show", "HEAD:vault.pqd"]),
                std::fs::read(f.local.join("vault.pqd")).unwrap()
            );
            assert_eq!(git(&f.local, &["log", "-1", "--format=%an"]), b"test\n");
            assert_eq!(
                git(&f.local, &["log", "-1", "--format=%ae"]),
                b"test@localhost\n"
            );
            assert_eq!(
                String::from_utf8(git(&f.local, &["log", "-1", "--format=%B"]))
                    .unwrap()
                    .trim(),
                f.config.git.commit_message
            );
            assert_eq!(
                git(&f.local, &["diff", "--cached", "--name-only"]),
                b"sentinel\n"
            );
            assert_eq!(
                git(&f.local, &["show", "--format=", "--name-only", "HEAD"]),
                b"vault.pqd\n"
            );
            assert!(!f.local.join("vault.pqd.bak").exists());
        }
    }
}

#[test]
fn later_choice_error_preserves_all_records_and_metadata_only_changes_conflict() {
    let f = Fixture::new(&[record(1, 1), record(2, 1)]);
    f.local(&[]);
    let mut first = record(1, 1);
    first.legacy_flag = 1;
    let mut second = record(2, 1);
    second.legacy_key_block = vec![9];
    f.publish(&[first, second]);
    let before = state(&f);
    let mut choices = 0;
    let error = resolve(&f, &mut |conflict| {
        choices += 1;
        assert_eq!(conflict.uuid, [choices; 16]);
        if choices == 1 {
            Ok(Some(ConflictResolution::KeepRemote))
        } else {
            Err(DiaryError::Git("second prompt failed".into()))
        }
    })
    .unwrap_err();
    assert!(error.to_string().contains("second prompt"));
    assert_eq!(choices, 2);
    assert_eq!(state(&f), before);
    assert!(!f.local.join("vault.pqd.bak").exists());
}

#[test]
fn invalid_timestamp_and_tampered_working_snapshot_fail_before_prompt() {
    for corrupt in [false, true] {
        let mut f = Fixture::new(&[record(1, 1)]);
        f.local(&[]);
        f.publish(&[record(1, 2)]);
        if corrupt {
            let path = f.local.join("vault.pqd");
            let mut bytes = std::fs::read(&path).unwrap();
            bytes[16] ^= 1;
            std::fs::write(path, bytes).unwrap();
        } else {
            f.config.git.privacy.timestamp_fuzz_hours = u64::MAX;
        }
        let before = state(&f);
        assert!(resolve(&f, &mut |_| panic!("invalid input must not prompt")).is_err());
        assert_eq!(state(&f), before);
        assert!(!f.local.join("vault.pqd.bak").exists());
    }
}

#[test]
fn pull_records_both_parents_and_allows_ordinary_push() {
    let f = Fixture::new(&[record(1, 1)]);
    f.local(&[record(1, 1), record(2, 1)]);
    git(&f.local, &["add", "vault.pqd"]);
    git(&f.local, &["commit", "-m", "local"]);
    let local = git(&f.local, &["rev-parse", "HEAD"]);
    f.publish(&[record(1, 1), record(3, 1)]);
    let remote = git(&f.remote, &["rev-parse", "HEAD"]);
    f.pull().unwrap();
    assert_eq!(git(&f.local, &["rev-parse", "HEAD^1"]), local);
    assert_eq!(git(&f.local, &["rev-parse", "HEAD^2"]), remote);
    git(&f.local, &["push"]);
    let head = git(&f.local, &["rev-parse", "HEAD"]);
    let vault = std::fs::read(f.local.join("vault.pqd")).unwrap();
    let index = std::fs::read(f.local.join(".git/index")).unwrap();
    f.pull().unwrap();
    assert_eq!(git(&f.local, &["rev-parse", "HEAD"]), head);
    assert_eq!(std::fs::read(f.local.join("vault.pqd")).unwrap(), vault);
    assert_eq!(std::fs::read(f.local.join(".git/index")).unwrap(), index);
}

#[test]
fn unchanged_records_still_record_remote_ancestry() {
    let f = Fixture::new(&[record(1, 1)]);
    let local = git(&f.local, &["rev-parse", "HEAD"]);
    f.publish(&[record(1, 1)]);
    let remote = git(&f.remote, &["rev-parse", "HEAD"]);
    let bytes = std::fs::read(f.local.join("vault.pqd")).unwrap();
    f.pull().unwrap();
    assert_eq!(git(&f.local, &["rev-parse", "HEAD^1"]), local);
    assert_eq!(git(&f.local, &["rev-parse", "HEAD^2"]), remote);
    assert_eq!(std::fs::read(f.local.join("vault.pqd")).unwrap(), bytes);
}

#[test]
fn unsupported_remote_paths_and_existing_operation_state_are_preserved() {
    for obstacle in [
        "remote-file",
        "MERGE_HEAD",
        "MERGE_MSG",
        "MERGE_MODE",
        "index.lock",
        "rebase-merge",
        "staged-vault",
    ] {
        let f = Fixture::new(&[record(1, 1)]);
        f.publish(&[record(1, 1), record(2, 1)]);
        if obstacle == "remote-file" {
            std::fs::write(f.remote.join("other\nfile"), b"remote data").unwrap();
            git(&f.remote, &["add", "."]);
            git(&f.remote, &["commit", "-m", "unsupported"]);
            git(&f.remote, &["push"]);
        } else if obstacle == "staged-vault" {
            f.local(&[record(1, 3)]);
            git(&f.local, &["add", "vault.pqd"]);
            f.local(&[record(1, 1)]);
        } else {
            std::fs::write(f.local.join(".git").join(obstacle), b"existing state").unwrap();
        }
        let before = state(&f);
        assert!(f.pull().is_err(), "{obstacle}");
        assert_eq!(state(&f), before, "{obstacle}");
        assert!(!f.local.join("vault.pqd.bak").exists());
        if !matches!(obstacle, "remote-file" | "staged-vault") {
            assert_eq!(
                std::fs::read(f.local.join(".git").join(obstacle)).unwrap(),
                b"existing state"
            );
        }
    }
}

#[test]
fn staged_add_modify_delete_and_unstaged_files_survive_merge() {
    let f = Fixture::new(&[record(1, 1)]);
    for path in ["modified", "deleted"] {
        std::fs::write(f.local.join(path), b"base").unwrap();
    }
    git(&f.local, &["add", "."]);
    git(&f.local, &["commit", "-m", "local files"]);
    std::fs::write(f.local.join("modified"), b"staged modification").unwrap();
    std::fs::write(f.local.join("added"), b"staged addition").unwrap();
    git(&f.local, &["rm", "deleted"]);
    git(&f.local, &["add", "modified", "added"]);
    std::fs::write(f.local.join("modified"), b"unstaged modification").unwrap();
    let staged = git(&f.local, &["diff", "--cached", "--binary"]);
    f.publish(&[record(1, 1), record(2, 1)]);
    f.pull().unwrap();
    assert_eq!(git(&f.local, &["diff", "--cached", "--binary"]), staged);
    assert_eq!(
        std::fs::read(f.local.join("modified")).unwrap(),
        b"unstaged modification"
    );
    assert_eq!(git(&f.local, &["show", "HEAD:modified"]), b"base");
    assert_eq!(git(&f.local, &["show", "HEAD:deleted"]), b"base");
    assert_eq!(
        git(
            &f.local,
            &[
                "diff-tree",
                "--no-commit-id",
                "--name-only",
                "-r",
                "HEAD^1",
                "HEAD"
            ]
        ),
        b"vault.pqd\n"
    );
}

#[test]
fn linked_worktree_with_spaces_uses_its_effective_index() {
    let mut f = Fixture::new(&[record(1, 1)]);
    let linked = f._dir.path().join("linked worktree");
    git(
        &f.local,
        &["worktree", "add", "-b", "linked", linked.to_str().unwrap()],
    );
    git(&linked, &["branch", "--set-upstream-to", "origin/main"]);
    let original_index = std::fs::read(f.local.join(".git/index")).unwrap();
    f.publish(&[record(1, 1), record(2, 1)]);
    let main = f.local.clone();
    f.local = linked;
    f.pull().unwrap();
    assert_eq!(
        std::fs::read(main.join(".git/index")).unwrap(),
        original_index
    );
    assert_eq!(
        git(&f.local, &["rev-parse", "HEAD^2"]),
        git(&f.remote, &["rev-parse", "HEAD"])
    );
}

#[cfg(unix)]
fn install_hook(f: &Fixture, name: &str, script: &str) {
    use std::os::unix::fs::PermissionsExt;
    let path = f.local.join(".git/hooks").join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
#[cfg(unix)]
fn nonzero_after_head_update_is_not_rolled_back() {
    let f = Fixture::new(&[record(1, 1)]);
    f.publish(&[record(1, 1), record(2, 1)]);
    install_hook(&f, "post-commit", "kill -TERM \"$PPID\"");
    f.pull().unwrap();
    assert_eq!(
        git(&f.local, &["rev-parse", "HEAD^2"]),
        git(&f.remote, &["rev-parse", "HEAD"])
    );
    assert_eq!(
        git(&f.local, &["show", "HEAD:vault.pqd"]),
        std::fs::read(f.local.join("vault.pqd")).unwrap()
    );
    assert!(git(&f.local, &["diff", "--cached", "--name-only"]).is_empty());
}

#[test]
#[cfg(unix)]
fn committed_index_publication_failure_retains_recovery_and_vault() {
    let f = Fixture::new(&[record(1, 1)]);
    f.publish(&[record(1, 1), record(2, 1)]);
    let before = state(&f);
    install_hook(&f, "post-commit", "mv .git/index .git/index.saved\nmkdir .git/index\nprintf blocked > .git/index/obstacle\nprintf hook-owned > .git/MERGE_MSG");
    let error = f.pull().unwrap_err().to_string();
    assert!(
        error.contains("commit created; index recovery required"),
        "{error}"
    );
    assert_ne!(git(&f.local, &["rev-parse", "HEAD"]), before.head);
    assert_eq!(
        git(&f.local, &["show", "HEAD:vault.pqd"]),
        std::fs::read(f.local.join("vault.pqd")).unwrap()
    );
    assert_eq!(
        std::fs::read(f.local.join("vault.pqd.bak")).unwrap(),
        before.vault
    );
    assert_eq!(
        std::fs::read(f.local.join(".git/index.saved")).unwrap(),
        before.index
    );
    assert!(f.local.join(".git/index.lock").is_file());
    assert_eq!(
        std::fs::read(f.local.join(".git/MERGE_MSG")).unwrap(),
        b"hook-owned"
    );
}

#[test]
#[cfg(unix)]
fn hook_modified_commit_is_not_reported_as_rolled_back() {
    let f = Fixture::new(&[record(1, 1)]);
    f.publish(&[record(1, 1), record(2, 1)]);
    let before = state(&f);
    install_hook(
        &f,
        "pre-commit",
        "printf hook > hook-file\ngit add hook-file",
    );
    let error = f.pull().unwrap_err().to_string();
    assert!(error.contains("outcome uncertain or unexpected"), "{error}");
    assert_ne!(git(&f.local, &["rev-parse", "HEAD"]), before.head);
    assert_eq!(
        std::fs::read(f.local.join(".git/index")).unwrap(),
        before.index
    );
    assert_eq!(
        git(&f.local, &["show", "HEAD:vault.pqd"]),
        std::fs::read(f.local.join("vault.pqd")).unwrap()
    );
    assert_eq!(git(&f.local, &["show", "HEAD:hook-file"]), b"hook");
    assert!(f.local.join("vault.pqd.bak").exists());
    assert!(f.local.join(".git/index.lock").exists());
}

#[test]
#[cfg(unix)]
fn postcommit_backup_cleanup_failure_remains_success() {
    let f = Fixture::new(&[record(1, 1)]);
    f.publish(&[record(1, 1), record(2, 1)]);
    install_hook(
        &f,
        "post-commit",
        "mv vault.pqd.bak saved-backup\nmkdir vault.pqd.bak\nprintf retained > vault.pqd.bak/keep",
    );
    f.pull().unwrap();
    assert_eq!(
        git(&f.local, &["show", "HEAD:vault.pqd"]),
        std::fs::read(f.local.join("vault.pqd")).unwrap()
    );
    assert_eq!(
        std::fs::read(f.local.join("vault.pqd.bak/keep")).unwrap(),
        b"retained"
    );
    assert!(!f.local.join(".git/index.lock").exists());
}

#[test]
fn unmerged_index_is_rejected_without_backup_or_mutation() {
    let f = Fixture::new(&[record(1, 1)]);
    f.publish(&[record(1, 1), record(2, 1)]);
    let blob = String::from_utf8(git(&f.local, &["rev-parse", "HEAD:vault.toml"])).unwrap();
    let mut child = std::process::Command::new("git")
        .current_dir(&f.local)
        .args(["update-index", "--index-info"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            format!(
                "100644 {} 1\tunmerged\n100644 {} 2\tunmerged\n",
                blob.trim(),
                blob.trim()
            )
            .as_bytes(),
        )
        .unwrap();
    assert!(child.wait().unwrap().success());
    let before = state(&f);
    assert!(f.pull().unwrap_err().to_string().contains("unmerged index"));
    assert_eq!(state(&f), before);
    assert!(!f.local.join("vault.pqd.bak").exists());
}
