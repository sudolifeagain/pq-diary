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
