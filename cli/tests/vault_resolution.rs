//! Exercise real CLI dispatch with isolated app homes and distinguishable vaults.
use std::path::Path;
use std::process::{Command, Output, Stdio};

use pq_diary_core::{
    crypto::kdf::Argon2Params,
    vault::{config::AppConfig, init::VaultManager},
    DiaryCore,
};
use secrecy::SecretString;

fn run(root: &Path, cwd: &Path, vault: Option<&Path>, args: &[&str], input: &str) -> Output {
    use std::io::Write;
    let mut command = Command::new(env!("CARGO_BIN_EXE_pq-diary"));
    command
        .env("PQ_DIARY_HOME", root)
        .current_dir(cwd)
        .args(["--password", "test-password"]);
    if let Some(vault) = vault {
        command.arg("--vault").arg(vault);
    }
    let mut child = command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn fixture(base: &Path, name: &str, title: &str) -> std::path::PathBuf {
    VaultManager::new(base.to_path_buf())
        .unwrap()
        .with_kdf_params(Argon2Params {
            memory_cost_kb: 8,
            time_cost: 1,
            parallelism: 1,
        })
        .init_vault(name, b"test-password")
        .unwrap();
    let file = base.join(name).join("vault.pqd");
    let mut core = DiaryCore::new(file.to_str().unwrap()).unwrap();
    core.unlock(SecretString::from("test-password")).unwrap();
    core.new_entry(title, "body", vec![]).unwrap();
    file
}

#[test]
fn default_dispatch_uses_configured_vault_not_cwd() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    std::fs::create_dir_all(&root).unwrap();
    let chosen = fixture(&root.join("vaults"), "chosen", "configured-entry");
    let decoy = fixture(temp.path(), "cwd", "cwd-decoy");
    let before = std::fs::read(&decoy).unwrap();
    let mut config = AppConfig::default();
    config.app.default_vault = "chosen".into();
    config.to_file(&root.join("config.toml")).unwrap();
    let cwd = decoy.parent().unwrap();

    success(run(
        &root,
        cwd,
        None,
        &["new", "-t", "new-default", "-b", "body"],
        "",
    ));
    let list = success(run(&root, cwd, None, &["list"], ""));
    assert!(list.contains("configured-entry") && list.contains("new-default"));
    assert!(!list.contains("cwd-decoy"));
    assert!(success(run(&root, cwd, None, &["info"], "")).contains("Entries:        2"));
    success(run(&root, cwd, None, &["attachment", "list"], ""));
    let export = temp.path().join("export");
    std::fs::create_dir(&export).unwrap();
    success(run(
        &root,
        cwd,
        None,
        &["export", export.to_str().unwrap()],
        "y\n",
    ));
    let contents: String = std::fs::read_dir(export)
        .unwrap()
        .map(|entry| std::fs::read_to_string(entry.unwrap().path()).unwrap())
        .collect();
    assert!(contents.contains("configured-entry") && contents.contains("new-default"));
    assert!(!contents.contains("cwd-decoy"));
    assert_eq!(std::fs::read(&decoy).unwrap(), before);
    assert!(success(run(&root, cwd, Some(&chosen), &["list"], "")).contains("new-default"));
}

#[test]
fn init_then_new_without_vault_works_from_unrelated_directory() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    success(run(&root, temp.path(), None, &["init"], ""));
    success(run(
        &root,
        temp.path(),
        None,
        &["new", "-t", "after-init", "-b", "body"],
        "",
    ));
    assert!(success(run(&root, temp.path(), None, &["list"], "")).contains("after-init"));
    success(run(&root, temp.path(), None, &["info"], ""));
    assert!(!temp.path().join("vault.pqd").exists());
}

#[test]
fn explicit_custom_file_entries_and_info_preserve_target_identity() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("unused-home");
    let normal = fixture(temp.path(), "normal", "sibling-only");
    let other = fixture(temp.path(), "other", "custom-only");
    let custom = normal.with_file_name("custom.pqd");
    std::fs::copy(other, &custom).unwrap();
    let sibling_before = std::fs::read(&normal).unwrap();
    let cwd = normal.parent().unwrap();
    success(run(
        &root,
        cwd,
        Some(Path::new("custom.pqd")),
        &["new", "-t", "custom-added", "-b", "body"],
        "",
    ));
    assert!(success(run(&root, cwd, Some(&custom), &["info"], "")).contains("Entries:        2"));
    let list = success(run(&root, cwd, Some(&custom), &["list"], ""));
    assert!(list.contains("custom-only") && list.contains("custom-added"));
    assert!(!list.contains("sibling-only"));
    assert_eq!(std::fs::read(normal).unwrap(), sibling_before);
}

#[test]
fn directory_and_standard_file_select_same_vault_even_with_pqd_directory_suffix() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("unused-home");
    let file = fixture(temp.path(), "directory.pqd", "directory-entry");
    for target in [&file, file.parent().unwrap()] {
        let list = success(run(&root, temp.path(), Some(target), &["list"], ""));
        assert!(list.contains("directory-entry"));
        success(run(&root, temp.path(), Some(target), &["info"], ""));
    }
}

#[test]
fn directory_only_operations_reject_custom_file_without_touching_either_vault() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("unused-home");
    let normal = fixture(temp.path(), "normal", "sibling-only");
    let custom = normal.with_file_name("custom.pqd");
    std::fs::copy(&normal, &custom).unwrap();
    let before = std::fs::read(&normal).unwrap();
    let input = temp.path().join("input");
    std::fs::create_dir(&input).unwrap();
    std::fs::write(input.join("entry.md"), "# Imported\nbody").unwrap();
    let attachment = input.join("entry.md");
    let cases = [
        vec!["change-password"],
        vec!["attachment", "list"],
        vec!["legacy", "list"],
        vec!["git-status"],
        vec!["export", input.to_str().unwrap()],
        vec!["import", input.to_str().unwrap()],
        vec![
            "new",
            "-t",
            "must-not-exist",
            "-b",
            "body",
            "--attach",
            attachment.to_str().unwrap(),
        ],
    ];
    for args in cases {
        let output = run(&root, temp.path(), Some(&custom), &args, "");
        assert!(!output.status.success(), "{args:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("custom vault filename is unsupported"),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(std::fs::read(&normal).unwrap(), before);
        assert_eq!(std::fs::read(&custom).unwrap(), before);
    }
    let output = run(&root, temp.path(), Some(&custom), &["init"], "");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("does not support --vault"));
    assert!(!root.exists());
}

#[test]
fn missing_or_invalid_default_config_never_falls_back_to_cwd() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    let decoy = fixture(temp.path(), "cwd", "cwd-decoy");
    let before = std::fs::read(&decoy).unwrap();
    for invalid_config in [false, true] {
        if invalid_config {
            std::fs::create_dir(&root).unwrap();
            std::fs::write(root.join("config.toml"), "invalid = [toml").unwrap();
        }
        for args in [vec!["list"], vec!["new", "-t", "unwanted", "-b", "body"]] {
            let output = run(&root, decoy.parent().unwrap(), None, &args, "");
            assert!(!output.status.success());
            assert!(String::from_utf8_lossy(&output.stderr).contains("config.toml"));
            assert_eq!(std::fs::read(&decoy).unwrap(), before);
        }
    }
}

#[test]
fn configured_default_rejects_path_escape_without_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    std::fs::create_dir_all(&root).unwrap();
    let outside = fixture(&root, "outside", "outside-entry");
    let before = std::fs::read(&outside).unwrap();
    let absolute = outside.parent().unwrap().to_str().unwrap();
    for name in [
        "",
        ".",
        "..",
        "../outside",
        "nested/vault",
        "nested\\vault",
        absolute,
    ] {
        let mut config = AppConfig::default();
        config.app.default_vault = name.into();
        config.to_file(&root.join("config.toml")).unwrap();
        let config_before = std::fs::read(root.join("config.toml")).unwrap();
        for args in [vec!["list"], vec!["new", "-t", "unwanted", "-b", "body"]] {
            let output = run(&root, temp.path(), None, &args, "");
            assert!(!output.status.success(), "accepted {name:?}");
            assert!(String::from_utf8_lossy(&output.stderr)
                .contains("Invalid config.toml default_vault"));
            assert_eq!(std::fs::read(&outside).unwrap(), before);
            assert_eq!(
                std::fs::read(root.join("config.toml")).unwrap(),
                config_before
            );
        }
    }
}

#[test]
fn configured_default_preserves_unicode_and_spaces() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("home");
    std::fs::create_dir_all(&root).unwrap();
    let name = "日記 archive";
    fixture(&root.join("vaults"), name, "unicode-default");
    let mut config = AppConfig::default();
    config.app.default_vault = name.into();
    config.to_file(&root.join("config.toml")).unwrap();
    let list = success(run(&root, temp.path(), None, &["list"], ""));
    assert!(list.contains("unicode-default"));
}

#[test]
fn export_preconditions_do_not_require_default_configuration() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("missing-home");
    let out = temp.path().join("out");
    std::fs::create_dir(&out).unwrap();
    let cases = [
        (
            vec!["--claude", "export", out.to_str().unwrap()],
            "export is not permitted with --claude",
        ),
        (
            vec!["export", root.to_str().unwrap()],
            "Directory does not exist",
        ),
    ];
    for (args, expected) in cases {
        let output = run(&root, temp.path(), None, &args, "");
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains(expected), "expected {expected}, got {error}");
        assert!(
            !error.contains("続行しますか"),
            "must fail before prompting"
        );
        assert!(!root.exists());
        assert_eq!(std::fs::read_dir(&out).unwrap().count(), 0);
    }
}
