//! Regression for a failed template overwrite through the real CLI.

#[cfg(target_os = "linux")]
#[test]
fn failed_template_overwrite_preserves_original_vault() {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};

    use pq_diary_core::{
        attachment, crypto::kdf::Argon2Params, vault::init::VaultManager, DiaryCore,
    };
    use secrecy::{SecretBox, SecretString};

    let dir = tempfile::tempdir().expect("test directory");
    let manager = VaultManager::new(dir.path().to_path_buf())
        .expect("manager")
        .with_kdf_params(Argon2Params {
            memory_cost_kb: 8,
            time_cost: 1,
            parallelism: 1,
        });
    manager.init_vault("v", b"password").expect("init");
    let vault_dir = dir.path().join("v");
    let vault_path = vault_dir.join("vault.pqd");
    let password = || -> SecretString { SecretBox::new(Box::from("password")) };
    let mut core = DiaryCore::new(vault_path.to_str().expect("UTF-8 path")).expect("core");
    core.unlock(password()).expect("unlock");
    core.new_template("daily", "original template")
        .expect("daily");
    core.new_template("weekly", "unrelated template")
        .expect("weekly");
    let entry_id = core
        .new_entry("keep", "original entry", vec![])
        .expect("entry");
    core.lock();

    let source = dir.path().join("fixture.txt");
    std::fs::write(&source, b"synthetic attachment\n").expect("attachment source");
    attachment::add_attachment(&vault_dir, &password(), &entry_id, &source).expect("attachment");
    let before = std::fs::read(&vault_path).expect("vault snapshot");
    let config_before = std::fs::read(vault_dir.join("vault.toml")).expect("config snapshot");
    let blob_path = std::fs::read_dir(vault_dir.join(".attachments"))
        .expect("blob directory")
        .next()
        .expect("one blob")
        .expect("blob")
        .path();
    let blob_before = std::fs::read(&blob_path).expect("blob snapshot");
    assert!(
        before.len() < 128 * 1024,
        "old vault must fit the file-size limit"
    );

    // The editor output fits RLIMIT_FSIZE exactly. The enlarged encrypted vault
    // cannot fit, but deleting the original template first would still succeed.
    let replacement = dir.path().join("replacement.txt");
    std::fs::write(&replacement, vec![b'x'; 128 * 1024]).expect("replacement");
    let editor = dir.path().join("editor.sh");
    std::fs::write(&editor, "#!/bin/sh\ncat \"$PQ_DIARY_TEST_BODY\" > \"$1\"\n").expect("editor");
    std::fs::set_permissions(&editor, std::fs::Permissions::from_mode(0o700)).expect("editor mode");

    // Isolate the limit and ignored SIGXFSZ in a child. No process-global limits,
    // signals, environment variables, or real home-directory files are changed.
    let mut child = Command::new("/bin/sh")
        .args([
            "-c",
            "trap '' XFSZ; ulimit -f 256; exec \"$@\"",
            "template-overwrite-test",
        ])
        .arg(env!("CARGO_BIN_EXE_pq-diary"))
        .arg("--vault")
        .arg(&vault_dir)
        .args(["--password", "password", "template", "add", "daily"])
        .env("HOME", dir.path())
        .env("PQ_DIARY_HOME", dir.path())
        .env("EDITOR", &editor)
        .env("PQ_DIARY_TEST_BODY", &replacement)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("CLI child");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(b"y\n")
        .expect("confirm overwrite");
    let output = child.wait_with_output().expect("CLI result");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "replacement write must fail");
    assert!(
        stderr.contains("File too large"),
        "expected file-size failure: {stderr}"
    );
    assert!(
        !stderr.contains("Editor failed"),
        "editor must finish before failure: {stderr}"
    );
    assert!(
        std::fs::read(&vault_path).expect("original vault") == before,
        "failed replacement must leave the complete original vault byte-for-byte unchanged"
    );
    assert_eq!(
        std::fs::read(vault_dir.join("vault.toml")).expect("config"),
        config_before
    );
    assert_eq!(std::fs::read(&blob_path).expect("blob"), blob_before);
    assert!(
        !vault_dir.join("vault.pqd.tmp").exists(),
        "failed write must clean its temporary file"
    );

    core.unlock(password()).expect("reopen original vault");
    assert_eq!(
        core.get_template("daily").expect("daily remains").body,
        "original template"
    );
    assert_eq!(
        core.get_template("weekly").expect("weekly remains").body,
        "unrelated template"
    );
    assert_eq!(core.list_templates().expect("templates").len(), 2);
    assert_eq!(
        core.get_entry(&entry_id).expect("entry remains").1.body,
        "original entry"
    );
    core.lock();
    let extracted = dir.path().join("extracted.txt");
    attachment::extract_attachment(
        &vault_dir,
        &password(),
        &entry_id,
        "fixture.txt",
        &extracted,
    )
    .expect("attachment remains readable");
    assert_eq!(
        std::fs::read(extracted).expect("extracted"),
        b"synthetic attachment\n"
    );
}
