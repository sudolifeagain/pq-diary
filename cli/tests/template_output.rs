//! Template output must be complete, fallible, and read-only.
use pq_diary_core::{crypto::kdf::Argon2Params, vault::init::VaultManager, DiaryCore};
use secrecy::{SecretBox, SecretString};
use std::process::{Command, Stdio};

#[test]
fn template_output_preserves_bytes_and_reports_device_failure() {
    let dir = tempfile::tempdir().expect("test directory");
    VaultManager::new(dir.path().to_path_buf())
        .expect("manager")
        .with_kdf_params(Argon2Params {
            memory_cost_kb: 8,
            time_cost: 1,
            parallelism: 1,
        })
        .init_vault("v", b"password")
        .expect("init");
    let vault_dir = dir.path().join("v");
    let vault_path = vault_dir.join("vault.pqd");
    let password = || -> SecretString { SecretBox::new(Box::from("password")) };
    let mut core = DiaryCore::new(vault_path.to_str().expect("path")).expect("core");
    core.unlock(password()).expect("unlock");
    let body = "private template body: 振り返り";
    core.new_template("weekly", "weekly body").expect("weekly");
    core.new_template("daily", body).expect("daily");
    core.lock();
    let before = std::fs::read(&vault_path).expect("snapshot");
    let config_before = std::fs::read(vault_dir.join("vault.toml")).expect("config");
    for (args, expected) in [
        (vec!["template", "list"], "daily\nweekly\n"),
        (vec!["template", "show", "daily"], body),
    ] {
        let command = || {
            let mut command = Command::new(env!("CARGO_BIN_EXE_pq-diary"));
            command
                .arg("--vault")
                .arg(&vault_dir)
                .args(["--password", "password"])
                .args(&args)
                .env("HOME", dir.path())
                .env("PQ_DIARY_HOME", dir.path())
                .stdin(Stdio::null());
            command
        };
        let output = command().output().expect("CLI");
        assert!(output.status.success(), "{:?}", output);
        assert_eq!(output.stdout, expected.as_bytes());
        #[cfg(unix)]
        if std::path::Path::new("/dev/full").exists() {
            let full = std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .expect("full device");
            let output = command().stdout(Stdio::from(full)).output().expect("CLI");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                !output.status.success(),
                "output failure must fail the command"
            );
            assert_ne!(output.status.code(), Some(101), "must not panic: {stderr}");
            assert!(stderr.contains("template output"), "{stderr}");
            assert!(!stderr.contains(body), "must not expose template body");
        }
        assert_eq!(std::fs::read(&vault_path).expect("vault"), before);
        assert_eq!(
            std::fs::read(vault_dir.join("vault.toml")).expect("config"),
            config_before
        );
    }
    core.unlock(password()).expect("reopen");
    assert_eq!(core.get_template("daily").expect("daily").body, body);
    assert_eq!(core.list_templates().expect("templates").len(), 2);
    core.lock();
}
