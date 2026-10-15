//! Process-isolated contract: denying policy wins before password acquisition.
use pq_diary_core::{crypto::kdf::Argon2Params, policy::AccessPolicy, vault::init::VaultManager};
use std::process::{Command, Stdio};

#[test]
fn ordinary_cli_commands_deny_without_credentials_or_vault_data() {
    let dir = tempfile::tempdir().expect("tempdir");
    VaultManager::new(dir.path().to_path_buf())
        .expect("manager")
        .with_kdf_params(Argon2Params {
            memory_cost_kb: 8,
            time_cost: 1,
            parallelism: 1,
        })
        .create_vault("denied", b"synthetic-password", AccessPolicy::None)
        .expect("create vault");
    let vault = dir.path().join("denied");
    std::fs::remove_file(vault.join("vault.pqd")).expect("remove encrypted data");
    let commands: &[&[&str]] = &[
        &["list"],
        &["show", "abcd"],
        &["edit", "abcd"],
        &["delete", "abcd", "--force"],
        &["template", "add", "name"],
        &["template", "list"],
        &["template", "show", "name"],
        &["template", "delete", "name", "--force"],
        &["today"],
        &["search", "x"],
        &["stats"],
    ];
    for args in commands {
        let output = Command::new(env!("CARGO_BIN_EXE_pq-diary"))
            .args(["--claude", "--vault"])
            .arg(&vault)
            .args(*args)
            .env_remove("PQ_DIARY_PASSWORD")
            .env("PQ_DIARY_HOME", dir.path())
            .stdin(Stdio::null())
            .output()
            .expect("run CLI");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{args:?} must fail");
        assert!(stderr.contains("Access denied"), "{args:?}: {stderr}");
        assert!(!stderr.contains("Password:"), "{args:?}: {stderr}");
        assert!(output.stdout.is_empty(), "{args:?}: unexpected output");
    }
}
