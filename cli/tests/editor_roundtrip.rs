//! Real external-editor round-trip regression coverage.
#![cfg(unix)]

use pq_diary_core::{crypto::kdf::Argon2Params, vault::init::VaultManager, DiaryCore};
use secrecy::SecretString;
use std::process::Command;

#[test]
fn noop_editor_preserves_stored_body_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    VaultManager::new(dir.path().to_path_buf())
        .expect("manager")
        .with_kdf_params(Argon2Params {
            memory_cost_kb: 8,
            time_cost: 1,
            parallelism: 1,
        })
        .init_vault("roundtrip", b"test-password")
        .expect("init vault");
    let vault = dir.path().join("roundtrip/vault.pqd");
    let mut core = DiaryCore::new(vault.to_str().expect("utf8 path")).expect("core");
    core.unlock(SecretString::from("test-password"))
        .expect("unlock");
    let body = "line1\r\nline2\n\nX\n\n";
    let id = core
        .new_entry("Title", body, vec!["tag".to_string()])
        .expect("new entry");
    core.lock();
    drop(core);

    let output = Command::new(env!("CARGO_BIN_EXE_pq-diary"))
        .arg("--vault")
        .arg(&vault)
        .args(["edit", &id])
        .env("PQ_DIARY_PASSWORD", "test-password")
        // The POSIX utility is in /usr/bin on macOS. Resolve it through PATH,
        // just as a configured editor name is resolved by the real CLI.
        .env("EDITOR", "true")
        .output()
        .expect("run CLI");
    assert!(
        output.status.success(),
        "CLI edit failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut core = DiaryCore::new(vault.to_str().expect("utf8 path")).expect("reopen");
    core.unlock(SecretString::from("test-password"))
        .expect("unlock again");
    let (_, entry) = core.get_entry(&id).expect("read entry");
    assert_eq!(entry.body.as_bytes(), body.as_bytes());
    assert_eq!(entry.title, "Title");
    assert_eq!(entry.tags, ["tag"]);
}
