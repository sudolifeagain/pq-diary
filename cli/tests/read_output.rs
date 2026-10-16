//! Read commands report output-device failures without panics or vault changes.
use pq_diary_core::{crypto::kdf::Argon2Params, vault::init::VaultManager, DiaryCore};
use secrecy::SecretBox;
use std::process::{Command, Stdio};

#[test]
fn read_commands_preserve_output_and_report_device_failure() {
    let dir = tempfile::tempdir().expect("tempdir");
    VaultManager::new(dir.path().to_path_buf())
        .expect("manager")
        .with_kdf_params(Argon2Params {
            memory_cost_kb: 8,
            time_cost: 1,
            parallelism: 1,
        })
        .init_vault("v", b"password")
        .expect("vault");
    let vault = dir.path().join("v");
    let path = vault.join("vault.pqd");
    let mut core = DiaryCore::new(path.to_str().expect("path")).expect("core");
    core.unlock(SecretBox::new(Box::from("password")))
        .expect("unlock");
    let id = core
        .new_entry(
            "read fixture",
            "private body without newline",
            vec!["tag".into()],
        )
        .expect("entry");
    core.lock();
    pq_diary_core::git::git_init(&vault, None).expect("git init");
    let empty_id = core_id_without_attachment(&path);
    let source = dir.path().join("fixture.txt");
    std::fs::write(&source, b"synthetic attachment").expect("fixture");
    pq_diary_core::attachment::add_attachment(
        &vault,
        &SecretBox::new(Box::from("password")),
        &id,
        &source,
    )
    .expect("attachment");
    let before = std::fs::read(&path).expect("snapshot");
    let config = std::fs::read(vault.join("vault.toml")).expect("config");
    for args in [
        vec!["list"],
        vec!["list", "--number", "0"],
        vec!["info"],
        vec!["info", "--security"],
        vec!["attachment", "list"],
        vec!["attachment", "list", &empty_id],
        vec!["vault", "list"],
        vec!["legacy", "list"],
        vec!["git-status"],
        vec!["show", &id],
        vec!["search", "private"],
        vec!["search", "missing"],
        vec!["search", "private", "--count"],
        vec!["stats"],
        vec!["stats", "--json"],
        vec!["stats", "--heatmap"],
    ] {
        let command = || {
            let mut c = Command::new(env!("CARGO_BIN_EXE_pq-diary"));
            c.arg("--vault")
                .arg(if args[0] == "vault" {
                    dir.path()
                } else {
                    &vault
                })
                .args(["--password", "password"])
                .args(&args)
                .env("HOME", dir.path())
                .env("PQ_DIARY_HOME", dir.path())
                .stdin(Stdio::null());
            c
        };
        let output = command().output().expect("CLI");
        assert!(output.status.success(), "{args:?}: {output:?}");
        if args == ["attachment", "list", &empty_id] {
            assert_eq!(output.stdout, b"No attachments.\n");
        }
        if args == ["search", "missing"] {
            assert_eq!(output.stdout, b"No matches found\n");
        }
        if args == ["search", "private", "--count"] {
            assert_eq!(output.stdout, b"1 entries matched\n");
        }
        #[cfg(target_os = "linux")]
        if !output.stdout.is_empty() {
            let full = std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .expect("full");
            let failed = command()
                .stdout(Stdio::from(full))
                .output()
                .expect("CLI full");
            let stderr = String::from_utf8_lossy(&failed.stderr);
            assert!(!failed.status.success(), "{args:?} must fail");
            assert_ne!(
                failed.status.code(),
                Some(101),
                "{args:?} panicked: {stderr}"
            );
            assert!(!stderr.contains("private body"));
        }
        assert_eq!(std::fs::read(&path).expect("vault"), before);
        assert_eq!(
            std::fs::read(vault.join("vault.toml")).expect("config"),
            config
        );
    }
    core.unlock(SecretBox::new(Box::from("password")))
        .expect("reopen");
    assert_eq!(
        core.get_entry(&id).expect("entry").1.body,
        "private body without newline"
    );
    core.lock();
}

fn core_id_without_attachment(path: &std::path::Path) -> String {
    let mut core = DiaryCore::new(path.to_str().expect("path")).expect("core");
    core.unlock(SecretBox::new(Box::from("password")))
        .expect("unlock");
    let id = core
        .new_entry("empty", "no attachment", vec![])
        .expect("entry");
    core.lock();
    id
}
