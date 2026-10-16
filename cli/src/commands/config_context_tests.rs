use super::*;
use clap::Parser as _;
use pq_diary_core::{vault::config::AppConfig, DiaryError};
use std::io::{self, BufRead, Read};
use std::path::Path;

fn cli_at(path: &Path, command: &str) -> Cli {
    Cli::try_parse_from([
        "pq-diary",
        "--vault",
        path.to_str().unwrap(),
        "--password",
        "password",
        command,
    ])
    .unwrap()
}

fn assert_io(error: &anyhow::Error, kind: io::ErrorKind) {
    assert_eq!(
        error
            .chain()
            .find_map(|cause| cause.downcast_ref::<io::Error>())
            .unwrap()
            .kind(),
        kind
    );
}

// Each HOME/cwd-dependent case runs alone in a child test process, without
// mutating the environment or current directory of the parallel parent suite.
fn isolated_home(test: &str) -> bool {
    const CHILD: &str = "PQ_DIARY_CONFIG_CONTEXT_TEST";
    if std::env::var(CHILD).as_deref() == Ok(test) {
        return false;
    }
    let dir = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            &format!("commands::config_context_tests::{test}"),
            "--nocapture",
        ])
        .env(CHILD, test)
        .env("PQ_DIARY_HOME", dir.path().join("app"))
        .env_remove("PQ_DIARY_PASSWORD")
        .current_dir(dir.path())
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("1 passed; 0 failed"));
    true
}

struct FailedInput;
impl Read for FailedInput {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "fixture input unavailable",
        ))
    }
}
impl BufRead for FailedInput {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "fixture input unavailable",
        ))
    }
    fn consume(&mut self, _: usize) {}
}

#[test]
fn config_context_full_confirmation_preserves_io_before_creation() {
    let dir = tempfile::tempdir().unwrap();
    let cli = cli_at(dir.path(), "info");
    let error = cmd_vault_create_impl(&cli, "new", Some("full"), &mut FailedInput, |_| {
        panic!("manager must not be opened before confirmation succeeds")
    })
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "Failed to read input: fixture input unavailable"
    );
    assert_io(&error, io::ErrorKind::BrokenPipe);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn config_context_delete_confirmation_preserves_io_and_vault() {
    let dir = tempfile::tempdir().unwrap();
    let vault = test_support::setup_vault(&dir);
    let original = std::fs::read(vault.join("vault.pqd")).unwrap();
    let config = std::fs::read(vault.join("vault.toml")).unwrap();
    let cli = cli_at(dir.path(), "info");
    let error = cmd_vault_delete_impl(&cli, "v", true, &mut FailedInput).unwrap_err();
    assert_eq!(
        error.to_string(),
        "Failed to read input: fixture input unavailable"
    );
    assert_io(&error, io::ErrorKind::BrokenPipe);
    assert_eq!(std::fs::read(vault.join("vault.pqd")).unwrap(), original);
    assert_eq!(std::fs::read(vault.join("vault.toml")).unwrap(), config);
}

#[test]
fn config_context_weak_password_confirmation_preserves_io_and_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let vault = test_support::setup_vault(&dir);
    let original = std::fs::read(vault.join("vault.pqd")).unwrap();
    let config = std::fs::read(vault.join("vault.toml")).unwrap();
    let secret = |value: &str| secrecy::SecretString::new(value.into());
    let error = cmd_change_password_impl(
        &cli_at(&vault, "change-password"),
        secret("PASSWORD_CONTEXT_OLD"),
        secret("weak"),
        secret("weak"),
        &mut FailedInput,
    )
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "Failed to read input: fixture input unavailable"
    );
    assert_io(&error, io::ErrorKind::BrokenPipe);
    assert!(!format!("{error:?}").contains("PASSWORD_CONTEXT_OLD"));
    assert!(!format!("{error:?}").contains("weak"));
    assert_eq!(std::fs::read(vault.join("vault.pqd")).unwrap(), original);
    assert_eq!(std::fs::read(vault.join("vault.toml")).unwrap(), config);
}

#[test]
fn config_context_init_directory_io_preserves_blocker() {
    if isolated_home("config_context_init_directory_io_preserves_blocker") {
        return;
    }
    let root = AppConfig::default_path()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    std::fs::write(&root, b"existing file").unwrap();
    let expected = std::fs::create_dir_all(&root).unwrap_err();
    let cli = Cli::try_parse_from(["pq-diary", "--password", "password", "init"]).unwrap();
    let error = cmd_init(&cli).unwrap_err();
    assert_eq!(
        error.to_string(),
        format!("Cannot create config directory: {expected}")
    );
    assert_io(&error, expected.kind());
    assert_eq!(std::fs::read(root).unwrap(), b"existing file");
}

#[cfg(unix)]
#[test]
fn config_context_init_reservation_io_preserves_symlink() {
    if isolated_home("config_context_init_reservation_io_preserves_symlink") {
        return;
    }
    let path = AppConfig::default_path().unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let missing = path.with_file_name("missing.toml");
    std::os::unix::fs::symlink(&missing, &path).unwrap();
    let expected = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap_err();
    let cli = Cli::try_parse_from(["pq-diary", "--password", "password", "init"]).unwrap();
    let error = cmd_init(&cli).unwrap_err();
    assert_eq!(
        error.to_string(),
        format!("Cannot create config file: {expected}")
    );
    assert_io(&error, io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read_link(&path).unwrap(), missing);
    assert!(!missing.exists());
    assert!(!path.parent().unwrap().join("vaults").exists());
}

#[test]
fn config_context_init_manager_io_rolls_back_only_new_config() {
    if isolated_home("config_context_init_manager_io_rolls_back_only_new_config") {
        return;
    }
    let path = AppConfig::default_path().unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let vaults = path.parent().unwrap().join("vaults");
    std::fs::write(&vaults, b"existing vaults file").unwrap();
    let expected = std::fs::create_dir_all(&vaults).unwrap_err();
    let cli = Cli::try_parse_from(["pq-diary", "--password", "password", "init"]).unwrap();
    let error = cmd_init(&cli).unwrap_err();
    assert_eq!(
        error.to_string(),
        format!("Vault creation failed: I/O error: {expected}")
    );
    assert!(matches!(
        error.downcast_ref::<DiaryError>(),
        Some(DiaryError::Io(_))
    ));
    assert_io(&error, expected.kind());
    assert!(!path.exists(), "only the new config is rolled back");
    assert_eq!(std::fs::read(vaults).unwrap(), b"existing vaults file");
}

#[test]
fn config_context_init_existing_vault_keeps_type_and_originals() {
    if isolated_home("config_context_init_existing_vault_keeps_type_and_originals") {
        return;
    }
    let path = AppConfig::default_path().unwrap();
    let vaults = path.parent().unwrap().join("vaults");
    let mgr = pq_diary_core::vault::init::VaultManager::new(vaults.clone())
        .unwrap()
        .with_kdf_params(test_support::fast_params());
    mgr.init_vault("default", b"password").unwrap();
    let vault = vaults.join("default");
    let original = std::fs::read(vault.join("vault.pqd")).unwrap();
    let config = std::fs::read(vault.join("vault.toml")).unwrap();
    let expected = mgr
        .create_vault(
            "default",
            b"password",
            pq_diary_core::policy::AccessPolicy::None,
        )
        .unwrap_err();
    let cli = Cli::try_parse_from(["pq-diary", "--password", "password", "init"]).unwrap();
    let error = cmd_init(&cli).unwrap_err();
    assert_eq!(
        error.to_string(),
        format!("Vault creation failed: {expected}")
    );
    assert!(matches!(
        error.downcast_ref::<DiaryError>(),
        Some(DiaryError::Vault(_))
    ));
    assert!(!path.exists(), "new config is rolled back");
    assert_eq!(std::fs::read(vault.join("vault.pqd")).unwrap(), original);
    assert_eq!(std::fs::read(vault.join("vault.toml")).unwrap(), config);
    let mut core = DiaryCore::new(vault.join("vault.pqd").to_str().unwrap()).unwrap();
    core.unlock(secrecy::SecretString::new("password".into()))
        .unwrap();
}

#[test]
fn config_context_sync_and_default_info_keep_config_errors() {
    if isolated_home("config_context_sync_and_default_info_keep_config_errors") {
        return;
    }
    let path = AppConfig::default_path().unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let invalid = b"this is not valid = toml [";
    std::fs::write(&path, invalid).unwrap();
    let expected = AppConfig::from_file(&path).unwrap_err();
    let sync = Cli::try_parse_from(["pq-diary", "sync"]).unwrap();
    let info = Cli::try_parse_from(["pq-diary", "info"]).unwrap();
    let mut output = Vec::new();
    for error in [
        cmd_sync(&sync).unwrap_err(),
        cmd_info_to(&info, false, &mut output).unwrap_err(),
    ] {
        assert_eq!(
            error.to_string(),
            format!("Invalid config.toml: {expected}")
        );
        assert!(matches!(
            error.downcast_ref::<DiaryError>(),
            Some(DiaryError::Config(_))
        ));
    }
    assert!(output.is_empty());
    assert_eq!(std::fs::read(&path).unwrap(), invalid);
    assert!(!path.parent().unwrap().join("vaults").exists());

    let mut config = AppConfig::default();
    config.app.default_vault = "../outside".into();
    config.to_file(&path).unwrap();
    let original = std::fs::read(&path).unwrap();
    let error = cmd_info_to(&info, false, &mut output).unwrap_err();
    assert_eq!(error.to_string(), "Invalid config.toml default_vault: invalid argument: vault name contains invalid path characters");
    assert!(matches!(
        error.downcast_ref::<DiaryError>(),
        Some(DiaryError::InvalidArgument(_))
    ));
    assert!(output.is_empty());
    assert_eq!(std::fs::read(path).unwrap(), original);
}

#[test]
fn config_context_info_keeps_config_io_before_password_or_output() {
    let dir = tempfile::tempdir().unwrap();
    let vault = test_support::setup_vault(&dir);
    let original = std::fs::read(vault.join("vault.pqd")).unwrap();
    std::fs::remove_file(vault.join("vault.toml")).unwrap();
    let expected = pq_diary_core::vault::config::VaultConfig::from_file(&vault.join("vault.toml"))
        .unwrap_err();
    let mut output = Vec::new();
    let error = cmd_info_to(&cli_at(&vault, "info"), false, &mut output).unwrap_err();
    assert_eq!(error.to_string(), format!("Invalid vault.toml: {expected}"));
    assert!(matches!(
        error.downcast_ref::<DiaryError>(),
        Some(DiaryError::Io(_))
    ));
    assert_io(&error, io::ErrorKind::NotFound);
    assert!(output.is_empty());
    assert_eq!(std::fs::read(vault.join("vault.pqd")).unwrap(), original);
    assert!(!vault.join("vault.toml").exists());
}

#[cfg(unix)]
#[test]
fn config_context_deleted_cwd_keeps_io_in_vault_and_shared_path_commands() {
    if isolated_home("config_context_deleted_cwd_keeps_io_in_vault_and_shared_path_commands") {
        return;
    }
    let cwd = std::env::current_dir().unwrap();
    std::fs::remove_dir(&cwd).unwrap();
    let expected = std::env::current_dir().unwrap_err();
    let list = Cli::try_parse_from(["pq-diary", "vault", "list"]).unwrap();
    let status = Cli::try_parse_from(["pq-diary", "--vault", "vault.pqd", "git-status"]).unwrap();
    for error in [
        cmd_vault_list_to(&list, &mut Vec::new()).unwrap_err(),
        cmd_git_status_to(&status, &mut Vec::new()).unwrap_err(),
    ] {
        assert_eq!(
            error.to_string(),
            format!("Cannot determine current directory: {expected}")
        );
        assert_io(&error, io::ErrorKind::NotFound);
    }
}

#[test]
fn config_context_authentication_redactions_still_hide_sources_and_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let vault = test_support::setup_vault(&dir);
    test_support::seed_templates(&vault, &[("CONTEXT_PRIVATE_TITLE", "CONTEXT_PRIVATE_BODY")]);
    let original = std::fs::read(vault.join("vault.pqd")).unwrap();
    let config = std::fs::read(vault.join("vault.toml")).unwrap();
    let mut cli = cli_at(&vault, "info");
    cli.password = Some("CONTEXT_WRONG_PASSWORD".into());
    let mut output = Vec::new();
    let info_error = cmd_info_to(&cli, false, &mut output).unwrap_err();
    assert_eq!(info_error.to_string(), "Vault unlock failed");
    let secret = |value: &str| secrecy::SecretString::new(value.into());
    let rotation_error = cmd_change_password_impl(
        &cli,
        secret("CONTEXT_WRONG_PASSWORD"),
        secret("Context-New-Passphrase-123!"),
        secret("Context-New-Passphrase-123!"),
        &mut io::Cursor::new("y\n"),
    )
    .unwrap_err();
    assert_eq!(rotation_error.to_string(), "Old password is incorrect");
    for error in [info_error, rotation_error] {
        assert!(error.downcast_ref::<DiaryError>().is_none());
        assert_eq!(error.chain().count(), 1);
        for secret in [
            "CONTEXT_WRONG_PASSWORD",
            "Context-New-Passphrase-123!",
            "CONTEXT_PRIVATE_TITLE",
            "CONTEXT_PRIVATE_BODY",
        ] {
            assert!(!format!("{error:?}").contains(secret));
        }
    }
    assert!(output.is_empty());
    assert_eq!(std::fs::read(vault.join("vault.pqd")).unwrap(), original);
    assert_eq!(std::fs::read(vault.join("vault.toml")).unwrap(), config);
}
