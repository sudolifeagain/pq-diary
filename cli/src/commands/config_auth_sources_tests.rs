use super::*;
use clap::Parser as _;
use pq_diary_core::DiaryError;

#[test]
fn config_auth_sources_missing_password_keeps_type_before_writes() {
    const CHILD: &str = "PQ_DIARY_TEST_CONFIG_AUTH_SOURCES";
    if std::env::var_os(CHILD).is_none() {
        let dir = tempfile::tempdir().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "commands::config_auth_sources_tests::config_auth_sources_missing_password_keeps_type_before_writes", "--nocapture"])
            .env(CHILD, "1").env("PQ_DIARY_HOME", dir.path().join("app"))
            .env_remove("PQ_DIARY_PASSWORD").stdin(std::process::Stdio::null()).output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "stdout: {stdout}\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(stdout.contains("1 passed; 0 failed"));
        assert!(!dir.path().join("app").exists());
        return;
    }
    let init = Cli::try_parse_from(["pq-diary", "init"]).unwrap();
    let error = cmd_init(&init).unwrap_err();
    assert_eq!(
        error.to_string(),
        "password error: No password provided and stdin is not a terminal"
    );
    assert!(matches!(
        error.downcast_ref::<DiaryError>(),
        Some(DiaryError::Password(_))
    ));

    let dir = tempfile::tempdir().unwrap();
    let vault = test_support::setup_vault(&dir);
    let before = std::fs::read(vault.join("vault.pqd")).unwrap();
    let info = Cli::try_parse_from(["pq-diary", "-v", vault.to_str().unwrap(), "info"]).unwrap();
    let mut output = Vec::new();
    let error = cmd_info_to(&info, false, &mut output).unwrap_err();
    assert_eq!(
        error.to_string(),
        "password error: No password provided and stdin is not a terminal"
    );
    assert!(matches!(
        error.downcast_ref::<DiaryError>(),
        Some(DiaryError::Password(_))
    ));
    assert!(output.is_empty());
    assert_eq!(std::fs::read(vault.join("vault.pqd")).unwrap(), before);
}

#[test]
fn config_auth_sources_rotation_config_io_keeps_source() {
    let dir = tempfile::tempdir().unwrap();
    let cli = Cli::try_parse_from([
        "pq-diary",
        "-v",
        dir.path().to_str().unwrap(),
        "change-password",
    ])
    .unwrap();
    let expected = pq_diary_core::DiaryCore::new(dir.path().join("vault.pqd").to_str().unwrap())
        .err()
        .unwrap()
        .to_string();
    let secret = |value: &str| secrecy::SecretString::new(value.into());
    let error = cmd_change_password_impl(
        &cli,
        secret("SOURCE_OLD_SECRET"),
        secret("Source-New-Passphrase-123!"),
        secret("Source-New-Passphrase-123!"),
        &mut std::io::Cursor::new("y\n"),
    )
    .unwrap_err();
    assert_eq!(error.to_string(), expected);
    assert!(matches!(
        error.downcast_ref::<DiaryError>(),
        Some(DiaryError::Io(_))
    ));
    assert_eq!(
        error
            .chain()
            .find_map(|e| e.downcast_ref::<std::io::Error>())
            .unwrap()
            .kind(),
        std::io::ErrorKind::NotFound
    );
    for secret in ["SOURCE_OLD_SECRET", "Source-New-Passphrase-123!"] {
        assert!(!format!("{error:?}").contains(secret));
    }
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn config_auth_sources_wrong_password_stays_redacted_and_preserves_vault() {
    let dir = tempfile::tempdir().unwrap();
    let vault = test_support::setup_vault(&dir);
    test_support::seed_templates(&vault, &[("SOURCE_PRIVATE_TITLE", "SOURCE_PRIVATE_BODY")]);
    let before = std::fs::read(vault.join("vault.pqd")).unwrap();
    let config = std::fs::read(vault.join("vault.toml")).unwrap();
    let cli = Cli::try_parse_from([
        "pq-diary",
        "-v",
        vault.to_str().unwrap(),
        "--password",
        "SOURCE_WRONG_PASSWORD",
        "info",
    ])
    .unwrap();
    let error = cmd_info_to(&cli, false, &mut Vec::new()).unwrap_err();
    assert_eq!(error.to_string(), "Vault unlock failed");
    assert!(error.downcast_ref::<DiaryError>().is_none());
    let secret = |value: &str| secrecy::SecretString::new(value.into());
    let rotation = cmd_change_password_impl(
        &cli,
        secret("SOURCE_WRONG_PASSWORD"),
        secret("Source-New-Passphrase-123!"),
        secret("Source-New-Passphrase-123!"),
        &mut std::io::Cursor::new("y\n"),
    )
    .unwrap_err();
    assert_eq!(rotation.to_string(), "Old password is incorrect");
    assert!(rotation.downcast_ref::<DiaryError>().is_none());
    for diagnostic in [format!("{error:?}"), format!("{rotation:?}")] {
        for secret in [
            "SOURCE_WRONG_PASSWORD",
            "Source-New-Passphrase-123!",
            "SOURCE_PRIVATE_TITLE",
            "SOURCE_PRIVATE_BODY",
        ] {
            assert!(!diagnostic.contains(secret));
        }
    }
    assert_eq!(std::fs::read(vault.join("vault.pqd")).unwrap(), before);
    assert_eq!(std::fs::read(vault.join("vault.toml")).unwrap(), config);
}
