use super::*;
use clap::Parser as _;
use pq_diary_core::DiaryError;

fn cli(path: &std::path::Path, password: &str) -> Cli {
    Cli::try_parse_from([
        "pq-diary",
        "-v",
        path.to_str().unwrap(),
        "--password",
        password,
        "legacy",
        "list",
    ])
    .unwrap()
}

#[test]
fn legacy_attachment_sources_missing_config_keeps_io_and_display() {
    let dir = tempfile::tempdir().unwrap();
    let cli = cli(dir.path(), "SOURCE_PRIVATE_PASSWORD");
    let secret = secrecy::SecretString::new("SOURCE_PRIVATE_PASSWORD".into());
    let expected = pq_diary_core::legacy::list_legacy_status(dir.path(), &secret)
        .unwrap_err()
        .to_string();
    let mut output = Vec::new();
    for error in [
        cmd_legacy_list_to(&cli, &mut output).unwrap_err(),
        cmd_attachment_list_to(&cli, None, &mut output).unwrap_err(),
    ] {
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
        assert!(!format!("{error:?}").contains("SOURCE_PRIVATE_PASSWORD"));
    }
    assert!(output.is_empty());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn legacy_attachment_sources_wrong_password_keeps_crypto_and_vault() {
    let dir = tempfile::tempdir().unwrap();
    let vault = test_support::setup_vault(&dir);
    test_support::seed_templates(&vault, &[("SOURCE_PRIVATE_TITLE", "SOURCE_PRIVATE_BODY")]);
    let before = std::fs::read(vault.join("vault.pqd")).unwrap();
    let config = std::fs::read(vault.join("vault.toml")).unwrap();
    let cli = cli(&vault, "SOURCE_WRONG_PASSWORD");
    let secret = secrecy::SecretString::new("SOURCE_WRONG_PASSWORD".into());
    let expected_legacy = pq_diary_core::legacy::list_legacy_status(&vault, &secret)
        .unwrap_err()
        .to_string();
    let expected_attachment = pq_diary_core::attachment::list_attachments(&vault, &secret, None)
        .unwrap_err()
        .to_string();
    let mut output = Vec::new();
    for (error, expected) in [
        (
            cmd_legacy_list_to(&cli, &mut output).unwrap_err(),
            expected_legacy,
        ),
        (
            cmd_attachment_list_to(&cli, None, &mut output).unwrap_err(),
            expected_attachment,
        ),
    ] {
        assert_eq!(error.to_string(), expected);
        assert!(matches!(
            error.downcast_ref::<DiaryError>(),
            Some(DiaryError::Crypto(_))
        ));
        for secret in [
            "SOURCE_WRONG_PASSWORD",
            "SOURCE_PRIVATE_TITLE",
            "SOURCE_PRIVATE_BODY",
        ] {
            assert!(!format!("{error:?}").contains(secret));
        }
    }
    assert!(output.is_empty());
    assert_eq!(std::fs::read(vault.join("vault.pqd")).unwrap(), before);
    assert_eq!(std::fs::read(vault.join("vault.toml")).unwrap(), config);
}

#[test]
fn legacy_attachment_sources_set_config_failure_precedes_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let vault = test_support::setup_vault(&dir);
    let before = std::fs::read(vault.join("vault.pqd")).unwrap();
    std::fs::remove_file(vault.join("vault.toml")).unwrap();
    let cli = cli(&vault, "SOURCE_PRIVATE_PASSWORD");
    let expected = pq_diary_core::vault::config::VaultConfig::from_file(&vault.join("vault.toml"))
        .unwrap_err()
        .to_string();
    for error in [
        cmd_legacy_set(&cli, "deadbeef".into(), false, true).unwrap_err(),
        cmd_attachment_set(&cli, "deadbeef".into(), "photo.txt".into(), false, true).unwrap_err(),
    ] {
        assert_eq!(error.to_string(), expected);
        assert!(matches!(
            error.downcast_ref::<DiaryError>(),
            Some(DiaryError::Io(_))
        ));
        assert!(error
            .chain()
            .any(|e| e.downcast_ref::<std::io::Error>().is_some()));
        assert!(!format!("{error:?}").contains("SOURCE_PRIVATE_PASSWORD"));
    }
    assert_eq!(std::fs::read(vault.join("vault.pqd")).unwrap(), before);
}
