use super::*;
use clap::Parser as _;
use pq_diary_core::DiaryError;

fn cli(vault: &std::path::Path, password: &str) -> Cli {
    Cli::try_parse_from([
        "pq-diary",
        "-v",
        vault.to_str().unwrap(),
        "--password",
        password,
        "new",
    ])
    .unwrap()
}

#[test]
fn entry_context_sources_unlock_keeps_crypto_and_exact_display() {
    let dir = tempfile::tempdir().unwrap();
    let vault = test_support::setup_vault(&dir);
    let before = std::fs::read(vault.join("vault.pqd")).unwrap();
    let cli = cli(&vault, "SOURCE_WRONG_PASSWORD");
    let mut core = DiaryCore::new(vault.join("vault.pqd").to_str().unwrap()).unwrap();
    let expected = core
        .unlock(secrecy::SecretString::new("SOURCE_WRONG_PASSWORD".into()))
        .unwrap_err();
    let mut output = Vec::new();
    for error in [
        cmd_new_with_attach_to(
            &cli,
            Some("SOURCE_PRIVATE_TITLE".into()),
            Some("SOURCE_PRIVATE_BODY".into()),
            vec![],
            None,
            vec![],
            &mut output,
        )
        .unwrap_err(),
        cmd_show_impl(&cli, "deadbeef".into(), &mut output).unwrap_err(),
    ] {
        assert_eq!(
            error.to_string(),
            format!("Vault unlock failed: {expected}")
        );
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
}

#[test]
fn entry_context_sources_delete_confirmation_io_keeps_source_and_vault() {
    struct FailedRead;
    impl std::io::Read for FailedRead {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "confirmation unavailable",
            ))
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let vault = test_support::setup_vault(&dir);
    let cli = cli(&vault, "password");
    let mut core = session::locked_core(&cli).unwrap();
    let guard = session::unlock(&mut core, secrecy::SecretString::new("password".into())).unwrap();
    let id = guard
        .new_entry("SOURCE_PRIVATE_TITLE", "SOURCE_PRIVATE_BODY", vec![])
        .unwrap();
    drop(guard);
    let before = std::fs::read(vault.join("vault.pqd")).unwrap();
    let error =
        cmd_delete_impl(&cli, id, false, &mut std::io::BufReader::new(FailedRead)).unwrap_err();
    assert_eq!(
        error.to_string(),
        "Failed to read input: confirmation unavailable"
    );
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::BrokenPipe
    );
    for secret in ["password", "SOURCE_PRIVATE_TITLE", "SOURCE_PRIVATE_BODY"] {
        assert!(!format!("{error:?}").contains(secret));
    }
    assert_eq!(std::fs::read(vault.join("vault.pqd")).unwrap(), before);
}
