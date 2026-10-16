//! Private ownership boundary for ordinary single-password commands.
use super::resolve_vault_path;
use crate::Cli;
use pq_diary_core::{DiaryCore, DiaryError};
use secrecy::SecretString;

/// Resolve and construct a locked core without prompting or evaluating policy.
/// Callers retain their policy and password-acquisition order.
pub(super) fn locked_core(cli: &Cli) -> anyhow::Result<DiaryCore> {
    let vault_path = resolve_vault_path(cli)?;
    let vault_str = vault_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Vault path contains non-UTF-8 characters"))?;
    DiaryCore::new(vault_str).map_err(anyhow::Error::new)
}

/// Keep the CLI diagnostic prefix while retaining the typed underlying error.
pub(super) fn unlock(
    core: &mut DiaryCore,
    password: SecretString,
) -> anyhow::Result<VaultGuard<'_>> {
    VaultGuard::unlock(core, password).map_err(|error| {
        let message = format!("Vault unlock failed: {error}");
        anyhow::Error::new(error).context(message)
    })
}

// Multi-use credentials (new/show attachments/import), creation, and special command
// flows still unlock explicitly and use new() immediately after success.
// ---------------------------------------------------------------------------
// VaultGuard — RAII drop guard for vault lock/unlock lifecycle
// ---------------------------------------------------------------------------

/// RAII guard that automatically calls [`DiaryCore::lock`] when dropped.
///
/// Create this guard immediately after a successful [`DiaryCore::unlock`] call.
/// The guard borrows the core mutably, so all vault operations must be
/// performed through `Deref` coercion (`guard.method()` instead of
/// `core.method()`).  When the guard goes out of scope — on success, on `?`
/// early return, or on panic — `lock()` is guaranteed to be called, securely
/// erasing the master key from memory.
pub(super) struct VaultGuard<'a>(&'a mut DiaryCore);

impl<'a> VaultGuard<'a> {
    /// Consume the protected password and expose a session only after unlock succeeds.
    pub(super) fn unlock(
        core: &'a mut DiaryCore,
        password: SecretString,
    ) -> Result<Self, DiaryError> {
        core.unlock(password)?;
        Ok(Self(core))
    }

    /// Wrap an already-unlocked `DiaryCore` in a guard.
    pub(super) fn new(core: &'a mut DiaryCore) -> Self {
        Self(core)
    }
}

impl Drop for VaultGuard<'_> {
    fn drop(&mut self) {
        self.0.lock();
    }
}

impl std::ops::Deref for VaultGuard<'_> {
    type Target = DiaryCore;
    fn deref(&self) -> &DiaryCore {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::setup_vault;
    use super::*;
    use clap::Parser as _;

    #[test]
    fn locked_core_preserves_constructor_error_type_display_and_io_source() {
        const PASSWORD: &str = "synthetic password must stay protected";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.pqd");
        let config_path = dir.path().join("vault.toml");
        let cli = Cli::try_parse_from([
            "pq-diary",
            "--vault",
            path.to_str().unwrap(),
            "--password",
            PASSWORD,
            "list",
        ])
        .unwrap();

        for invalid_config in [false, true] {
            if invalid_config {
                std::fs::write(&config_path, "[").unwrap();
            }
            let expected = DiaryCore::new(path.to_str().unwrap()).err().unwrap();
            let error = locked_core(&cli).err().unwrap();
            let typed = error.downcast_ref::<DiaryError>().expect("typed source");
            assert_eq!(error.to_string(), expected.to_string());
            if invalid_config {
                assert!(matches!(typed, DiaryError::Config(_)));
                assert_eq!(std::fs::read_to_string(&config_path).unwrap(), "[");
            } else {
                assert!(matches!(typed, DiaryError::Io(io) if io.kind() == std::io::ErrorKind::NotFound));
                let io = error
                    .chain()
                    .find_map(|source| source.downcast_ref::<std::io::Error>())
                    .expect("original I/O cause");
                assert_eq!(io.kind(), std::io::ErrorKind::NotFound);
                assert!(!config_path.exists());
            }
            assert!(!error.to_string().contains(PASSWORD));
            assert!(!format!("{error:?}").contains(PASSWORD));
            assert!(!path.exists());
        }
    }

    #[test]
    fn locked_core_does_not_consume_password_or_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let vault = setup_vault(&dir);
        let cli = Cli::try_parse_from([
            "pq-diary",
            "--vault",
            vault.to_str().unwrap(),
            "--password",
            "synthetic wrong password",
            "list",
        ])
        .unwrap();
        let core = locked_core(&cli).unwrap();
        assert!(matches!(core.list_entries(None), Err(DiaryError::NotUnlocked)));
        assert!(cli.password.is_some());
    }

    // =========================================================================
    // TC-A13: VaultGuard drop guard tests (TASK-0056)
    // =========================================================================

    /// TC-A13-01: VaultGuard drop calls lock() on the underlying DiaryCore.
    ///
    /// After the guard goes out of scope, the vault must be locked: any
    /// attempt to call a vault operation should return `NotUnlocked`.
    #[test]
    fn tc_a13_01_vault_guard_drop_calls_lock() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_pqd = vault_dir.join("vault.pqd");
        let vault_str = vault_pqd.to_str().expect("utf8");

        let mut core = DiaryCore::new(vault_str).expect("DiaryCore::new");
        let pw: secrecy::SecretString = secrecy::SecretBox::new(Box::from("password"));

        {
            let _guard = VaultGuard::unlock(&mut core, pw).expect("unlock");
            // guard is alive; vault is unlocked
        }
        // guard dropped here — lock() must have been called

        let result = core.list_entries(None);
        assert!(
            matches!(result, Err(DiaryError::NotUnlocked)),
            "core must be locked after VaultGuard drop; list_entries should fail"
        );
    }

    /// TC-A13-02: VaultGuard calls lock() even when an early return (error path) occurs.
    ///
    /// Uses a closure that creates a VaultGuard and then returns `Err(...)` via `?`.
    /// The guard's Drop must run before the closure exits, ensuring lock() is called.
    #[test]
    fn tc_a13_02_error_path_calls_lock() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_pqd = vault_dir.join("vault.pqd");
        let vault_str = vault_pqd.to_str().expect("utf8");

        let mut core = DiaryCore::new(vault_str).expect("DiaryCore::new");
        let pw: secrecy::SecretString = secrecy::SecretBox::new(Box::from("password"));

        // Simulate an error path: guard is created, then ? causes early return.
        let result: anyhow::Result<()> = (|| {
            let _guard = VaultGuard::unlock(&mut core, pw).expect("unlock");
            anyhow::bail!("simulated error to trigger early return");
        })();

        assert!(result.is_err(), "closure must propagate the error");

        // Even though the closure returned Err, lock() must have been called.
        let list_result = core.list_entries(None);
        assert!(
            matches!(list_result, Err(DiaryError::NotUnlocked)),
            "core must be locked after VaultGuard drop on error path"
        );
    }

    #[test]
    fn unlock_session_locks_on_unwind() {
        let dir = tempfile::tempdir().unwrap();
        let vault = setup_vault(&dir).join("vault.pqd");
        let mut core = DiaryCore::new(vault.to_str().unwrap()).unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let guard = VaultGuard::unlock(&mut core, SecretString::from("password")).unwrap();
            assert!(guard.list_entries(None).is_ok());
            panic!("synthetic unwind");
        }));
        assert!(result.is_err());
        assert!(matches!(
            core.list_entries(None),
            Err(DiaryError::NotUnlocked)
        ));
    }

    #[test]
    fn failed_unlock_retains_source_and_never_exposes_session() {
        let dir = tempfile::tempdir().unwrap();
        let vault = setup_vault(&dir).join("vault.pqd");
        let mut core = DiaryCore::new(vault.to_str().unwrap()).unwrap();
        let error = match unlock(&mut core, SecretString::from("synthetic wrong password")) {
            Ok(_) => panic!("wrong password unlocked"),
            Err(error) => error,
        };
        let source = error
            .downcast_ref::<DiaryError>()
            .expect("typed unlock source");
        assert_eq!(error.to_string(), format!("Vault unlock failed: {source}"));
        assert!(!format!("{error:?}").contains("synthetic wrong password"));
        assert!(matches!(
            core.list_entries(None),
            Err(DiaryError::NotUnlocked)
        ));
    }
}
