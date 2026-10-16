//! Password acquisition for the pq-diary CLI.
//!
//! Implements a three-stage fallback mechanism for obtaining the vault master
//! password:
//! 1. `--password` CLI flag  (highest priority; warns about security risk)
//! 2. `PQ_DIARY_PASSWORD` environment variable
//! 3. Interactive TTY prompt with echo disabled

use pq_diary_core::DiaryError;
use secrecy::{SecretBox, SecretString};

/// Source from which the master password was obtained.
///
/// Each variant carries the password as a [`SecretString`] that is zeroed on
/// drop.
pub enum PasswordSource {
    /// Password was supplied via the `--password` CLI flag.
    ///
    /// Least secure option: the value may appear in shell history and process
    /// listings.
    Flag(SecretString),

    /// Password was read from the `PQ_DIARY_PASSWORD` environment variable.
    Env(SecretString),

    /// Password was entered interactively via the controlling TTY (safest).
    ///
    /// Echo is disabled during input so the password is not displayed.
    Tty(SecretString),
}

impl PasswordSource {
    /// Move the existing protected allocation out of its source without copying.
    pub fn into_secret(self) -> SecretString {
        match self {
            Self::Flag(secret) | Self::Env(secret) | Self::Tty(secret) => secret,
        }
    }

    /// Returns a reference to the underlying [`SecretString`].
    pub fn secret(&self) -> &SecretString {
        match self {
            PasswordSource::Flag(s) | PasswordSource::Env(s) | PasswordSource::Tty(s) => s,
        }
    }
}

/// Obtain the master password using a three-stage fallback strategy.
///
/// Priority order:
/// 1. `flag_value` — value of the `--password` CLI argument as a [`SecretString`],
///    if present.  A warning is written to stderr because passing passwords on
///    the command line is insecure.
/// 2. `PQ_DIARY_PASSWORD` environment variable.
/// 3. Interactive TTY prompt with echo disabled.
///
/// Accepting `Option<&SecretString>` instead of `Option<&str>` ensures that the
/// password is never held as a plain `String` on the call stack.
///
/// # Errors
///
/// Returns [`DiaryError::Password`] when stdin is not a terminal and neither
/// `flag_value` nor `PQ_DIARY_PASSWORD` is set.
pub fn get_password(flag_value: Option<&SecretString>) -> Result<PasswordSource, DiaryError> {
    // Stage 1: --password flag
    if let Some(secret) = flag_value {
        eprintln!("Warning: Specifying a password on the command line is a security risk.");
        use secrecy::ExposeSecret as _;
        return Ok(PasswordSource::Flag(SecretBox::new(Box::from(
            secret.expose_secret(),
        ))));
    }

    // Stage 2: PQ_DIARY_PASSWORD environment variable
    if let Ok(env_pass) = std::env::var("PQ_DIARY_PASSWORD") {
        // Remove the variable immediately to prevent child processes or memory
        // dumps from leaking the password via the environment.
        std::env::remove_var("PQ_DIARY_PASSWORD");
        return Ok(PasswordSource::Env(SecretBox::new(
            env_pass.into_boxed_str(),
        )));
    }

    // Stage 3: interactive TTY prompt
    use std::io::IsTerminal as _;
    if std::io::stdin().is_terminal() {
        return read_password_tty("Password: ").map(PasswordSource::Tty);
    }

    Err(DiaryError::Password(
        "No password provided and stdin is not a terminal".to_string(),
    ))
}

/// Read a password from the controlling TTY with echo disabled, using a
/// caller-supplied prompt.
///
/// This is the public entry point for commands that need to prompt for an
/// additional password beyond the default `"Password: "` (e.g. `change-password`
/// requires `"Old password: "`, `"New password: "`, `"Confirm new password: "`).
///
/// Returns `DiaryError::Password` if stdin is not a terminal — non-interactive
/// callers must use the `cmd_*_impl` helper variants that take `SecretString`
/// directly.
///
/// # Errors
///
/// Returns [`DiaryError::Password`] when stdin is not a terminal or the TTY
/// I/O fails.
pub fn prompt_password(prompt: &str) -> Result<SecretString, DiaryError> {
    use std::io::IsTerminal as _;
    if !std::io::stdin().is_terminal() {
        return Err(DiaryError::Password(format!(
            "Cannot prompt '{prompt}' — stdin is not a terminal"
        )));
    }
    read_password_tty(prompt)
}

/// Restoration is best effort, including when the diagnostic stream has failed.
fn warn_restore_failure(
    warnings: &mut impl std::io::Write,
    target: &str,
    error: &impl std::fmt::Display,
) {
    let _ = writeln!(warnings, "Warning: Failed to restore {target}: {error}");
}

/// Report prompt I/O before Windows disables console echo.
#[cfg(any(windows, test))]
fn write_console_prompt(
    writer: &mut impl std::io::Write,
    prompt: &str,
) -> Result<(), DiaryError> {
    write!(writer, "{prompt}")
        .and_then(|()| writer.flush())
        .map_err(|e| DiaryError::Password(format!("Cannot write console prompt: {e}")))
}

// =============================================================================
// Platform-specific TTY implementations
// =============================================================================

/// Read a password from the controlling TTY with echo disabled (Unix).
///
/// Opens `/dev/tty` directly so that reading works even when stdin is
/// redirected.  Terminal echo flags (`ECHO`, `ECHOE`, `ECHOK`, `ECHONL`) are
/// disabled via `termios` and restored on return through a RAII guard.
/// The caller supplies the prompt string written to the TTY.
#[cfg(unix)]
fn read_password_tty(prompt: &str) -> Result<SecretString, DiaryError> {
    use nix::sys::termios::{self, LocalFlags, SetArg};
    use std::io::{Read, Write};
    use zeroize::Zeroizing;

    // Open the controlling terminal for both reading (password) and writing
    // (prompt + newline after input).
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| DiaryError::Password(format!("Cannot open /dev/tty: {e}")))?;

    // Save the current terminal attributes.
    let old_attrs = termios::tcgetattr(&tty)
        .map_err(|e| DiaryError::Password(format!("tcgetattr failed: {e}")))?;

    // Build new attributes with all ECHO flags disabled.
    let mut new_attrs = old_attrs.clone();
    new_attrs
        .local_flags
        .remove(LocalFlags::ECHO | LocalFlags::ECHOE | LocalFlags::ECHOK | LocalFlags::ECHONL);
    termios::tcsetattr(&tty, SetArg::TCSANOW, &new_attrs)
        .map_err(|e| DiaryError::Password(format!("tcsetattr failed: {e}")))?;

    // RAII guard: owns the tty file and restores terminal attributes on drop.
    // Defining the struct inside the function keeps it private to this scope.
    struct TtyGuard {
        file: std::fs::File,
        old: nix::sys::termios::Termios,
    }
    impl Drop for TtyGuard {
        fn drop(&mut self) {
            if let Err(e) = nix::sys::termios::tcsetattr(
                &self.file,
                nix::sys::termios::SetArg::TCSANOW,
                &self.old,
            ) {
                warn_restore_failure(
                    &mut std::io::stderr().lock(),
                    "terminal attributes",
                    &e,
                );
            }
        }
    }
    let mut guard = TtyGuard {
        file: tty,
        old: old_attrs,
    };

    // Print the password prompt.
    write!(guard.file, "{prompt}")
        .map_err(|e| DiaryError::Password(format!("Cannot write prompt: {e}")))?;
    guard
        .file
        .flush()
        .map_err(|e| DiaryError::Password(format!("Cannot flush prompt: {e}")))?;

    // Read raw bytes until LF/CR or EOF.
    let mut raw: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    let mut byte = [0u8; 1];
    loop {
        match guard.file.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => match byte[0] {
                b'\n' | b'\r' => break,
                0x7f | 0x08 => {
                    raw.pop();
                } // DEL / BS
                b => raw.push(b),
            },
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(DiaryError::Password(format!("TTY read error: {e}"))),
        }
    }

    // Move to a new line after the hidden input.
    writeln!(guard.file).ok();

    // Validate UTF-8 in-place (no heap copy) and wrap in SecretString.
    // `from_utf8` borrows `raw`; on error the `Utf8Error` does not contain the
    // bytes, so no un-zeroized copy is leaked.  `raw` itself is zeroized on drop.
    let s = std::str::from_utf8(&raw)
        .map_err(|_| DiaryError::Password("Password contains non-UTF-8 bytes".to_string()))?;

    Ok(SecretBox::new(Box::from(s)))
    // guard drops here → tcsetattr restores echo
}

/// Read a password from the console with echo disabled (Windows).
///
/// Uses `GetConsoleMode` / `SetConsoleMode` to disable `ENABLE_ECHO_INPUT` and
/// `ReadConsoleW` to read Unicode input.  The original console mode is always
/// restored before the function returns. The caller supplies the prompt
/// string written to stderr.
#[cfg(windows)]
fn read_password_tty(prompt: &str) -> Result<SecretString, DiaryError> {
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, ReadConsoleW, SetConsoleMode, ENABLE_ECHO_INPUT,
        STD_INPUT_HANDLE,
    };
    use zeroize::Zeroizing;

    // SAFETY: STD_INPUT_HANDLE is a documented selector. The returned handle
    // is checked before use and is borrowed, never closed by this function.
    #[allow(unsafe_code, reason = "OS console-handle boundary: GetStdHandle")]
    let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    // INVALID_HANDLE_VALUE = -1 as pointer; null = 0 pointer (both invalid)
    if handle.is_null() || (handle as isize) == -1 {
        return Err(DiaryError::Password(
            "Failed to obtain stdin console handle".to_string(),
        ));
    }

    let mut old_mode: u32 = 0;
    // SAFETY: handle passed the invalid-handle checks; old_mode is a live,
    // uniquely borrowed u32 output slot for the duration of the call.
    #[allow(unsafe_code, reason = "OS console-mode boundary: GetConsoleMode")]
    let mode_read = unsafe { GetConsoleMode(handle, &mut old_mode) };
    if mode_read == 0 {
        return Err(DiaryError::Password(
            "Failed to read console mode".to_string(),
        ));
    }

    // A prompt write/flush failure must return while the original mode is intact.
    write_console_prompt(&mut std::io::stderr().lock(), prompt)?;

    // Disable echo input.
    let new_mode = old_mode & !ENABLE_ECHO_INPUT;
    // SAFETY: handle is a console handle verified by GetConsoleMode; new_mode
    // preserves the original flags except for disabling echo.
    #[allow(unsafe_code, reason = "OS console-mode boundary: SetConsoleMode")]
    let mode_set = unsafe { SetConsoleMode(handle, new_mode) };
    if mode_set == 0 {
        return Err(DiaryError::Password(
            "Failed to disable console echo".to_string(),
        ));
    }

    // Read up to 256 UTF-16 code units from the console.
    let mut buf: Zeroizing<[u16; 256]> = Zeroizing::new([0u16; 256]);
    let mut chars_read: u32 = 0;
    // SAFETY: buf is a live, uniquely borrowed 256-unit UTF-16 buffer, and the
    // supplied count is its capacity. chars_read is a live u32 output slot.
    // The optional input-control pointer is null; neither pointer escapes.
    #[allow(unsafe_code, reason = "OS console-input boundary: ReadConsoleW")]
    let ok = unsafe {
        ReadConsoleW(
            handle,
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
            &mut chars_read,
            std::ptr::null(),
        )
    };

    // Restore console mode before any early return.
    // SAFETY: the same live console handle and its saved original flags are
    // passed back before handling any read or decoding error.
    #[allow(unsafe_code, reason = "OS console-mode restoration: SetConsoleMode")]
    let mode_restored = unsafe { SetConsoleMode(handle, old_mode) };
    if mode_restored == 0 {
        warn_restore_failure(
            &mut std::io::stderr().lock(),
            "console mode",
            &std::io::Error::last_os_error(),
        );
    }
    // Neither restoration warnings nor the cosmetic newline may panic before
    // the original ReadConsoleW result is handled.
    {
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr().lock());
    }

    if ok == 0 {
        return Err(DiaryError::Password(
            "Failed to read password from console".to_string(),
        ));
    }

    let slice = &buf[..chars_read as usize];
    // Strip trailing CR+LF, lone LF, or lone CR.
    let trimmed = slice
        .strip_suffix(&[b'\r' as u16, b'\n' as u16])
        .or_else(|| slice.strip_suffix(&[b'\n' as u16]))
        .or_else(|| slice.strip_suffix(&[b'\r' as u16]))
        .unwrap_or(slice);

    let password = String::from_utf16(trimmed)
        .map_err(|e| DiaryError::Password(format!("Failed to decode console input: {e}")))?;

    Ok(SecretBox::new(password.into_boxed_str()))
}

/// Fallback for platforms that support neither Unix termios nor Win32 console.
#[cfg(not(any(unix, windows)))]
fn read_password_tty(_prompt: &str) -> Result<SecretString, DiaryError> {
    Err(DiaryError::Password(
        "Interactive TTY password input is not supported on this platform".to_string(),
    ))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    struct FailedOutput {
        fail_flush: bool,
    }

    impl std::io::Write for FailedOutput {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.fail_flush {
                Ok(bytes.len())
            } else {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
    }

    #[test]
    fn console_prompt_write_and_flush_failures_are_password_errors() {
        for fail_flush in [false, true] {
            assert!(matches!(
                write_console_prompt(&mut FailedOutput { fail_flush }, "Password: "),
                Err(DiaryError::Password(_))
            ));
        }
    }

    #[test]
    fn terminal_restore_warning_failure_does_not_panic_during_unwind() {
        struct RestoreWarning;
        impl Drop for RestoreWarning {
            fn drop(&mut self) {
                warn_restore_failure(
                    &mut FailedOutput { fail_flush: false },
                    "terminal attributes",
                    &std::io::Error::from(std::io::ErrorKind::Other),
                );
            }
        }
        let result = std::panic::catch_unwind(|| {
            let _guard = RestoreWarning;
            panic!("primary password read failure");
        });
        let panic = result.unwrap_err();
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"primary password read failure")
        );
    }

    #[test]
    fn into_secret_preserves_allocation_for_every_source() {
        for wrap in [
            PasswordSource::Flag,
            PasswordSource::Env,
            PasswordSource::Tty,
        ] {
            let source = wrap(make_secret("synthetic protected password"));
            let address = source.secret().expose_secret().as_ptr();
            let secret = source.into_secret();
            assert_eq!(secret.expose_secret(), "synthetic protected password");
            assert_eq!(secret.expose_secret().as_ptr(), address);
            assert!(!format!("{secret:?}").contains("synthetic protected password"));
        }
    }

    /// Helper: construct a `SecretString` from a literal for use in tests.
    fn make_secret(s: &str) -> SecretString {
        SecretString::from(s.to_string())
    }

    // -------------------------------------------------------------------------
    // TASK-0081 tests: H-1 get_password SecretString シグネチャ変更
    // -------------------------------------------------------------------------

    /// TC-S9-081-03: `get_password(Some(&SecretString))` からパスワード文字列を正しく取得する。
    #[test]
    fn tc_s9_081_03_get_password_with_secret_string() {
        if crate::test_environment::isolated() {
            return;
        }

        std::env::remove_var("PQ_DIARY_PASSWORD");

        let secret = make_secret("my_pass");
        let result = get_password(Some(&secret));
        assert!(result.is_ok(), "Expected Ok, got: {:?}", result.err());
        let source = result.unwrap();
        assert!(
            matches!(source, PasswordSource::Flag(_)),
            "Expected PasswordSource::Flag variant"
        );
        assert_eq!(source.secret().expose_secret(), "my_pass");
    }

    /// TC-S9-081-04: `get_password(None)` が非TTY環境でエラーを返すことを検証する。
    ///
    /// テスト環境では stdin が TTY ではないため、`None` かつ環境変数なしの場合は
    /// `DiaryError::Password` が返る。これは既存テスト TC-0034-04 と同じ条件での
    /// インタラクティブフォールバック検証である。
    #[test]
    fn tc_s9_081_04_get_password_none_falls_back_to_interactive() {
        if crate::test_environment::isolated() {
            return;
        }

        use std::io::IsTerminal as _;
        if std::io::stdin().is_terminal() {
            // Running in an interactive TTY — skip this test.
            return;
        }

        std::env::remove_var("PQ_DIARY_PASSWORD");
        let result = get_password(None);
        assert!(
            matches!(result, Err(DiaryError::Password(_))),
            "Expected DiaryError::Password when no credentials and stdin is not a terminal"
        );
    }

    // -------------------------------------------------------------------------
    // Existing tests (updated to use Option<&SecretString> API)
    // -------------------------------------------------------------------------

    /// TC-0034-01: `--password` flag returns `PasswordSource::Flag` with the
    /// correct secret value.
    #[test]
    fn tc_0034_01_flag_returns_flag_source() {
        if crate::test_environment::isolated() {
            return;
        }

        std::env::remove_var("PQ_DIARY_PASSWORD");

        let secret = make_secret("flag_test_password");
        let result = get_password(Some(&secret));
        assert!(result.is_ok(), "Expected Ok, got: {:?}", result.err());
        let source = result.unwrap();
        assert!(
            matches!(source, PasswordSource::Flag(_)),
            "Expected PasswordSource::Flag variant"
        );
        assert_eq!(source.secret().expose_secret(), "flag_test_password");
    }

    /// TC-0034-02: `PQ_DIARY_PASSWORD` env var (no flag) returns
    /// `PasswordSource::Env` with the correct secret value.
    #[test]
    fn tc_0034_02_env_var_returns_env_source() {
        if crate::test_environment::isolated() {
            return;
        }

        let test_val = "env_tc0034_02_unique";
        std::env::set_var("PQ_DIARY_PASSWORD", test_val);
        let result = get_password(None);
        std::env::remove_var("PQ_DIARY_PASSWORD");

        assert!(result.is_ok(), "Expected Ok, got: {:?}", result.err());
        let source = result.unwrap();
        assert!(
            matches!(source, PasswordSource::Env(_)),
            "Expected PasswordSource::Env variant"
        );
        assert_eq!(source.secret().expose_secret(), test_val);
    }

    /// TC-0034-03: `--password` flag takes priority over the env var.
    #[test]
    fn tc_0034_03_flag_priority_over_env() {
        if crate::test_environment::isolated() {
            return;
        }

        std::env::set_var("PQ_DIARY_PASSWORD", "env_pass_03");
        let secret = make_secret("flag_pass_03");
        let result = get_password(Some(&secret));
        std::env::remove_var("PQ_DIARY_PASSWORD");

        let source = result.expect("Expected Ok");
        assert!(
            matches!(source, PasswordSource::Flag(_)),
            "Flag must take priority over env var"
        );
        assert_eq!(source.secret().expose_secret(), "flag_pass_03");
    }

    /// TC-0034-04: Non-TTY stdin with no credentials returns
    /// `DiaryError::Password`.
    ///
    /// In a `cargo test` environment stdin is not a terminal, so
    /// `get_password(None)` with no env var must return an error.
    #[test]
    fn tc_0034_04_no_tty_no_credentials_returns_error() {
        if crate::test_environment::isolated() {
            return;
        }

        use std::io::IsTerminal as _;
        if std::io::stdin().is_terminal() {
            return;
        }

        std::env::remove_var("PQ_DIARY_PASSWORD");
        let result = get_password(None);

        assert!(
            matches!(result, Err(DiaryError::Password(_))),
            "Expected DiaryError::Password when stdin is not a terminal and no credentials provided"
        );
    }

    /// TC-0034-05: The password is stored in a `SecretString` whose `Debug`
    /// representation does not reveal the secret value.
    #[test]
    fn tc_0034_05_secret_string_redacts_debug_output() {
        if crate::test_environment::isolated() {
            return;
        }

        std::env::remove_var("PQ_DIARY_PASSWORD");

        let secret = make_secret("super_secret_value");
        let result = get_password(Some(&secret)).expect("Expected Ok");
        assert_eq!(result.secret().expose_secret(), "super_secret_value");
        let debug_repr = format!("{:?}", result.secret());
        assert!(
            !debug_repr.contains("super_secret_value"),
            "SecretString must redact its value in Debug; got: {debug_repr}"
        );
    }

    /// TC-0034-06: An empty password supplied via `--password ""` is accepted
    /// without panicking.  Validation (min-length, etc.) is the responsibility
    /// of the caller.
    #[test]
    fn tc_0034_06_empty_password_flag_accepted() {
        if crate::test_environment::isolated() {
            return;
        }

        std::env::remove_var("PQ_DIARY_PASSWORD");

        let secret = make_secret("");
        let result = get_password(Some(&secret));
        assert!(result.is_ok(), "Empty password via flag must not panic");
        let source = result.unwrap();
        assert!(matches!(source, PasswordSource::Flag(_)));
        assert_eq!(source.secret().expose_secret(), "");
    }

    /// TC-0034-07: An empty `PQ_DIARY_PASSWORD` env var is accepted without
    /// panicking.
    #[test]
    fn tc_0034_07_empty_password_env_accepted() {
        if crate::test_environment::isolated() {
            return;
        }

        std::env::set_var("PQ_DIARY_PASSWORD", "");
        let result = get_password(None);
        // Note: get_password removes the var; the remove_var below is a no-op.
        std::env::remove_var("PQ_DIARY_PASSWORD");

        assert!(result.is_ok(), "Empty password via env var must not panic");
        let source = result.unwrap();
        assert!(matches!(source, PasswordSource::Env(_)));
        assert_eq!(source.secret().expose_secret(), "");
    }

    /// TC-A07-01: `PQ_DIARY_PASSWORD` is removed from the environment immediately
    /// after `get_password` reads it, so child processes cannot inherit it.
    #[test]
    fn tc_a07_01_env_var_removed_after_read() {
        if crate::test_environment::isolated() {
            return;
        }

        std::env::set_var("PQ_DIARY_PASSWORD", "secret_a07_01");
        let result = get_password(None);
        assert!(result.is_ok(), "Expected Ok, got: {:?}", result.err());

        assert!(
            std::env::var("PQ_DIARY_PASSWORD").is_err(),
            "PQ_DIARY_PASSWORD must be absent from the environment after get_password returns"
        );
    }
}
