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
/// 1. `flag_value` — value of the `--password` CLI argument, if present.
///    A warning is written to stderr because passing passwords on the command
///    line is insecure.
/// 2. `PQ_DIARY_PASSWORD` environment variable.
/// 3. Interactive TTY prompt with echo disabled.
///
/// # Errors
///
/// Returns [`DiaryError::Password`] when stdin is not a terminal and neither
/// `flag_value` nor `PQ_DIARY_PASSWORD` is set.
pub fn get_password(flag_value: Option<&str>) -> Result<PasswordSource, DiaryError> {
    // Stage 1: --password flag
    if let Some(v) = flag_value {
        eprintln!("Warning: Specifying a password on the command line is a security risk.");
        return Ok(PasswordSource::Flag(SecretBox::new(v.into())));
    }

    // Stage 2: PQ_DIARY_PASSWORD environment variable
    if let Ok(env_pass) = std::env::var("PQ_DIARY_PASSWORD") {
        return Ok(PasswordSource::Env(SecretBox::new(
            env_pass.into_boxed_str(),
        )));
    }

    // Stage 3: interactive TTY prompt
    use std::io::IsTerminal as _;
    if std::io::stdin().is_terminal() {
        return read_password_tty().map(PasswordSource::Tty);
    }

    Err(DiaryError::Password(
        "No password provided and stdin is not a terminal".to_string(),
    ))
}

// =============================================================================
// Platform-specific TTY implementations
// =============================================================================

/// Read a password from the controlling TTY with echo disabled (Unix).
///
/// Opens `/dev/tty` directly so that reading works even when stdin is
/// redirected.  Terminal echo flags (`ECHO`, `ECHOE`, `ECHOK`, `ECHONL`) are
/// disabled via `termios` and restored on return through a RAII guard.
#[cfg(unix)]
fn read_password_tty() -> Result<SecretString, DiaryError> {
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
            let _ = nix::sys::termios::tcsetattr(
                &self.file,
                nix::sys::termios::SetArg::TCSANOW,
                &self.old,
            );
        }
    }
    let mut guard = TtyGuard {
        file: tty,
        old: old_attrs,
    };

    // Print the password prompt.
    write!(guard.file, "Password: ")
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
/// restored before the function returns.
#[cfg(windows)]
fn read_password_tty() -> Result<SecretString, DiaryError> {
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, ReadConsoleW, SetConsoleMode, ENABLE_ECHO_INPUT,
        STD_INPUT_HANDLE,
    };
    use zeroize::Zeroizing;

    // SAFETY: This block calls Win32 console APIs which require `unsafe` as
    // they are raw FFI functions from windows-sys.  The pattern (save mode →
    // modify → use → restore) is the standard Windows approach for disabling
    // console echo, directly analogous to the Unix termios pattern above.
    // All handles and buffers used here are valid for the lifetime of this
    // function.
    unsafe {
        let handle = GetStdHandle(STD_INPUT_HANDLE);
        // INVALID_HANDLE_VALUE = -1 as pointer; null = 0 pointer (both invalid)
        if handle.is_null() || (handle as isize) == -1 {
            return Err(DiaryError::Password(
                "Failed to obtain stdin console handle".to_string(),
            ));
        }

        let mut old_mode: u32 = 0;
        if GetConsoleMode(handle, &mut old_mode) == 0 {
            return Err(DiaryError::Password(
                "Failed to read console mode".to_string(),
            ));
        }

        // Disable echo input.
        let new_mode = old_mode & !ENABLE_ECHO_INPUT;
        if SetConsoleMode(handle, new_mode) == 0 {
            return Err(DiaryError::Password(
                "Failed to disable console echo".to_string(),
            ));
        }

        // Print the prompt to stderr so it is always visible.
        eprint!("Password: ");

        // Read up to 256 UTF-16 code units from the console.
        let mut buf: Zeroizing<[u16; 256]> = Zeroizing::new([0u16; 256]);
        let mut chars_read: u32 = 0;
        let ok = ReadConsoleW(
            handle,
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
            &mut chars_read,
            std::ptr::null(),
        );

        // Restore console mode before any early return.
        let _ = SetConsoleMode(handle, old_mode);
        eprintln!(); // newline after the hidden input

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
}

/// Fallback for platforms that support neither Unix termios nor Win32 console.
#[cfg(not(any(unix, windows)))]
fn read_password_tty() -> Result<SecretString, DiaryError> {
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

    /// Mutex to serialize tests that read/write the `PQ_DIARY_PASSWORD`
    /// environment variable.  Env vars are process-global state, so concurrent
    /// access from parallel tests causes flaky failures.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// TC-0034-01: `--password` flag returns `PasswordSource::Flag` with the
    /// correct secret value.
    #[test]
    fn tc_0034_01_flag_returns_flag_source() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::remove_var("PQ_DIARY_PASSWORD");

        let result = get_password(Some("flag_test_password"));
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
        let _lock = ENV_LOCK.lock().unwrap();

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
        let _lock = ENV_LOCK.lock().unwrap();

        std::env::set_var("PQ_DIARY_PASSWORD", "env_pass_03");
        let result = get_password(Some("flag_pass_03"));
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
        let _lock = ENV_LOCK.lock().unwrap();

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
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::remove_var("PQ_DIARY_PASSWORD");

        let result = get_password(Some("super_secret_value")).expect("Expected Ok");
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
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::remove_var("PQ_DIARY_PASSWORD");

        let result = get_password(Some(""));
        assert!(result.is_ok(), "Empty password via flag must not panic");
        let source = result.unwrap();
        assert!(matches!(source, PasswordSource::Flag(_)));
        assert_eq!(source.secret().expose_secret(), "");
    }

    /// TC-0034-07: An empty `PQ_DIARY_PASSWORD` env var is accepted without
    /// panicking.
    #[test]
    fn tc_0034_07_empty_password_env_accepted() {
        let _lock = ENV_LOCK.lock().unwrap();

        std::env::set_var("PQ_DIARY_PASSWORD", "");
        let result = get_password(None);
        std::env::remove_var("PQ_DIARY_PASSWORD");

        assert!(result.is_ok(), "Empty password via env var must not panic");
        let source = result.unwrap();
        assert!(matches!(source, PasswordSource::Env(_)));
        assert_eq!(source.secret().expose_secret(), "");
    }
}
