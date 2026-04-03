//! Secure temporary file management for the pq-diary editor integration.
//!
//! Provides a secure temporary directory selection strategy and a
//! cryptographically overwritten file deletion primitive used when the
//! external editor finishes working with a plaintext entry.
//!
//! Items here are consumed by command handlers implemented in subsequent tasks
//! (TASK-0036 onwards).
// Allow dead_code until the command handlers wire these up.
#![allow(dead_code)]

use pq_diary_core::DiaryError;
use std::path::{Path, PathBuf};

// =============================================================================
// Public API
// =============================================================================

/// Returns a platform-appropriate secure temporary directory.
///
/// The directory is created with owner-only access permissions.
///
/// **Unix selection order**:
/// 1. `/dev/shm/pq-diary-{uid}/` — RAM-backed (Linux), highest priority
/// 2. `/run/user/{uid}/pq-diary/` — `tmpfs` managed by `systemd-logind`
/// 3. `/tmp/pq-diary-{uid}/` — on-disk fallback; a warning is written to
///    `stderr` before returning this path
///
/// **Windows**: creates `%LOCALAPPDATA%\pq-diary\tmp\` and applies an ACL
/// granting full control to the current user only (inheritance removed).
///
/// # Errors
///
/// Returns [`DiaryError::Editor`] if the directory cannot be created, or if
/// required environment variables (`LOCALAPPDATA`, `USERNAME`) are absent.
pub fn secure_tmpdir() -> Result<PathBuf, DiaryError> {
    #[cfg(unix)]
    {
        secure_tmpdir_unix()
    }
    #[cfg(windows)]
    {
        secure_tmpdir_windows()
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(DiaryError::Editor(
            "Secure temporary directory is not supported on this platform".to_string(),
        ))
    }
}

/// Overwrites a file with random data, flushes to disk, then deletes it.
///
/// This reduces the risk of recovering sensitive content from the storage
/// medium.  The overwrite buffer is zeroed before being freed.
///
/// **Steps**:
/// 1. Read the file size via `metadata`.
/// 2. Fill a buffer of that length with `OsRng` random bytes.
/// 3. Open the file in write mode, call `write_all`, then `sync_all`.
/// 4. Zeroize the buffer.
/// 5. Remove the file with `remove_file`.
///
/// # Errors
///
/// Returns [`DiaryError::Io`] if any I/O operation fails (file not found,
/// permission denied, etc.).
pub fn secure_delete(path: &Path) -> Result<(), DiaryError> {
    use rand::RngCore as _;
    use std::io::Write as _;
    use zeroize::Zeroize as _;

    let len = std::fs::metadata(path)?.len() as usize;

    let mut buf = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut buf);

    {
        let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
        file.write_all(&buf)?;
        file.sync_all()?;
    }

    buf.zeroize();
    std::fs::remove_file(path)?;

    Ok(())
}

// =============================================================================
// Unix implementation
// =============================================================================

#[cfg(unix)]
fn secure_tmpdir_unix() -> Result<PathBuf, DiaryError> {
    let uid = nix::unistd::getuid().as_raw();

    // Priority 1: /dev/shm  (RAM-backed tmpfs on Linux)
    {
        let base = Path::new("/dev/shm");
        if base.is_dir() {
            let dir = base.join(format!("pq-diary-{uid}"));
            if ensure_dir_0700(&dir).is_ok() {
                return Ok(dir);
            }
        }
    }

    // Priority 2: /run/user/$UID  (tmpfs managed by systemd-logind)
    {
        let base = PathBuf::from(format!("/run/user/{uid}"));
        if base.is_dir() {
            let dir = base.join("pq-diary");
            if ensure_dir_0700(&dir).is_ok() {
                return Ok(dir);
            }
        }
    }

    // Priority 3: /tmp  (on-disk fallback)
    eprintln!("Warning: No memory-based temporary directory is available. Using /tmp.");
    let dir = PathBuf::from(format!("/tmp/pq-diary-{uid}"));
    ensure_dir_0700(&dir)?;
    Ok(dir)
}

/// Creates `dir` with `0o700` permissions.
///
/// If the directory already exists its permissions are updated to `0o700`.
/// Returns an error if creation or permission-setting fails.
#[cfg(unix)]
fn ensure_dir_0700(dir: &Path) -> Result<(), DiaryError> {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

    if dir.is_dir() {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
            DiaryError::Editor(format!("Failed to set tmpdir permissions: {e}"))
        })?;
        return Ok(());
    }

    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(dir)
        .map_err(|e| DiaryError::Editor(format!("Failed to create tmpdir: {e}")))
}

// =============================================================================
// Windows implementation
// =============================================================================

#[cfg(windows)]
fn secure_tmpdir_windows() -> Result<PathBuf, DiaryError> {
    let local_app_data = std::env::var("LOCALAPPDATA").map_err(|_| {
        DiaryError::Editor("LOCALAPPDATA environment variable is not set".to_string())
    })?;

    let dir = PathBuf::from(&local_app_data).join("pq-diary").join("tmp");

    std::fs::create_dir_all(&dir)
        .map_err(|e| DiaryError::Editor(format!("Failed to create temp directory: {e}")))?;

    set_owner_only_acl(&dir)?;

    Ok(dir)
}

/// Restricts `path` to the current user by invoking `icacls`.
///
/// Removes inherited ACEs (`/inheritance:r`) and grants the current user
/// object-inherit + container-inherit full control (`(OI)(CI)F`).
#[cfg(windows)]
fn set_owner_only_acl(path: &Path) -> Result<(), DiaryError> {
    let username = std::env::var("USERNAME").map_err(|_| {
        DiaryError::Editor("USERNAME environment variable is not set".to_string())
    })?;

    let path_str = path.to_str().ok_or_else(|| {
        DiaryError::Editor(
            "Temp directory path contains non-UTF-8 characters".to_string(),
        )
    })?;

    let status = std::process::Command::new("icacls")
        .arg(path_str)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(format!("{}:(OI)(CI)F", username))
        .status()
        .map_err(|e| DiaryError::Editor(format!("Failed to run icacls: {e}")))?;

    if !status.success() {
        return Err(DiaryError::Editor(
            "icacls failed to set directory ACL".to_string(),
        ));
    }

    Ok(())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // secure_delete tests
    // -------------------------------------------------------------------------

    /// TC-0035-01: secure_delete removes the file after overwriting with random
    /// data.
    #[test]
    fn tc_0035_01_secure_delete_removes_file() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let file_path = dir.path().join("tc0035_01.txt");
        std::fs::write(&file_path, b"sensitive content").expect("write failed");

        let result = secure_delete(&file_path);
        assert!(result.is_ok(), "secure_delete failed: {:?}", result.err());
        assert!(
            !file_path.exists(),
            "File must not exist after secure_delete"
        );
    }

    /// TC-0035-02: secure_delete on a nonexistent file returns an error.
    #[test]
    fn tc_0035_02_secure_delete_nonexistent_returns_error() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let file_path = dir.path().join("nonexistent_tc0035_02.txt");

        let result = secure_delete(&file_path);
        assert!(result.is_err(), "Expected error for nonexistent file");
        assert!(
            matches!(result, Err(DiaryError::Io(_))),
            "Expected DiaryError::Io, got: {:?}",
            result
        );
    }

    /// TC-0035-03: secure_delete on a zero-byte file succeeds without panic.
    #[test]
    fn tc_0035_03_secure_delete_empty_file() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let file_path = dir.path().join("empty_tc0035_03.txt");
        std::fs::write(&file_path, b"").expect("write failed");

        let result = secure_delete(&file_path);
        assert!(
            result.is_ok(),
            "secure_delete on empty file failed: {:?}",
            result.err()
        );
        assert!(
            !file_path.exists(),
            "Empty file must not exist after secure_delete"
        );
    }

    // -------------------------------------------------------------------------
    // secure_tmpdir tests
    // -------------------------------------------------------------------------

    /// TC-0035-04: secure_tmpdir returns an existing directory.
    #[test]
    fn tc_0035_04_secure_tmpdir_creates_dir() {
        let result = secure_tmpdir();
        assert!(result.is_ok(), "secure_tmpdir failed: {:?}", result.err());
        let dir = result.unwrap();
        assert!(
            dir.is_dir(),
            "secure_tmpdir must return an existing directory: {dir:?}"
        );
    }

    /// TC-0035-05: calling secure_tmpdir twice succeeds and returns the same
    /// path (idempotent).
    #[test]
    fn tc_0035_05_secure_tmpdir_idempotent() {
        let first = secure_tmpdir().expect("first call failed");
        let second = secure_tmpdir().expect("second call failed");
        assert_eq!(first, second, "Both calls must return the same path");
    }

    /// TC-0035-06 (Unix): returned directory has exactly `0o700` permissions.
    #[cfg(unix)]
    #[test]
    fn tc_0035_06_unix_permissions_0700() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = secure_tmpdir().expect("secure_tmpdir failed");
        let perms = std::fs::metadata(&dir)
            .expect("metadata failed")
            .permissions();
        let mode = perms.mode() & 0o777;
        assert_eq!(mode, 0o700, "Expected 0o700, got 0o{mode:o}");
    }

    /// TC-0035-07 (Unix): `/dev/shm` is preferred when available.
    #[cfg(unix)]
    #[test]
    fn tc_0035_07_unix_prefers_devshm() {
        if !Path::new("/dev/shm").is_dir() {
            return; // /dev/shm not available on this host; skip
        }
        let dir = secure_tmpdir().expect("secure_tmpdir failed");
        assert!(
            dir.starts_with("/dev/shm"),
            "/dev/shm is present but was not selected; got: {dir:?}"
        );
    }

    /// TC-0035-08 (Windows): directory is inside `%LOCALAPPDATA%\pq-diary\tmp`.
    #[cfg(windows)]
    #[test]
    fn tc_0035_08_windows_localappdata_path() {
        let expected_suffix = std::path::Path::new("pq-diary").join("tmp");
        let dir = secure_tmpdir().expect("secure_tmpdir failed");
        assert!(
            dir.ends_with(&expected_suffix),
            "Expected path ending with pq-diary\\tmp, got: {dir:?}"
        );
    }

    /// TC-0035-09 (Windows): the current user can write to the secure temp
    /// directory (confirms ACL grants access to the owner).
    #[cfg(windows)]
    #[test]
    fn tc_0035_09_windows_owner_can_write() {
        let dir = secure_tmpdir().expect("secure_tmpdir failed");
        let test_file = dir.join(".perm_test_tc0035_09");
        let write_result = std::fs::write(&test_file, b"acl_test");
        assert!(
            write_result.is_ok(),
            "Owner must be able to write to the secure temp directory"
        );
        let _ = std::fs::remove_file(&test_file);
    }
}
