//! Owned sibling replacement shared by vault and configuration persistence.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::DiaryError;

/// Owns only a sibling successfully created with exclusive creation. The file
/// handle is closed before rename/removal, including on Windows. Cleanup is
/// best effort; this is not a physical-erasure or crash-durability guarantee.
struct OwnedTemp {
    path: PathBuf,
    armed: bool,
}

impl OwnedTemp {
    fn create(path: PathBuf) -> Result<(Self, std::fs::File), DiaryError> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        // Apply permissions before any bytes reach the file. Windows
        // continues to rely on the destination directory's ACLs.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path)?;
        Ok((Self { path, armed: true }, file))
    }
}

impl Drop for OwnedTemp {
    fn drop(&mut self) {
        if self.armed {
            if let Err(error) = std::fs::remove_file(&self.path) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    // Drop must not panic if stderr is closed or broken,
                    // especially while unwinding another failure.
                    let _ = writeln!(
                        std::io::stderr().lock(),
                        "Warning: failed to remove temporary file: {error}"
                    );
                }
            }
        }
    }
}

/// The caller must control the parent directory and enforce its own path policy.
/// This replaces (never follows) the final component, but follows parent
/// components like ordinary filesystem operations; it is not a directory-handle
/// sandbox. The callback must finish writing and syncing before returning Ok.
/// Rename is the commit point: no fallible operation follows a successful rename.
pub(super) fn write_atomic(
    path: &Path,
    write_and_sync: impl FnOnce(&mut std::fs::File) -> Result<(), DiaryError>,
) -> Result<(), DiaryError> {
    let mut name = path
        .file_name()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "destination path has no file name",
            )
        })?
        .to_os_string();
    name.push(format!(".tmp.{}", uuid::Uuid::new_v4()));
    // A collision fails closed: no ownership guard exists until create_new
    // succeeds, so an existing file, directory or symlink cannot be cleaned up.
    let (mut temp, mut file) = OwnedTemp::create(path.with_file_name(name))?;
    let result = write_and_sync(&mut file);
    drop(file);
    result?;
    // Keep the platform's existing atomic-replacement semantics. Do not delete
    // the destination first or fall back to copying over it.
    std::fs::rename(&temp.path, path)?;
    temp.armed = false;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_partial_write_and_sync_errors_preserve_original_and_primary_error() {
        use crate::vault::config::{AppConfig, VaultConfig};
        let dir = tempfile::tempdir().unwrap();
        for name in ["vault.toml", "config.toml"] {
            let path = dir.path().join(name);
            if name == "vault.toml" {
                VaultConfig::default().to_file(&path).unwrap();
            } else {
                AppConfig::default().to_file(&path).unwrap();
            }
            let original = std::fs::read(&path).unwrap();
            for sync_failure in [false, true] {
                let result = write_atomic(&path, |file| {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        assert_eq!(file.metadata()?.permissions().mode() & 0o777, 0o600);
                        assert_eq!(file.metadata()?.len(), 0);
                    }
                    file.write_all(b"synthetic partial config")?;
                    if sync_failure {
                        file.flush()?;
                    }
                    Err(std::io::Error::new(
                        std::io::ErrorKind::StorageFull,
                        "injected config I/O failure",
                    )
                    .into())
                });
                match result {
                    Err(DiaryError::Io(error)) => {
                        assert_eq!(error.kind(), std::io::ErrorKind::StorageFull);
                        assert_eq!(error.to_string(), "injected config I/O failure");
                    }
                    other => panic!("expected primary I/O failure: {other:?}"),
                }
                assert_eq!(std::fs::read(&path).unwrap(), original);
                if name == "vault.toml" {
                    VaultConfig::from_file(&path).unwrap();
                } else {
                    AppConfig::from_file(&path).unwrap();
                }
                assert!(std::fs::read_dir(dir.path()).unwrap().all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains(".tmp.")));
            }
        }
    }

    #[test]
    fn exclusive_collision_preserves_existing_paths() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.pqd.tmp.collision");
        std::fs::write(&path, b"existing file").unwrap();
        assert!(OwnedTemp::create(path.clone()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"existing file");
        let directory = dir.path().join("directory");
        std::fs::create_dir(&directory).unwrap();
        assert!(OwnedTemp::create(directory.clone()).is_err());
        assert!(directory.is_dir());
        #[cfg(unix)]
        {
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(OwnedTemp::create(link.clone()).is_err());
            assert_eq!(std::fs::read_link(&link).unwrap(), path);
            assert_eq!(std::fs::read(&path).unwrap(), b"existing file");
            let dangling = dir.path().join("dangling");
            std::os::unix::fs::symlink(dir.path().join("absent"), &dangling).unwrap();
            assert!(OwnedTemp::create(dangling.clone()).is_err());
            assert!(std::fs::symlink_metadata(dangling).unwrap().is_symlink());
            assert!(!dir.path().join("absent").exists());
        }
    }
}
