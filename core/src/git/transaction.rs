//! Git's ref update is the commit point. Never restore the vault after HEAD moves.
//! The real index lock excludes ordinary Git index writers, not alternate-index
//! commits, direct ref mutation, or non-Git vault writers during this short phase.
//! Hooks run normally, but arbitrary replacement of owned backup/staging paths
//! is outside the ownership guarantee; their side effects cannot be rolled back.
use super::*;
use reconciliation::{git_stdout, pin_commit};
use std::process::Command;

fn command(dir: &Path, index: Option<&Path>) -> Command {
    let mut c = Command::new("git");
    c.current_dir(dir)
        .env("GIT_GRAFT_FILE", "")
        .env("GIT_NO_REPLACE_OBJECTS", "1");
    if let Some(index) = index {
        c.env("GIT_INDEX_FILE", index);
    }
    c
}
fn output(c: &mut Command) -> Result<Vec<u8>, DiaryError> {
    let out = c.output()?;
    if !out.status.success() {
        return Err(DiaryError::Git(
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ));
    }
    Ok(out.stdout)
}
fn value(bytes: Vec<u8>) -> Result<String, DiaryError> {
    String::from_utf8(bytes)
        .map(|s| s.trim_end_matches('\n').to_owned())
        .map_err(|_| DiaryError::Git("non-UTF-8 Git metadata".into()))
}
fn git_path(dir: &Path, name: &str) -> Result<PathBuf, DiaryError> {
    Ok(PathBuf::from(value(git_stdout(
        dir,
        &["rev-parse", "--path-format=absolute", "--git-path", name],
    )?)?))
}
pub(super) fn ancestry_needed(dir: &Path, local: &str, remote: &str) -> Result<bool, DiaryError> {
    let out = command(dir, None)
        .args(["merge-base", "--is-ancestor", remote, local])
        .output()?;
    match out.status.code() {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        _ => Err(DiaryError::Git("cannot determine remote ancestry".into())),
    }
}
pub(super) fn validate_remote_tree(dir: &Path, base: &str, remote: &str) -> Result<(), DiaryError> {
    let raw = git_stdout(
        dir,
        &[
            "diff-tree",
            "--no-renames",
            "--raw",
            "-r",
            "-z",
            base,
            remote,
            "--",
        ],
    )?;
    let mut parts = raw.split(|b| *b == 0);
    while let Some(meta) = parts.next().filter(|p| !p.is_empty()) {
        let path = parts
            .next()
            .ok_or_else(|| DiaryError::Git("invalid remote tree diff".into()))?;
        // Config semantics have already been checked. Do not acknowledge unrelated
        // remote files, additions/deletions, or mode/type changes we cannot merge.
        if !matches!(path, b"vault.pqd" | b"vault.toml")
            || !meta.starts_with(b":100644 100644 ")
            || !meta.ends_with(b" M")
        {
            return Err(DiaryError::Git("remote history changes unsupported files or modes; preserve both copies and review manually".into()));
        }
    }
    Ok(())
}
const STATES: &[&str] = &[
    "MERGE_HEAD",
    "MERGE_MODE",
    "MERGE_MSG",
    "SQUASH_MSG",
    "MERGE_AUTOSTASH",
    "CHERRY_PICK_HEAD",
    "REVERT_HEAD",
    "sequencer",
    "rebase-merge",
    "rebase-apply",
];
fn validate_state(dir: &Path) -> Result<(), DiaryError> {
    let root = PathBuf::from(value(git_stdout(dir, &["rev-parse", "--show-toplevel"])?)?);
    if std::fs::canonicalize(root)? != std::fs::canonicalize(dir)? {
        return Err(DiaryError::Git(
            "git pull requires the repository root".into(),
        ));
    }
    for name in STATES {
        match std::fs::symlink_metadata(git_path(dir, name)?) {
            Ok(_) => {
                return Err(DiaryError::Git(format!(
                    "existing Git operation state {name}; finish it before pulling"
                )))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    if !git_stdout(dir, &["ls-files", "--unmerged", "-z"])?.is_empty()
        || !git_stdout(
            dir,
            &[
                "diff",
                "--cached",
                "--name-only",
                "-z",
                "HEAD",
                "--",
                "vault.pqd",
            ],
        )?
        .is_empty()
    {
        return Err(DiaryError::Git(
            "unmerged index or separately staged vault; preserve staging before pulling".into(),
        ));
    }
    Ok(())
}
struct OwnedPath {
    path: PathBuf,
    armed: bool,
    directory: bool,
}
impl OwnedPath {
    fn file(path: PathBuf, bytes: &[u8]) -> Result<Self, DiaryError> {
        Self::write_file(path, |file| file.write_all(bytes))
    }
    fn write_file(
        path: PathBuf,
        write: impl FnOnce(&mut std::fs::File) -> std::io::Result<()>,
    ) -> Result<Self, DiaryError> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path)?;
        let owned = Self {
            path,
            armed: true,
            directory: false,
        };
        let result = write(&mut file).and_then(|_| file.sync_all());
        drop(file);
        result?;
        Ok(owned)
    }
    fn directory(path: PathBuf) -> Result<Self, DiaryError> {
        std::fs::create_dir(&path)?;
        Ok(Self {
            path,
            armed: true,
            directory: true,
        })
    }
}
impl Drop for OwnedPath {
    fn drop(&mut self) {
        if self.armed {
            let result = if self.directory {
                std::fs::remove_dir_all(&self.path)
            } else {
                std::fs::remove_file(&self.path)
            };
            if let Err(e) = result {
                if e.kind() != std::io::ErrorKind::NotFound {
                    let _ = writeln!(
                        std::io::stderr(),
                        "warning: could not remove owned Git staging {}: {e}",
                        self.path.display()
                    );
                }
            }
        }
    }
}
pub(super) struct Commit<'a> {
    pub dir: &'a Path,
    pub path: &'a Path,
    pub local: &'a str,
    pub remote: &'a str,
    pub config: &'a VaultConfig,
    pub timestamp: &'a str,
    pub original: &'a [u8],
    pub merge: bool,
}
pub(super) fn apply(
    c: Commit<'_>,
    revalidate: impl FnOnce() -> Result<(), DiaryError>,
    write: impl FnOnce() -> Result<(), DiaryError>,
) -> Result<(), DiaryError> {
    validate_state(c.dir)?;
    let index = git_path(c.dir, "index")?;
    let mut lock_name = index.as_os_str().to_os_string();
    lock_name.push(".lock");
    let mut lock = OwnedPath::file(PathBuf::from(lock_name), &[])?;
    if !std::fs::symlink_metadata(&index)?.file_type().is_file() {
        return Err(DiaryError::Git(
            "effective Git index must be a regular file".into(),
        ));
    }
    let original_index = std::fs::read(&index)?;
    validate_state(c.dir)?;
    revalidate()?;
    let mut staging = OwnedPath::directory(git_path(
        c.dir,
        &format!("pqd-merge-{}", uuid::Uuid::new_v4()),
    )?)?;
    let private_index = staging.path.join("commit-index");
    let preserved_index = staging.path.join("preserved-index");
    output(command(c.dir, Some(&private_index)).args(["read-tree", c.local]))?;
    std::fs::write(&preserved_index, &original_index)?;
    let backup_path = c.path.with_file_name("vault.pqd.bak");
    let mut backup = OwnedPath::file(backup_path.clone(), c.original)?;
    // Backup remains recoverable on every failure after this point.
    backup.armed = false;
    let mut merge_files: Vec<OwnedPath> = Vec::new();
    let prepared = (|| {
        write()?;
        // Pull already validated this path against the repository's vault.pqd.
        // Use its relative name: canonicalize produces a verbatim Windows path
        // (\\?\...) which Git for Windows cannot open here.
        let blob = value(output(
            command(c.dir, None)
                .args(["hash-object", "-w", "--no-filters"])
                .arg("vault.pqd"),
        )?)?;
        for target in [&private_index, &preserved_index] {
            output(command(c.dir, Some(target)).args([
                "update-index",
                "--add",
                "--cacheinfo",
                "100644",
                &blob,
                "vault.pqd",
            ]))?;
        }
        let tree = value(output(
            command(c.dir, Some(&private_index)).arg("write-tree"),
        )?)?;
        let candidate = std::fs::read(&preserved_index)?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&lock.path)?;
        file.write_all(&candidate)?;
        file.sync_all()?;
        drop(file);
        if c.merge {
            for (name, bytes) in [
                ("MERGE_HEAD", format!("{}\n", c.remote)),
                ("MERGE_MODE", "no-ff".into()),
                ("MERGE_MSG", c.config.git.commit_message.clone()),
            ] {
                merge_files.push(OwnedPath::file(git_path(c.dir, name)?, bytes.as_bytes())?);
            }
        }
        if pin_commit(c.dir, "HEAD")? != c.local {
            return Err(DiaryError::Git("HEAD changed before commit".into()));
        }
        Ok(tree)
    })();
    let tree = match prepared {
        Ok(tree) => tree,
        Err(error) => {
            restore(c.path, c.original)?;
            return Err(error);
        }
    };
    let committed = command(c.dir, Some(&private_index))
        .arg("-c")
        .arg(format!("user.name={}", c.config.git.author_name))
        .arg("-c")
        .arg(format!("user.email={}", c.config.git.author_email))
        .args([
            "commit",
            "--date",
            c.timestamp,
            "-m",
            &c.config.git.commit_message,
        ])
        .env("GIT_AUTHOR_DATE", c.timestamp)
        .env("GIT_COMMITTER_DATE", c.timestamp)
        .output();
    let observed = pin_commit(c.dir, "HEAD");
    if observed.as_ref().is_ok_and(|head| head == c.local) {
        restore(c.path, c.original)?;
        return Err(DiaryError::Git(format!(
            "git commit did not update HEAD; vault restored, backup retained: {}",
            match committed {
                Ok(out) => String::from_utf8_lossy(&out.stderr).into_owned(),
                Err(e) => e.to_string(),
            }
        )));
    }
    // Git may have consumed these paths, and hooks may have recreated them.
    for file in &mut merge_files {
        file.armed = false;
    }
    staging.armed = false;
    lock.armed = false;
    let expected_parents = if c.merge {
        format!("{} {}", c.local, c.remote)
    } else {
        c.local.to_owned()
    };
    let exact = observed
        .and_then(|head| {
            value(git_stdout(
                c.dir,
                &["show", "-s", "--format=%T%n%P", &head],
            )?)
        })
        .is_ok_and(|description| description == format!("{tree}\n{expected_parents}"));
    if !exact {
        return Err(DiaryError::Git(format!("commit outcome uncertain or unexpected; vault was not rolled back. Preserve backup {} and index recovery {} for manual review", backup_path.display(), staging.path.display())));
    }
    if let Err(e) = std::fs::rename(&lock.path, &index) {
        return Err(DiaryError::Git(format!(
            "commit created; index recovery required: {e}. Preserve {} and {}",
            staging.path.display(),
            backup_path.display()
        )));
    }
    // Ownership transferred at rename; no fallible operation may re-arm it.
    if committed.as_ref().map_or(true, |out| !out.status.success()) {
        let _ = writeln!(
            std::io::stderr(),
            "warning: Git reported a post-commit error; verified commit and index were saved"
        );
    }
    staging.armed = true;
    // Do not remove an obviously replaced recovery path. This is a conservative
    // content/type check, not protection against hostile concurrent replacement.
    let backup_unchanged = std::fs::symlink_metadata(&backup.path)
        .is_ok_and(|metadata| metadata.file_type().is_file())
        && std::fs::read(&backup.path).is_ok_and(|bytes| bytes == c.original);
    if backup_unchanged {
        backup.armed = true;
    } else {
        let _ = writeln!(
            std::io::stderr(),
            "warning: recovery backup changed; retained {}",
            backup.path.display()
        );
    }
    Ok(())
}
fn restore(path: &Path, bytes: &[u8]) -> Result<(), DiaryError> {
    // The authenticated captured bytes remain in the exclusive recovery backup if
    // restoration itself fails. Do not touch refs or the caller's real index.
    std::fs::write(path, bytes).map_err(|e| {
        DiaryError::Git(format!(
            "commit failed and vault restoration failed; retain vault.pqd.bak: {e}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn partial_owned_writes_clean_up_but_collisions_preserve_existing_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("candidate");
        let failure = OwnedPath::write_file(path.clone(), |file| {
            file.write_all(b"partial")?;
            Err(std::io::Error::other("injected partial write"))
        });
        assert!(failure.is_err());
        assert!(!path.exists());
        std::fs::write(&path, b"preexisting").unwrap();
        assert!(OwnedPath::file(path.clone(), b"replacement").is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"preexisting");
    }
}
