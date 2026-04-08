//! Secure temporary file management and external editor integration for pq-diary.
//!
//! Provides a secure temporary directory selection strategy, header comment
//! formatting for `$EDITOR`-edited temporary files, and editor process management.

use pq_diary_core::{DiaryError, EntryPlaintext};
use std::path::{Path, PathBuf};

// =============================================================================
// Public Types
// =============================================================================

/// Configuration for launching an external editor.
///
/// Build with [`EditorConfig::from_env`] to read `$EDITOR` and detect
/// vim/neovim for security-option injection.
pub struct EditorConfig {
    /// Editor command (`$EDITOR` or platform fallback: `"vi"` / `"notepad"`).
    pub command: String,

    /// Extra arguments for vim/neovim: `["-c", "set noswapfile nobackup noundofile"]`.
    /// Empty for all other editors.
    pub vim_options: Vec<String>,

    /// Secure temporary directory obtained from [`secure_tmpdir`].
    pub secure_tmpdir: PathBuf,
}

impl EditorConfig {
    /// Construct an `EditorConfig` from the current environment.
    ///
    /// - Reads `$EDITOR`; falls back to `"vi"` on Unix and `"notepad"` on Windows.
    /// - Prepends `-c "set noswapfile nobackup noundofile"` for `vim`/`nvim`.
    /// - Calls [`secure_tmpdir`] to resolve the temporary directory.
    ///
    /// # Errors
    ///
    /// Returns [`DiaryError::Editor`] if [`secure_tmpdir`] fails.
    pub fn from_env() -> Result<Self, DiaryError> {
        let command = std::env::var("EDITOR").unwrap_or_else(|_| default_editor());
        let vim_options = vim_options_for(&command);
        let secure_tmpdir = secure_tmpdir()?;
        Ok(Self {
            command,
            vim_options,
            secure_tmpdir,
        })
    }
}

/// Parsed result of a header-comment temporary file.
///
/// Fields are `None` when the file does not contain a valid header (i.e. the
/// `# ---` separator line is absent).
pub struct HeaderComment {
    /// Entry title extracted from the `# Title:` line; `None` if absent or header invalid.
    pub title: Option<String>,

    /// Tag list extracted from the `# Tags:` line; `None` if absent or header invalid.
    pub tags: Option<Vec<String>>,

    /// Entry body: content after `# ---`, or the whole file when no header is present.
    pub body: String,
}

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

/// Write an [`EntryPlaintext`] to a header-comment formatted temporary file.
///
/// The file is created inside `tmpdir` with a UUID-based filename (`{uuid}.md`).
///
/// **Output format**:
/// ```text
/// # Title: {title}
/// # Tags: {tag1}, {tag2}
/// # ---
///
/// {body}
/// ```
///
/// An empty tag list produces `# Tags:` with no content after the colon.
///
/// # Errors
///
/// Returns [`DiaryError::Io`] on file creation or write failure.
pub fn write_header_file(tmpdir: &Path, plaintext: &EntryPlaintext) -> Result<PathBuf, DiaryError> {
    use std::io::Write as _;

    let filename = format!("{}.md", uuid::Uuid::new_v4().as_simple());
    let path = tmpdir.join(&filename);

    let tags_str = plaintext.tags.join(", ");
    let content = format!(
        "# Title: {}\n# Tags: {}\n# ---\n\n{}",
        plaintext.title, tags_str, plaintext.body
    );

    let mut file = std::fs::File::create(&path)?;
    file.write_all(content.as_bytes())?;

    Ok(path)
}

/// Parse a header-comment formatted file into [`HeaderComment`].
///
/// **Parse rules**:
/// - Lines before `# ---` are scanned for `# Title: ` and `# Tags: `.
/// - The `# Tags:` value is split on commas; empty strings are discarded.
/// - Body is the content after `# ---` (one leading blank line is skipped).
///
/// **Fallback when no `# ---` separator is found**:
/// - `title` and `tags` are set to `None`.
/// - `body` contains the entire raw file content.
///
/// # Errors
///
/// Returns [`DiaryError::Io`] if the file cannot be read.
pub fn read_header_file(path: &Path) -> Result<HeaderComment, DiaryError> {
    let content = std::fs::read_to_string(path)?;

    let lines: Vec<&str> = content.lines().collect();

    let sep_idx = lines.iter().position(|l| *l == "# ---");

    let Some(sep_idx) = sep_idx else {
        // No separator: invalid format — return whole content as body.
        return Ok(HeaderComment {
            title: None,
            tags: None,
            body: content,
        });
    };

    let mut title: Option<String> = None;
    let mut tags: Option<Vec<String>> = None;

    for line in &lines[..sep_idx] {
        if let Some(t) = line.strip_prefix("# Title: ") {
            title = Some(t.to_string());
        } else if let Some(t) = line.strip_prefix("# Tags: ") {
            let tag_str = t.trim();
            if tag_str.is_empty() {
                tags = Some(vec![]);
            } else {
                tags = Some(
                    tag_str
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect(),
                );
            }
        }
    }

    // Body = lines after the separator.
    // Skip exactly one leading blank line (the blank line between header and body).
    let after_sep = &lines[sep_idx + 1..];
    let body = if after_sep.first().is_some_and(|l| l.is_empty()) {
        after_sep[1..].join("\n")
    } else {
        after_sep.join("\n")
    };

    Ok(HeaderComment { title, tags, body })
}

/// Write a blank template body to a temporary plain-text file.
///
/// The file is created inside `tmpdir` with a UUID-based filename (`{uuid}.md`)
/// and contains no content, allowing the user to write the template body from scratch.
///
/// # Errors
///
/// Returns [`DiaryError::Io`] on file creation failure.
pub fn write_template_file(tmpdir: &Path) -> Result<PathBuf, DiaryError> {
    let filename = format!("{}.md", uuid::Uuid::new_v4().as_simple());
    let path = tmpdir.join(&filename);
    std::fs::File::create(&path)?;
    Ok(path)
}

/// Read the contents of a template temporary file as plain text.
///
/// Unlike [`read_header_file`], this function returns the raw file contents
/// without any header parsing.
///
/// # Errors
///
/// Returns [`DiaryError::Io`] if the file cannot be read.
pub fn read_template_file(path: &Path) -> Result<String, DiaryError> {
    std::fs::read_to_string(path).map_err(DiaryError::from)
}

/// Write a list of entry titles to a temporary completion file.
///
/// The file is created inside `tmpdir` with a UUID-based filename
/// (`{uuid}.completion`) and contains one title per line (joined by `"\n"`).
/// Only titles are written — no body text or tag information.
///
/// # Errors
///
/// Returns [`DiaryError::Io`] on file creation or write failure.
pub fn write_completion_file(tmpdir: &Path, titles: &[String]) -> Result<PathBuf, DiaryError> {
    let filename = format!("{}.completion", uuid::Uuid::new_v4().as_simple());
    let path = tmpdir.join(&filename);
    let content = titles.join("\n");
    std::fs::write(&path, content.as_bytes())?;
    Ok(path)
}

/// Returns vim/neovim `[[title]]` completion options for the given completion file.
///
/// Reads `$EDITOR` (falling back to the platform default) to detect vim/nvim.
/// For vim or nvim, returns `["-c", "<vim-script>"]` that defines the
/// `PqDiaryComplete` completefunc, which reads titles from `completion_file`
/// and filters them by the typed base string.
/// Returns an empty vector for all other editors.
pub fn vim_completion_options(completion_file: &Path) -> Vec<String> {
    let command = std::env::var("EDITOR").unwrap_or_else(|_| default_editor());
    vim_completion_options_for(&command, completion_file)
}

/// Launch `$EDITOR` for the given temporary file and wait for it to exit.
///
/// - vim/neovim options (`-c "set noswapfile nobackup noundofile"`) are
///   prepended when present in `config.vim_options`.
/// - `TMPDIR` (Unix), `TEMP`, and `TMP` are set to `config.secure_tmpdir`
///   so that the editor cannot leak data outside the secure area.
///
/// # Errors
///
/// - Returns [`DiaryError::Editor`] if the process cannot be spawned.
/// - Returns [`DiaryError::Editor`] if the editor exits with a non-zero status.
pub fn launch_editor(tmpfile: &Path, config: &EditorConfig) -> Result<(), DiaryError> {
    let mut cmd = std::process::Command::new(&config.command);

    for opt in &config.vim_options {
        cmd.arg(opt);
    }

    cmd.arg(tmpfile);

    let tmpdir_str = config.secure_tmpdir.to_str().ok_or_else(|| {
        DiaryError::Editor(
            "Secure tmpdir path contains non-UTF-8 characters".to_string(),
        )
    })?;

    #[cfg(unix)]
    cmd.env("TMPDIR", tmpdir_str);
    cmd.env("TEMP", tmpdir_str);
    cmd.env("TMP", tmpdir_str);

    let status = cmd
        .status()
        .map_err(|e| DiaryError::Editor(format!("Failed to launch editor '{}': {}", config.command, e)))?;

    if !status.success() {
        return Err(DiaryError::Editor(format!(
            "Editor '{}' exited with non-zero status: {}",
            config.command,
            status.code().unwrap_or(-1)
        )));
    }

    Ok(())
}

// =============================================================================
// Private helpers
// =============================================================================

/// Returns the platform default editor when `$EDITOR` is not set.
///
/// Returns `"notepad"` on Windows and `"vi"` on all other platforms.
fn default_editor() -> String {
    if cfg!(windows) {
        "notepad".to_string()
    } else {
        "vi".to_string()
    }
}

/// Returns vim/neovim completion `-c` options for the given editor command and file.
///
/// Returns `["-c", "<vim-script>"]` when the basename of `command` is `"vim"`
/// or `"nvim"` (`.exe` suffix stripped on Windows).  The vim script defines
/// `PqDiaryComplete` as the `completefunc` and reads titles from `completion_file`.
/// Path separators in `completion_file` are normalised to `/` for vim script
/// compatibility on Windows.
/// Returns an empty vector for all other editors.
fn vim_completion_options_for(command: &str, completion_file: &Path) -> Vec<String> {
    let basename = Path::new(command)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(command);
    let basename = basename.strip_suffix(".exe").unwrap_or(basename);

    if basename != "vim" && basename != "nvim" {
        return vec![];
    }

    // Normalise Windows backslashes to forward slashes for vim script.
    let path_str = completion_file
        .to_str()
        .unwrap_or("")
        .replace('\\', "/");

    let vim_script = format!(
        "set completefunc=PqDiaryComplete\n\
         function! PqDiaryComplete(findstart, base)\n\
           if a:findstart\n\
             let line = getline('.')\n\
             let start = col('.') - 1\n\
             while start > 1 && line[start-2:start-1] != '[['\n\
               let start -= 1\n\
             endwhile\n\
             return start\n\
           else\n\
             let titles = readfile('{path}')\n\
             return filter(titles, 'v:val =~ \"^\" . a:base')\n\
           endif\n\
         endfunction",
        path = path_str
    );

    vec!["-c".to_string(), vim_script]
}

/// Returns the vim/neovim security options for the given editor command.
///
/// Returns `["-c", "set noswapfile nobackup noundofile"]` when the basename
/// of `command` is `"vim"` or `"nvim"` (`.exe` suffix is stripped on Windows).
/// Returns an empty vector for all other editors.
fn vim_options_for(command: &str) -> Vec<String> {
    let basename = Path::new(command)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(command);

    let basename = basename.strip_suffix(".exe").unwrap_or(basename);

    if basename == "vim" || basename == "nvim" {
        vec![
            "-c".to_string(),
            "set noswapfile nobackup noundofile".to_string(),
        ]
    } else {
        vec![]
    }
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
    // secure_delete tests (TASK-0035)
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
    // secure_tmpdir tests (TASK-0035)
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

    // -------------------------------------------------------------------------
    // write_header_file / read_header_file round-trip tests (TASK-0036)
    // -------------------------------------------------------------------------

    fn make_plaintext(title: &str, tags: Vec<&str>, body: &str) -> EntryPlaintext {
        EntryPlaintext {
            title: title.to_string(),
            tags: tags.into_iter().map(|s| s.to_string()).collect(),
            body: body.to_string(),
        }
    }

    /// TC-0036-01: full round-trip with title, multiple tags, and body.
    #[test]
    fn tc_0036_01_roundtrip_full() {
        let dir = tempfile::tempdir().expect("tempdir");
        let plaintext = make_plaintext("My Title", vec!["tag1", "tag2", "tag3"], "Hello\nWorld");

        let path = write_header_file(dir.path(), &plaintext).expect("write_header_file");
        let header = read_header_file(&path).expect("read_header_file");

        assert_eq!(header.title, Some("My Title".to_string()));
        assert_eq!(
            header.tags,
            Some(vec!["tag1".to_string(), "tag2".to_string(), "tag3".to_string()])
        );
        assert_eq!(header.body, "Hello\nWorld");
    }

    /// TC-0036-02: round-trip with empty tag list.
    #[test]
    fn tc_0036_02_roundtrip_empty_tags() {
        let dir = tempfile::tempdir().expect("tempdir");
        let plaintext = make_plaintext("Title", vec![], "body text");

        let path = write_header_file(dir.path(), &plaintext).expect("write_header_file");
        let header = read_header_file(&path).expect("read_header_file");

        assert_eq!(header.title, Some("Title".to_string()));
        assert_eq!(header.tags, Some(vec![]));
        assert_eq!(header.body, "body text");
    }

    /// TC-0036-03: round-trip with Japanese tags and multi-line body.
    #[test]
    fn tc_0036_03_roundtrip_japanese_tags() {
        let dir = tempfile::tempdir().expect("tempdir");
        let plaintext = make_plaintext(
            "日記タイトル",
            vec!["日記", "仕事/設計"],
            "今日の出来事\n箇条書き1\n箇条書き2",
        );

        let path = write_header_file(dir.path(), &plaintext).expect("write_header_file");
        let header = read_header_file(&path).expect("read_header_file");

        assert_eq!(header.title, Some("日記タイトル".to_string()));
        assert_eq!(
            header.tags,
            Some(vec!["日記".to_string(), "仕事/設計".to_string()])
        );
        assert_eq!(header.body, "今日の出来事\n箇条書き1\n箇条書き2");
    }

    // -------------------------------------------------------------------------
    // Partial header tests (TASK-0036)
    // -------------------------------------------------------------------------

    /// TC-0036-04: title-only header (no Tags line) — title parsed, tags=None.
    #[test]
    fn tc_0036_04_partial_title_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("partial_title.md");
        std::fs::write(&path, "# Title: Only Title\n# ---\n\nbody here").expect("write");

        let header = read_header_file(&path).expect("read_header_file");

        assert_eq!(header.title, Some("Only Title".to_string()));
        assert_eq!(header.tags, None);
        assert_eq!(header.body, "body here");
    }

    /// TC-0036-05: tags-only header (no Title line) — tags parsed, title=None.
    #[test]
    fn tc_0036_05_partial_tags_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("partial_tags.md");
        std::fs::write(&path, "# Tags: foo, bar\n# ---\n\nbody content").expect("write");

        let header = read_header_file(&path).expect("read_header_file");

        assert_eq!(header.title, None);
        assert_eq!(
            header.tags,
            Some(vec!["foo".to_string(), "bar".to_string()])
        );
        assert_eq!(header.body, "body content");
    }

    // -------------------------------------------------------------------------
    // Invalid header fallback tests (TASK-0036)
    // -------------------------------------------------------------------------

    /// TC-0036-06: file with no header at all — title=None, tags=None, body=whole file.
    #[test]
    fn tc_0036_06_no_header_fallback() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("no_header.md");
        let raw = "Just plain text\nNo header here\n";
        std::fs::write(&path, raw).expect("write");

        let header = read_header_file(&path).expect("read_header_file");

        assert_eq!(header.title, None);
        assert_eq!(header.tags, None);
        assert_eq!(header.body, raw);
    }

    /// TC-0036-07: file with title/tags lines but no `# ---` separator — fallback to whole file.
    #[test]
    fn tc_0036_07_no_separator_fallback() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("no_sep.md");
        let raw = "# Title: Foo\n# Tags: bar\nsome body without separator\n";
        std::fs::write(&path, raw).expect("write");

        let header = read_header_file(&path).expect("read_header_file");

        assert_eq!(header.title, None);
        assert_eq!(header.tags, None);
        assert_eq!(header.body, raw);
    }

    // -------------------------------------------------------------------------
    // vim option detection tests (TASK-0036)
    // -------------------------------------------------------------------------

    /// TC-0036-08: "vim" command → security options are added.
    #[test]
    fn tc_0036_08_vim_options_for_vim() {
        let opts = vim_options_for("vim");
        assert_eq!(
            opts,
            vec!["-c".to_string(), "set noswapfile nobackup noundofile".to_string()]
        );
    }

    /// TC-0036-09: "nvim" command → security options are added.
    #[test]
    fn tc_0036_09_vim_options_for_nvim() {
        let opts = vim_options_for("nvim");
        assert_eq!(
            opts,
            vec!["-c".to_string(), "set noswapfile nobackup noundofile".to_string()]
        );
    }

    /// TC-0036-10: full path to vim → security options are added (basename check).
    #[cfg(unix)]
    #[test]
    fn tc_0036_10_vim_options_full_path() {
        let opts = vim_options_for("/usr/bin/vim");
        assert_eq!(
            opts,
            vec!["-c".to_string(), "set noswapfile nobackup noundofile".to_string()]
        );
    }

    /// TC-0036-11: "nano" → no vim options.
    #[test]
    fn tc_0036_11_non_vim_no_options() {
        let opts = vim_options_for("nano");
        assert!(opts.is_empty(), "nano must not produce vim options");
    }

    /// TC-0036-12: "emacs" → no vim options.
    #[test]
    fn tc_0036_12_emacs_no_options() {
        let opts = vim_options_for("emacs");
        assert!(opts.is_empty(), "emacs must not produce vim options");
    }

    /// TC-0036-13: `$EDITOR` unset → default_editor() returns platform fallback.
    #[test]
    fn tc_0036_13_default_editor_fallback() {
        let editor = default_editor();
        if cfg!(windows) {
            assert_eq!(editor, "notepad");
        } else {
            assert_eq!(editor, "vi");
        }
    }

    /// TC-0036-14: vim.exe on Windows path → security options are added.
    #[test]
    fn tc_0036_14_vim_exe_windows() {
        let opts = vim_options_for("vim.exe");
        assert_eq!(
            opts,
            vec!["-c".to_string(), "set noswapfile nobackup noundofile".to_string()]
        );
    }

    /// TC-0036-15: write_header_file creates a .md file in the given directory.
    #[test]
    fn tc_0036_15_write_creates_md_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let plaintext = make_plaintext("Test", vec!["t1"], "body");

        let path = write_header_file(dir.path(), &plaintext).expect("write_header_file");

        assert!(path.exists(), "File must exist after write_header_file");
        assert_eq!(
            path.extension().and_then(|e| e.to_str()),
            Some("md"),
            "File must have .md extension"
        );
        assert_eq!(
            path.parent().expect("parent"),
            dir.path(),
            "File must be inside the given tmpdir"
        );
    }

    /// TC-0036-16: each call to write_header_file creates a distinct file.
    #[test]
    fn tc_0036_16_write_unique_filenames() {
        let dir = tempfile::tempdir().expect("tempdir");
        let plaintext = make_plaintext("A", vec![], "b");

        let p1 = write_header_file(dir.path(), &plaintext).expect("write 1");
        let p2 = write_header_file(dir.path(), &plaintext).expect("write 2");

        assert_ne!(p1, p2, "Each write must produce a unique filename");
    }

    // -------------------------------------------------------------------------
    // write_completion_file tests (TASK-0051)
    // -------------------------------------------------------------------------

    /// TC-051-01: write_completion_file produces one-title-per-line content.
    #[test]
    fn tc_051_01_write_completion_file_content() {
        let dir = tempfile::tempdir().expect("tempdir");
        let titles = vec![
            "日記A".to_string(),
            "ミーティング".to_string(),
            "TODO".to_string(),
        ];

        let path = write_completion_file(dir.path(), &titles).expect("write_completion_file");
        let content = std::fs::read_to_string(&path).expect("read");

        assert_eq!(content, "日記A\nミーティング\nTODO");
    }

    /// TC-051-02: write_completion_file contains titles only (no body or tag info).
    #[test]
    fn tc_051_02_write_completion_file_titles_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let titles = vec!["タイトル1".to_string(), "タイトル2".to_string()];

        let path = write_completion_file(dir.path(), &titles).expect("write_completion_file");
        let content = std::fs::read_to_string(&path).expect("read");

        // Each line must be exactly one of the input titles.
        for line in content.lines() {
            assert!(
                titles.contains(&line.to_string()),
                "Completion file contains unexpected content: {line:?}"
            );
        }
        // Number of lines must match number of titles.
        assert_eq!(content.lines().count(), titles.len());
    }

    // -------------------------------------------------------------------------
    // vim_completion_options tests (TASK-0051)
    // -------------------------------------------------------------------------

    /// TC-051-03: vim_completion_options_for returns "-c" options for "vim".
    #[test]
    fn tc_051_03_vim_completion_options_for_vim() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tc051_03.completion");
        std::fs::write(&path, "").expect("write");

        let opts = vim_completion_options_for("vim", &path);
        assert!(!opts.is_empty(), "vim must produce completion options");
        assert!(
            opts.contains(&"-c".to_string()),
            "options must contain \"-c\": {opts:?}"
        );
    }

    /// TC-051-03b: vim_completion_options_for returns "-c" options for "nvim".
    #[test]
    fn tc_051_03b_vim_completion_options_for_nvim() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tc051_03b.completion");
        std::fs::write(&path, "").expect("write");

        let opts = vim_completion_options_for("nvim", &path);
        assert!(!opts.is_empty(), "nvim must produce completion options");
        assert!(opts.contains(&"-c".to_string()));
    }

    /// TC-051-04: vim_completion_options_for returns empty Vec for "nano".
    #[test]
    fn tc_051_04_vim_completion_options_for_nano() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tc051_04.completion");
        std::fs::write(&path, "").expect("write");

        let opts = vim_completion_options_for("nano", &path);
        assert!(opts.is_empty(), "nano must not produce completion options");
    }

    /// TC-051-04b: vim_completion_options_for returns empty Vec for "emacs".
    #[test]
    fn tc_051_04b_vim_completion_options_for_emacs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tc051_04b.completion");
        std::fs::write(&path, "").expect("write");

        let opts = vim_completion_options_for("emacs", &path);
        assert!(opts.is_empty(), "emacs must not produce completion options");
    }

    /// TC-051-05: secure_delete removes a completion file without trace.
    #[test]
    fn tc_051_05_secure_delete_removes_completion_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let titles = vec!["Entry A".to_string(), "Entry B".to_string()];
        let path = write_completion_file(dir.path(), &titles).expect("write_completion_file");

        assert!(path.exists(), "Completion file must exist before deletion");

        let result = secure_delete(&path);
        assert!(result.is_ok(), "secure_delete failed: {:?}", result.err());
        assert!(
            !path.exists(),
            "Completion file must not exist after secure_delete"
        );
    }

    /// write_completion_file produces a ".completion" extension file inside tmpdir.
    #[test]
    fn tc_051_file_extension_and_location() {
        let dir = tempfile::tempdir().expect("tempdir");
        let titles = vec!["A".to_string()];

        let path = write_completion_file(dir.path(), &titles).expect("write_completion_file");

        assert_eq!(
            path.extension().and_then(|e| e.to_str()),
            Some("completion"),
            "File must have .completion extension"
        );
        assert_eq!(
            path.parent().expect("parent"),
            dir.path(),
            "File must be inside the given tmpdir"
        );
    }

    /// vim_completion_options_for includes the completion file path in the script.
    #[test]
    fn tc_051_completion_script_contains_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("titles.completion");
        std::fs::write(&path, "").expect("write");

        let opts = vim_completion_options_for("vim", &path);
        assert_eq!(opts.len(), 2, "Must return exactly [\"-c\", \"<script>\"]");

        let script = &opts[1];
        let path_forward = path.to_str().unwrap().replace('\\', "/");
        assert!(
            script.contains(&path_forward),
            "vim script must reference the completion file path"
        );
    }
}
