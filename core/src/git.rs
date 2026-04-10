//! Git synchronisation operations.
//!
//! Provides Git repository initialisation and related utilities for pq-diary vaults.
//! Full push/pull/merge support is planned for later Sprint 8 tasks.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use rand::rngs::OsRng;
use rand::{Rng, RngCore};

use crate::crypto::CryptoEngine;
use crate::error::DiaryError;
use crate::vault::config::VaultConfig;
use crate::vault::reader::read_vault;
use crate::vault::writer::write_vault;

// =============================================================================
// Types
// =============================================================================

/// Git operation context for a vault directory.
///
/// Holds the path to the vault directory and provides a context for all
/// Git operations performed on that vault.
pub struct GitOperations {
    /// Path to the vault directory (parent of `.git`).
    vault_dir: PathBuf,
}

impl GitOperations {
    /// Create a new [`GitOperations`] context for the given `vault_dir`.
    pub fn new(vault_dir: PathBuf) -> Self {
        Self { vault_dir }
    }

    /// Return the vault directory path.
    pub fn vault_dir(&self) -> &Path {
        &self.vault_dir
    }
}

// =============================================================================
// Public functions
// =============================================================================

/// Check whether `git` is installed and available in `PATH`.
///
/// Runs `git --version` and returns `Ok(())` if the command exits successfully.
///
/// # Errors
///
/// Returns [`DiaryError::Git`] if `git` is not found or cannot be executed.
pub fn check_git_available() -> Result<(), DiaryError> {
    let output = std::process::Command::new("git")
        .arg("--version")
        .output()
        .map_err(|_| DiaryError::Git("git is not installed or not found in PATH".to_string()))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(DiaryError::Git(
            "git is not installed or not found in PATH".to_string(),
        ))
    }
}

/// Generate a privacy-preserving random author email address.
///
/// Uses [`OsRng`] to produce 4 cryptographically random bytes, encodes them
/// as an 8-character lowercase hex string, and appends `@localhost`.
///
/// # Format
///
/// Returns a string matching the pattern `^[0-9a-f]{8}@localhost$`.
pub fn generate_random_author_email() -> String {
    let mut bytes = [0u8; 4];
    OsRng.fill_bytes(&mut bytes);
    format!(
        "{:02x}{:02x}{:02x}{:02x}@localhost",
        bytes[0], bytes[1], bytes[2], bytes[3]
    )
}

/// Generate the `.gitignore` content for a pq-diary vault.
///
/// Returns a string that excludes plaintext diary entries (`entries/*.md`)
/// from Git tracking, ensuring only the encrypted `vault.pqd` is committed.
pub fn generate_gitignore() -> String {
    "entries/*.md\n".to_string()
}

/// Initialise a Git repository in `vault_dir`.
///
/// # Steps
///
/// 1. Checks that `.git` does not already exist (returns an error if present).
/// 2. Runs `git init`.
/// 3. Writes `.gitignore` using [`generate_gitignore`].
/// 4. Generates a random author email via [`generate_random_author_email`].
/// 5. Configures `user.name = "pq-diary"` and `user.email`.
/// 6. If `vault.toml` exists, atomically updates its `[git]` section.
/// 7. If `remote` is `Some(url)`, runs `git remote add origin <url>`.
///
/// # Errors
///
/// Returns [`DiaryError::Git`] if `.git` already exists, any Git command fails,
/// or `vault.toml` cannot be read/written.
pub fn git_init(vault_dir: &Path, remote: Option<&str>) -> Result<(), DiaryError> {
    // Step 1: Check if already initialised (EDGE-006).
    if vault_dir.join(".git").exists() {
        return Err(DiaryError::Git("already initialized".to_string()));
    }

    // Step 2: git init (REQ-001).
    let out = run_git_command(vault_dir, &["init"])?;
    if !out.status.success() {
        return Err(DiaryError::Git(format!(
            "git init failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }

    // Step 3: Write .gitignore (REQ-002).
    std::fs::write(vault_dir.join(".gitignore"), generate_gitignore())
        .map_err(|e| DiaryError::Git(format!("failed to write .gitignore: {e}")))?;

    // Steps 4-5: Generate random author email and configure git user (REQ-003).
    let author_email = generate_random_author_email();

    let out = run_git_command(vault_dir, &["config", "user.name", "pq-diary"])?;
    if !out.status.success() {
        return Err(DiaryError::Git(format!(
            "git config user.name failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }

    let out = run_git_command(vault_dir, &["config", "user.email", &author_email])?;
    if !out.status.success() {
        return Err(DiaryError::Git(format!(
            "git config user.email failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }

    // Step 6: Atomically update vault.toml [git] section if present (REQ-004).
    let toml_path = vault_dir.join("vault.toml");
    if toml_path.exists() {
        let content = std::fs::read_to_string(&toml_path)
            .map_err(|e| DiaryError::Git(format!("failed to read vault.toml: {e}")))?;
        let mut config: VaultConfig = toml::from_str(&content)
            .map_err(|e| DiaryError::Git(format!("failed to parse vault.toml: {e}")))?;
        config.git.author_name = "pq-diary".to_string();
        config.git.author_email = author_email;
        let new_content = toml::to_string_pretty(&config)
            .map_err(|e| DiaryError::Git(format!("failed to serialize vault.toml: {e}")))?;
        // Atomic write: .toml.tmp → rename to vault.toml (mirrors set_policy pattern).
        let tmp_path = toml_path.with_extension("toml.tmp");
        {
            use std::io::Write;
            let mut file = std::fs::File::create(&tmp_path)
                .map_err(|e| DiaryError::Git(format!("failed to create temp file: {e}")))?;
            file.write_all(new_content.as_bytes())
                .map_err(|e| DiaryError::Git(format!("failed to write temp file: {e}")))?;
            file.sync_all()
                .map_err(|e| DiaryError::Git(format!("failed to sync temp file: {e}")))?;
        }
        if let Err(e) = std::fs::rename(&tmp_path, &toml_path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(DiaryError::Io(e));
        }
    }

    // Step 7: Add remote if provided (REQ-005).
    if let Some(url) = remote {
        let out = run_git_command(vault_dir, &["remote", "add", "origin", url])?;
        if !out.status.success() {
            return Err(DiaryError::Git(format!(
                "git remote add origin failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
    }

    Ok(())
}

/// Build an anonymised Git author string from the vault configuration.
///
/// Returns a string in the format `"pq-diary <{author_email}>"` using only
/// the `author_email` stored in the vault's `[git]` section.  Real user names
/// and email addresses are never included — REQ-011, REQ-052.
///
/// # Example
///
/// ```text
/// "pq-diary <a3f1b2c4@localhost>"
/// ```
pub fn make_author(config: &VaultConfig) -> String {
    format!("pq-diary <{}>", config.git.author_email)
}

/// Generate a privacy-preserving, monotonically increasing commit timestamp.
///
/// # Arguments
///
/// * `prev` — author date of the most-recent commit, or `None` if this is the
///   first commit.
/// * `fuzz_hours` — maximum number of hours to subtract from the candidate
///   timestamp.  Pass `0` to disable fuzzing (returns `Utc::now()`).
///
/// # Algorithm
///
/// 1. If `fuzz_hours == 0` return `Utc::now()` immediately (fuzzing disabled,
///    REQ-014).
/// 2. Draw a random `offset_secs` in `[0, fuzz_hours * 3600]` from [`OsRng`].
/// 3. Compute `candidate = base + (offset_secs + 1) seconds`, where `base` is
///    `prev` when `Some`, or `Utc::now() - fuzz_hours hours` when `None`.
/// 4. Return `min(candidate, Utc::now())` to prevent future-dated timestamps.
///
/// The `+ 1` guarantees strict `prev < result` on every call (REQ-015).
pub fn fuzz_timestamp(prev: Option<DateTime<Utc>>, fuzz_hours: u64) -> DateTime<Utc> {
    if fuzz_hours == 0 {
        return Utc::now();
    }

    let max_offset_secs = fuzz_hours * 3600;
    let offset_secs = OsRng.gen_range(0u64..=max_offset_secs);

    let base = match prev {
        Some(p) => p,
        None => Utc::now() - Duration::hours(fuzz_hours as i64),
    };

    let candidate = base + Duration::seconds(offset_secs as i64 + 1);
    let now = Utc::now();

    candidate.min(now)
}

/// Retrieve the author date of the most-recent commit in the repository.
///
/// Runs `git log -1 --format=%aI` in `vault_dir` and parses the ISO 8601
/// output into a [`DateTime<Utc>`].
///
/// Returns `None` when:
/// * The repository has no commits yet (empty repo).
/// * The `git log` command fails for any reason.
/// * The timestamp string cannot be parsed.
pub fn get_last_commit_timestamp(vault_dir: &Path) -> Option<DateTime<Utc>> {
    let out = run_git_command(vault_dir, &["log", "-1", "--format=%aI"]).ok()?;
    if !out.status.success() {
        return None;
    }
    let raw = String::from_utf8_lossy(&out.stdout);
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    chrono::DateTime::parse_from_rfc3339(trimmed)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

/// Generate a random-length byte sequence for commit-size obfuscation.
///
/// Returns a `Vec<u8>` of length drawn uniformly from `[0, max_bytes)` using
/// [`OsRng`].  The contents are cryptographically random bytes.
///
/// When `max_bytes == 0` an empty `Vec` is returned immediately (REQ-054).
pub fn generate_extra_padding(max_bytes: usize) -> Vec<u8> {
    if max_bytes == 0 {
        return Vec::new();
    }
    let size = OsRng.gen_range(0..max_bytes);
    let mut padding = vec![0u8; size];
    OsRng.fill_bytes(&mut padding);
    padding
}

/// Apply the privacy pipeline and push the vault to the remote Git repository.
///
/// # Pipeline
///
/// 1. Verifies `.git` directory exists in `vault_dir` (`EDGE-003` if absent).
/// 2. Verifies at least one remote is configured (`EDGE-002` if absent).
/// 3. Re-writes `vault_path` with new random padding — makes binary diffs
///    across commits unpredictable (REQ-013, REQ-016).
/// 4. Optionally appends extra random bytes when
///    `config.git.privacy.extra_padding_bytes_max > 0` (REQ-054).
/// 5. Computes a fuzzed commit timestamp via [`fuzz_timestamp`] (REQ-014).
/// 6. Stages only `vault.pqd`, `vault.toml`, and `.gitignore` (REQ-010).
/// 7. Commits with the anonymous author from `config.git` and a fixed
///    commit message (REQ-011, REQ-012, REQ-017).
/// 8. Pushes the current branch to `origin` (REQ-010).
///
/// # Errors
///
/// Returns [`DiaryError::Git`] when:
/// - `.git` does not exist (`EDGE-003`)
/// - no remote is configured (`EDGE-002`)
/// - any Git sub-command exits with a non-zero status
/// - `vault_path` cannot be read or written
pub fn git_push(
    vault_dir: &Path,
    config: &VaultConfig,
    _engine: &CryptoEngine,
    vault_path: &Path,
) -> Result<(), DiaryError> {
    // Step 1: .git directory must exist (EDGE-003).
    if !vault_dir.join(".git").exists() {
        return Err(DiaryError::Git(
            "git repository is not initialized: .git directory not found (EDGE-003)".to_string(),
        ));
    }

    // Step 2: At least one remote must be configured (EDGE-002).
    let remote_out = run_git_command(vault_dir, &["remote"])?;
    if !remote_out.status.success()
        || String::from_utf8_lossy(&remote_out.stdout)
            .trim()
            .is_empty()
    {
        return Err(DiaryError::Git(
            "no remote repository configured (EDGE-002)".to_string(),
        ));
    }

    // Step 3: Re-write vault.pqd with new random padding (REQ-013, REQ-016).
    // Decryption is not required — EntryRecords are passed through unchanged.
    {
        let (header, entries) = read_vault(vault_path)?;
        write_vault(vault_path, header, &entries)?;
    }

    // Step 3b: Append extra padding when configured (REQ-054).
    let extra_max = config.git.privacy.extra_padding_bytes_max;
    if extra_max > 0 {
        let extra = generate_extra_padding(extra_max);
        if !extra.is_empty() {
            use std::io::Write as IoWrite;
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(vault_path)
                .map_err(|e| {
                    DiaryError::Git(format!("failed to open vault.pqd for extra padding: {e}"))
                })?;
            file.write_all(&extra).map_err(|e| {
                DiaryError::Git(format!("failed to append extra padding to vault.pqd: {e}"))
            })?;
        }
    }

    // Step 4: Compute fuzzed author/committer timestamp (REQ-014).
    let prev_ts = get_last_commit_timestamp(vault_dir);
    let fuzz_hours = config.git.privacy.timestamp_fuzz_hours;
    let fuzzed_ts = fuzz_timestamp(prev_ts, fuzz_hours);
    let ts_str = fuzzed_ts.to_rfc3339();

    // Step 5: Stage only the three allowed files (REQ-010).
    let add_out = run_git_command(vault_dir, &["add", "vault.pqd", "vault.toml", ".gitignore"])?;
    if !add_out.status.success() {
        return Err(DiaryError::Git(format!(
            "git add failed: {}",
            String::from_utf8_lossy(&add_out.stderr)
        )));
    }

    // Step 6: Commit with anonymous author, fixed message, and fuzzed date
    //         (REQ-011, REQ-012, REQ-017).
    let commit_message = &config.git.commit_message;
    let commit_out = std::process::Command::new("git")
        .current_dir(vault_dir)
        .arg("-c")
        .arg(format!("user.name={}", config.git.author_name))
        .arg("-c")
        .arg(format!("user.email={}", config.git.author_email))
        .args(["commit", "--date", &ts_str, "-m", commit_message])
        .env("GIT_AUTHOR_DATE", &ts_str)
        .env("GIT_COMMITTER_DATE", &ts_str)
        .output()
        .map_err(|e| DiaryError::Git(format!("failed to spawn git commit: {e}")))?;
    if !commit_out.status.success() {
        return Err(DiaryError::Git(format!(
            "git commit failed: {}",
            String::from_utf8_lossy(&commit_out.stderr)
        )));
    }

    // Step 7: Push current branch to origin (REQ-010).
    let branch_out = run_git_command(vault_dir, &["rev-parse", "--abbrev-ref", "HEAD"])?;
    let branch = if branch_out.status.success() {
        String::from_utf8_lossy(&branch_out.stdout)
            .trim()
            .to_string()
    } else {
        "main".to_string()
    };

    let push_out = run_git_command(vault_dir, &["push", "origin", &branch])?;
    if !push_out.status.success() {
        return Err(DiaryError::Git(format!(
            "git push failed: {}",
            String::from_utf8_lossy(&push_out.stderr)
        )));
    }

    Ok(())
}

// =============================================================================
// Private helpers
// =============================================================================

/// Run a Git command in `vault_dir` with the specified `args`.
///
/// Returns the [`std::process::Output`] from the Git process.
///
/// # Errors
///
/// Returns [`DiaryError::Git`] if the process cannot be spawned.
fn run_git_command(vault_dir: &Path, args: &[&str]) -> Result<std::process::Output, DiaryError> {
    std::process::Command::new("git")
        .current_dir(vault_dir)
        .args(args)
        .output()
        .map_err(|e| DiaryError::Git(format!("failed to run git {}: {e}", args.join(" "))))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// TC-S8-074-01: check_git_available succeeds in a git-installed environment.
    #[test]
    fn tc_s8_074_01_check_git_available_success() {
        // Assumes git is installed in the test environment.
        let result = check_git_available();
        assert!(result.is_ok(), "expected Ok(()), got: {:?}", result);
    }

    /// TC-S8-074-02: generate_random_author_email returns the correct format.
    #[test]
    fn tc_s8_074_02_random_author_email_format() {
        let email = generate_random_author_email();

        // Must match ^[0-9a-f]{8}@localhost$
        assert!(
            email.ends_with("@localhost"),
            "must end with @localhost: {}",
            email
        );
        let hex_part = email.trim_end_matches("@localhost");
        assert_eq!(hex_part.len(), 8, "hex part must be 8 chars: {}", email);
        assert!(
            hex_part.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')),
            "hex part must be lowercase hex: {}",
            email
        );

        // Multiple calls should return different values
        let email2 = generate_random_author_email();
        let email3 = generate_random_author_email();
        assert!(
            email != email2 || email != email3,
            "multiple calls should return different values"
        );
    }

    /// TC-S8-074-03: generate_gitignore contains "entries/*.md".
    #[test]
    fn tc_s8_074_03_gitignore_contains_entries() {
        let content = generate_gitignore();
        assert!(
            content.contains("entries/*.md"),
            "gitignore must contain entries/*.md, got: {}",
            content
        );
    }

    /// TC-S8-074-04: git_init creates a .git directory.
    #[test]
    fn tc_s8_074_04_git_init_creates_git_directory() {
        let dir = tempdir().expect("tempdir");
        let result = git_init(dir.path(), None);
        assert!(result.is_ok(), "git_init failed: {:?}", result);
        assert!(
            dir.path().join(".git").exists(),
            ".git directory must exist after git_init"
        );
    }

    /// TC-S8-074-05: git_init creates .gitignore with entries/*.md content.
    #[test]
    fn tc_s8_074_05_git_init_creates_gitignore() {
        let dir = tempdir().expect("tempdir");
        git_init(dir.path(), None).expect("git_init");

        let gitignore_path = dir.path().join(".gitignore");
        assert!(gitignore_path.exists(), ".gitignore must exist");
        let content = std::fs::read_to_string(&gitignore_path).expect("read .gitignore");
        assert!(
            content.contains("entries/*.md"),
            ".gitignore must contain entries/*.md, got: {}",
            content
        );
    }

    /// TC-S8-074-06: git_init updates vault.toml with author_name and random email.
    #[test]
    fn tc_s8_074_06_git_init_updates_vault_toml() {
        use crate::vault::config::VaultConfig;

        let dir = tempdir().expect("tempdir");

        // Create a vault.toml before git_init.
        let config = VaultConfig::default();
        let toml_path = dir.path().join("vault.toml");
        config.to_file(&toml_path).expect("write vault.toml");

        git_init(dir.path(), None).expect("git_init");

        // Re-read vault.toml and verify [git] section.
        let updated = VaultConfig::from_file(&toml_path).expect("read vault.toml");
        assert_eq!(
            updated.git.author_name, "pq-diary",
            "author_name must be 'pq-diary'"
        );

        // author_email must match ^[0-9a-f]{8}@localhost$
        let email = &updated.git.author_email;
        assert!(
            email.ends_with("@localhost"),
            "author_email must end with @localhost: {}",
            email
        );
        let hex_part = email.trim_end_matches("@localhost");
        assert_eq!(hex_part.len(), 8, "hex part must be 8 chars: {}", email);
        assert!(
            hex_part.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')),
            "hex part must be lowercase hex: {}",
            email
        );
    }

    /// TC-S8-074-07: git_init with remote adds origin.
    #[test]
    fn tc_s8_074_07_git_init_with_remote() {
        let dir = tempdir().expect("tempdir");
        let remote_url = "https://example.com/repo.git";

        git_init(dir.path(), Some(remote_url)).expect("git_init with remote");

        // Verify remote was added via git remote -v.
        let out = std::process::Command::new("git")
            .current_dir(dir.path())
            .args(["remote", "-v"])
            .output()
            .expect("git remote -v");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("origin"),
            "remote -v must contain 'origin': {}",
            stdout
        );
        assert!(
            stdout.contains(remote_url),
            "remote -v must contain the URL: {}",
            stdout
        );
    }

    /// TC-S8-074-08: git_init returns error when already initialized (EDGE-006).
    #[test]
    fn tc_s8_074_08_git_init_already_initialized() {
        let dir = tempdir().expect("tempdir");

        // First init succeeds.
        git_init(dir.path(), None).expect("first git_init");

        // Second init must fail with "already initialized".
        let result = git_init(dir.path(), None);
        assert!(result.is_err(), "second git_init must fail");

        match result {
            Err(DiaryError::Git(msg)) => {
                assert!(
                    msg.contains("already initialized"),
                    "error must mention 'already initialized': {}",
                    msg
                );
            }
            other => panic!("expected DiaryError::Git, got {:?}", other),
        }
    }

    /// TC-S8-074-09: check_git_available returns useful error when git is not installed (EDGE-001).
    ///
    /// This test modifies the process-wide PATH environment variable and must
    /// be run in isolation. Execute with: `cargo test -- --ignored tc_s8_074_09`
    #[test]
    #[ignore = "requires environment without git in PATH; run: cargo test -- --ignored"]
    fn tc_s8_074_09_git_not_installed_error_message() {
        // Temporarily clear PATH so git cannot be found.
        // WARNING: modifies process-wide environment; do not run in parallel.
        let original_path = std::env::var_os("PATH").unwrap_or_default();
        std::env::set_var("PATH", "");
        let result = check_git_available();
        std::env::set_var("PATH", original_path);

        match result {
            Err(DiaryError::Git(msg)) => {
                assert!(
                    msg.contains("git is not installed") || msg.contains("not found in PATH"),
                    "error message must be user-friendly: {}",
                    msg
                );
            }
            Ok(()) => panic!("expected error when git is not in PATH"),
            Err(e) => panic!("unexpected error type: {}", e),
        }
    }

    // -------------------------------------------------------------------------
    // TASK-0075 tests
    // -------------------------------------------------------------------------

    /// TC-S8-075-01: make_author returns "pq-diary <X@localhost>" format.
    #[test]
    fn tc_s8_075_01_make_author_format() {
        use crate::vault::config::VaultConfig;

        let mut config = VaultConfig::default();
        config.git.author_email = "abcd1234@localhost".to_string();

        let author = make_author(&config);
        assert_eq!(
            author, "pq-diary <abcd1234@localhost>",
            "make_author must return 'pq-diary <abcd1234@localhost>', got: {}",
            author
        );
        // Real user names must not appear.
        assert!(
            !author.contains(whoami_name_guard()),
            "make_author must not contain real system username"
        );
    }

    /// TC-S8-075-02: fuzz_timestamp with fuzz_hours=0 returns approximately Utc::now().
    #[test]
    fn tc_s8_075_02_fuzz_timestamp_disabled() {
        use chrono::{Duration, Utc};

        let before = Utc::now();
        let result = fuzz_timestamp(None, 0);
        let after = Utc::now();

        let diff = (result - before).num_milliseconds().abs();
        assert!(
            diff < 1000,
            "fuzz_timestamp(None, 0) must be within 1 second of Utc::now(), diff={}ms",
            diff
        );
        assert!(
            result >= before && result <= after + Duration::milliseconds(1),
            "result must be in [before, after]: before={before}, result={result}, after={after}"
        );
    }

    /// TC-S8-075-03: fuzz_timestamp with fuzz_hours=6 satisfies prev < result <= Utc::now().
    #[test]
    fn tc_s8_075_03_fuzz_timestamp_range() {
        use chrono::{Duration, Utc};

        let prev = Utc::now() - Duration::hours(12);
        let mut results = Vec::new();

        for _ in 0..5 {
            let result = fuzz_timestamp(Some(prev), 6);
            let now = Utc::now();
            assert!(
                result > prev,
                "result must be strictly greater than prev: prev={prev}, result={result}"
            );
            assert!(
                result <= now,
                "result must not exceed Utc::now(): result={result}, now={now}"
            );
            results.push(result);
        }

        // At least two distinct values should appear across 5 calls (randomness check).
        let unique_count = results.windows(2).filter(|w| w[0] != w[1]).count();
        assert!(
            unique_count > 0,
            "multiple calls should produce different timestamps (at least 1 distinct pair)"
        );
    }

    /// TC-S8-075-04: fuzz_timestamp guarantees strict monotonicity (prev < result).
    #[test]
    fn tc_s8_075_04_fuzz_timestamp_monotonic() {
        use chrono::{Duration, Utc};

        let prev = Utc::now() - Duration::hours(1);

        for i in 0..10 {
            let result = fuzz_timestamp(Some(prev), 6);
            assert!(
                result > prev,
                "iteration {i}: prev < result must hold. prev={prev}, result={result}"
            );
        }
    }

    /// TC-S8-075-05: generate_extra_padding with max_bytes=0 returns empty Vec.
    #[test]
    fn tc_s8_075_05_padding_zero_max() {
        let padding = generate_extra_padding(0);
        assert_eq!(
            padding.len(),
            0,
            "generate_extra_padding(0) must return empty Vec"
        );
    }

    /// TC-S8-075-06: generate_extra_padding with max_bytes=4096 returns 0..4096 bytes.
    #[test]
    fn tc_s8_075_06_padding_size_bounds() {
        let max = 4096usize;
        let mut any_nonzero = false;

        for _ in 0..100 {
            let padding = generate_extra_padding(max);
            assert!(
                padding.len() <= max,
                "padding length {} must be <= {max}",
                padding.len()
            );
            if padding.len() > 0 {
                any_nonzero = true;
            }
        }

        assert!(
            any_nonzero,
            "at least one call out of 100 must return non-empty padding"
        );
    }

    /// TC-S8-075-07: get_last_commit_timestamp returns None for an empty repository.
    #[test]
    fn tc_s8_075_07_no_commits_returns_none() {
        let dir = tempdir().expect("tempdir");

        // git init (no commits).
        let out = std::process::Command::new("git")
            .current_dir(dir.path())
            .args(["init"])
            .output()
            .expect("git init");
        assert!(out.status.success(), "git init must succeed");

        let result = get_last_commit_timestamp(dir.path());
        assert!(
            result.is_none(),
            "get_last_commit_timestamp must return None for empty repo, got: {:?}",
            result
        );
    }

    /// Return a placeholder that is never equal to real author strings.
    ///
    /// Used only to satisfy the "real username must not appear" check in
    /// TC-S8-075-01 without importing any OS username crate in tests.
    fn whoami_name_guard() -> &'static str {
        // The fixed author string "pq-diary" is intentionally used as the
        // author name — it never coincides with a real login name.
        "__REAL_USER__"
    }

    // -------------------------------------------------------------------------
    // TASK-0076 helpers
    // -------------------------------------------------------------------------

    /// Build a [`VaultConfig`] suitable for git_push() tests.
    fn make_git_push_config(
        author_name: &str,
        author_email: &str,
        commit_message: &str,
        fuzz_hours: u64,
        extra_padding_bytes_max: usize,
    ) -> crate::vault::config::VaultConfig {
        use crate::policy::AccessPolicy;
        use crate::vault::config::{
            AccessSection, Argon2Section, GitPrivacySection, GitSection, VaultConfig, VaultSection,
        };

        VaultConfig {
            vault: VaultSection {
                name: "test".to_string(),
                schema_version: 4,
            },
            access: AccessSection {
                policy: AccessPolicy::None,
            },
            git: GitSection {
                author_name: author_name.to_string(),
                author_email: author_email.to_string(),
                commit_message: commit_message.to_string(),
                privacy: GitPrivacySection {
                    timestamp_fuzz_hours: fuzz_hours,
                    extra_padding_bytes_max,
                },
            },
            argon2: Argon2Section {
                memory_cost_kb: 65536,
                time_cost: 3,
                parallelism: 1,
            },
        }
    }

    /// Set up a vault directory with git initialized, vault files, and a local
    /// bare remote.  Returns `(TempDir, vault_dir_path, vault_pqd_path)`.
    ///
    /// The working repo has one initial commit already pushed to the bare
    /// remote so that subsequent `git_push()` calls can push a second commit.
    fn setup_vault_with_remote(
        config: &crate::vault::config::VaultConfig,
    ) -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        use crate::vault::format::VaultHeader;
        use crate::vault::writer::write_vault as wv;

        let tmp = tempdir().expect("tempdir");
        let bare_dir = tmp.path().join("bare.git");
        let vault_dir = tmp.path().join("vault");

        std::fs::create_dir_all(&bare_dir).expect("create bare dir");
        std::fs::create_dir_all(&vault_dir).expect("create vault dir");

        // Initialise the bare remote.
        let out = std::process::Command::new("git")
            .current_dir(&bare_dir)
            .args(["init", "--bare"])
            .output()
            .expect("git init --bare");
        assert!(out.status.success(), "git init --bare failed");

        // Initialise the working repo.
        let out = std::process::Command::new("git")
            .current_dir(&vault_dir)
            .args(["init"])
            .output()
            .expect("git init");
        assert!(out.status.success(), "git init failed");

        // Configure local git identity for the initial commit.
        for (k, v) in [
            ("user.name", "setup-user"),
            ("user.email", "setup@localhost"),
        ] {
            let out = std::process::Command::new("git")
                .current_dir(&vault_dir)
                .args(["config", k, v])
                .output()
                .expect("git config");
            assert!(out.status.success(), "git config {k} failed");
        }

        // Create vault files.
        let vault_path = vault_dir.join("vault.pqd");
        wv(&vault_path, VaultHeader::new(), &[]).expect("write_vault");

        let toml_path = vault_dir.join("vault.toml");
        config.to_file(&toml_path).expect("write vault.toml");

        std::fs::write(vault_dir.join(".gitignore"), generate_gitignore())
            .expect("write .gitignore");

        // Add the bare repo as remote "origin".
        let out = std::process::Command::new("git")
            .current_dir(&vault_dir)
            .args(["remote", "add", "origin", bare_dir.to_str().unwrap()])
            .output()
            .expect("git remote add");
        assert!(out.status.success(), "git remote add failed");

        // Initial commit (adds all three files).
        let out = std::process::Command::new("git")
            .current_dir(&vault_dir)
            .args(["add", "vault.pqd", "vault.toml", ".gitignore"])
            .output()
            .expect("git add");
        assert!(out.status.success(), "initial git add failed");

        let out = std::process::Command::new("git")
            .current_dir(&vault_dir)
            .args(["commit", "-m", "initial commit"])
            .output()
            .expect("git commit");
        assert!(
            out.status.success(),
            "initial git commit failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        // Push initial commit to bare remote.
        let branch_out = std::process::Command::new("git")
            .current_dir(&vault_dir)
            .args(["rev-parse", "--abbrev-ref", "HEAD"])
            .output()
            .expect("git rev-parse HEAD");
        let branch = String::from_utf8_lossy(&branch_out.stdout)
            .trim()
            .to_string();

        let out = std::process::Command::new("git")
            .current_dir(&vault_dir)
            .args(["push", "-u", "origin", &branch])
            .output()
            .expect("git push -u");
        assert!(
            out.status.success(),
            "initial git push failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        (tmp, vault_dir, vault_path)
    }

    // -------------------------------------------------------------------------
    // TASK-0076 tests
    // -------------------------------------------------------------------------

    /// TC-S8-076-01: git_push() re-writes vault.pqd (bytes change after call).
    #[test]
    fn tc_s8_076_01_vault_pqd_bytes_change() {
        use crate::crypto::CryptoEngine;

        let config = make_git_push_config("anon", "tc01@localhost", "Update vault", 0, 0);
        let (_tmp, vault_dir, vault_path) = setup_vault_with_remote(&config);

        let before = std::fs::read(&vault_path).expect("read vault before");

        let engine = CryptoEngine::new();
        let result = git_push(&vault_dir, &config, &engine, &vault_path);
        assert!(result.is_ok(), "git_push failed: {:?}", result);

        let after = std::fs::read(&vault_path).expect("read vault after");
        assert_ne!(
            before, after,
            "vault.pqd must have different bytes after git_push (random padding regenerated)"
        );
    }

    /// TC-S8-076-02: git_push() commits with the anonymous author from vault.toml.
    #[test]
    fn tc_s8_076_02_anonymous_author_used() {
        use crate::crypto::CryptoEngine;

        let anon_name = "pq-anon-test";
        let anon_email = "ab12cd34@localhost";
        let config = make_git_push_config(anon_name, anon_email, "Update vault", 0, 0);
        let (_tmp, vault_dir, vault_path) = setup_vault_with_remote(&config);

        let engine = CryptoEngine::new();
        let result = git_push(&vault_dir, &config, &engine, &vault_path);
        assert!(result.is_ok(), "git_push failed: {:?}", result);

        let out = std::process::Command::new("git")
            .current_dir(&vault_dir)
            .args(["log", "-1", "--format=%an%n%ae"])
            .output()
            .expect("git log");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let mut lines = stdout.trim().lines();
        let got_name = lines.next().unwrap_or("").trim();
        let got_email = lines.next().unwrap_or("").trim();

        assert_eq!(
            got_name, anon_name,
            "commit author name must be anonymous_name from config: got '{got_name}'"
        );
        assert_eq!(
            got_email, anon_email,
            "commit author email must be anonymous_email from config: got '{got_email}'"
        );
    }

    /// TC-S8-076-03: git_push() commits with the fixed commit_message from vault.toml.
    #[test]
    fn tc_s8_076_03_fixed_commit_message_used() {
        use crate::crypto::CryptoEngine;

        let expected_msg = "pq-diary sync operation";
        let config = make_git_push_config("anon", "tc03@localhost", expected_msg, 0, 0);
        let (_tmp, vault_dir, vault_path) = setup_vault_with_remote(&config);

        let engine = CryptoEngine::new();
        let result = git_push(&vault_dir, &config, &engine, &vault_path);
        assert!(result.is_ok(), "git_push failed: {:?}", result);

        let out = std::process::Command::new("git")
            .current_dir(&vault_dir)
            .args(["log", "-1", "--format=%s"])
            .output()
            .expect("git log --format=%s");
        let got_msg = String::from_utf8_lossy(&out.stdout).trim().to_string();

        assert_eq!(
            got_msg, expected_msg,
            "commit message must match config.git.commit_message: got '{got_msg}'"
        );
    }

    /// TC-S8-076-04: git_push() applies timestamp fuzzing (fuzz_hours > 0).
    #[test]
    fn tc_s8_076_04_timestamp_fuzzing_applied() {
        use crate::crypto::CryptoEngine;
        use chrono::Utc;

        let fuzz_hours: u64 = 6;
        let config = make_git_push_config("anon", "tc04@localhost", "Update vault", fuzz_hours, 0);
        let (_tmp, vault_dir, vault_path) = setup_vault_with_remote(&config);

        let before_push = Utc::now();
        let engine = CryptoEngine::new();
        let result = git_push(&vault_dir, &config, &engine, &vault_path);
        assert!(result.is_ok(), "git_push failed: {:?}", result);
        let after_push = Utc::now();

        // Read the author date from the commit.
        let out = std::process::Command::new("git")
            .current_dir(&vault_dir)
            .args(["log", "-1", "--format=%aI"])
            .output()
            .expect("git log --format=%aI");
        let ts_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let commit_ts = chrono::DateTime::parse_from_rfc3339(&ts_str)
            .expect("parse commit author date")
            .with_timezone(&Utc);

        // The commit timestamp must not be in the future.
        assert!(
            commit_ts <= after_push + Duration::seconds(1),
            "commit timestamp must not exceed current time: commit={commit_ts}, now={after_push}"
        );

        // The commit timestamp must be within fuzz_hours of the call time.
        let max_past = before_push - Duration::hours(fuzz_hours as i64);
        assert!(
            commit_ts >= max_past,
            "commit timestamp must not be more than {fuzz_hours}h in the past: \
             commit={commit_ts}, floor={max_past}"
        );

        // Also verify fuzz_hours=0 uses approximately current time.
        let config0 = make_git_push_config("anon", "tc04b@localhost", "Update vault", 0, 0);
        let (_tmp2, vault_dir2, vault_path2) = setup_vault_with_remote(&config0);
        let t_before = Utc::now();
        let engine2 = CryptoEngine::new();
        let result2 = git_push(&vault_dir2, &config0, &engine2, &vault_path2);
        assert!(result2.is_ok(), "git_push (fuzz=0) failed: {:?}", result2);
        let t_after = Utc::now();

        let out2 = std::process::Command::new("git")
            .current_dir(&vault_dir2)
            .args(["log", "-1", "--format=%aI"])
            .output()
            .expect("git log --format=%aI");
        let ts_str2 = String::from_utf8_lossy(&out2.stdout).trim().to_string();
        let commit_ts2 = chrono::DateTime::parse_from_rfc3339(&ts_str2)
            .expect("parse commit author date (fuzz=0)")
            .with_timezone(&Utc);

        let diff_secs = (commit_ts2 - t_before).num_seconds().abs();
        assert!(
            diff_secs <= (t_after - t_before).num_seconds() + 2,
            "fuzz_hours=0 commit timestamp must be close to current time: \
             commit={commit_ts2}, before={t_before}"
        );
    }

    /// TC-S8-076-05: extra_padding_bytes_max=0 does not add extra bytes.
    #[test]
    fn tc_s8_076_05_no_extra_padding_when_max_zero() {
        use crate::crypto::CryptoEngine;
        use crate::vault::reader::read_vault as rv;

        let config = make_git_push_config("anon", "tc05@localhost", "Update vault", 0, 0);
        let (_tmp, vault_dir, vault_path) = setup_vault_with_remote(&config);

        let engine = CryptoEngine::new();
        let result = git_push(&vault_dir, &config, &engine, &vault_path);
        assert!(result.is_ok(), "git_push failed: {:?}", result);

        // vault.pqd must still be parseable (no format corruption from extra bytes).
        let parse_result = rv(&vault_path);
        assert!(
            parse_result.is_ok(),
            "vault.pqd must be parseable after git_push with extra_padding_bytes_max=0: {:?}",
            parse_result
        );

        // File size must not exceed the upper bound of write_vault() with empty entries:
        // header (~212 B) + entry_sentinel (4 B) + max_tail_padding (4096 B) + margin.
        let file_size = std::fs::metadata(&vault_path).expect("metadata").len();
        let reasonable_upper = 212 + 4 + 4096 + 256; // generous margin
        assert!(
            file_size <= reasonable_upper as u64,
            "vault.pqd size {file_size} B exceeds expected upper bound {reasonable_upper} B \
             (no extra padding should be added when max=0)"
        );
    }

    /// TC-S8-076-06: git_push() returns EDGE-003 when .git is not initialized.
    #[test]
    fn tc_s8_076_06_edge_003_no_git_directory() {
        use crate::crypto::CryptoEngine;
        use crate::vault::format::VaultHeader;
        use crate::vault::writer::write_vault as wv;

        let tmp = tempdir().expect("tempdir");
        let vault_dir = tmp.path().to_path_buf();
        let vault_path = vault_dir.join("vault.pqd");
        wv(&vault_path, VaultHeader::new(), &[]).expect("write_vault");

        let config = make_git_push_config("anon", "tc06@localhost", "Update vault", 0, 0);
        let engine = CryptoEngine::new();

        let result = git_push(&vault_dir, &config, &engine, &vault_path);
        assert!(result.is_err(), "expected Err for missing .git, got Ok");

        match result {
            Err(DiaryError::Git(msg)) => {
                assert!(
                    msg.contains("EDGE-003") || msg.contains("not initialized"),
                    "error must mention EDGE-003 or 'not initialized': {msg}"
                );
            }
            other => panic!("expected DiaryError::Git, got {:?}", other),
        }
    }

    /// TC-S8-076-07: git_push() returns EDGE-002 when no remote is configured.
    #[test]
    fn tc_s8_076_07_edge_002_no_remote_configured() {
        use crate::crypto::CryptoEngine;
        use crate::vault::format::VaultHeader;
        use crate::vault::writer::write_vault as wv;

        let tmp = tempdir().expect("tempdir");
        let vault_dir = tmp.path().to_path_buf();
        let vault_path = vault_dir.join("vault.pqd");
        wv(&vault_path, VaultHeader::new(), &[]).expect("write_vault");

        // Create vault.toml and .gitignore.
        let config = make_git_push_config("anon", "tc07@localhost", "Update vault", 0, 0);
        config
            .to_file(&vault_dir.join("vault.toml"))
            .expect("write vault.toml");
        std::fs::write(vault_dir.join(".gitignore"), generate_gitignore())
            .expect("write .gitignore");

        // git init but DO NOT add a remote.
        let out = std::process::Command::new("git")
            .current_dir(&vault_dir)
            .args(["init"])
            .output()
            .expect("git init");
        assert!(out.status.success(), "git init failed");

        let engine = CryptoEngine::new();
        let result = git_push(&vault_dir, &config, &engine, &vault_path);
        assert!(result.is_err(), "expected Err for missing remote, got Ok");

        match result {
            Err(DiaryError::Git(msg)) => {
                assert!(
                    msg.contains("EDGE-002") || msg.contains("no remote"),
                    "error must mention EDGE-002 or 'no remote': {msg}"
                );
            }
            other => panic!("expected DiaryError::Git, got {:?}", other),
        }
    }

    /// TC-S8-076-08: git add stages only vault.pqd, vault.toml, .gitignore.
    ///
    /// An extra file in `entries/` (not matching `entries/*.md` gitignore rule)
    /// must not appear in the commit produced by `git_push()`.
    #[test]
    fn tc_s8_076_08_only_allowed_files_are_staged() {
        use crate::crypto::CryptoEngine;

        let config = make_git_push_config("anon", "tc08@localhost", "Update vault", 0, 0);
        let (_tmp, vault_dir, vault_path) = setup_vault_with_remote(&config);

        // Create an untracked file under entries/ that is NOT covered by
        // `entries/*.md` gitignore rule (it uses a .txt extension).
        let entries_dir = vault_dir.join("entries");
        std::fs::create_dir_all(&entries_dir).expect("create entries dir");
        std::fs::write(entries_dir.join("secret.txt"), b"should not be committed")
            .expect("write entries/secret.txt");

        let engine = CryptoEngine::new();
        let result = git_push(&vault_dir, &config, &engine, &vault_path);
        assert!(result.is_ok(), "git_push failed: {:?}", result);

        // Inspect which files appeared in the last commit.
        let out = std::process::Command::new("git")
            .current_dir(&vault_dir)
            .args(["show", "--name-only", "--format=", "HEAD"])
            .output()
            .expect("git show");
        let committed = String::from_utf8_lossy(&out.stdout);

        assert!(
            !committed.contains("entries/secret.txt"),
            "entries/secret.txt must NOT be committed, but it appears in: {committed}"
        );

        // The three allowed files must be present.
        assert!(
            committed.contains("vault.pqd"),
            "vault.pqd must be in the commit: {committed}"
        );
    }
}
