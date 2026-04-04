//! Command handlers for pq-diary CLI.
//!
//! Each public function corresponds to a CLI subcommand and is wired up in
//! `main.rs`.  Handlers in this module may return `anyhow::Result` so that
//! arbitrary error sources can be propagated through the main entry-point.

use crate::editor::{self, EditorConfig};
use crate::password::get_password;
use crate::Cli;
use pq_diary_core::{DiaryCore, EntryPlaintext};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Resolve the path to `vault.pqd` from the CLI global flags.
///
/// - `--vault <path>.pqd` → used as-is.
/// - `--vault <dir>`      → `<dir>/vault.pqd`.
/// - No `--vault`         → `vault.pqd` in the current working directory.
fn resolve_vault_path(cli: &Cli) -> anyhow::Result<PathBuf> {
    let path = match &cli.vault {
        Some(v) => {
            let p = PathBuf::from(v);
            if p.extension().is_some_and(|e| e == "pqd") {
                p
            } else {
                p.join("vault.pqd")
            }
        }
        None => PathBuf::from("vault.pqd"),
    };
    Ok(path)
}

// ---------------------------------------------------------------------------
// Public command handlers
// ---------------------------------------------------------------------------

/// Execute the `pq-diary new` command.
///
/// Obtains the body text in the following priority order:
/// 1. `body` parameter (`-b` / `--body` flag) — editor is **not** launched.
/// 2. Piped stdin (non-terminal stdin) — all content read via `read_to_string`.
/// 3. `$EDITOR` — a header-comment temp file is written, the editor is
///    launched, the result is parsed, and the temp file is securely deleted.
///
/// When `title` is `None` or an empty string, `"Untitled"` is used.
///
/// Prints `Created: {prefix} "{title}"` on success.
///
/// # Errors
///
/// Returns an error if password acquisition, vault unlock, editor launch,
/// stdin read, or entry creation fails.
pub fn cmd_new(
    cli: &Cli,
    title: Option<String>,
    body: Option<String>,
    tags: Vec<String>,
) -> anyhow::Result<()> {
    use secrecy::{ExposeSecret as _, SecretBox};
    use std::io::{IsTerminal as _, Read as _};

    // Step 1: Obtain password and unlock the vault.
    let password_source =
        get_password(cli.password.as_deref()).map_err(|e| anyhow::anyhow!("{e}"))?;

    let vault_path = resolve_vault_path(cli)?;
    let vault_str = vault_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Vault path contains non-UTF-8 characters"))?;

    let mut core = DiaryCore::new(vault_str).map_err(|e| anyhow::anyhow!("{e}"))?;

    let secret_password: secrecy::SecretString =
        SecretBox::new(Box::from(password_source.secret().expose_secret()));
    core.unlock(secret_password)
        .map_err(|e| anyhow::anyhow!("Vault unlock failed: {e}"))?;

    // Step 2: Determine body text and potentially update title/tags.
    let (final_body, final_title, final_tags) = if let Some(b) = body {
        // -b / --body flag: highest priority; editor is NOT launched.
        (b, title, tags)
    } else if !std::io::stdin().is_terminal() {
        // Piped stdin: read all content.
        let mut content = String::new();
        std::io::stdin()
            .read_to_string(&mut content)
            .map_err(|e| anyhow::anyhow!("Failed to read stdin: {e}"))?;
        (content, title, tags)
    } else {
        // $EDITOR: write header-comment temp file, launch editor, read back.
        let config = EditorConfig::from_env().map_err(|e| anyhow::anyhow!("{e}"))?;

        let initial = EntryPlaintext {
            title: title.clone().unwrap_or_else(|| "Untitled".to_string()),
            tags: tags.clone(),
            body: String::new(),
        };

        let tmpfile = editor::write_header_file(&config.secure_tmpdir, &initial)
            .map_err(|e| anyhow::anyhow!("Failed to write temp file: {e}"))?;

        // Launch editor and read result; always delete the temp file afterward.
        let edit_result = editor::launch_editor(&tmpfile, &config);
        let read_result = editor::read_header_file(&tmpfile);
        let _del = editor::secure_delete(&tmpfile);

        edit_result.map_err(|e| anyhow::anyhow!("Editor failed: {e}"))?;
        let header = read_result.map_err(|e| anyhow::anyhow!("Failed to read temp file: {e}"))?;

        // Prefer header-parsed title/tags over CLI-supplied values.
        let new_title = header.title.or(title);
        let new_tags = header.tags.unwrap_or(tags);
        (header.body, new_title, new_tags)
    };

    // Step 3: Apply "Untitled" default for missing or empty title.
    let actual_title = final_title
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| "Untitled".to_string());

    // Step 4: Create the entry.
    let uuid_hex = core
        .new_entry(&actual_title, &final_body, final_tags)
        .map_err(|e| anyhow::anyhow!("Failed to create entry: {e}"))?;

    // Step 5: Print success message with an 8-character ID prefix.
    let prefix = &uuid_hex[..8];
    println!("Created: {prefix} \"{actual_title}\"");

    // Step 6: Lock the vault.
    core.lock();

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;

    // -------------------------------------------------------------------------
    // Test helpers
    // -------------------------------------------------------------------------

    fn fast_params() -> pq_diary_core::crypto::kdf::Argon2Params {
        pq_diary_core::crypto::kdf::Argon2Params {
            memory_cost_kb: 8,
            time_cost: 1,
            parallelism: 1,
        }
    }

    /// Initialise a test vault and return the vault **directory** path.
    ///
    /// The vault is created with the password `"password"`.
    fn setup_vault(dir: &tempfile::TempDir) -> PathBuf {
        use pq_diary_core::vault::init::VaultManager;
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());
        mgr.init_vault("v", b"password").expect("init_vault");
        dir.path().join("v")
    }

    /// Build a `Cli` that targets `vault_dir` with an optional password flag.
    fn make_cli(vault_dir_str: &str, password: Option<&str>) -> crate::Cli {
        let mut args: Vec<&str> = vec!["pq-diary", "-v", vault_dir_str];
        if let Some(pw) = password {
            args.extend_from_slice(&["--password", pw]);
        }
        args.push("new");
        crate::Cli::try_parse_from(&args).expect("parse test CLI")
    }

    /// Open the test vault and return all entry metadata.
    fn read_vault_entries(vault_dir: &std::path::Path) -> Vec<pq_diary_core::EntryMeta> {
        let vault_pqd = vault_dir.join("vault.pqd");
        let vault_str = vault_pqd.to_str().expect("utf8");
        let mut core = DiaryCore::new(vault_str).expect("DiaryCore::new");
        let pw: secrecy::SecretString = secrecy::SecretBox::new(Box::from("password"));
        core.unlock(pw).expect("unlock");
        let entries = core.list_entries(None).expect("list_entries");
        core.lock();
        entries
    }

    /// Open the test vault and return the plaintext of the first entry.
    fn read_first_entry_plaintext(
        vault_dir: &std::path::Path,
    ) -> pq_diary_core::EntryPlaintext {
        let vault_pqd = vault_dir.join("vault.pqd");
        let vault_str = vault_pqd.to_str().expect("utf8");
        let mut core = DiaryCore::new(vault_str).expect("DiaryCore::new");
        let pw: secrecy::SecretString = secrecy::SecretBox::new(Box::from("password"));
        core.unlock(pw).expect("unlock");
        let entries = core.list_entries(None).expect("list_entries");
        assert!(!entries.is_empty(), "vault must not be empty");
        let prefix = &entries[0].uuid_hex[..4];
        let (_, plaintext) = core.get_entry(prefix).expect("get_entry");
        core.lock();
        plaintext
    }

    // -------------------------------------------------------------------------
    // TC-0037-01: Title defaults to "Untitled" when not specified
    // -------------------------------------------------------------------------

    /// TC-0037-01: No title argument → entry is created with title "Untitled".
    #[test]
    fn tc_0037_01_title_defaults_to_untitled() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let cli = make_cli(vault_dir_str, Some("password"));
        let result = cmd_new(&cli, None, Some("body text".to_string()), vec![]);
        assert!(result.is_ok(), "cmd_new failed: {:?}", result.err());

        let entries = read_vault_entries(&vault_dir);
        assert_eq!(entries.len(), 1, "must have exactly 1 entry");
        assert_eq!(entries[0].title, "Untitled");
    }

    // -------------------------------------------------------------------------
    // TC-0037-02: Empty title string is replaced by "Untitled"
    // -------------------------------------------------------------------------

    /// TC-0037-02: Empty string title → replaced by "Untitled".
    #[test]
    fn tc_0037_02_empty_title_becomes_untitled() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let cli = make_cli(vault_dir_str, Some("password"));
        let result = cmd_new(&cli, Some(String::new()), Some("body".to_string()), vec![]);
        assert!(result.is_ok(), "cmd_new failed: {:?}", result.err());

        let entries = read_vault_entries(&vault_dir);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "Untitled");
    }

    // -------------------------------------------------------------------------
    // TC-0037-03: Specified title is used as-is
    // -------------------------------------------------------------------------

    /// TC-0037-03: A non-empty title is stored verbatim.
    #[test]
    fn tc_0037_03_specified_title_is_used() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let cli = make_cli(vault_dir_str, Some("password"));
        let result = cmd_new(
            &cli,
            Some("My Diary Entry".to_string()),
            Some("body text".to_string()),
            vec![],
        );
        assert!(result.is_ok(), "cmd_new failed: {:?}", result.err());

        let entries = read_vault_entries(&vault_dir);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "My Diary Entry");
    }

    // -------------------------------------------------------------------------
    // TC-0037-04: -b flag body is stored as the entry body
    // -------------------------------------------------------------------------

    /// TC-0037-04: Body supplied via the `body` parameter is stored verbatim.
    #[test]
    fn tc_0037_04_body_flag_is_stored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let cli = make_cli(vault_dir_str, Some("password"));
        let result = cmd_new(
            &cli,
            Some("Title".to_string()),
            Some("Hello World body text".to_string()),
            vec![],
        );
        assert!(result.is_ok(), "cmd_new failed: {:?}", result.err());

        let plaintext = read_first_entry_plaintext(&vault_dir);
        assert_eq!(plaintext.body, "Hello World body text");
    }

    // -------------------------------------------------------------------------
    // TC-0037-05: Multiple tags are stored correctly
    // -------------------------------------------------------------------------

    /// TC-0037-05: Multiple tags are stored in the entry.
    #[test]
    fn tc_0037_05_multiple_tags_are_stored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let cli = make_cli(vault_dir_str, Some("password"));
        let tags = vec![
            "tag1".to_string(),
            "tag2".to_string(),
            "work/project".to_string(),
        ];
        let result = cmd_new(&cli, None, Some("body".to_string()), tags.clone());
        assert!(result.is_ok(), "cmd_new failed: {:?}", result.err());

        let plaintext = read_first_entry_plaintext(&vault_dir);
        assert_eq!(plaintext.tags, tags);
    }

    // -------------------------------------------------------------------------
    // TC-0037-06: No tags → empty tag list
    // -------------------------------------------------------------------------

    /// TC-0037-06: When no tags are provided, an empty list is stored.
    #[test]
    fn tc_0037_06_no_tags_stores_empty_list() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let cli = make_cli(vault_dir_str, Some("password"));
        let result = cmd_new(&cli, None, Some("body".to_string()), vec![]);
        assert!(result.is_ok(), "cmd_new failed: {:?}", result.err());

        let plaintext = read_first_entry_plaintext(&vault_dir);
        assert!(plaintext.tags.is_empty(), "tags must be empty when none specified");
    }

    // -------------------------------------------------------------------------
    // TC-0037-07: Wrong password returns an error
    // -------------------------------------------------------------------------

    /// TC-0037-07: Incorrect vault password → cmd_new returns an error.
    #[test]
    fn tc_0037_07_wrong_password_returns_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let cli = make_cli(vault_dir_str, Some("wrong_password"));
        let result = cmd_new(&cli, None, Some("body".to_string()), vec![]);
        assert!(result.is_err(), "Expected error for wrong password");
    }

    // -------------------------------------------------------------------------
    // TC-0037-08: resolve_vault_path appends vault.pqd for directory paths
    // -------------------------------------------------------------------------

    /// TC-0037-08: A directory vault path gets `vault.pqd` appended.
    #[test]
    fn tc_0037_08_resolve_vault_path_appends_pqd() {
        let cli = crate::Cli::try_parse_from(["pq-diary", "-v", "/some/dir", "new"])
            .expect("parse");
        let path = resolve_vault_path(&cli).expect("resolve_vault_path");
        assert_eq!(path, PathBuf::from("/some/dir/vault.pqd"));
    }

    /// TC-0037-09: A `.pqd` vault path is used as-is.
    #[test]
    fn tc_0037_09_resolve_vault_path_pqd_passthrough() {
        let cli = crate::Cli::try_parse_from(["pq-diary", "-v", "/some/vault.pqd", "new"])
            .expect("parse");
        let path = resolve_vault_path(&cli).expect("resolve_vault_path");
        assert_eq!(path, PathBuf::from("/some/vault.pqd"));
    }

    /// TC-0037-10: No `--vault` flag → defaults to `vault.pqd` in CWD.
    #[test]
    fn tc_0037_10_resolve_vault_path_default() {
        let cli = crate::Cli::try_parse_from(["pq-diary", "new"]).expect("parse");
        let path = resolve_vault_path(&cli).expect("resolve_vault_path");
        assert_eq!(path, PathBuf::from("vault.pqd"));
    }
}
