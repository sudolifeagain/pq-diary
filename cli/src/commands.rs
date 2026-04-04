//! Command handlers for pq-diary CLI.
//!
//! Each public function corresponds to a CLI subcommand and is wired up in
//! `main.rs`.  Handlers in this module may return `anyhow::Result` so that
//! arbitrary error sources can be propagated through the main entry-point.

use crate::editor::{self, EditorConfig};
use crate::password::get_password;
use crate::Cli;
use chrono::{DateTime, Utc};
use pq_diary_core::{DiaryCore, EntryMeta, EntryPlaintext, Tag};
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
// Private helpers
// ---------------------------------------------------------------------------

/// Format a Unix timestamp (seconds) as `YYYY-MM-DD` in UTC.
fn format_timestamp(ts: u64) -> String {
    DateTime::<Utc>::from_timestamp(ts as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "????-??-??".to_string())
}

/// Apply tag filter, keyword filter, sort by `updated_at` descending, and limit.
///
/// - `tag`: if `Some`, keeps only entries where at least one tag is matched by
///   [`Tag::is_prefix_of`] (nested-tag prefix match).
/// - `query`: if `Some`, keeps only entries whose title contains `query` as a
///   case-insensitive substring.
/// - `number`: truncates the result to at most this many entries.
///
/// # Errors
///
/// Returns an error if `tag` is not a valid [`Tag`] string.
fn filter_and_sort(
    mut entries: Vec<EntryMeta>,
    tag: Option<&str>,
    query: Option<&str>,
    number: usize,
) -> anyhow::Result<Vec<EntryMeta>> {
    // Tag filter (prefix match for nested tags)
    if let Some(tag_str) = tag {
        let filter_tag = Tag::new(tag_str).map_err(|e| anyhow::anyhow!("{e}"))?;
        entries.retain(|e| {
            e.tags.iter().any(|t| {
                Tag::new(t)
                    .map(|entry_tag| filter_tag.is_prefix_of(&entry_tag))
                    .unwrap_or(false)
            })
        });
    }

    // Query filter (case-insensitive title partial match)
    if let Some(q) = query {
        let q_lower = q.to_lowercase();
        entries.retain(|e| e.title.to_lowercase().contains(&q_lower));
    }

    // Sort by updated_at descending (newest first)
    entries.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));

    // Limit to requested number
    entries.truncate(number);

    Ok(entries)
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

/// Execute the `pq-diary list` command.
///
/// Lists diary entries sorted by `updated_at` descending (newest first),
/// with optional tag filter (nested-tag prefix match), title keyword filter
/// (case-insensitive), and a maximum display count (default 20).
///
/// Output format per line: `{id_prefix}  {date}  {title}  #{tag1}  #{tag2}`
///
/// # Errors
///
/// Returns an error if password acquisition, vault unlock, or entry listing fails.
pub fn cmd_list(
    cli: &Cli,
    tag: Option<String>,
    query: Option<String>,
    number: usize,
) -> anyhow::Result<()> {
    use secrecy::{ExposeSecret as _, SecretBox};

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

    let entries = core
        .list_entries(None)
        .map_err(|e| anyhow::anyhow!("Failed to list entries: {e}"))?;

    let filtered = filter_and_sort(entries, tag.as_deref(), query.as_deref(), number)?;

    for meta in &filtered {
        let prefix = meta.id_prefix(8);
        let date = format_timestamp(meta.updated_at);
        if meta.tags.is_empty() {
            println!("{prefix}  {date}  {}", meta.title);
        } else {
            let tags_str = meta
                .tags
                .iter()
                .map(|t| format!("#{t}"))
                .collect::<Vec<_>>()
                .join("  ");
            println!("{prefix}  {date}  {}  {tags_str}", meta.title);
        }
    }

    core.lock();
    Ok(())
}

/// Execute the `pq-diary show` command.
///
/// Displays the full content of the entry identified by `id` (an ID prefix of
/// at least 4 hex characters).  Output includes title, created/updated dates,
/// tag list, a blank line, and the full body text.
///
/// # Errors
///
/// Returns an error if password acquisition, vault unlock, or entry lookup fails.
/// Returns an error with a descriptive message when no entry matches or multiple
/// entries match the given prefix.
pub fn cmd_show(cli: &Cli, id: String) -> anyhow::Result<()> {
    use secrecy::{ExposeSecret as _, SecretBox};

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

    let result = core.get_entry(&id);

    match result {
        Err(e) => {
            core.lock();
            Err(anyhow::anyhow!("{e}"))
        }
        Ok((record, plaintext)) => {
            let created = format_timestamp(record.created_at);
            let updated = format_timestamp(record.updated_at);

            println!("Title:   {}", plaintext.title);
            println!("Created: {created}  Updated: {updated}");
            if plaintext.tags.is_empty() {
                println!("Tags:    (none)");
            } else {
                let tags_str = plaintext
                    .tags
                    .iter()
                    .map(|t| format!("#{t}"))
                    .collect::<Vec<_>>()
                    .join("  ");
                println!("Tags:    {tags_str}");
            }
            println!();
            print!("{}", plaintext.body);

            core.lock();
            Ok(())
        }
    }
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

    // =========================================================================
    // filter_and_sort unit tests (TASK-0038)
    // =========================================================================

    /// Build a minimal `EntryMeta` for unit testing filter/sort logic.
    fn make_meta(uuid_hex: &str, title: &str, tags: &[&str], updated_at: u64) -> EntryMeta {
        EntryMeta {
            uuid_hex: uuid_hex.to_string(),
            title: title.to_string(),
            tags: tags.iter().map(|s| s.to_string()).collect(),
            created_at: 0,
            updated_at,
        }
    }

    /// TC-0038-U01: Tag exact match filter keeps only matching entries.
    #[test]
    fn tc_0038_u01_tag_filter_exact_match() {
        let entries = vec![
            make_meta("aa000000", "A", &["日記"], 1),
            make_meta("bb000000", "B", &["仕事"], 2),
        ];
        let result = filter_and_sort(entries, Some("日記"), None, 20).expect("filter");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].title, "A");
    }

    /// TC-0038-U02: Tag prefix match includes nested tags (e.g. "日記" matches "日記/旅行").
    #[test]
    fn tc_0038_u02_tag_prefix_matches_nested() {
        let entries = vec![
            make_meta("aa000000", "A", &["日記"], 1),
            make_meta("bb000000", "B", &["日記/旅行"], 2),
            make_meta("cc000000", "C", &["仕事"], 3),
        ];
        let result = filter_and_sort(entries, Some("日記"), None, 20).expect("filter");
        assert_eq!(result.len(), 2);
        let titles: Vec<&str> = result.iter().map(|e| e.title.as_str()).collect();
        assert!(titles.contains(&"A"));
        assert!(titles.contains(&"B"));
    }

    /// TC-0038-U03: Non-existent tag returns an empty list.
    #[test]
    fn tc_0038_u03_nonexistent_tag_returns_empty() {
        let entries = vec![
            make_meta("aa000000", "A", &["日記"], 1),
            make_meta("bb000000", "B", &["仕事"], 2),
        ];
        let result = filter_and_sort(entries, Some("趣味"), None, 20).expect("filter");
        assert!(result.is_empty());
    }

    /// TC-0038-U04: "仕事人" is NOT matched by tag filter "仕事" (requires `/` separator).
    #[test]
    fn tc_0038_u04_tag_filter_no_false_prefix() {
        let entries = vec![
            make_meta("aa000000", "A", &["仕事人"], 1),
        ];
        let result = filter_and_sort(entries, Some("仕事"), None, 20).expect("filter");
        assert!(result.is_empty(), "仕事人 must not match 仕事 filter");
    }

    /// TC-0038-U05: Query filter matches title case-insensitively.
    #[test]
    fn tc_0038_u05_query_case_insensitive() {
        let entries = vec![
            make_meta("aa000000", "Hello World", &[], 1),
            make_meta("bb000000", "hello world", &[], 2),
            make_meta("cc000000", "Other", &[], 3),
        ];
        let result = filter_and_sort(entries, None, Some("hello"), 20).expect("filter");
        assert_eq!(result.len(), 2);
    }

    /// TC-0038-U06: Query filter partial match on Japanese title.
    #[test]
    fn tc_0038_u06_query_partial_match_japanese() {
        let entries = vec![
            make_meta("aa000000", "テストエントリ", &[], 1),
            make_meta("bb000000", "別のエントリ", &[], 2),
        ];
        let result = filter_and_sort(entries, None, Some("テスト"), 20).expect("filter");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].title, "テストエントリ");
    }

    /// TC-0038-U07: Entries are returned sorted by updated_at descending.
    #[test]
    fn tc_0038_u07_sort_updated_at_desc() {
        let entries = vec![
            make_meta("aa000000", "Old", &[], 100),
            make_meta("bb000000", "Newest", &[], 300),
            make_meta("cc000000", "Middle", &[], 200),
        ];
        let result = filter_and_sort(entries, None, None, 20).expect("filter");
        assert_eq!(result[0].title, "Newest");
        assert_eq!(result[1].title, "Middle");
        assert_eq!(result[2].title, "Old");
    }

    /// TC-0038-U08: Default number=20 limits output to 20 entries.
    #[test]
    fn tc_0038_u08_default_number_limit_20() {
        let entries: Vec<EntryMeta> = (0u64..30)
            .map(|i| make_meta(&format!("{:032x}", i), "Entry", &[], i))
            .collect();
        let result = filter_and_sort(entries, None, None, 20).expect("filter");
        assert_eq!(result.len(), 20);
    }

    /// TC-0038-U09: Custom number limit restricts output count.
    #[test]
    fn tc_0038_u09_custom_number_limit() {
        let entries: Vec<EntryMeta> = (0u64..10)
            .map(|i| make_meta(&format!("{:032x}", i), "Entry", &[], i))
            .collect();
        let result = filter_and_sort(entries, None, None, 5).expect("filter");
        assert_eq!(result.len(), 5);
    }

    /// TC-0038-U10: When entry count < limit, all entries are returned.
    #[test]
    fn tc_0038_u10_fewer_entries_than_limit() {
        let entries = vec![
            make_meta("aa000000", "A", &[], 1),
            make_meta("bb000000", "B", &[], 2),
        ];
        let result = filter_and_sort(entries, None, None, 20).expect("filter");
        assert_eq!(result.len(), 2);
    }

    // =========================================================================
    // cmd_list integration tests (TASK-0038)
    // =========================================================================

    /// Build a `Cli` targeting `vault_dir` for the `list` command.
    fn make_list_cli(vault_dir_str: &str, password: Option<&str>) -> crate::Cli {
        let mut args: Vec<&str> = vec!["pq-diary", "-v", vault_dir_str];
        if let Some(pw) = password {
            args.extend_from_slice(&["--password", pw]);
        }
        args.push("list");
        crate::Cli::try_parse_from(&args).expect("parse test CLI")
    }

    /// Build a `Cli` targeting `vault_dir` for the `show` command.
    fn make_show_cli(vault_dir_str: &str, password: Option<&str>, id: &str) -> crate::Cli {
        let mut args: Vec<&str> = vec!["pq-diary", "-v", vault_dir_str];
        if let Some(pw) = password {
            args.extend_from_slice(&["--password", pw]);
        }
        args.extend_from_slice(&["show", id]);
        crate::Cli::try_parse_from(&args).expect("parse test CLI")
    }

    /// TC-0038-01: cmd_list succeeds on a vault with entries.
    #[test]
    fn tc_0038_01_cmd_list_succeeds() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        // Create an entry first
        let new_cli = make_cli(vault_dir_str, Some("password"));
        cmd_new(&new_cli, Some("Test".to_string()), Some("body".to_string()), vec![])
            .expect("cmd_new");

        let list_cli = make_list_cli(vault_dir_str, Some("password"));
        let result = cmd_list(&list_cli, None, None, 20);
        assert!(result.is_ok(), "cmd_list failed: {:?}", result.err());
    }

    /// TC-0038-02: cmd_list succeeds on an empty vault (zero entries).
    #[test]
    fn tc_0038_02_cmd_list_empty_vault() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let list_cli = make_list_cli(vault_dir_str, Some("password"));
        let result = cmd_list(&list_cli, None, None, 20);
        assert!(result.is_ok(), "cmd_list on empty vault failed: {:?}", result.err());
    }

    /// TC-0038-03: cmd_show retrieves an entry by 4-character ID prefix.
    #[test]
    fn tc_0038_03_cmd_show_by_prefix() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let new_cli = make_cli(vault_dir_str, Some("password"));
        cmd_new(
            &new_cli,
            Some("Show Test".to_string()),
            Some("body text".to_string()),
            vec![],
        )
        .expect("cmd_new");

        let entries = read_vault_entries(&vault_dir);
        let prefix4 = &entries[0].uuid_hex[..4];

        let show_cli = make_show_cli(vault_dir_str, Some("password"), prefix4);
        let result = cmd_show(&show_cli, prefix4.to_string());
        assert!(result.is_ok(), "cmd_show by prefix failed: {:?}", result.err());
    }

    /// TC-0038-04: cmd_show retrieves an entry by full 32-character UUID hex.
    #[test]
    fn tc_0038_04_cmd_show_by_full_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let new_cli = make_cli(vault_dir_str, Some("password"));
        cmd_new(
            &new_cli,
            Some("Full ID Show".to_string()),
            Some("body".to_string()),
            vec![],
        )
        .expect("cmd_new");

        let entries = read_vault_entries(&vault_dir);
        let full_id = entries[0].uuid_hex.clone();

        let show_cli = make_show_cli(vault_dir_str, Some("password"), &full_id);
        let result = cmd_show(&show_cli, full_id.clone());
        assert!(result.is_ok(), "cmd_show by full ID failed: {:?}", result.err());
    }

    /// TC-0038-05: cmd_show returns an error for a non-existent ID prefix.
    #[test]
    fn tc_0038_05_cmd_show_nonexistent_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let show_cli = make_show_cli(vault_dir_str, Some("password"), "0000");
        let result = cmd_show(&show_cli, "0000".to_string());
        assert!(result.is_err(), "Expected error for non-existent ID");
    }

    /// TC-0038-06: cmd_list with wrong password returns an error.
    #[test]
    fn tc_0038_06_cmd_list_wrong_password() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let list_cli = make_list_cli(vault_dir_str, Some("wrong_password"));
        let result = cmd_list(&list_cli, None, None, 20);
        assert!(result.is_err(), "Expected error for wrong password");
    }
}
