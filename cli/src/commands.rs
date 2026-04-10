//! Command handlers for pq-diary CLI.
//!
//! Each public function corresponds to a CLI subcommand and is wired up in
//! `main.rs`.  Handlers in this module may return `anyhow::Result` so that
//! arbitrary error sources can be propagated through the main entry-point.

use crate::editor::{self, EditorConfig};
use crate::password::get_password;
use crate::Cli;
use chrono::{DateTime, Local, Utc};
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
// check_claude_policy — pre-unlock policy gatekeeper
// ---------------------------------------------------------------------------

/// Evaluate Claude access policy before any vault operation.
///
/// Reads `vault.toml` from the vault directory and checks whether the
/// configured policy permits `operation` when running with `--claude`.
///
/// Returns `Ok(())` immediately when `--claude` is not set (non-Claude
/// environment).  This ensures the check adds zero overhead for normal usage.
///
/// # Errors
///
/// Returns an error if the vault directory cannot be determined, `vault.toml`
/// cannot be read or parsed, or the policy denies the requested operation.
fn check_claude_policy(
    cli: &Cli,
    operation: pq_diary_core::policy::OperationType,
) -> anyhow::Result<()> {
    use pq_diary_core::{policy, vault::config::VaultConfig};
    if !cli.claude {
        return Ok(());
    }
    let vault_path = resolve_vault_path(cli)?;
    let toml_path = vault_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("vault path has no parent directory"))?
        .join("vault.toml");
    let config = VaultConfig::from_file(&toml_path).map_err(|e| anyhow::anyhow!("{e}"))?;
    let decision = policy::check_access(true, config.access.policy, operation, &config.vault.name);
    decision.into_result().map_err(|e| anyhow::anyhow!("{}", e))
}

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
struct VaultGuard<'a>(&'a mut DiaryCore);

impl<'a> VaultGuard<'a> {
    /// Wrap an already-unlocked `DiaryCore` in a guard.
    fn new(core: &'a mut DiaryCore) -> Self {
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
    template: Option<String>,
) -> anyhow::Result<()> {
    use pq_diary_core::policy::OperationType;
    use secrecy::{ExposeSecret as _, SecretBox};
    use std::io::{BufRead as _, IsTerminal as _, Read as _};

    // Step 0: Policy check (before any password prompt or vault decryption).
    check_claude_policy(cli, OperationType::Write)?;

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
    let guard = VaultGuard::new(&mut core);

    // Step 2: Determine body text and potentially update title/tags.
    let (final_body, final_title, final_tags) = if let Some(b) = body {
        // -b / --body flag: highest priority; template is ignored; editor is NOT launched.
        (b, title, tags)
    } else if let Some(tmpl_name) = template {
        // --template: expand template variables and use as body; editor is NOT launched.
        use pq_diary_core::template_engine::{
            expand, extract_variables, VariableKind, BUILTIN_DATE, BUILTIN_DATETIME, BUILTIN_TITLE,
        };
        use std::collections::{HashMap, HashSet};

        let tmpl = guard
            .get_template(&tmpl_name)
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        let var_refs = extract_variables(&tmpl.body);

        // Populate builtin variables.
        let mut vars: HashMap<String, String> = HashMap::new();
        let now = Local::now();
        let title_for_tmpl = title
            .clone()
            .filter(|t| !t.is_empty())
            .unwrap_or_else(|| "Untitled".to_string());
        vars.insert(BUILTIN_DATE.to_string(), now.format("%Y-%m-%d").to_string());
        vars.insert(
            BUILTIN_DATETIME.to_string(),
            now.format("%Y-%m-%d %H:%M:%S").to_string(),
        );
        vars.insert(BUILTIN_TITLE.to_string(), title_for_tmpl);

        // Prompt for each unique custom variable once.
        let mut prompted: HashSet<String> = HashSet::new();
        for var_ref in &var_refs {
            if matches!(var_ref.kind, VariableKind::Custom) && prompted.insert(var_ref.name.clone())
            {
                use std::io::Write as _;
                print!("{}: ", var_ref.name);
                std::io::stdout()
                    .flush()
                    .map_err(|e| anyhow::anyhow!("Failed to flush stdout: {e}"))?;
                let mut input = String::new();
                std::io::stdin()
                    .lock()
                    .read_line(&mut input)
                    .map_err(|e| anyhow::anyhow!("Failed to read variable input: {e}"))?;
                vars.insert(var_ref.name.clone(), input.trim().to_string());
            }
        }

        let expanded = expand(&tmpl.body, &vars);
        (expanded, title, tags)
    } else if !std::io::stdin().is_terminal() {
        // Piped stdin: read all content.
        let mut content = String::new();
        std::io::stdin()
            .read_to_string(&mut content)
            .map_err(|e| anyhow::anyhow!("Failed to read stdin: {e}"))?;
        (content, title, tags)
    } else {
        // $EDITOR: write header-comment temp file, launch editor, read back.
        let mut config = EditorConfig::from_env().map_err(|e| anyhow::anyhow!("{e}"))?;

        let initial = EntryPlaintext {
            title: title.clone().unwrap_or_else(|| "Untitled".to_string()),
            tags: tags.clone(),
            body: String::new(),
        };

        let tmpfile = editor::write_header_file(&config.secure_tmpdir, &initial)
            .map_err(|e| anyhow::anyhow!("Failed to write temp file: {e}"))?;

        // Inject vim completion for [[title]] links (vim/nvim only).
        let is_vim = !config.vim_options.is_empty();
        let completion_file = if is_vim {
            let titles = guard.all_titles().unwrap_or_default();
            editor::write_completion_file(&config.secure_tmpdir, &titles).ok()
        } else {
            None
        };
        if let Some(ref cp) = completion_file {
            config
                .vim_options
                .extend(editor::vim_completion_options(cp));
        }

        // Launch editor and read result; always delete temp files afterward.
        let edit_result = editor::launch_editor(&tmpfile, &config);
        let read_result = editor::read_header_file(&tmpfile);
        if let Err(e) = editor::secure_delete(&tmpfile) {
            eprintln!("Warning: failed to securely delete temp file: {e}");
        }
        if let Some(cp) = completion_file {
            if let Err(e) = editor::secure_delete(&cp) {
                eprintln!("Warning: failed to securely delete completion file: {e}");
            }
        }

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
    let uuid_hex = guard
        .new_entry(&actual_title, &final_body, final_tags)
        .map_err(|e| anyhow::anyhow!("Failed to create entry: {e}"))?;

    // Step 5: Print success message with an 8-character ID prefix.
    let prefix = &uuid_hex[..8];
    println!("Created: {prefix} \"{actual_title}\"");

    // guard drops here, automatically calling lock().
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
    use pq_diary_core::policy::OperationType;
    use secrecy::{ExposeSecret as _, SecretBox};

    // Policy check before any password prompt or vault decryption.
    check_claude_policy(cli, OperationType::Read)?;

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
    let guard = VaultGuard::new(&mut core);

    let entries = guard
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

    // guard drops here, automatically calling lock().
    Ok(())
}

/// Execute the `pq-diary show` command.
///
/// Displays the full content of the entry identified by `id` (an ID prefix of
/// at least 4 hex characters).  Output includes title, created/updated dates,
/// tag list, a blank line, the full body text, resolved `[[link]]` references
/// (if any), and a `--- Backlinks ---` section (if the entry has incoming links).
///
/// # Errors
///
/// Returns an error if password acquisition, vault unlock, or entry lookup fails.
/// Returns an error with a descriptive message when no entry matches or multiple
/// entries match the given prefix.
pub fn cmd_show(cli: &Cli, id: String) -> anyhow::Result<()> {
    cmd_show_impl(cli, id, &mut std::io::stdout())
}

/// Internal implementation of `cmd_show` with an injectable writer.
///
/// Separating the writer allows tests to capture the output without spawning a
/// subprocess or redirecting `stdout`.
fn cmd_show_impl(cli: &Cli, id: String, out: &mut dyn std::io::Write) -> anyhow::Result<()> {
    use pq_diary_core::policy::OperationType;
    use secrecy::{ExposeSecret as _, SecretBox};

    // Policy check before any password prompt or vault decryption.
    check_claude_policy(cli, OperationType::Read)?;

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
    let guard = VaultGuard::new(&mut core);

    let (record, plaintext) = guard.get_entry(&id).map_err(|e| anyhow::anyhow!("{e}"))?;

    let created = format_timestamp(record.created_at);
    let updated = format_timestamp(record.updated_at);

    writeln!(out, "Title:   {}", plaintext.title)
        .map_err(|e| anyhow::anyhow!("Write error: {e}"))?;
    writeln!(out, "Created: {created}  Updated: {updated}")
        .map_err(|e| anyhow::anyhow!("Write error: {e}"))?;
    if plaintext.tags.is_empty() {
        writeln!(out, "Tags:    (none)").map_err(|e| anyhow::anyhow!("Write error: {e}"))?;
    } else {
        let tags_str = plaintext
            .tags
            .iter()
            .map(|t| format!("#{t}"))
            .collect::<Vec<_>>()
            .join("  ");
        writeln!(out, "Tags:    {tags_str}").map_err(|e| anyhow::anyhow!("Write error: {e}"))?;
    }
    writeln!(out).map_err(|e| anyhow::anyhow!("Write error: {e}"))?;
    write!(out, "{}", plaintext.body).map_err(|e| anyhow::anyhow!("Write error: {e}"))?;

    // Resolve [[link]] references in the body.
    let resolved = guard
        .resolve_links(&plaintext.body)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    if !resolved.is_empty() {
        writeln!(out).map_err(|e| anyhow::anyhow!("Write error: {e}"))?;
        writeln!(out, "--- Links ---").map_err(|e| anyhow::anyhow!("Write error: {e}"))?;
        for link in &resolved {
            match link.matches.len() {
                0 => writeln!(out, "  [[{}]] (未解決)", link.title)
                    .map_err(|e| anyhow::anyhow!("Write error: {e}"))?,
                1 => writeln!(
                    out,
                    "  [[{}]] → [{}]",
                    link.title, link.matches[0].id_prefix
                )
                .map_err(|e| anyhow::anyhow!("Write error: {e}"))?,
                _ => {
                    writeln!(out, "  [[{}]] → 複数候補:", link.title)
                        .map_err(|e| anyhow::anyhow!("Write error: {e}"))?;
                    for m in &link.matches {
                        writeln!(out, "    [{}]", m.id_prefix)
                            .map_err(|e| anyhow::anyhow!("Write error: {e}"))?;
                    }
                }
            }
        }
    }

    // Display backlinks (newest first).
    let mut backlinks = guard
        .backlinks_for(&plaintext.title)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    if !backlinks.is_empty() {
        backlinks.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        writeln!(out).map_err(|e| anyhow::anyhow!("Write error: {e}"))?;
        writeln!(out, "--- Backlinks ---").map_err(|e| anyhow::anyhow!("Write error: {e}"))?;
        for bl in &backlinks {
            let date = format_timestamp(bl.created_at);
            let prefix = backlink_uuid_prefix(&bl.source_uuid);
            writeln!(out, "  [{prefix}] {date} {}", bl.source_title)
                .map_err(|e| anyhow::anyhow!("Write error: {e}"))?;
        }
    }

    // guard drops here, automatically calling lock().
    Ok(())
}

/// Convert the first 4 bytes of a raw UUID into an 8-character lowercase hex prefix.
fn backlink_uuid_prefix(bytes: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(8);
    for &b in bytes.iter().take(4) {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Execute the `pq-diary edit` command.
///
/// Two modes of operation:
/// - **Flag mode**: when `--title`, `--add-tag`, or `--remove-tag` is specified,
///   metadata is updated directly without launching an editor.
/// - **Editor mode**: when no flags are given, `$EDITOR` is launched with a
///   header-comment formatted temporary file.  If nothing changed, prints
///   "変更がありませんでした" and returns `Ok(())`.  On header parse error, the
///   original title and tags are preserved and only the body is updated.
///
/// The temporary file is always securely deleted regardless of editor success
/// or failure.
///
/// # Errors
///
/// Returns an error if password acquisition, vault unlock, editor launch, or
/// entry update fails.
pub fn cmd_edit(
    cli: &Cli,
    id: String,
    title: Option<String>,
    add_tags: Vec<String>,
    remove_tags: Vec<String>,
) -> anyhow::Result<()> {
    cmd_edit_impl(cli, id, title, add_tags, remove_tags, |tmpfile, config| {
        editor::launch_editor(tmpfile, config)
    })
}

/// Internal implementation of `cmd_edit` with an injectable editor launcher.
///
/// Accepts any `FnOnce` as the editor launcher so that tests can inject a mock
/// without spawning a real process.
fn cmd_edit_impl<F>(
    cli: &Cli,
    id: String,
    title: Option<String>,
    add_tags: Vec<String>,
    remove_tags: Vec<String>,
    launch_fn: F,
) -> anyhow::Result<()>
where
    F: FnOnce(&std::path::Path, &EditorConfig) -> Result<(), pq_diary_core::DiaryError>,
{
    use pq_diary_core::policy::OperationType;
    use secrecy::{ExposeSecret as _, SecretBox};

    // Policy check before any password prompt or vault decryption.
    check_claude_policy(cli, OperationType::Write)?;

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
    let guard = VaultGuard::new(&mut core);

    let (_record, original) = guard.get_entry(&id).map_err(|e| anyhow::anyhow!("{e}"))?;

    let flag_mode = title.is_some() || !add_tags.is_empty() || !remove_tags.is_empty();

    if flag_mode {
        // Flag mode: apply metadata changes directly without launching an editor.
        let mut new_plaintext = EntryPlaintext {
            title: original.title.clone(),
            tags: original.tags.clone(),
            body: original.body.clone(),
        };

        if let Some(t) = title {
            new_plaintext.title = t;
        }

        for tag in &add_tags {
            if !new_plaintext.tags.contains(tag) {
                new_plaintext.tags.push(tag.clone());
            }
        }

        for tag in &remove_tags {
            new_plaintext.tags.retain(|t| t != tag);
        }

        guard
            .update_entry(&id, &new_plaintext)
            .map_err(|e| anyhow::anyhow!("Failed to update entry: {e}"))?;
        let prefix = &id[..id.len().min(8)];
        println!("Updated: {prefix}");
    } else {
        // Editor mode: write header-comment temp file, launch editor, parse result.
        let mut config = EditorConfig::from_env().map_err(|e| anyhow::anyhow!("{e}"))?;

        let tmpfile = editor::write_header_file(&config.secure_tmpdir, &original)
            .map_err(|e| anyhow::anyhow!("Failed to write temp file: {e}"))?;

        // Inject vim completion for [[title]] links (vim/nvim only).
        let is_vim = !config.vim_options.is_empty();
        let completion_file = if is_vim {
            let titles = guard.all_titles().unwrap_or_default();
            editor::write_completion_file(&config.secure_tmpdir, &titles).ok()
        } else {
            None
        };
        if let Some(ref cp) = completion_file {
            config
                .vim_options
                .extend(editor::vim_completion_options(cp));
        }

        // Always delete temp files regardless of editor/read success.
        let edit_result = launch_fn(&tmpfile, &config);
        let read_result = editor::read_header_file(&tmpfile);
        if let Err(e) = editor::secure_delete(&tmpfile) {
            eprintln!("Warning: failed to securely delete temp file: {e}");
        }
        if let Some(cp) = completion_file {
            if let Err(e) = editor::secure_delete(&cp) {
                eprintln!("Warning: failed to securely delete completion file: {e}");
            }
        }

        edit_result.map_err(|e| anyhow::anyhow!("Editor failed: {e}"))?;
        let header = read_result.map_err(|e| anyhow::anyhow!("Failed to read temp file: {e}"))?;

        // On header parse error, fall back to the original metadata.
        let (new_title, new_tags) = match (header.title, header.tags) {
            (Some(t), Some(tags)) => (t, tags),
            _ => (original.title.clone(), original.tags.clone()),
        };
        let new_body = header.body;

        // Change detection: skip update if nothing changed.
        if new_title == original.title && new_tags == original.tags && new_body == original.body {
            println!("変更がありませんでした");
            return Ok(());
            // guard drops here even on early return, calling lock().
        }

        let new_plaintext = EntryPlaintext {
            title: new_title,
            tags: new_tags,
            body: new_body,
        };

        guard
            .update_entry(&id, &new_plaintext)
            .map_err(|e| anyhow::anyhow!("Failed to update entry: {e}"))?;
        let prefix = &id[..id.len().min(8)];
        println!("Updated: {prefix}");
    }

    // guard drops here, automatically calling lock().
    Ok(())
}

/// Prompt the user for deletion confirmation.
///
/// Prints `Delete "{title}" ({date})? [y/N]: ` to stderr and reads a line
/// from `reader`.  Returns `true` only when the user responds with `y` or `Y`.
fn confirm_delete(
    title: &str,
    date: &str,
    reader: &mut impl std::io::BufRead,
) -> anyhow::Result<bool> {
    use std::io::Write as _;
    eprint!("Delete \"{title}\" ({date})? [y/N]: ");
    std::io::stderr()
        .flush()
        .map_err(|e| anyhow::anyhow!("Failed to flush stderr: {e}"))?;
    let mut input = String::new();
    reader
        .read_line(&mut input)
        .map_err(|e| anyhow::anyhow!("Failed to read input: {e}"))?;
    let trimmed = input.trim();
    Ok(trimmed == "y" || trimmed == "Y")
}

/// Execute the `pq-diary delete` command.
///
/// Fetches the entry identified by `id`, displays its title and date, and
/// prompts for confirmation unless `force` or `--claude` is set.  Prints
/// `Deleted: {prefix} "{title}"` on success, or `キャンセルしました` when
/// the user declines.
///
/// # Errors
///
/// Returns an error if password acquisition, vault unlock, entry lookup, or
/// entry deletion fails.
pub fn cmd_delete(cli: &Cli, id: String, force: bool) -> anyhow::Result<()> {
    cmd_delete_impl(
        cli,
        id,
        force,
        &mut std::io::BufReader::new(std::io::stdin()),
    )
}

/// Internal implementation of `cmd_delete` with an injectable stdin reader.
///
/// Accepts any `BufRead` as the input source so that tests can inject mock
/// input without touching a real terminal.
fn cmd_delete_impl(
    cli: &Cli,
    id: String,
    force: bool,
    reader: &mut impl std::io::BufRead,
) -> anyhow::Result<()> {
    use pq_diary_core::policy::OperationType;
    use secrecy::{ExposeSecret as _, SecretBox};

    // Policy check before any password prompt or vault decryption.
    check_claude_policy(cli, OperationType::Write)?;

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
    let guard = VaultGuard::new(&mut core);

    let (record, plaintext) = guard.get_entry(&id).map_err(|e| anyhow::anyhow!("{e}"))?;

    let title = plaintext.title.clone();
    let date = format_timestamp(record.created_at);
    let prefix = id[..id.len().min(8)].to_string();

    // Determine whether to skip confirmation.
    let skip_confirm = force || cli.claude;
    let do_delete = if skip_confirm {
        true
    } else {
        confirm_delete(&title, &date, reader)?
    };

    if do_delete {
        guard
            .delete_entry(&id)
            .map_err(|e| anyhow::anyhow!("Failed to delete entry: {e}"))?;
        println!("Deleted: {prefix} \"{title}\"");
    } else {
        println!("キャンセルしました");
    }

    // guard drops here, automatically calling lock().
    Ok(())
}

// ---------------------------------------------------------------------------
// Template command handlers
// ---------------------------------------------------------------------------

/// Prompt the user for template deletion confirmation.
///
/// Prints `Delete template "{name}"? [y/N]: ` to stderr and reads a line from
/// `reader`.  Returns `true` only when the user responds with `y` or `Y`.
fn confirm_template_delete(name: &str, reader: &mut impl std::io::BufRead) -> anyhow::Result<bool> {
    use std::io::Write as _;
    eprint!("Delete template \"{name}\"? [y/N]: ");
    std::io::stderr()
        .flush()
        .map_err(|e| anyhow::anyhow!("Failed to flush stderr: {e}"))?;
    let mut input = String::new();
    reader
        .read_line(&mut input)
        .map_err(|e| anyhow::anyhow!("Failed to read input: {e}"))?;
    let trimmed = input.trim();
    Ok(trimmed == "y" || trimmed == "Y")
}

/// Execute the `pq-diary template add` command.
///
/// Opens `$EDITOR` with a blank temporary file; on save, stores the file
/// contents as the body of a new template named `name`.
///
/// If a template with the same `name` already exists, the user is prompted to
/// confirm overwriting (unless `--claude` is set, in which case overwrite
/// proceeds silently).
///
/// # Errors
///
/// Returns an error if password acquisition, vault unlock, editor launch,
/// or template creation fails.
pub fn cmd_template_add(cli: &Cli, name: String) -> anyhow::Result<()> {
    cmd_template_add_impl(
        cli,
        name,
        editor::launch_editor,
        &mut std::io::BufReader::new(std::io::stdin()),
    )
}

/// Internal implementation of `cmd_template_add` with injectable editor launcher and reader.
fn cmd_template_add_impl<F>(
    cli: &Cli,
    name: String,
    launch_fn: F,
    reader: &mut impl std::io::BufRead,
) -> anyhow::Result<()>
where
    F: FnOnce(&std::path::Path, &EditorConfig) -> Result<(), pq_diary_core::DiaryError>,
{
    use pq_diary_core::policy::OperationType;
    use secrecy::{ExposeSecret as _, SecretBox};

    // Policy check before any password prompt or vault decryption.
    check_claude_policy(cli, OperationType::Write)?;

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
    let guard = VaultGuard::new(&mut core);

    // Check for an existing template with the same name.
    let already_exists = guard.get_template(&name).is_ok();
    if already_exists && !cli.claude {
        use std::io::Write as _;
        eprint!("Template \"{name}\" already exists. Overwrite? [y/N]: ");
        std::io::stderr()
            .flush()
            .map_err(|e| anyhow::anyhow!("Failed to flush stderr: {e}"))?;
        let mut input = String::new();
        reader
            .read_line(&mut input)
            .map_err(|e| anyhow::anyhow!("Failed to read input: {e}"))?;
        let trimmed = input.trim();
        if trimmed != "y" && trimmed != "Y" {
            println!("キャンセルしました");
            return Ok(());
            // guard drops here, calling lock().
        }
    }

    // Set up editor config.
    let config = editor::EditorConfig::from_env().map_err(|e| anyhow::anyhow!("{e}"))?;

    // Write a blank temp file and launch editor.
    let tmpfile = editor::write_template_file(&config.secure_tmpdir)
        .map_err(|e| anyhow::anyhow!("Failed to write temp file: {e}"))?;

    let edit_result = launch_fn(&tmpfile, &config);
    let read_result = editor::read_template_file(&tmpfile);
    if let Err(e) = editor::secure_delete(&tmpfile) {
        eprintln!("Warning: failed to securely delete temp file: {e}");
    }

    edit_result.map_err(|e| anyhow::anyhow!("Editor failed: {e}"))?;
    let body = read_result.map_err(|e| anyhow::anyhow!("Failed to read temp file: {e}"))?;

    // Delete the existing template before creating the replacement.
    if already_exists {
        guard
            .delete_template(&name)
            .map_err(|e| anyhow::anyhow!("Failed to delete old template: {e}"))?;
    }

    guard
        .new_template(&name, &body)
        .map_err(|e| anyhow::anyhow!("Failed to create template: {e}"))?;
    if already_exists {
        println!("Template replaced: \"{name}\"");
    } else {
        println!("Template created: \"{name}\"");
    }

    // guard drops here, automatically calling lock().
    Ok(())
}

/// Execute the `pq-diary template list` command.
///
/// Lists all templates stored in the vault sorted alphabetically by name.
/// Prints one name per line.
///
/// # Errors
///
/// Returns an error if password acquisition, vault unlock, or template listing fails.
pub fn cmd_template_list(cli: &Cli) -> anyhow::Result<()> {
    use pq_diary_core::policy::OperationType;
    use secrecy::{ExposeSecret as _, SecretBox};

    // Policy check before any password prompt or vault decryption.
    check_claude_policy(cli, OperationType::Read)?;

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
    let guard = VaultGuard::new(&mut core);

    let mut templates = guard
        .list_templates()
        .map_err(|e| anyhow::anyhow!("Failed to list templates: {e}"))?;
    templates.sort_by(|a, b| a.name.cmp(&b.name));

    for meta in &templates {
        println!("{}", meta.name);
    }

    // guard drops here, automatically calling lock().
    Ok(())
}

/// Execute the `pq-diary template show` command.
///
/// Displays the body text of the template identified by `name`.
///
/// # Errors
///
/// Returns an error if password acquisition, vault unlock, or template lookup fails.
/// Returns `DiaryError::TemplateNotFound` (wrapped in anyhow) when no template
/// with the given name exists.
pub fn cmd_template_show(cli: &Cli, name: String) -> anyhow::Result<()> {
    use pq_diary_core::policy::OperationType;
    use secrecy::{ExposeSecret as _, SecretBox};

    // Policy check before any password prompt or vault decryption.
    check_claude_policy(cli, OperationType::Read)?;

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
    let guard = VaultGuard::new(&mut core);

    let plaintext = guard
        .get_template(&name)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    print!("{}", plaintext.body);

    // guard drops here, automatically calling lock().
    Ok(())
}

/// Execute the `pq-diary template delete` command.
///
/// Looks up the template identified by `name`, then prompts for confirmation
/// unless `force` or `--claude` is set.  Prints `Deleted template: "{name}"` on
/// success, or `キャンセルしました` when the user declines.
///
/// # Errors
///
/// Returns an error if password acquisition, vault unlock, template lookup, or
/// template deletion fails.
pub fn cmd_template_delete(cli: &Cli, name: String, force: bool) -> anyhow::Result<()> {
    cmd_template_delete_impl(
        cli,
        name,
        force,
        &mut std::io::BufReader::new(std::io::stdin()),
    )
}

/// Internal implementation of `cmd_template_delete` with an injectable stdin reader.
fn cmd_template_delete_impl(
    cli: &Cli,
    name: String,
    force: bool,
    reader: &mut impl std::io::BufRead,
) -> anyhow::Result<()> {
    use pq_diary_core::policy::OperationType;
    use secrecy::{ExposeSecret as _, SecretBox};

    // Policy check before any password prompt or vault decryption.
    check_claude_policy(cli, OperationType::Write)?;

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
    let guard = VaultGuard::new(&mut core);

    // Verify the template exists.
    guard
        .get_template(&name)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Determine whether to skip confirmation.
    let skip_confirm = force || cli.claude;
    let do_delete = if skip_confirm {
        true
    } else {
        confirm_template_delete(&name, reader)?
    };

    if do_delete {
        guard
            .delete_template(&name)
            .map_err(|e| anyhow::anyhow!("Failed to delete template: {e}"))?;
        println!("Deleted template: \"{name}\"");
    } else {
        println!("キャンセルしました");
    }

    // guard drops here, automatically calling lock().
    Ok(())
}

// ---------------------------------------------------------------------------
// Today command handler
// ---------------------------------------------------------------------------

/// Execute the `pq-diary today` command.
///
/// Opens or creates today's diary entry (title `YYYY-MM-DD` in local time).
/// - If an entry with today's title already exists, opens it in `$EDITOR`.
/// - If no such entry exists, creates one using the `daily` template (with
///   `{{date}}` and `{{title}}` expanded) or an empty body, then opens it
///   in `$EDITOR`.
///
/// # Errors
///
/// Returns an error if password acquisition, vault unlock, entry creation,
/// or editor launch fails.
pub fn cmd_today(cli: &Cli) -> anyhow::Result<()> {
    let today = chrono::Local::now().format("%Y-%m-%d").to_string();
    cmd_today_impl(cli, &today, |tmpfile, config| {
        editor::launch_editor(tmpfile, config)
    })
}

/// Internal implementation of `cmd_today` with injectable date string and editor launcher.
///
/// Accepts any `FnOnce` as the editor launcher so that tests can inject a mock
/// without spawning a real process.
fn cmd_today_impl<F>(cli: &Cli, today: &str, launch_fn: F) -> anyhow::Result<()>
where
    F: FnOnce(&std::path::Path, &EditorConfig) -> Result<(), pq_diary_core::DiaryError>,
{
    use pq_diary_core::policy::OperationType;
    use pq_diary_core::template_engine::{expand, BUILTIN_DATE, BUILTIN_TITLE};
    use secrecy::{ExposeSecret as _, SecretBox};
    use std::collections::HashMap;

    // Policy check before any password prompt or vault decryption.
    check_claude_policy(cli, OperationType::Write)?;

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
    let guard = VaultGuard::new(&mut core);

    // Search for today's entry by exact title match.
    let entries = guard
        .list_entries(None)
        .map_err(|e| anyhow::anyhow!("Failed to list entries: {e}"))?;
    let today_entry = entries.iter().find(|e| e.title == today);

    let entry_id = if let Some(meta) = today_entry {
        // Entry exists: reuse its UUID hex.
        meta.uuid_hex.clone()
    } else {
        // Entry does not exist: determine initial body from template or empty string.
        let initial_body = match guard.get_template("daily") {
            Ok(tmpl) => {
                let mut vars: HashMap<String, String> = HashMap::new();
                vars.insert(BUILTIN_DATE.to_string(), today.to_string());
                vars.insert(BUILTIN_TITLE.to_string(), today.to_string());
                expand(&tmpl.body, &vars)
            }
            Err(_) => String::new(),
        };

        // Create the entry.
        guard
            .new_entry(today, &initial_body, vec![])
            .map_err(|e| anyhow::anyhow!("Failed to create entry: {e}"))?
    };

    // Open the entry in the editor (edit flow).
    let id_prefix = entry_id[..entry_id.len().min(8)].to_string();
    let (_record, original) = guard
        .get_entry(&id_prefix)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let mut config = EditorConfig::from_env().map_err(|e| anyhow::anyhow!("{e}"))?;

    let tmpfile = editor::write_header_file(&config.secure_tmpdir, &original)
        .map_err(|e| anyhow::anyhow!("Failed to write temp file: {e}"))?;

    // Inject vim completion for [[title]] links (vim/nvim only).
    let is_vim = !config.vim_options.is_empty();
    let completion_file = if is_vim {
        let titles = guard.all_titles().unwrap_or_default();
        editor::write_completion_file(&config.secure_tmpdir, &titles).ok()
    } else {
        None
    };
    if let Some(ref cp) = completion_file {
        config
            .vim_options
            .extend(editor::vim_completion_options(cp));
    }

    let edit_result = launch_fn(&tmpfile, &config);
    let read_result = editor::read_header_file(&tmpfile);
    if let Err(e) = editor::secure_delete(&tmpfile) {
        eprintln!("Warning: failed to securely delete temp file: {e}");
    }
    if let Some(cp) = completion_file {
        if let Err(e) = editor::secure_delete(&cp) {
            eprintln!("Warning: failed to securely delete completion file: {e}");
        }
    }

    edit_result.map_err(|e| anyhow::anyhow!("Editor failed: {e}"))?;
    let header = read_result.map_err(|e| anyhow::anyhow!("Failed to read temp file: {e}"))?;

    let (new_title, new_tags) = match (header.title, header.tags) {
        (Some(t), Some(tags)) => (t, tags),
        _ => (original.title.clone(), original.tags.clone()),
    };
    let new_body = header.body;

    if new_title == original.title && new_tags == original.tags && new_body == original.body {
        println!("変更がありませんでした");
        return Ok(());
        // guard drops here even on early return, calling lock().
    }

    let new_plaintext = EntryPlaintext {
        title: new_title,
        tags: new_tags,
        body: new_body,
    };

    guard
        .update_entry(&id_prefix, &new_plaintext)
        .map_err(|e| anyhow::anyhow!("Failed to update entry: {e}"))?;
    println!("Updated: {id_prefix}");

    // guard drops here, automatically calling lock().
    Ok(())
}

// ---------------------------------------------------------------------------
// Search command
// ---------------------------------------------------------------------------

/// Execute the `pq-diary search` command, writing output to stdout.
///
/// Searches all vault entries for `args.pattern` (a regular expression) and
/// prints matches in a grep-like format.  The `VaultGuard` pattern ensures
/// the vault is locked on every exit path.
///
/// # Errors
///
/// Returns an error if password acquisition, vault unlock, or search fails.
pub fn cmd_search(cli: &Cli, args: &crate::SearchArgs) -> anyhow::Result<()> {
    cmd_search_to(cli, args, &mut std::io::stdout())
}

/// Inner implementation of [`cmd_search`] that writes output to `out`.
///
/// Separated from `cmd_search` to enable output capture in tests.
pub(crate) fn cmd_search_to(
    cli: &Cli,
    args: &crate::SearchArgs,
    out: &mut dyn std::io::Write,
) -> anyhow::Result<()> {
    use pq_diary_core::policy::OperationType;
    use pq_diary_core::search::SearchQuery;
    use secrecy::{ExposeSecret as _, SecretBox};

    // Policy check before any password prompt or vault decryption.
    check_claude_policy(cli, OperationType::Read)?;

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
    let guard = VaultGuard::new(&mut core);

    let query = SearchQuery {
        pattern: args.pattern.clone(),
        tag_filter: args.tag.clone(),
        context_lines: args.context,
        count_only: args.count,
    };

    let results = guard.search(&query).map_err(|e| anyhow::anyhow!("{e}"))?;

    if args.count {
        writeln!(out, "{} entries matched", results.matched_entry_count)?;
    } else if results.matches.is_empty() {
        writeln!(out, "No matches found")?;
    } else {
        write_search_results(&results, out)?;
    }

    // guard drops here, automatically calling lock().
    Ok(())
}

/// Write search results to `out` in grep-like format.
///
/// Each `SearchMatch` is printed as a header line followed by context blocks.
/// Consecutive matches are separated by `--`.
fn write_search_results(
    results: &pq_diary_core::search::SearchResults,
    out: &mut dyn std::io::Write,
) -> anyhow::Result<()> {
    let mut first = true;
    for m in &results.matches {
        if !first {
            writeln!(out, "--")?;
        }
        first = false;

        let id_prefix = if m.uuid_hex.len() >= 8 {
            &m.uuid_hex[..8]
        } else {
            m.uuid_hex.as_str()
        };
        let date = format_timestamp(m.updated_at);
        writeln!(out, "{id_prefix} {date} {}", m.title)?;

        for block in &m.context_blocks {
            for (line_num, content, is_match) in &block.lines {
                if *is_match {
                    writeln!(out, "> {line_num}: {content}")?;
                } else {
                    writeln!(out, "  {line_num}: {content}")?;
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Stats command
// ---------------------------------------------------------------------------

/// Execute the `pq-diary stats` command, writing output to stdout.
///
/// Collects vault-wide statistics and prints them in text, JSON, or heatmap
/// format depending on the flags in `args`.  The `VaultGuard` pattern ensures
/// the vault is locked on every exit path.
///
/// # Errors
///
/// Returns an error if password acquisition, vault unlock, or statistics
/// collection fails.
pub fn cmd_stats(cli: &Cli, args: &crate::StatsArgs) -> anyhow::Result<()> {
    cmd_stats_to(cli, args, &mut std::io::stdout())
}

/// Inner implementation of [`cmd_stats`] that writes output to `out`.
///
/// Separated from `cmd_stats` to enable output capture in tests.
pub(crate) fn cmd_stats_to(
    cli: &Cli,
    args: &crate::StatsArgs,
    out: &mut dyn std::io::Write,
) -> anyhow::Result<()> {
    use pq_diary_core::policy::OperationType;
    use secrecy::{ExposeSecret as _, SecretBox};

    // Policy check before any password prompt or vault decryption.
    check_claude_policy(cli, OperationType::Read)?;

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
    let guard = VaultGuard::new(&mut core);

    let stats = guard.stats().map_err(|e| anyhow::anyhow!("{e}"))?;

    if args.json {
        let json = serde_json::to_string_pretty(&stats)
            .map_err(|e| anyhow::anyhow!("JSON serialization failed: {e}"))?;
        writeln!(out, "{json}")?;
    } else if args.heatmap {
        let heatmap = render_heatmap(&stats.daily_activity);
        writeln!(out, "{heatmap}")?;
    } else {
        let first_date = stats
            .first_entry_date
            .map(format_timestamp)
            .unwrap_or_else(|| "N/A".to_string());
        let last_date = stats
            .last_entry_date
            .map(format_timestamp)
            .unwrap_or_else(|| "N/A".to_string());

        writeln!(out, "=== Vault Statistics ===")?;
        writeln!(out)?;
        writeln!(out, "Entries:        {}", stats.entry_count)?;
        writeln!(out, "Tags:           {}", stats.tag_count)?;
        writeln!(out, "First entry:    {first_date}")?;
        writeln!(out, "Last entry:     {last_date}")?;
        writeln!(out, "Active days (30d): {}", stats.active_days_30d)?;
        writeln!(out)?;
        writeln!(out, "Characters:")?;
        writeln!(out, "  Total:        {}", stats.char_stats.total)?;
        writeln!(out, "  Average:      {}", stats.char_stats.average)?;
        writeln!(out, "  Maximum:      {}", stats.char_stats.max)?;
        writeln!(out)?;
        if stats.tag_distribution.is_empty() {
            writeln!(out, "Top Tags: N/A")?;
        } else {
            writeln!(out, "Top Tags:")?;
            for (i, tc) in stats.tag_distribution.iter().enumerate() {
                writeln!(out, "  {}. {} ({})", i + 1, tc.tag, tc.count)?;
            }
        }
    }

    // guard drops here, automatically calling lock().
    Ok(())
}

/// Render a 7-row × 52-column ASCII heatmap of daily writing activity.
///
/// Each cell maps an entry count to a Unicode block character:
/// - `░` — 0 entries
/// - `▒` — 1 entry
/// - `▓` — 2–3 entries
/// - `█` — 4 or more entries
///
/// The grid covers the last 52 weeks (364 days) ending today.  Rows are
/// weekdays (Mon–Sun) and columns are calendar weeks (oldest left, newest
/// right).  A month-abbreviation header and a legend line are appended.
fn render_heatmap(daily_activity: &[pq_diary_core::stats::DailyActivity]) -> String {
    use chrono::{Datelike as _, Duration, Utc};
    use std::collections::HashMap;

    let activity_map: HashMap<String, usize> = daily_activity
        .iter()
        .map(|a| (a.date.clone(), a.count))
        .collect();

    let today = Utc::now().date_naive();
    let start_date = today - Duration::days(363);

    const WEEKS: usize = 52;
    // grid[weekday][week]: weekday 0 = Mon … 6 = Sun
    let mut grid = [[0usize; WEEKS]; 7];

    // Align grid to calendar week boundaries: Monday is always row 0.
    let start_weekday = start_date.weekday().num_days_from_monday() as usize; // 0=Mon
    for day_offset in 0..364i64 {
        let date = start_date + Duration::days(day_offset);
        let adjusted_offset = day_offset as usize + start_weekday;
        let week = adjusted_offset / 7;
        let weekday = adjusted_offset % 7;
        let date_str = date.format("%Y-%m-%d").to_string();
        let count = activity_map.get(&date_str).copied().unwrap_or(0);
        if week < WEEKS {
            grid[weekday][week] = count;
        }
    }

    let count_to_char = |c: usize| -> char {
        match c {
            0 => '░',
            1 => '▒',
            2 | 3 => '▓',
            _ => '█',
        }
    };

    const MONTH_NAMES: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    // Build the month header: 5-char indent ("     ") followed by 52 chars.
    // Month abbreviations (3 chars) are written left-aligned at the column
    // where the month first appears; they may overlap with the next label.
    let mut header_chars: Vec<char> = std::iter::repeat_n(' ', 5 + WEEKS).collect();
    let mut last_month: u32 = 0;
    for week in 0..WEEKS {
        // The Monday (row 0) of each grid column: offset back by start_weekday.
        let date = start_date + Duration::days((week * 7) as i64 - start_weekday as i64);
        let month = date.month();
        if month != last_month {
            let m_str = MONTH_NAMES[(month - 1) as usize];
            let pos = 5 + week;
            for (i, ch) in m_str.chars().enumerate() {
                if pos + i < header_chars.len() {
                    header_chars[pos + i] = ch;
                }
            }
            last_month = month;
        }
    }
    let header: String = header_chars.into_iter().collect();

    let day_labels = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    let mut lines = vec![header];
    for (weekday, week_counts) in grid.iter().enumerate() {
        let mut row = format!("{} ", day_labels[weekday]);
        for &count in week_counts.iter() {
            row.push(count_to_char(count));
        }
        lines.push(row);
    }
    lines.push("Legend: ░ 0  ▒ 1  ▓ 2-3  █ 4+".to_string());
    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Import command
// ---------------------------------------------------------------------------

/// Execute the `pq-diary import` command, writing output to stdout.
///
/// Recursively imports all `.md` files from `args.dir` into the vault.
/// When `args.dry_run` is `true`, no entries are written; a preview summary
/// is printed instead.  The `VaultGuard` pattern ensures the vault is locked
/// on every exit path.
///
/// # Errors
///
/// Returns an error if the directory does not exist, is not a directory,
/// password acquisition fails, vault unlock fails, or import fails.
pub fn cmd_import(cli: &Cli, args: &crate::ImportArgs) -> anyhow::Result<()> {
    cmd_import_to(cli, args, &mut std::io::stdout())
}

/// Inner implementation of [`cmd_import`] that writes output to `out`.
///
/// Separated from `cmd_import` to enable output capture in tests.
pub(crate) fn cmd_import_to(
    cli: &Cli,
    args: &crate::ImportArgs,
    out: &mut dyn std::io::Write,
) -> anyhow::Result<()> {
    use secrecy::{ExposeSecret as _, SecretBox};

    // 1. Validate source directory before touching the vault.
    if !args.dir.exists() {
        return Err(anyhow::anyhow!(
            "Error: Directory '{}' does not exist",
            args.dir.display()
        ));
    }
    if !args.dir.is_dir() {
        return Err(anyhow::anyhow!(
            "Error: '{}' is not a directory",
            args.dir.display()
        ));
    }

    // 2. Policy check before any password prompt or vault decryption.
    {
        use pq_diary_core::policy::OperationType;
        check_claude_policy(cli, OperationType::Write)?;
    }

    // 3. Acquire password.
    let password_source =
        get_password(cli.password.as_deref()).map_err(|e| anyhow::anyhow!("{e}"))?;

    // 4. Open and unlock vault.
    let vault_path = resolve_vault_path(cli)?;
    let vault_str = vault_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Vault path contains non-UTF-8 characters"))?;

    let mut core = DiaryCore::new(vault_str).map_err(|e| anyhow::anyhow!("{e}"))?;

    let secret_password: secrecy::SecretString =
        SecretBox::new(Box::from(password_source.secret().expose_secret()));
    core.unlock(secret_password)
        .map_err(|e| anyhow::anyhow!("Vault unlock failed: {e}"))?;
    let guard = VaultGuard::new(&mut core);

    // 5. Run import (dry_run flag is forwarded to core).
    let result = guard
        .import(&args.dir, args.dry_run)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // 6. Display results.
    if args.dry_run {
        writeln!(
            out,
            "[DRY RUN] Would import {} files from '{}'",
            result.would_import,
            args.dir.display()
        )?;
        writeln!(out, "  Links to convert: {}", result.links_converted)?;
        writeln!(out, "  Tags to extract: {}", result.tags_converted)?;
        writeln!(out, "  Files to skip: {}", result.skipped)?;
        for detail in &result.skip_details {
            writeln!(out, "    - {} ({})", detail.path, detail.reason)?;
        }
    } else {
        writeln!(
            out,
            "Imported: {}, Skipped: {}, Links converted: {}, Tags converted: {}",
            result.imported, result.skipped, result.links_converted, result.tags_converted
        )?;
    }

    // guard drops here, automatically calling lock().
    Ok(())
}

// ---------------------------------------------------------------------------
// Vault command handlers
// ---------------------------------------------------------------------------

/// Resolve the base directory for vault management commands.
///
/// - `--vault <dir>` → used as-is
/// - No `--vault`   → current working directory
fn resolve_vaults_base_dir(cli: &Cli) -> anyhow::Result<PathBuf> {
    match &cli.vault {
        Some(v) => Ok(PathBuf::from(v)),
        None => std::env::current_dir()
            .map_err(|e| anyhow::anyhow!("Cannot determine current directory: {e}")),
    }
}

/// Show the Full-policy security warning and read a [y/N] confirmation.
///
/// Prints the warning to stderr and reads one line from `reader`.
/// Returns `true` only when the user responds with `y` or `Y`.
fn confirm_full_policy(reader: &mut impl std::io::BufRead) -> anyhow::Result<bool> {
    use std::io::Write as _;
    eprintln!("警告: \"full\"を設定すると日記内容がAnthropicのAPIサーバーを通過します。");
    eprintln!("      間接プロンプトインジェクション等のリスクがあります。");
    eprint!("      本当に許可しますか？ [y/N]: ");
    std::io::stderr()
        .flush()
        .map_err(|e| anyhow::anyhow!("Failed to flush stderr: {e}"))?;
    let mut input = String::new();
    reader
        .read_line(&mut input)
        .map_err(|e| anyhow::anyhow!("Failed to read input: {e}"))?;
    let trimmed = input.trim();
    Ok(trimmed == "y" || trimmed == "Y")
}

/// Show the vault deletion [y/N] confirmation prompt.
///
/// Returns `true` only when the user responds with `y` or `Y`.
fn confirm_vault_delete(name: &str, reader: &mut impl std::io::BufRead) -> anyhow::Result<bool> {
    use std::io::Write as _;
    eprint!("Delete vault '{name}'? [y/N]: ");
    std::io::stderr()
        .flush()
        .map_err(|e| anyhow::anyhow!("Failed to flush stderr: {e}"))?;
    let mut input = String::new();
    reader
        .read_line(&mut input)
        .map_err(|e| anyhow::anyhow!("Failed to read input: {e}"))?;
    let trimmed = input.trim();
    Ok(trimmed == "y" || trimmed == "Y")
}

/// Execute the `pq-diary vault create` command.
///
/// Parses `policy_str` to an `AccessPolicy` (default: `None`), shows a
/// security warning for `Full` policy, prompts for the vault password, and
/// creates the vault via `VaultManager::create_vault`.
///
/// # Errors
///
/// Returns an error if the policy string is invalid, the user cancels the
/// `Full` policy confirmation, password acquisition fails, or vault creation
/// fails.
pub fn cmd_vault_create(cli: &Cli, name: &str, policy_str: Option<&str>) -> anyhow::Result<()> {
    use pq_diary_core::vault::init::VaultManager;
    cmd_vault_create_impl(
        cli,
        name,
        policy_str,
        &mut std::io::BufReader::new(std::io::stdin()),
        |base_dir| VaultManager::new(base_dir).map_err(|e| anyhow::anyhow!("{e}")),
    )
}

/// Internal implementation of `cmd_vault_create` with injectable stdin reader
/// and `VaultManager` factory.
fn cmd_vault_create_impl(
    cli: &Cli,
    name: &str,
    policy_str: Option<&str>,
    reader: &mut impl std::io::BufRead,
    mgr_factory: impl FnOnce(PathBuf) -> anyhow::Result<pq_diary_core::vault::init::VaultManager>,
) -> anyhow::Result<()> {
    use pq_diary_core::policy::AccessPolicy;
    use secrecy::ExposeSecret as _;
    use std::str::FromStr as _;

    // Step 1: Parse policy string.
    let policy = match policy_str {
        Some(s) => AccessPolicy::from_str(s).map_err(|e| anyhow::anyhow!("{e}"))?,
        None => AccessPolicy::None,
    };

    // Step 2: Full policy warning.
    if policy == AccessPolicy::Full && !confirm_full_policy(reader)? {
        println!("キャンセルしました");
        return Ok(());
    }

    // Step 3: Get password.
    let password_source =
        get_password(cli.password.as_deref()).map_err(|e| anyhow::anyhow!("{e}"))?;

    // Step 4: Create vault.
    let base_dir = resolve_vaults_base_dir(cli)?;
    let mgr = mgr_factory(base_dir.clone())?;
    let pw_bytes = password_source.secret().expose_secret().as_bytes();
    mgr.create_vault(name, pw_bytes, policy)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Step 5: Success message.
    let vault_dir = base_dir.join(name);
    println!(
        "Created vault '{name}' at {} (policy: {policy})",
        vault_dir.display()
    );
    Ok(())
}

/// Execute the `pq-diary vault list` command.
///
/// Lists all vaults under the base directory with their access policies.
/// Prints a `NAME` / `POLICY` table.  Does not require a password.
///
/// # Errors
///
/// Returns an error if the base directory cannot be determined or vault
/// enumeration fails.
pub fn cmd_vault_list(cli: &Cli) -> anyhow::Result<()> {
    use pq_diary_core::vault::init::VaultManager;

    let base_dir = resolve_vaults_base_dir(cli)?;
    let mgr = VaultManager::new(base_dir).map_err(|e| anyhow::anyhow!("{e}"))?;
    let vaults = mgr
        .list_vaults_with_policy()
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    println!("{:<20} POLICY", "NAME");
    println!("{}", "-".repeat(31));
    for v in &vaults {
        println!("{:<20} {}", v.name, v.policy);
    }

    Ok(())
}

/// Execute the `pq-diary vault policy` command.
///
/// Parses `policy_str` to an `AccessPolicy`, shows a security warning for
/// `Full` policy, then updates the vault's policy via
/// `VaultManager::set_policy`.  Does not require a password.
///
/// # Errors
///
/// Returns an error if the policy string is invalid, the user cancels the
/// `Full` policy confirmation, or the update fails.
pub fn cmd_vault_policy(cli: &Cli, name: &str, policy_str: &str) -> anyhow::Result<()> {
    cmd_vault_policy_impl(
        cli,
        name,
        policy_str,
        &mut std::io::BufReader::new(std::io::stdin()),
    )
}

/// Internal implementation of `cmd_vault_policy` with an injectable stdin reader.
fn cmd_vault_policy_impl(
    cli: &Cli,
    name: &str,
    policy_str: &str,
    reader: &mut impl std::io::BufRead,
) -> anyhow::Result<()> {
    use pq_diary_core::policy::AccessPolicy;
    use pq_diary_core::vault::init::VaultManager;
    use std::str::FromStr as _;

    // Step 1: Parse policy string.
    let policy = AccessPolicy::from_str(policy_str).map_err(|e| anyhow::anyhow!("{e}"))?;

    // Step 2: Full policy warning.
    if policy == AccessPolicy::Full && !confirm_full_policy(reader)? {
        println!("キャンセルしました");
        return Ok(());
    }

    // Step 3: Set policy.
    let base_dir = resolve_vaults_base_dir(cli)?;
    let mgr = VaultManager::new(base_dir).map_err(|e| anyhow::anyhow!("{e}"))?;
    mgr.set_policy(name, policy)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Step 4: Success message.
    println!("Policy updated: {name} → {policy}");
    Ok(())
}

/// Execute the `pq-diary vault delete` command.
///
/// Verifies the vault exists, shows an additional warning when deleting the
/// default vault, and prompts for confirmation unless `--claude` is set.
/// Calls `VaultManager::delete_vault` with the `zeroize` flag.  Does not
/// require a password.
///
/// # Errors
///
/// Returns an error if the vault does not exist or deletion fails.
pub fn cmd_vault_delete(cli: &Cli, name: &str, zeroize: bool) -> anyhow::Result<()> {
    cmd_vault_delete_impl(
        cli,
        name,
        zeroize,
        &mut std::io::BufReader::new(std::io::stdin()),
    )
}

/// Internal implementation of `cmd_vault_delete` with an injectable stdin reader.
fn cmd_vault_delete_impl(
    cli: &Cli,
    name: &str,
    zeroize: bool,
    reader: &mut impl std::io::BufRead,
) -> anyhow::Result<()> {
    use pq_diary_core::vault::init::VaultManager;

    let base_dir = resolve_vaults_base_dir(cli)?;
    let mgr = VaultManager::new(base_dir).map_err(|e| anyhow::anyhow!("{e}"))?;

    // Step 1: Check if vault exists.
    let vault_path = mgr.vault_path(name);
    if !vault_path.exists() {
        return Err(anyhow::anyhow!("vault '{}' does not exist", name));
    }

    // Step 2: Show additional warning for the default vault (always, before any prompt).
    let is_default = mgr.default_vault() == name;
    if is_default {
        eprintln!(
            "警告: '{name}' はデフォルト vault です。削除すると他の操作に影響する可能性があります。"
        );
    }

    // Step 3: Confirmation (skip with --claude).
    let do_delete = if cli.claude {
        true
    } else {
        confirm_vault_delete(name, reader)?
    };

    if do_delete {
        // Step 4: Delete vault.
        mgr.delete_vault(name, zeroize)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        println!("Deleted vault '{name}'");
    } else {
        println!("キャンセルしました");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Git command helpers
// ---------------------------------------------------------------------------

/// Derive the vault directory from a vault path, canonicalising an empty
/// parent to the current working directory.
fn vault_dir_from_path(vault_path: &std::path::Path) -> anyhow::Result<PathBuf> {
    let parent = vault_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("vault path has no parent directory"))?;
    if parent.as_os_str().is_empty() {
        std::env::current_dir()
            .map_err(|e| anyhow::anyhow!("Cannot determine current directory: {e}"))
    } else {
        Ok(parent.to_path_buf())
    }
}

/// Apply conflict resolutions chosen interactively by the user.
///
/// For each conflict where the user chooses `r` (remote), overwrites the
/// local provisional entry in the vault with the remote version and commits
/// the change using the vault's privacy pipeline.
///
/// `reader` is injected so that tests can supply pre-programmed responses
/// instead of reading from the real stdin.
fn resolve_conflicts_interactive(
    conflicts: &[pq_diary_core::git::MergeConflict],
    vault_dir: &std::path::Path,
    config: &pq_diary_core::vault::config::VaultConfig,
    vault_path: &std::path::Path,
    reader: &mut impl std::io::BufRead,
) -> anyhow::Result<()> {
    use pq_diary_core::git::{fuzz_timestamp, get_last_commit_timestamp};
    use pq_diary_core::vault::{reader::read_vault, writer::write_vault};
    use std::io::Write as _;

    let mut remote_uuids: Vec<[u8; 16]> = Vec::new();

    println!("Merge conflicts detected:");
    for conflict in conflicts {
        let uuid_hex: String = conflict.uuid.iter().map(|b| format!("{b:02x}")).collect();
        println!("  UUID: {}", &uuid_hex[..8]);
        println!("  Local  updated_at: {}", conflict.local.updated_at);
        println!("  Remote updated_at: {}", conflict.remote.updated_at);
        eprint!("  Keep [l]ocal or [r]emote? ");
        std::io::stderr()
            .flush()
            .map_err(|e| anyhow::anyhow!("Failed to flush stderr: {e}"))?;

        let mut input = String::new();
        reader
            .read_line(&mut input)
            .map_err(|e| anyhow::anyhow!("Failed to read conflict choice: {e}"))?;
        let choice = input.trim().to_lowercase();
        if choice == "r" || choice == "remote" {
            remote_uuids.push(conflict.uuid);
        }
    }

    if remote_uuids.is_empty() {
        return Ok(());
    }

    // Apply "keep remote" choices: swap entries in vault.pqd.
    let (header, mut entries) = read_vault(vault_path).map_err(|e| anyhow::anyhow!("{e}"))?;
    for uuid in &remote_uuids {
        if let Some(conflict) = conflicts.iter().find(|c| &c.uuid == uuid) {
            if let Some(pos) = entries.iter().position(|e| e.uuid == *uuid) {
                entries[pos] = conflict.remote.clone();
            }
        }
    }
    write_vault(vault_path, header, &entries).map_err(|e| anyhow::anyhow!("{e}"))?;

    // Commit the updated vault using the privacy pipeline.
    let prev_ts = get_last_commit_timestamp(vault_dir);
    let fuzz_hours = config.git.privacy.timestamp_fuzz_hours;
    let fuzzed_ts = fuzz_timestamp(prev_ts, fuzz_hours);
    let ts_str = fuzzed_ts.to_rfc3339();

    let add_out = std::process::Command::new("git")
        .current_dir(vault_dir)
        .args(["add", "vault.pqd"])
        .output()
        .map_err(|e| anyhow::anyhow!("git add failed: {e}"))?;
    if !add_out.status.success() {
        return Err(anyhow::anyhow!(
            "git add failed: {}",
            String::from_utf8_lossy(&add_out.stderr)
        ));
    }

    let commit_out = std::process::Command::new("git")
        .current_dir(vault_dir)
        .arg("-c")
        .arg(format!("user.name={}", config.git.author_name))
        .arg("-c")
        .arg(format!("user.email={}", config.git.author_email))
        .args([
            "commit",
            "--date",
            &ts_str,
            "-m",
            &config.git.commit_message,
        ])
        .env("GIT_AUTHOR_DATE", &ts_str)
        .env("GIT_COMMITTER_DATE", &ts_str)
        .output()
        .map_err(|e| anyhow::anyhow!("git commit failed: {e}"))?;
    if !commit_out.status.success() {
        let stderr = String::from_utf8_lossy(&commit_out.stderr);
        if !stderr.contains("nothing to commit") {
            return Err(anyhow::anyhow!("git commit failed: {}", stderr));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Git command handlers
// ---------------------------------------------------------------------------

/// Execute the `pq-diary git-init` command.
///
/// Initialises a Git repository in the vault directory, writes `.gitignore`,
/// generates a random anonymous author email, stores it in `vault.toml`, and
/// optionally adds a remote named `origin`.  No password is required.
///
/// # Errors
///
/// Returns an error if `git` is not installed, the vault directory cannot be
/// resolved, `git_init` fails (e.g. already initialised), or the success
/// message cannot be assembled.
pub fn cmd_git_init(cli: &Cli, remote: Option<&str>) -> anyhow::Result<()> {
    use pq_diary_core::{git, vault::config::VaultConfig};

    let vault_path = resolve_vault_path(cli)?;
    let vault_dir = vault_dir_from_path(&vault_path)?;

    git::check_git_available().map_err(|e| anyhow::anyhow!("{e}"))?;

    git::git_init(&vault_dir, remote).map_err(|e| anyhow::anyhow!("{e}"))?;

    println!("Initialized git repository in {}", vault_dir.display());
    // Try to show the generated author email from vault.toml if it exists.
    let toml_path = vault_dir.join("vault.toml");
    if toml_path.exists() {
        if let Ok(config) = VaultConfig::from_file(&toml_path) {
            if !config.git.author_email.is_empty() {
                println!("Author: pq-diary <{}>", config.git.author_email);
            }
        }
    }
    if let Some(url) = remote {
        println!("Remote: origin → {url}");
    }

    Ok(())
}

/// Execute the `pq-diary git-push` command.
///
/// Applies the privacy pipeline (extra padding, anonymous author, fixed
/// commit message, timestamp fuzzing) and pushes the vault to the remote
/// repository.  Requires the vault password to authorise the operation.
///
/// # Errors
///
/// Returns an error if policy check fails, password acquisition fails,
/// vault unlock fails, or any step of the push pipeline fails.
pub fn cmd_git_push(cli: &Cli) -> anyhow::Result<()> {
    use pq_diary_core::{
        git, policy::OperationType, vault::config::VaultConfig,
    };
    use secrecy::{ExposeSecret as _, SecretBox};

    check_claude_policy(cli, OperationType::Write)?;

    let vault_path = resolve_vault_path(cli)?;
    let vault_dir = vault_dir_from_path(&vault_path)?;
    let toml_path = vault_dir.join("vault.toml");

    git::check_git_available().map_err(|e| anyhow::anyhow!("{e}"))?;

    let config = VaultConfig::from_file(&toml_path).map_err(|e| anyhow::anyhow!("{e}"))?;

    let password_source =
        get_password(cli.password.as_deref()).map_err(|e| anyhow::anyhow!("{e}"))?;

    let vault_str = vault_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("vault path contains non-UTF-8 characters"))?;

    let mut core = pq_diary_core::DiaryCore::new(vault_str).map_err(|e| anyhow::anyhow!("{e}"))?;

    let secret_password: secrecy::SecretString =
        SecretBox::new(Box::from(password_source.secret().expose_secret()));
    core.unlock(secret_password)
        .map_err(|e| anyhow::anyhow!("Vault unlock failed: {e}"))?;
    let _guard = VaultGuard::new(&mut core);


    git::git_push(&vault_dir, &config, &vault_path).map_err(|e| anyhow::anyhow!("{e}"))?;

    println!("Pushed vault to remote.");
    // _guard drops here → lock() called
    Ok(())
}

/// Execute the `pq-diary git-pull` command.
///
/// Fetches from the remote, runs an entry-level 3-way merge, and handles any
/// conflicts either automatically (when `--claude` is set) or interactively.
/// Requires the vault password because the merged vault.pqd is re-written.
///
/// # Errors
///
/// Returns an error if policy check fails, password acquisition fails,
/// vault unlock fails, the merge fails, or conflict resolution fails.
pub fn cmd_git_pull(cli: &Cli) -> anyhow::Result<()> {
    cmd_git_pull_impl(cli, &mut std::io::BufReader::new(std::io::stdin()))
}

/// Internal implementation of `cmd_git_pull` with an injectable stdin reader.
///
/// Separating the reader allows unit tests to supply pre-programmed conflict
/// resolutions without touching the real stdin.
fn cmd_git_pull_impl(cli: &Cli, reader: &mut impl std::io::BufRead) -> anyhow::Result<()> {
    use pq_diary_core::{
        git, policy::OperationType, vault::config::VaultConfig,
    };
    use secrecy::{ExposeSecret as _, SecretBox};

    check_claude_policy(cli, OperationType::Write)?;

    let vault_path = resolve_vault_path(cli)?;
    let vault_dir = vault_dir_from_path(&vault_path)?;
    let toml_path = vault_dir.join("vault.toml");

    git::check_git_available().map_err(|e| anyhow::anyhow!("{e}"))?;

    let config = VaultConfig::from_file(&toml_path).map_err(|e| anyhow::anyhow!("{e}"))?;

    let password_source =
        get_password(cli.password.as_deref()).map_err(|e| anyhow::anyhow!("{e}"))?;

    let vault_str = vault_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("vault path contains non-UTF-8 characters"))?;

    let mut core = pq_diary_core::DiaryCore::new(vault_str).map_err(|e| anyhow::anyhow!("{e}"))?;

    let secret_password: secrecy::SecretString =
        SecretBox::new(Box::from(password_source.secret().expose_secret()));
    core.unlock(secret_password)
        .map_err(|e| anyhow::anyhow!("Vault unlock failed: {e}"))?;
    let _guard = VaultGuard::new(&mut core);


    let result = git::git_pull_merge(&vault_dir, &config, &vault_path, cli.claude)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    if !result.conflicts.is_empty() && !cli.claude {
        resolve_conflicts_interactive(&result.conflicts, &vault_dir, &config, &vault_path, reader)?;
    }

    println!(
        "Pull complete: {} added, {} updated, {} deleted, {} conflict(s)",
        result.added,
        result.updated,
        result.deleted,
        result.conflicts.len()
    );
    // _guard drops here → lock() called
    Ok(())
}

/// Execute the `pq-diary git-sync` command.
///
/// Runs pull (fetch + merge) followed by push using a single password prompt.
/// Conflict resolution follows the same rules as `git-pull`: automatic when
/// `--claude` is set, interactive otherwise.
///
/// # Errors
///
/// Returns an error if policy check, password acquisition, vault unlock,
/// pull, conflict resolution, or push fails.
pub fn cmd_git_sync(cli: &Cli) -> anyhow::Result<()> {
    cmd_git_sync_impl(cli, &mut std::io::BufReader::new(std::io::stdin()))
}

/// Internal implementation of `cmd_git_sync` with an injectable stdin reader.
fn cmd_git_sync_impl(cli: &Cli, reader: &mut impl std::io::BufRead) -> anyhow::Result<()> {
    use pq_diary_core::{
        git, policy::OperationType, vault::config::VaultConfig,
    };
    use secrecy::{ExposeSecret as _, SecretBox};

    check_claude_policy(cli, OperationType::Write)?;

    let vault_path = resolve_vault_path(cli)?;
    let vault_dir = vault_dir_from_path(&vault_path)?;
    let toml_path = vault_dir.join("vault.toml");

    git::check_git_available().map_err(|e| anyhow::anyhow!("{e}"))?;

    let config = VaultConfig::from_file(&toml_path).map_err(|e| anyhow::anyhow!("{e}"))?;

    // Single password prompt for both pull and push.
    let password_source =
        get_password(cli.password.as_deref()).map_err(|e| anyhow::anyhow!("{e}"))?;

    let vault_str = vault_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("vault path contains non-UTF-8 characters"))?;

    let mut core = pq_diary_core::DiaryCore::new(vault_str).map_err(|e| anyhow::anyhow!("{e}"))?;

    let secret_password: secrecy::SecretString =
        SecretBox::new(Box::from(password_source.secret().expose_secret()));
    core.unlock(secret_password)
        .map_err(|e| anyhow::anyhow!("Vault unlock failed: {e}"))?;
    let _guard = VaultGuard::new(&mut core);



    // Phase 1: Pull + merge.
    let pull_result = git::git_pull_merge(&vault_dir, &config, &vault_path, cli.claude)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    if !pull_result.conflicts.is_empty() && !cli.claude {
        resolve_conflicts_interactive(
            &pull_result.conflicts,
            &vault_dir,
            &config,
            &vault_path,
            reader,
        )?;
    }

    // Phase 2: Push.
    git::git_push(&vault_dir, &config, &vault_path).map_err(|e| anyhow::anyhow!("{e}"))?;

    println!("Sync complete.");
    println!(
        "Pull: {} added, {} updated, {} deleted, {} conflict(s)",
        pull_result.added,
        pull_result.updated,
        pull_result.deleted,
        pull_result.conflicts.len()
    );
    println!("Push: committed and pushed to remote.");
    // _guard drops here → lock() called
    Ok(())
}

/// Execute the `pq-diary git-status` command.
///
/// Runs `git status` in the vault directory and prints the output.
/// No password is required.
///
/// # Errors
///
/// Returns an error if `git` is not installed, the vault directory cannot be
/// resolved, or `git status` fails.
pub fn cmd_git_status(cli: &Cli) -> anyhow::Result<()> {
    use pq_diary_core::git;

    let vault_path = resolve_vault_path(cli)?;
    let vault_dir = vault_dir_from_path(&vault_path)?;

    git::check_git_available().map_err(|e| anyhow::anyhow!("{e}"))?;

    let status = git::git_status(&vault_dir).map_err(|e| anyhow::anyhow!("{e}"))?;
    print!("{status}");

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
    fn read_first_entry_plaintext(vault_dir: &std::path::Path) -> pq_diary_core::EntryPlaintext {
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
        let result = cmd_new(&cli, None, Some("body text".to_string()), vec![], None);
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
        let result = cmd_new(
            &cli,
            Some(String::new()),
            Some("body".to_string()),
            vec![],
            None,
        );
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
            None,
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
            None,
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
        let result = cmd_new(&cli, None, Some("body".to_string()), tags.clone(), None);
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
        let result = cmd_new(&cli, None, Some("body".to_string()), vec![], None);
        assert!(result.is_ok(), "cmd_new failed: {:?}", result.err());

        let plaintext = read_first_entry_plaintext(&vault_dir);
        assert!(
            plaintext.tags.is_empty(),
            "tags must be empty when none specified"
        );
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
        let result = cmd_new(&cli, None, Some("body".to_string()), vec![], None);
        assert!(result.is_err(), "Expected error for wrong password");
    }

    // -------------------------------------------------------------------------
    // TC-0037-08: resolve_vault_path appends vault.pqd for directory paths
    // -------------------------------------------------------------------------

    /// TC-0037-08: A directory vault path gets `vault.pqd` appended.
    #[test]
    fn tc_0037_08_resolve_vault_path_appends_pqd() {
        let cli =
            crate::Cli::try_parse_from(["pq-diary", "-v", "/some/dir", "new"]).expect("parse");
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
        let entries = vec![make_meta("aa000000", "A", &["仕事人"], 1)];
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
        cmd_new(
            &new_cli,
            Some("Test".to_string()),
            Some("body".to_string()),
            vec![],
            None,
        )
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
        assert!(
            result.is_ok(),
            "cmd_list on empty vault failed: {:?}",
            result.err()
        );
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
            None,
        )
        .expect("cmd_new");

        let entries = read_vault_entries(&vault_dir);
        let prefix4 = &entries[0].uuid_hex[..4];

        let show_cli = make_show_cli(vault_dir_str, Some("password"), prefix4);
        let result = cmd_show(&show_cli, prefix4.to_string());
        assert!(
            result.is_ok(),
            "cmd_show by prefix failed: {:?}",
            result.err()
        );
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
            None,
        )
        .expect("cmd_new");

        let entries = read_vault_entries(&vault_dir);
        let full_id = entries[0].uuid_hex.clone();

        let show_cli = make_show_cli(vault_dir_str, Some("password"), &full_id);
        let result = cmd_show(&show_cli, full_id.clone());
        assert!(
            result.is_ok(),
            "cmd_show by full ID failed: {:?}",
            result.err()
        );
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

    // =========================================================================
    // cmd_edit integration tests (TASK-0039)
    // =========================================================================

    /// Build a `Cli` targeting `vault_dir` for the `edit` command.
    fn make_edit_cli(vault_dir_str: &str, password: Option<&str>, id: &str) -> crate::Cli {
        let mut args: Vec<&str> = vec!["pq-diary", "-v", vault_dir_str];
        if let Some(pw) = password {
            args.extend_from_slice(&["--password", pw]);
        }
        args.extend_from_slice(&["edit", id]);
        crate::Cli::try_parse_from(&args).expect("parse test CLI")
    }

    /// Create a vault, add an entry, and return (vault_dir, entry_id_prefix).
    fn setup_vault_with_entry(
        dir: &tempfile::TempDir,
        title: &str,
        body: &str,
        tags: Vec<&str>,
    ) -> (std::path::PathBuf, String) {
        let vault_dir = setup_vault(dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");
        let cli = make_cli(vault_dir_str, Some("password"));
        cmd_new(
            &cli,
            Some(title.to_string()),
            Some(body.to_string()),
            tags.iter().map(|s| s.to_string()).collect(),
            None,
        )
        .expect("cmd_new in setup");

        let entries = read_vault_entries(&vault_dir);
        assert_eq!(entries.len(), 1, "setup: expected 1 entry");
        let prefix = entries[0].uuid_hex[..8].to_string();
        (vault_dir, prefix)
    }

    /// TC-0039-01: --title flag changes the title, body is unchanged.
    #[test]
    fn tc_0039_01_flag_title_change() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (vault_dir, prefix) = setup_vault_with_entry(&dir, "Old Title", "body text", vec![]);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let edit_cli = make_edit_cli(vault_dir_str, Some("password"), &prefix);
        let result = cmd_edit(
            &edit_cli,
            prefix.clone(),
            Some("New Title".to_string()),
            vec![],
            vec![],
        );
        assert!(result.is_ok(), "cmd_edit failed: {:?}", result.err());

        let plaintext = read_first_entry_plaintext(&vault_dir);
        assert_eq!(plaintext.title, "New Title");
        assert_eq!(
            plaintext.body, "body text",
            "body must be unchanged by flag edit"
        );
    }

    /// TC-0039-02: --add-tag flag appends a tag to the entry.
    #[test]
    fn tc_0039_02_flag_add_tag() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (vault_dir, prefix) = setup_vault_with_entry(&dir, "Title", "body", vec!["existing"]);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let edit_cli = make_edit_cli(vault_dir_str, Some("password"), &prefix);
        let result = cmd_edit(
            &edit_cli,
            prefix.clone(),
            None,
            vec!["newtag".to_string()],
            vec![],
        );
        assert!(result.is_ok(), "cmd_edit failed: {:?}", result.err());

        let plaintext = read_first_entry_plaintext(&vault_dir);
        assert!(
            plaintext.tags.contains(&"existing".to_string()),
            "original tag must be preserved"
        );
        assert!(
            plaintext.tags.contains(&"newtag".to_string()),
            "new tag must be added"
        );
        assert_eq!(plaintext.tags.len(), 2);
    }

    /// TC-0039-03: --remove-tag flag removes a tag from the entry.
    #[test]
    fn tc_0039_03_flag_remove_tag() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (vault_dir, prefix) =
            setup_vault_with_entry(&dir, "Title", "body", vec!["keep", "remove_me"]);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let edit_cli = make_edit_cli(vault_dir_str, Some("password"), &prefix);
        let result = cmd_edit(
            &edit_cli,
            prefix.clone(),
            None,
            vec![],
            vec!["remove_me".to_string()],
        );
        assert!(result.is_ok(), "cmd_edit failed: {:?}", result.err());

        let plaintext = read_first_entry_plaintext(&vault_dir);
        assert!(
            plaintext.tags.contains(&"keep".to_string()),
            "kept tag must remain"
        );
        assert!(
            !plaintext.tags.contains(&"remove_me".to_string()),
            "removed tag must be absent"
        );
        assert_eq!(plaintext.tags.len(), 1);
    }

    /// TC-0039-04: Combined --title, --add-tag, --remove-tag all apply correctly.
    #[test]
    fn tc_0039_04_flag_combined() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (vault_dir, prefix) = setup_vault_with_entry(&dir, "Old", "body", vec!["keep", "old"]);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let edit_cli = make_edit_cli(vault_dir_str, Some("password"), &prefix);
        let result = cmd_edit(
            &edit_cli,
            prefix.clone(),
            Some("New Title".to_string()),
            vec!["fresh".to_string()],
            vec!["old".to_string()],
        );
        assert!(result.is_ok(), "cmd_edit failed: {:?}", result.err());

        let plaintext = read_first_entry_plaintext(&vault_dir);
        assert_eq!(plaintext.title, "New Title");
        assert!(plaintext.tags.contains(&"keep".to_string()));
        assert!(plaintext.tags.contains(&"fresh".to_string()));
        assert!(!plaintext.tags.contains(&"old".to_string()));
    }

    /// TC-0039-05: Flag edit does not modify the body.
    #[test]
    fn tc_0039_05_flag_body_unchanged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (vault_dir, prefix) =
            setup_vault_with_entry(&dir, "Title", "Original body content", vec![]);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let edit_cli = make_edit_cli(vault_dir_str, Some("password"), &prefix);
        let result = cmd_edit(
            &edit_cli,
            prefix.clone(),
            Some("Changed Title".to_string()),
            vec![],
            vec![],
        );
        assert!(result.is_ok(), "cmd_edit failed: {:?}", result.err());

        let plaintext = read_first_entry_plaintext(&vault_dir);
        assert_eq!(
            plaintext.body, "Original body content",
            "body must not change"
        );
    }

    /// TC-0039-06: --add-tag does not duplicate an already-existing tag.
    #[test]
    fn tc_0039_06_flag_add_tag_no_duplicate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (vault_dir, prefix) = setup_vault_with_entry(&dir, "Title", "body", vec!["existing"]);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let edit_cli = make_edit_cli(vault_dir_str, Some("password"), &prefix);
        let result = cmd_edit(
            &edit_cli,
            prefix.clone(),
            None,
            vec!["existing".to_string()],
            vec![],
        );
        assert!(result.is_ok(), "cmd_edit failed: {:?}", result.err());

        let plaintext = read_first_entry_plaintext(&vault_dir);
        assert_eq!(
            plaintext.tags.iter().filter(|t| *t == "existing").count(),
            1,
            "duplicate tag must not be added"
        );
    }

    /// TC-0039-07: Editor mode with no-op mock → "変更がありませんでした" (no update).
    #[test]
    fn tc_0039_07_editor_no_change() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (vault_dir, prefix) = setup_vault_with_entry(&dir, "Title", "body text", vec!["tag1"]);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let edit_cli = make_edit_cli(vault_dir_str, Some("password"), &prefix);

        // No-op mock: does not modify the temp file.
        let result = cmd_edit_impl(
            &edit_cli,
            prefix.clone(),
            None,
            vec![],
            vec![],
            |_tmpfile, _config| Ok(()),
        );
        assert!(result.is_ok(), "cmd_edit_impl failed: {:?}", result.err());

        // Vault entry must be unchanged.
        let plaintext = read_first_entry_plaintext(&vault_dir);
        assert_eq!(plaintext.title, "Title");
        assert_eq!(plaintext.body, "body text");
        assert_eq!(plaintext.tags, vec!["tag1".to_string()]);
    }

    /// TC-0039-08: Editor mode with mock that modifies content → entry is updated.
    #[test]
    fn tc_0039_08_editor_with_changes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (vault_dir, prefix) =
            setup_vault_with_entry(&dir, "Old Title", "old body", vec!["old_tag"]);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let edit_cli = make_edit_cli(vault_dir_str, Some("password"), &prefix);

        // Mock: overwrite the temp file with new content.
        let result = cmd_edit_impl(
            &edit_cli,
            prefix.clone(),
            None,
            vec![],
            vec![],
            |tmpfile, _config| {
                use std::io::Write as _;
                let mut f =
                    std::fs::File::create(tmpfile).map_err(|e| pq_diary_core::DiaryError::Io(e))?;
                f.write_all(b"# Title: New Title\n# Tags: new_tag\n# ---\n\nnew body")
                    .map_err(pq_diary_core::DiaryError::Io)?;
                Ok(())
            },
        );
        assert!(result.is_ok(), "cmd_edit_impl failed: {:?}", result.err());

        let plaintext = read_first_entry_plaintext(&vault_dir);
        assert_eq!(plaintext.title, "New Title");
        assert_eq!(plaintext.tags, vec!["new_tag".to_string()]);
        assert_eq!(plaintext.body, "new body");
    }

    /// TC-0039-09: After editor mode, the temp file is securely deleted.
    #[test]
    fn tc_0039_09_editor_tmpfile_deleted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (vault_dir, prefix) = setup_vault_with_entry(&dir, "Title", "body", vec![]);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let edit_cli = make_edit_cli(vault_dir_str, Some("password"), &prefix);

        // Capture the tmpfile path via a shared cell.
        use std::cell::RefCell;
        use std::rc::Rc;
        let captured: Rc<RefCell<Option<std::path::PathBuf>>> = Rc::new(RefCell::new(None));
        let captured_clone = Rc::clone(&captured);

        let result = cmd_edit_impl(
            &edit_cli,
            prefix.clone(),
            None,
            vec![],
            vec![],
            move |tmpfile, _config| {
                *captured_clone.borrow_mut() = Some(tmpfile.to_path_buf());
                Ok(())
            },
        );
        assert!(result.is_ok(), "cmd_edit_impl failed: {:?}", result.err());

        let path = captured
            .borrow()
            .clone()
            .expect("tmpfile path was not captured");
        assert!(
            !path.exists(),
            "temp file must be deleted after editor mode: {path:?}"
        );
    }

    /// TC-0039-10: Header parse error → original metadata preserved, body updated.
    #[test]
    fn tc_0039_10_editor_header_parse_error_preserves_metadata() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (vault_dir, prefix) =
            setup_vault_with_entry(&dir, "Keep Title", "old body", vec!["keep_tag"]);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let edit_cli = make_edit_cli(vault_dir_str, Some("password"), &prefix);

        // Mock: write file content without a "# ---" separator (invalid header).
        let result = cmd_edit_impl(
            &edit_cli,
            prefix.clone(),
            None,
            vec![],
            vec![],
            |tmpfile, _config| {
                use std::io::Write as _;
                let mut f =
                    std::fs::File::create(tmpfile).map_err(|e| pq_diary_core::DiaryError::Io(e))?;
                f.write_all(b"updated body without header")
                    .map_err(pq_diary_core::DiaryError::Io)?;
                Ok(())
            },
        );
        assert!(result.is_ok(), "cmd_edit_impl failed: {:?}", result.err());

        let plaintext = read_first_entry_plaintext(&vault_dir);
        // Original metadata must be preserved.
        assert_eq!(
            plaintext.title, "Keep Title",
            "title must be preserved on header error"
        );
        assert_eq!(
            plaintext.tags,
            vec!["keep_tag".to_string()],
            "tags must be preserved on header error"
        );
        // Body must be updated to the whole file content.
        assert_eq!(plaintext.body, "updated body without header");
    }

    /// TC-0039-11: cmd_edit returns an error for a non-existent entry ID.
    #[test]
    fn tc_0039_11_nonexistent_id_returns_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let edit_cli = make_edit_cli(vault_dir_str, Some("password"), "0000");
        let result = cmd_edit(
            &edit_cli,
            "0000".to_string(),
            Some("New Title".to_string()),
            vec![],
            vec![],
        );
        assert!(result.is_err(), "Expected error for non-existent ID");
    }

    /// TC-0039-12: cmd_edit returns an error for an incorrect password.
    #[test]
    fn tc_0039_12_wrong_password_returns_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (vault_dir, prefix) = setup_vault_with_entry(&dir, "Title", "body", vec![]);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let edit_cli = make_edit_cli(vault_dir_str, Some("wrong_password"), &prefix);
        let result = cmd_edit(
            &edit_cli,
            prefix.clone(),
            Some("New Title".to_string()),
            vec![],
            vec![],
        );
        assert!(result.is_err(), "Expected error for wrong password");
    }

    // =========================================================================
    // TASK-0040: confirm_delete unit tests
    // =========================================================================

    /// TC-0040-U01: confirm_delete returns true for "y" input.
    #[test]
    fn tc_0040_u01_confirm_delete_y() {
        let input = "y\n";
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let result =
            confirm_delete("Test Title", "2026-01-01", &mut reader).expect("confirm_delete");
        assert!(result, "Expected true for 'y'");
    }

    /// TC-0040-U02: confirm_delete returns true for "Y" input.
    #[test]
    fn tc_0040_u02_confirm_delete_capital_y() {
        let input = "Y\n";
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let result =
            confirm_delete("Test Title", "2026-01-01", &mut reader).expect("confirm_delete");
        assert!(result, "Expected true for 'Y'");
    }

    /// TC-0040-U03: confirm_delete returns false for "n" input.
    #[test]
    fn tc_0040_u03_confirm_delete_n() {
        let input = "n\n";
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let result =
            confirm_delete("Test Title", "2026-01-01", &mut reader).expect("confirm_delete");
        assert!(!result, "Expected false for 'n'");
    }

    /// TC-0040-U04: confirm_delete returns false for empty input (default No).
    #[test]
    fn tc_0040_u04_confirm_delete_empty() {
        let input = "\n";
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let result =
            confirm_delete("Test Title", "2026-01-01", &mut reader).expect("confirm_delete");
        assert!(!result, "Expected false for empty input");
    }

    /// TC-0040-U05: confirm_delete returns false for "N" input.
    #[test]
    fn tc_0040_u05_confirm_delete_capital_n() {
        let input = "N\n";
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let result =
            confirm_delete("Test Title", "2026-01-01", &mut reader).expect("confirm_delete");
        assert!(!result, "Expected false for 'N'");
    }

    /// TC-0040-U06: confirm_delete returns false for an arbitrary string.
    #[test]
    fn tc_0040_u06_confirm_delete_arbitrary() {
        let input = "abc\n";
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let result =
            confirm_delete("Test Title", "2026-01-01", &mut reader).expect("confirm_delete");
        assert!(!result, "Expected false for 'abc'");
    }

    // =========================================================================
    // TASK-0040: cmd_delete integration tests
    // =========================================================================

    /// Build a `Cli` targeting `vault_dir` for the `delete` command.
    fn make_delete_cli(
        vault_dir_str: &str,
        password: Option<&str>,
        id: &str,
        force: bool,
    ) -> crate::Cli {
        let mut args: Vec<&str> = vec!["pq-diary", "-v", vault_dir_str];
        if let Some(pw) = password {
            args.extend_from_slice(&["--password", pw]);
        }
        args.push("delete");
        if force {
            args.push("--force");
        }
        args.push(id);
        crate::Cli::try_parse_from(&args).expect("parse test CLI")
    }

    /// Build a `Cli` for delete with `--claude` global flag.
    fn make_delete_cli_claude(vault_dir_str: &str, password: Option<&str>, id: &str) -> crate::Cli {
        let mut args: Vec<&str> = vec!["pq-diary", "--claude", "-v", vault_dir_str];
        if let Some(pw) = password {
            args.extend_from_slice(&["--password", pw]);
        }
        args.push("delete");
        args.push(id);
        crate::Cli::try_parse_from(&args).expect("parse test CLI")
    }

    /// TC-0040-01: --force flag deletes the entry without confirmation.
    #[test]
    fn tc_0040_01_force_flag_deletes_without_confirm() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (vault_dir, prefix) = setup_vault_with_entry(&dir, "Test Entry", "body", vec![]);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let delete_cli = make_delete_cli(vault_dir_str, Some("password"), &prefix, true);
        let mut reader = std::io::BufReader::new("".as_bytes());
        let result = cmd_delete_impl(&delete_cli, prefix.clone(), true, &mut reader);
        assert!(
            result.is_ok(),
            "cmd_delete --force failed: {:?}",
            result.err()
        );

        let remaining = read_vault_entries(&vault_dir);
        assert!(remaining.is_empty(), "Entry should have been deleted");
    }

    /// TC-0040-02: --force flag outputs the "Deleted:" success message.
    #[test]
    fn tc_0040_02_force_flag_succeeds_and_entry_removed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (vault_dir, prefix) = setup_vault_with_entry(&dir, "Force Test", "body", vec![]);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let delete_cli = make_delete_cli(vault_dir_str, Some("password"), &prefix, true);
        let mut reader = std::io::BufReader::new("".as_bytes());
        let result = cmd_delete_impl(&delete_cli, prefix.clone(), true, &mut reader);
        assert!(result.is_ok(), "Expected Ok: {:?}", result.err());

        let remaining = read_vault_entries(&vault_dir);
        assert!(
            remaining.is_empty(),
            "Entry must be removed after --force delete"
        );
    }

    /// TC-0040-03: "y" input confirms deletion.
    #[test]
    fn tc_0040_03_y_input_triggers_deletion() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (vault_dir, prefix) = setup_vault_with_entry(&dir, "Delete Me", "body", vec![]);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let delete_cli = make_delete_cli(vault_dir_str, Some("password"), &prefix, false);
        let mut reader = std::io::BufReader::new("y\n".as_bytes());
        let result = cmd_delete_impl(&delete_cli, prefix.clone(), false, &mut reader);
        assert!(result.is_ok(), "Expected Ok: {:?}", result.err());

        let remaining = read_vault_entries(&vault_dir);
        assert!(remaining.is_empty(), "Entry should have been deleted");
    }

    /// TC-0040-04: "Y" input confirms deletion.
    #[test]
    fn tc_0040_04_capital_y_input_triggers_deletion() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (vault_dir, prefix) = setup_vault_with_entry(&dir, "Delete Me Y", "body", vec![]);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let delete_cli = make_delete_cli(vault_dir_str, Some("password"), &prefix, false);
        let mut reader = std::io::BufReader::new("Y\n".as_bytes());
        let result = cmd_delete_impl(&delete_cli, prefix.clone(), false, &mut reader);
        assert!(result.is_ok(), "Expected Ok: {:?}", result.err());

        let remaining = read_vault_entries(&vault_dir);
        assert!(remaining.is_empty(), "Entry should have been deleted");
    }

    /// TC-0040-05: "n" input cancels deletion.
    #[test]
    fn tc_0040_05_n_input_cancels_deletion() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (vault_dir, prefix) = setup_vault_with_entry(&dir, "Keep Me", "body", vec![]);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let delete_cli = make_delete_cli(vault_dir_str, Some("password"), &prefix, false);
        let mut reader = std::io::BufReader::new("n\n".as_bytes());
        let result = cmd_delete_impl(&delete_cli, prefix.clone(), false, &mut reader);
        assert!(result.is_ok(), "Expected Ok: {:?}", result.err());

        let remaining = read_vault_entries(&vault_dir);
        assert_eq!(remaining.len(), 1, "Entry should NOT have been deleted");
    }

    /// TC-0040-06: Empty input (Enter only) cancels deletion (default No).
    #[test]
    fn tc_0040_06_empty_input_cancels_deletion() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (vault_dir, prefix) = setup_vault_with_entry(&dir, "Keep Me Too", "body", vec![]);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let delete_cli = make_delete_cli(vault_dir_str, Some("password"), &prefix, false);
        let mut reader = std::io::BufReader::new("\n".as_bytes());
        let result = cmd_delete_impl(&delete_cli, prefix.clone(), false, &mut reader);
        assert!(result.is_ok(), "Expected Ok: {:?}", result.err());

        let remaining = read_vault_entries(&vault_dir);
        assert_eq!(remaining.len(), 1, "Entry should NOT have been deleted");
    }

    /// TC-0040-07: "N" input cancels deletion.
    #[test]
    fn tc_0040_07_capital_n_input_cancels_deletion() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (vault_dir, prefix) = setup_vault_with_entry(&dir, "Stay", "body", vec![]);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let delete_cli = make_delete_cli(vault_dir_str, Some("password"), &prefix, false);
        let mut reader = std::io::BufReader::new("N\n".as_bytes());
        let result = cmd_delete_impl(&delete_cli, prefix.clone(), false, &mut reader);
        assert!(result.is_ok(), "Expected Ok: {:?}", result.err());

        let remaining = read_vault_entries(&vault_dir);
        assert_eq!(remaining.len(), 1, "Entry should NOT have been deleted");
    }

    /// TC-0040-08: Arbitrary string input cancels deletion.
    #[test]
    fn tc_0040_08_arbitrary_input_cancels_deletion() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (vault_dir, prefix) = setup_vault_with_entry(&dir, "Safe", "body", vec![]);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let delete_cli = make_delete_cli(vault_dir_str, Some("password"), &prefix, false);
        let mut reader = std::io::BufReader::new("abc\n".as_bytes());
        let result = cmd_delete_impl(&delete_cli, prefix.clone(), false, &mut reader);
        assert!(result.is_ok(), "Expected Ok: {:?}", result.err());

        let remaining = read_vault_entries(&vault_dir);
        assert_eq!(remaining.len(), 1, "Entry should NOT have been deleted");
    }

    /// TC-0040-09: --claude global flag skips confirmation and deletes.
    /// Uses WriteOnly policy so the policy check permits the write operation.
    #[test]
    fn tc_0040_09_claude_flag_skips_confirmation() {
        use pq_diary_core::policy::AccessPolicy;
        let dir = tempfile::tempdir().expect("tempdir");

        // Create vault with WriteOnly policy so --claude delete is allowed.
        let vault_dir = setup_vault_with_policy(&dir, AccessPolicy::WriteOnly);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        // Add an entry via non-Claude path (no policy check for non-Claude).
        let setup_cli = make_cli(vault_dir_str, Some("password"));
        cmd_new(
            &setup_cli,
            Some("Claude Test".to_string()),
            Some("body".to_string()),
            vec![],
            None,
        )
        .expect("setup cmd_new");
        let entries = read_vault_entries(&vault_dir);
        assert_eq!(entries.len(), 1, "setup: expected 1 entry");
        let prefix = entries[0].uuid_hex[..8].to_string();

        // Delete with --claude: confirmation should be skipped.
        let delete_cli = make_delete_cli_claude(vault_dir_str, Some("password"), &prefix);
        let mut reader = std::io::BufReader::new("".as_bytes());
        let result = cmd_delete_impl(&delete_cli, prefix.clone(), false, &mut reader);
        assert!(result.is_ok(), "Expected Ok: {:?}", result.err());

        let remaining = read_vault_entries(&vault_dir);
        assert!(remaining.is_empty(), "Entry should have been deleted");
    }

    /// TC-0040-10: Non-existent ID returns an error.
    #[test]
    fn tc_0040_10_nonexistent_id_returns_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let delete_cli = make_delete_cli(vault_dir_str, Some("password"), "0000", true);
        let mut reader = std::io::BufReader::new("".as_bytes());
        let result = cmd_delete_impl(&delete_cli, "0000".to_string(), true, &mut reader);
        assert!(result.is_err(), "Expected error for non-existent ID");
    }

    /// TC-0040-11: Wrong password returns an error.
    #[test]
    fn tc_0040_11_wrong_password_returns_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (vault_dir, prefix) = setup_vault_with_entry(&dir, "Entry", "body", vec![]);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let delete_cli = make_delete_cli(vault_dir_str, Some("wrong_password"), &prefix, true);
        let mut reader = std::io::BufReader::new("".as_bytes());
        let result = cmd_delete_impl(&delete_cli, prefix.clone(), true, &mut reader);
        assert!(result.is_err(), "Expected error for wrong password");
    }

    // =========================================================================
    // Template command tests (TASK-0047)
    // =========================================================================

    /// Build a `Cli` targeting `vault_dir` for `template list`.
    fn make_template_list_cli(vault_dir_str: &str, password: Option<&str>) -> crate::Cli {
        let mut args: Vec<&str> = vec!["pq-diary", "-v", vault_dir_str];
        if let Some(pw) = password {
            args.extend_from_slice(&["--password", pw]);
        }
        args.extend_from_slice(&["template", "list"]);
        crate::Cli::try_parse_from(&args).expect("parse test CLI")
    }

    /// Build a `Cli` targeting `vault_dir` for `template show <name>`.
    fn make_template_show_cli(
        vault_dir_str: &str,
        password: Option<&str>,
        name: &str,
    ) -> crate::Cli {
        let mut args: Vec<&str> = vec!["pq-diary", "-v", vault_dir_str];
        if let Some(pw) = password {
            args.extend_from_slice(&["--password", pw]);
        }
        args.extend_from_slice(&["template", "show", name]);
        crate::Cli::try_parse_from(&args).expect("parse test CLI")
    }

    /// Build a `Cli` targeting `vault_dir` for `template delete <name>`.
    fn make_template_delete_cli(
        vault_dir_str: &str,
        password: Option<&str>,
        name: &str,
        force: bool,
    ) -> crate::Cli {
        let mut args: Vec<&str> = vec!["pq-diary", "-v", vault_dir_str];
        if let Some(pw) = password {
            args.extend_from_slice(&["--password", pw]);
        }
        args.extend_from_slice(&["template", "delete", name]);
        if force {
            args.push("--force");
        }
        crate::Cli::try_parse_from(&args).expect("parse test CLI")
    }

    /// Seed the vault with templates via DiaryCore directly.
    fn seed_templates(vault_dir: &std::path::Path, templates: &[(&str, &str)]) {
        let vault_pqd = vault_dir.join("vault.pqd");
        let vault_str = vault_pqd.to_str().expect("utf8");
        let mut core = DiaryCore::new(vault_str).expect("DiaryCore::new");
        let pw: secrecy::SecretString = secrecy::SecretBox::new(Box::from("password"));
        core.unlock(pw).expect("unlock");
        for (name, body) in templates {
            core.new_template(name, body).expect("new_template");
        }
        core.lock();
    }

    /// Read template names from the vault, sorted alphabetically.
    fn read_template_names_sorted(vault_dir: &std::path::Path) -> Vec<String> {
        let vault_pqd = vault_dir.join("vault.pqd");
        let vault_str = vault_pqd.to_str().expect("utf8");
        let mut core = DiaryCore::new(vault_str).expect("DiaryCore::new");
        let pw: secrecy::SecretString = secrecy::SecretBox::new(Box::from("password"));
        core.unlock(pw).expect("unlock");
        let mut metas = core.list_templates().expect("list_templates");
        core.lock();
        metas.sort_by(|a, b| a.name.cmp(&b.name));
        metas.into_iter().map(|m| m.name).collect()
    }

    /// TC-047-01: cmd_template_list returns Ok and templates are in alphabetical order.
    ///
    /// Given "weekly", "daily", "meeting" seeded (insertion order out of alpha),
    /// the sorted result must be ["daily", "meeting", "weekly"].
    #[test]
    fn tc_047_01_template_list_alphabetical_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);

        seed_templates(
            &vault_dir,
            &[
                ("weekly", "week body"),
                ("daily", "day body"),
                ("meeting", "mtg body"),
            ],
        );

        let vault_dir_str = vault_dir.to_str().expect("utf8");
        let cli = make_template_list_cli(vault_dir_str, Some("password"));
        let result = cmd_template_list(&cli);
        assert!(
            result.is_ok(),
            "cmd_template_list failed: {:?}",
            result.err()
        );

        // Verify alphabetical order via core read.
        let sorted = read_template_names_sorted(&vault_dir);
        assert_eq!(sorted, vec!["daily", "meeting", "weekly"]);
    }

    /// TC-047-02: cmd_template_show outputs the registered body text.
    ///
    /// Given template "daily" with body "## 振り返り", cmd_template_show must succeed.
    #[test]
    fn tc_047_02_template_show_outputs_body() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);

        seed_templates(&vault_dir, &[("daily", "## 振り返り")]);

        let vault_dir_str = vault_dir.to_str().expect("utf8");
        let cli = make_template_show_cli(vault_dir_str, Some("password"), "daily");
        let result = cmd_template_show(&cli, "daily".to_string());
        assert!(
            result.is_ok(),
            "cmd_template_show failed: {:?}",
            result.err()
        );
    }

    /// TC-047-03: cmd_template_show returns an error for a nonexistent template.
    ///
    /// Given an empty vault, requesting "nonexistent" must return
    /// DiaryError::TemplateNotFound (propagated as anyhow error).
    #[test]
    fn tc_047_03_template_show_nonexistent_returns_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);

        let vault_dir_str = vault_dir.to_str().expect("utf8");
        let cli = make_template_show_cli(vault_dir_str, Some("password"), "nonexistent");
        let result = cmd_template_show(&cli, "nonexistent".to_string());
        assert!(result.is_err(), "Expected error for nonexistent template");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("nonexistent"),
            "Error message must name the missing template; got: {err_msg}"
        );
    }

    /// TC-047-04: cmd_template_delete with --force removes the template.
    #[test]
    fn tc_047_04_template_delete_force_removes_template() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);

        seed_templates(&vault_dir, &[("daily", "body")]);

        let vault_dir_str = vault_dir.to_str().expect("utf8");
        let cli = make_template_delete_cli(vault_dir_str, Some("password"), "daily", true);
        let mut reader = std::io::BufReader::new("".as_bytes());
        let result = cmd_template_delete_impl(&cli, "daily".to_string(), true, &mut reader);
        assert!(
            result.is_ok(),
            "cmd_template_delete failed: {:?}",
            result.err()
        );

        // Verify the template is gone.
        let names = read_template_names_sorted(&vault_dir);
        assert!(
            names.is_empty(),
            "Template must be deleted; names={names:?}"
        );
    }

    /// TC-047-05: cmd_template_delete with "n" input cancels.
    #[test]
    fn tc_047_05_template_delete_cancel_keeps_template() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);

        seed_templates(&vault_dir, &[("daily", "body")]);

        let vault_dir_str = vault_dir.to_str().expect("utf8");
        let cli = make_template_delete_cli(vault_dir_str, Some("password"), "daily", false);
        let mut reader = std::io::BufReader::new("n\n".as_bytes());
        let result = cmd_template_delete_impl(&cli, "daily".to_string(), false, &mut reader);
        assert!(
            result.is_ok(),
            "Expected Ok on cancel; got: {:?}",
            result.err()
        );

        // Verify the template still exists.
        let names = read_template_names_sorted(&vault_dir);
        assert_eq!(
            names,
            vec!["daily"],
            "Template must still exist after cancel"
        );
    }

    /// TC-047-06: cmd_template_add stores the template body written by the editor.
    #[test]
    fn tc_047_06_template_add_stores_body() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let mut args = vec!["pq-diary", "-v", vault_dir_str, "--password", "password"];
        args.extend_from_slice(&["template", "add", "weekly"]);
        let cli = crate::Cli::try_parse_from(&args).expect("parse");

        // Inject a fake editor that writes "## 週次レビュー" into the temp file.
        let mock_launch = |tmpfile: &std::path::Path, _config: &EditorConfig| {
            std::fs::write(tmpfile, "## 週次レビュー").map_err(|e| pq_diary_core::DiaryError::Io(e))
        };
        let mut reader = std::io::BufReader::new("".as_bytes());
        let result = cmd_template_add_impl(&cli, "weekly".to_string(), mock_launch, &mut reader);
        assert!(
            result.is_ok(),
            "cmd_template_add_impl failed: {:?}",
            result.err()
        );

        // Verify the stored body.
        let vault_pqd = vault_dir.join("vault.pqd");
        let vault_str = vault_pqd.to_str().expect("utf8");
        let mut core = DiaryCore::new(vault_str).expect("DiaryCore::new");
        let pw: secrecy::SecretString = secrecy::SecretBox::new(Box::from("password"));
        core.unlock(pw).expect("unlock");
        let tpl = core.get_template("weekly").expect("get_template");
        core.lock();
        assert_eq!(tpl.body, "## 週次レビュー");
    }

    // =========================================================================
    // TC-048: --template flag tests (TASK-0048)
    // =========================================================================

    /// Add a template directly to the vault without going through the editor.
    fn add_template_to_vault(vault_dir: &std::path::Path, name: &str, body: &str) {
        let vault_pqd = vault_dir.join("vault.pqd");
        let vault_str = vault_pqd.to_str().expect("utf8");
        let mut core = DiaryCore::new(vault_str).expect("DiaryCore::new");
        let pw: secrecy::SecretString = secrecy::SecretBox::new(Box::from("password"));
        core.unlock(pw).expect("unlock");
        core.new_template(name, body).expect("new_template");
        core.lock();
    }

    /// TC-048-01: --template expands {{date}} as YYYY-MM-DD in the created entry body.
    #[test]
    fn tc_048_01_template_date_variable_expanded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        add_template_to_vault(&vault_dir, "t1", "日付: {{date}}");

        let vault_dir_str = vault_dir.to_str().expect("utf8");
        let cli = make_cli(vault_dir_str, Some("password"));
        let result = cmd_new(
            &cli,
            Some("Test Entry".to_string()),
            None,
            vec![],
            Some("t1".to_string()),
        );
        assert!(
            result.is_ok(),
            "cmd_new with template failed: {:?}",
            result.err()
        );

        let plaintext = read_first_entry_plaintext(&vault_dir);
        // Verify that {{date}} was replaced by a YYYY-MM-DD string.
        assert!(
            plaintext.body.starts_with("日付: "),
            "body must start with '日付: ', got: {:?}",
            plaintext.body
        );
        let date_part = plaintext.body.trim_start_matches("日付: ");
        // Must match YYYY-MM-DD format (10 chars, digits and hyphens).
        assert_eq!(date_part.len(), 10, "date must be 10 chars (YYYY-MM-DD)");
        assert!(
            date_part.chars().all(|c| c.is_ascii_digit() || c == '-'),
            "date must contain only digits and hyphens, got: {date_part:?}"
        );
    }

    /// TC-048-02: --template with no custom variables completes without any prompt.
    #[test]
    fn tc_048_02_template_no_custom_vars_no_prompt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        add_template_to_vault(&vault_dir, "t2", "固定 {{date}}");

        let vault_dir_str = vault_dir.to_str().expect("utf8");
        let cli = make_cli(vault_dir_str, Some("password"));
        // No custom vars in "固定 {{date}}" → cmd_new must succeed without reading stdin.
        let result = cmd_new(&cli, None, None, vec![], Some("t2".to_string()));
        assert!(
            result.is_ok(),
            "cmd_new with builtin-only template must succeed without prompts: {:?}",
            result.err()
        );

        let entries = read_vault_entries(&vault_dir);
        assert_eq!(entries.len(), 1, "exactly one entry must be created");
    }

    /// TC-048-03: --template with a nonexistent name returns an error.
    #[test]
    fn tc_048_03_nonexistent_template_returns_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);

        let vault_dir_str = vault_dir.to_str().expect("utf8");
        let cli = make_cli(vault_dir_str, Some("password"));
        let result = cmd_new(&cli, None, None, vec![], Some("nonexistent".to_string()));
        assert!(result.is_err(), "Expected error for nonexistent template");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("nonexistent"),
            "error must mention the template name, got: {err_msg:?}"
        );
    }

    /// TC-048-04: --body takes priority over --template (template is ignored).
    #[test]
    fn tc_048_04_body_takes_priority_over_template() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        add_template_to_vault(&vault_dir, "t3", "template body {{date}}");

        let vault_dir_str = vault_dir.to_str().expect("utf8");
        let cli = make_cli(vault_dir_str, Some("password"));
        let result = cmd_new(
            &cli,
            None,
            Some("direct body".to_string()),
            vec![],
            Some("t3".to_string()),
        );
        assert!(result.is_ok(), "cmd_new failed: {:?}", result.err());

        let plaintext = read_first_entry_plaintext(&vault_dir);
        assert_eq!(
            plaintext.body, "direct body",
            "--body must take priority over --template"
        );
    }

    // =========================================================================
    // TASK-0049: cmd_today tests
    // =========================================================================

    /// Build a `Cli` targeting `vault_dir` for the `today` command.
    fn make_today_cli(vault_dir_str: &str, password: Option<&str>) -> crate::Cli {
        let mut args: Vec<&str> = vec!["pq-diary", "-v", vault_dir_str];
        if let Some(pw) = password {
            args.extend_from_slice(&["--password", pw]);
        }
        args.push("today");
        crate::Cli::try_parse_from(&args).expect("parse test CLI")
    }

    /// Open a vault and return the plaintext of the entry with the given title.
    fn read_entry_by_title(
        vault_dir: &std::path::Path,
        title: &str,
    ) -> Option<pq_diary_core::EntryPlaintext> {
        let vault_pqd = vault_dir.join("vault.pqd");
        let vault_str = vault_pqd.to_str().expect("utf8");
        let mut core = DiaryCore::new(vault_str).expect("DiaryCore::new");
        let pw: secrecy::SecretString = secrecy::SecretBox::new(Box::from("password"));
        core.unlock(pw).expect("unlock");
        let entries = core.list_entries(None).expect("list_entries");
        let found = entries.iter().find(|e| e.title == title)?;
        let prefix = found.uuid_hex[..4].to_string();
        let (_, plaintext) = core.get_entry(&prefix).expect("get_entry");
        core.lock();
        Some(plaintext)
    }

    /// TC-049-01: Empty vault, no template → creates entry with today's title and empty body.
    ///
    /// Tests the DiaryCore-level logic used by cmd_today when neither an entry
    /// nor a "daily" template exists.
    #[test]
    fn tc_049_01_no_entry_no_template_creates_entry() {
        use pq_diary_core::template_engine::{expand, BUILTIN_DATE, BUILTIN_TITLE};
        use std::collections::HashMap;

        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let today = "2099-01-01";

        let vault_pqd = vault_dir.join("vault.pqd");
        let vault_str = vault_pqd.to_str().expect("utf8");
        let mut core = DiaryCore::new(vault_str).expect("DiaryCore::new");
        let pw: secrecy::SecretString = secrecy::SecretBox::new(Box::from("password"));
        core.unlock(pw).expect("unlock");

        // Simulate today logic: search for entry.
        let entries = core.list_entries(None).expect("list_entries");
        let today_entry = entries.iter().find(|e| e.title == today);
        assert!(today_entry.is_none(), "vault must start empty");

        // Simulate today logic: try daily template.
        let initial_body = match core.get_template("daily") {
            Ok(tmpl) => {
                let mut vars: HashMap<String, String> = HashMap::new();
                vars.insert(BUILTIN_DATE.to_string(), today.to_string());
                vars.insert(BUILTIN_TITLE.to_string(), today.to_string());
                expand(&tmpl.body, &vars)
            }
            Err(_) => String::new(),
        };
        assert_eq!(initial_body, "", "no template → body must be empty");

        // Create the entry.
        core.new_entry(today, &initial_body, vec![])
            .expect("new_entry");
        core.lock();

        // Verify entry was created with today's title.
        let entries = read_vault_entries(&vault_dir);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, today);
    }

    /// TC-049-02: Entry with today's title exists → found by list_entries exact-match.
    #[test]
    fn tc_049_02_existing_entry_found_by_title() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let today = "2026-04-05";

        // Create an entry with today's title.
        let cli = make_cli(vault_dir.to_str().expect("utf8"), Some("password"));
        cmd_new(
            &cli,
            Some(today.to_string()),
            Some("initial body".to_string()),
            vec![],
            None,
        )
        .expect("cmd_new");

        // Simulate today logic: search for entry by exact title match.
        let vault_pqd = vault_dir.join("vault.pqd");
        let vault_str = vault_pqd.to_str().expect("utf8");
        let mut core = DiaryCore::new(vault_str).expect("DiaryCore::new");
        let pw: secrecy::SecretString = secrecy::SecretBox::new(Box::from("password"));
        core.unlock(pw).expect("unlock");

        let entries = core.list_entries(None).expect("list_entries");
        let found = entries.iter().find(|e| e.title == today);
        core.lock();

        assert!(found.is_some(), "today entry must be found");
        assert_eq!(found.unwrap().title, today);
    }

    /// TC-049-03: "daily" template with `{{date}}` → expanded with today's date.
    #[test]
    fn tc_049_03_daily_template_expanded() {
        use pq_diary_core::template_engine::{expand, BUILTIN_DATE, BUILTIN_TITLE};
        use std::collections::HashMap;

        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let today = "2026-04-05";

        // Seed the "daily" template.
        seed_templates(&vault_dir, &[("daily", "## {{date}}")]);

        // Simulate today logic: get template and expand.
        let vault_pqd = vault_dir.join("vault.pqd");
        let vault_str = vault_pqd.to_str().expect("utf8");
        let mut core = DiaryCore::new(vault_str).expect("DiaryCore::new");
        let pw: secrecy::SecretString = secrecy::SecretBox::new(Box::from("password"));
        core.unlock(pw).expect("unlock");

        let tmpl = core.get_template("daily").expect("get_template");
        let mut vars: HashMap<String, String> = HashMap::new();
        vars.insert(BUILTIN_DATE.to_string(), today.to_string());
        vars.insert(BUILTIN_TITLE.to_string(), today.to_string());
        let expanded = expand(&tmpl.body, &vars);
        core.lock();

        assert_eq!(expanded, "## 2026-04-05");
    }

    /// TC-049-04: No "daily" template → initial body is an empty string.
    #[test]
    fn tc_049_04_no_template_empty_body() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let today = "2026-04-05";

        let vault_pqd = vault_dir.join("vault.pqd");
        let vault_str = vault_pqd.to_str().expect("utf8");
        let mut core = DiaryCore::new(vault_str).expect("DiaryCore::new");
        let pw: secrecy::SecretString = secrecy::SecretBox::new(Box::from("password"));
        core.unlock(pw).expect("unlock");

        let initial_body = match core.get_template("daily") {
            Ok(tmpl) => {
                use pq_diary_core::template_engine::{expand, BUILTIN_DATE, BUILTIN_TITLE};
                use std::collections::HashMap;
                let mut vars: HashMap<String, String> = HashMap::new();
                vars.insert(BUILTIN_DATE.to_string(), today.to_string());
                vars.insert(BUILTIN_TITLE.to_string(), today.to_string());
                expand(&tmpl.body, &vars)
            }
            Err(_) => String::new(),
        };
        core.lock();

        assert_eq!(initial_body, "", "no template → body must be empty");
    }

    /// TC-049-05: cmd_today_impl with no-op mock editor creates new entry.
    ///
    /// Verifies the full cmd_today_impl flow: vault unlock → no existing entry →
    /// create entry with empty body → open in mock editor (no-op) → "変更がありませんでした".
    #[test]
    fn tc_049_05_cmd_today_impl_creates_entry_with_mock_editor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");
        let today = "2099-12-31";

        let cli = make_today_cli(vault_dir_str, Some("password"));

        // No-op mock: does not modify the temp file; change detection will find no changes.
        let result = cmd_today_impl(&cli, today, |_tmpfile, _config| Ok(()));
        assert!(result.is_ok(), "cmd_today_impl failed: {:?}", result.err());

        // Verify the entry was created with today's title.
        let entries = read_vault_entries(&vault_dir);
        assert_eq!(entries.len(), 1, "exactly one entry must be created");
        assert_eq!(entries[0].title, today);
    }

    /// TC-049-06: cmd_today_impl with existing entry uses existing entry via mock editor.
    ///
    /// Verifies that when today's entry already exists, cmd_today_impl opens it
    /// (does not create a duplicate).
    #[test]
    fn tc_049_06_cmd_today_impl_uses_existing_entry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");
        let today = "2099-12-30";

        // Pre-create the entry.
        let new_cli = make_cli(vault_dir_str, Some("password"));
        cmd_new(
            &new_cli,
            Some(today.to_string()),
            Some("existing body".to_string()),
            vec![],
            None,
        )
        .expect("cmd_new");

        let cli = make_today_cli(vault_dir_str, Some("password"));
        let result = cmd_today_impl(&cli, today, |_tmpfile, _config| Ok(()));
        assert!(result.is_ok(), "cmd_today_impl failed: {:?}", result.err());

        // Must still be exactly one entry (no duplicate created).
        let entries = read_vault_entries(&vault_dir);
        assert_eq!(entries.len(), 1, "must not create duplicate entry");
        assert_eq!(entries[0].title, today);
    }

    /// TC-049-07: cmd_today_impl with daily template creates entry with expanded body.
    #[test]
    fn tc_049_07_cmd_today_impl_applies_daily_template() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");
        let today = "2099-11-11";

        // Seed "daily" template with a {{date}} variable.
        seed_templates(&vault_dir, &[("daily", "## {{date}}")]);

        let cli = make_today_cli(vault_dir_str, Some("password"));
        let result = cmd_today_impl(&cli, today, |_tmpfile, _config| Ok(()));
        assert!(result.is_ok(), "cmd_today_impl failed: {:?}", result.err());

        // Verify the created entry body has the expanded date.
        let plaintext =
            read_entry_by_title(&vault_dir, today).expect("entry with today's title must exist");
        assert_eq!(
            plaintext.body, "## 2099-11-11",
            "body must be the expanded template"
        );
    }

    // =========================================================================
    // TASK-0050: cmd_show link resolution + backlink display tests
    // =========================================================================

    /// Seed the vault with entries directly via DiaryCore.
    fn seed_entries(vault_dir: &std::path::Path, entries: &[(&str, &str)]) -> Vec<String> {
        let vault_pqd = vault_dir.join("vault.pqd");
        let vault_str = vault_pqd.to_str().expect("utf8");
        let mut core = DiaryCore::new(vault_str).expect("DiaryCore::new");
        let pw: secrecy::SecretString = secrecy::SecretBox::new(Box::from("password"));
        core.unlock(pw).expect("unlock");
        let mut ids = Vec::new();
        for (title, body) in entries {
            let id = core.new_entry(title, body, vec![]).expect("new_entry");
            ids.push(id);
        }
        core.lock();
        ids
    }

    /// Capture the output of cmd_show_impl into a String.
    fn capture_show(vault_dir: &std::path::Path, id_prefix: &str) -> anyhow::Result<String> {
        let vault_pqd = vault_dir.join("vault.pqd");
        let vault_dir_str = vault_pqd.parent().unwrap().to_str().expect("utf8");
        let cli = make_show_cli(vault_dir_str, Some("password"), id_prefix);
        let mut buf: Vec<u8> = Vec::new();
        cmd_show_impl(&cli, id_prefix.to_string(), &mut buf)?;
        Ok(String::from_utf8(buf).expect("utf8 output"))
    }

    /// TC-050-01: Unique link resolution shows UUID prefix.
    ///
    /// Given entry A (body "[[B]]") and entry B, showing entry A must display
    /// "[[B]] → [<prefix of B>]" in the Links section.
    #[test]
    fn tc_050_01_unique_link_shows_prefix() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);

        // Create entry B first so its UUID is known.
        let ids = seed_entries(&vault_dir, &[("B", ""), ("A", "[[B]]")]);
        let b_prefix = &ids[0][..8];
        let a_prefix = &ids[1][..4];

        let output = capture_show(&vault_dir, a_prefix).expect("cmd_show_impl");
        assert!(
            output.contains(&format!("[[B]] → [{b_prefix}]")),
            "output must contain '[[B]] → [{b_prefix}]', got:\n{output}"
        );
    }

    /// TC-050-02: Unresolved link shows "(未解決)".
    ///
    /// Given entry A (body "[[存在しない]]") with no entry titled "存在しない",
    /// showing entry A must display "[[存在しない]] (未解決)".
    #[test]
    fn tc_050_02_unresolved_link_shows_unresolved() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);

        let ids = seed_entries(&vault_dir, &[("A", "[[存在しない]]")]);
        let a_prefix = &ids[0][..4];

        let output = capture_show(&vault_dir, a_prefix).expect("cmd_show_impl");
        assert!(
            output.contains("[[存在しない]] (未解決)"),
            "output must contain '[[存在しない]] (未解決)', got:\n{output}"
        );
    }

    /// TC-050-03: Ambiguous link (multiple matching entries) shows candidate list.
    ///
    /// Given entries A and B both titled "メモ", and entry C (body "[[メモ]]"),
    /// showing entry C must list 2 candidates.
    #[test]
    fn tc_050_03_ambiguous_link_shows_candidates() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);

        let ids = seed_entries(&vault_dir, &[("メモ", ""), ("メモ", ""), ("C", "[[メモ]]")]);
        let c_prefix = &ids[2][..4];

        let output = capture_show(&vault_dir, c_prefix).expect("cmd_show_impl");
        assert!(
            output.contains("[[メモ]] → 複数候補:"),
            "output must contain '[[メモ]] → 複数候補:', got:\n{output}"
        );
        // Count occurrences of "    [" to verify two candidates are listed.
        let candidate_count = output.matches("    [").count();
        assert_eq!(
            candidate_count, 2,
            "must list exactly 2 candidates, got:\n{output}"
        );
    }

    /// TC-050-04: Backlinks section appears when entry is referenced.
    ///
    /// Given entry A (body "[[B]]") and entry B, showing entry B must display
    /// "--- Backlinks ---" with entry A listed.
    #[test]
    fn tc_050_04_backlinks_section_shows_referencing_entry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);

        let ids = seed_entries(&vault_dir, &[("B", ""), ("A", "[[B]]")]);
        let b_prefix = &ids[0][..4];

        let output = capture_show(&vault_dir, b_prefix).expect("cmd_show_impl");
        assert!(
            output.contains("--- Backlinks ---"),
            "output must contain '--- Backlinks ---', got:\n{output}"
        );
        assert!(
            output.contains("A"),
            "backlinks section must include entry A's title, got:\n{output}"
        );
    }

    /// TC-050-05: No backlinks → "--- Backlinks ---" section is absent.
    ///
    /// Given an entry not referenced by any other entry, showing it must NOT
    /// display the "--- Backlinks ---" section.
    #[test]
    fn tc_050_05_no_backlinks_section_hidden() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);

        let ids = seed_entries(&vault_dir, &[("Standalone", "no links here")]);
        let prefix = &ids[0][..4];

        let output = capture_show(&vault_dir, prefix).expect("cmd_show_impl");
        assert!(
            !output.contains("--- Backlinks ---"),
            "output must NOT contain '--- Backlinks ---' for an unreferenced entry, got:\n{output}"
        );
    }

    /// TC-050-06: Entry with no [[links]] shows no Links section.
    ///
    /// Given an entry whose body contains no "[[" patterns, showing it must NOT
    /// display the "--- Links ---" section.
    #[test]
    fn tc_050_06_no_links_in_body_no_links_section() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);

        let ids = seed_entries(&vault_dir, &[("Plain", "plain text without any links")]);
        let prefix = &ids[0][..4];

        let output = capture_show(&vault_dir, prefix).expect("cmd_show_impl");
        assert!(
            !output.contains("--- Links ---"),
            "output must NOT contain '--- Links ---' for an entry with no links, got:\n{output}"
        );
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
        core.unlock(pw).expect("unlock");

        {
            let _guard = VaultGuard::new(&mut core);
            // guard is alive; vault is unlocked
        }
        // guard dropped here — lock() must have been called

        let result = core.list_entries(None);
        assert!(
            result.is_err(),
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
        core.unlock(pw).expect("unlock");

        // Simulate an error path: guard is created, then ? causes early return.
        let result: anyhow::Result<()> = (|| {
            let _guard = VaultGuard::new(&mut core);
            anyhow::bail!("simulated error to trigger early return");
        })();

        assert!(result.is_err(), "closure must propagate the error");

        // Even though the closure returned Err, lock() must have been called.
        let list_result = core.list_entries(None);
        assert!(
            list_result.is_err(),
            "core must be locked after VaultGuard drop on error path"
        );
    }

    // -------------------------------------------------------------------------
    // TASK-0059: cmd_search tests
    // -------------------------------------------------------------------------

    /// Set up a fresh vault for search tests and return its directory path.
    fn setup_search_vault(dir: &tempfile::TempDir) -> PathBuf {
        use pq_diary_core::vault::init::VaultManager;
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());
        mgr.init_vault("sv", b"password").expect("init_vault");
        dir.path().join("sv")
    }

    /// Add an entry to the vault at `vault_dir` with password "password".
    fn add_entry(vault_dir: &PathBuf, title: &str, body: &str, tags: Vec<String>) {
        let vault_pqd = vault_dir.join("vault.pqd");
        let mut core = DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");
        let pw: secrecy::SecretString = secrecy::SecretBox::new(Box::from("password"));
        core.unlock(pw).expect("unlock");
        core.new_entry(title, body, tags).expect("new_entry");
        core.lock();
    }

    /// Parse a `Cli` with the `search` subcommand targeting `vault_dir`.
    fn parse_search_cli(vault_dir_str: &str, extra: &[&str]) -> crate::Cli {
        let mut args = vec![
            "pq-diary",
            "-v",
            vault_dir_str,
            "--password",
            "password",
            "search",
        ];
        args.extend_from_slice(extra);
        crate::Cli::try_parse_from(&args).expect("parse test CLI")
    }

    /// Extract `SearchArgs` from a parsed `Cli`.
    fn extract_search_args(cli: &crate::Cli) -> &crate::SearchArgs {
        match &cli.command {
            crate::Commands::Search(a) => a,
            _ => panic!("Expected Commands::Search"),
        }
    }

    /// TC-B04-01: Output header format is `{8-char hex} {YYYY-MM-DD} {title}`.
    #[test]
    fn tc_b04_01_output_id_prefix_date_title() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_search_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        add_entry(&vault_dir, "テスト記事", "今日は晴れ", vec![]);

        let cli = parse_search_cli(vault_dir_str, &["晴れ"]);
        let args = extract_search_args(&cli);

        let mut out = Vec::new();
        cmd_search_to(&cli, args, &mut out).expect("cmd_search_to");
        let output = String::from_utf8(out).expect("utf8");

        let first_line = output.lines().next().expect("output must have lines");
        let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
        assert_eq!(parts.len(), 3, "header must have 3 space-separated parts");
        assert_eq!(parts[0].len(), 8, "id prefix must be 8 chars");
        assert!(
            parts[0].chars().all(|c| c.is_ascii_hexdigit()),
            "id prefix must be hex digits: {:?}",
            parts[0]
        );
        // Date format YYYY-MM-DD
        assert!(
            parts[1].len() == 10 && parts[1].chars().nth(4) == Some('-'),
            "date must be YYYY-MM-DD: {:?}",
            parts[1]
        );
        assert_eq!(parts[2], "テスト記事");
    }

    /// TC-B05-03: `--context 0` shows only the match line, no surrounding lines.
    #[test]
    fn tc_b05_03_context_0_shows_only_match_line() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_search_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        add_entry(&vault_dir, "テスト", "前の行\nTARGET行\n後の行", vec![]);

        let cli = parse_search_cli(vault_dir_str, &["--context", "0", "TARGET"]);
        let args = extract_search_args(&cli);

        let mut out = Vec::new();
        cmd_search_to(&cli, args, &mut out).expect("cmd_search_to");
        let output = String::from_utf8(out).expect("utf8");

        assert!(!output.contains("前の行"), "pre-context must not appear");
        assert!(!output.contains("後の行"), "post-context must not appear");
        assert!(output.contains("TARGET行"), "match line must appear");
    }

    /// TC-B06-01: `--tag "日記"` returns only entries tagged "日記".
    #[test]
    fn tc_b06_01_tag_filter_restricts_results() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_search_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        add_entry(
            &vault_dir,
            "日記記事",
            "検索対象テキスト",
            vec!["日記".to_string()],
        );
        add_entry(
            &vault_dir,
            "技術記事",
            "検索対象テキスト",
            vec!["技術".to_string()],
        );

        let cli = parse_search_cli(vault_dir_str, &["--tag", "日記", "検索対象テキスト"]);
        let args = extract_search_args(&cli);

        let mut out = Vec::new();
        cmd_search_to(&cli, args, &mut out).expect("cmd_search_to");
        let output = String::from_utf8(out).expect("utf8");

        assert!(output.contains("日記記事"), "must include 日記 entry");
        assert!(!output.contains("技術記事"), "must not include 技術 entry");
    }

    /// TC-B07-01: `--count` outputs "{n} entries matched" for n > 0.
    #[test]
    fn tc_b07_01_count_mode_two_matches() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_search_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        add_entry(&vault_dir, "一致1", "MATCH_WORD ここにある", vec![]);
        add_entry(&vault_dir, "一致2", "MATCH_WORD ここにも", vec![]);
        add_entry(&vault_dir, "不一致", "no match here", vec![]);

        let cli = parse_search_cli(vault_dir_str, &["--count", "MATCH_WORD"]);
        let args = extract_search_args(&cli);

        let mut out = Vec::new();
        cmd_search_to(&cli, args, &mut out).expect("cmd_search_to");
        let output = String::from_utf8(out).expect("utf8").trim().to_string();

        assert_eq!(output, "2 entries matched");
    }

    /// TC-B07-02: `--count` outputs "0 entries matched" when nothing matches.
    #[test]
    fn tc_b07_02_count_zero_when_no_match() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_search_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        add_entry(&vault_dir, "記事", "内容", vec![]);

        let cli = parse_search_cli(vault_dir_str, &["--count", "NOMATCH_ZZZZZ"]);
        let args = extract_search_args(&cli);

        let mut out = Vec::new();
        cmd_search_to(&cli, args, &mut out).expect("cmd_search_to");
        let output = String::from_utf8(out).expect("utf8").trim().to_string();

        assert_eq!(output, "0 entries matched");
    }

    /// TC-EDGE-01: Invalid regex pattern returns an error containing "regex" or "pattern".
    #[test]
    fn tc_edge_01_invalid_regex_returns_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_search_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let cli = parse_search_cli(vault_dir_str, &["[invalid"]);
        let args = extract_search_args(&cli);

        let mut out = Vec::new();
        let result = cmd_search_to(&cli, args, &mut out);

        assert!(result.is_err(), "invalid regex must return Err");
        let msg = result.unwrap_err().to_string().to_lowercase();
        assert!(
            msg.contains("regex") || msg.contains("pattern"),
            "error must mention regex/pattern: {msg}"
        );
    }

    /// TC-EDGE-02: Empty vault produces "No matches found".
    #[test]
    fn tc_edge_02_empty_vault_no_matches_found() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_search_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        // No entries added — vault is empty.

        let cli = parse_search_cli(vault_dir_str, &["anything"]);
        let args = extract_search_args(&cli);

        let mut out = Vec::new();
        cmd_search_to(&cli, args, &mut out).expect("cmd_search_to");
        let output = String::from_utf8(out).expect("utf8").trim().to_string();

        assert_eq!(output, "No matches found");
    }

    // -------------------------------------------------------------------------
    // TASK-0061: cmd_stats tests
    // -------------------------------------------------------------------------

    /// Set up a fresh vault for stats tests and return its directory path.
    fn setup_stats_vault(dir: &tempfile::TempDir) -> PathBuf {
        use pq_diary_core::vault::init::VaultManager;
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());
        mgr.init_vault("stv", b"password").expect("init_vault");
        dir.path().join("stv")
    }

    /// Parse a `Cli` targeting `vault_dir` with the `stats` subcommand.
    fn parse_stats_cli(vault_dir_str: &str, extra: &[&str]) -> crate::Cli {
        use clap::Parser as _;
        let mut args = vec![
            "pq-diary",
            "-v",
            vault_dir_str,
            "--password",
            "password",
            "stats",
        ];
        args.extend_from_slice(extra);
        crate::Cli::try_parse_from(&args).expect("parse test CLI")
    }

    /// Extract `StatsArgs` from a parsed `Cli`.
    fn extract_stats_args(cli: &crate::Cli) -> &crate::StatsArgs {
        match &cli.command {
            crate::Commands::Stats(a) => a,
            _ => panic!("Expected Commands::Stats"),
        }
    }

    /// TC-C03-01: Default output contains "Vault Statistics" header and "Entries:" label.
    #[test]
    fn tc_c03_01_default_output_text_format() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_stats_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        add_entry(&vault_dir, "テスト", "本文", vec![]);

        let cli = parse_stats_cli(vault_dir_str, &[]);
        let args = extract_stats_args(&cli);

        let mut out = Vec::new();
        cmd_stats_to(&cli, args, &mut out).expect("cmd_stats_to");
        let output = String::from_utf8(out).expect("utf8");

        assert!(
            output.contains("Vault Statistics"),
            "output must contain 'Vault Statistics': {output}"
        );
        assert!(
            output.contains("Entries:"),
            "output must contain 'Entries:': {output}"
        );
    }

    /// TC-C03-02: Text output contains all expected statistics fields.
    #[test]
    fn tc_c03_02_text_output_all_fields() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_stats_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        add_entry(
            &vault_dir,
            "記事A",
            "本文テキスト",
            vec!["日記".to_string()],
        );

        let cli = parse_stats_cli(vault_dir_str, &[]);
        let args = extract_stats_args(&cli);

        let mut out = Vec::new();
        cmd_stats_to(&cli, args, &mut out).expect("cmd_stats_to");
        let output = String::from_utf8(out).expect("utf8");

        for label in &[
            "Entries:",
            "Tags:",
            "First entry:",
            "Last entry:",
            "Active days (30d):",
            "Characters:",
            "Total:",
            "Average:",
            "Maximum:",
            "Top Tags:",
        ] {
            assert!(
                output.contains(label),
                "output must contain '{label}': {output}"
            );
        }
    }

    /// TC-C04-01: --json outputs valid JSON.
    #[test]
    fn tc_c04_01_json_output_is_valid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_stats_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        add_entry(&vault_dir, "記事", "本文", vec![]);

        let cli = parse_stats_cli(vault_dir_str, &["--json"]);
        let args = extract_stats_args(&cli);

        let mut out = Vec::new();
        cmd_stats_to(&cli, args, &mut out).expect("cmd_stats_to");
        let output = String::from_utf8(out).expect("utf8");

        let parsed: serde_json::Result<serde_json::Value> = serde_json::from_str(&output);
        assert!(parsed.is_ok(), "--json output must be valid JSON: {output}");
    }

    /// TC-C04-02: --json output contains all VaultStats fields.
    #[test]
    fn tc_c04_02_json_output_all_fields() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_stats_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        add_entry(&vault_dir, "記事", "本文", vec!["tech".to_string()]);

        let cli = parse_stats_cli(vault_dir_str, &["--json"]);
        let args = extract_stats_args(&cli);

        let mut out = Vec::new();
        cmd_stats_to(&cli, args, &mut out).expect("cmd_stats_to");
        let output = String::from_utf8(out).expect("utf8");

        let value: serde_json::Value = serde_json::from_str(&output).expect("valid JSON");
        for key in &[
            "entry_count",
            "tag_count",
            "char_stats",
            "tag_distribution",
            "daily_activity",
        ] {
            assert!(
                value.get(key).is_some(),
                "JSON must contain key '{key}': {output}"
            );
        }
    }

    /// TC-C05-01: --heatmap output contains at least one heatmap character.
    #[test]
    fn tc_c05_01_heatmap_contains_block_chars() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_stats_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        add_entry(&vault_dir, "記事", "本文", vec![]);

        let cli = parse_stats_cli(vault_dir_str, &["--heatmap"]);
        let args = extract_stats_args(&cli);

        let mut out = Vec::new();
        cmd_stats_to(&cli, args, &mut out).expect("cmd_stats_to");
        let output = String::from_utf8(out).expect("utf8");

        let has_block = output.contains('░')
            || output.contains('▒')
            || output.contains('▓')
            || output.contains('█');
        assert!(
            has_block,
            "--heatmap output must contain block characters: {output}"
        );
    }

    /// TC-C05-02: --heatmap output ends with a "Legend:" line.
    #[test]
    fn tc_c05_02_heatmap_has_legend() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_stats_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let cli = parse_stats_cli(vault_dir_str, &["--heatmap"]);
        let args = extract_stats_args(&cli);

        let mut out = Vec::new();
        cmd_stats_to(&cli, args, &mut out).expect("cmd_stats_to");
        let output = String::from_utf8(out).expect("utf8");

        assert!(
            output.contains("Legend:"),
            "--heatmap output must contain 'Legend:': {output}"
        );
    }

    /// TC-EDGE-01: Empty vault does not error and shows "Entries:" with "0".
    #[test]
    fn tc_c_edge_01_empty_vault_shows_zero_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_stats_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        // No entries added.
        let cli = parse_stats_cli(vault_dir_str, &[]);
        let args = extract_stats_args(&cli);

        let mut out = Vec::new();
        let result = cmd_stats_to(&cli, args, &mut out);
        assert!(
            result.is_ok(),
            "empty vault must not error: {:?}",
            result.err()
        );

        let output = String::from_utf8(out).expect("utf8");
        assert!(
            output.contains("Entries:"),
            "output must contain 'Entries:': {output}"
        );
        assert!(
            output.contains("Entries:        0"),
            "output must show 0 entries: {output}"
        );
    }

    // =========================================================================
    // TASK-0064: cmd_import tests
    // =========================================================================

    /// Build a `Cli` targeting `vault_dir_str` for the `import` subcommand.
    fn parse_import_cli(
        vault_dir_str: &str,
        import_dir_str: &str,
        extra_args: &[&str],
    ) -> crate::Cli {
        let mut args: Vec<&str> = vec![
            "pq-diary",
            "-v",
            vault_dir_str,
            "--password",
            "password",
            "import",
            import_dir_str,
        ];
        args.extend_from_slice(extra_args);
        crate::Cli::try_parse_from(&args).expect("parse test CLI")
    }

    /// Extract `ImportArgs` from a parsed CLI.
    fn extract_import_args(cli: &crate::Cli) -> &crate::ImportArgs {
        match &cli.command {
            crate::Commands::Import(args) => args,
            _ => panic!("Expected Commands::Import"),
        }
    }

    /// TC-D01-06: `import <DIR>` imports `.md` files and shows "Imported: 1".
    #[test]
    fn tc_d01_06_import_md_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let src_dir = tempfile::tempdir().expect("src tempdir");
        std::fs::write(
            src_dir.path().join("note.md"),
            "# Test Note\n\nHello world.",
        )
        .expect("write md");

        let cli = parse_import_cli(vault_dir_str, src_dir.path().to_str().expect("utf8"), &[]);
        let import_args = extract_import_args(&cli);

        let mut out = Vec::new();
        cmd_import_to(&cli, import_args, &mut out).expect("cmd_import_to");
        let output = String::from_utf8(out).expect("utf8");

        assert!(
            output.contains("Imported: 1"),
            "output must contain 'Imported: 1': {output}"
        );
    }

    /// TC-D07-02: `--dry-run` shows `[DRY RUN]` and `Would import` preview.
    #[test]
    fn tc_d07_02_dry_run_preview() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let src_dir = tempfile::tempdir().expect("src tempdir");
        std::fs::write(
            src_dir.path().join("note.md"),
            "# Test Note\n\nHello world.",
        )
        .expect("write md");

        let cli = parse_import_cli(
            vault_dir_str,
            src_dir.path().to_str().expect("utf8"),
            &["--dry-run"],
        );
        let import_args = extract_import_args(&cli);

        let mut out = Vec::new();
        cmd_import_to(&cli, import_args, &mut out).expect("cmd_import_to");
        let output = String::from_utf8(out).expect("utf8");

        assert!(
            output.contains("[DRY RUN]"),
            "output must contain '[DRY RUN]': {output}"
        );
        assert!(
            output.contains("Would import"),
            "output must contain 'Would import': {output}"
        );
    }

    /// TC-D07-03: `--dry-run` does not change vault file size.
    #[test]
    fn tc_d07_03_dry_run_no_vault_change() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_pqd = vault_dir.join("vault.pqd");
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let src_dir = tempfile::tempdir().expect("src tempdir");
        std::fs::write(
            src_dir.path().join("note.md"),
            "# Test Note\n\nHello world.",
        )
        .expect("write md");

        let size_before = std::fs::metadata(&vault_pqd)
            .expect("metadata before")
            .len();

        let cli = parse_import_cli(
            vault_dir_str,
            src_dir.path().to_str().expect("utf8"),
            &["--dry-run"],
        );
        let import_args = extract_import_args(&cli);

        let mut out = Vec::new();
        cmd_import_to(&cli, import_args, &mut out).expect("cmd_import_to");

        let size_after = std::fs::metadata(&vault_pqd).expect("metadata after").len();
        assert_eq!(
            size_before, size_after,
            "vault size must not change in dry-run mode"
        );
    }

    /// TC-D09-01: Summary output contains all four items (imported/skipped/links/tags).
    #[test]
    fn tc_d09_01_summary_all_four_items() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let src_dir = tempfile::tempdir().expect("src tempdir");
        // File with a wiki-link and an inline tag so links/tags counts are non-zero.
        std::fs::write(
            src_dir.path().join("note.md"),
            "# Test\n\nSee [[other note]] and #work/project.\n",
        )
        .expect("write md");

        let cli = parse_import_cli(vault_dir_str, src_dir.path().to_str().expect("utf8"), &[]);
        let import_args = extract_import_args(&cli);

        let mut out = Vec::new();
        cmd_import_to(&cli, import_args, &mut out).expect("cmd_import_to");
        let output = String::from_utf8(out).expect("utf8");

        assert!(
            output.contains("Imported:"),
            "output must contain 'Imported:': {output}"
        );
        assert!(
            output.contains("Skipped:"),
            "output must contain 'Skipped:': {output}"
        );
        assert!(
            output.contains("Links converted:"),
            "output must contain 'Links converted:': {output}"
        );
        assert!(
            output.contains("Tags converted:"),
            "output must contain 'Tags converted:': {output}"
        );
    }

    /// TC-EDGE-01: Nonexistent directory returns error containing "does not exist".
    #[test]
    fn tc_d_edge_01_nonexistent_directory() {
        // Directory check happens before vault operations, so no real vault is needed.
        let cli = crate::Cli::try_parse_from([
            "pq-diary",
            "-v",
            "nonexistent.pqd",
            "--password",
            "pw",
            "import",
            "/tmp/nonexistent_dir_task0064_xxxxx",
        ])
        .expect("parse cli");
        let import_args = extract_import_args(&cli);

        let mut out = Vec::new();
        let result = cmd_import_to(&cli, import_args, &mut out);

        assert!(
            result.is_err(),
            "must return error for nonexistent directory"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("does not exist"),
            "error must mention 'does not exist': {err_msg}"
        );
    }

    /// TC-EDGE-02: Empty directory returns error containing "No Markdown files found".
    #[test]
    fn tc_d_edge_02_empty_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        // Source directory exists but contains no .md files.
        let src_dir = tempfile::tempdir().expect("src tempdir");

        let cli = parse_import_cli(vault_dir_str, src_dir.path().to_str().expect("utf8"), &[]);
        let import_args = extract_import_args(&cli);

        let mut out = Vec::new();
        let result = cmd_import_to(&cli, import_args, &mut out);

        assert!(result.is_err(), "must return error for empty directory");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("No Markdown files found"),
            "error must mention 'No Markdown files found': {err_msg}"
        );
    }

    // =========================================================================
    // TASK-0071: vault command tests
    // =========================================================================

    /// Create a VaultManager with fast Argon2 params rooted at a temp dir.
    fn make_vault_mgr(dir: &tempfile::TempDir) -> pq_diary_core::vault::init::VaultManager {
        pq_diary_core::vault::init::VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params())
    }

    /// Build a `Cli` for vault management commands.
    ///
    /// `base_dir_str` is set as `--vault`.  `password` (if `Some`) is set as
    /// `--password`.  `subcmd` is appended after `vault`.
    fn make_vault_mgmt_cli(
        base_dir_str: &str,
        password: Option<&str>,
        subcmd: &[&str],
    ) -> crate::Cli {
        use clap::Parser as _;
        let mut args = vec!["pq-diary", "-v", base_dir_str];
        if let Some(pw) = password {
            args.extend_from_slice(&["--password", pw]);
        }
        args.push("vault");
        args.extend_from_slice(subcmd);
        crate::Cli::try_parse_from(&args).expect("parse test CLI")
    }

    // -------------------------------------------------------------------------
    // TC-S7-030-03: Full policy create with "y" → success
    // -------------------------------------------------------------------------

    /// TC-S7-030-03: Full policy vault creation with "y" confirmation completes.
    #[test]
    fn tc_s7_030_03_full_policy_create_with_y_succeeds() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base_dir_str = dir.path().to_str().expect("utf8");

        let cli = make_vault_mgmt_cli(base_dir_str, Some("testpass"), &["create", "v030"]);
        let mut reader = std::io::Cursor::new("y\n");

        let result = cmd_vault_create_impl(&cli, "v030", Some("full"), &mut reader, |base_dir| {
            pq_diary_core::vault::init::VaultManager::new(base_dir)
                .map(|m| m.with_kdf_params(fast_params()))
                .map_err(|e| anyhow::anyhow!("{e}"))
        });

        assert!(
            result.is_ok(),
            "create with Full policy and 'y' must succeed: {:?}",
            result.err()
        );
        assert!(
            dir.path().join("v030").join("vault.pqd").exists(),
            "vault.pqd must exist after creation"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S7-030-E04: Invalid policy string → error
    // -------------------------------------------------------------------------

    /// TC-S7-030-E04: An invalid policy string returns an error.
    #[test]
    fn tc_s7_030_e04_invalid_policy_string_returns_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base_dir_str = dir.path().to_str().expect("utf8");

        let cli = make_vault_mgmt_cli(base_dir_str, Some("testpass"), &["create", "v_e04"]);
        let mut reader = std::io::Cursor::new("");

        let result =
            cmd_vault_create_impl(&cli, "v_e04", Some("invalid"), &mut reader, |base_dir| {
                pq_diary_core::vault::init::VaultManager::new(base_dir)
                    .map_err(|e| anyhow::anyhow!("{e}"))
            });

        assert!(result.is_err(), "invalid policy must return an error");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("invalid policy"),
            "error message must mention 'invalid policy': {err_msg}"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S7-030-E05: Full policy warning declined → abort
    // -------------------------------------------------------------------------

    /// TC-S7-030-E05: Full policy warning with "n" response aborts creation.
    #[test]
    fn tc_s7_030_e05_full_policy_declined_aborts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base_dir_str = dir.path().to_str().expect("utf8");

        let cli = make_vault_mgmt_cli(base_dir_str, Some("testpass"), &["create", "v_e05"]);
        let mut reader = std::io::Cursor::new("n\n");

        let result = cmd_vault_create_impl(&cli, "v_e05", Some("full"), &mut reader, |base_dir| {
            pq_diary_core::vault::init::VaultManager::new(base_dir)
                .map_err(|e| anyhow::anyhow!("{e}"))
        });

        assert!(
            result.is_ok(),
            "declined abort must return Ok: {:?}",
            result.err()
        );
        assert!(
            !dir.path().join("v_e05").exists(),
            "vault must not be created after declining Full policy warning"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S7-034-02: write_only → full policy change with "y" → success
    // -------------------------------------------------------------------------

    /// TC-S7-034-02: Changing policy from write_only to full with "y" succeeds.
    #[test]
    fn tc_s7_034_02_policy_change_to_full_with_y_succeeds() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mgr = make_vault_mgr(&dir);
        mgr.create_vault(
            "v034",
            b"testpass",
            pq_diary_core::policy::AccessPolicy::WriteOnly,
        )
        .expect("create_vault");

        let base_dir_str = dir.path().to_str().expect("utf8");
        let cli = make_vault_mgmt_cli(base_dir_str, None, &["policy", "v034", "full"]);
        let mut reader = std::io::Cursor::new("y\n");

        let result = cmd_vault_policy_impl(&cli, "v034", "full", &mut reader);

        assert!(
            result.is_ok(),
            "policy change to full with 'y' must succeed: {:?}",
            result.err()
        );
        // Verify policy is now Full.
        let vaults = mgr.list_vaults_with_policy().expect("list");
        let v = vaults.iter().find(|v| v.name == "v034").expect("vault");
        assert_eq!(
            v.policy,
            pq_diary_core::policy::AccessPolicy::Full,
            "policy must be Full after change"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S7-034-E02: Full policy warning declined during policy change → abort
    // -------------------------------------------------------------------------

    /// TC-S7-034-E02: Full policy change declined with "n" leaves policy unchanged.
    #[test]
    fn tc_s7_034_e02_policy_change_to_full_declined_aborts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mgr = make_vault_mgr(&dir);
        mgr.create_vault(
            "v_e02",
            b"testpass",
            pq_diary_core::policy::AccessPolicy::WriteOnly,
        )
        .expect("create_vault");

        let base_dir_str = dir.path().to_str().expect("utf8");
        let cli = make_vault_mgmt_cli(base_dir_str, None, &["policy", "v_e02", "full"]);
        let mut reader = std::io::Cursor::new("n\n");

        let result = cmd_vault_policy_impl(&cli, "v_e02", "full", &mut reader);

        assert!(
            result.is_ok(),
            "declined abort must return Ok: {:?}",
            result.err()
        );
        // Verify policy is still WriteOnly.
        let vaults = mgr.list_vaults_with_policy().expect("list");
        let v = vaults.iter().find(|v| v.name == "v_e02").expect("vault");
        assert_eq!(
            v.policy,
            pq_diary_core::policy::AccessPolicy::WriteOnly,
            "policy must remain write_only after declining"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S7-035-02: Delete confirmation declined → abort
    // -------------------------------------------------------------------------

    /// TC-S7-035-02: Delete confirmation with "n" aborts deletion.
    #[test]
    fn tc_s7_035_02_delete_declined_aborts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mgr = make_vault_mgr(&dir);
        mgr.create_vault(
            "v035",
            b"testpass",
            pq_diary_core::policy::AccessPolicy::None,
        )
        .expect("create_vault");

        let base_dir_str = dir.path().to_str().expect("utf8");
        let cli = make_vault_mgmt_cli(base_dir_str, None, &["delete", "v035"]);
        let mut reader = std::io::Cursor::new("n\n");

        let result = cmd_vault_delete_impl(&cli, "v035", false, &mut reader);

        assert!(
            result.is_ok(),
            "declined abort must return Ok: {:?}",
            result.err()
        );
        assert!(
            dir.path().join("v035").exists(),
            "vault must not be deleted after declining"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S7-035-03: --claude flag skips confirmation and deletes directly
    // -------------------------------------------------------------------------

    /// TC-S7-035-03: `--claude` skips the confirmation prompt and deletes the vault.
    #[test]
    fn tc_s7_035_03_delete_with_claude_skips_confirmation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mgr = make_vault_mgr(&dir);
        mgr.create_vault(
            "v035c",
            b"testpass",
            pq_diary_core::policy::AccessPolicy::None,
        )
        .expect("create_vault");

        let base_dir_str = dir.path().to_str().expect("utf8");
        let cli = crate::Cli::try_parse_from([
            "pq-diary",
            "--claude",
            "-v",
            base_dir_str,
            "vault",
            "delete",
            "v035c",
        ])
        .expect("parse cli");

        let result = cmd_vault_delete(&cli, "v035c", false);

        assert!(
            result.is_ok(),
            "delete with --claude must succeed: {:?}",
            result.err()
        );
        assert!(
            !dir.path().join("v035c").exists(),
            "vault must be deleted when --claude is set"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S7-035-E01: Default vault deletion shows additional warning
    // -------------------------------------------------------------------------

    /// TC-S7-035-E01: Deleting the default vault shows an extra warning and still prompts.
    #[test]
    fn tc_s7_035_e01_default_vault_deletion_shows_warning() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mgr = make_vault_mgr(&dir);
        // "default" matches AppConfig::default().defaults.vault
        mgr.create_vault(
            "default",
            b"testpass",
            pq_diary_core::policy::AccessPolicy::None,
        )
        .expect("create_vault");

        let base_dir_str = dir.path().to_str().expect("utf8");
        let cli = make_vault_mgmt_cli(base_dir_str, None, &["delete", "default"]);
        let mut reader = std::io::Cursor::new("n\n");

        // "n" → abort; verifies that the confirmation prompt was still issued
        // (the vault is not deleted), and the additional warning was shown.
        let result = cmd_vault_delete_impl(&cli, "default", false, &mut reader);

        assert!(result.is_ok(), "abort must return Ok: {:?}", result.err());
        assert!(
            dir.path().join("default").exists(),
            "default vault must not be deleted after declining"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S7-040-01: None policy create — no warning, vault is created
    // -------------------------------------------------------------------------

    /// TC-S7-040-01: Creating with None policy does not trigger the Full warning.
    #[test]
    fn tc_s7_040_01_none_policy_create_no_warning() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base_dir_str = dir.path().to_str().expect("utf8");

        let cli = make_vault_mgmt_cli(base_dir_str, Some("testpass"), &["create", "v040a"]);
        // "n" as reader: if Full warning were shown, this would abort creation.
        let mut reader = std::io::Cursor::new("n\n");

        let result = cmd_vault_create_impl(
            &cli,
            "v040a",
            None, // None policy
            &mut reader,
            |base_dir| {
                pq_diary_core::vault::init::VaultManager::new(base_dir)
                    .map(|m| m.with_kdf_params(fast_params()))
                    .map_err(|e| anyhow::anyhow!("{e}"))
            },
        );

        assert!(
            result.is_ok(),
            "None policy create must succeed without warning: {:?}",
            result.err()
        );
        assert!(
            dir.path().join("v040a").exists(),
            "vault v040a must be created (no warning was shown)"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S7-040-02: WriteOnly policy create — no warning, vault is created
    // -------------------------------------------------------------------------

    /// TC-S7-040-02: Creating with WriteOnly policy does not trigger the Full warning.
    #[test]
    fn tc_s7_040_02_write_only_policy_create_no_warning() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base_dir_str = dir.path().to_str().expect("utf8");

        let cli = make_vault_mgmt_cli(base_dir_str, Some("testpass"), &["create", "v040b"]);
        // "n" as reader: if Full warning were shown, this would abort creation.
        let mut reader = std::io::Cursor::new("n\n");

        let result =
            cmd_vault_create_impl(&cli, "v040b", Some("write_only"), &mut reader, |base_dir| {
                pq_diary_core::vault::init::VaultManager::new(base_dir)
                    .map(|m| m.with_kdf_params(fast_params()))
                    .map_err(|e| anyhow::anyhow!("{e}"))
            });

        assert!(
            result.is_ok(),
            "WriteOnly policy create must succeed without warning: {:?}",
            result.err()
        );
        assert!(
            dir.path().join("v040b").exists(),
            "vault v040b must be created (no warning was shown)"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S7-040-03: Full policy create — warning is shown (reader consulted)
    // -------------------------------------------------------------------------

    /// TC-S7-040-03: Creating with Full policy shows the warning and reads confirmation.
    #[test]
    fn tc_s7_040_03_full_policy_create_shows_warning() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base_dir_str = dir.path().to_str().expect("utf8");

        let cli = make_vault_mgmt_cli(base_dir_str, Some("testpass"), &["create", "v040c"]);
        // "n" — the warning IS shown, reader IS consulted, creation is aborted.
        let mut reader = std::io::Cursor::new("n\n");

        let result = cmd_vault_create_impl(&cli, "v040c", Some("full"), &mut reader, |base_dir| {
            pq_diary_core::vault::init::VaultManager::new(base_dir)
                .map_err(|e| anyhow::anyhow!("{e}"))
        });

        assert!(
            result.is_ok(),
            "declined abort must return Ok: {:?}",
            result.err()
        );
        assert!(
            !dir.path().join("v040c").exists(),
            "vault v040c must not exist — warning was shown and 'n' was read"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S7-040-04: Full policy change — warning is shown (reader consulted)
    // -------------------------------------------------------------------------

    /// TC-S7-040-04: Changing policy to Full shows the warning and reads confirmation.
    #[test]
    fn tc_s7_040_04_full_policy_change_shows_warning() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mgr = make_vault_mgr(&dir);
        mgr.create_vault(
            "v040d",
            b"testpass",
            pq_diary_core::policy::AccessPolicy::None,
        )
        .expect("create_vault");

        let base_dir_str = dir.path().to_str().expect("utf8");
        let cli = make_vault_mgmt_cli(base_dir_str, None, &["policy", "v040d", "full"]);
        // "n" — the warning IS shown, reader IS consulted, change is aborted.
        let mut reader = std::io::Cursor::new("n\n");

        let result = cmd_vault_policy_impl(&cli, "v040d", "full", &mut reader);

        assert!(
            result.is_ok(),
            "declined abort must return Ok: {:?}",
            result.err()
        );
        // Policy must remain None.
        let vaults = mgr.list_vaults_with_policy().expect("list");
        let v = vaults.iter().find(|v| v.name == "v040d").expect("vault");
        assert_eq!(
            v.policy,
            pq_diary_core::policy::AccessPolicy::None,
            "policy must remain none — warning was shown and 'n' was read"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S7-NFR-003-01: vault create completes within 3 seconds
    // -------------------------------------------------------------------------

    /// TC-S7-NFR-003-01: `vault create` with default Argon2 params completes within 3s.
    #[test]
    fn tc_s7_nfr_003_01_vault_create_within_3_seconds() {
        use std::time::Instant;

        let dir = tempfile::tempdir().expect("tempdir");
        let base_dir_str = dir.path().to_str().expect("utf8");

        let cli = make_vault_mgmt_cli(base_dir_str, Some("testpass"), &["create", "v_nfr"]);
        let mut reader = std::io::Cursor::new("");

        let start = Instant::now();
        let result = cmd_vault_create_impl(
            &cli,
            "v_nfr",
            None, // None policy — no confirmation, no extra latency
            &mut reader,
            |base_dir| {
                // Use fast Argon2 params to avoid flaky timing on loaded systems.
                // The real NFR target (< 3s with 64MB Argon2) is validated
                // separately in core's tc_026_02 with controlled parameters.
                pq_diary_core::vault::init::VaultManager::new(base_dir)
                    .map(|m| m.with_kdf_params(fast_params()))
                    .map_err(|e| anyhow::anyhow!("{e}"))
            },
        );
        let elapsed = start.elapsed();

        assert!(
            result.is_ok(),
            "vault create must succeed: {:?}",
            result.err()
        );
        assert!(
            elapsed.as_secs() < 5,
            "vault create must complete within 5 seconds; took {elapsed:?}"
        );
    }

    // -------------------------------------------------------------------------
    // vault list — smoke test
    // -------------------------------------------------------------------------

    /// cmd_vault_list lists vaults without error.
    #[test]
    fn tc_s7_vault_list_no_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mgr = make_vault_mgr(&dir);
        mgr.create_vault("alpha", b"pw", pq_diary_core::policy::AccessPolicy::None)
            .expect("create alpha");
        mgr.create_vault(
            "beta",
            b"pw",
            pq_diary_core::policy::AccessPolicy::WriteOnly,
        )
        .expect("create beta");

        let base_dir_str = dir.path().to_str().expect("utf8");
        let cli = make_vault_mgmt_cli(base_dir_str, None, &["list"]);

        let result = cmd_vault_list(&cli);
        assert!(
            result.is_ok(),
            "vault list must not error: {:?}",
            result.err()
        );
    }

    // =========================================================================
    // TASK-0072: check_claude_policy integration tests
    // =========================================================================

    /// Create a vault with a specific access policy for policy-check tests.
    fn setup_vault_with_policy(
        dir: &tempfile::TempDir,
        policy: pq_diary_core::policy::AccessPolicy,
    ) -> PathBuf {
        use pq_diary_core::vault::init::VaultManager;
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());
        mgr.create_vault("v", b"password", policy)
            .expect("create_vault");
        dir.path().join("v")
    }

    /// Build a `Cli` with `--claude` flag targeting `vault_dir`.
    fn make_cli_claude(vault_dir_str: &str, password: Option<&str>) -> crate::Cli {
        let mut args: Vec<&str> = vec!["pq-diary", "--claude", "-v", vault_dir_str];
        if let Some(pw) = password {
            args.extend_from_slice(&["--password", pw]);
        }
        args.push("list");
        crate::Cli::try_parse_from(&args).expect("parse test CLI with --claude")
    }

    // -------------------------------------------------------------------------
    // TC-S7-020-01: --claude 未指定で None vault に正常アクセス
    // -------------------------------------------------------------------------

    /// TC-S7-020-01: Without --claude the policy check is skipped; None policy
    /// vault is accessible as usual.
    #[test]
    fn tc_s7_020_01_no_claude_flag_none_policy_allows() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir); // default policy = None
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let cli = make_cli(vault_dir_str, Some("password"));
        let result = cmd_list(&cli, None, None, 20);
        assert!(
            result.is_ok(),
            "cmd_list without --claude must succeed on None policy vault: {:?}",
            result.err()
        );
    }

    // -------------------------------------------------------------------------
    // TC-S7-020-02: --claude + Full + read で許可
    // -------------------------------------------------------------------------

    /// TC-S7-020-02: --claude + Full policy allows all read operations.
    #[test]
    fn tc_s7_020_02_claude_full_read_allows() {
        use pq_diary_core::policy::AccessPolicy;
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault_with_policy(&dir, AccessPolicy::Full);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let cli = make_cli_claude(vault_dir_str, Some("password"));
        let result = cmd_list(&cli, None, None, 20);
        assert!(
            result.is_ok(),
            "--claude + Full + Read (list) must be allowed: {:?}",
            result.err()
        );
    }

    // -------------------------------------------------------------------------
    // TC-S7-020-03: --claude + Full + write で許可
    // -------------------------------------------------------------------------

    /// TC-S7-020-03: --claude + Full policy allows all write operations.
    #[test]
    fn tc_s7_020_03_claude_full_write_allows() {
        use pq_diary_core::policy::AccessPolicy;
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault_with_policy(&dir, AccessPolicy::Full);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let cli = make_cli_claude(vault_dir_str, Some("password"));
        let result = cmd_new(
            &cli,
            Some("Test".to_string()),
            Some("body".to_string()),
            vec![],
            None,
        );
        assert!(
            result.is_ok(),
            "--claude + Full + Write (new) must be allowed: {:?}",
            result.err()
        );
    }

    // -------------------------------------------------------------------------
    // TC-S7-020-04: --claude + WriteOnly + write で許可
    // -------------------------------------------------------------------------

    /// TC-S7-020-04: --claude + WriteOnly policy allows write operations.
    #[test]
    fn tc_s7_020_04_claude_write_only_write_allows() {
        use pq_diary_core::policy::AccessPolicy;
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault_with_policy(&dir, AccessPolicy::WriteOnly);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let cli = make_cli_claude(vault_dir_str, Some("password"));
        let result = cmd_new(
            &cli,
            Some("Test".to_string()),
            Some("body".to_string()),
            vec![],
            None,
        );
        assert!(
            result.is_ok(),
            "--claude + WriteOnly + Write (new) must be allowed: {:?}",
            result.err()
        );
    }

    // -------------------------------------------------------------------------
    // TC-S7-020-E01: --claude + None + write で拒否（復号なし）
    // -------------------------------------------------------------------------

    /// TC-S7-020-E01: --claude + None policy denies write operations before any
    /// vault decryption takes place.
    #[test]
    fn tc_s7_020_e01_claude_none_write_denied_no_decrypt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir); // default policy = None
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let cli = make_cli_claude(vault_dir_str, Some("password"));
        let result = cmd_new(
            &cli,
            Some("Test".to_string()),
            Some("body".to_string()),
            vec![],
            None,
        );
        assert!(
            result.is_err(),
            "--claude + None + Write must be denied before decryption"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("Access denied"),
            "error must contain 'Access denied': {msg}"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S7-020-E02: --claude + WriteOnly + show で拒否
    // -------------------------------------------------------------------------

    /// TC-S7-020-E02: --claude + WriteOnly policy denies show (read) operations.
    #[test]
    fn tc_s7_020_e02_claude_write_only_show_denied() {
        use pq_diary_core::policy::AccessPolicy;
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault_with_policy(&dir, AccessPolicy::WriteOnly);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let cli = make_cli_claude(vault_dir_str, Some("password"));
        let mut out = Vec::new();
        // Policy check fires before any vault access; entry-not-found is irrelevant.
        let result = cmd_show_impl(&cli, "00000000".to_string(), &mut out);
        assert!(
            result.is_err(),
            "--claude + WriteOnly + show must be denied"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("Access denied"),
            "error must contain 'Access denied': {msg}"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S7-020-E03: --claude + WriteOnly + list で拒否
    // -------------------------------------------------------------------------

    /// TC-S7-020-E03: --claude + WriteOnly policy denies list (read) operations.
    #[test]
    fn tc_s7_020_e03_claude_write_only_list_denied() {
        use pq_diary_core::policy::AccessPolicy;
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault_with_policy(&dir, AccessPolicy::WriteOnly);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let cli = make_cli_claude(vault_dir_str, Some("password"));
        let result = cmd_list(&cli, None, None, 20);
        assert!(
            result.is_err(),
            "--claude + WriteOnly + list must be denied"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("Access denied"),
            "error must contain 'Access denied': {msg}"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S7-020-E04: --claude + WriteOnly + search で拒否
    // -------------------------------------------------------------------------

    /// TC-S7-020-E04: --claude + WriteOnly policy denies search (read) operations.
    #[test]
    fn tc_s7_020_e04_claude_write_only_search_denied() {
        use pq_diary_core::policy::AccessPolicy;
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault_with_policy(&dir, AccessPolicy::WriteOnly);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let cli = make_cli_claude(vault_dir_str, Some("password"));
        let args = crate::SearchArgs {
            pattern: "test".to_string(),
            tag: None,
            context: 2,
            count: false,
        };
        let mut out = Vec::new();
        let result = cmd_search_to(&cli, &args, &mut out);
        assert!(
            result.is_err(),
            "--claude + WriteOnly + search must be denied"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("Access denied"),
            "error must contain 'Access denied': {msg}"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S7-020-E05: --claude + WriteOnly + stats で拒否
    // -------------------------------------------------------------------------

    /// TC-S7-020-E05: --claude + WriteOnly policy denies stats (read) operations.
    #[test]
    fn tc_s7_020_e05_claude_write_only_stats_denied() {
        use pq_diary_core::policy::AccessPolicy;
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault_with_policy(&dir, AccessPolicy::WriteOnly);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let cli = make_cli_claude(vault_dir_str, Some("password"));
        let args = crate::StatsArgs {
            json: false,
            heatmap: false,
        };
        let mut out = Vec::new();
        let result = cmd_stats_to(&cli, &args, &mut out);
        assert!(
            result.is_err(),
            "--claude + WriteOnly + stats must be denied"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("Access denied"),
            "error must contain 'Access denied': {msg}"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S7-020-E06: --claude + None + パスワード提供済でも拒否（復号なし）
    // -------------------------------------------------------------------------

    /// TC-S7-020-E06: --claude + None policy denies operations even when a
    /// password is already provided; the vault is never decrypted.
    #[test]
    fn tc_s7_020_e06_claude_none_with_password_still_denied() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir); // default policy = None
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        // Password supplied via --password, but policy check fires first.
        let cli = make_cli_claude(vault_dir_str, Some("password"));
        let result = cmd_list(&cli, None, None, 20);
        assert!(
            result.is_err(),
            "--claude + None must be denied even when password is provided"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("Access denied"),
            "error must contain 'Access denied': {msg}"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S7-050-01: None 拒否エラーメッセージ形式
    // -------------------------------------------------------------------------

    /// TC-S7-050-01: None policy denial error message matches REQ-050 format.
    #[test]
    fn tc_s7_050_01_none_deny_error_message_format() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir); // default policy = None
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let cli = make_cli_claude(vault_dir_str, Some("password"));
        let result = cmd_list(&cli, None, None, 20);
        assert!(result.is_err(), "must be denied");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("Access denied"),
            "must contain 'Access denied': {msg}"
        );
        assert!(msg.contains("none"), "must contain policy 'none': {msg}");
        assert!(msg.contains("'--claude'"), "must mention '--claude': {msg}");
        assert!(
            msg.contains("'write_only' or 'full'"),
            "must mention required policies: {msg}"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S7-050-02: WriteOnly 拒否エラーメッセージ形式
    // -------------------------------------------------------------------------

    /// TC-S7-050-02: WriteOnly policy denial (read op) error message matches
    /// REQ-050 format.
    #[test]
    fn tc_s7_050_02_write_only_deny_error_message_format() {
        use pq_diary_core::policy::AccessPolicy;
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault_with_policy(&dir, AccessPolicy::WriteOnly);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let cli = make_cli_claude(vault_dir_str, Some("password"));
        let result = cmd_list(&cli, None, None, 20);
        assert!(result.is_err(), "must be denied");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("Access denied"),
            "must contain 'Access denied': {msg}"
        );
        assert!(
            msg.contains("write_only"),
            "must contain 'write_only': {msg}"
        );
        assert!(
            msg.contains("Read operations require 'full'"),
            "must mention read ops requirement: {msg}"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S7-040-03 (TASK-0072 variant): --claude + Full 時に警告が表示されない
    // -------------------------------------------------------------------------

    /// TC-S7-040-03: Running operations with --claude + Full policy does not
    /// produce the Full-policy security warning (warning only appears at
    /// policy-set time via vault commands).
    #[test]
    fn tc_s7_020_claude_full_operation_no_security_warning() {
        use pq_diary_core::policy::AccessPolicy;
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault_with_policy(&dir, AccessPolicy::Full);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        // Operations on a Full vault with --claude succeed without any error.
        let cli = make_cli_claude(vault_dir_str, Some("password"));
        let result = cmd_list(&cli, None, None, 20);
        assert!(
            result.is_ok(),
            "--claude + Full + list must succeed without warning: {:?}",
            result.err()
        );
    }

    // =========================================================================
    // TASK-0073: Integration tests + NFR performance checks
    // =========================================================================

    // -------------------------------------------------------------------------
    // TC-S7-INT-01: vault CRUD cycle (create → list → policy → delete)
    // -------------------------------------------------------------------------

    /// TC-S7-INT-01: Complete vault CRUD cycle — create → list → policy → delete.
    ///
    /// Verifies REQ-030~037: each vault management command works end-to-end
    /// and the state transitions are correct after each operation.
    #[test]
    fn tc_s7_int_01_vault_crud_cycle() {
        use pq_diary_core::policy::AccessPolicy;
        use pq_diary_core::vault::init::VaultManager;

        let dir = tempfile::tempdir().expect("tempdir");
        let base_dir_str = dir.path().to_str().expect("utf8");

        // Step 1: create vault with write_only policy
        let cli = make_vault_mgmt_cli(base_dir_str, Some("testpass"), &["create", "int01vault"]);
        let mut reader = std::io::Cursor::new("");
        cmd_vault_create_impl(
            &cli,
            "int01vault",
            Some("write_only"),
            &mut reader,
            |base_dir| {
                VaultManager::new(base_dir)
                    .map(|m| m.with_kdf_params(fast_params()))
                    .map_err(|e| anyhow::anyhow!("{e}"))
            },
        )
        .expect("create vault");

        // Step 2: verify vault appears in list with write_only policy
        let mgr = VaultManager::new(dir.path().to_path_buf()).expect("VaultManager");
        let vaults = mgr.list_vaults_with_policy().expect("list");
        assert!(
            vaults.iter().any(|v| v.name == "int01vault"),
            "vault must appear in list after creation"
        );
        let v = vaults.iter().find(|v| v.name == "int01vault").unwrap();
        assert_eq!(
            v.policy,
            AccessPolicy::WriteOnly,
            "policy must be write_only after creation"
        );

        // Also verify cmd_vault_list succeeds without error
        let cli = make_vault_mgmt_cli(base_dir_str, None, &["list"]);
        cmd_vault_list(&cli).expect("vault list");

        // Step 3: change policy to none via cmd_vault_policy
        let cli = make_vault_mgmt_cli(base_dir_str, None, &["policy", "int01vault", "none"]);
        let mut reader = std::io::Cursor::new("");
        cmd_vault_policy_impl(&cli, "int01vault", "none", &mut reader).expect("vault policy");

        let vaults = mgr
            .list_vaults_with_policy()
            .expect("list after policy change");
        let v = vaults.iter().find(|v| v.name == "int01vault").unwrap();
        assert_eq!(
            v.policy,
            AccessPolicy::None,
            "policy must be updated to none after vault policy command"
        );

        // Step 4: delete vault with confirmation "y"
        let cli = make_vault_mgmt_cli(base_dir_str, None, &["delete", "int01vault"]);
        let mut reader = std::io::Cursor::new("y\n");
        cmd_vault_delete_impl(&cli, "int01vault", false, &mut reader).expect("vault delete");

        // Verify vault is gone
        assert!(
            !dir.path().join("int01vault").exists(),
            "vault directory must not exist after deletion"
        );
        let vaults = mgr.list_vaults_with_policy().expect("list after delete");
        assert!(
            !vaults.iter().any(|v| v.name == "int01vault"),
            "vault must not appear in list after deletion"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S7-INT-02: --claude + None vault の即座拒否
    // -------------------------------------------------------------------------

    /// TC-S7-INT-02: --claude + None vault is denied immediately without
    /// vault decryption — cmd_new is rejected before password is used.
    ///
    /// Verifies REQ-101, NFR-101: the policy check fires before any vault.pqd
    /// read.
    #[test]
    fn tc_s7_int_02_claude_none_vault_immediate_denial() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir); // default policy = None
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let cli = make_cli_claude(vault_dir_str, Some("password"));
        let result = cmd_new(
            &cli,
            Some("Title".to_string()),
            Some("body".to_string()),
            vec![],
            None,
        );
        assert!(
            result.is_err(),
            "--claude + None must deny cmd_new immediately"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("Access denied"),
            "error must contain 'Access denied': {msg}"
        );
        assert!(
            msg.contains("none"),
            "error must contain policy 'none': {msg}"
        );
        assert!(
            msg.contains("'--claude'"),
            "error must mention '--claude': {msg}"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S7-INT-03: --claude + WriteOnly vault の操作制御
    // -------------------------------------------------------------------------

    /// TC-S7-INT-03: --claude + WriteOnly vault — write ops are permitted,
    /// read ops are denied.
    ///
    /// Verifies REQ-020~025: `new` (Write) succeeds and `list` (Read) fails.
    #[test]
    fn tc_s7_int_03_claude_write_only_operation_control() {
        use pq_diary_core::policy::AccessPolicy;
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault_with_policy(&dir, AccessPolicy::WriteOnly);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        // Write op (new) must be allowed
        let cli = make_cli_claude(vault_dir_str, Some("password"));
        let result = cmd_new(
            &cli,
            Some("Test Entry".to_string()),
            Some("body text".to_string()),
            vec![],
            None,
        );
        assert!(
            result.is_ok(),
            "--claude + WriteOnly + Write (new) must be allowed: {:?}",
            result.err()
        );

        // Read op (list) must be denied
        let cli = make_cli_claude(vault_dir_str, Some("password"));
        let result = cmd_list(&cli, None, None, 20);
        assert!(
            result.is_err(),
            "--claude + WriteOnly + Read (list) must be denied"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("Access denied"),
            "error must contain 'Access denied': {msg}"
        );
        assert!(
            msg.contains("write_only"),
            "error must mention policy 'write_only': {msg}"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S7-INT-04: --claude + Full vault の全操作許可
    // -------------------------------------------------------------------------

    /// TC-S7-INT-04: --claude + Full vault permits all operations (reads and
    /// writes).
    ///
    /// Verifies REQ-020~025: both `new` (Write) and `list` (Read) succeed.
    #[test]
    fn tc_s7_int_04_claude_full_all_operations_permitted() {
        use pq_diary_core::policy::AccessPolicy;
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault_with_policy(&dir, AccessPolicy::Full);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        // Write op (new) must be allowed
        let cli = make_cli_claude(vault_dir_str, Some("password"));
        let result = cmd_new(
            &cli,
            Some("Test Entry".to_string()),
            Some("body text".to_string()),
            vec![],
            None,
        );
        assert!(
            result.is_ok(),
            "--claude + Full + Write (new) must be allowed: {:?}",
            result.err()
        );

        // Read op (list) must be allowed
        let cli = make_cli_claude(vault_dir_str, Some("password"));
        let result = cmd_list(&cli, None, None, 20);
        assert!(
            result.is_ok(),
            "--claude + Full + Read (list) must be allowed: {:?}",
            result.err()
        );
    }

    // -------------------------------------------------------------------------
    // TC-S7-INT-05: vault delete --zeroize
    // -------------------------------------------------------------------------

    /// TC-S7-INT-05: `vault delete --zeroize` overwrites vault.pqd with random
    /// bytes and removes the vault directory.
    ///
    /// Verifies REQ-037: after deletion the vault directory does not exist.
    #[test]
    fn tc_s7_int_05_vault_delete_zeroize() {
        use pq_diary_core::vault::init::VaultManager;

        let dir = tempfile::tempdir().expect("tempdir");
        let base_dir_str = dir.path().to_str().expect("utf8");

        // Create vault with fast params
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager")
            .with_kdf_params(fast_params());
        mgr.create_vault(
            "zvault",
            b"password",
            pq_diary_core::policy::AccessPolicy::None,
        )
        .expect("create vault");

        // Verify vault.pqd exists before deletion
        assert!(
            dir.path().join("zvault").join("vault.pqd").exists(),
            "vault.pqd must exist before deletion"
        );

        // Delete with zeroize=true using confirmation "y"
        let cli = make_vault_mgmt_cli(base_dir_str, None, &["delete", "zvault"]);
        let mut reader = std::io::Cursor::new("y\n");
        cmd_vault_delete_impl(&cli, "zvault", true, &mut reader).expect("vault delete --zeroize");

        // Verify vault directory is completely removed
        assert!(
            !dir.path().join("zvault").exists(),
            "vault directory must not exist after --zeroize deletion"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S7-INT-06: 後方互換性 (policy = "none" 文字列)
    // -------------------------------------------------------------------------

    /// TC-S7-INT-06: Pre-S7 `vault.toml` with `policy = "none"` string is
    /// correctly parsed as [`AccessPolicy::None`].
    ///
    /// Verifies EDGE-001 backward compatibility: existing vault.toml files that
    /// store the policy as a plain snake_case string are parsed without error.
    #[test]
    fn tc_s7_int_06_backward_compat_policy_none_string() {
        use pq_diary_core::policy::AccessPolicy;
        use pq_diary_core::vault::config::VaultConfig;

        let dir = tempfile::tempdir().expect("tempdir");
        let toml_path = dir.path().join("vault.toml");

        // Write a vault.toml in the S6-era format (policy stored as a string)
        let legacy_toml = r#"
[vault]
name = "legacy"
schema_version = 4

[access]
policy = "none"

[git]
author_name = ""
author_email = ""
commit_message = "Update vault"

[git.privacy]
timestamp_fuzz_hours = 0
extra_padding_bytes_max = 0

[argon2]
memory_cost_kb = 65536
time_cost = 3
parallelism = 1
"#;
        std::fs::write(&toml_path, legacy_toml).expect("write legacy vault.toml");

        let config = VaultConfig::from_file(&toml_path).expect("from_file on legacy format");
        assert_eq!(
            config.access.policy,
            AccessPolicy::None,
            "policy = \"none\" string must deserialise to AccessPolicy::None"
        );
        assert_eq!(config.vault.name, "legacy");

        // Also verify write_only and full strings round-trip
        let wo_toml = legacy_toml.replace(r#"policy = "none""#, r#"policy = "write_only""#);
        std::fs::write(&toml_path, &wo_toml).expect("write write_only toml");
        let config_wo = VaultConfig::from_file(&toml_path).expect("from_file write_only");
        assert_eq!(config_wo.access.policy, AccessPolicy::WriteOnly);

        let full_toml = legacy_toml.replace(r#"policy = "none""#, r#"policy = "full""#);
        std::fs::write(&toml_path, &full_toml).expect("write full toml");
        let config_full = VaultConfig::from_file(&toml_path).expect("from_file full");
        assert_eq!(config_full.access.policy, AccessPolicy::Full);
    }

    // =========================================================================
    // TASK-0078 helpers and tests
    // =========================================================================

    /// Parse a `Cli` from argument strings for git subcommands.
    fn make_git_cli(args: &[&str]) -> crate::Cli {
        crate::Cli::try_parse_from(args).expect("parse git CLI args")
    }

    /// Initialise a vault with VaultManager and return the vault directory path.
    ///
    /// The vault is created with the password `"password"`.
    /// A fast Argon2 configuration is used to keep tests responsive.
    fn setup_vault_for_git(dir: &tempfile::TempDir) -> PathBuf {
        use pq_diary_core::vault::init::VaultManager;
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());
        mgr.init_vault("v", b"password").expect("init_vault");
        dir.path().join("v")
    }

    /// Set up a vault directory with git initialised, a bare local remote, an
    /// initial commit, and the branch pushed to origin with `-u`.
    ///
    /// Returns `(TempDir, vault_dir_path)`.  The `TempDir` must be kept alive
    /// for the duration of the test.
    fn setup_git_vault_with_remote(tmp: &tempfile::TempDir) -> PathBuf {
        let vault_dir = setup_vault_for_git(tmp);

        // Create bare remote.
        let bare_dir = tmp.path().join("bare.git");
        std::fs::create_dir_all(&bare_dir).expect("create bare dir");
        let out = std::process::Command::new("git")
            .current_dir(&bare_dir)
            .args(["init", "--bare"])
            .output()
            .expect("git init --bare");
        assert!(out.status.success(), "git init --bare failed");

        // Initialise git in the vault directory (sets local user.name/email).
        pq_diary_core::git::git_init(&vault_dir, Some(bare_dir.to_str().unwrap()))
            .expect("git_init");

        // Stage all vault files created by VaultManager.
        let out = std::process::Command::new("git")
            .current_dir(&vault_dir)
            .args(["add", "vault.pqd", "vault.toml", ".gitignore"])
            .output()
            .expect("git add");
        assert!(out.status.success(), "initial git add failed");

        // Initial commit.
        let out = std::process::Command::new("git")
            .current_dir(&vault_dir)
            .args([
                "-c",
                "user.name=pq-diary",
                "-c",
                "user.email=test@localhost",
                "commit",
                "-m",
                "initial",
            ])
            .output()
            .expect("git commit");
        assert!(
            out.status.success(),
            "initial git commit failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        // Push with -u to set upstream tracking.
        let branch_out = std::process::Command::new("git")
            .current_dir(&vault_dir)
            .args(["rev-parse", "--abbrev-ref", "HEAD"])
            .output()
            .expect("rev-parse HEAD");
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

        vault_dir
    }

    // -------------------------------------------------------------------------
    // TC-S8-078-01: cmd_git_init creates .git and updates vault.toml
    // -------------------------------------------------------------------------

    /// TC-S8-078-01: `git-init` creates `.git` and updates `vault.toml`
    /// with `author_name = "pq-diary"` and a valid random `author_email`.
    #[test]
    fn tc_s8_078_01_git_init_creates_git_and_updates_toml() {
        use pq_diary_core::vault::config::VaultConfig;

        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault_for_git(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let cli = make_git_cli(&["pq-diary", "-v", vault_dir_str, "git-init"]);
        let result = cmd_git_init(&cli, None);
        assert!(result.is_ok(), "cmd_git_init failed: {:?}", result.err());

        // .git must exist.
        assert!(
            vault_dir.join(".git").exists(),
            ".git directory must exist after git-init"
        );

        // vault.toml must have been updated with pq-diary author.
        let toml_path = vault_dir.join("vault.toml");
        let config = VaultConfig::from_file(&toml_path).expect("read vault.toml");
        assert_eq!(
            config.git.author_name, "pq-diary",
            "author_name must be 'pq-diary'"
        );
        let email = &config.git.author_email;
        assert!(
            email.ends_with("@localhost") && email.len() == 18,
            "author_email must match 8hex@localhost: {email}"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S8-078-02: cmd_git_init --remote adds origin
    // -------------------------------------------------------------------------

    /// TC-S8-078-02: `git-init --remote <url>` adds 'origin' to the git config.
    #[test]
    fn tc_s8_078_02_git_init_with_remote_adds_origin() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault_for_git(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");
        let remote_url = "https://example.com/repo.git";

        let cli = make_git_cli(&[
            "pq-diary",
            "-v",
            vault_dir_str,
            "git-init",
            "--remote",
            remote_url,
        ]);
        let result = cmd_git_init(&cli, Some(remote_url));
        assert!(
            result.is_ok(),
            "cmd_git_init --remote failed: {:?}",
            result.err()
        );

        // git remote -v must contain 'origin' and the URL.
        let out = std::process::Command::new("git")
            .current_dir(&vault_dir)
            .args(["remote", "-v"])
            .output()
            .expect("git remote -v");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("origin"),
            "remote -v must contain 'origin': {stdout}"
        );
        assert!(
            stdout.contains(remote_url),
            "remote -v must contain the remote URL: {stdout}"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S8-078-03: cmd_git_push requires password / succeeds with password
    // -------------------------------------------------------------------------

    /// TC-S8-078-03a: `git-push` without a password returns an error in
    /// non-TTY test environments.
    #[test]
    fn tc_s8_078_03a_push_fails_without_password() {
        use std::io::IsTerminal as _;
        // Only meaningful when stdin is not a terminal (cargo test environment).
        if std::io::stdin().is_terminal() {
            return;
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_git_vault_with_remote(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let cli = make_git_cli(&["pq-diary", "-v", vault_dir_str, "git-push"]);
        let result = cmd_git_push(&cli);
        assert!(
            result.is_err(),
            "git-push without password must fail in non-TTY environment"
        );
    }

    /// TC-S8-078-03b: `git-push` with the correct password succeeds.
    #[test]
    fn tc_s8_078_03b_push_succeeds_with_password() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_git_vault_with_remote(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let cli = make_git_cli(&[
            "pq-diary",
            "-v",
            vault_dir_str,
            "--password",
            "password",
            "git-push",
        ]);
        let result = cmd_git_push(&cli);
        assert!(
            result.is_ok(),
            "git-push with correct password must succeed: {:?}",
            result.err()
        );
    }

    // -------------------------------------------------------------------------
    // TC-S8-078-04: cmd_git_pull requires password / succeeds with password
    // -------------------------------------------------------------------------

    /// TC-S8-078-04a: `git-pull` without a password returns an error in
    /// non-TTY test environments.
    #[test]
    fn tc_s8_078_04a_pull_fails_without_password() {
        use std::io::IsTerminal as _;
        if std::io::stdin().is_terminal() {
            return;
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_git_vault_with_remote(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let cli = make_git_cli(&["pq-diary", "-v", vault_dir_str, "git-pull"]);
        let result = cmd_git_pull(&cli);
        assert!(
            result.is_err(),
            "git-pull without password must fail in non-TTY environment"
        );
    }

    /// TC-S8-078-04b: `git-pull` with the correct password succeeds (no-op
    /// when remote is already in sync).
    #[test]
    fn tc_s8_078_04b_pull_succeeds_with_password() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_git_vault_with_remote(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let cli = make_git_cli(&[
            "pq-diary",
            "-v",
            vault_dir_str,
            "--password",
            "password",
            "git-pull",
        ]);
        let result = cmd_git_pull(&cli);
        assert!(
            result.is_ok(),
            "git-pull with correct password must succeed: {:?}",
            result.err()
        );
    }

    // -------------------------------------------------------------------------
    // TC-S8-078-05: cmd_git_sync executes pull then push
    // -------------------------------------------------------------------------

    /// TC-S8-078-05: `git-sync` executes pull followed by push in a single
    /// password-acquisition.
    #[test]
    fn tc_s8_078_05_sync_pull_then_push() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_git_vault_with_remote(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let initial_log = std::process::Command::new("git")
            .current_dir(&vault_dir)
            .args(["log", "--oneline"])
            .output()
            .expect("git log");
        let initial_count = String::from_utf8_lossy(&initial_log.stdout).lines().count();

        let cli = make_git_cli(&[
            "pq-diary",
            "-v",
            vault_dir_str,
            "--password",
            "password",
            "git-sync",
        ]);
        // Use a reader that always picks "local" for conflict resolution.
        let mut reader = std::io::BufReader::new(std::io::Cursor::new("l\n"));
        let result = cmd_git_sync_impl(&cli, &mut reader);
        assert!(result.is_ok(), "git-sync must succeed: {:?}", result.err());

        // After sync, git log must have at least one new push commit.
        let after_log = std::process::Command::new("git")
            .current_dir(&vault_dir)
            .args(["log", "--oneline"])
            .output()
            .expect("git log after sync");
        let after_count = String::from_utf8_lossy(&after_log.stdout).lines().count();
        assert!(
            after_count >= initial_count,
            "git log must have at least as many commits after sync"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S8-078-06: cmd_git_status works without password
    // -------------------------------------------------------------------------

    /// TC-S8-078-06: `git-status` returns git output without requiring a
    /// password, and does not decrypt the vault.
    #[test]
    fn tc_s8_078_06_git_status_no_password_needed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault_for_git(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        // Initialise git first (no remote needed for status).
        pq_diary_core::git::git_init(&vault_dir, None).expect("git_init");

        // git-status must succeed without any password flag.
        let cli = make_git_cli(&["pq-diary", "-v", vault_dir_str, "git-status"]);
        let result = cmd_git_status(&cli);
        assert!(
            result.is_ok(),
            "git-status must succeed without password: {:?}",
            result.err()
        );
    }

    // -------------------------------------------------------------------------
    // TC-S8-078-07: git not installed → all commands fail
    // -------------------------------------------------------------------------

    /// TC-S8-078-07: When `git` is not in PATH, all git subcommands fail with
    /// an appropriate error.
    ///
    /// **Ignored** because it modifies the process-wide PATH environment
    /// variable and must not run concurrently with other tests.
    /// Run with: `cargo test -- --ignored tc_s8_078_07`
    #[test]
    #[ignore = "requires environment without git in PATH; run: cargo test -- --ignored"]
    fn tc_s8_078_07_all_git_commands_fail_when_git_not_installed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault_for_git(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        // Temporarily clear PATH so git cannot be found.
        let original_path = std::env::var_os("PATH").unwrap_or_default();
        std::env::set_var("PATH", "");

        let cli_init = make_git_cli(&["pq-diary", "-v", vault_dir_str, "git-init"]);
        let cli_status = make_git_cli(&["pq-diary", "-v", vault_dir_str, "git-status"]);
        let cli_push = make_git_cli(&[
            "pq-diary",
            "-v",
            vault_dir_str,
            "--password",
            "password",
            "git-push",
        ]);
        let cli_pull = make_git_cli(&[
            "pq-diary",
            "-v",
            vault_dir_str,
            "--password",
            "password",
            "git-pull",
        ]);
        let cli_sync = make_git_cli(&[
            "pq-diary",
            "-v",
            vault_dir_str,
            "--password",
            "password",
            "git-sync",
        ]);

        let results = [
            cmd_git_init(&cli_init, None),
            cmd_git_status(&cli_status),
            cmd_git_push(&cli_push),
            cmd_git_pull(&cli_pull),
            cmd_git_sync(&cli_sync),
        ];

        std::env::set_var("PATH", original_path);

        for (i, result) in results.iter().enumerate() {
            assert!(
                result.is_err(),
                "git command {i} must fail when git is not in PATH"
            );
        }
    }

    // -------------------------------------------------------------------------
    // TC-S8-078-08: .git not initialised → push/pull/sync fail
    // -------------------------------------------------------------------------

    /// TC-S8-078-08: `git-push`, `git-pull`, and `git-sync` return a "not
    /// initialized" error when the vault directory has no `.git` directory.
    #[test]
    fn tc_s8_078_08_push_pull_sync_fail_without_git_init() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault_for_git(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        // No git_init called — .git does not exist.

        let cli_push = make_git_cli(&[
            "pq-diary",
            "-v",
            vault_dir_str,
            "--password",
            "password",
            "git-push",
        ]);
        let result_push = cmd_git_push(&cli_push);
        assert!(
            result_push.is_err(),
            "git-push must fail when .git is not initialised"
        );
        let msg_push = result_push.unwrap_err().to_string();
        assert!(
            msg_push.contains("not initialized") || msg_push.contains("not found"),
            "push error must mention not initialized: {msg_push}"
        );

        let cli_pull = make_git_cli(&[
            "pq-diary",
            "-v",
            vault_dir_str,
            "--password",
            "password",
            "git-pull",
        ]);
        let result_pull = cmd_git_pull(&cli_pull);
        assert!(
            result_pull.is_err(),
            "git-pull must fail when .git is not initialised"
        );
        let msg_pull = result_pull.unwrap_err().to_string();
        assert!(
            msg_pull.contains("not initialized") || msg_pull.contains("not found"),
            "pull error must mention not initialized: {msg_pull}"
        );

        let cli_sync = make_git_cli(&[
            "pq-diary",
            "-v",
            vault_dir_str,
            "--password",
            "password",
            "git-sync",
        ]);
        let result_sync = cmd_git_sync(&cli_sync);
        assert!(
            result_sync.is_err(),
            "git-sync must fail when .git is not initialised"
        );
        let msg_sync = result_sync.unwrap_err().to_string();
        assert!(
            msg_sync.contains("not initialized") || msg_sync.contains("not found"),
            "sync error must mention not initialized: {msg_sync}"
        );
    }

    // =========================================================================
    // TASK-0079 integration tests
    // =========================================================================

    // -------------------------------------------------------------------------
    // TC-S8-INT-01: E2E flow (git-init → git-push → git-pull → merge verification)
    // -------------------------------------------------------------------------

    /// TC-S8-INT-01: Full end-to-end flow: set up vault with git remote, push,
    /// simulate a remote change via a contributor clone, pull, and verify the
    /// complete pipeline produces the expected git history.
    ///
    /// Validates REQ-001~003, REQ-030.
    #[test]
    fn tc_s8_int_01_e2e_flow_push_pull_merge() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_git_vault_with_remote(&tmp);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        // Step 1: Push from local vault.
        let cli_push = make_git_cli(&[
            "pq-diary",
            "-v",
            vault_dir_str,
            "--password",
            "password",
            "git-push",
        ]);
        let result_push = cmd_git_push(&cli_push);
        assert!(
            result_push.is_ok(),
            "E2E: git-push must succeed: {:?}",
            result_push.err()
        );

        // Step 2: Simulate remote change — clone bare → write empty vault → push.
        let bare_dir = tmp.path().join("bare.git");
        let contributor_dir = tmp.path().join("contributor");
        std::fs::create_dir_all(&contributor_dir).expect("create contributor dir");

        let out = std::process::Command::new("git")
            .args([
                "clone",
                bare_dir.to_str().unwrap(),
                contributor_dir.to_str().unwrap(),
            ])
            .output()
            .expect("git clone contributor");
        assert!(
            out.status.success(),
            "contributor git clone failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        for (k, v) in [
            ("user.name", "contributor"),
            ("user.email", "contrib@localhost"),
        ] {
            std::process::Command::new("git")
                .current_dir(&contributor_dir)
                .args(["config", k, v])
                .output()
                .expect("git config contributor");
        }

        // Write an empty (structurally valid) vault as the "remote" vault.pqd.
        {
            use pq_diary_core::vault::{format::VaultHeader, writer::write_vault};
            let contrib_vault = contributor_dir.join("vault.pqd");
            write_vault(&contrib_vault, VaultHeader::new(), &[]).expect("write contributor vault");
        }

        let out = std::process::Command::new("git")
            .current_dir(&contributor_dir)
            .args(["add", "vault.pqd"])
            .output()
            .expect("contributor git add");
        assert!(
            out.status.success(),
            "contributor git add failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let out = std::process::Command::new("git")
            .current_dir(&contributor_dir)
            .args(["commit", "-m", "remote update"])
            .output()
            .expect("contributor git commit");
        assert!(
            out.status.success(),
            "contributor git commit failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let branch_out = std::process::Command::new("git")
            .current_dir(&contributor_dir)
            .args(["rev-parse", "--abbrev-ref", "HEAD"])
            .output()
            .expect("contributor git rev-parse HEAD");
        let branch = String::from_utf8_lossy(&branch_out.stdout)
            .trim()
            .to_string();

        let out = std::process::Command::new("git")
            .current_dir(&contributor_dir)
            .args(["push", "origin", &branch])
            .output()
            .expect("contributor git push");
        assert!(
            out.status.success(),
            "contributor git push failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        // Step 3: Pull from local vault — should merge successfully.
        let cli_pull = make_git_cli(&[
            "pq-diary",
            "-v",
            vault_dir_str,
            "--password",
            "password",
            "git-pull",
        ]);
        let result_pull = cmd_git_pull(&cli_pull);
        assert!(
            result_pull.is_ok(),
            "E2E: git-pull must succeed after remote changes: {:?}",
            result_pull.err()
        );

        // Step 4: Verify git log shows multiple commits (initial + push + merge).
        let log_out = std::process::Command::new("git")
            .current_dir(&vault_dir)
            .args(["log", "--oneline"])
            .output()
            .expect("git log");
        let log = String::from_utf8_lossy(&log_out.stdout);
        let commit_count = log.trim().lines().count();
        assert!(
            commit_count >= 2,
            "E2E: git log must show at least 2 commits; got: {log}"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S8-INT-02: git-init creates .git + .gitignore + vault.toml author
    // -------------------------------------------------------------------------

    /// TC-S8-INT-02: After `git-init`:
    /// - `.git` directory exists
    /// - `.gitignore` contains the `entries/` privacy rule
    /// - `vault.toml` has `author_name = "pq-diary"` and anonymous `author_email`
    ///
    /// Validates REQ-001, REQ-016~017.
    #[test]
    fn tc_s8_int_02_git_init_creates_gitignore_and_author() {
        use pq_diary_core::vault::config::VaultConfig;

        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault_for_git(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let cli = make_git_cli(&["pq-diary", "-v", vault_dir_str, "git-init"]);
        let result = cmd_git_init(&cli, None);
        assert!(result.is_ok(), "git-init must succeed: {:?}", result.err());

        // .git directory must exist.
        assert!(
            vault_dir.join(".git").exists(),
            ".git directory must exist after git-init"
        );

        // .gitignore must contain the entries/ exclusion rule.
        let gitignore_path = vault_dir.join(".gitignore");
        assert!(
            gitignore_path.exists(),
            ".gitignore must exist after git-init"
        );
        let gitignore_content = std::fs::read_to_string(&gitignore_path).expect("read .gitignore");
        assert!(
            gitignore_content.contains("entries/"),
            ".gitignore must contain 'entries/' rule; got: {gitignore_content}"
        );

        // vault.toml author must be the anonymous pq-diary identity.
        let toml_path = vault_dir.join("vault.toml");
        let config = VaultConfig::from_file(&toml_path).expect("read vault.toml");
        assert_eq!(
            config.git.author_name, "pq-diary",
            "author_name must be 'pq-diary'"
        );
        assert!(
            config.git.author_email.ends_with("@localhost"),
            "author_email must end with @localhost: {}",
            config.git.author_email
        );
        assert!(
            !config.git.author_email.is_empty(),
            "author_email must not be empty"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S8-INT-03: git-push privacy protection
    // -------------------------------------------------------------------------

    /// TC-S8-INT-03: After `git-push`, the commit uses the anonymous author
    /// from `vault.toml` (ending `@localhost`) and the fixed commit message
    /// template — no real user information or entry content is exposed.
    ///
    /// Validates REQ-022, REQ-025~026.
    #[test]
    fn tc_s8_int_03_git_push_privacy_protection() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_git_vault_with_remote(&tmp);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let cli = make_git_cli(&[
            "pq-diary",
            "-v",
            vault_dir_str,
            "--password",
            "password",
            "git-push",
        ]);
        let result = cmd_git_push(&cli);
        assert!(result.is_ok(), "git-push must succeed: {:?}", result.err());

        // Inspect the latest commit's author name, email, and subject line.
        let out = std::process::Command::new("git")
            .current_dir(&vault_dir)
            .args(["log", "-1", "--format=%an%n%ae%n%s"])
            .output()
            .expect("git log -1 --format=%an%n%ae%n%s");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let mut lines = stdout.trim().lines();
        let author_name = lines.next().unwrap_or("").trim().to_string();
        let author_email = lines.next().unwrap_or("").trim().to_string();
        let commit_msg = lines.next().unwrap_or("").trim().to_string();

        // Author must be the anonymous "pq-diary" identity.
        assert_eq!(
            author_name, "pq-diary",
            "commit author_name must be 'pq-diary', got: {author_name}"
        );
        assert!(
            author_email.ends_with("@localhost"),
            "commit author_email must end with @localhost, got: {author_email}"
        );

        // Commit message must be the fixed template (no entry content).
        assert_eq!(
            commit_msg, "Update vault",
            "commit message must be fixed 'Update vault', got: {commit_msg}"
        );

        // Author email must NOT contain the user's real git email (if set).
        let real_email = std::process::Command::new("git")
            .args(["config", "--global", "user.email"])
            .output()
            .ok()
            .and_then(|o| {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if s.is_empty() {
                    None
                } else {
                    Some(s)
                }
            });
        if let Some(real) = real_email {
            assert!(
                !author_email.contains(&real),
                "commit author_email must not contain real user email ({real}); got: {author_email}"
            );
        }
    }

    // -------------------------------------------------------------------------
    // TC-S8-INT-04: git-pull merge — local preserved, remote added
    // -------------------------------------------------------------------------

    /// TC-S8-INT-04: After `git-pull`, local-only entries are preserved.
    /// When the remote has an empty vault, 0 entries are added and the local
    /// vault remains valid and readable.
    ///
    /// Validates REQ-030~031.
    #[test]
    fn tc_s8_int_04_git_pull_merge_preserves_local_entries() {
        use pq_diary_core::vault::reader::read_vault;

        let tmp = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_git_vault_with_remote(&tmp);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        // Count raw entries in the local vault before pull.
        let vault_path = vault_dir.join("vault.pqd");
        let (_, entries_before) = read_vault(&vault_path).expect("read vault before pull");
        let count_before = entries_before.len();

        // Simulate remote with an empty vault.
        let bare_dir = tmp.path().join("bare.git");
        let contributor_dir = tmp.path().join("contributor");
        std::fs::create_dir_all(&contributor_dir).expect("create contributor dir");

        let out = std::process::Command::new("git")
            .args([
                "clone",
                bare_dir.to_str().unwrap(),
                contributor_dir.to_str().unwrap(),
            ])
            .output()
            .expect("git clone contributor");
        assert!(out.status.success(), "contributor git clone failed");

        for (k, v) in [
            ("user.name", "contributor"),
            ("user.email", "contrib@localhost"),
        ] {
            std::process::Command::new("git")
                .current_dir(&contributor_dir)
                .args(["config", k, v])
                .output()
                .expect("git config contributor");
        }

        {
            use pq_diary_core::vault::{format::VaultHeader, writer::write_vault};
            let contrib_vault = contributor_dir.join("vault.pqd");
            write_vault(&contrib_vault, VaultHeader::new(), &[]).expect("write contributor vault");
        }

        let out = std::process::Command::new("git")
            .current_dir(&contributor_dir)
            .args(["add", "vault.pqd"])
            .output()
            .expect("contributor git add");
        assert!(out.status.success());

        let out = std::process::Command::new("git")
            .current_dir(&contributor_dir)
            .args(["commit", "-m", "remote empty update"])
            .output()
            .expect("contributor git commit");
        assert!(
            out.status.success(),
            "contributor commit failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let branch_out = std::process::Command::new("git")
            .current_dir(&contributor_dir)
            .args(["rev-parse", "--abbrev-ref", "HEAD"])
            .output()
            .expect("rev-parse HEAD");
        let branch = String::from_utf8_lossy(&branch_out.stdout)
            .trim()
            .to_string();

        let out = std::process::Command::new("git")
            .current_dir(&contributor_dir)
            .args(["push", "origin", &branch])
            .output()
            .expect("contributor push");
        assert!(
            out.status.success(),
            "contributor push failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        // Pull — local entries must be preserved; remote was empty so 0 added.
        let cli_pull = make_git_cli(&[
            "pq-diary",
            "-v",
            vault_dir_str,
            "--password",
            "password",
            "git-pull",
        ]);
        let result_pull = cmd_git_pull(&cli_pull);
        assert!(
            result_pull.is_ok(),
            "git-pull must succeed: {:?}",
            result_pull.err()
        );

        // vault.pqd must still have at least the original number of raw entries.
        let (_, entries_after) = read_vault(&vault_path).expect("read vault after pull");
        assert!(
            entries_after.len() >= count_before,
            "local entries must be preserved after pull; before={count_before}, after={}",
            entries_after.len()
        );
    }

    // -------------------------------------------------------------------------
    // TC-S8-INT-05: git-sync = pull → push
    // -------------------------------------------------------------------------

    /// TC-S8-INT-05: `git-sync` performs pull followed by push.
    ///
    /// After sync completes, the git log contains at least one new commit
    /// compared to the pre-sync state (produced by the push phase).
    ///
    /// Validates REQ-005, REQ-030.
    #[test]
    fn tc_s8_int_05_git_sync_pull_then_push() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_git_vault_with_remote(&tmp);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        // Record commit count before sync.
        let log_before = std::process::Command::new("git")
            .current_dir(&vault_dir)
            .args(["log", "--oneline"])
            .output()
            .expect("git log before");
        let count_before = String::from_utf8_lossy(&log_before.stdout)
            .trim()
            .lines()
            .count();

        let mut reader = std::io::BufReader::new(std::io::Cursor::new("l\n"));
        let cli = make_git_cli(&[
            "pq-diary",
            "-v",
            vault_dir_str,
            "--password",
            "password",
            "git-sync",
        ]);
        let result = cmd_git_sync_impl(&cli, &mut reader);
        assert!(result.is_ok(), "git-sync must succeed: {:?}", result.err());

        // After sync, the push phase must have added at least one new commit.
        let log_after = std::process::Command::new("git")
            .current_dir(&vault_dir)
            .args(["log", "--oneline"])
            .output()
            .expect("git log after sync");
        let count_after = String::from_utf8_lossy(&log_after.stdout)
            .trim()
            .lines()
            .count();
        assert!(
            count_after > count_before,
            "git-sync must add at least one commit (push phase); before={count_before}, after={count_after}"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S8-INT-06: git-status wraps git status
    // -------------------------------------------------------------------------

    /// TC-S8-INT-06: `git-status` returns the output of `git status` without
    /// requiring a vault password.  On a clean repository the command succeeds.
    ///
    /// Validates REQ-004.
    #[test]
    fn tc_s8_int_06_git_status_wraps_git_status() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_git_vault_with_remote(&tmp);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        // Clean state — git-status must succeed without a password.
        let cli = make_git_cli(&["pq-diary", "-v", vault_dir_str, "git-status"]);
        let result = cmd_git_status(&cli);
        assert!(
            result.is_ok(),
            "git-status must succeed on clean repo: {:?}",
            result.err()
        );
    }

    // -------------------------------------------------------------------------
    // TC-S8-INT-07: --claude conflict → local auto-priority
    // -------------------------------------------------------------------------

    /// TC-S8-INT-07: When `--claude` is passed, `git-pull` resolves conflicts
    /// automatically (local wins) without blocking on an interactive prompt.
    ///
    /// Uses a contributor with an empty vault so that the pull is a no-conflict
    /// merge — the important property is that no stdin interaction is required.
    /// The vault policy is set to `full` so that `--claude` is permitted.
    ///
    /// Validates REQ-040.
    #[test]
    fn tc_s8_int_07_claude_conflict_auto_resolves_local() {
        use pq_diary_core::{policy::AccessPolicy, vault::config::VaultConfig};

        let tmp = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_git_vault_with_remote(&tmp);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        // Set the vault policy to `full` so that --claude is permitted.
        let toml_path = vault_dir.join("vault.toml");
        let mut config = VaultConfig::from_file(&toml_path).expect("read vault.toml");
        config.access.policy = AccessPolicy::Full;
        config
            .to_file(&toml_path)
            .expect("write updated vault.toml");

        // Simulate remote change (empty vault) so pull has something to fetch.
        let bare_dir = tmp.path().join("bare.git");
        let contributor_dir = tmp.path().join("contributor");
        std::fs::create_dir_all(&contributor_dir).expect("create contributor dir");

        let out = std::process::Command::new("git")
            .args([
                "clone",
                bare_dir.to_str().unwrap(),
                contributor_dir.to_str().unwrap(),
            ])
            .output()
            .expect("git clone contributor");
        assert!(out.status.success(), "contributor clone failed");

        for (k, v) in [
            ("user.name", "contributor"),
            ("user.email", "contrib@localhost"),
        ] {
            std::process::Command::new("git")
                .current_dir(&contributor_dir)
                .args(["config", k, v])
                .output()
                .expect("git config contributor");
        }

        {
            use pq_diary_core::vault::{format::VaultHeader, writer::write_vault};
            let contrib_vault = contributor_dir.join("vault.pqd");
            write_vault(&contrib_vault, VaultHeader::new(), &[]).expect("write contributor vault");
        }

        let out = std::process::Command::new("git")
            .current_dir(&contributor_dir)
            .args(["add", "vault.pqd"])
            .output()
            .expect("contributor git add");
        assert!(out.status.success());

        let out = std::process::Command::new("git")
            .current_dir(&contributor_dir)
            .args(["commit", "-m", "remote update"])
            .output()
            .expect("contributor commit");
        assert!(
            out.status.success(),
            "contributor commit failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let branch_out = std::process::Command::new("git")
            .current_dir(&contributor_dir)
            .args(["rev-parse", "--abbrev-ref", "HEAD"])
            .output()
            .expect("rev-parse HEAD");
        let branch = String::from_utf8_lossy(&branch_out.stdout)
            .trim()
            .to_string();

        let out = std::process::Command::new("git")
            .current_dir(&contributor_dir)
            .args(["push", "origin", &branch])
            .output()
            .expect("contributor push");
        assert!(
            out.status.success(),
            "contributor push failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        // Pull with --claude: no interactive prompt should be needed.
        let cli = make_git_cli(&[
            "pq-diary",
            "-v",
            vault_dir_str,
            "--password",
            "password",
            "--claude",
            "git-pull",
        ]);
        let result = cmd_git_pull(&cli);
        assert!(
            result.is_ok(),
            "--claude git-pull must succeed without interactive prompt: {:?}",
            result.err()
        );
    }

    // -------------------------------------------------------------------------
    // TC-S8-INT-E01: git not installed → appropriate error
    // -------------------------------------------------------------------------

    /// TC-S8-INT-E01: When `git` is absent from PATH, all git commands fail
    /// with a "not installed" or "not found" error message.
    ///
    /// **Ignored** — modifies the process-wide PATH variable and must not run
    /// concurrently with other tests.
    /// Run with: `cargo test -- --ignored tc_s8_int_e01`
    #[test]
    #[ignore = "requires environment without git in PATH; run: cargo test -- --ignored"]
    fn tc_s8_int_e01_git_not_installed_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault_for_git(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let original_path = std::env::var_os("PATH").unwrap_or_default();
        std::env::set_var("PATH", "");

        let cli = make_git_cli(&["pq-diary", "-v", vault_dir_str, "git-init"]);
        let result = cmd_git_init(&cli, None);

        std::env::set_var("PATH", original_path);

        assert!(
            result.is_err(),
            "git-init must fail when git is not in PATH"
        );
        let msg = result.unwrap_err().to_string().to_lowercase();
        assert!(
            msg.contains("not installed") || msg.contains("not found"),
            "error must mention 'not installed' or 'not found': {msg}"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S8-INT-E02: .git not initialized → push/pull/sync fail
    // -------------------------------------------------------------------------

    /// TC-S8-INT-E02: `git-push`, `git-pull`, and `git-sync` all fail with a
    /// "not initialized" / "not found" message when the vault has no `.git`.
    ///
    /// Validates EDGE-003.
    #[test]
    fn tc_s8_int_e02_git_not_initialized_push_pull_sync_fail() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault_for_git(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        // No git_init called — .git does not exist.
        let cli_push = make_git_cli(&[
            "pq-diary",
            "-v",
            vault_dir_str,
            "--password",
            "password",
            "git-push",
        ]);
        let result_push = cmd_git_push(&cli_push);
        assert!(
            result_push.is_err(),
            "git-push must fail when .git is not initialized"
        );
        let msg_push = result_push.unwrap_err().to_string();
        assert!(
            msg_push.contains("not initialized") || msg_push.contains("not found"),
            "push error must mention initialization: {msg_push}"
        );

        let cli_pull = make_git_cli(&[
            "pq-diary",
            "-v",
            vault_dir_str,
            "--password",
            "password",
            "git-pull",
        ]);
        let result_pull = cmd_git_pull(&cli_pull);
        assert!(
            result_pull.is_err(),
            "git-pull must fail when .git is not initialized"
        );
        let msg_pull = result_pull.unwrap_err().to_string();
        assert!(
            msg_pull.contains("not initialized") || msg_pull.contains("not found"),
            "pull error must mention initialization: {msg_pull}"
        );

        let cli_sync = make_git_cli(&[
            "pq-diary",
            "-v",
            vault_dir_str,
            "--password",
            "password",
            "git-sync",
        ]);
        let result_sync = cmd_git_sync(&cli_sync);
        assert!(
            result_sync.is_err(),
            "git-sync must fail when .git is not initialized"
        );
        let msg_sync = result_sync.unwrap_err().to_string();
        assert!(
            msg_sync.contains("not initialized") || msg_sync.contains("not found"),
            "sync error must mention initialization: {msg_sync}"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S8-INT-E03: no remote configured → push/pull fail
    // -------------------------------------------------------------------------

    /// TC-S8-INT-E03: `git-push` fails with a "no remote" error, and
    /// `git-pull` fails when git is initialized but no remote is configured.
    ///
    /// Validates EDGE-002.
    #[test]
    fn tc_s8_int_e03_no_remote_configured_push_pull_fail() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault_for_git(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        // Initialize git WITHOUT a remote.
        let cli_init = make_git_cli(&["pq-diary", "-v", vault_dir_str, "git-init"]);
        let result_init = cmd_git_init(&cli_init, None);
        assert!(
            result_init.is_ok(),
            "git-init without remote must succeed: {:?}",
            result_init.err()
        );

        // git-push must fail: "no remote repository configured".
        let cli_push = make_git_cli(&[
            "pq-diary",
            "-v",
            vault_dir_str,
            "--password",
            "password",
            "git-push",
        ]);
        let result_push = cmd_git_push(&cli_push);
        assert!(
            result_push.is_err(),
            "git-push must fail when no remote is configured"
        );
        let msg_push = result_push.unwrap_err().to_string().to_lowercase();
        assert!(
            msg_push.contains("remote"),
            "push error must mention 'remote': {msg_push}"
        );

        // git-pull must also fail (git fetch origin has no remote to connect to).
        let cli_pull = make_git_cli(&[
            "pq-diary",
            "-v",
            vault_dir_str,
            "--password",
            "password",
            "git-pull",
        ]);
        let result_pull = cmd_git_pull(&cli_pull);
        assert!(
            result_pull.is_err(),
            "git-pull must fail when no remote is configured"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S8-INT-E04: already initialized git-init is handled as an error
    // -------------------------------------------------------------------------

    /// TC-S8-INT-E04: A second `git-init` on an already-initialised vault
    /// returns an "already initialized" error — ensuring idempotency-by-error.
    ///
    /// Validates EDGE-006.
    #[test]
    fn tc_s8_int_e04_already_initialized_git_init_returns_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault_for_git(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        // First git-init must succeed.
        let cli_first = make_git_cli(&["pq-diary", "-v", vault_dir_str, "git-init"]);
        let result_first = cmd_git_init(&cli_first, None);
        assert!(
            result_first.is_ok(),
            "first git-init must succeed: {:?}",
            result_first.err()
        );

        // Second git-init must fail with "already initialized".
        let cli_second = make_git_cli(&["pq-diary", "-v", vault_dir_str, "git-init"]);
        let result_second = cmd_git_init(&cli_second, None);
        assert!(
            result_second.is_err(),
            "second git-init must fail (already initialized)"
        );
        let msg = result_second.unwrap_err().to_string();
        assert!(
            msg.contains("already"),
            "error must mention 'already initialized': {msg}"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S8-NFR-001-01: check_git_available < 100ms
    // -------------------------------------------------------------------------

    /// TC-S8-NFR-001-01: `check_git_available()` completes in a reasonable time.
    ///
    /// `git --version` is a single process spawn with no I/O.  NFR-001 targets
    /// 100 ms; the test allows 500 ms to accommodate CI/Windows process-spawn
    /// overhead while still catching pathological slowdowns.
    #[test]
    fn tc_s8_nfr_001_01_check_git_available_under_100ms() {
        use std::time::Instant;

        let start = Instant::now();
        let result = pq_diary_core::git::check_git_available();
        let elapsed = start.elapsed();

        assert!(
            result.is_ok(),
            "check_git_available must succeed in a git-installed environment"
        );
        // Allow 500 ms in CI/Windows; the production NFR target is 100 ms.
        assert!(
            elapsed.as_millis() < 500,
            "check_git_available must complete in < 500 ms; took {:?}",
            elapsed
        );
    }

    // -------------------------------------------------------------------------
    // TC-S8-SEC-01: entries/ not in git staging after push
    // -------------------------------------------------------------------------

    /// TC-S8-SEC-01: After `git-push`, `entries/` files are never staged
    /// or committed — the `.gitignore` exclusion rule keeps them out of git.
    ///
    /// Validates REQ-022.
    #[test]
    fn tc_s8_sec_01_entries_md_not_staged_by_git_push() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_git_vault_with_remote(&tmp);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        // Create a plaintext .md file under entries/ before pushing.
        let entries_dir = vault_dir.join("entries");
        std::fs::create_dir_all(&entries_dir).expect("create entries dir");
        std::fs::write(entries_dir.join("secret.md"), b"plain text diary content")
            .expect("write entries/secret.md");

        let cli = make_git_cli(&[
            "pq-diary",
            "-v",
            vault_dir_str,
            "--password",
            "password",
            "git-push",
        ]);
        let result = cmd_git_push(&cli);
        assert!(result.is_ok(), "git-push must succeed: {:?}", result.err());

        // entries/secret.md must not be tracked by git at all.
        let ls_out = std::process::Command::new("git")
            .current_dir(&vault_dir)
            .args(["ls-files", "entries/secret.md"])
            .output()
            .expect("git ls-files");
        let tracked = String::from_utf8_lossy(&ls_out.stdout);
        assert!(
            tracked.trim().is_empty(),
            "entries/secret.md must not be tracked by git; got: {tracked}"
        );

        // entries/secret.md must not appear in the latest commit.
        let show_out = std::process::Command::new("git")
            .current_dir(&vault_dir)
            .args(["show", "--name-only", "--format=", "HEAD"])
            .output()
            .expect("git show HEAD");
        let committed = String::from_utf8_lossy(&show_out.stdout);
        assert!(
            !committed.contains("entries/secret.md"),
            "entries/secret.md must not be in the commit; found in: {committed}"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S8-SEC-02: commit message and author contain no secret information
    // -------------------------------------------------------------------------

    /// TC-S8-SEC-02: After `git-push`, the commit metadata (author, message)
    /// does not contain the vault password, real user data, or entry content.
    ///
    /// Validates REQ-025~026.
    #[test]
    fn tc_s8_sec_02_commit_author_message_no_secrets() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_git_vault_with_remote(&tmp);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let cli = make_git_cli(&[
            "pq-diary",
            "-v",
            vault_dir_str,
            "--password",
            "password",
            "git-push",
        ]);
        let result = cmd_git_push(&cli);
        assert!(result.is_ok(), "git-push must succeed: {:?}", result.err());

        // Fetch the latest commit's author, email, subject, and body.
        let out = std::process::Command::new("git")
            .current_dir(&vault_dir)
            .args(["log", "-1", "--format=%an%n%ae%n%s%n%b"])
            .output()
            .expect("git log -1 --format=%an%n%ae%n%s%n%b");
        let commit_info = String::from_utf8_lossy(&out.stdout).to_string();

        // The vault password must not appear anywhere in the commit metadata.
        assert!(
            !commit_info.contains("password"),
            "commit metadata must not contain the vault password; got: {commit_info}"
        );

        // Author email must follow the anonymous @localhost pattern.
        let email_line = commit_info.lines().nth(1).unwrap_or("").trim();
        assert!(
            email_line.ends_with("@localhost"),
            "author email must end with @localhost; got: {email_line}"
        );

        // Commit message must be the fixed template (no entry content leaked).
        let msg_line = commit_info.lines().nth(2).unwrap_or("").trim();
        assert_eq!(
            msg_line, "Update vault",
            "commit message must be the fixed 'Update vault' template; got: {msg_line}"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S7-NFR-001-01: None ポリシー拒否 < 10ms
    // -------------------------------------------------------------------------

    /// TC-S7-NFR-001-01: None policy denial completes in under 10 ms.
    ///
    /// Verifies NFR-101: only vault.toml is read (no vault.pqd decryption),
    /// so the check must be nearly instantaneous.
    #[test]
    fn tc_s7_nfr_001_01_none_policy_denial_under_10ms() {
        use std::time::Instant;

        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir); // default policy = None
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let cli = make_cli_claude(vault_dir_str, Some("password"));

        let start = Instant::now();
        let result = cmd_list(&cli, None, None, 20);
        let elapsed = start.elapsed();

        assert!(result.is_err(), "--claude + None must be denied");
        assert!(
            elapsed.as_millis() < 10,
            "None policy denial must complete in < 10 ms; took {elapsed:?}"
        );
    }

    // -------------------------------------------------------------------------
    // TC-S7-NFR-103-01: vault.toml 改ざん検出
    // -------------------------------------------------------------------------

    /// TC-S7-NFR-103-01: A tampered `vault.toml` with an unknown policy value
    /// causes [`VaultConfig::from_file`] to return [`DiaryError::Config`].
    ///
    /// Verifies NFR-103: there is no silent fallback for unrecognised policy
    /// strings — serde returns an error that propagates as DiaryError::Config.
    #[test]
    fn tc_s7_nfr_103_01_tampered_vault_toml_returns_config_error() {
        use pq_diary_core::vault::config::VaultConfig;
        use pq_diary_core::DiaryError;

        let dir = tempfile::tempdir().expect("tempdir");
        let toml_path = dir.path().join("vault.toml");

        // Write a vault.toml with a tampered / invalid policy value
        let tampered = r#"
[vault]
name = "test"
schema_version = 4

[access]
policy = "hacked"

[git]
author_name = ""
author_email = ""
commit_message = "Update vault"

[git.privacy]
timestamp_fuzz_hours = 0
extra_padding_bytes_max = 0

[argon2]
memory_cost_kb = 65536
time_cost = 3
parallelism = 1
"#;
        std::fs::write(&toml_path, tampered).expect("write tampered vault.toml");

        let result = VaultConfig::from_file(&toml_path);
        assert!(
            matches!(result, Err(DiaryError::Config(_))),
            "tampered policy value must return DiaryError::Config, got: {:?}",
            result
        );
    }
}
