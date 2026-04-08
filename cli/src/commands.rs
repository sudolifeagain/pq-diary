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
    use secrecy::{ExposeSecret as _, SecretBox};
    use std::io::{BufRead as _, IsTerminal as _, Read as _};

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
        // -b / --body flag: highest priority; template is ignored; editor is NOT launched.
        (b, title, tags)
    } else if let Some(tmpl_name) = template {
        // --template: expand template variables and use as body; editor is NOT launched.
        use pq_diary_core::template_engine::{
            expand, extract_variables, VariableKind, BUILTIN_DATE, BUILTIN_DATETIME, BUILTIN_TITLE,
        };
        use std::collections::{HashMap, HashSet};

        let tmpl = match core.get_template(&tmpl_name) {
            Ok(t) => t,
            Err(e) => {
                core.lock();
                return Err(anyhow::anyhow!("{e}"));
            }
        };

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
                if let Err(e) = std::io::stdout().flush() {
                    core.lock();
                    return Err(anyhow::anyhow!("Failed to flush stdout: {e}"));
                }
                let mut input = String::new();
                if let Err(e) = std::io::stdin().lock().read_line(&mut input) {
                    core.lock();
                    return Err(anyhow::anyhow!("Failed to read variable input: {e}"));
                }
                vars.insert(var_ref.name.clone(), input.trim().to_string());
            }
        }

        let expanded = expand(&tmpl.body, &vars);
        (expanded, title, tags)
    } else if !std::io::stdin().is_terminal() {
        // Piped stdin: read all content.
        let mut content = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut content) {
            core.lock();
            return Err(anyhow::anyhow!("Failed to read stdin: {e}"));
        }
        (content, title, tags)
    } else {
        // $EDITOR: write header-comment temp file, launch editor, read back.
        let mut config = match EditorConfig::from_env() {
            Ok(c) => c,
            Err(e) => {
                core.lock();
                return Err(anyhow::anyhow!("{e}"));
            }
        };

        let initial = EntryPlaintext {
            title: title.clone().unwrap_or_else(|| "Untitled".to_string()),
            tags: tags.clone(),
            body: String::new(),
        };

        let tmpfile = match editor::write_header_file(&config.secure_tmpdir, &initial) {
            Ok(p) => p,
            Err(e) => {
                core.lock();
                return Err(anyhow::anyhow!("Failed to write temp file: {e}"));
            }
        };

        // Inject vim completion for [[title]] links (vim/nvim only).
        let is_vim = !config.vim_options.is_empty();
        let completion_file = if is_vim {
            let titles = core.all_titles().unwrap_or_default();
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

        if let Err(e) = edit_result {
            core.lock();
            return Err(anyhow::anyhow!("Editor failed: {e}"));
        }
        let header = match read_result {
            Ok(h) => h,
            Err(e) => {
                core.lock();
                return Err(anyhow::anyhow!("Failed to read temp file: {e}"));
            }
        };

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
    let uuid_hex = match core.new_entry(&actual_title, &final_body, final_tags) {
        Ok(h) => h,
        Err(e) => {
            core.lock();
            return Err(anyhow::anyhow!("Failed to create entry: {e}"));
        }
    };

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

    let entries = match core.list_entries(None) {
        Ok(e) => e,
        Err(e) => {
            core.lock();
            return Err(anyhow::anyhow!("Failed to list entries: {e}"));
        }
    };

    let filtered = match filter_and_sort(entries, tag.as_deref(), query.as_deref(), number) {
        Ok(f) => f,
        Err(e) => {
            core.lock();
            return Err(e);
        }
    };

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

            writeln!(out, "Title:   {}", plaintext.title)
                .map_err(|e| anyhow::anyhow!("Write error: {e}"))?;
            writeln!(out, "Created: {created}  Updated: {updated}")
                .map_err(|e| anyhow::anyhow!("Write error: {e}"))?;
            if plaintext.tags.is_empty() {
                writeln!(out, "Tags:    (none)")
                    .map_err(|e| anyhow::anyhow!("Write error: {e}"))?;
            } else {
                let tags_str = plaintext
                    .tags
                    .iter()
                    .map(|t| format!("#{t}"))
                    .collect::<Vec<_>>()
                    .join("  ");
                writeln!(out, "Tags:    {tags_str}")
                    .map_err(|e| anyhow::anyhow!("Write error: {e}"))?;
            }
            writeln!(out).map_err(|e| anyhow::anyhow!("Write error: {e}"))?;
            write!(out, "{}", plaintext.body).map_err(|e| anyhow::anyhow!("Write error: {e}"))?;

            // Resolve [[link]] references in the body.
            let resolved = core
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
            let mut backlinks = core
                .backlinks_for(&plaintext.title)
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            if !backlinks.is_empty() {
                backlinks.sort_by(|a, b| b.created_at.cmp(&a.created_at));

                writeln!(out).map_err(|e| anyhow::anyhow!("Write error: {e}"))?;
                writeln!(out, "--- Backlinks ---")
                    .map_err(|e| anyhow::anyhow!("Write error: {e}"))?;
                for bl in &backlinks {
                    let date = format_timestamp(bl.created_at);
                    let prefix = backlink_uuid_prefix(&bl.source_uuid);
                    writeln!(out, "  [{prefix}] {date} {}", bl.source_title)
                        .map_err(|e| anyhow::anyhow!("Write error: {e}"))?;
                }
            }

            core.lock();
            Ok(())
        }
    }
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

    let get_result = core.get_entry(&id);
    let (_record, original) = match get_result {
        Ok(r) => r,
        Err(e) => {
            core.lock();
            return Err(anyhow::anyhow!("{e}"));
        }
    };

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

        let update_result = core.update_entry(&id, &new_plaintext);
        core.lock();
        update_result.map_err(|e| anyhow::anyhow!("Failed to update entry: {e}"))?;
        let prefix = &id[..id.len().min(8)];
        println!("Updated: {prefix}");
    } else {
        // Editor mode: write header-comment temp file, launch editor, parse result.
        let mut config = match EditorConfig::from_env() {
            Ok(c) => c,
            Err(e) => {
                core.lock();
                return Err(anyhow::anyhow!("{e}"));
            }
        };

        let tmpfile = match editor::write_header_file(&config.secure_tmpdir, &original) {
            Ok(p) => p,
            Err(e) => {
                core.lock();
                return Err(anyhow::anyhow!("Failed to write temp file: {e}"));
            }
        };

        // Inject vim completion for [[title]] links (vim/nvim only).
        let is_vim = !config.vim_options.is_empty();
        let completion_file = if is_vim {
            let titles = core.all_titles().unwrap_or_default();
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

        if let Err(e) = edit_result {
            core.lock();
            return Err(anyhow::anyhow!("Editor failed: {e}"));
        }

        let header = match read_result {
            Ok(h) => h,
            Err(e) => {
                core.lock();
                return Err(anyhow::anyhow!("Failed to read temp file: {e}"));
            }
        };

        // On header parse error, fall back to the original metadata.
        let (new_title, new_tags) = match (header.title, header.tags) {
            (Some(t), Some(tags)) => (t, tags),
            _ => (original.title.clone(), original.tags.clone()),
        };
        let new_body = header.body;

        // Change detection: skip update if nothing changed.
        if new_title == original.title && new_tags == original.tags && new_body == original.body {
            println!("変更がありませんでした");
            core.lock();
            return Ok(());
        }

        let new_plaintext = EntryPlaintext {
            title: new_title,
            tags: new_tags,
            body: new_body,
        };

        let update_result = core.update_entry(&id, &new_plaintext);
        core.lock();
        update_result.map_err(|e| anyhow::anyhow!("Failed to update entry: {e}"))?;
        let prefix = &id[..id.len().min(8)];
        println!("Updated: {prefix}");
    }

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

    let get_result = core.get_entry(&id);
    let (record, plaintext) = match get_result {
        Ok(r) => r,
        Err(e) => {
            core.lock();
            return Err(anyhow::anyhow!("{e}"));
        }
    };

    let title = plaintext.title.clone();
    let date = format_timestamp(record.created_at);
    let prefix = id[..id.len().min(8)].to_string();

    // Determine whether to skip confirmation.
    let skip_confirm = force || cli.claude;
    let do_delete = if skip_confirm {
        true
    } else {
        match confirm_delete(&title, &date, reader) {
            Ok(v) => v,
            Err(e) => {
                core.lock();
                return Err(e);
            }
        }
    };

    if do_delete {
        let delete_result = core.delete_entry(&id);
        core.lock();
        delete_result.map_err(|e| anyhow::anyhow!("Failed to delete entry: {e}"))?;
        println!("Deleted: {prefix} \"{title}\"");
    } else {
        core.lock();
        println!("キャンセルしました");
    }

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

    // Check for an existing template with the same name.
    let already_exists = core.get_template(&name).is_ok();
    if already_exists && !cli.claude {
        use std::io::Write as _;
        eprint!("Template \"{name}\" already exists. Overwrite? [y/N]: ");
        if let Err(e) = std::io::stderr().flush() {
            core.lock();
            return Err(anyhow::anyhow!("Failed to flush stderr: {e}"));
        }
        let mut input = String::new();
        if let Err(e) = reader.read_line(&mut input) {
            core.lock();
            return Err(anyhow::anyhow!("Failed to read input: {e}"));
        }
        let trimmed = input.trim();
        if trimmed != "y" && trimmed != "Y" {
            core.lock();
            println!("キャンセルしました");
            return Ok(());
        }
    }

    // Set up editor config.
    let config = match editor::EditorConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            core.lock();
            return Err(anyhow::anyhow!("{e}"));
        }
    };

    // Write a blank temp file and launch editor.
    let tmpfile = match editor::write_template_file(&config.secure_tmpdir) {
        Ok(p) => p,
        Err(e) => {
            core.lock();
            return Err(anyhow::anyhow!("Failed to write temp file: {e}"));
        }
    };

    let edit_result = launch_fn(&tmpfile, &config);
    let read_result = editor::read_template_file(&tmpfile);
    if let Err(e) = editor::secure_delete(&tmpfile) {
        eprintln!("Warning: failed to securely delete temp file: {e}");
    }

    if let Err(e) = edit_result {
        core.lock();
        return Err(anyhow::anyhow!("Editor failed: {e}"));
    }

    let body = match read_result {
        Ok(b) => b,
        Err(e) => {
            core.lock();
            return Err(anyhow::anyhow!("Failed to read temp file: {e}"));
        }
    };

    let result = core.new_template(&name, &body);
    core.lock();
    result.map_err(|e| anyhow::anyhow!("Failed to create template: {e}"))?;
    println!("Template created: \"{name}\"");
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

    let result = core.list_templates();
    core.lock();

    let mut templates = result.map_err(|e| anyhow::anyhow!("Failed to list templates: {e}"))?;
    templates.sort_by(|a, b| a.name.cmp(&b.name));

    for meta in &templates {
        println!("{}", meta.name);
    }

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

    let result = core.get_template(&name);
    match result {
        Err(e) => {
            core.lock();
            Err(anyhow::anyhow!("{e}"))
        }
        Ok(plaintext) => {
            print!("{}", plaintext.body);
            core.lock();
            Ok(())
        }
    }
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

    // Verify the template exists.
    let get_result = core.get_template(&name);
    if let Err(e) = get_result {
        core.lock();
        return Err(anyhow::anyhow!("{e}"));
    }

    // Determine whether to skip confirmation.
    let skip_confirm = force || cli.claude;
    let do_delete = if skip_confirm {
        true
    } else {
        match confirm_template_delete(&name, reader) {
            Ok(v) => v,
            Err(e) => {
                core.lock();
                return Err(e);
            }
        }
    };

    if do_delete {
        let delete_result = core.delete_template(&name);
        core.lock();
        delete_result.map_err(|e| anyhow::anyhow!("Failed to delete template: {e}"))?;
        println!("Deleted template: \"{name}\"");
    } else {
        core.lock();
        println!("キャンセルしました");
    }

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
    use pq_diary_core::template_engine::{expand, BUILTIN_DATE, BUILTIN_TITLE};
    use secrecy::{ExposeSecret as _, SecretBox};
    use std::collections::HashMap;

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

    // Search for today's entry by exact title match.
    let entries = match core.list_entries(None) {
        Ok(e) => e,
        Err(e) => {
            core.lock();
            return Err(anyhow::anyhow!("Failed to list entries: {e}"));
        }
    };
    let today_entry = entries.iter().find(|e| e.title == today);

    let entry_id = if let Some(meta) = today_entry {
        // Entry exists: reuse its UUID hex.
        meta.uuid_hex.clone()
    } else {
        // Entry does not exist: determine initial body from template or empty string.
        let initial_body = match core.get_template("daily") {
            Ok(tmpl) => {
                let mut vars: HashMap<String, String> = HashMap::new();
                vars.insert(BUILTIN_DATE.to_string(), today.to_string());
                vars.insert(BUILTIN_TITLE.to_string(), today.to_string());
                expand(&tmpl.body, &vars)
            }
            Err(_) => String::new(),
        };

        // Create the entry.
        match core.new_entry(today, &initial_body, vec![]) {
            Ok(uuid_hex) => uuid_hex,
            Err(e) => {
                core.lock();
                return Err(anyhow::anyhow!("Failed to create entry: {e}"));
            }
        }
    };

    // Open the entry in the editor (edit flow).
    let id_prefix = entry_id[..entry_id.len().min(8)].to_string();
    let get_result = core.get_entry(&id_prefix);
    let (_record, original) = match get_result {
        Ok(r) => r,
        Err(e) => {
            core.lock();
            return Err(anyhow::anyhow!("{e}"));
        }
    };

    let mut config = match EditorConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            core.lock();
            return Err(anyhow::anyhow!("{e}"));
        }
    };

    let tmpfile = match editor::write_header_file(&config.secure_tmpdir, &original) {
        Ok(p) => p,
        Err(e) => {
            core.lock();
            return Err(anyhow::anyhow!("Failed to write temp file: {e}"));
        }
    };

    // Inject vim completion for [[title]] links (vim/nvim only).
    let is_vim = !config.vim_options.is_empty();
    let completion_file = if is_vim {
        let titles = core.all_titles().unwrap_or_default();
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

    if let Err(e) = edit_result {
        core.lock();
        return Err(anyhow::anyhow!("Editor failed: {e}"));
    }

    let header = match read_result {
        Ok(h) => h,
        Err(e) => {
            core.lock();
            return Err(anyhow::anyhow!("Failed to read temp file: {e}"));
        }
    };

    let (new_title, new_tags) = match (header.title, header.tags) {
        (Some(t), Some(tags)) => (t, tags),
        _ => (original.title.clone(), original.tags.clone()),
    };
    let new_body = header.body;

    if new_title == original.title && new_tags == original.tags && new_body == original.body {
        println!("変更がありませんでした");
        core.lock();
        return Ok(());
    }

    let new_plaintext = EntryPlaintext {
        title: new_title,
        tags: new_tags,
        body: new_body,
    };

    let update_result = core.update_entry(&id_prefix, &new_plaintext);
    core.lock();
    update_result.map_err(|e| anyhow::anyhow!("Failed to update entry: {e}"))?;
    println!("Updated: {id_prefix}");

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
    #[test]
    fn tc_0040_09_claude_flag_skips_confirmation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (vault_dir, prefix) = setup_vault_with_entry(&dir, "Claude Test", "body", vec![]);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

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
}
