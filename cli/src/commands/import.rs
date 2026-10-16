//! Markdown import command, attachment resolution, and output adapters.

use super::{
    check_claude_policy, resolve_legacy_vault_dir, resolve_vault_path, session::VaultGuard,
};
use crate::password::get_password;
use crate::Cli;
use pq_diary_core::DiaryCore;
use std::path::{Path, PathBuf};

/// Resolve an Obsidian `![[...]]` attachment target against the import
/// `attachments/` directory without allowing absolute paths, `..`, or symlink
/// escapes outside that directory.
fn resolve_import_attachment_source(attachments_dir: &Path, link_target: &str) -> Option<PathBuf> {
    let relative = Path::new(link_target.trim());
    let mut has_component = false;
    for component in relative.components() {
        match component {
            std::path::Component::Normal(_) => has_component = true,
            _ => return None,
        }
    }
    if !has_component {
        return None;
    }

    let candidate = attachments_dir.join(relative);
    if !candidate.is_file() {
        return None;
    }

    let attachments_dir = attachments_dir.canonicalize().ok()?;
    let candidate = candidate.canonicalize().ok()?;
    if candidate.starts_with(&attachments_dir) && candidate.is_file() {
        Some(candidate)
    } else {
        None
    }
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
    use anyhow::Context as _;
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

    // Import may add attachments after entries; reject unsupported targets before
    // any writes rather than partially importing or opening a sibling vault.
    resolve_legacy_vault_dir(cli)?;

    // 2. Policy check before any password prompt or vault decryption.
    {
        use pq_diary_core::policy::OperationType;
        check_claude_policy(cli, OperationType::Write)?;
    }

    // 3. Acquire password; attachments reuse it after the guarded entry import.
    let password_source =
        get_password(cli.password.as_ref()).map_err(|e| anyhow::anyhow!("{e}"))?;

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

    // Snapshot the set of entry UUIDs that exist before the import so we can
    // identify the newly-created entries afterwards and walk their bodies for
    // `![[FILE]]` attachment references (S13).
    let pre_import_uuids: std::collections::HashSet<String> = guard
        .list_entries(None)
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .into_iter()
        .map(|m| m.uuid_hex)
        .collect();

    // 5. Run import (dry_run flag is forwarded to core).
    let result = guard
        .import(&args.dir, args.dry_run)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // 5b. (S13) Walk every newly-imported entry, parse `![[FILE]]` references
    // from the body, and attach matching files from `<dir>/attachments/`.
    // Performed inside the same guard scope so we can read entry bodies; the
    // actual `add_attachment` call self-locks and is invoked once the guard
    // is dropped at the end of this block.
    let mut attached = 0_usize;
    let mut skipped_links: Vec<String> = Vec::new();
    let mut pending_attachments: Vec<(String, std::path::PathBuf)> = Vec::new();
    let mut queued_attachments: std::collections::HashSet<(String, std::path::PathBuf)> =
        std::collections::HashSet::new();
    if !args.dry_run {
        let attachments_dir = args.dir.join("attachments");
        let post_metas = guard
            .list_entries(None)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        for meta in &post_metas {
            if pre_import_uuids.contains(&meta.uuid_hex) {
                continue;
            }
            let id_prefix = &meta.uuid_hex[..meta.uuid_hex.len().min(8)];
            let (_, plaintext) = guard
                .get_entry(id_prefix)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let links = pq_diary_core::importer::parse_obsidian_attachment_links(&plaintext.body);
            for filename in links {
                if let Some(src) = resolve_import_attachment_source(&attachments_dir, &filename) {
                    let id_prefix = id_prefix.to_string();
                    if queued_attachments.insert((id_prefix.clone(), src.clone())) {
                        pending_attachments.push((id_prefix, src));
                    }
                } else {
                    skipped_links.push(filename);
                }
            }
        }
    }

    // guard drops here, automatically calling lock().
    drop(guard);

    // 7. (S13) Apply the queued attachment adds now that the guard is gone —
    // `add_attachment` re-opens the vault with the master password.
    let mut attachment_warnings = Vec::new();
    if !pending_attachments.is_empty() {
        let vault_dir = resolve_legacy_vault_dir(cli)?;
        let master_pwd: secrecy::SecretString =
            SecretBox::new(Box::from(password_source.secret().expose_secret()));
        for (id_prefix, src) in &pending_attachments {
            match pq_diary_core::attachment::add_attachment(&vault_dir, &master_pwd, id_prefix, src)
            {
                Ok(_) => attached += 1,
                Err(e) => {
                    let filename = src.file_name().and_then(|n| n.to_str()).unwrap_or("?");
                    attachment_warnings
                        .push(format!("  warning: failed to attach {filename}: {e}"));
                }
            }
        }
    }
    // Finish requested mutations before a reporting error can return early.
    (|| -> std::io::Result<()> {
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

        for warning in &attachment_warnings {
            writeln!(out, "{warning}")?;
        }
        if attached > 0 || !skipped_links.is_empty() {
            writeln!(
                out,
                "Attachments: {attached} added, {} unresolved ![[...]] reference(s) left as-is",
                skipped_links.len()
            )?;
            for missing in &skipped_links {
                writeln!(out, "  unresolved: {missing}")?;
            }
        }
        out.flush()
    })()
    .with_context(|| {
        format!(
            "Failed to report import result ({} entries imported, {attached} attachments added)",
            result.imported
        )
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{read_vault_entries, setup_vault, FailingMutationWriter};
    use super::*;
    use clap::Parser as _;

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

    /// TC-S13-110-01: `import <DIR>` resolves `![[FILE]]` references against
    /// `<DIR>/attachments/<FILE>` and adds the matched binaries as attachments.
    #[test]
    fn tc_s13_110_01_import_resolves_attachments() {
        use secrecy::SecretBox;

        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let src_dir = tempfile::tempdir().expect("src tempdir");
        std::fs::write(
            src_dir.path().join("note.md"),
            "# Note\n\nMy photo: ![[photo.png]]\n",
        )
        .expect("write md");
        std::fs::create_dir_all(src_dir.path().join("attachments")).expect("mkdir attachments");
        std::fs::write(
            src_dir.path().join("attachments/photo.png"),
            b"\x89PNG\r\n\x1a\nfake png body",
        )
        .expect("write attachment");

        let cli = parse_import_cli(vault_dir_str, src_dir.path().to_str().expect("utf8"), &[]);
        let import_args = extract_import_args(&cli);

        let mut out = Vec::new();
        cmd_import_to(&cli, import_args, &mut out).expect("cmd_import_to");
        let output = String::from_utf8(out).expect("utf8");
        assert!(
            output.contains("Attachments: 1 added"),
            "output must report 1 attachment added: {output}"
        );

        let pwd = SecretBox::new(Box::from("password"));
        let metas = pq_diary_core::attachment::list_attachments(&vault_dir, &pwd, None)
            .expect("list_attachments");
        assert_eq!(metas.len(), 1, "the vault should now hold one attachment");
        assert_eq!(metas[0].filename, "photo.png");
    }

    /// TC-S13-110-02: `import <DIR>` warns about `![[FILE]]` whose source
    /// is missing instead of aborting.
    #[test]
    fn tc_s13_110_02_import_warns_on_missing_attachment() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let src_dir = tempfile::tempdir().expect("src tempdir");
        std::fs::write(
            src_dir.path().join("note.md"),
            "# Note\n\n![[missing.pdf]]\n",
        )
        .expect("write md");
        // Intentionally do NOT create src_dir/attachments/missing.pdf.

        let cli = parse_import_cli(vault_dir_str, src_dir.path().to_str().expect("utf8"), &[]);
        let import_args = extract_import_args(&cli);

        let mut out = Vec::new();
        cmd_import_to(&cli, import_args, &mut out).expect("cmd_import_to");
        let output = String::from_utf8(out).expect("utf8");

        assert!(
            output.contains("Imported: 1"),
            "entry import must still succeed: {output}"
        );
        assert!(
            output.contains("unresolved") && output.contains("missing.pdf"),
            "output must list the unresolved attachment reference: {output}"
        );
    }

    /// TC-S13-110-03: `import <DIR>` must not resolve attachment links outside
    /// `<DIR>/attachments/`, even when the referenced outside file exists.
    #[test]
    fn tc_s13_110_03_import_rejects_attachment_path_escape() {
        use secrecy::SecretBox;

        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let src_dir = tempfile::tempdir().expect("src tempdir");
        std::fs::write(
            src_dir.path().join("note.md"),
            "# Note\n\n![[../outside.txt]]\n",
        )
        .expect("write md");
        std::fs::create_dir_all(src_dir.path().join("attachments")).expect("mkdir attachments");
        std::fs::write(src_dir.path().join("outside.txt"), b"outside attachment")
            .expect("write outside");

        let cli = parse_import_cli(vault_dir_str, src_dir.path().to_str().expect("utf8"), &[]);
        let import_args = extract_import_args(&cli);

        let mut out = Vec::new();
        cmd_import_to(&cli, import_args, &mut out).expect("cmd_import_to");
        let output = String::from_utf8(out).expect("utf8");

        assert!(
            output.contains("unresolved") && output.contains("../outside.txt"),
            "path escape must be reported as unresolved: {output}"
        );

        let pwd = SecretBox::new(Box::from("password"));
        let metas = pq_diary_core::attachment::list_attachments(&vault_dir, &pwd, None)
            .expect("list_attachments");
        assert!(
            metas.is_empty(),
            "outside file must not be imported as an attachment"
        );
    }

    /// TC-S13-110-04: repeated `![[FILE]]` links in the same imported entry
    /// attach the file once and report the real number of added records.
    #[test]
    fn tc_s13_110_04_import_dedupes_duplicate_attachment_links() {
        use secrecy::SecretBox;

        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let src_dir = tempfile::tempdir().expect("src tempdir");
        std::fs::write(
            src_dir.path().join("note.md"),
            "# Note\n\n![[photo.png]]\n![[photo.png]]\n",
        )
        .expect("write md");
        std::fs::create_dir_all(src_dir.path().join("attachments")).expect("mkdir attachments");
        std::fs::write(
            src_dir.path().join("attachments/photo.png"),
            b"fake png body",
        )
        .expect("write attachment");

        let cli = parse_import_cli(vault_dir_str, src_dir.path().to_str().expect("utf8"), &[]);
        let import_args = extract_import_args(&cli);

        let mut out = Vec::new();
        cmd_import_to(&cli, import_args, &mut out).expect("cmd_import_to");
        let output = String::from_utf8(out).expect("utf8");
        assert!(
            output.contains("Attachments: 1 added"),
            "duplicate link must report a single added attachment: {output}"
        );

        let pwd = SecretBox::new(Box::from("password"));
        let metas = pq_diary_core::attachment::list_attachments(&vault_dir, &pwd, None)
            .expect("list_attachments");
        assert_eq!(metas.len(), 1, "duplicate links must create one attachment");
    }

    /// TC-S13-110-05: files in top-level `<DIR>/attachments/` are attachment
    /// payloads and must not also be imported as diary entries.
    #[test]
    fn tc_s13_110_05_import_ignores_attachments_dir_as_entries() {
        use secrecy::SecretBox;

        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        let src_dir = tempfile::tempdir().expect("src tempdir");
        std::fs::write(
            src_dir.path().join("note.md"),
            "# Note\n\n![[snippet.md]]\n",
        )
        .expect("write md");
        std::fs::create_dir_all(src_dir.path().join("attachments")).expect("mkdir attachments");
        std::fs::write(
            src_dir.path().join("attachments/snippet.md"),
            "# Not a diary entry\n",
        )
        .expect("write attachment");

        let cli = parse_import_cli(vault_dir_str, src_dir.path().to_str().expect("utf8"), &[]);
        let import_args = extract_import_args(&cli);

        let mut out = Vec::new();
        cmd_import_to(&cli, import_args, &mut out).expect("cmd_import_to");
        let output = String::from_utf8(out).expect("utf8");
        assert!(
            output.contains("Imported: 1, Skipped: 0"),
            "attachments/ files must not affect entry import counts: {output}"
        );

        let vault_pqd_str = vault_dir.join("vault.pqd");
        let mut core =
            DiaryCore::new(vault_pqd_str.to_str().expect("utf8")).expect("DiaryCore::new");
        core.unlock(SecretBox::new(Box::from("password")))
            .expect("unlock");
        let entries = core.list_entries(None).expect("list_entries");
        core.lock();
        assert_eq!(
            entries.len(),
            1,
            "only note.md must be imported as an entry"
        );
        assert_eq!(entries[0].title, "note");

        let pwd = SecretBox::new(Box::from("password"));
        let metas = pq_diary_core::attachment::list_attachments(&vault_dir, &pwd, None)
            .expect("list_attachments");
        assert_eq!(metas.len(), 1, "snippet.md must still be attached");
        assert_eq!(metas[0].filename, "snippet.md");
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

    #[test]
    fn import_output_failure_keeps_requested_attachments() {
        for fail_write in [true, false] {
            let dir = tempfile::tempdir().expect("tempdir");
            let vault_dir = setup_vault(&dir);
            let config = std::fs::read(vault_dir.join("vault.toml")).expect("config");
            let source = dir.path().join("source");
            std::fs::create_dir_all(source.join("attachments")).expect("source directory");
            std::fs::write(source.join("note.md"), "# Note\n\n![[photo.txt]]\n")
                .expect("source entry");
            std::fs::write(source.join("attachments/photo.txt"), b"attachment contents")
                .expect("source attachment");
            let cli = parse_import_cli(
                vault_dir.to_str().expect("vault path"),
                source.to_str().expect("source path"),
                &[],
            );
            let error = cmd_import_to(
                &cli,
                extract_import_args(&cli),
                &mut FailingMutationWriter { fail_write },
            )
            .expect_err("output failure must propagate");
            assert_eq!(
                error
                    .downcast_ref::<std::io::Error>()
                    .expect("I/O source")
                    .kind(),
                std::io::ErrorKind::BrokenPipe
            );
            let entries = read_vault_entries(&vault_dir);
            assert_eq!(entries.len(), 1, "entry remains committed");
            let attachments = pq_diary_core::attachment::list_attachments(
                &vault_dir,
                &secrecy::SecretBox::new(Box::from("password")),
                Some(&entries[0].uuid_hex),
            )
            .expect("reopen attachments");
            assert_eq!(
                attachments.len(),
                1,
                "reporting must not skip attachment work"
            );
            assert_eq!(attachments[0].filename, "photo.txt");
            assert_eq!(
                std::fs::read(vault_dir.join("vault.toml")).expect("config"),
                config
            );
            assert!(source.join("note.md").is_file());
        }
    }

    // -------------------------------------------------------------------------
    // TC-S9-E2E-03: Import lifecycle
    // -------------------------------------------------------------------------

    /// TC-S9-E2E-03: Import lifecycle — create Markdown file → import → verify entry.
    ///
    /// Creates an Obsidian-compatible Markdown file with wiki-links and nested
    /// tags, imports it into the vault, and verifies the entry was created.
    #[test]
    fn tc_s9_e2e_03_import_lifecycle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_dir_str = vault_dir.to_str().expect("utf8");

        // Create Obsidian-compatible Markdown file with YAML frontmatter,
        // wiki-links, and nested tags.  The importer uses the frontmatter
        // `title:` field (or filename stem when absent).
        let src_dir = tempfile::tempdir().expect("src tempdir");
        let md_content = "---\ntitle: Obsidian Note\n---\n\n\
            This note links to [[Another Note]].\n\
            Tags: #日記/旅行 #tech\n\n\
            Body of the imported note.\n";
        std::fs::write(src_dir.path().join("obsidian_note.md"), md_content).expect("write md file");

        // Import via CLI command.
        let cli = parse_import_cli(vault_dir_str, src_dir.path().to_str().expect("utf8"), &[]);
        let import_args = extract_import_args(&cli);

        let mut out = Vec::new();
        cmd_import_to(&cli, import_args, &mut out).expect("cmd_import_to");
        let output = String::from_utf8(out).expect("utf8 output");

        assert!(
            output.contains("Imported: 1"),
            "output must confirm 1 import: {output}"
        );

        // Verify the entry is accessible in the vault.
        let entries = read_vault_entries(&vault_dir);
        assert_eq!(
            entries.len(),
            1,
            "vault must contain exactly 1 imported entry"
        );
        assert_eq!(
            entries[0].title, "Obsidian Note",
            "imported entry title must match frontmatter title"
        );
    }
}
