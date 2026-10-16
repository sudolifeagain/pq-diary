//! Template CRUD commands and their confirmation, editor, and output adapters.

use super::{check_claude_policy, session};
use crate::editor::{self, EditorConfig};
use crate::password::get_password;
use crate::Cli;

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

/// Preserve the existing one-line diagnostic and the inspectable core source.
/// Debug/CLI error-chain rendering may additionally print a `Caused by` line.
fn template_command_error(context: &str, error: pq_diary_core::DiaryError) -> anyhow::Error {
    let message = format!("{context}: {error}");
    anyhow::Error::new(error).context(message)
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

    // Policy check before any password prompt or vault decryption.
    check_claude_policy(cli, OperationType::Write)?;

    let password_source = get_password(cli.password.as_ref())?;

    let mut core = session::locked_core(cli)?;
    let guard = session::unlock(&mut core, password_source.into_secret())?;

    // Check for an existing template with the same name.
    let already_exists = match guard.get_template(&name) {
        Ok(_) => true,
        Err(pq_diary_core::DiaryError::TemplateNotFound(_)) => false,
        Err(e) => return Err(template_command_error("Failed to look up template", e)),
    };
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
    let config = editor::EditorConfig::from_env()?;

    // Write a blank temp file and launch editor.
    let session = editor::EditorSession::template(&config.secure_tmpdir)
        .map_err(|e| anyhow::anyhow!("Failed to write temp file: {e}"))?;
    let body = session.finish(&config, launch_fn, editor::read_template_file)?;

    // Commit an overwrite once, so a failed replacement retains the original.
    if already_exists {
        guard
            .replace_template(&name, &body)
            .map_err(|e| template_command_error("Failed to replace template", e))?;
        println!("Template replaced: \"{name}\"");
    } else {
        guard
            .new_template(&name, &body)
            .map_err(|e| template_command_error("Failed to create template", e))?;
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
/// Returns an error if password acquisition, vault unlock, template listing, or output fails.
pub fn cmd_template_list(cli: &Cli) -> anyhow::Result<()> {
    cmd_template_list_with_writer(cli, &mut std::io::stdout().lock())
}

fn cmd_template_list_with_writer(
    cli: &Cli,
    output: &mut impl std::io::Write,
) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use pq_diary_core::policy::OperationType;

    // Policy check before any password prompt or vault decryption.
    check_claude_policy(cli, OperationType::Read)?;

    let password_source = get_password(cli.password.as_ref())?;

    let mut core = session::locked_core(cli)?;
    let guard = session::unlock(&mut core, password_source.into_secret())?;

    let mut templates = guard
        .list_templates()
        .map_err(|e| template_command_error("Failed to list templates", e))?;
    templates.sort_by(|a, b| a.name.cmp(&b.name));

    for meta in &templates {
        writeln!(output, "{}", meta.name).context("Failed to write template output")?;
    }
    output.flush().context("Failed to flush template output")?;

    // guard drops here, automatically calling lock().
    Ok(())
}

/// Execute the `pq-diary template show` command.
///
/// Displays the body text of the template identified by `name`.
///
/// # Errors
///
/// Returns an error if password acquisition, vault unlock, template lookup, or output fails.
/// Returns `DiaryError::TemplateNotFound` (wrapped in anyhow) when no template
/// with the given name exists.
pub fn cmd_template_show(cli: &Cli, name: String) -> anyhow::Result<()> {
    cmd_template_show_with_writer(cli, name, &mut std::io::stdout().lock())
}

fn cmd_template_show_with_writer(
    cli: &Cli,
    name: String,
    output: &mut impl std::io::Write,
) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use pq_diary_core::policy::OperationType;

    // Policy check before any password prompt or vault decryption.
    check_claude_policy(cli, OperationType::Read)?;

    let password_source = get_password(cli.password.as_ref())?;

    let mut core = session::locked_core(cli)?;
    let guard = session::unlock(&mut core, password_source.into_secret())?;

    let plaintext = guard.get_template(&name)?;
    output
        .write_all(plaintext.body.as_bytes())
        .context("Failed to write template output")?;
    output.flush().context("Failed to flush template output")?;

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

    // Policy check before any password prompt or vault decryption.
    check_claude_policy(cli, OperationType::Write)?;

    let password_source = get_password(cli.password.as_ref())?;

    let mut core = session::locked_core(cli)?;
    let guard = session::unlock(&mut core, password_source.into_secret())?;

    // Verify the template exists.
    guard.get_template(&name)?;

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
            .map_err(|e| template_command_error("Failed to delete template", e))?;
        println!("Deleted template: \"{name}\"");
    } else {
        println!("キャンセルしました");
    }

    // guard drops here, automatically calling lock().
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{
        seed_malformed_template, seed_templates, setup_vault, setup_vault_with_policy,
    };
    use super::*;
    use clap::Parser as _;
    use pq_diary_core::DiaryCore;
    use std::path::Path;

    #[test]
    fn command_sources_template_password_retains_type() {
        const CHILD: &str = "PQ_DIARY_TEST_TEMPLATE_PASSWORD_SOURCE";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "commands::templates::tests::command_sources_template_password_retains_type",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .env_remove("PQ_DIARY_PASSWORD")
                .stdin(std::process::Stdio::null())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let cli = make_template_list_cli(dir.path().to_str().unwrap(), None);
        let error = cmd_template_list_with_writer(&cli, &mut Vec::new()).unwrap_err();
        assert_eq!(
            error.to_string(),
            "password error: No password provided and stdin is not a terminal"
        );
        assert!(matches!(
            error.downcast_ref::<pq_diary_core::DiaryError>(),
            Some(pq_diary_core::DiaryError::Password(_))
        ));
        assert!(!dir.path().join("vault.pqd").exists());
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

    #[test]
    fn template_output_propagates_write_and_flush_errors() {
        use std::io::{self, Write};

        struct FailingWriter {
            fail_write: bool,
            kind: io::ErrorKind,
        }
        impl Write for FailingWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.fail_write {
                    Err(io::Error::from(self.kind))
                } else {
                    Ok(bytes.len())
                }
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::from(self.kind))
            }
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        seed_templates(&vault_dir, &[("daily", "private body without newline")]);
        let before = std::fs::read(vault_dir.join("vault.pqd")).expect("snapshot");
        let cli = make_template_list_cli(vault_dir.to_str().expect("path"), Some("password"));
        for fail_write in [true, false] {
            for kind in [io::ErrorKind::Other, io::ErrorKind::BrokenPipe] {
                for show in [false, true] {
                    let mut writer = FailingWriter { fail_write, kind };
                    let result = if show {
                        cmd_template_show_with_writer(&cli, "daily".into(), &mut writer)
                    } else {
                        cmd_template_list_with_writer(&cli, &mut writer)
                    };
                    let err = result.expect_err("output failure must propagate");
                    assert_eq!(
                        err.downcast_ref::<io::Error>().expect("I/O source").kind(),
                        kind
                    );
                    let message = format!("{err:#}");
                    assert!(message.contains(if fail_write {
                        "write template output"
                    } else {
                        "flush template output"
                    }));
                    assert!(!message.contains("private body"));
                    assert_eq!(
                        std::fs::read(vault_dir.join("vault.pqd")).expect("vault"),
                        before
                    );
                }
            }
        }
        assert_eq!(read_template_names_sorted(&vault_dir), vec!["daily"]);
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
            std::fs::write(tmpfile, "## 週次レビュー").map_err(pq_diary_core::DiaryError::Io)
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

    #[test]
    fn template_overwrite_preserves_confirmation_and_identity() {
        use pq_diary_core::policy::AccessPolicy;
        for (claude, answer, replace) in [
            (false, "n\n", false),
            (false, "y\n", true),
            (true, "", true),
        ] {
            let dir = tempfile::tempdir().expect("tempdir");
            let vault_dir = setup_vault_with_policy(&dir, AccessPolicy::Full);
            seed_templates(&vault_dir, &[("daily", "original")]);
            let vault_path = vault_dir.join("vault.pqd");
            let before = std::fs::read(&vault_path).expect("snapshot");
            let mut core = DiaryCore::new(vault_path.to_str().expect("UTF-8")).expect("core");
            core.unlock(secrecy::SecretBox::new(Box::from("password")))
                .expect("unlock");
            let original = core.list_templates().expect("template metadata");
            core.lock();

            let mut args = vec![
                "pq-diary",
                "--vault",
                vault_dir.to_str().expect("UTF-8"),
                "--password",
                "password",
            ];
            if claude {
                args.push("--claude");
            }
            args.extend(["template", "add", "daily"]);
            let cli = crate::Cli::try_parse_from(args).expect("CLI");
            let launch = |path: &Path, _: &EditorConfig| {
                assert!(replace, "declining overwrite must not open the editor");
                std::fs::write(path, "replacement").map_err(pq_diary_core::DiaryError::Io)
            };
            cmd_template_add_impl(
                &cli,
                "daily".into(),
                launch,
                &mut std::io::Cursor::new(answer),
            )
            .expect("template add");

            core.unlock(secrecy::SecretBox::new(Box::from("password")))
                .expect("reopen");
            let templates = core.list_templates().expect("templates");
            assert_eq!(templates.len(), 1);
            assert_eq!(templates[0].uuid_hex, original[0].uuid_hex);
            assert_eq!(templates[0].created_at, original[0].created_at);
            assert_eq!(
                core.get_template("daily").expect("template").body,
                if replace { "replacement" } else { "original" }
            );
            if !replace {
                assert_eq!(std::fs::read(&vault_path).expect("vault"), before);
            }
        }
    }

    #[test]
    fn template_overwrite_editor_error_preserves_original() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        seed_templates(&vault_dir, &[("daily", "original")]);
        let vault_path = vault_dir.join("vault.pqd");
        let before = std::fs::read(&vault_path).expect("snapshot");
        let cli = crate::Cli::try_parse_from([
            "pq-diary",
            "--vault",
            vault_dir.to_str().expect("UTF-8"),
            "--password",
            "password",
            "template",
            "add",
            "daily",
        ])
        .expect("CLI");
        let launch = |_: &Path, _: &EditorConfig| {
            Err(pq_diary_core::DiaryError::Editor(
                "synthetic failure".into(),
            ))
        };
        let error = cmd_template_add_impl(
            &cli,
            "daily".into(),
            launch,
            &mut std::io::Cursor::new("y\n"),
        )
        .expect_err("editor failure");
        assert!(error.to_string().contains("Editor failed"));
        assert_eq!(std::fs::read(&vault_path).expect("vault"), before);
    }

    #[test]
    fn template_overwrite_rejects_tampering_during_editor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        seed_templates(&vault_dir, &[("daily", "original")]);
        let vault_path = vault_dir.join("vault.pqd");
        let mut tampered = std::fs::read(&vault_path).expect("snapshot");
        let padding_offset = tampered.len() - pq_diary_core::vault::format::VAULT_MAC_LEN - 1;
        tampered[padding_offset] ^= 1;
        let cli = crate::Cli::try_parse_from([
            "pq-diary",
            "--vault",
            vault_dir.to_str().expect("UTF-8"),
            "--password",
            "password",
            "template",
            "add",
            "daily",
        ])
        .expect("CLI");
        let launch = |path: &Path, _: &EditorConfig| {
            std::fs::write(path, "replacement")?;
            // The vault was valid at unlock; alter authenticated padding while
            // the editor is open, after the original lookup already succeeded.
            std::fs::write(&vault_path, &tampered).map_err(pq_diary_core::DiaryError::Io)
        };
        let error = cmd_template_add_impl(
            &cli,
            "daily".into(),
            launch,
            &mut std::io::Cursor::new("y\n"),
        )
        .expect_err("integrity failure");
        assert!(matches!(
            error.downcast_ref::<pq_diary_core::DiaryError>(),
            Some(pq_diary_core::DiaryError::Crypto(_))
        ));
        assert!(error.to_string().starts_with("Failed to replace template:"));
        assert!(
            error.to_string().contains("integrity verification failed"),
            "{error}"
        );
        assert_eq!(std::fs::read(&vault_path).expect("vault"), tampered);
    }

    #[test]
    fn template_context_preserves_io_source_and_diagnostic() {
        for prefix in [
            "Failed to look up template",
            "Failed to list templates",
            "Failed to create template",
            "Failed to replace template",
            "Failed to delete template",
        ] {
            let error = template_command_error(
                prefix,
                pq_diary_core::DiaryError::Io(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "synthetic read failure",
                )),
            );
            assert_eq!(
                error.to_string(),
                format!("{prefix}: I/O error: synthetic read failure")
            );
            assert!(matches!(
                error.downcast_ref::<pq_diary_core::DiaryError>(),
                Some(pq_diary_core::DiaryError::Io(_))
            ));
            assert!(error.chain().any(|cause| cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied)));
        }
    }

    #[test]
    fn template_commands_preserve_lookup_error_types() {
        let dir = tempfile::tempdir().unwrap();
        let vault_dir = setup_vault(&dir);
        let cli = make_template_show_cli(vault_dir.to_str().unwrap(), Some("password"), "daily");
        for error in [
            cmd_template_show(&cli, "daily".into()).unwrap_err(),
            cmd_template_delete_impl(&cli, "daily".into(), true, &mut std::io::Cursor::new(""))
                .unwrap_err(),
        ] {
            assert!(matches!(
                error.downcast_ref::<pq_diary_core::DiaryError>(),
                Some(pq_diary_core::DiaryError::TemplateNotFound(_))
            ));
            assert_eq!(error.to_string(), "template not found: daily");
        }
        seed_malformed_template(&vault_dir);
        let before = std::fs::read(vault_dir.join("vault.pqd")).unwrap();
        for (error, prefix) in [
            (
                cmd_template_list(&cli).unwrap_err(),
                "Failed to list templates:",
            ),
            (
                cmd_template_show(&cli, "daily".into()).unwrap_err(),
                "template error:",
            ),
            (
                cmd_template_delete_impl(&cli, "daily".into(), true, &mut std::io::Cursor::new(""))
                    .unwrap_err(),
                "template error:",
            ),
            (
                cmd_template_add_impl(
                    &cli,
                    "daily".into(),
                    |_, _| panic!("must not launch editor"),
                    &mut std::io::Cursor::new(""),
                )
                .unwrap_err(),
                "Failed to look up template:",
            ),
        ] {
            assert!(matches!(
                error.downcast_ref::<pq_diary_core::DiaryError>(),
                Some(pq_diary_core::DiaryError::Template(_))
            ));
            assert!(error
                .chain()
                .any(|cause| cause.is::<pq_diary_core::DiaryError>()));
            assert!(error.to_string().starts_with(prefix));
            assert!(!format!("{error:?}").contains("S47_PRIVATE_BODY"));
            assert!(!format!("{error:?}").contains("password"));
            assert_eq!(std::fs::read(vault_dir.join("vault.pqd")).unwrap(), before);
        }
    }

    #[test]
    fn template_create_preserves_invalid_name_error() {
        let dir = tempfile::tempdir().unwrap();
        let vault_dir = setup_vault(&dir);
        let before = std::fs::read(vault_dir.join("vault.pqd")).unwrap();
        let cli = make_template_list_cli(vault_dir.to_str().unwrap(), Some("password"));
        let error = cmd_template_add_impl(
            &cli,
            "bad name".into(),
            |_, _| Ok(()),
            &mut std::io::Cursor::new(""),
        )
        .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<pq_diary_core::DiaryError>(),
            Some(pq_diary_core::DiaryError::InvalidTemplateName(_))
        ));
        assert!(error.to_string().starts_with("Failed to create template:"));
        assert_eq!(std::fs::read(vault_dir.join("vault.pqd")).unwrap(), before);
    }

    /// TC-S9-E2E-02: Template lifecycle — add → list → show → delete.
    ///
    /// Validates template CRUD operations end-to-end through DiaryCore API.
    #[test]
    fn tc_s9_e2e_02_template_lifecycle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_vault(&dir);
        let vault_pqd = vault_dir.join("vault.pqd");
        let vault_str = vault_pqd.to_str().expect("utf8");

        let mut core = DiaryCore::new(vault_str).expect("DiaryCore::new");
        let pw: secrecy::SecretString = secrecy::SecretBox::new(Box::from("password"));
        core.unlock(pw).expect("unlock");

        // add template
        let _tmpl_id = core
            .new_template("daily", "# Daily Note\n\nDate: {{date}}\n\n## Tasks\n")
            .expect("new_template");

        // list templates
        let templates = core.list_templates().expect("list_templates");
        assert_eq!(templates.len(), 1, "must have 1 template");
        assert_eq!(templates[0].name, "daily");

        // show template
        let tmpl = core.get_template("daily").expect("get_template");
        assert_eq!(tmpl.name, "daily");
        assert!(
            tmpl.body.contains("Daily Note"),
            "template body must contain 'Daily Note'"
        );

        // delete template
        core.delete_template("daily").expect("delete_template");

        let templates2 = core.list_templates().expect("list_templates after delete");
        assert_eq!(
            templates2.len(),
            0,
            "template list must be empty after delete"
        );

        core.lock();
    }
}
