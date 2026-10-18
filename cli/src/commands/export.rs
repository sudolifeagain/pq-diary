//! Markdown export, exclusive output creation, and export-specific formatting.

use super::{resolve_legacy_vault_dir, resolve_vault_path, session::VaultGuard};
use crate::password::get_password;
use crate::Cli;
use pq_diary_core::DiaryCore;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// export command
// ---------------------------------------------------------------------------

/// Execute the `pq-diary export <DIR>` command.
pub fn cmd_export(cli: &Cli, dir: PathBuf) -> anyhow::Result<()> {
    cmd_export_impl(cli, dir, &mut std::io::BufReader::new(std::io::stdin()))
}

fn cmd_export_impl(
    cli: &Cli,
    dir: PathBuf,
    reader: &mut impl std::io::BufRead,
) -> anyhow::Result<()> {
    use secrecy::{ExposeSecret as _, SecretBox};
    use std::io::Write as _;

    if cli.claude {
        anyhow::bail!("export is not permitted with --claude");
    }

    if !dir.exists() {
        anyhow::bail!("Directory does not exist: {}", dir.display());
    }

    // Preserve policy/output preflight errors before loading configuration,
    // while rejecting unsupported vault targets before any plaintext writes.
    let vault_dir = resolve_legacy_vault_dir(cli)?;

    eprint!(
        "平文を {} に書き出します。続行しますか? [y/N]: ",
        dir.display()
    );
    std::io::stderr()
        .flush()
        .map_err(|e| anyhow::anyhow!("Failed to flush stderr: {e}"))?;
    let mut answer = String::new();
    reader
        .read_line(&mut answer)
        .map_err(|e| anyhow::anyhow!("Failed to read confirmation: {e}"))?;
    let trimmed = answer.trim();
    if !trimmed.eq_ignore_ascii_case("y") {
        println!("キャンセルしました");
        return Ok(());
    }

    let password_source =
        get_password(cli.password.as_ref()).map_err(|e| anyhow::anyhow!("{e}"))?;
    let vault_pqd = resolve_vault_path(cli)?;
    let vault_pqd_str = vault_pqd
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("vault path contains non-UTF-8 characters"))?;

    let mut core = DiaryCore::new(vault_pqd_str).map_err(|e| anyhow::anyhow!("{e}"))?;
    let secret_password: secrecy::SecretString =
        SecretBox::new(Box::from(password_source.secret().expose_secret()));
    core.unlock(secret_password)
        .map_err(|e| anyhow::anyhow!("Vault unlock failed: {e}"))?;
    let guard = VaultGuard::new(&mut core);

    let metas = guard
        .list_entries(None)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    if metas.is_empty() {
        println!("No entries to export");
        return Ok(());
    }

    // Validate every attachment listing before publishing any plaintext output.
    let listing_pwd: secrecy::SecretString =
        secrecy::SecretBox::new(Box::from(password_source.secret().expose_secret()));
    let mut targets = Vec::with_capacity(metas.len());
    for meta in metas {
        let filename = build_export_filename(&meta);
        let path = dir.join(&filename);
        if path.exists() {
            anyhow::bail!("File exists: {}", path.display());
        }
        let attachments = pq_diary_core::attachment::list_attachments(
            &vault_dir,
            &listing_pwd,
            Some(&meta.uuid_hex),
        )
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to list attachments for entry {}: {e}",
                meta.uuid_hex
            )
        })?;
        targets.push((meta, path, attachments));
    }

    let count = targets.len();
    // S13: attachment dir (created lazily — only if any entry has attachments).
    let attachments_dir = dir.join("attachments");
    let mut attachment_count = 0_usize;
    let mut exported_attachment_files: std::collections::HashMap<String, [u8; 32]> =
        std::collections::HashMap::new();
    for (meta, path, attachments) in &targets {
        let id_hex = meta.uuid_hex.clone();
        let (_, plaintext) = guard
            .get_entry(&id_hex)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        // Build base MD body.
        let mut body = plaintext.body.clone();

        // S13: append `![[filename]]` for each attachment, and extract the
        // decrypted file into `<dir>/attachments/`.
        if !attachments.is_empty() {
            std::fs::create_dir_all(&attachments_dir).map_err(|e| {
                anyhow::anyhow!("Failed to create {}: {e}", attachments_dir.display())
            })?;
            if !body.is_empty() && !body.ends_with('\n') {
                body.push('\n');
            }
            for m in attachments {
                let mut export_filename = m.filename.clone();
                let mut out_path = attachments_dir.join(&export_filename);
                let mut already_exported = false;

                if let Some(existing_sha) = exported_attachment_files.get(&export_filename) {
                    if existing_sha == &m.sha256 {
                        already_exported = true;
                    } else {
                        export_filename = disambiguate_attachment_export_filename(
                            &m.filename,
                            &m.sha256,
                            &attachments_dir,
                            &exported_attachment_files,
                        );
                        out_path = attachments_dir.join(&export_filename);
                    }
                } else if out_path.exists() {
                    export_filename = disambiguate_attachment_export_filename(
                        &m.filename,
                        &m.sha256,
                        &attachments_dir,
                        &exported_attachment_files,
                    );
                    out_path = attachments_dir.join(&export_filename);
                }
                if exported_attachment_files
                    .get(&export_filename)
                    .is_some_and(|existing_sha| existing_sha == &m.sha256)
                {
                    already_exported = true;
                }

                if !already_exported {
                    pq_diary_core::attachment::extract_attachment(
                        &vault_dir,
                        &listing_pwd,
                        &id_hex,
                        &m.filename,
                        &out_path,
                    )
                    .map_err(|e| anyhow::anyhow!("attachment extract: {e}"))?;
                    exported_attachment_files.insert(export_filename.clone(), m.sha256);
                }
                body.push_str(&format!("\n![[{}]]", export_filename));
                attachment_count += 1;
            }
        }

        let content = build_export_content(meta, &body);
        write_export_markdown(path, &content)?;
    }

    if attachment_count > 0 {
        println!(
            "Exported {} entries with {} attachments to {}",
            count,
            attachment_count,
            dir.display()
        );
    } else {
        println!("Exported {} entries to {}", count, dir.display());
    }
    Ok(())
}

/// Claim only a new export destination and write through that same handle.
/// The earlier existence check is advisory: another writer or a dangling
/// symlink may occupy the path by the time plaintext is ready to publish.
fn write_export_markdown(path: &Path, content: &str) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use std::io::Write as _;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("Failed to create export file {}", path.display()))?;
    file.write_all(content.as_bytes())
        .with_context(|| format!("Failed to write {}", path.display()))
}

fn build_export_filename(meta: &pq_diary_core::EntryMeta) -> String {
    let date = chrono::DateTime::<chrono::Utc>::from_timestamp(meta.created_at as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "0000-00-00".to_string());
    let slug = slugify(&meta.title);
    let id8 = &meta.uuid_hex[..meta.uuid_hex.len().min(8)];
    format!("{date}-{slug}-{id8}.md")
}

fn build_export_content(meta: &pq_diary_core::EntryMeta, body: &str) -> String {
    let mut out = String::new();
    out.push_str("---\n");
    out.push_str(&format!("id: {}\n", meta.uuid_hex));
    out.push_str(&format!("title: \"{}\"\n", yaml_escape(&meta.title)));
    if meta.tags.is_empty() {
        out.push_str("tags: []\n");
    } else {
        out.push_str("tags:\n");
        for tag in &meta.tags {
            out.push_str(&format!("  - \"{}\"\n", yaml_escape(tag)));
        }
    }
    let created = chrono::DateTime::<chrono::Utc>::from_timestamp(meta.created_at as i64, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| "1970-01-01T00:00:00+00:00".to_string());
    let updated = chrono::DateTime::<chrono::Utc>::from_timestamp(meta.updated_at as i64, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| "1970-01-01T00:00:00+00:00".to_string());
    out.push_str(&format!("created: {created}\n"));
    out.push_str(&format!("updated: {updated}\n"));
    out.push_str("---\n\n");
    out.push_str(body);
    out
}

fn disambiguate_attachment_export_filename(
    filename: &str,
    sha256: &[u8; 32],
    attachments_dir: &std::path::Path,
    exported: &std::collections::HashMap<String, [u8; 32]>,
) -> String {
    let suffix = short_sha_hex(sha256);
    let path = std::path::Path::new(filename);
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("attachment");
    let ext = path.extension().and_then(|s| s.to_str());

    for attempt in 0..1000 {
        let candidate = match (ext, attempt) {
            (Some(ext), 0) => format!("{stem}-{suffix}.{ext}"),
            (None, 0) => format!("{stem}-{suffix}"),
            (Some(ext), n) => format!("{stem}-{suffix}-{n}.{ext}"),
            (None, n) => format!("{stem}-{suffix}-{n}"),
        };
        if let Some(existing_sha) = exported.get(&candidate) {
            if existing_sha == sha256 {
                return candidate;
            }
            continue;
        }
        if !attachments_dir.join(&candidate).exists() {
            return candidate;
        }
    }

    format!("{stem}-{suffix}-overflow")
}

fn short_sha_hex(sha256: &[u8; 32]) -> String {
    sha256.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

fn slugify(title: &str) -> String {
    let mut s = String::with_capacity(title.len());
    let mut prev_dash = false;
    for c in title.chars() {
        if c.is_control() {
            continue;
        }
        let mapped = match c {
            ' ' | '\t' => '-',
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            other => other,
        };
        if mapped == '-' {
            if prev_dash {
                continue;
            }
            prev_dash = true;
        } else {
            prev_dash = false;
        }
        s.push(mapped);
    }
    let trimmed = s.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "untitled".to_string()
    } else {
        trimmed
    }
}

fn yaml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c if c.is_control() => continue,
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{
        make_cli_plain, read_first_entry_plaintext, setup_s10_vault, setup_vault,
    };
    use super::*;
    use pq_diary_core::EntryMeta;

    // -------------------------------------------------------------------------
    // TASK-0094: export tests (helpers + impl)
    // -------------------------------------------------------------------------

    /// TC-501-Slug: slugify handles common cases.
    #[test]
    fn tc_501_slug_handles_common_cases() {
        assert_eq!(slugify("hello"), "hello");
        assert_eq!(slugify(""), "untitled");
        assert_eq!(slugify("   "), "untitled");
        assert_eq!(slugify("foo bar"), "foo-bar");
        assert_eq!(slugify("foo/bar"), "foo_bar");
        assert_eq!(slugify("a\\b:c*d?e\"f<g>h|i"), "a_b_c_d_e_f_g_h_i");
        assert_eq!(slugify("a  b"), "a-b");
    }

    /// TC-501-Yaml: yaml_escape handles quotes / backslashes / newlines.
    #[test]
    fn tc_501_yaml_escape() {
        assert_eq!(yaml_escape("hello"), "hello");
        assert_eq!(yaml_escape("a\"b"), "a\\\"b");
        assert_eq!(yaml_escape("a\\b"), "a\\\\b");
        assert_eq!(yaml_escape("a\nb"), "a\\nb");
        assert_eq!(yaml_escape("a\x07b"), "ab");
    }

    #[test]
    fn exported_frontmatter_roundtrips_without_literal_escapes() {
        for title in [
            "a\"b\\c\n日本語🦀",
            "",
            " leading and trailing ",
            "'quoted'",
        ] {
            let meta = EntryMeta {
                uuid_hex: "0123456789abcdef0123456789abcdef".into(),
                title: title.into(),
                tags: vec![
                    "a,b".into(),
                    "a\"b\\c\n日本語🦀".into(),
                    "".into(),
                    "'tag'".into(),
                ],
                created_at: 0,
                updated_at: 0,
            };
            let exported = build_export_content(&meta, "body");
            let (imported, _, _) =
                pq_diary_core::importer::parse_markdown(&exported, "fallback.md").unwrap();
            assert_eq!(imported.title, meta.title);
            assert_eq!(imported.tags, meta.tags);
        }
    }

    #[test]
    fn exported_frontmatter_survives_import_and_reopen() {
        let source = tempfile::tempdir().unwrap();
        let source_vault = setup_vault(&source);
        let title = "a\"b\\c\n日本語🦀";
        let tags = vec!["comma,tag".to_string(), "'quote'".into(), "".into()];
        let body = "literal #123 and `#code`";
        {
            let mut core =
                DiaryCore::new(source_vault.join("vault.pqd").to_str().unwrap()).unwrap();
            core.unlock(secrecy::SecretBox::new(Box::from("password")))
                .unwrap();
            core.new_entry(title, body, tags.clone()).unwrap();
        }
        let exported = tempfile::tempdir().unwrap();
        let cli = make_cli_plain(&[
            "-v",
            source_vault.to_str().unwrap(),
            "--password",
            "password",
            "export",
            exported.path().to_str().unwrap(),
        ]);
        cmd_export_impl(
            &cli,
            exported.path().to_path_buf(),
            &mut std::io::Cursor::new("y\n"),
        )
        .unwrap();
        let destination = tempfile::tempdir().unwrap();
        let destination_vault = setup_vault(&destination);
        {
            let mut core =
                DiaryCore::new(destination_vault.join("vault.pqd").to_str().unwrap()).unwrap();
            core.unlock(secrecy::SecretBox::new(Box::from("password")))
                .unwrap();
            assert_eq!(core.import(exported.path(), false).unwrap().imported, 1);
        }
        let imported = read_first_entry_plaintext(&destination_vault);
        assert_eq!(imported.title, title);
        assert_eq!(imported.tags, tags);
        // Export deliberately separates frontmatter from the original body.
        assert_eq!(imported.body, format!("\n{body}"));
    }

    /// TC-501-Fname: build_export_filename produces YYYY-MM-DD-slug-id8.md.
    #[test]
    fn tc_501_filename_format() {
        let meta = EntryMeta {
            uuid_hex: "3c6b775f4d8e4c2b9a1f8d5e1f0a2b3c".to_string(),
            title: "Hello World".to_string(),
            tags: vec![],
            created_at: 1_747_440_000,
            updated_at: 1_747_440_000,
        };
        let name = build_export_filename(&meta);
        assert!(name.starts_with("2025-05-17-Hello-World-3c6b775f"));
        assert!(name.ends_with(".md"));
    }

    /// TC-501-AttachmentName: same attachment filename with different content is disambiguated.
    #[test]
    fn tc_501_attachment_export_filename_disambiguates_collision() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut exported = std::collections::HashMap::new();
        exported.insert("photo.png".to_string(), [0x11; 32]);

        let name = disambiguate_attachment_export_filename(
            "photo.png",
            &[0x22; 32],
            dir.path(),
            &exported,
        );

        assert_eq!(name, "photo-22222222.png");
    }

    /// TC-503-01: build_export_content emits expected YAML keys.
    #[test]
    fn tc_503_01_content_has_yaml_keys() {
        let meta = EntryMeta {
            uuid_hex: "3c6b775f4d8e4c2b9a1f8d5e1f0a2b3c".to_string(),
            title: "T".to_string(),
            tags: vec!["x".to_string()],
            created_at: 1_747_440_000,
            updated_at: 1_747_440_000,
        };
        let body = "Hello!\n";
        let content = build_export_content(&meta, body);
        assert!(content.starts_with("---\n"));
        assert!(content.contains("id: 3c6b775f4d8e4c2b9a1f8d5e1f0a2b3c"));
        assert!(content.contains("title: \"T\""));
        assert!(content.contains("tags:\n  - \"x\""));
        assert!(content.contains("created: "));
        assert!(content.contains("updated: "));
        assert!(content.ends_with("Hello!\n"));
    }

    /// TC-511-01: --claude blocks export.
    #[test]
    fn tc_511_01_export_blocked_with_claude() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out_dir = dir.path().join("out");
        std::fs::create_dir_all(&out_dir).expect("mkdir out");

        let cli = make_cli_plain(&["--claude", "export", out_dir.to_str().unwrap()]);
        let mut stdin = std::io::Cursor::new(b"y\n".to_vec());
        let err = cmd_export_impl(&cli, out_dir.clone(), &mut stdin).expect_err("must fail");
        assert!(
            format!("{err:#}").contains("not permitted with --claude"),
            "got: {err:#}"
        );

        let count = std::fs::read_dir(&out_dir).unwrap().count();
        assert_eq!(count, 0);
    }

    /// TC-512-01: nonexistent dir errors.
    #[test]
    fn tc_512_01_export_missing_dir_errors() {
        let cli = make_cli_plain(&["export", "/no/such/dir"]);
        let mut stdin = std::io::Cursor::new(b"y\n".to_vec());
        let err = cmd_export_impl(&cli, PathBuf::from("/no/such/dir"), &mut stdin)
            .expect_err("must fail");
        assert!(
            format!("{err:#}").contains("Directory does not exist"),
            "got: {err:#}"
        );
    }

    /// TC-513-01: empty input cancels.
    #[test]
    fn tc_513_01_export_cancel_on_empty_input() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_s10_vault(&dir, "v", b"password");
        let vault_dir_str = vault_dir.to_str().expect("utf8");
        let out_dir = dir.path().join("out");
        std::fs::create_dir_all(&out_dir).expect("mkdir out");

        let cli = make_cli_plain(&[
            "-v",
            vault_dir_str,
            "--password",
            "password",
            "export",
            out_dir.to_str().unwrap(),
        ]);
        let mut stdin = std::io::Cursor::new(b"\n".to_vec());
        cmd_export_impl(&cli, out_dir.clone(), &mut stdin).expect("cancel is Ok");
        assert_eq!(std::fs::read_dir(&out_dir).unwrap().count(), 0);
    }

    /// TC-513-02: 'n' input cancels.
    #[test]
    fn tc_513_02_export_cancel_on_n() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_s10_vault(&dir, "v", b"password");
        let vault_dir_str = vault_dir.to_str().expect("utf8");
        let out_dir = dir.path().join("out");
        std::fs::create_dir_all(&out_dir).expect("mkdir out");

        let cli = make_cli_plain(&[
            "-v",
            vault_dir_str,
            "--password",
            "password",
            "export",
            out_dir.to_str().unwrap(),
        ]);
        let mut stdin = std::io::Cursor::new(b"n\n".to_vec());
        cmd_export_impl(&cli, out_dir.clone(), &mut stdin).expect("cancel is Ok");
        assert_eq!(std::fs::read_dir(&out_dir).unwrap().count(), 0);
    }

    /// TC-501-B01: empty vault → "No entries to export".
    #[test]
    fn tc_501_b01_empty_vault() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_s10_vault(&dir, "v", b"password");
        let vault_dir_str = vault_dir.to_str().expect("utf8");
        let out_dir = dir.path().join("out");
        std::fs::create_dir_all(&out_dir).expect("mkdir out");

        let cli = make_cli_plain(&[
            "-v",
            vault_dir_str,
            "--password",
            "password",
            "export",
            out_dir.to_str().unwrap(),
        ]);
        let mut stdin = std::io::Cursor::new(b"y\n".to_vec());
        cmd_export_impl(&cli, out_dir.clone(), &mut stdin).expect("ok");
        assert_eq!(std::fs::read_dir(&out_dir).unwrap().count(), 0);
    }

    /// Attachment metadata errors must fail export before publishing any files.
    #[test]
    fn export_rejects_corrupt_attachment_metadata() {
        export_attachment_fixture(true);
    }

    #[test]
    fn export_preserves_attachment_content_and_links() {
        export_attachment_fixture(false);
    }

    fn export_attachment_fixture(corrupt: bool) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_s10_vault(&dir, "v", b"password");
        let pqd = vault_dir.join("vault.pqd");
        let password = secrecy::SecretBox::new(Box::from("password"));
        let id = {
            let mut core = DiaryCore::new(pqd.to_str().unwrap()).expect("core");
            core.unlock(secrecy::SecretBox::new(Box::from("password")))
                .expect("unlock");
            core.new_entry("without attachment", "first body", vec![])
                .expect("first entry");
            core.new_entry("with attachment", "second body", vec![])
                .expect("second entry")
        };
        let source = dir.path().join("example.txt");
        std::fs::write(&source, b"attachment contents").expect("source");
        pq_diary_core::attachment::add_attachment(&vault_dir, &password, &id, &source)
            .expect("add attachment");
        if corrupt {
            let (header, entries, mut attachments) =
                pq_diary_core::vault::reader::read_vault_with_attachments(&pqd)
                    .expect("read fixture");
            attachments[0].content_hmac[0] ^= 1;
            // The legacy/test writer omits the whole-vault MAC so unlock succeeds;
            // attachment enumeration must still reject the invalid record HMAC.
            pq_diary_core::vault::writer::write_vault_with_attachments(
                &pqd,
                header,
                &entries,
                &attachments,
            )
            .expect("write corrupt fixture");
        }
        let original = std::fs::read(&pqd).expect("vault bytes");
        let original_config = std::fs::read(vault_dir.join("vault.toml")).expect("config bytes");
        let out = dir.path().join("out");
        std::fs::create_dir(&out).expect("output directory");
        let cli = make_cli_plain(&[
            "--vault",
            vault_dir.to_str().unwrap(),
            "--password",
            "password",
            "export",
            out.to_str().unwrap(),
        ]);
        let result = cmd_export_impl(&cli, out.clone(), &mut std::io::Cursor::new(b"y\n"));
        if corrupt {
            let error = result
                .expect_err("corrupt attachment must fail export")
                .to_string();
            assert!(
                error.contains("Failed to list attachments for entry"),
                "{error}"
            );
            assert_eq!(std::fs::read_dir(&out).unwrap().count(), 0);
        } else {
            result.expect("export succeeds");
            assert_eq!(
                std::fs::read(out.join("attachments/example.txt")).unwrap(),
                b"attachment contents"
            );
            let markdown: Vec<_> = std::fs::read_dir(&out)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "md"))
                .collect();
            assert_eq!(markdown.len(), 2);
            assert!(markdown.iter().any(|path| std::fs::read_to_string(path)
                .unwrap()
                .contains("second body\n\n![[example.txt]]")));
        }
        assert_eq!(std::fs::read(&pqd).unwrap(), original);
        assert_eq!(
            std::fs::read(vault_dir.join("vault.toml")).unwrap(),
            original_config
        );
        let mut core = DiaryCore::new(pqd.to_str().unwrap()).expect("reopen");
        core.unlock(password).expect("unlock after export");
        assert_eq!(core.list_entries(None).unwrap().len(), 2);
        assert_eq!(core.get_entry(&id).unwrap().1.body, "second body");
    }

    #[test]
    fn export_preserves_destination_created_after_preflight() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("export.md");
        assert!(!path.exists(), "export preflight sees an available path");
        // A competing writer claims the destination after our preflight.
        std::fs::write(&path, b"other writer's contents").expect("competing file");

        let error = write_export_markdown(&path, "private export body")
            .expect_err("exclusive creation must reject the competing file");
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .expect("typed output error")
                .kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            std::fs::read(&path).expect("competing file"),
            b"other writer's contents"
        );
    }

    #[cfg(unix)]
    #[test]
    fn export_rejects_dangling_symlink_without_publishing_plaintext() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_s10_vault(&dir, "v", b"password");
        let pqd = vault_dir.join("vault.pqd");
        let mut core = DiaryCore::new(pqd.to_str().expect("path")).expect("core");
        core.unlock(secrecy::SecretBox::new(Box::from("password")))
            .expect("unlock");
        let id = core
            .new_entry("export fixture", "private export body", vec![])
            .expect("entry");
        let meta = core.list_entries(None).expect("entries").remove(0);
        core.lock();

        let original = std::fs::read(&pqd).expect("vault snapshot");
        let config_path = vault_dir.join("vault.toml");
        let original_config = std::fs::read(&config_path).expect("config snapshot");
        let out = dir.path().join("out");
        std::fs::create_dir(&out).expect("output directory");
        let destination = out.join(build_export_filename(&meta));
        let outside = dir.path().join("must-not-create.md");
        symlink(&outside, &destination).expect("dangling output symlink");
        assert!(
            !destination.exists(),
            "preflight follows the missing target"
        );

        let cli = make_cli_plain(&[
            "--vault",
            vault_dir.to_str().expect("vault path"),
            "--password",
            "password",
            "export",
            out.to_str().expect("output path"),
        ]);
        let error = cmd_export_impl(&cli, out.clone(), &mut std::io::Cursor::new(b"y\n"))
            .expect_err("export must not follow the output symlink");
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .expect("typed output error")
                .kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert!(
            !outside.exists(),
            "plaintext must not escape the output directory"
        );
        assert_eq!(std::fs::read_link(&destination).expect("symlink"), outside);
        assert_eq!(std::fs::read_dir(&out).expect("outputs").count(), 1);
        assert_eq!(std::fs::read(&pqd).expect("vault"), original);
        assert_eq!(
            std::fs::read(&config_path).expect("config"),
            original_config
        );
        core.unlock(secrecy::SecretBox::new(Box::from("password")))
            .expect("reopen");
        assert_eq!(
            core.get_entry(&id).expect("entry").1.body,
            "private export body"
        );
        core.lock();
    }

    /// TC-501-01: 3 entries export → 3 well-named files.
    #[test]
    fn tc_501_01_export_three_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_dir = setup_s10_vault(&dir, "v", b"password");
        let vault_dir_str = vault_dir.to_str().expect("utf8");
        let out_dir = dir.path().join("out");
        std::fs::create_dir_all(&out_dir).expect("mkdir out");

        let pqd = vault_dir.join("vault.pqd");
        {
            let mut core = DiaryCore::new(pqd.to_str().unwrap()).expect("DiaryCore::new");
            core.unlock(secrecy::SecretBox::new(Box::from("password")))
                .expect("unlock");
            core.new_entry("first", "body1", vec!["t".into()])
                .expect("e1");
            core.new_entry("second", "body2", vec![]).expect("e2");
            core.new_entry("third", "body3", vec![]).expect("e3");
        }

        let cli = make_cli_plain(&[
            "-v",
            vault_dir_str,
            "--password",
            "password",
            "export",
            out_dir.to_str().unwrap(),
        ]);
        let mut stdin = std::io::Cursor::new(b"y\n".to_vec());
        cmd_export_impl(&cli, out_dir.clone(), &mut stdin).expect("export ok");

        let files: Vec<_> = std::fs::read_dir(&out_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(files.len(), 3, "must export 3 files");
        for entry in files {
            let name = entry.file_name();
            let s = name.to_string_lossy();
            assert!(s.ends_with(".md"), "extension .md: {s}");
            assert!(
                s.chars().nth(4) == Some('-') && s.chars().nth(7) == Some('-'),
                "expected date prefix in {s}"
            );
        }
    }
}
