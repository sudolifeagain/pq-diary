//! Obsidian-compatible Markdown file importer.
//!
//! Provides types and functions for parsing Markdown files with YAML frontmatter,
//! converting Obsidian wiki-links, extracting inline `#tag` notation, and
//! filtering paths during directory traversal.
//!
//! # Batch import
//!
//! [`import_directory`] walks a source directory recursively, parses each `.md`
//! file via [`parse_markdown`], and writes all resulting entries to the vault
//! with a single [`batch_create_entries`] call (i.e., one `write_vault`
//! invocation regardless of the number of files).

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use uuid::Uuid;
use walkdir::WalkDir;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// =========================================================================
// Static regexes (compiled once via LazyLock)
// =========================================================================

static WIKI_LINK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\[\[([^\]|]+)(?:\|[^\]]+)?\]\]").unwrap()
});

static TAG_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"#([\w/]+)").unwrap()
});

static FENCED_CODE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)```[^\n]*\n.*?```").unwrap()
});

static INLINE_CODE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"`[^`]+`").unwrap()
});

use crate::{
    crypto::CryptoEngine,
    entry::EntryPlaintext,
    error::DiaryError,
    vault::{
        format::{generate_entry_padding, EntryRecord, RECORD_TYPE_ENTRY},
        reader::read_vault,
        writer::write_vault,
    },
};

// =========================================================================
// Public types
// =========================================================================

/// Import source configuration.
pub struct ImportSource {
    /// Source directory path.
    pub directory: PathBuf,
    /// If true, only preview without writing (dry-run mode).
    pub dry_run: bool,
}

/// A parsed Markdown file ready for import into the vault.
///
/// Implements [`Zeroize`] and [`ZeroizeOnDrop`] to ensure that parsed
/// content (title, body, tags) is securely erased from memory when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MarkdownFile {
    /// Entry title derived from frontmatter `title:` field or the filename stem.
    pub title: String,
    /// Combined tag list from frontmatter `tags:` and inline `#tag` notation.
    pub tags: Vec<String>,
    /// Body text with wiki-link aliases removed and inline tags stripped.
    pub body: String,
    /// Original source file path, used for error reporting.
    pub source_path: String,
}

/// Summary of an import operation.
pub struct ImportResult {
    /// Number of entries successfully imported into the vault.
    pub imported: usize,
    /// Number of files skipped (non-`.md`, inside `.obsidian/`, or duplicates).
    pub skipped: usize,
    /// Total number of `[[link|alias]]` → `[[link]]` conversions performed.
    pub links_converted: usize,
    /// Total number of inline `#tag` extractions performed.
    pub tags_converted: usize,
    /// Per-file details for each skipped entry.
    pub skip_details: Vec<SkipDetail>,
    /// Number of files that would have been imported (populated only in dry-run mode).
    pub would_import: usize,
}

/// Details about a single skipped file during import.
pub struct SkipDetail {
    /// File path that was skipped.
    pub path: String,
    /// Human-readable reason for skipping.
    pub reason: String,
}

// =========================================================================
// Public API
// =========================================================================

/// Parse raw Markdown content into a [`MarkdownFile`].
///
/// Processes YAML frontmatter for `title` and `tags`, converts Obsidian-style
/// `[[link|alias]]` to `[[link]]`, and extracts inline `#tag` notation into
/// the tag list.
///
/// # Arguments
///
/// * `content` — Raw UTF-8 Markdown content.
/// * `filename` — File name (with extension) used as fallback title when no
///   frontmatter title is present.
///
/// # Returns
///
/// A tuple `(MarkdownFile, links_converted, tags_converted)` on success.
///
/// # Errors
///
/// Returns [`DiaryError::Import`] if an internal regex fails to compile.
pub fn parse_markdown(
    content: &str,
    filename: &str,
) -> Result<(MarkdownFile, usize, usize), DiaryError> {
    // 0. Normalize CRLF → LF
    let content = Zeroizing::new(content.replace("\r\n", "\n"));

    // 1. Parse YAML frontmatter
    let (frontmatter_title, frontmatter_tags, body_raw) = parse_frontmatter(&content);

    // 2. Determine title: frontmatter title takes priority over filename stem
    let title = frontmatter_title.unwrap_or_else(|| {
        Path::new(filename)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(filename)
            .to_string()
    });

    // 3. Convert wiki-links in body
    let (body_after_links, links_converted) = convert_wiki_links(body_raw)?;

    // 4. Extract inline #tags from body
    let (extracted_tags, body_final, tags_converted) = extract_tags(&body_after_links)?;

    // 5. Merge tags: frontmatter tags first, then extracted tags (no duplicates)
    let mut all_tags = frontmatter_tags;
    for tag in extracted_tags {
        if !all_tags.contains(&tag) {
            all_tags.push(tag);
        }
    }

    let md_file = MarkdownFile {
        title,
        tags: all_tags,
        body: body_final,
        source_path: filename.to_string(),
    };

    Ok((md_file, links_converted, tags_converted))
}

/// Returns `true` if `path` contains a `.obsidian` path component.
///
/// Used during directory traversal to skip Obsidian metadata directories.
pub fn should_skip_path(path: &Path) -> bool {
    path.components().any(|c| c.as_os_str() == ".obsidian")
}

/// Create multiple vault entries in a single `write_vault` call.
///
/// Reads the existing vault, encrypts and signs every [`MarkdownFile`] as an
/// [`EntryRecord`], appends all records to the existing list, then calls
/// `write_vault` **exactly once**.  This is the performance-critical path for
/// bulk import: O(n) encryption + O(1) vault I/O.
///
/// Returns an [`ImportResult`] with `imported` set to the number of entries
/// written and all other counters at zero; callers such as
/// [`import_directory`] are expected to fill in the remaining fields.
///
/// # Errors
///
/// Returns [`DiaryError::Io`] on vault I/O failure.
/// Returns [`DiaryError::Import`] if JSON serialisation fails or the system
///   clock is unavailable.
/// Returns [`DiaryError::Crypto`] on encryption or signing failure.
pub fn batch_create_entries(
    vault_path: &Path,
    engine: &CryptoEngine,
    files: Vec<MarkdownFile>,
) -> Result<ImportResult, DiaryError> {
    let (header, mut records) = read_vault(vault_path)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| DiaryError::Import(format!("system time error: {e}")))?
        .as_secs();

    let imported = files.len();

    for mut file in files.into_iter() {
        let uuid = Uuid::new_v4();

        let plaintext = EntryPlaintext {
            title: std::mem::take(&mut file.title),
            tags: std::mem::take(&mut file.tags),
            body: std::mem::take(&mut file.body),
        };

        let json_bytes = Zeroizing::new(
            serde_json::to_vec(&plaintext)
                .map_err(|e| DiaryError::Import(format!("serialization failed: {e}")))?,
        );

        let (ciphertext, iv) = engine.encrypt(&json_bytes)?;
        let signature = engine.dsa_sign(&ciphertext)?;
        let content_hmac = engine.hmac(&ciphertext)?;

        let record = EntryRecord {
            record_type: RECORD_TYPE_ENTRY,
            uuid: *uuid.as_bytes(),
            created_at: now,
            updated_at: now,
            iv,
            ciphertext,
            signature,
            content_hmac,
            legacy_flag: 0x00,
            legacy_key_block: vec![],
            attachment_count: 0,
            attachment_offset: 0,
            padding: generate_entry_padding(),
        };

        records.push(record);
    }

    write_vault(vault_path, header, &records)?;

    Ok(ImportResult {
        imported,
        skipped: 0,
        links_converted: 0,
        tags_converted: 0,
        skip_details: vec![],
        would_import: 0,
    })
}

/// Import all Markdown files found under `source_dir` into the vault.
///
/// Recursively walks `source_dir` using [`walkdir`], skipping `.obsidian/`
/// directories and non-`.md` files.  Each `.md` file is read into a
/// `Zeroizing<String>` buffer (ensuring the raw content is erased on drop),
/// parsed with [`parse_markdown`], and collected into a batch.  All entries
/// are then written to the vault in a single [`batch_create_entries`] call.
///
/// Source files are **never** deleted or modified.
///
/// When `dry_run` is `true` the vault file is not touched; the returned
/// [`ImportResult`] has `imported: 0` and the remaining fields reflect what
/// *would* have happened.
///
/// # Errors
///
/// Returns [`DiaryError::Import`] if `source_dir` does not exist.
/// Returns [`DiaryError::Import`] if no `.md` files are found under `source_dir`.
/// Returns [`DiaryError::Io`] on file-read or vault I/O failure.
/// Returns [`DiaryError::Import`] on directory walk errors.
/// Returns [`DiaryError::Crypto`] on encryption or signing failure.
pub fn import_directory(
    vault_path: &Path,
    engine: &CryptoEngine,
    source_dir: &Path,
    dry_run: bool,
) -> Result<ImportResult, DiaryError> {
    if !source_dir.exists() {
        return Err(DiaryError::Import(format!(
            "source directory does not exist: {}",
            source_dir.display()
        )));
    }

    let mut parsed_files: Vec<MarkdownFile> = Vec::new();
    let mut skip_details: Vec<SkipDetail> = Vec::new();
    let mut links_converted: usize = 0;
    let mut tags_converted: usize = 0;

    for entry in WalkDir::new(source_dir).follow_links(false) {
        let entry = entry.map_err(|e| DiaryError::Import(format!("directory walk error: {e}")))?;
        let path = entry.path();

        // Directories are traversed but not counted.
        if entry.file_type().is_dir() {
            continue;
        }

        // Files inside .obsidian/ are skipped with a reason recorded.
        if should_skip_path(path) {
            skip_details.push(SkipDetail {
                path: path.to_string_lossy().into_owned(),
                reason: "inside .obsidian directory".to_string(),
            });
            continue;
        }

        // Non-Markdown files are skipped with a reason recorded.
        let is_md = path.extension().and_then(|s| s.to_str()) == Some("md");
        if !is_md {
            skip_details.push(SkipDetail {
                path: path.to_string_lossy().into_owned(),
                reason: "not a Markdown (.md) file".to_string(),
            });
            continue;
        }

        // Parse the .md file.  Wrap raw content in Zeroizing so it is erased
        // from memory as soon as it goes out of scope.
        let filename = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown.md");

        let content = Zeroizing::new(std::fs::read_to_string(path)?);
        let (md_file, lc, tc) = parse_markdown(&content, filename)?;
        links_converted += lc;
        tags_converted += tc;
        parsed_files.push(md_file);
    }

    if parsed_files.is_empty() {
        return Err(DiaryError::Import("No Markdown files found".to_string()));
    }

    let skipped = skip_details.len();

    if dry_run {
        return Ok(ImportResult {
            imported: 0,
            skipped,
            links_converted,
            tags_converted,
            skip_details,
            would_import: parsed_files.len(),
        });
    }

    let mut result = batch_create_entries(vault_path, engine, parsed_files)?;
    result.skipped = skipped;
    result.links_converted = links_converted;
    result.tags_converted = tags_converted;
    result.skip_details = skip_details;

    Ok(result)
}

// =========================================================================
// Private helpers
// =========================================================================

/// Parse YAML frontmatter from Markdown content.
///
/// Returns `(title, tags, body_str)` where `body_str` is a `&str` slice
/// into `content` following the closing `---` delimiter.  When no valid
/// frontmatter is detected, returns `(None, [], content)`.
fn parse_frontmatter(content: &str) -> (Option<String>, Vec<String>, &str) {
    if !content.starts_with("---\n") {
        return (None, Vec::new(), content);
    }

    let after_open = &content[4..]; // skip "---\n"

    // Find the closing delimiter.  Try "\n---\n" first (body follows), then
    // "\n---" at end-of-file (no trailing newline).
    let close_pair = after_open
        .find("\n---\n")
        .map(|pos| (pos, pos + 5))
        .or_else(|| {
            if after_open.ends_with("\n---") {
                let pos = after_open.len() - 4;
                Some((pos, after_open.len()))
            } else {
                None
            }
        });

    let (fm_end, body_start) = match close_pair {
        Some(pair) => pair,
        None => return (None, Vec::new(), content),
    };

    let fm_str = &after_open[..fm_end];
    let body = &after_open[body_start..];

    let title = extract_frontmatter_title(fm_str);
    let tags = extract_frontmatter_tags(fm_str);

    (title, tags, body)
}

/// Extract the `title:` value from a frontmatter string.
fn extract_frontmatter_title(fm: &str) -> Option<String> {
    for line in fm.lines() {
        if let Some(rest) = line.strip_prefix("title:") {
            let value = rest.trim().trim_matches('"').trim_matches('\'').to_string();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

/// Extract `tags:` values from a frontmatter string.
///
/// Handles both inline `tags: [tag1, tag2]` and YAML list formats:
/// ```text
/// tags:
///   - tag1
///   - tag2
/// ```
fn extract_frontmatter_tags(fm: &str) -> Vec<String> {
    let mut tags = Vec::new();
    let mut in_tags_list = false;

    for line in fm.lines() {
        if let Some(rest) = line.strip_prefix("tags:") {
            in_tags_list = false;
            let rest = rest.trim();
            if rest.starts_with('[') && rest.ends_with(']') {
                // Inline format: tags: [tag1, tag2]
                let inner = &rest[1..rest.len() - 1];
                for tag in inner.split(',') {
                    let t = tag.trim().trim_matches('"').trim_matches('\'').to_string();
                    if !t.is_empty() {
                        tags.push(t);
                    }
                }
            } else if rest.is_empty() {
                // List format: tags: followed by "- tag" lines
                in_tags_list = true;
            }
        } else if in_tags_list {
            let trimmed = line.trim();
            if let Some(tag_str) = trimmed.strip_prefix("- ") {
                let t = tag_str
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string();
                if !t.is_empty() {
                    tags.push(t);
                }
            } else if !trimmed.is_empty() {
                // Non-list-item line encountered: end of tag list
                in_tags_list = false;
            }
        }
    }

    tags
}

/// Convert Obsidian `[[wiki-link|alias]]` to `[[wiki-link]]`.
///
/// Alias-free links such as `[[My Note]]` are preserved unchanged.
/// Links with aliases such as `[[My Note|alias]]` are converted to `[[My Note]]`.
///
/// Returns `(converted_body, alias_removal_count)`.
///
/// # Errors
///
/// Returns [`DiaryError::Import`] if the regex fails to compile.
fn convert_wiki_links(body: &str) -> Result<(String, usize), DiaryError> {
    let re = &*WIKI_LINK_RE;

    let mut count = 0usize;
    let result = re.replace_all(body, |caps: &regex::Captures| {
        let title = caps.get(1).map_or("", |m| m.as_str());
        let full_match = caps.get(0).map_or("", |m| m.as_str());
        if full_match.contains('|') {
            count += 1;
        }
        format!("[[{title}]]")
    });

    Ok((result.into_owned(), count))
}

/// Extract inline `#tag` notation from body text.
///
/// Finds all `#word` and `#word/word` patterns, adds them to the tag list, and
/// removes them from the body.  Nested tags (e.g. `#work/project/alpha`) are
/// preserved with the `/` separator intact.
///
/// Returns `(tags, cleaned_body, extraction_count)`.
///
/// # Errors
///
/// Returns [`DiaryError::Import`] if the regex fails to compile.
fn extract_tags(body: &str) -> Result<(Vec<String>, String, usize), DiaryError> {
    let re = &*TAG_RE;

    // Build a set of byte-offset ranges that fall inside code blocks
    // (fenced ```...``` and inline `...`).  Tags inside these ranges are ignored.
    let mut code_ranges: Vec<std::ops::Range<usize>> = Vec::new();
    for m in FENCED_CODE_RE.find_iter(body) {
        code_ranges.push(m.start()..m.end());
    }
    for m in INLINE_CODE_RE.find_iter(body) {
        code_ranges.push(m.start()..m.end());
    }

    let in_code = |pos: usize| -> bool { code_ranges.iter().any(|r| r.contains(&pos)) };

    let mut tags: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut count = 0usize;

    let cleaned = re.replace_all(body, |caps: &regex::Captures| {
        let m = caps.get(0).unwrap();
        if in_code(m.start()) {
            // Inside a code block — keep the original text untouched.
            return m.as_str().to_string();
        }
        let tag_name = caps.get(1).map_or("", |m| m.as_str()).to_string();
        if seen.insert(tag_name.clone()) {
            tags.push(tag_name);
        }
        count += 1;
        String::new()
    });

    Ok((tags, cleaned.into_owned(), count))
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::kdf::Argon2Params,
        vault::{init::VaultManager, reader::read_vault},
        DiaryCore,
    };
    use secrecy::SecretBox;
    use std::path::Path;
    use tempfile::TempDir;

    // -------------------------------------------------------------------------
    // Shared helpers
    // -------------------------------------------------------------------------

    fn fast_params() -> Argon2Params {
        Argon2Params {
            memory_cost_kb: 8,
            time_cost: 1,
            parallelism: 1,
        }
    }

    /// Initialise a test vault and return the path to `vault.pqd`.
    fn setup_test_vault(dir: &TempDir) -> std::path::PathBuf {
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());
        mgr.init_vault("test", b"password").expect("init_vault");
        dir.path().join("test").join("vault.pqd")
    }

    fn secret(s: &str) -> secrecy::SecretString {
        SecretBox::new(s.into())
    }

    // -------------------------------------------------------------------------
    // TC-D01-03: filename becomes title when no frontmatter
    // -------------------------------------------------------------------------

    /// TC-D01-03: parse_markdown with no frontmatter uses filename stem as title.
    #[test]
    fn tc_d01_03_filename_as_title() {
        let content = "This is the body text without frontmatter.";
        let (md, _, _) = parse_markdown(content, "my-daily-note.md").expect("parse_markdown");
        assert_eq!(md.title, "my-daily-note");
    }

    // -------------------------------------------------------------------------
    // TC-D01-04: frontmatter title takes priority over filename
    // -------------------------------------------------------------------------

    /// TC-D01-04: frontmatter `title:` is used instead of filename stem.
    #[test]
    fn tc_d01_04_frontmatter_title_priority() {
        let content = "---\ntitle: My Custom Title\n---\nBody content.";
        let (md, _, _) = parse_markdown(content, "fallback-name.md").expect("parse_markdown");
        assert_eq!(md.title, "My Custom Title");
    }

    // -------------------------------------------------------------------------
    // TC-D04-01: [[wiki-link]] without alias is preserved
    // -------------------------------------------------------------------------

    /// TC-D04-01: `[[My Note]]` (no alias) is kept as-is; links_converted = 0.
    #[test]
    fn tc_d04_01_wiki_link_preserved() {
        let content = "See [[My Note]] for details";
        let (md, links, _) = parse_markdown(content, "test.md").expect("parse_markdown");
        assert!(
            md.body.contains("[[My Note]]"),
            "body must contain [[My Note]]"
        );
        assert_eq!(links, 0, "no alias conversions for alias-free links");
    }

    // -------------------------------------------------------------------------
    // TC-D04-02: [[link|alias]] → [[link]] with alias removal counted
    // -------------------------------------------------------------------------

    /// TC-D04-02: `[[Other|alias text]]` → `[[Other]]`; links_converted = 1.
    #[test]
    fn tc_d04_02_alias_removal() {
        let content = "See [[Other|alias text]] for details";
        let (md, links, _) = parse_markdown(content, "test.md").expect("parse_markdown");
        assert_eq!(md.body, "See [[Other]] for details");
        assert_eq!(links, 1, "one alias conversion performed");
    }

    // -------------------------------------------------------------------------
    // TC-D05-01: #tag extracted from body
    // -------------------------------------------------------------------------

    /// TC-D05-01: `#diary` is extracted into tags and removed from body.
    #[test]
    fn tc_d05_01_inline_tag_extracted() {
        let content = "Today #diary stuff";
        let (md, _, tags_count) = parse_markdown(content, "test.md").expect("parse_markdown");
        assert!(
            md.tags.contains(&"diary".to_string()),
            "tags must contain 'diary'"
        );
        assert!(
            !md.body.contains("#diary"),
            "body must not contain #diary after extraction"
        );
        assert_eq!(tags_count, 1, "one tag extracted");
    }

    // -------------------------------------------------------------------------
    // TC-D05-02: nested tag #parent/child/grandchild preserved with /
    // -------------------------------------------------------------------------

    /// TC-D05-02: `#work/project/alpha` is stored as a single tag with `/` separators.
    #[test]
    fn tc_d05_02_nested_tag_preserved() {
        let content = "Working on #work/project/alpha";
        let (md, _, _) = parse_markdown(content, "test.md").expect("parse_markdown");
        assert!(
            md.tags.contains(&"work/project/alpha".to_string()),
            "tags must contain 'work/project/alpha'"
        );
    }

    // -------------------------------------------------------------------------
    // TC-D06-01: frontmatter tags + extracted tags merged without duplicates
    // -------------------------------------------------------------------------

    /// TC-D06-01: frontmatter `tags: [diary, personal]` merged with extracted `#work`.
    #[test]
    fn tc_d06_01_frontmatter_and_extracted_tags_merged() {
        let content = "---\ntags: [diary, personal]\n---\nToday #work";
        let (md, _, _) = parse_markdown(content, "test.md").expect("parse_markdown");
        assert_eq!(
            md.tags,
            vec![
                "diary".to_string(),
                "personal".to_string(),
                "work".to_string()
            ],
            "tags must be frontmatter tags followed by extracted tags"
        );
    }

    // -------------------------------------------------------------------------
    // TC-D08-01: .obsidian/ paths are skipped
    // -------------------------------------------------------------------------

    /// TC-D08-01: `should_skip_path` returns true for `.obsidian/` and false otherwise.
    #[test]
    fn tc_d08_01_obsidian_dir_skipped() {
        assert!(
            should_skip_path(Path::new("notes/.obsidian/config.json")),
            "paths inside .obsidian/ must be skipped"
        );
        assert!(
            !should_skip_path(Path::new("notes/daily/2026-04-08.md")),
            "normal paths must not be skipped"
        );
    }

    // -------------------------------------------------------------------------
    // Additional: MarkdownFile implements Zeroize + ZeroizeOnDrop
    // -------------------------------------------------------------------------

    /// Compile-time check that MarkdownFile derives Zeroize and ZeroizeOnDrop.
    #[test]
    fn md_file_implements_zeroize() {
        use zeroize::{Zeroize, ZeroizeOnDrop};
        fn assert_zeroize<T: Zeroize>() {}
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize::<MarkdownFile>();
        assert_zeroize_on_drop::<MarkdownFile>();
    }

    // -------------------------------------------------------------------------
    // TC-D01-01: .md file is imported as an entry
    // -------------------------------------------------------------------------

    /// TC-D01-01: A single `note1.md` in the source dir is imported as one entry
    /// whose title equals "note1".
    #[test]
    fn tc_d01_01_single_md_file_imported() {
        let vault_dir = tempfile::tempdir().expect("vault tempdir");
        let vault_pqd = setup_test_vault(&vault_dir);

        let source_dir = tempfile::tempdir().expect("source tempdir");
        std::fs::write(source_dir.path().join("note1.md"), "Hello world").expect("write note1.md");

        let mut core = DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");
        core.unlock(secret("password")).expect("unlock");

        let result = core.import(source_dir.path(), false).expect("import");
        assert_eq!(result.imported, 1, "one entry must be imported");

        let entries = core.list_entries(None).expect("list_entries");
        assert_eq!(entries.len(), 1, "vault must contain exactly one entry");
        assert_eq!(entries[0].title, "note1", "title must match filename stem");

        core.lock();
    }

    // -------------------------------------------------------------------------
    // TC-D01-02: subdirectory recursive import
    // -------------------------------------------------------------------------

    /// TC-D01-02: `root.md` and `sub/nested.md` are both imported; `imported == 2`.
    #[test]
    fn tc_d01_02_subdirectory_recursion() {
        let vault_dir = tempfile::tempdir().expect("vault tempdir");
        let vault_pqd = setup_test_vault(&vault_dir);

        let source_dir = tempfile::tempdir().expect("source tempdir");
        std::fs::write(source_dir.path().join("root.md"), "Root note").expect("write root.md");
        let sub = source_dir.path().join("sub");
        std::fs::create_dir(&sub).expect("create sub dir");
        std::fs::write(sub.join("nested.md"), "Nested note").expect("write nested.md");

        let mut core = DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");
        core.unlock(secret("password")).expect("unlock");

        let result = core.import(source_dir.path(), false).expect("import");
        assert_eq!(
            result.imported, 2,
            "both root.md and sub/nested.md must be imported"
        );

        core.lock();
    }

    // -------------------------------------------------------------------------
    // TC-D01-05: non-.md files are skipped
    // -------------------------------------------------------------------------

    /// TC-D01-05: `note.md` is imported; `image.png` and `data.json` are skipped.
    #[test]
    fn tc_d01_05_non_md_files_skipped() {
        let vault_dir = tempfile::tempdir().expect("vault tempdir");
        let vault_pqd = setup_test_vault(&vault_dir);

        let source_dir = tempfile::tempdir().expect("source tempdir");
        std::fs::write(source_dir.path().join("note.md"), "A note").expect("write note.md");
        std::fs::write(source_dir.path().join("image.png"), b"\x89PNG").expect("write image.png");
        std::fs::write(source_dir.path().join("data.json"), "{}").expect("write data.json");

        let mut core = DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");
        core.unlock(secret("password")).expect("unlock");

        let result = core.import(source_dir.path(), false).expect("import");
        assert_eq!(result.imported, 1, "only note.md must be imported");
        assert_eq!(result.skipped, 2, "image.png and data.json must be skipped");

        let skipped_paths: Vec<&str> = result
            .skip_details
            .iter()
            .map(|d| d.path.as_str())
            .collect();
        let has_png = skipped_paths.iter().any(|p| p.contains("image.png"));
        let has_json = skipped_paths.iter().any(|p| p.contains("data.json"));
        assert!(has_png, "skip_details must contain image.png");
        assert!(has_json, "skip_details must contain data.json");

        core.lock();
    }

    // -------------------------------------------------------------------------
    // TC-D07-01: --dry-run does not write the vault
    // -------------------------------------------------------------------------

    /// TC-D07-01: dry_run=true leaves the vault file unchanged and returns imported=0.
    #[test]
    fn tc_d07_01_dry_run_no_write() {
        let vault_dir = tempfile::tempdir().expect("vault tempdir");
        let vault_pqd = setup_test_vault(&vault_dir);

        let source_dir = tempfile::tempdir().expect("source tempdir");
        std::fs::write(source_dir.path().join("note.md"), "Dry run test").expect("write note.md");

        let before = std::fs::read(&vault_pqd).expect("read vault before");

        let mut core = DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");
        core.unlock(secret("password")).expect("unlock");

        let result = core
            .import(source_dir.path(), true)
            .expect("dry-run import");
        assert_eq!(result.imported, 0, "dry_run must report imported=0");

        core.lock();

        let after = std::fs::read(&vault_pqd).expect("read vault after");
        assert_eq!(before, after, "vault bytes must be identical after dry_run");
    }

    // -------------------------------------------------------------------------
    // TC-D10-01: 100 files imported via single batch write
    // -------------------------------------------------------------------------

    /// TC-D10-01: 100 `.md` files are imported; `imported == 100` and
    /// `read_vault` finds exactly 100 ENTRY records after the call.
    #[test]
    fn tc_d10_01_batch_100_files() {
        let vault_dir = tempfile::tempdir().expect("vault tempdir");
        let vault_pqd = setup_test_vault(&vault_dir);

        let source_dir = tempfile::tempdir().expect("source tempdir");
        for i in 0..100u32 {
            let name = format!("note{i:03}.md");
            std::fs::write(source_dir.path().join(&name), format!("Content {i}"))
                .expect("write note");
        }

        let mut core = DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");
        core.unlock(secret("password")).expect("unlock");

        let result = core.import(source_dir.path(), false).expect("import 100");
        assert_eq!(
            result.imported, 100,
            "all 100 entries must be reported as imported"
        );

        // Verify via read_vault that exactly 100 ENTRY records exist.
        let (_header, records) = read_vault(&vault_pqd).expect("read_vault");
        let entry_count = records
            .iter()
            .filter(|r| r.record_type == crate::vault::format::RECORD_TYPE_ENTRY)
            .count();
        assert_eq!(
            entry_count, 100,
            "vault must contain exactly 100 ENTRY records"
        );

        core.lock();
    }

    // -------------------------------------------------------------------------
    // TC-D11-01: Zeroizing<String> is used for file content (static/compile check)
    // -------------------------------------------------------------------------

    /// TC-D11-01: Verify that `Zeroizing<String>` can be passed to `parse_markdown`
    /// via deref coercion.  This is the pattern used in `import_directory` to
    /// guarantee the raw file content is erased on drop.
    #[test]
    fn tc_d11_01_zeroizing_string_used_for_content() {
        // Ensure Zeroizing<String> derefs to &str, compatible with parse_markdown.
        let raw = "# Hello\nBody text.".to_string();
        let content: Zeroizing<String> = Zeroizing::new(raw);
        // parse_markdown takes &str; Zeroizing<String> derefs transparently.
        let result = parse_markdown(&content, "hello.md");
        assert!(
            result.is_ok(),
            "parse_markdown must accept Zeroizing<String> via deref"
        );
        let (md, _, _) = result.expect("parse");
        assert_eq!(md.title, "hello");
        // content is dropped (and zeroed) at end of scope.
    }

    // -------------------------------------------------------------------------
    // TC-D12-01: source files are not deleted after import
    // -------------------------------------------------------------------------

    /// TC-D12-01: After `import_directory` the original `note.md` must still
    /// exist with its original content unchanged.
    #[test]
    fn tc_d12_01_source_files_not_deleted() {
        let vault_dir = tempfile::tempdir().expect("vault tempdir");
        let vault_pqd = setup_test_vault(&vault_dir);

        let source_dir = tempfile::tempdir().expect("source tempdir");
        let note_path = source_dir.path().join("note.md");
        let original_content = "Original content that must survive import.";
        std::fs::write(&note_path, original_content).expect("write note.md");

        let mut core = DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");
        core.unlock(secret("password")).expect("unlock");
        core.import(source_dir.path(), false).expect("import");
        core.lock();

        assert!(
            note_path.exists(),
            "source note.md must still exist after import"
        );
        let after = std::fs::read_to_string(&note_path).expect("read note.md after import");
        assert_eq!(
            after, original_content,
            "source file content must be unchanged"
        );
    }
}
