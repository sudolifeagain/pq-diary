//! Obsidian-compatible Markdown file importer.
//!
//! Provides types and functions for parsing Markdown files with YAML frontmatter,
//! converting Obsidian wiki-links, extracting inline `#tag` notation, and
//! filtering paths during directory traversal.
//!
//! # Batch import
//!
//! `import_directory` walks a source directory recursively, parses each `.md`
//! file via `parse_markdown`, and writes all resulting entries to the vault
//! with a single `batch_create_entries` call (i.e., one `write_vault`
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

static WIKI_LINK_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\[\[([^\]|]+)(?:\|[^\]]+)?\]\]").unwrap());

static TAG_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"#([\w/-]+)").unwrap());

/// Obsidian attachment-embed pattern: `![[filename.ext]]` (S13).
static ATTACHMENT_LINK_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"!\[\[([^\]|]+)(?:\|[^\]]+)?\]\]").unwrap());

/// Extract every `![[filename]]` reference from a markdown body, returning
/// the captured filenames in document order (duplicates preserved). Used by
/// the CLI import path to walk source `attachments/<filename>` files and
/// attach them to the freshly-imported entry (S13).
///
/// Names are returned verbatim (including any `../`, absolute, or
/// alternate-data-stream forms). Path-escape safety is enforced one layer up by
/// the CLI's `resolve_import_attachment_source`, which canonicalises the
/// resolved path and verifies it stays within `<source>/attachments/`, then
/// reports anything outside as an *unresolved* reference (audit M7 — verified
/// by `tc_s13_110_03_import_rejects_attachment_path_escape`). Filtering here
/// instead would silently drop such references and hide them from that report.
pub fn parse_obsidian_attachment_links(body: &str) -> Vec<String> {
    ATTACHMENT_LINK_RE
        .captures_iter(body)
        .map(|c| c[1].trim().to_string())
        .collect()
}

#[cfg(test)]
mod attachment_link_tests {
    use super::parse_obsidian_attachment_links;

    /// TC-S13-010-01: extracts single ![[FILE]] reference.
    #[test]
    fn tc_s13_010_01_single_link() {
        let body = "See ![[photo.png]] for details.";
        assert_eq!(parse_obsidian_attachment_links(body), vec!["photo.png"]);
    }

    /// TC-S13-010-02: extracts multiple references in document order.
    #[test]
    fn tc_s13_010_02_multiple_links() {
        let body = "![[a.png]] and ![[b.pdf]]\n\nand ![[c.txt]]";
        assert_eq!(
            parse_obsidian_attachment_links(body),
            vec!["a.png", "b.pdf", "c.txt"]
        );
    }

    /// TC-S13-010-03: ignores plain `[[wiki links]]` (no leading `!`).
    #[test]
    fn tc_s13_010_03_ignores_plain_wiki_link() {
        let body = "See [[entry]] not ![[attachment.png]]";
        assert_eq!(
            parse_obsidian_attachment_links(body),
            vec!["attachment.png"]
        );
    }

    /// TC-S13-010-04: empty body yields empty Vec.
    #[test]
    fn tc_s13_010_04_empty_body() {
        assert!(parse_obsidian_attachment_links("").is_empty());
    }
}

/// Conservative source-span protection, not a complete CommonMark parser.
/// Both import rewrites use this scanner so literal source bytes stay intact.
fn protected_markdown(body: &str) -> Vec<bool> {
    let bytes = body.as_bytes();
    let mut protected = vec![false; bytes.len()];
    let mut fence: Option<(u8, usize)> = None;
    let mut offset = 0;
    for line in body.split_inclusive('\n') {
        let trimmed = line.trim_start_matches(' ');
        let indent = line.len() - trimmed.len();
        let marker = trimmed.as_bytes().first().copied().unwrap_or(0);
        let run = trimmed.bytes().take_while(|&b| b == marker).count();
        if let Some((kind, width)) = fence {
            protected[offset..offset + line.len()].fill(true);
            if indent <= 3 && marker == kind && run >= width && trimmed[run..].trim().is_empty() {
                fence = None;
            }
        } else if indent <= 3
            && matches!(marker, b'`' | b'~')
            && run >= 3
            && (marker != b'`' || !trimmed[run..].contains('`'))
        {
            fence = Some((marker, run));
            protected[offset..offset + line.len()].fill(true);
        } else if indent >= 4
            || line.starts_with('\t')
            || (trimmed.starts_with('[') && trimmed.contains("]:"))
        {
            // Preserve indented code and reference-definition lines conservatively.
            protected[offset..offset + line.len()].fill(true);
        }
        offset += line.len();
    }
    // Index delimiter runs once: unmatched runs must not rescan every suffix.
    let mut backticks: std::collections::HashMap<usize, Vec<usize>> =
        std::collections::HashMap::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor] == b'`' {
            let width = bytes[cursor..].iter().take_while(|&&b| b == b'`').count();
            backticks.entry(width).or_default().push(cursor);
            cursor += width;
        } else {
            cursor += 1;
        }
    }
    let mut i = 0;
    while i < bytes.len() {
        if protected[i] {
            i += 1;
            continue;
        }
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == b'`' {
            let width = bytes[i..].iter().take_while(|&&b| b == b'`').count();
            if let Some(positions) = backticks.get(&width) {
                if let Some(&start) = positions.get(positions.partition_point(|&start| start <= i))
                {
                    let end = start + width;
                    protected[i..end].fill(true);
                    i = end;
                    continue;
                }
            }
            i += width;
            continue;
        }
        // Protect balanced inline destinations (including optional titles),
        // and angle-bracket autolinks/HTML. Unclosed spans conservatively
        // protect the remainder rather than repeatedly rescanning suffixes.
        let close = if bytes[i] == b'(' && i > 0 && bytes[i - 1] == b']' {
            Some(b')')
        } else if bytes[i] == b'<'
            && bytes
                .get(i + 1)
                .is_some_and(|b| b.is_ascii_alphabetic() || matches!(b, b'/' | b'!' | b'?'))
        {
            Some(b'>')
        } else {
            None
        };
        if let Some(close) = close {
            let mut depth = 1;
            let mut quote = None;
            let mut j = i + 1;
            while j < bytes.len() {
                if bytes[j] == b'\\' {
                    j += 2;
                    continue;
                }
                if let Some(delimiter) = quote {
                    if bytes[j] == delimiter {
                        quote = None;
                    }
                } else if bytes[j] == b'<' && close == b')' {
                    // Parentheses inside an angle-bracket destination are literal.
                    quote = Some(b'>');
                } else if matches!(bytes[j], b'\'' | b'"')
                    && (bytes[i] == b'<' || bytes[j - 1].is_ascii_whitespace())
                {
                    quote = Some(bytes[j]);
                } else {
                    if bytes[j] == bytes[i] {
                        depth += 1;
                    }
                    if bytes[j] == close {
                        depth -= 1;
                    }
                    if depth == 0 {
                        break;
                    }
                }
                j += 1;
            }
            if j < bytes.len() && depth == 0 {
                protected[i..=j].fill(true);
                i = j + 1;
                continue;
            }
            protected[i..].fill(true);
            break;
        }
        i += 1;
    }
    // A fragment may follow punctuation inside a bare URL, e.g. /(#part).
    // Conservatively preserve the whole whitespace-delimited URL token.
    let mut offset = 0;
    for token in body.split_whitespace() {
        if let Some(relative) = body[offset..].find(token) {
            let start = offset + relative;
            offset = start + token.len();
            if token.contains("://") || token.starts_with("www.") {
                protected[start..offset].fill(true);
            }
        }
    }
    protected
}

fn escaped(bytes: &[u8], pos: usize) -> bool {
    bytes[..pos]
        .iter()
        .rev()
        .take_while(|&&b| b == b'\\')
        .count()
        % 2
        == 1
}

use crate::{
    crypto::CryptoEngine,
    entry::EntryPlaintext,
    error::DiaryError,
    vault::{
        format::{generate_entry_padding, EntryRecord, RECORD_TYPE_ENTRY},
        reader::read_vault,
        writer::write_vault_authenticated,
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
/// This is a conservative Markdown subset, not a CommonMark parser. Rewrites
/// skip backtick code spans with matching delimiter lengths, backtick/tilde
/// fences (up to three leading spaces, including unclosed fences), indented
/// lines, balanced inline link destinations/titles, angle-bracket spans, and
/// reference-definition lines, and whitespace-delimited tokens containing
/// `://` or starting with `www.`. Backslash-escaped markers are preserved. Tags
/// also skip wiki-link targets. Blockquote/list-nested fences and HTML blocks
/// are not parsed as containers. Unclosed inline destinations/angle spans
/// conservatively protect the remainder of the body. Angle spans must start
/// with an ASCII letter, `/`, `!` or `?` after `<`; ordinary math like `1 < 2`
/// is not a protected span. CRLF normalization and frontmatter handling
/// remain separate from these body rewrites.
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

/// Returns `true` for files under the source directory's top-level
/// `attachments/` directory.
///
/// Obsidian attachment imports use this directory as binary payload storage, so
/// its contents must not also be imported as diary entries.
fn is_top_level_attachments_path(source_dir: &Path, path: &Path) -> bool {
    path.strip_prefix(source_dir)
        .ok()
        .and_then(|relative| relative.components().next())
        .is_some_and(|c| c.as_os_str() == "attachments")
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

    let mac_key = engine.vault_mac_key()?;
    write_vault_authenticated(vault_path, header, &records, &mac_key)?;

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

        // Top-level attachments/ is reserved for Obsidian embed payloads and
        // is handled by the CLI import attachment pass.
        if is_top_level_attachments_path(source_dir, path) {
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

    let protected = protected_markdown(body);
    let mut count = 0usize;
    let result = re.replace_all(body, |caps: &regex::Captures| {
        if let Some(m) = caps.get(0) {
            if protected[m.start()..m.end()].iter().any(|&p| p)
                || escaped(body.as_bytes(), m.start())
            {
                return m.as_str().to_string();
            }
        }
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
/// Finds tags at the start of text, after whitespace, or after an opening
/// bracket/quote, using Unicode word characters, hyphens and slashes. Nested
/// tags (e.g. `#work/project/alpha`) retain their `/` separators. Literal source
/// spans, escapes, embedded hashes and wiki-link targets are left unchanged.
///
/// Returns `(tags, cleaned_body, extraction_count)`.
///
/// # Errors
///
/// Returns [`DiaryError::Import`] if the regex fails to compile.
fn extract_tags(body: &str) -> Result<(Vec<String>, String, usize), DiaryError> {
    let re = &*TAG_RE;

    let mut protected = protected_markdown(body);
    // A heading fragment or filename inside a wiki-link is not an inline tag.
    for m in WIKI_LINK_RE.find_iter(body) {
        protected[m.start()..m.end()].fill(true);
    }

    let mut tags: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut count = 0usize;

    let cleaned = re.replace_all(body, |caps: &regex::Captures| {
        let Some(m) = caps.get(0) else {
            return String::new();
        };
        let boundary = body[..m.start()]
            .chars()
            .next_back()
            .is_none_or(|c| c.is_whitespace() || matches!(c, '(' | '[' | '{' | '\'' | '"'));
        if !boundary
            || escaped(body.as_bytes(), m.start())
            || protected[m.start()..m.end()].iter().any(|&p| p)
        {
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

    #[test]
    fn markdown_literals_survive_import() {
        for body in [
            "https://example.test/page#fragment",
            "https://example.test/(#fragment)",
            "[jump](#fragment) and ![img](image.png#part)",
            r##"[jump]( #fragment "#title")"##,
            "`[[x|literal]] #literal`",
            "`https://example.test/ #literal [[x|literal]]`",
            "`` [[x|literal]] ` #literal ``",
            "`first\n    second\n#literal [[x|literal]]`",
            "~~~rust\n[[x|literal]] #literal\n~~~",
            "````\n```\n[[x|literal]] #literal\n````",
            "~~~\n[[x|literal]] #literal",
            r"\#literal \[[x|literal]]",
            "[[Note #section]] and ![[image #1.png]]",
            "[id]: #fragment \"#title\"",
            "    #literal [[x|literal]]",
            "word#literal ##heading C#code",
        ] {
            let (md, links, tags) = parse_markdown(body, "test.md").unwrap();
            assert_eq!(md.body, body, "body: {body}");
            assert!(md.tags.is_empty(), "body: {body}");
            assert_eq!((links, tags), (0, 0), "body: {body}");
        }
    }

    #[test]
    fn markdown_tags_have_boundaries_and_unicode_names() {
        let body = "#daily-note #日本語/日記 (#café) #daily-note";
        let (md, links, count) = parse_markdown(body, "test.md").unwrap();
        assert_eq!(md.tags, ["daily-note", "日本語/日記", "café"]);
        assert_eq!(md.body, "  () ");
        assert_eq!((links, count), (0, 4));
    }

    #[test]
    fn markdown_protection_ends_at_matching_delimiters() {
        let body = "~~~rust\n#literal [[x|literal]]\n~~\n~~~\n#real [[x|alias]]";
        let (md, links, tags) = parse_markdown(body, "test.md").unwrap();
        assert_eq!(md.body, "~~~rust\n#literal [[x|literal]]\n~~\n~~~\n [[x]]");
        assert_eq!(md.tags, ["real"]);
        assert_eq!((links, tags), (1, 1));
    }

    #[test]
    fn markdown_backslash_parity_and_unmatched_ticks() {
        let body = r"\\[[x|alias]] \[[x|literal]] `unclosed #real";
        let (md, links, tags) = parse_markdown(body, "test.md").unwrap();
        assert_eq!(md.body, r"\\[[x]] \[[x|literal]] `unclosed ");
        assert_eq!(md.tags, ["real"]);
        assert_eq!((links, tags), (1, 1));
    }

    #[test]
    fn markdown_links_preserve_nested_and_escaped_destinations() {
        for body in [
            r"[a](path(with)#fragment)",
            r"[a](<path) #literal>)",
            r"[a](<path) [[x|literal]]>)",
            r"[a](path\) #fragment)",
            r##"[a](path "a) #literal [[x|alias]]")"##,
            "<https://example.test/#fragment>",
            "[a](path/[[x|literal]] \"#title\")",
            "日本語 `#例 [[例|別名]]` 続き",
            "   ~~~\n#literal\n   ~~~",
            "```\n#literal\n~~~\n#still-literal",
        ] {
            let (md, links, tags) = parse_markdown(body, "test.md").unwrap();
            assert_eq!(md.body, body);
            assert_eq!((links, tags), (0, 0));
        }
    }

    #[test]
    fn markdown_unmatched_delimiters_do_not_rescan_suffixes() {
        for body in [
            "<".repeat(100_000),
            "<a".repeat(50_000),
            "](".repeat(50_000),
        ] {
            let (md, links, tags) = parse_markdown(&body, "test.md").unwrap();
            assert_eq!(md.body, body);
            assert_eq!((links, tags), (0, 0));
        }
        let body = (1..500)
            .map(|n| format!("{} ", "`".repeat(n)))
            .collect::<String>();
        let (md, links, tags) = parse_markdown(&body, "test.md").unwrap();
        assert_eq!(md.body, body);
        assert_eq!((links, tags), (0, 0));
    }

    #[test]
    fn markdown_math_does_not_hide_real_tags_or_aliases() {
        let (md, links, tags) = parse_markdown("1 < 2 #daily [[note|alias]]", "test.md").unwrap();
        assert_eq!(md.body, "1 < 2  [[note]]");
        assert_eq!(md.tags, ["daily"]);
        assert_eq!((links, tags), (1, 1));
    }

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
