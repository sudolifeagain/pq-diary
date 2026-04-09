//! Obsidian-compatible Markdown file importer.
//!
//! Provides types and functions for parsing Markdown files with YAML frontmatter,
//! converting Obsidian wiki-links, extracting inline `#tag` notation, and
//! filtering paths during directory traversal.

use std::path::{Path, PathBuf};

use regex::Regex;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::DiaryError;

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
    // 1. Parse YAML frontmatter
    let (frontmatter_title, frontmatter_tags, body_raw) = parse_frontmatter(content);

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
    let re = Regex::new(r"\[\[([^\]|]+)(?:\|[^\]]+)?\]\]")
        .map_err(|e| DiaryError::Import(format!("wiki-link regex compile error: {e}")))?;

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
    let re = Regex::new(r"#([\w/]+)")
        .map_err(|e| DiaryError::Import(format!("tag regex compile error: {e}")))?;

    let mut tags: Vec<String> = Vec::new();
    let mut count = 0usize;

    let cleaned = re.replace_all(body, |caps: &regex::Captures| {
        let tag = caps.get(1).map_or("", |m| m.as_str()).to_string();
        tags.push(tag);
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
    use std::path::Path;

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
}
