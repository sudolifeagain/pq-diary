//! Full-text search across vault entries using regular expressions.
//!
//! Implements a streaming search strategy: each entry is decrypted, searched,
//! and then its plaintext is dropped (zeroed via [`zeroize::ZeroizeOnDrop`])
//! before moving to the next entry. Returned titles and context text remain
//! alive until their search-result owners are dropped and zeroized. Context may
//! contain an entire body, so plaintext memory is O(one entry + retained output).
//! All encrypted records are loaded from one freshly authenticated vault snapshot.
//!
//! # Search fields
//!
//! | Record type | Fields searched               |
//! |-------------|-------------------------------|
//! | `ENTRY`     | `body`, `title`, `tags`       |
//! | `TEMPLATE`  | `body` (matched_field = "template") |

use crate::{
    crypto::CryptoEngine,
    entry::EntryPlaintext,
    error::DiaryError,
    template::TemplatePlaintext,
    vault::{
        format::{RECORD_TYPE_ENTRY, RECORD_TYPE_TEMPLATE},
        reader::read_vault_with_attachments_authenticated,
    },
};
use regex::Regex;
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// Public types
// =============================================================================

/// Search query parameters.
pub struct SearchQuery {
    /// Regex pattern string compiled with the `regex` crate.
    pub pattern: String,
    /// Tag prefix filter.  `None` means all entries are searched.
    ///
    /// When set, only entries whose tag list contains a tag that equals
    /// `filter` or starts with `"{filter}/"` are included in the search.
    pub tag_filter: Option<String>,
    /// Number of context lines to include before and after each match.
    ///
    /// Default: 2.
    pub context_lines: usize,
    /// When `true`, context blocks are omitted; only counts are returned.
    pub count_only: bool,
}

/// A single search match within an entry or template record.
///
/// Owned title and context text are zeroized on drop. Borrow fields rather than
/// moving them out; explicitly extracted or cloned strings need their own guard.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SearchMatch {
    /// Entry UUID hex (32 chars, no dashes).
    #[zeroize(skip)]
    pub uuid_hex: String,
    /// Entry title, or template name for template matches.
    pub title: String,
    /// Entry last-update timestamp (Unix seconds).
    #[zeroize(skip)]
    pub updated_at: u64,
    /// Which field matched: `"body"`, `"title"`, `"tags"`, or `"template"`.
    #[zeroize(skip)]
    pub matched_field: String,
    /// Context lines around each match.  Empty when `count_only` is `true`.
    pub context_blocks: Vec<ContextBlock>,
}

/// A block of lines surrounding a single match location.
///
/// Line contents are zeroized on drop, even when the context is the full body.
pub struct ContextBlock {
    /// 1-based line number of the first matching line in this block.
    pub match_line_number: usize,
    /// Lines: `(line_number_1based, line_content, is_match)`.
    pub lines: Vec<(usize, String, bool)>,
}

impl Zeroize for ContextBlock {
    fn zeroize(&mut self) {
        for (_, content, _) in &mut self.lines {
            content.zeroize();
        }
    }
}

impl Drop for ContextBlock {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ContextBlock {}

impl std::fmt::Debug for ContextBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ContextBlock([REDACTED])")
    }
}

impl std::fmt::Debug for SearchMatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SearchMatch([REDACTED])")
    }
}

/// Aggregated search results returned by [`search_entries`].
pub struct SearchResults {
    /// All field-level matches across entries and templates.
    pub matches: Vec<SearchMatch>,
    /// Number of distinct records (entries or templates) with at least one match.
    pub matched_entry_count: usize,
    /// Total number of distinct matching lines across all fields.
    ///
    /// Body/template lines are projected from full-body regex matches. Line
    /// terminators belong to the preceding line; zero-width matches at a line
    /// start belong to that line, and EOF belongs to the last displayed line.
    /// An empty body has no displayed lines, even if the regex matches it.
    ///
    /// Available for future `--count --verbose` mode extension in the CLI.
    pub matched_line_count: usize,
}

// =============================================================================
// Public API
// =============================================================================

/// Search all journal entries and templates in `vault_path` for `query.pattern`.
///
/// Uses a streaming strategy: each record is decrypted, searched, and its
/// plaintext is dropped (zeroed via [`zeroize::ZeroizeOnDrop`]) before the
/// next record is processed.
///
/// # Search behaviour
///
/// - For `ENTRY` records: searches `body`, `title`, and `tags` fields.
///   If `query.tag_filter` is set, only entries whose tag list contains a
///   matching prefix are searched.
/// - For `TEMPLATE` records: searches the `body` field only.
///   `matched_field` is set to `"template"` for template matches.
///
/// # Errors
///
/// Returns [`DiaryError::Search`] if `query.pattern` is not a valid regex.
/// Returns [`DiaryError::Entry`] or [`DiaryError::Template`] if JSON
/// deserialisation fails for a record.
/// Returns [`DiaryError::Crypto`] on decryption failure.
/// Returns [`DiaryError::Io`] on vault file I/O failure.
pub fn search_entries(
    vault_path: &Path,
    engine: &CryptoEngine,
    query: &SearchQuery,
) -> Result<SearchResults, DiaryError> {
    let regex = Regex::new(&query.pattern)
        .map_err(|e| DiaryError::Search(format!("invalid regex pattern: {e}")))?;

    let mac_key = engine.vault_mac_key()?;
    let (_header, records, _attachments) =
        read_vault_with_attachments_authenticated(vault_path, &mac_key)?;

    let mut all_matches: Vec<SearchMatch> = Vec::new();
    let mut matched_entry_count = 0usize;
    let mut matched_line_count = 0usize;

    for record in &records {
        let uuid_hex: String = record.uuid.iter().map(|b| format!("{b:02x}")).collect();
        let mut entry_had_match = false;

        match record.record_type {
            RECORD_TYPE_ENTRY => {
                // Verify HMAC over ciphertext before decryption.
                if !engine.hmac_verify(&record.ciphertext, &record.content_hmac)? {
                    return Err(DiaryError::Crypto(format!(
                        "content HMAC verification failed for entry {}",
                        uuid_hex
                    )));
                }

                // Decrypt and deserialize. `plaintext` is ZeroizeOnDrop; its
                // contents are zeroed when the match arm exits.
                let decrypted = engine.decrypt(&record.iv, &record.ciphertext)?;
                let plaintext: EntryPlaintext = serde_json::from_slice(decrypted.as_ref())
                    .map_err(|e| DiaryError::Entry(format!("deserialization failed: {e}")))?;

                // Apply tag prefix filter — skip entries that do not match.
                if let Some(filter) = &query.tag_filter {
                    let filter_matches = plaintext
                        .tags
                        .iter()
                        .any(|t| t == filter || t.starts_with(&format!("{filter}/")));
                    if !filter_matches {
                        continue;
                    }
                }

                // --- body ---
                let body_matches = BodyMatches::new(&plaintext.body, &regex);
                if body_matches.has_match {
                    matched_line_count += body_matches.match_indices.len();
                    let context_blocks = if query.count_only {
                        Vec::new()
                    } else {
                        body_matches.format_context(query.context_lines)
                    };
                    all_matches.push(SearchMatch {
                        uuid_hex: uuid_hex.clone(),
                        title: plaintext.title.clone(),
                        updated_at: record.updated_at,
                        matched_field: "body".to_string(),
                        context_blocks,
                    });
                    entry_had_match = true;
                }

                // --- title ---
                if regex.is_match(&plaintext.title) {
                    matched_line_count += 1;
                    let context_blocks = if query.count_only {
                        Vec::new()
                    } else {
                        vec![ContextBlock {
                            match_line_number: 1,
                            lines: vec![(1, plaintext.title.clone(), true)],
                        }]
                    };
                    all_matches.push(SearchMatch {
                        uuid_hex: uuid_hex.clone(),
                        title: plaintext.title.clone(),
                        updated_at: record.updated_at,
                        matched_field: "title".to_string(),
                        context_blocks,
                    });
                    entry_had_match = true;
                }

                // --- tags ---
                let matching_tags: Vec<&String> = plaintext
                    .tags
                    .iter()
                    .filter(|t| regex.is_match(t.as_str()))
                    .collect();
                if !matching_tags.is_empty() {
                    matched_line_count += matching_tags.len();
                    let context_blocks = if query.count_only {
                        Vec::new()
                    } else {
                        vec![ContextBlock {
                            match_line_number: 1,
                            lines: matching_tags
                                .iter()
                                .enumerate()
                                .map(|(i, t)| (i + 1, (*t).clone(), true))
                                .collect(),
                        }]
                    };
                    all_matches.push(SearchMatch {
                        uuid_hex: uuid_hex.clone(),
                        title: plaintext.title.clone(),
                        updated_at: record.updated_at,
                        matched_field: "tags".to_string(),
                        context_blocks,
                    });
                    entry_had_match = true;
                }
            }

            RECORD_TYPE_TEMPLATE => {
                // Decrypt and deserialize. `plaintext` is ZeroizeOnDrop; its
                // contents are zeroed when the match arm exits.
                let decrypted = engine.decrypt(&record.iv, &record.ciphertext)?;
                let plaintext: TemplatePlaintext = serde_json::from_slice(decrypted.as_ref())
                    .map_err(|e| DiaryError::Template(format!("deserialization failed: {e}")))?;

                // Search template body only.
                let body_matches = BodyMatches::new(&plaintext.body, &regex);
                if body_matches.has_match {
                    matched_line_count += body_matches.match_indices.len();
                    let context_blocks = if query.count_only {
                        Vec::new()
                    } else {
                        body_matches.format_context(query.context_lines)
                    };
                    all_matches.push(SearchMatch {
                        uuid_hex: uuid_hex.clone(),
                        title: plaintext.name.clone(),
                        updated_at: record.updated_at,
                        matched_field: "template".to_string(),
                        context_blocks,
                    });
                    entry_had_match = true;
                }
            }

            // Unknown record types are ignored.
            _ => continue,
        }

        if entry_had_match {
            matched_entry_count += 1;
        }
    }

    Ok(SearchResults {
        matches: all_matches,
        matched_entry_count,
        matched_line_count,
    })
}

// =============================================================================
// Private helpers
// =============================================================================

/// Line projection of the regex engine's full-body, non-overlapping matches.
/// No plaintext is copied until context output is requested. Projection uses
/// O(lines) memory and O(matches * log(lines) + lines) work beyond regex matching;
/// non-overlapping match spans cannot repeatedly traverse the same line ranges.
struct BodyMatches<'a> {
    lines: Vec<&'a str>,
    match_indices: Vec<usize>,
    has_match: bool,
}

impl<'a> BodyMatches<'a> {
    fn new(body: &'a str, regex: &Regex) -> Self {
        let lines: Vec<&str> = body.lines().collect();
        // Include terminators in each line's byte range, but not its displayed
        // text (str::lines strips both LF and CRLF). Do not invent a final line
        // after a trailing newline, preserving the existing display convention.
        let mut offset = 0;
        let starts: Vec<usize> = body
            .split_inclusive('\n')
            .map(|line| {
                let start = offset;
                offset += line.len();
                start
            })
            .collect();
        let mut matched = vec![false; lines.len()];
        let mut has_match = false;
        for found in regex.find_iter(body) {
            has_match = true;
            if lines.is_empty() {
                continue;
            }
            // A zero-width match belongs to the line starting at that position;
            // EOF belongs to the last displayed line. A nonempty match's end
            // is exclusive, so a match ending at a line start excludes that line.
            let first = starts.partition_point(|&start| start <= found.start()) - 1;
            let last_byte = if found.is_empty() {
                found.start()
            } else {
                found.end() - 1
            };
            let last = starts.partition_point(|&start| start <= last_byte) - 1;
            matched[first..=last].fill(true);
        }
        let match_indices = matched
            .into_iter()
            .enumerate()
            .filter_map(|(idx, is_match)| is_match.then_some(idx))
            .collect();
        Self {
            lines,
            match_indices,
            has_match,
        }
    }

    /// Merge overlapping or adjacent context windows. Regex matching is never
    /// repeated against isolated lines, which would change anchors and flags.
    fn format_context(&self, context_lines: usize) -> Vec<ContextBlock> {
        let mut ranges: Vec<(usize, usize, usize)> = Vec::new();
        for &idx in &self.match_indices {
            let start = idx.saturating_sub(context_lines);
            let end = idx.saturating_add(context_lines).min(self.lines.len() - 1);
            if let Some(last) = ranges.last_mut() {
                if start <= last.1 + 1 {
                    last.1 = last.1.max(end);
                    continue;
                }
            }
            ranges.push((start, end, idx));
        }

        let mut match_pos = 0;
        ranges
            .into_iter()
            .map(|(start, end, first)| {
                let lines = (start..=end)
                    .map(|idx| {
                        let is_match = self.match_indices.get(match_pos) == Some(&idx);
                        if is_match {
                            match_pos += 1;
                        }
                        (idx + 1, self.lines[idx].to_string(), is_match)
                    })
                    .collect();
                ContextBlock {
                    match_line_number: first + 1,
                    lines,
                }
            })
            .collect()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto::kdf::Argon2Params, vault::init::VaultManager, DiaryCore};
    use secrecy::SecretBox;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use zeroize::ZeroizeOnDrop;

    // -------------------------------------------------------------------------
    // Test helpers
    // -------------------------------------------------------------------------

    fn fast_params() -> Argon2Params {
        Argon2Params {
            memory_cost_kb: 8,
            time_cost: 1,
            parallelism: 1,
        }
    }

    fn setup_test_vault(dir: &TempDir) -> PathBuf {
        let mgr = VaultManager::new(dir.path().to_path_buf())
            .expect("VaultManager::new")
            .with_kdf_params(fast_params());
        mgr.init_vault("test", b"password").expect("init_vault");
        dir.path().join("test").join("vault.pqd")
    }

    fn secret(s: &str) -> secrecy::SecretString {
        SecretBox::new(s.into())
    }

    fn make_query(pattern: &str) -> SearchQuery {
        SearchQuery {
            pattern: pattern.to_string(),
            tag_filter: None,
            context_lines: 2,
            count_only: false,
        }
    }

    #[test]
    fn body_match_spans_respect_line_boundaries_and_flags() {
        // Expected indices are zero-based and unique, not the number of regex hits.
        let cases = [
            ("alpha\r\nbeta\r\nend", r"alpha\r\nbeta", vec![0, 1]),
            ("alpha\nbeta\nend", r"alpha\n", vec![0]),
            ("alpha\nbeta", r"\n", vec![0]),
            ("alpha\nbeta\nalpha\nbeta", r"alpha\nbeta", vec![0, 1, 2, 3]),
            ("hit hit\nother\nhit", "hit", vec![0, 2]),
            ("hit\nother\nhit", "^hit", vec![0]),
            ("hit\nother\nhit", "(?m)^hit", vec![0, 2]),
            ("alpha\ninside\nbeta", "(?s)alpha.*beta", vec![0, 1, 2]),
            ("α\nβ", r"\A|\z", vec![0, 1]),
            ("a\nb\n", "(?m)^", vec![0, 1]),
            ("a\r\nb", "(?mR)$", vec![0, 1]),
            ("a\nb\n", r"\z", vec![1]),
            ("a\n\nb", "(?m)^$", vec![1]),
            ("α\nβ", "", vec![0, 1]),
            ("", "^$", vec![]),
            ("x", "missing", vec![]),
        ];
        for (body, pattern, expected) in cases {
            let regex = Regex::new(pattern).unwrap();
            let found = BodyMatches::new(body, &regex);
            assert_eq!(found.has_match, regex.is_match(body), "{pattern:?}");
            assert_eq!(found.match_indices, expected, "{body:?} / {pattern:?}");
            let blocks = found.format_context(usize::MAX);
            let displayed_matches: Vec<_> = blocks
                .iter()
                .flat_map(|block| &block.lines)
                .filter_map(|(line, _, matched)| matched.then_some(line - 1))
                .collect();
            assert_eq!(displayed_matches, expected);
            assert!(blocks
                .iter()
                .flat_map(|block| &block.lines)
                .all(|(_, text, _)| !text.ends_with('\r')));
        }
    }

    #[test]
    fn multiline_context_windows_merge_without_duplicate_lines() {
        let body = "before\na\nb\nbetween\na\nb\nafter\ngap\ngap\na\nb\nlast";
        let found = BodyMatches::new(body, &Regex::new(r"a\nb").unwrap());
        let blocks = found.format_context(1);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].match_line_number, 2);
        assert_eq!(blocks[1].match_line_number, 10);
        assert_eq!(
            blocks[0]
                .lines
                .iter()
                .map(|line| line.0)
                .collect::<Vec<_>>(),
            (1..=7).collect::<Vec<_>>()
        );
        assert_eq!(
            blocks[1]
                .lines
                .iter()
                .map(|line| line.0)
                .collect::<Vec<_>>(),
            (9..=12).collect::<Vec<_>>()
        );
        assert_eq!(
            blocks
                .iter()
                .flat_map(|block| &block.lines)
                .filter(|line| line.2)
                .count(),
            6
        );
    }

    #[test]
    fn multiline_body_and_template_context_regression() {
        let dir = tempfile::tempdir().unwrap();
        let vault = setup_test_vault(&dir);
        let mut core = DiaryCore::new(vault.to_str().unwrap()).unwrap();
        core.unlock(secret("password")).unwrap();
        let body = "before\nalpha\nbeta\nafter";
        core.new_entry("entry", body, vec![]).unwrap();
        core.new_template("template", body).unwrap();
        for count_only in [false, true] {
            let mut query = make_query(r"alpha\nbeta");
            query.count_only = count_only;
            query.context_lines = 0;
            let result = core.search(&query).unwrap();
            assert_eq!(result.matched_entry_count, 2);
            assert_eq!(result.matched_line_count, 4);
            assert_eq!(result.matches.len(), 2);
            for found in result.matches {
                if count_only {
                    assert!(found.context_blocks.is_empty());
                } else {
                    assert_eq!(found.context_blocks.len(), 1);
                    let block = &found.context_blocks[0];
                    assert_eq!(block.match_line_number, 2);
                    assert_eq!(
                        block.lines,
                        vec![(2, "alpha".into(), true), (3, "beta".into(), true)]
                    );
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // TC-B01-01: body match
    // -------------------------------------------------------------------------

    /// TC-B01-01: Entry with matching body is returned with matched_field = "body".
    #[test]
    fn tc_b01_01_body_match() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_pqd = setup_test_vault(&dir);

        let mut core = DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");
        core.unlock(secret("password")).expect("unlock");

        core.new_entry("タイトル", "今日は天気が良い", vec![])
            .expect("new_entry");

        let results = core.search(&make_query("天気")).expect("search");

        assert_eq!(results.matched_entry_count, 1);
        let body_match = results
            .matches
            .iter()
            .find(|m| m.matched_field == "body")
            .expect("must have a body match");
        assert_eq!(body_match.matched_field, "body");
    }

    // -------------------------------------------------------------------------
    // TC-B01-02: title match
    // -------------------------------------------------------------------------

    /// TC-B01-02: Entry with matching title is returned with matched_field = "title".
    #[test]
    fn tc_b01_02_title_match() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_pqd = setup_test_vault(&dir);

        let mut core = DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");
        core.unlock(secret("password")).expect("unlock");

        core.new_entry("2026年4月の振り返り", "本文テキスト", vec![])
            .expect("new_entry");

        let results = core.search(&make_query("振り返り")).expect("search");

        assert_eq!(results.matched_entry_count, 1);
        let title_match = results
            .matches
            .iter()
            .find(|m| m.matched_field == "title")
            .expect("must have a title match");
        assert_eq!(title_match.matched_field, "title");
    }

    // -------------------------------------------------------------------------
    // TC-B01-03: tags match
    // -------------------------------------------------------------------------

    /// TC-B01-03: Entry with matching tag is returned with matched_field = "tags".
    #[test]
    fn tc_b01_03_tags_match() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_pqd = setup_test_vault(&dir);

        let mut core = DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");
        core.unlock(secret("password")).expect("unlock");

        core.new_entry("タイトル", "本文テキスト", vec!["日記/旅行".to_string()])
            .expect("new_entry");

        let results = core.search(&make_query("旅行")).expect("search");

        assert_eq!(results.matched_entry_count, 1);
        let tags_match = results
            .matches
            .iter()
            .find(|m| m.matched_field == "tags")
            .expect("must have a tags match");
        assert_eq!(tags_match.matched_field, "tags");
    }

    // -------------------------------------------------------------------------
    // TC-B01-04: template body match
    // -------------------------------------------------------------------------

    /// TC-B01-04: Template with matching body is returned with matched_field = "template".
    #[test]
    fn tc_b01_04_template_body_match() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_pqd = setup_test_vault(&dir);

        let mut core = DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");
        core.unlock(secret("password")).expect("unlock");

        core.new_template("daily-report", "## 日報テンプレート\n本日の作業内容")
            .expect("new_template");

        let results = core.search(&make_query("日報")).expect("search");

        assert!(
            results
                .matches
                .iter()
                .any(|m| m.matched_field == "template"),
            "must find a template match"
        );
        assert!(results.matched_entry_count >= 1);
    }

    // -------------------------------------------------------------------------
    // TC-B01-05: no match
    // -------------------------------------------------------------------------

    /// TC-B01-05: Pattern that matches nothing returns empty results.
    #[test]
    fn tc_b01_05_no_match() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_pqd = setup_test_vault(&dir);

        let mut core = DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");
        core.unlock(secret("password")).expect("unlock");

        core.new_entry("タイトルA", "本文A", vec!["タグA".to_string()])
            .expect("new_entry 1");
        core.new_entry("タイトルB", "本文B", vec!["タグB".to_string()])
            .expect("new_entry 2");
        core.new_entry("タイトルC", "本文C", vec!["タグC".to_string()])
            .expect("new_entry 3");

        let results = core.search(&make_query("ZZZZNOTFOUND")).expect("search");

        assert_eq!(results.matched_entry_count, 0);
        assert!(results.matches.is_empty());
    }

    // -------------------------------------------------------------------------
    // TC-B01-06: regex date pattern
    // -------------------------------------------------------------------------

    /// TC-B01-06: Regex `\d{4}-\d{2}-\d{2}` matches a date string in the body.
    #[test]
    fn tc_b01_06_regex_date_pattern() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_pqd = setup_test_vault(&dir);

        let mut core = DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");
        core.unlock(secret("password")).expect("unlock");

        core.new_entry("会議メモ", "会議は2026-04-08に開催", vec![])
            .expect("new_entry");

        let results = core
            .search(&make_query(r"\d{4}-\d{2}-\d{2}"))
            .expect("search");

        assert!(
            results.matched_entry_count >= 1,
            "must find at least 1 match"
        );
        assert!(
            results.matches.iter().any(|m| m.matched_field == "body"),
            "must have a body match"
        );
    }

    // -------------------------------------------------------------------------
    // TC-B05-01: default context lines (2)
    // -------------------------------------------------------------------------

    /// TC-B05-01: With context_lines=2, match on line 5 yields lines 3–7 (5 lines).
    #[test]
    fn tc_b05_01_default_context_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_pqd = setup_test_vault(&dir);

        let mut core = DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");
        core.unlock(secret("password")).expect("unlock");

        // 10-line body; the pattern "TARGET" appears only on line 5.
        let body = "行1\n行2\n行3\n行4\nTARGET行5\n行6\n行7\n行8\n行9\n行10";
        core.new_entry("テスト", body, vec![]).expect("new_entry");

        let results = core.search(&make_query("TARGET")).expect("search");

        let body_match = results
            .matches
            .iter()
            .find(|m| m.matched_field == "body")
            .expect("must have body match");
        assert_eq!(body_match.context_blocks.len(), 1);
        let block = &body_match.context_blocks[0];
        // Line 5 ± 2 → lines 3 to 7 (1-based)
        assert_eq!(block.lines.len(), 5, "context block must contain 5 lines");
        assert_eq!(block.lines[0].0, 3, "first line must be line 3");
        assert_eq!(block.lines[4].0, 7, "last line must be line 7");
        // The match line (line 5) must be marked as is_match = true.
        let match_line = block
            .lines
            .iter()
            .find(|(_, _, is_m)| *is_m)
            .expect("must have match line");
        assert_eq!(match_line.0, 5, "match must be on line 5");
    }

    // -------------------------------------------------------------------------
    // TC-B05-02: context_lines = 5
    // -------------------------------------------------------------------------

    /// TC-B05-02: With context_lines=5, match on line 5 of a 10-line body yields all 10 lines.
    #[test]
    fn tc_b05_02_large_context_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_pqd = setup_test_vault(&dir);

        let mut core = DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");
        core.unlock(secret("password")).expect("unlock");

        let body = "行1\n行2\n行3\n行4\nTARGET行5\n行6\n行7\n行8\n行9\n行10";
        core.new_entry("テスト", body, vec![]).expect("new_entry");

        let query = SearchQuery {
            pattern: "TARGET".to_string(),
            tag_filter: None,
            context_lines: 5,
            count_only: false,
        };
        let results = core.search(&query).expect("search");

        let body_match = results
            .matches
            .iter()
            .find(|m| m.matched_field == "body")
            .expect("must have body match");
        assert_eq!(body_match.context_blocks.len(), 1);
        let block = &body_match.context_blocks[0];
        // Line 5 ± 5 → lines 1 to 10 (all 10 lines, clamped)
        assert_eq!(
            block.lines.len(),
            10,
            "context block must contain all 10 lines"
        );
        assert_eq!(block.lines[0].0, 1, "first line must be line 1");
        assert_eq!(block.lines[9].0, 10, "last line must be line 10");
    }

    #[test]
    fn search_plaintext_owners_erase_live_buffers_and_redact_debug() {
        fn assert_owner<T: zeroize::Zeroize + ZeroizeOnDrop>() {}
        assert_owner::<ContextBlock>();
        assert_owner::<SearchMatch>();
        let sentinel = "S53_PRIVATE_SENTINEL";
        let mut result = SearchMatch {
            uuid_hex: "public-id".to_string(),
            title: sentinel.to_string(),
            updated_at: 7,
            matched_field: "body".to_string(),
            context_blocks: vec![ContextBlock {
                match_line_number: 1,
                lines: vec![(1, sentinel.to_string(), true)],
            }],
        };
        assert!(!format!("{result:?}").contains(sentinel));
        assert!(!format!("{result:#?}").contains(sentinel));
        assert!(!format!("{:?}", result.context_blocks[0]).contains(sentinel));
        assert!(!format!("{:#?}", result.context_blocks[0]).contains(sentinel));
        // Exercise the exact wipe routine called by Drop while ownership is live.
        zeroize::Zeroize::zeroize(&mut result.context_blocks[0]);
        assert!(result.context_blocks[0].lines[0].1.is_empty());
        assert_eq!(result.context_blocks[0].lines[0].0, 1);
        zeroize::Zeroize::zeroize(&mut result);
        assert!(result.title.is_empty());
        assert!(result.context_blocks.is_empty());
        assert_eq!(result.uuid_hex, "public-id");
        assert_eq!(result.updated_at, 7);
    }

    // =========================================================================
    // TASK-0082: search での HMAC 検証
    // =========================================================================

    /// TC-S9-082-06: search verifies HMAC for each entry; tampered entry causes an error.
    #[test]
    fn tc_s9_082_06_search_hmac_verification() {
        use crate::vault::{reader::read_vault, writer::write_vault};

        let dir = tempfile::tempdir().expect("tempdir");
        let vault_pqd = setup_test_vault(&dir);

        let mut core = DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");
        core.unlock(secret("password")).expect("unlock");

        // Create an entry that the search will match.
        core.new_entry("検索テスト", "FINDME content", vec![])
            .expect("new_entry");

        // Part 1: normal search succeeds and finds the entry.
        let results = core
            .search(&make_query("FINDME"))
            .expect("search must succeed");
        assert_eq!(results.matched_entry_count, 1, "expected 1 matching entry");

        // Part 2: tamper the ciphertext of the entry; search must now return an error.
        core.lock();
        {
            let (header, mut records) = read_vault(&vault_pqd).expect("read_vault");
            if let Some(b) = records
                .iter_mut()
                .find(|r| r.record_type == crate::vault::format::RECORD_TYPE_ENTRY)
                .and_then(|r| r.ciphertext.get_mut(7))
            {
                *b ^= 0xFF;
            }
            write_vault(&vault_pqd, header, &records).expect("write_vault");
        }

        // Re-open and unlock; list_entries_with_body is called during unlock,
        // so we need to create a fresh DiaryCore without calling unlock (which would fail).
        // Instead, call search_entries directly with a manual engine.
        {
            use crate::crypto::CryptoEngine;

            // Re-derive the engine using the vault header.
            let mut file = std::fs::File::open(&vault_pqd).expect("open vault");
            let header = crate::vault::reader::read_header(&mut file).expect("read_header");
            let params = fast_params();
            let mut engine = CryptoEngine::new();
            engine
                .unlock_with_vault(
                    b"password",
                    &header.kdf_salt,
                    &crate::crypto::kdf::Argon2Params {
                        memory_cost_kb: params.memory_cost_kb,
                        time_cost: params.time_cost,
                        parallelism: params.parallelism,
                    },
                    header.verification_iv,
                    &header.verification_ct,
                    &header.kem_encrypted_sk,
                    &header.dsa_encrypted_sk,
                )
                .expect("unlock_with_vault");

            let query = make_query("FINDME");
            let err = match search_entries(&vault_pqd, &engine, &query) {
                Ok(_) => panic!("search_entries must fail on tampered entry"),
                Err(e) => e,
            };
            assert!(
                matches!(err, crate::error::DiaryError::Crypto(_)),
                "expected DiaryError::Crypto, got {:?}",
                err
            );
        }
    }
}
