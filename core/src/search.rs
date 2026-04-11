//! Full-text search across vault entries using regular expressions.
//!
//! Implements a streaming search strategy: each entry is decrypted, searched,
//! and then its plaintext is dropped (zeroed via [`zeroize::ZeroizeOnDrop`])
//! before moving to the next entry.  Plaintext memory is O(1 entry) — each
//! entry is decrypted, searched, and zeroized before the next.  However, all
//! encrypted records are loaded into memory by `read_vault()`.
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
        reader::read_vault,
    },
};
use regex::Regex;
use std::path::Path;

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
pub struct SearchMatch {
    /// Entry UUID hex (32 chars, no dashes).
    pub uuid_hex: String,
    /// Entry title, or template name for template matches.
    pub title: String,
    /// Entry last-update timestamp (Unix seconds).
    pub updated_at: u64,
    /// Which field matched: `"body"`, `"title"`, `"tags"`, or `"template"`.
    pub matched_field: String,
    /// Context lines around each match.  Empty when `count_only` is `true`.
    pub context_blocks: Vec<ContextBlock>,
}

/// A block of lines surrounding a single match location.
pub struct ContextBlock {
    /// 1-based line number of the first matching line in this block.
    pub match_line_number: usize,
    /// Lines: `(line_number_1based, line_content, is_match)`.
    pub lines: Vec<(usize, String, bool)>,
}

/// Aggregated search results returned by [`search_entries`].
pub struct SearchResults {
    /// All field-level matches across entries and templates.
    pub matches: Vec<SearchMatch>,
    /// Number of distinct records (entries or templates) with at least one match.
    pub matched_entry_count: usize,
    /// Total number of individual lines that matched across all fields.
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

    let (_header, records) = read_vault(vault_path)?;

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
                if regex.is_match(&plaintext.body) {
                    let line_count = plaintext.body.lines().filter(|l| regex.is_match(l)).count();
                    matched_line_count += line_count;
                    let context_blocks = if query.count_only {
                        Vec::new()
                    } else {
                        format_context(&plaintext.body, &regex, query.context_lines)
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
                let matching_tags: Vec<String> = plaintext
                    .tags
                    .iter()
                    .filter(|t| regex.is_match(t.as_str()))
                    .cloned()
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
                                .map(|(i, t)| (i + 1, t.clone(), true))
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
                if regex.is_match(&plaintext.body) {
                    let line_count = plaintext.body.lines().filter(|l| regex.is_match(l)).count();
                    matched_line_count += line_count;
                    let context_blocks = if query.count_only {
                        Vec::new()
                    } else {
                        format_context(&plaintext.body, &regex, query.context_lines)
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

/// Extract context lines surrounding each regex match in `body`.
///
/// Splits `body` into lines and finds all lines that match `regex`.  For each
/// matching line, a window of `[idx - context_lines, idx + context_lines]`
/// (clamped to the line range) is included in a [`ContextBlock`].
/// Overlapping windows are merged into a single block.
///
/// Returns an empty `Vec` if no line matches.
fn format_context(body: &str, regex: &Regex, context_lines: usize) -> Vec<ContextBlock> {
    let lines: Vec<&str> = body.lines().collect();
    let n = lines.len();

    if n == 0 {
        return Vec::new();
    }

    // Collect 0-based indices of all matching lines.
    let match_indices: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| regex.is_match(line))
        .map(|(i, _)| i)
        .collect();

    if match_indices.is_empty() {
        return Vec::new();
    }

    // Build context ranges [start, end] (0-based), merging overlapping ones.
    let mut ranges: Vec<(usize, usize)> = Vec::new();

    for &idx in &match_indices {
        let start = idx.saturating_sub(context_lines);
        let end = idx.saturating_add(context_lines).min(n - 1);

        if let Some(last) = ranges.last_mut() {
            if start <= last.1 + 1 {
                // Overlapping or adjacent: extend the current range.
                last.1 = last.1.max(end);
            } else {
                ranges.push((start, end));
            }
        } else {
            ranges.push((start, end));
        }
    }

    // Convert ranges to ContextBlocks, tracking which match_index belongs to
    // which range so we can report the correct 1-based match_line_number.
    let mut blocks = Vec::new();
    let mut match_pos = 0usize;

    for (range_start, range_end) in ranges {
        // First match index within this range.
        let first_match = match_indices.get(match_pos).copied().unwrap_or(range_start);

        // Advance past all match indices consumed by this range.
        while match_pos < match_indices.len() && match_indices[match_pos] <= range_end {
            match_pos += 1;
        }

        let block_lines: Vec<(usize, String, bool)> = (range_start..=range_end)
            .map(|i| (i + 1, lines[i].to_string(), regex.is_match(lines[i])))
            .collect();

        blocks.push(ContextBlock {
            match_line_number: first_match + 1, // convert to 1-based
            lines: block_lines,
        });
    }

    blocks
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::kdf::Argon2Params, entry::EntryPlaintext, vault::init::VaultManager, DiaryCore,
    };
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

    // -------------------------------------------------------------------------
    // TC-B08-01: ZeroizeOnDrop and no raw body in SearchResults
    // -------------------------------------------------------------------------

    /// TC-B08-01: EntryPlaintext implements ZeroizeOnDrop; SearchMatch does not
    /// expose a raw body field.
    #[test]
    fn tc_b08_01_zeroize_on_drop() {
        // Compile-time check: EntryPlaintext must implement ZeroizeOnDrop.
        // This assertion fails to compile if the derive is missing.
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<EntryPlaintext>();

        // Verify that SearchMatch does not have a `body` field by confirming
        // that only context_blocks (excerpts) are accessible — the struct
        // layout enforces this at compile time.
        let sm = SearchMatch {
            uuid_hex: "abc".to_string(),
            title: "t".to_string(),
            updated_at: 0,
            matched_field: "body".to_string(),
            context_blocks: Vec::new(),
        };
        // SearchResults only exposes title, uuid_hex, matched_field, updated_at,
        // and context_blocks — never the full plaintext body.
        assert_eq!(sm.matched_field, "body");
        assert!(sm.context_blocks.is_empty());
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
