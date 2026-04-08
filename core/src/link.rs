//! `[[title]]` wiki-link parser and backlink index.
//!
//! Extracts Obsidian-style `[[title]]` link references from journal entry
//! bodies and returns them as [`ParsedLink`] values with byte-offset positions.
//!
//! The [`LinkIndex`] type builds forward and reverse link maps from a set of
//! decrypted entries, enabling link resolution and backlink queries.

use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;
use zeroize::Zeroize;

use crate::entry::EntryMeta;

// =============================================================================
// ParsedLink / parse_links
// =============================================================================

/// A parsed `[[title]]` wiki-link reference found in a body string.
///
/// `start` and `end` are byte offsets in the original body; `&body[start..end]`
/// yields the full `[[title]]` text including brackets.
#[derive(Debug, PartialEq)]
pub struct ParsedLink {
    /// Link target title (the content between `[[` and `]]`).
    pub title: String,
    /// Byte offset of the opening `[[` in the original body string.
    pub start: usize,
    /// Byte offset one past the closing `]]` in the original body string.
    pub end: usize,
}

/// Returns a reference to the compiled link regex, initialised at most once.
fn link_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Infallible: pattern is a compile-time literal that always compiles.
        Regex::new(r"\[\[([^\[\]]+)\]\]").unwrap_or_else(|_| unreachable!())
    })
}

/// Extract all `[[title]]` link references from `body`.
///
/// Links are returned in the order they appear.  Empty links `[[]]` are
/// automatically ignored because `[^\[\]]+` requires at least one character.
/// For nested brackets such as `[[a[[b]]]]`, the innermost `[[b]]` is matched
/// by the non-bracket character class.
///
/// `ParsedLink::start` and `ParsedLink::end` are byte offsets in `body`;
/// `&body[link.start..link.end]` reconstructs the full `[[title]]` text.
///
/// # Examples
///
/// ```
/// use pq_diary_core::link::parse_links;
///
/// let links = parse_links("参照: [[プロジェクトA]]");
/// assert_eq!(links.len(), 1);
/// assert_eq!(links[0].title, "プロジェクトA");
/// ```
pub fn parse_links(body: &str) -> Vec<ParsedLink> {
    link_regex()
        .captures_iter(body)
        .filter_map(|cap| {
            let m = cap.get(0)?;
            let title = cap.get(1)?.as_str().to_string();
            Some(ParsedLink {
                title,
                start: m.start(),
                end: m.end(),
            })
        })
        .collect()
}

// =============================================================================
// LinkIndex — forward and reverse link maps
// =============================================================================

/// An entry matched during link resolution.
#[derive(Debug)]
pub struct ResolvedEntry {
    /// UUID hex (32 lowercase characters).
    pub uuid_hex: String,
    /// Short UUID prefix for display (first 8 characters of `uuid_hex`).
    pub id_prefix: String,
    /// Creation timestamp of the matched entry (Unix seconds).
    pub created_at: u64,
}

/// The result of resolving a `[[title]]` link reference.
#[derive(Debug)]
pub struct ResolvedLink {
    /// The title that was looked up.
    pub title: String,
    /// Matched entries: 0 = unresolved, 1 = unique, ≥2 = ambiguous.
    pub matches: Vec<ResolvedEntry>,
}

/// A backlink entry recording that one entry references another.
#[derive(Debug)]
pub struct BacklinkEntry {
    /// UUID (16 raw bytes) of the referencing entry.
    pub source_uuid: [u8; 16],
    /// Title of the referencing entry.
    pub source_title: String,
    /// Creation timestamp of the referencing entry (Unix seconds).
    pub created_at: u64,
}

impl Zeroize for BacklinkEntry {
    fn zeroize(&mut self) {
        self.source_uuid.zeroize();
        self.source_title.zeroize();
        self.created_at.zeroize();
    }
}

impl Drop for BacklinkEntry {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// In-memory forward and reverse link index.
///
/// Built at vault unlock time from all decrypted entries; dropped and zeroized
/// at lock time.  Contains plaintext title strings, so it must be treated as
/// secret data.
///
/// # Fields (private)
///
/// - `title_to_uuids`: forward lookup — title → list of UUIDs (multiple if
///   duplicate titles exist)
/// - `uuid_to_backlinks`: reverse lookup — UUID → list of backlink sources
/// - `uuid_to_title`: UUID → entry title (for display)
/// - `uuid_to_created_at`: UUID → creation timestamp (for [`ResolvedEntry`])
pub struct LinkIndex {
    /// Forward index: title → list of raw UUID bytes.
    title_to_uuids: HashMap<String, Vec<[u8; 16]>>,
    /// Reverse index: UUID → list of backlink sources.
    uuid_to_backlinks: HashMap<[u8; 16], Vec<BacklinkEntry>>,
    /// UUID → entry title (for backlink display).
    uuid_to_title: HashMap<[u8; 16], String>,
    /// UUID → creation timestamp (for [`ResolvedEntry::created_at`]).
    uuid_to_created_at: HashMap<[u8; 16], u64>,
}

impl LinkIndex {
    /// Build a [`LinkIndex`] from a slice of `(EntryMeta, body)` pairs.
    ///
    /// The `body` strings are the decrypted plaintext body of each entry.
    /// This function parses `[[title]]` links in each body to populate both
    /// the forward map (title → UUIDs) and reverse map (UUID → backlinks).
    ///
    /// Entries whose `uuid_hex` cannot be parsed as 32 lowercase hex characters
    /// are silently skipped.
    pub fn build(entries: &[(EntryMeta, String)]) -> Self {
        let mut index = LinkIndex {
            title_to_uuids: HashMap::new(),
            uuid_to_backlinks: HashMap::new(),
            uuid_to_title: HashMap::new(),
            uuid_to_created_at: HashMap::new(),
        };

        // First pass: build forward map (title → UUID) and timestamp map.
        for (meta, _body) in entries {
            let Ok(uuid_bytes) = uuid_hex_to_bytes(&meta.uuid_hex) else {
                continue;
            };
            index
                .title_to_uuids
                .entry(meta.title.clone())
                .or_default()
                .push(uuid_bytes);
            index.uuid_to_title.insert(uuid_bytes, meta.title.clone());
            index
                .uuid_to_created_at
                .insert(uuid_bytes, meta.created_at);
        }

        // Second pass: build reverse map (UUID → backlinks) by parsing each body.
        for (meta, body) in entries {
            let Ok(source_uuid) = uuid_hex_to_bytes(&meta.uuid_hex) else {
                continue;
            };
            for link in parse_links(body) {
                let Some(target_uuids) = index.title_to_uuids.get(&link.title) else {
                    continue;
                };
                // Clone to avoid borrow conflict while mutating uuid_to_backlinks.
                let target_uuids: Vec<[u8; 16]> = target_uuids.clone();
                for target_uuid in target_uuids {
                    index
                        .uuid_to_backlinks
                        .entry(target_uuid)
                        .or_default()
                        .push(BacklinkEntry {
                            source_uuid,
                            source_title: meta.title.clone(),
                            created_at: meta.created_at,
                        });
                }
            }
        }

        index
    }

    /// Resolve a `[[title]]` reference to matching entries.
    ///
    /// Returns a [`ResolvedLink`] whose `matches` field contains:
    /// - 0 entries — the title is unknown (unresolved link)
    /// - 1 entry  — the title maps to exactly one entry (unique link)
    /// - ≥2 entries — the title is shared by multiple entries (ambiguous link)
    pub fn resolve(&self, title: &str) -> ResolvedLink {
        let matches = self
            .title_to_uuids
            .get(title)
            .map(|uuids| {
                uuids
                    .iter()
                    .map(|uuid_bytes| {
                        let uuid_hex = bytes_to_uuid_hex(uuid_bytes);
                        let id_prefix = uuid_hex[..8.min(uuid_hex.len())].to_string();
                        let created_at = self
                            .uuid_to_created_at
                            .get(uuid_bytes)
                            .copied()
                            .unwrap_or(0);
                        ResolvedEntry {
                            uuid_hex,
                            id_prefix,
                            created_at,
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        ResolvedLink {
            title: title.to_string(),
            matches,
        }
    }

    /// Return all backlink sources for entries with the given `title`.
    ///
    /// If multiple entries share the same `title`, backlinks for all of them
    /// are aggregated and returned together.  Returns an empty `Vec` when the
    /// title is unknown or has no incoming links.
    pub fn backlinks_for(&self, title: &str) -> Vec<BacklinkEntry> {
        let Some(uuids) = self.title_to_uuids.get(title) else {
            return Vec::new();
        };
        let mut result = Vec::new();
        for uuid in uuids {
            if let Some(backlinks) = self.uuid_to_backlinks.get(uuid) {
                for entry in backlinks {
                    result.push(BacklinkEntry {
                        source_uuid: entry.source_uuid,
                        source_title: entry.source_title.clone(),
                        created_at: entry.created_at,
                    });
                }
            }
        }
        result
    }

    /// Return all known entry titles in unspecified order.
    ///
    /// Used by the CLI to generate the completion file for vim's `completefunc`.
    pub fn all_titles(&self) -> Vec<String> {
        self.title_to_uuids.keys().cloned().collect()
    }
}

impl Zeroize for LinkIndex {
    /// Zeroize all secret data held by this index.
    ///
    /// All `HashMap`s are drained; title `String` values and UUID keys are
    /// explicitly zeroized before being dropped so that the bytes are
    /// overwritten in memory before the allocator reclaims them.
    fn zeroize(&mut self) {
        // Drain title_to_uuids: zeroize each title key and each UUID array.
        for (mut title, mut uuids) in self.title_to_uuids.drain() {
            title.zeroize();
            for uuid in uuids.iter_mut() {
                uuid.zeroize();
            }
        }

        // Drain uuid_to_backlinks: zeroize each UUID key and BacklinkEntry.
        for (mut uuid_key, mut backlinks) in self.uuid_to_backlinks.drain() {
            uuid_key.zeroize();
            for entry in backlinks.iter_mut() {
                entry.zeroize();
            }
        }

        // Drain uuid_to_title: zeroize each UUID key and title string.
        for (mut uuid_key, mut title) in self.uuid_to_title.drain() {
            uuid_key.zeroize();
            title.zeroize();
        }

        // Drain uuid_to_created_at: zeroize UUID keys and timestamp values.
        for (mut uuid_key, mut ts) in self.uuid_to_created_at.drain() {
            uuid_key.zeroize();
            ts.zeroize();
        }
    }
}

impl Drop for LinkIndex {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// =============================================================================
// UUID hex helpers (private)
// =============================================================================

/// Parse a 32-character lowercase hex string into 16 raw bytes.
///
/// Returns `Err(())` if `hex` is not exactly 32 bytes or contains non-hex
/// characters.
fn uuid_hex_to_bytes(hex: &str) -> Result<[u8; 16], ()> {
    if hex.len() != 32 {
        return Err(());
    }
    let bytes = hex.as_bytes();
    let mut out = [0u8; 16];
    for (i, chunk) in bytes.chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0]).ok_or(())?;
        let lo = hex_nibble(chunk[1]).ok_or(())?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

/// Convert a single ASCII hex digit to its numeric value.
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Convert 16 raw UUID bytes to a 32-character lowercase hex string.
fn bytes_to_uuid_hex(bytes: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(32);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // TC-044-01: 単一リンクのパース
    // =========================================================================

    /// TC-044-01: parse_links finds a single [[...]] link and records its
    /// title and byte positions.
    #[test]
    fn tc_044_01_single_link_parse() {
        let body = "今日は [[プロジェクトA]] について";
        let links = parse_links(body);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].title, "プロジェクトA");
        // start..end must reconstruct the full [[...]] text
        assert_eq!(&body[links[0].start..links[0].end], "[[プロジェクトA]]");
    }

    // =========================================================================
    // TC-044-02: 複数リンクのパース
    // =========================================================================

    /// TC-044-02: parse_links returns one ParsedLink per [[...]] occurrence.
    #[test]
    fn tc_044_02_multiple_links_parse() {
        let body = "[[A]] と [[B]] を参照";
        let links = parse_links(body);
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].title, "A");
        assert_eq!(links[1].title, "B");
        assert_eq!(&body[links[0].start..links[0].end], "[[A]]");
        assert_eq!(&body[links[1].start..links[1].end], "[[B]]");
    }

    // =========================================================================
    // TC-044-03: 空リンク [[]] のスキップ
    // =========================================================================

    /// TC-044-03: [[]] is not matched because [^\[\]]+ requires at least one
    /// character.
    #[test]
    fn tc_044_03_empty_link_skipped() {
        let links = parse_links("テスト [[]] 空");
        assert!(links.is_empty(), "[[]] must produce no ParsedLink");
    }

    // =========================================================================
    // TC-044-04: リンクなし
    // =========================================================================

    /// TC-044-04: Plain text with no [[...]] patterns yields an empty Vec.
    #[test]
    fn tc_044_04_no_links() {
        let links = parse_links("リンクなしテキスト");
        assert!(links.is_empty(), "no links expected in plain text");
    }

    // =========================================================================
    // TC-044-05: 日本語タイトルのリンク
    // =========================================================================

    /// TC-044-05: Unicode (Japanese) titles are extracted correctly.
    #[test]
    fn tc_044_05_japanese_title_link() {
        let body = "[[日本語のタイトル]]";
        let links = parse_links(body);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].title, "日本語のタイトル");
        assert_eq!(&body[links[0].start..links[0].end], "[[日本語のタイトル]]");
    }

    // =========================================================================
    // TC-044-06: 特殊文字を含むタイトル
    // =========================================================================

    /// TC-044-06: Titles with spaces, hyphens, and # are extracted correctly.
    #[test]
    fn tc_044_06_special_chars_in_title() {
        let body = "[[2026-04-05 ミーティング #議事録]]";
        let links = parse_links(body);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].title, "2026-04-05 ミーティング #議事録");
        assert_eq!(
            &body[links[0].start..links[0].end],
            "[[2026-04-05 ミーティング #議事録]]"
        );
    }

    // =========================================================================
    // Additional: ネストした括弧のハンドリング
    // =========================================================================

    /// Nested brackets: [[a[[b]]]] — only the innermost [[b]] matches.
    #[test]
    fn nested_brackets_innermost_match() {
        let body = "[[a[[b]]]]";
        let links = parse_links(body);
        // [^\[\]]+ forbids brackets inside, so only [[b]] matches
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].title, "b");
    }

    // =========================================================================
    // Additional: 空文字列の入力
    // =========================================================================

    /// Empty string input yields an empty Vec.
    #[test]
    fn empty_body_yields_no_links() {
        let links = parse_links("");
        assert!(links.is_empty());
    }

    // =========================================================================
    // Additional: 複数リンクの順序保証
    // =========================================================================

    /// Links are returned in the order they appear in the body.
    #[test]
    fn links_returned_in_order() {
        let body = "[[第一]] 本文 [[第二]] 続き [[第三]]";
        let links = parse_links(body);
        assert_eq!(links.len(), 3);
        assert_eq!(links[0].title, "第一");
        assert_eq!(links[1].title, "第二");
        assert_eq!(links[2].title, "第三");
    }

    // =========================================================================
    // LinkIndex tests
    // =========================================================================

    /// Construct an `EntryMeta` for testing.
    fn make_meta(uuid_hex: &str, title: &str, created_at: u64) -> EntryMeta {
        EntryMeta {
            uuid_hex: uuid_hex.to_string(),
            title: title.to_string(),
            tags: vec![],
            created_at,
            updated_at: 0,
        }
    }

    // Deterministic test UUIDs (32 hex chars each).
    const UUID_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const UUID_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const UUID_C: &str = "cccccccccccccccccccccccccccccccc";

    // =========================================================================
    // TC-045-01: 基本的なインデックス構築
    // =========================================================================

    /// TC-045-01: Given entry A (body "[[B]]") and entry B (body ""),
    /// resolve("B") returns entry B's UUID and backlinks_for("B") returns entry A.
    #[test]
    fn tc_045_01_basic_index_build() {
        let entries = vec![
            (make_meta(UUID_A, "A", 100), "[[B]]".to_string()),
            (make_meta(UUID_B, "B", 200), String::new()),
        ];
        let index = LinkIndex::build(&entries);

        // resolve("B") → 1 match: entry B
        let resolved = index.resolve("B");
        assert_eq!(resolved.title, "B");
        assert_eq!(resolved.matches.len(), 1);
        assert_eq!(resolved.matches[0].uuid_hex, UUID_B);
        assert_eq!(resolved.matches[0].created_at, 200);

        // backlinks_for("B") → entry A is the source
        let backlinks = index.backlinks_for("B");
        assert_eq!(backlinks.len(), 1);
        assert_eq!(backlinks[0].source_title, "A");
    }

    // =========================================================================
    // TC-045-02: 同名タイトル重複の解決
    // =========================================================================

    /// TC-045-02: Two entries share title "メモ"; resolve("メモ") returns both.
    #[test]
    fn tc_045_02_duplicate_title_resolution() {
        let entries = vec![
            (make_meta(UUID_A, "メモ", 100), String::new()),
            (make_meta(UUID_B, "メモ", 200), String::new()),
            (make_meta(UUID_C, "C", 300), "[[メモ]]".to_string()),
        ];
        let index = LinkIndex::build(&entries);

        let resolved = index.resolve("メモ");
        assert_eq!(resolved.matches.len(), 2, "both メモ entries must match");
        let found_uuids: Vec<&str> = resolved.matches.iter().map(|m| m.uuid_hex.as_str()).collect();
        assert!(found_uuids.contains(&UUID_A), "UUID_A must be in matches");
        assert!(found_uuids.contains(&UUID_B), "UUID_B must be in matches");
    }

    // =========================================================================
    // TC-045-03: 未解決リンク
    // =========================================================================

    /// TC-045-03: A link to a non-existent title resolves to an empty matches list.
    #[test]
    fn tc_045_03_unresolved_link() {
        let entries = vec![(
            make_meta(UUID_A, "A", 100),
            "[[存在しない]]".to_string(),
        )];
        let index = LinkIndex::build(&entries);

        let resolved = index.resolve("存在しない");
        assert!(
            resolved.matches.is_empty(),
            "unresolved link must yield empty matches"
        );
    }

    // =========================================================================
    // TC-045-04: 相互リンク
    // =========================================================================

    /// TC-045-04: A links to B and B links to A; each appears as a backlink of the other.
    #[test]
    fn tc_045_04_mutual_links() {
        let entries = vec![
            (make_meta(UUID_A, "A", 100), "[[B]]".to_string()),
            (make_meta(UUID_B, "B", 200), "[[A]]".to_string()),
        ];
        let index = LinkIndex::build(&entries);

        let bl_a = index.backlinks_for("A");
        assert_eq!(bl_a.len(), 1);
        assert_eq!(bl_a[0].source_title, "B");

        let bl_b = index.backlinks_for("B");
        assert_eq!(bl_b.len(), 1);
        assert_eq!(bl_b[0].source_title, "A");
    }

    // =========================================================================
    // TC-045-05: all_titles()
    // =========================================================================

    /// TC-045-05: all_titles returns every unique entry title.
    #[test]
    fn tc_045_05_all_titles() {
        let entries = vec![
            (make_meta(UUID_A, "A", 100), String::new()),
            (make_meta(UUID_B, "B", 200), String::new()),
            (make_meta(UUID_C, "C", 300), String::new()),
        ];
        let index = LinkIndex::build(&entries);

        let mut titles = index.all_titles();
        titles.sort();
        assert_eq!(titles, vec!["A", "B", "C"]);
    }

    // =========================================================================
    // TC-045-06: 空インデックス
    // =========================================================================

    /// TC-045-06: An index built from an empty slice returns empty results.
    #[test]
    fn tc_045_06_empty_index() {
        let index = LinkIndex::build(&[]);
        assert!(
            index.resolve("anything").matches.is_empty(),
            "empty index resolve must be empty"
        );
        assert!(
            index.backlinks_for("anything").is_empty(),
            "empty index backlinks_for must be empty"
        );
        assert!(
            index.all_titles().is_empty(),
            "empty index all_titles must be empty"
        );
    }

    // =========================================================================
    // Zeroize: インデックスのzeroize後はすべて空
    // =========================================================================

    /// After zeroize() the index must behave as if empty.
    #[test]
    fn tc_045_zeroize_clears_index() {
        let entries = vec![
            (make_meta(UUID_A, "A", 100), "[[B]]".to_string()),
            (make_meta(UUID_B, "B", 200), String::new()),
        ];
        let mut index = LinkIndex::build(&entries);
        index.zeroize();

        assert!(index.all_titles().is_empty(), "titles must be empty after zeroize");
        assert!(
            index.resolve("A").matches.is_empty(),
            "resolve must be empty after zeroize"
        );
        assert!(
            index.backlinks_for("B").is_empty(),
            "backlinks must be empty after zeroize"
        );
    }

    // =========================================================================
    // uuid_hex_to_bytes / bytes_to_uuid_hex roundtrip
    // =========================================================================

    /// UUID hex ↔ bytes roundtrip must be lossless.
    #[test]
    fn uuid_hex_bytes_roundtrip() {
        let hex = "0123456789abcdef0123456789abcdef";
        let bytes = uuid_hex_to_bytes(hex).expect("valid hex");
        let roundtripped = bytes_to_uuid_hex(&bytes);
        assert_eq!(roundtripped, hex);
    }

    /// uuid_hex_to_bytes rejects strings that are not 32 characters.
    #[test]
    fn uuid_hex_to_bytes_rejects_wrong_length() {
        assert!(uuid_hex_to_bytes("abc").is_err());
        assert!(uuid_hex_to_bytes("").is_err());
    }

    /// uuid_hex_to_bytes rejects strings with non-hex characters.
    #[test]
    fn uuid_hex_to_bytes_rejects_non_hex() {
        let bad = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"; // 32 chars, non-hex
        assert!(uuid_hex_to_bytes(bad).is_err());
    }
}
