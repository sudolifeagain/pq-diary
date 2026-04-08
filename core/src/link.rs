//! `[[title]]` wiki-link parser.
//!
//! Extracts Obsidian-style `[[title]]` link references from journal entry
//! bodies and returns them as [`ParsedLink`] values with byte-offset positions.

use regex::Regex;
use std::sync::OnceLock;

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
}
