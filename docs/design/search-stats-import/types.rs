// ========================================
// search-stats-import 型定義
// ========================================
//
// 作成日: 2026-04-09
// 関連設計: architecture.md
//
// 信頼性レベル:
// - 🔵 青信号: EARS要件定義書・設計文書・既存実装を参考にした確実な型定義
// - 🟡 黄信号: EARS要件定義書・設計文書・既存実装から妥当な推測による型定義
// - 🔴 赤信号: EARS要件定義書・設計文書・既存実装にない推測による型定義

use serde::Serialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ========================================
// Phase B: search 型定義
// ========================================

/// Search query parameters.
/// 🔵 信頼性: 要件定義 REQ-B01〜B07 + ユーザヒアリング
pub struct SearchQuery {
    /// Regex pattern string. 🔵 REQ-B02
    pub pattern: String,
    /// Tag filter (prefix match). None = all entries. 🟡 REQ-B06
    pub tag_filter: Option<String>,
    /// Number of context lines before/after match. Default: 2. 🔵 REQ-B05
    pub context_lines: usize,
    /// If true, return count only. 🟡 REQ-B07
    pub count_only: bool,
}

/// A single search match within an entry.
/// 🔵 信頼性: 要件定義 REQ-B04 + grep 慣例
pub struct SearchMatch {
    /// Entry UUID hex (32 chars). 🔵 既存 EntryMeta
    pub uuid_hex: String,
    /// Entry title. 🔵 既存 EntryMeta
    pub title: String,
    /// Entry updated_at timestamp. 🔵 既存 EntryMeta
    pub updated_at: u64,
    /// Which field matched: "body", "title", "tags", "template". 🔵 REQ-B03
    pub matched_field: String,
    /// Context lines around each match. 🔵 REQ-B04/B05
    pub context_blocks: Vec<ContextBlock>,
}

/// A block of lines surrounding a match.
/// 🟡 信頼性: grep 出力慣例から推測
pub struct ContextBlock {
    /// 1-based line number of the match line. 🟡 grep 慣例
    pub match_line_number: usize,
    /// Lines: (line_number, line_content, is_match). 🟡 grep 慣例
    pub lines: Vec<(usize, String, bool)>,
}

/// Search results summary.
/// 🔵 信頼性: 要件定義 REQ-B01
pub struct SearchResults {
    /// All matches across entries. 🔵 REQ-B01
    pub matches: Vec<SearchMatch>,
    /// Total number of entries that matched. 🔵 REQ-B07
    pub matched_entry_count: usize,
    /// Total number of individual line matches. 🟡 推測
    pub matched_line_count: usize,
}

// ========================================
// Phase C: stats 型定義
// ========================================

/// Vault-wide statistics.
/// 🔵 信頼性: 要件定義 REQ-C01〜C02 + ユーザヒアリング
#[derive(Serialize)]
pub struct VaultStats {
    /// Total number of entries. 🔵 REQ-C02
    pub entry_count: usize,
    /// Total number of unique tags. 🔵 REQ-C02
    pub tag_count: usize,
    /// Earliest entry date (Unix timestamp). 🔵 REQ-C02
    pub first_entry_date: Option<u64>,
    /// Latest entry date (Unix timestamp). 🔵 REQ-C02
    pub last_entry_date: Option<u64>,
    /// Number of active days in the last 30 days. 🟡 REQ-C02 推測
    pub active_days_30d: usize,
    /// Character count statistics. 🔵 REQ-C02
    pub char_stats: CharStats,
    /// Tag distribution (sorted by count desc, top N). 🔵 REQ-C02
    pub tag_distribution: Vec<TagCount>,
    /// Daily activity for heatmap (date → count). 🔵 REQ-C05
    pub daily_activity: Vec<DailyActivity>,
}

/// Character count statistics.
/// 🟡 信頼性: 要件「文字数推移」から推測
#[derive(Serialize)]
pub struct CharStats {
    /// Total characters across all entries. 🟡 推測
    pub total: usize,
    /// Average characters per entry. 🟡 推測
    pub average: usize,
    /// Maximum characters in a single entry. 🟡 推測
    pub max: usize,
}

/// Tag name and occurrence count.
/// 🔵 信頼性: 要件「タグ分布」
#[derive(Serialize)]
pub struct TagCount {
    /// Tag name. 🔵
    pub tag: String,
    /// Number of entries with this tag. 🔵
    pub count: usize,
}

/// Daily writing activity.
/// 🔵 信頼性: 要件 REQ-C05 ヒートマップ
#[derive(Serialize)]
pub struct DailyActivity {
    /// Date string "YYYY-MM-DD". 🔵
    pub date: String,
    /// Number of entries created/updated on this date. 🔵
    pub count: usize,
}

// ========================================
// Phase D: import 型定義
// ========================================

/// Import source configuration.
/// 🔵 信頼性: 要件定義 REQ-D01〜D08
pub struct ImportSource {
    /// Source directory path. 🔵 REQ-D01
    pub directory: std::path::PathBuf,
    /// If true, only preview without writing. 🟡 REQ-D07
    pub dry_run: bool,
}

/// A parsed Markdown file ready for import.
/// 🔵 信頼性: 要件定義 REQ-D03〜D06
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MarkdownFile {
    /// Entry title (from frontmatter or filename). 🔵 REQ-D03
    pub title: String,
    /// Extracted tags (from frontmatter + inline #tags). 🔵 REQ-D05/D06
    pub tags: Vec<String>,
    /// Body text after wiki-link/tag conversion. 🔵 REQ-D04/D05
    pub body: String,
    /// Original file path (for error reporting). 🔵
    pub source_path: String,
}

/// Import result summary.
/// 🔵 信頼性: 要件定義 REQ-D09
pub struct ImportResult {
    /// Number of entries successfully imported. 🔵 REQ-D09
    pub imported: usize,
    /// Number of files skipped (non-.md, .obsidian, duplicates). 🔵 REQ-D09
    pub skipped: usize,
    /// Number of [[wiki-link]] conversions performed. 🔵 REQ-D09
    pub links_converted: usize,
    /// Number of #tag extractions performed. 🔵 REQ-D09
    pub tags_converted: usize,
    /// Skipped file details (path + reason). 🟡 推測
    pub skip_details: Vec<SkipDetail>,
}

/// Detail about a skipped file during import.
/// 🟡 信頼性: UX 観点から推測
pub struct SkipDetail {
    /// File path. 🟡
    pub path: String,
    /// Reason for skipping. 🟡
    pub reason: String,
}

// ========================================
// Phase A: VaultGuard (技術的負債修正)
// ========================================

/// RAII guard that ensures `DiaryCore::lock()` is called on drop.
///
/// Wraps a mutable reference to `DiaryCore` and calls `lock()` in its
/// `Drop` implementation, guaranteeing that key material is erased even
/// when an early `?` return or panic occurs.
///
/// 🟡 信頼性: S5レビュー L-2 から推測した設計パターン
pub struct VaultGuard<'a> {
    core: &'a mut crate::DiaryCore,
}

// ========================================
// 信頼性レベルサマリー
// ========================================
// - 🔵 青信号: 38件 (72%)
// - 🟡 黄信号: 15件 (28%)
// - 🔴 赤信号: 0件 (0%)
//
// 品質評価: ✅ 高品質
