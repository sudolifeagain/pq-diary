//! Vault-wide statistics collection.
//!
//! Provides `collect_stats` which iterates over all `ENTRY` records in the
//! vault, decrypts each one, and accumulates statistics into a `VaultStats`
//! value.  Each `EntryPlaintext` is dropped (zeroed via
//! [`zeroize::ZeroizeOnDrop`]) immediately after aggregation, so only one
//! entry's plaintext occupies memory at a time.

use crate::{
    crypto::CryptoEngine,
    entry::EntryPlaintext,
    error::DiaryError,
    vault::{format::RECORD_TYPE_ENTRY, reader::read_vault},
};
use chrono::DateTime;
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;

// =============================================================================
// Public types
// =============================================================================

/// Vault-wide statistics.
#[derive(Serialize)]
pub struct VaultStats {
    /// Total number of entries.
    pub entry_count: usize,
    /// Total number of unique tags across all entries.
    pub tag_count: usize,
    /// Earliest entry creation date (Unix timestamp seconds).
    /// `None` when the vault has no entries.
    pub first_entry_date: Option<u64>,
    /// Latest entry creation date (Unix timestamp seconds).
    /// `None` when the vault has no entries.
    pub last_entry_date: Option<u64>,
    /// Number of distinct days with at least one entry in the last 30 days.
    pub active_days_30d: usize,
    /// Character count statistics across all entry bodies.
    pub char_stats: CharStats,
    /// Tag distribution sorted by count descending (at most 10 tags).
    pub tag_distribution: Vec<TagCount>,
    /// Daily activity sorted by date ascending.
    pub daily_activity: Vec<DailyActivity>,
}

/// Character count statistics across all entry bodies.
#[derive(Serialize)]
pub struct CharStats {
    /// Total characters summed over all entry bodies.
    pub total: usize,
    /// Average characters per entry body (0 when there are no entries).
    pub average: usize,
    /// Maximum characters in any single entry body.
    pub max: usize,
}

/// Tag name and occurrence count.
///
/// Tag names are treated as non-secret metadata (they appear in list output).
/// Only entry body content is considered secret and is zeroized after
/// aggregation.
#[derive(Serialize)]
pub struct TagCount {
    /// Tag name.
    pub tag: String,
    /// Number of entries carrying this tag.
    pub count: usize,
}

/// Daily writing activity.
#[derive(Serialize)]
pub struct DailyActivity {
    /// Date in "YYYY-MM-DD" format (UTC).
    pub date: String,
    /// Number of entries created on this date.
    pub count: usize,
}

// =============================================================================
// Public API
// =============================================================================

/// Collect vault-wide statistics by scanning all entry records.
///
/// Reads the vault at `vault_path`, iterates over every `ENTRY` record,
/// decrypts and deserialises each plaintext, and aggregates:
///
/// - Entry count, first/last creation timestamp, active-days-30d
/// - Per-body character totals (total, average, max)
/// - Tag occurrence counts (top 10, descending by count)
/// - Daily activity (date → count, ascending by date)
///
/// Template records are skipped.  Each [`crate::entry::EntryPlaintext`] is
/// zeroed (via [`zeroize::ZeroizeOnDrop`]) as soon as its fields have been
/// aggregated.
///
/// # Security note
///
/// Tag names and dates are treated as non-secret metadata (they appear in
/// `pq-diary list` output).  Only entry body content is considered secret
/// and is zeroized after aggregation.  Wrapping these values in `Zeroizing`
/// would complicate `Serialize` without meaningful security benefit, since
/// other commands already expose them in plaintext.
///
/// # Errors
///
/// Returns [`DiaryError::Entry`] if JSON deserialisation fails for any record.
/// Returns [`DiaryError::Crypto`] on decryption failure.
/// Returns [`DiaryError::Io`] on vault file I/O failure.
pub fn collect_stats(vault_path: &Path, engine: &CryptoEngine) -> Result<VaultStats, DiaryError> {
    let (_header, records) = read_vault(vault_path)?;

    let mut entry_count = 0usize;
    let mut total_chars = 0usize;
    let mut max_chars = 0usize;
    let mut tag_counts: HashMap<String, usize> = HashMap::new();
    let mut daily_counts: HashMap<String, usize> = HashMap::new();
    let mut first_date: Option<u64> = None;
    let mut last_date: Option<u64> = None;

    for record in &records {
        if record.record_type != RECORD_TYPE_ENTRY {
            continue;
        }

        // Decrypt and deserialise. `plaintext` is ZeroizeOnDrop; its contents
        // are zeroed when this block exits.
        let decrypted = engine.decrypt(&record.iv, &record.ciphertext)?;
        let plaintext: EntryPlaintext = serde_json::from_slice(decrypted.as_ref())
            .map_err(|e| DiaryError::Entry(format!("deserialization failed: {e}")))?;

        let char_count = plaintext.body.chars().count();
        entry_count += 1;
        total_chars += char_count;
        if char_count > max_chars {
            max_chars = char_count;
        }

        for tag in &plaintext.tags {
            *tag_counts.entry(tag.clone()).or_insert(0) += 1;
        }

        let date_str = unix_ts_to_date_str(record.created_at);
        *daily_counts.entry(date_str).or_insert(0) += 1;

        first_date = Some(match first_date {
            None => record.created_at,
            Some(prev) => prev.min(record.created_at),
        });
        last_date = Some(match last_date {
            None => record.created_at,
            Some(prev) => prev.max(record.created_at),
        });
    }

    let average_chars = if entry_count > 0 {
        total_chars / entry_count
    } else {
        0
    };
    let tag_count = tag_counts.len();

    // Tag distribution: descending by count, tie-break ascending by tag name;
    // keep only the top 10.
    let mut tag_distribution: Vec<TagCount> = tag_counts
        .into_iter()
        .map(|(tag, count)| TagCount { tag, count })
        .collect();
    tag_distribution.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.tag.cmp(&b.tag)));
    tag_distribution.truncate(10);

    // active_days_30d: count distinct days within the last 30 days.
    let now_ts = chrono::Utc::now().timestamp();
    let cutoff_ts = now_ts - 30i64 * 24 * 3600;
    let active_days_30d = daily_counts
        .keys()
        .filter(|date_str| {
            date_str_to_day_start_ts(date_str)
                .map(|ts| ts >= cutoff_ts)
                .unwrap_or(false)
        })
        .count();

    // Daily activity: sorted by date ascending.
    let mut daily_activity: Vec<DailyActivity> = daily_counts
        .into_iter()
        .map(|(date, count)| DailyActivity { date, count })
        .collect();
    daily_activity.sort_by(|a, b| a.date.cmp(&b.date));

    Ok(VaultStats {
        entry_count,
        tag_count,
        first_entry_date: first_date,
        last_entry_date: last_date,
        active_days_30d,
        char_stats: CharStats {
            total: total_chars,
            average: average_chars,
            max: max_chars,
        },
        tag_distribution,
        daily_activity,
    })
}

// =============================================================================
// Private helpers
// =============================================================================

/// Convert a Unix timestamp (seconds) to a "YYYY-MM-DD" date string in UTC.
fn unix_ts_to_date_str(ts: u64) -> String {
    use chrono::TimeZone as _;
    match chrono::Utc.timestamp_opt(ts as i64, 0).single() {
        Some(dt) => dt.format("%Y-%m-%d").to_string(),
        None => "1970-01-01".to_string(),
    }
}

/// Parse a "YYYY-MM-DD" string to the Unix timestamp of the start of that day
/// (00:00:00 UTC).  Returns `None` if parsing fails.
fn date_str_to_day_start_ts(s: &str) -> Option<i64> {
    let rfc3339 = format!("{s}T00:00:00Z");
    rfc3339
        .parse::<DateTime<chrono::Utc>>()
        .ok()
        .map(|dt| dt.timestamp())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use crate::{
        crypto::kdf::Argon2Params,
        vault::{init::VaultManager, reader::read_vault, writer::write_vault},
        DiaryCore,
    };
    use secrecy::SecretBox;
    use std::path::PathBuf;
    use tempfile::TempDir;

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

    /// Patch the `created_at` (and `updated_at`) timestamps of all ENTRY records
    /// in `vault_path`, in order, using values from `timestamps`.
    fn patch_entry_timestamps(vault_path: &PathBuf, timestamps: &[u64]) {
        let (header, mut records) = read_vault(vault_path).expect("read_vault");
        let mut ts_iter = timestamps.iter();
        for record in &mut records {
            if record.record_type == crate::vault::format::RECORD_TYPE_ENTRY {
                if let Some(&ts) = ts_iter.next() {
                    record.created_at = ts;
                    record.updated_at = ts;
                }
            }
        }
        write_vault(vault_path, header, &records).expect("write_vault");
    }

    // -------------------------------------------------------------------------
    // TC-C01-01: entry count
    // -------------------------------------------------------------------------

    /// TC-C01-01: collect_stats returns the correct entry count.
    #[test]
    fn tc_c01_01_entry_count() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_pqd = setup_test_vault(&dir);

        let mut core = DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");
        core.unlock(secret("password")).expect("unlock");

        core.new_entry("エントリ1", "本文1", vec![])
            .expect("new_entry 1");
        core.new_entry("エントリ2", "本文2", vec![])
            .expect("new_entry 2");
        core.new_entry("エントリ3", "本文3", vec![])
            .expect("new_entry 3");

        let stats = core.stats().expect("stats");
        assert_eq!(stats.entry_count, 3, "entry_count must be 3");
    }

    // -------------------------------------------------------------------------
    // TC-C01-02: first/last entry dates
    // -------------------------------------------------------------------------

    /// TC-C01-02: collect_stats returns correct first/last entry dates.
    ///
    /// Entries are created normally, then their `created_at` timestamps are
    /// patched to known values via read-modify-write on the vault file.
    #[test]
    fn tc_c01_02_first_last_dates() {
        // 2026-01-01 00:00:00 UTC
        const TS_JAN01: u64 = 1_735_689_600;
        // 2026-04-01 00:00:00 UTC
        const TS_APR01: u64 = 1_743_465_600;
        // 2026-04-08 00:00:00 UTC
        const TS_APR08: u64 = 1_744_070_400;

        let dir = tempfile::tempdir().expect("tempdir");
        let vault_pqd = setup_test_vault(&dir);

        let mut core = DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");
        core.unlock(secret("password")).expect("unlock");

        core.new_entry("エントリA", "本文A", vec![])
            .expect("new_entry A");
        core.new_entry("エントリB", "本文B", vec![])
            .expect("new_entry B");
        core.new_entry("エントリC", "本文C", vec![])
            .expect("new_entry C");

        // Patch timestamps in creation order.
        patch_entry_timestamps(&vault_pqd, &[TS_JAN01, TS_APR01, TS_APR08]);

        let stats = core.stats().expect("stats");

        assert_eq!(
            stats.first_entry_date,
            Some(TS_JAN01),
            "first_entry_date must be 2026-01-01"
        );
        assert_eq!(
            stats.last_entry_date,
            Some(TS_APR08),
            "last_entry_date must be 2026-04-08"
        );
    }

    // -------------------------------------------------------------------------
    // TC-C01-03: character count statistics
    // -------------------------------------------------------------------------

    /// TC-C01-03: char_stats totals, average, and max are correct.
    #[test]
    fn tc_c01_03_char_stats() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_pqd = setup_test_vault(&dir);

        let mut core = DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");
        core.unlock(secret("password")).expect("unlock");

        // Bodies of exactly 100, 200, and 300 characters.
        core.new_entry("エントリ1", &"a".repeat(100), vec![])
            .expect("new_entry 1");
        core.new_entry("エントリ2", &"b".repeat(200), vec![])
            .expect("new_entry 2");
        core.new_entry("エントリ3", &"c".repeat(300), vec![])
            .expect("new_entry 3");

        let stats = core.stats().expect("stats");

        assert_eq!(stats.char_stats.total, 600, "total chars must be 600");
        assert_eq!(stats.char_stats.average, 200, "average chars must be 200");
        assert_eq!(stats.char_stats.max, 300, "max chars must be 300");
    }

    // -------------------------------------------------------------------------
    // TC-C01-04: tag distribution
    // -------------------------------------------------------------------------

    /// TC-C01-04: tag_distribution is sorted descending and capped at 10.
    ///
    /// Creates entries with "日記" ×5, "技術" ×3, "旅行" ×1, and 7 unique
    /// single-occurrence tags, yielding exactly 10 unique tags.
    #[test]
    fn tc_c01_04_tag_distribution() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_pqd = setup_test_vault(&dir);

        let mut core = DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");
        core.unlock(secret("password")).expect("unlock");

        for i in 0..5 {
            core.new_entry(
                &format!("日記エントリ{i}"),
                "本文",
                vec!["日記".to_string()],
            )
            .expect("new_entry 日記");
        }
        for i in 0..3 {
            core.new_entry(
                &format!("技術エントリ{i}"),
                "本文",
                vec!["技術".to_string()],
            )
            .expect("new_entry 技術");
        }
        core.new_entry("旅行エントリ", "本文", vec!["旅行".to_string()])
            .expect("new_entry 旅行");
        for tag in &["aaa", "bbb", "ccc", "ddd", "eee", "fff", "ggg"] {
            core.new_entry(&format!("エントリ_{tag}"), "本文", vec![tag.to_string()])
                .expect("new_entry other");
        }

        let stats = core.stats().expect("stats");

        assert!(
            stats.tag_distribution.len() <= 10,
            "tag_distribution must have at most 10 entries"
        );
        assert_eq!(
            stats.tag_distribution.len(),
            10,
            "with exactly 10 unique tags the distribution must have 10 entries"
        );
        assert_eq!(
            stats.tag_distribution[0].tag, "日記",
            "first tag must be 日記"
        );
        assert_eq!(stats.tag_distribution[0].count, 5, "日記 count must be 5");
        assert_eq!(
            stats.tag_distribution[1].tag, "技術",
            "second tag must be 技術"
        );
        assert_eq!(stats.tag_distribution[1].count, 3, "技術 count must be 3");
        // Verify descending order throughout.
        for i in 0..stats.tag_distribution.len() - 1 {
            assert!(
                stats.tag_distribution[i].count >= stats.tag_distribution[i + 1].count,
                "tag_distribution must be sorted descending at index {i}"
            );
        }
    }

    // -------------------------------------------------------------------------
    // TC-C01-05: empty vault
    // -------------------------------------------------------------------------

    /// TC-C01-05: collect_stats on an empty vault does not error.
    #[test]
    fn tc_c01_05_empty_vault() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_pqd = setup_test_vault(&dir);

        let mut core = DiaryCore::new(vault_pqd.to_str().expect("utf8")).expect("DiaryCore::new");
        core.unlock(secret("password")).expect("unlock");

        let stats = core.stats().expect("stats must not error on empty vault");

        assert_eq!(stats.entry_count, 0, "entry_count must be 0");
        assert_eq!(
            stats.first_entry_date, None,
            "first_entry_date must be None"
        );
        assert_eq!(stats.char_stats.total, 0, "char_stats.total must be 0");
        assert!(
            stats.tag_distribution.is_empty(),
            "tag_distribution must be empty"
        );
        assert!(
            stats.daily_activity.is_empty(),
            "daily_activity must be empty"
        );
    }
}
