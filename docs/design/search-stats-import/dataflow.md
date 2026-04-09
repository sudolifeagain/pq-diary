# 検索 + 統計 + インポート データフロー図

**作成日**: 2026-04-09
**関連アーキテクチャ**: [architecture.md](architecture.md)
**関連要件定義**: [requirements.md](../../spec/search-stats-import/requirements.md)

**【信頼性レベル凡例】**:
- 🔵 **青信号**: EARS要件定義書・設計文書・ユーザヒアリングを参考にした確実なフロー
- 🟡 **黄信号**: EARS要件定義書・設計文書・ユーザヒアリングから妥当な推測によるフロー
- 🔴 **赤信号**: EARS要件定義書・設計文書・ユーザヒアリングにない推測によるフロー

---

## search コマンドのデータフロー 🔵

**信頼性**: 🔵 *要件定義 REQ-B01〜B09 + 設計ヒアリング（ストリーミング方式）*

```
User
 │
 ├── pq-diary search "パターン" [--tag TAG] [--context N] [--count]
 │
 ▼
cli::cmd_search
 │
 ├── 1. get_password() → SecretString
 ├── 2. DiaryCore::new() + unlock()
 ├── 3. VaultGuard 取得
 │
 ▼
core::search::search_entries(engine, vault_path, query)
 │
 ├── 4. regex::Regex::new(pattern)?
 ├── 5. read_vault() → (header, records)
 │
 ├── FOR each record (record_type == ENTRY):
 │   ├── 6. engine.decrypt(iv, ciphertext) → Zeroizing<Vec<u8>>
 │   ├── 7. serde_json::from_slice → EntryPlaintext
 │   ├── 8. regex.is_match(body) || regex.is_match(title) || tags.any(match)
 │   ├── 9. IF match → format_context(body, matches, context_lines)
 │   │              → push to results Vec<SearchMatch>
 │   └── 10. EntryPlaintext::zeroize() (ZeroizeOnDrop)
 │
 ├── FOR each record (record_type == TEMPLATE) [テンプレート本文検索]:
 │   ├── 同上の復号 + マッチ処理
 │   └── zeroize
 │
 ▼
cli::cmd_search (結果表示)
 │
 ├── 11. IF --count → print count only
 ├── 12. ELSE → print each SearchMatch (id, date, title, context lines)
 ├── 13. VaultGuard drop → core.lock()
 │
 ▼
User sees search results
```

### format_context() の詳細 🟡

**信頼性**: 🟡 *grep 慣例から推測*

```
入力: body = "line1\nline2\nmatch_line\nline4\nline5", match_pos, context=2

出力:
  1: line1
  2: line2
> 3: match_line    ← マッチ行（ハイライト）
  4: line4
  5: line5
```

---

## stats コマンドのデータフロー 🔵

**信頼性**: 🔵 *要件定義 REQ-C01〜C06*

```
User
 │
 ├── pq-diary stats [--json] [--heatmap]
 │
 ▼
cli::cmd_stats
 │
 ├── 1. get_password() → SecretString
 ├── 2. DiaryCore::new() + unlock()
 ├── 3. VaultGuard 取得
 │
 ▼
core::stats::collect_stats(engine, vault_path)
 │
 ├── 4. read_vault() → (header, records)
 │
 ├── FOR each record (record_type == ENTRY):
 │   ├── 5. engine.decrypt() → Zeroizing<Vec<u8>>
 │   ├── 6. serde_json::from_slice → EntryPlaintext
 │   ├── 7. 集計:
 │   │   ├── entry_count += 1
 │   │   ├── total_chars += body.chars().count()
 │   │   ├── max_chars = max(max_chars, body.chars().count())
 │   │   ├── daily_activity[date] += 1
 │   │   ├── tag_counts[tag] += 1 (for each tag)
 │   │   ├── first_date = min(first_date, created_at)
 │   │   └── last_date = max(last_date, created_at)
 │   └── 8. EntryPlaintext::zeroize()
 │
 ├── 9. Build VaultStats {
 │       entry_count, tag_count, first_date, last_date,
 │       active_days_30d, total_chars, avg_chars, max_chars,
 │       tag_distribution (top 10), daily_activity
 │   }
 │
 ▼
cli::cmd_stats (表示)
 │
 ├── 10a. IF --json → serde_json::to_string_pretty(stats) → stdout
 ├── 10b. IF --heatmap → render_heatmap(daily_activity, 52 weeks)
 ├── 10c. ELSE → テキストフォーマット表示
 ├── 11. VaultGuard drop → core.lock()
 │
 ▼
User sees statistics
```

### ヒートマップ表示例 🟡

**信頼性**: 🟡 *GitHub コントリビューショングラフから推測*

```
2025-04 ░░▒▓░░░░▒▒▓▓░░░░░▒░░░░░░░░░▒▒░
2025-05 ░▒▓▓▒░░░░▒▒░░░░░▒▒▒░░░░▒░░░░░░
...
Legend: ░ 0件  ▒ 1件  ▓ 2-3件  █ 4件以上
```

---

## import コマンドのデータフロー 🔵

**信頼性**: 🔵 *要件定義 REQ-D01〜D12 + 設計ヒアリング（バッチ関数方式）*

```
User
 │
 ├── pq-diary import <DIR> [--dry-run]
 │
 ▼
cli::cmd_import
 │
 ├── 1. get_password() → SecretString
 ├── 2. DiaryCore::new() + unlock()
 ├── 3. VaultGuard 取得
 │
 ▼
core::importer::import_directory(engine, vault_path, source_dir, dry_run)
 │
 ├── 4. walkdir::WalkDir::new(source_dir)
 │      .filter(|e| e.extension() == "md")
 │      .filter(|e| !path.contains(".obsidian"))
 │
 ├── FOR each .md file:
 │   ├── 5. std::fs::read_to_string() → Zeroizing<String>
 │   ├── 6. parse_markdown(content, filename):
 │   │   ├── 6a. YAML frontmatter パース → title?, tags?
 │   │   ├── 6b. title = frontmatter.title || filename_stem
 │   │   ├── 6c. convert_wiki_links(body) → [[wiki-link]] → [[タイトル]]
 │   │   ├── 6d. extract_tags(body) → Vec<String> + cleaned_body
 │   │   └── 6e. tags = frontmatter.tags + extracted_tags (重複除去)
 │   ├── 7. MarkdownFile { title, tags, body } → push to Vec<MarkdownFile>
 │   └── 8. Zeroizing<String> drop → zeroize 原文
 │
 ├── 9. IF --dry-run:
 │   │   print "Would import {n} files, convert {m} links, {k} tags"
 │   │   return Ok(ImportResult { imported: 0, ... })
 │   │
 │   ▼
 ├── 10. batch_create_entries(engine, vault_path, parsed_files):
 │   ├── 10a. read_vault() → (header, existing_records)
 │   ├── 10b. FOR each MarkdownFile:
 │   │   ├── UUID v4 生成
 │   │   ├── EntryPlaintext { title, tags, body } → JSON → encrypt → sign → HMAC
 │   │   └── EntryRecord → push to existing_records
 │   ├── 10c. write_vault(vault_path, header, all_records) ← 1回のみ
 │   └── 10d. return ImportResult { imported, skipped, links_converted, tags_converted }
 │
 ▼
cli::cmd_import (サマリー表示)
 │
 ├── 11. print "Imported: {n}, Skipped: {s}, Links: {l}, Tags: {t}"
 ├── 12. VaultGuard drop → core.lock()
 │
 ▼
User sees import summary
```

### wiki-link 変換の詳細 🔵

**信頼性**: 🔵 *ADR-0004 + 既存 link.rs の parse_links()*

```
入力: "See [[My Note]] and [[Other|alias]] for details"

変換処理:
  1. regex: \[\[([^\]|]+)(?:\|[^\]]+)?\]\]
  2. [[My Note]] → [[My Note]]  (変換不要、そのまま)
  3. [[Other|alias]] → [[Other]] (エイリアスを除去)

出力: "See [[My Note]] and [[Other]] for details"
```

### タグ抽出の詳細 🔵

**信頼性**: 🔵 *backlog.md「#ネスト/タグ 自動変換」+ 既存 Tag 型*

```
入力: "Today I worked on #work/project and #personal stuff"

抽出処理:
  1. regex: #([\w/]+) (Unicode word chars + /)
  2. matches: ["work/project", "personal"]
  3. Tag::new("work/project") → Ok(Tag)
  4. Tag::new("personal") → Ok(Tag)

出力:
  tags: ["work/project", "personal"]
  body: "Today I worked on  and  stuff" (タグ除去)
```

### frontmatter パースの詳細 🟡

**信頼性**: 🟡 *Obsidian/Hugo 慣例から推測*

```
入力:
  ---
  title: My Daily Note
  tags: [diary, personal]
  date: 2026-01-15
  ---
  Body content here.

パース処理:
  1. "---" で区切られた YAML ブロックを検出
  2. serde_yaml::from_str() でパース (serde_yaml クレート追加不要なら手動パース)
  3. title → "My Daily Note"
  4. tags → ["diary", "personal"]
  5. body → "Body content here."
```

---

## Phase A: 技術的負債修正のフロー 🔵

**信頼性**: 🔵 *S1-S5 レビュー結果*

### アトミック write フロー

```
write_vault(path, header, records)
 │
 ├── 1. temp_path = path.with_extension("pqd.tmp")
 ├── 2. File::create(temp_path) → write header + records
 ├── 3. file.sync_all()
 ├── 4. std::fs::rename(temp_path, path) ← アトミック
 │
 └── エラー時: temp_path が残るだけ。元の vault.pqd は無傷
```

### VaultGuard 適用フロー 🟡

**信頼性**: 🟡 *S5レビュー L-2 から推測*

```
既存 (lock 漏れリスク):
  core.unlock()?;
  let data = core.get_entry(&id)?;  // ← ここで ? → lock() 呼ばれない
  core.lock();

修正後 (VaultGuard):
  core.unlock()?;
  let guard = VaultGuard(&mut core);
  let data = guard.get_entry(&id)?;  // ← ここで ? → guard.drop() → lock()
  drop(guard);  // 明示的 drop (省略可、スコープ終了で自動)
```

---

## エラーハンドリングフロー 🔵

**信頼性**: 🔵 *既存 DiaryError パターン + CLAUDE.md*

### 新規エラーバリアント

```rust
pub enum DiaryError {
    // 既存...

    // S6 追加
    /// Invalid regex pattern in search.
    #[error("search error: {0}")]
    Search(String),

    /// Import processing error.
    #[error("import error: {0}")]
    Import(String),
}
```

`Search` と `Import` は既に `DiaryError` に定義済み（S1 で予約済み）。

---

## 関連文書

- **アーキテクチャ**: [architecture.md](architecture.md)
- **型定義**: [types.rs](types.rs)
- **要件定義**: [requirements.md](../../spec/search-stats-import/requirements.md)

## 信頼性レベルサマリー

- 🔵 青信号: 11件 (73%)
- 🟡 黄信号: 4件 (27%)
- 🔴 赤信号: 0件 (0%)

**品質評価**: ✅ 高品質
