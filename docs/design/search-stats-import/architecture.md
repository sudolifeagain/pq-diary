# 検索 + 統計 + インポート アーキテクチャ設計

**作成日**: 2026-04-09
**関連要件定義**: [requirements.md](../../spec/search-stats-import/requirements.md)
**ヒアリング記録**: [design-interview.md](design-interview.md)

**【信頼性レベル凡例】**:
- 🔵 **青信号**: EARS要件定義書・設計文書・ユーザヒアリングを参考にした確実な設計
- 🟡 **黄信号**: EARS要件定義書・設計文書・ユーザヒアリングから妥当な推測による設計
- 🔴 **赤信号**: EARS要件定義書・設計文書・ユーザヒアリングにない推測による設計

---

## システム概要 🔵

**信頼性**: 🔵 *requirements.md + backlog.md S6*

Sprint 6 は4つの Phase で構成される:
- **Phase A**: 技術的負債修正 (13件) — vault reader/writer 堅牢化、秘密データ保護強化、CLI アーキテクチャ改善
- **Phase B**: search コマンド — ストリーミング復号 + インメモリ正規表現検索
- **Phase C**: stats コマンド — 全エントリ統計集計 (テキスト/JSON/ヒートマップ)
- **Phase D**: import コマンド — Obsidian/プレーン MD 一括暗号化取り込み

## アーキテクチャパターン 🔵

**信頼性**: 🔵 *CLAUDE.md・既存設計より*

既存の Facade パターン (`DiaryCore`) を維持し、新機能は以下の方針で追加:
- **core/**: `search`, `stats`, `importer` モジュールを新設。プラットフォーム非依存
- **cli/**: `cmd_search`, `cmd_stats`, `cmd_import` コマンドハンドラを追加
- **依存追加**: `regex` クレート (search)、`walkdir` クレート (import のディレクトリ走査)

## コンポーネント構成

### Phase A: 技術的負債 🔵

**信頼性**: 🔵 *S1-S5 全スプリントレビュー結果*

| 対象ファイル | 修正内容 | 要件 |
|-------------|---------|------|
| `core/src/vault/reader.rs` | フィールドサイズ上限 (16 MiB) チェック追加 | REQ-A01/A02 |
| `core/src/vault/writer.rs` | `as u32`/`as u8` → `try_from` + アトミック write | REQ-A04/A05 |
| `core/src/vault/init.rs` | 空パスワードガード | REQ-A03 |
| `cli/src/editor.rs` | vim `nowritebackup`/`viminfo=''` 追加、tmpfile 0o600 | REQ-A06/A08 |
| `cli/src/password.rs` | `env::remove_var("PQ_DIARY_PASSWORD")` | REQ-A07 |
| `core/src/crypto/hmac_util.rs` | `compute()` → `Result<[u8; 32], DiaryError>` | REQ-A09 |
| `core/src/entry.rs` | `EntryPlaintext` に `Zeroize`/`ZeroizeOnDrop` derive | REQ-A10 |
| `core/src/lib.rs` | `list_entries_with_body` 中間値を `Zeroizing` でラップ | REQ-A11 |
| `docs/adr/` | Win32 コンソール API unsafe ADR | REQ-A12 |
| `cli/src/commands.rs` | `VaultGuard` drop guard パターン抽出 | REQ-A13 |

### Phase B: search モジュール 🔵

**信頼性**: 🔵 *要件定義 REQ-B01〜B09 + ユーザヒアリング*

```
core/src/search.rs (新規)
├── SearchQuery     — 正規表現パターン + オプション
├── SearchMatch     — マッチ結果 (エントリ情報 + マッチ行 + コンテキスト)
├── search_entries() — ストリーミング復号 + 検索 (1エントリずつ復号→検索→zeroize)
└── format_context() — マッチ行 + 前後N行のコンテキスト抽出
```

**設計決定**: ストリーミング方式 🔵 *ユーザヒアリング 2026-04-09*
- 1エントリずつ復号 → regex マッチ → zeroize → 次のエントリ
- メモリ使用量: O(1エントリ) — 大量エントリでもメモリ安全
- 復号回数は一括方式と同じ O(n)

### Phase C: stats モジュール 🔵

**信頼性**: 🔵 *要件定義 REQ-C01〜C06 + ユーザヒアリング*

```
core/src/stats.rs (新規)
├── VaultStats      — 統計データ構造体 (Serialize 対応)
├── DailyActivity   — 日別活動データ
├── TagDistribution — タグ分布データ
├── collect_stats() — 全エントリ走査して統計集計
└── render_heatmap() — ASCII ヒートマップ生成
```

**設計決定**: stats はストリーミングではなく全エントリ走査 🟡 *文字数集計に本文復号が必要*
- `list_entries_with_body()` で全エントリを復号して統計集計
- 集計完了後に中間データを zeroize

### Phase D: importer モジュール 🔵

**信頼性**: 🔵 *要件定義 REQ-D01〜D12 + ユーザヒアリング*

```
core/src/importer.rs (新規)
├── ImportSource    — ディレクトリパス + オプション
├── ImportResult    — 取り込み結果サマリー
├── MarkdownFile    — パース済み MD ファイル (title, tags, body, links)
├── parse_markdown() — frontmatter パース + wiki-link/タグ変換
├── convert_wiki_links() — [[wiki-link]] → [[タイトル]] 変換
├── extract_tags()  — #ネスト/タグ 抽出 + 本文からの除去
├── import_directory() — ディレクトリ走査 + バッチ暗号化 + 書き込み
└── batch_create_entries() — 複数エントリ一括暗号化・vault 追記
```

**設計決定**: 専用バッチ関数 `batch_create_entries()` 🔵 *ユーザヒアリング 2026-04-09*
- `read_vault()` → 全エントリを暗号化してレコード追加 → `write_vault()` を1回のみ呼び出し
- O(n) の暗号化 + O(1) の vault 書き込み

## ディレクトリ構造 (S6 変更分) 🔵

**信頼性**: 🔵 *既存プロジェクト構造 + 要件定義*

```
core/src/
├── search.rs          (新規) — 正規表現検索エンジン
├── stats.rs           (新規) — 統計集計
├── importer.rs        (新規) — MD インポーター
├── entry.rs           (変更) — EntryPlaintext に Zeroize derive
├── lib.rs             (変更) — DiaryCore に search/stats/import メソッド追加
├── crypto/
│   └── hmac_util.rs   (変更) — compute() の戻り値型変更
└── vault/
    ├── reader.rs       (変更) — サイズ上限チェック追加
    ├── writer.rs       (変更) — try_from + アトミック write
    └── init.rs         (変更) — 空パスワードガード

cli/src/
├── commands.rs        (変更) — cmd_search/cmd_stats/cmd_import 追加 + VaultGuard
├── editor.rs          (変更) — vim オプション追加 + tmpfile パーミッション
├── password.rs        (変更) — env::remove_var 追加
└── main.rs            (変更) — search/stats/import サブコマンド定義

core/Cargo.toml        (変更) — regex, walkdir 追加
docs/adr/0007-win32-console-unsafe.md (新規)
```

## 非機能要件の実現方法

### パフォーマンス 🟡

**信頼性**: 🟡 *NFR-001〜003 から推測*

- **search**: ストリーミング方式で O(n) 復号。regex クレートの NFA ベースマッチで高速
- **stats**: 全エントリ走査は O(n) だが、メタデータのみで済む統計（エントリ数、日付範囲）は復号不要で O(1) にできる。文字数は本文復号が必要
- **import**: バッチ書き込みで vault I/O は O(1)。暗号化は O(n) だが並列化は不要（逐次処理で十分）

### セキュリティ 🔵

**信頼性**: 🔵 *requirements.md 設計原則 + NFR-101/102*

- **search**: ストリーミング復号で1エントリ分のみメモリ上に保持。マッチ結果の表示後に zeroize
- **stats**: 集計用の中間データは `Zeroizing` でラップ。JSON 出力後に zeroize
- **import**: 読み込んだ MD ファイル内容を `Zeroizing<String>` で保持。暗号化完了後に zeroize。元ファイルは読み取り専用（削除しない）

### VaultGuard パターン 🟡

**信頼性**: 🟡 *S5レビュー L-2 から推測した設計*

```rust
/// RAII guard that calls `core.lock()` on drop.
struct VaultGuard<'a>(&'a mut DiaryCore);

impl Drop for VaultGuard<'_> {
    fn drop(&mut self) {
        self.0.lock();
    }
}
```

全コマンドハンドラを以下のパターンに統一:
```rust
fn cmd_xxx(cli: &Cli, ...) -> anyhow::Result<()> {
    let mut core = DiaryCore::new(vault_str)?;
    core.unlock(password)?;
    let guard = VaultGuard(&mut core);
    // ... ここで ? を自由に使える。guard の Drop で lock() が保証される
    drop(guard);
    Ok(())
}
```

## 依存クレート追加 🔵

**信頼性**: 🔵 *要件定義 + Rust エコシステム標準*

| クレート | バージョン | 用途 | 追加先 |
|---------|-----------|------|--------|
| `regex` | `1.x` | 正規表現検索 (search) | `core/Cargo.toml` |
| `walkdir` | `2.x` | ディレクトリ再帰走査 (import) | `core/Cargo.toml` |
| `serde_json` | 既存 | stats JSON 出力 | 追加不要 |

## 技術的制約 🔵

**信頼性**: 🔵 *CLAUDE.md・requirements.md*

- core/ にプラットフォーム依存コードを入れない
- `unsafe` は既存の許可リスト (mlock/VirtualLock/PR_SET_DUMPABLE/Win32 Console) のみ
- 秘密データは `zeroize` / `SecretString` / `SecretBytes` で保持
- エラーは `thiserror` (core/) / `anyhow` (cli/)

## 関連文書

- **データフロー**: [dataflow.md](dataflow.md)
- **型定義**: [types.rs](types.rs)
- **要件定義**: [requirements.md](../../spec/search-stats-import/requirements.md)
- **受け入れ基準**: [acceptance-criteria.md](../../spec/search-stats-import/acceptance-criteria.md)

## 信頼性レベルサマリー

- 🔵 青信号: 15件 (79%)
- 🟡 黄信号: 4件 (21%)
- 🔴 赤信号: 0件 (0%)

**品質評価**: ✅ 高品質
