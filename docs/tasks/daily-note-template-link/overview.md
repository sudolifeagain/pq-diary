# daily-note-template-link タスク概要

**作成日**: 2026-04-05
**推定工数**: 76時間
**総タスク数**: 11件

## 関連文書

- **要件定義書**: [requirements.md](../../spec/daily-note-template-link/requirements.md)
- **設計文書**: [architecture.md](../../design/daily-note-template-link/architecture.md)
- **データフロー図**: [dataflow.md](../../design/daily-note-template-link/dataflow.md)
- **型定義**: [types.rs](../../design/daily-note-template-link/types.rs)
- **コンテキストノート**: [note.md](../../spec/daily-note-template-link/note.md)

## フェーズ構成

| フェーズ | 成果物 | タスク数 | 工数 | ファイル |
|---------|--------|----------|------|----------|
| Phase 1 | Core テンプレート + リンク基盤 | 4件 | 28h | [TASK-0042~0045](#phase-1-core-テンプレート--リンク基盤) |
| Phase 2 | DiaryCore + CLIコマンド | 4件 | 28h | [TASK-0046~0049](#phase-2-diarycore--cliコマンド) |
| Phase 3 | show拡張 + vim補完 + 統合テスト | 3件 | 20h | [TASK-0050~0052](#phase-3-show拡張--vim補完--統合テスト) |

## タスク番号管理

**使用済みタスク番号**: TASK-0042 ~ TASK-0052
**次回開始番号**: TASK-0053

## 全体進捗

- [ ] Phase 1: Core テンプレート + リンク基盤
- [ ] Phase 2: DiaryCore + CLIコマンド
- [ ] Phase 3: show拡張 + vim補完 + 統合テスト

---

## Phase 1: Core テンプレート + リンク基盤

**目標**: テンプレートCRUD、変数展開エンジン、リンクパーサー、バックリンクインデックスの core 実装
**成果物**: `core/src/template.rs`, `core/src/template_engine.rs`, `core/src/link.rs`

### タスク一覧

- [ ] [TASK-0042: TemplatePlaintext型 + テンプレートCRUD](TASK-0042.md) - 8h (TDD) 🔵
- [ ] [TASK-0043: テンプレートエンジン (変数展開)](TASK-0043.md) - 6h (TDD) 🔵
- [ ] [TASK-0044: LinkParser ([[タイトル]] パーサー)](TASK-0044.md) - 6h (TDD) 🔵
- [ ] [TASK-0045: LinkIndex (バックリンクインデックス)](TASK-0045.md) - 8h (TDD) 🔵

### 依存関係

```
TASK-0042 ──┐
TASK-0043 ──┼── TASK-0046
TASK-0044 → TASK-0045 ──┘
```

**並行実行可能**: TASK-0042, TASK-0043, TASK-0044 は独立して並行実装可能

---

## Phase 2: DiaryCore + CLIコマンド

**目標**: DiaryCore ファサードの拡張と CLI コマンドの実装
**成果物**: `core/src/lib.rs` 拡張, `cli/src/commands.rs` 拡張, `cli/src/main.rs` 拡張

### タスク一覧

- [ ] [TASK-0046: DiaryCore拡張 (テンプレート+リンク+unlock/lock)](TASK-0046.md) - 8h (TDD) 🔵
- [ ] [TASK-0047: template add/list/show/delete CLIコマンド](TASK-0047.md) - 8h (TDD) 🔵
- [ ] [TASK-0048: new --template + 変数プロンプト](TASK-0048.md) - 6h (TDD) 🔵
- [ ] [TASK-0049: today コマンド](TASK-0049.md) - 6h (TDD) 🔵

### 依存関係

```
TASK-0046 → TASK-0047 → TASK-0048 → TASK-0049
TASK-0046 → TASK-0050 (Phase 3)
TASK-0046 → TASK-0051 (Phase 3)
```

---

## Phase 3: show拡張 + vim補完 + 統合テスト

**目標**: リンク解決表示、vim補完機能、全機能の統合テスト
**成果物**: `cli/src/commands.rs` 拡張, `cli/src/editor.rs` 拡張, `cli/tests/integration_test.rs` 拡張

### タスク一覧

- [ ] [TASK-0050: show 拡張 (リンク解決+バックリンク表示)](TASK-0050.md) - 6h (TDD) 🔵
- [ ] [TASK-0051: vim補完関数 (editor.rs拡張)](TASK-0051.md) - 6h (TDD) 🔵
- [ ] [TASK-0052: 統合テスト + doc comments](TASK-0052.md) - 8h (TDD) 🔵

### 依存関係

```
TASK-0050 ──┐
TASK-0051 ──┼── TASK-0052
TASK-0047 ──┤
TASK-0048 ──┤
TASK-0049 ──┘
```

**並行実行可能**: TASK-0050, TASK-0051 は独立して並行実装可能

---

## 信頼性レベルサマリー

### 全タスク統計

- **総タスク数**: 11件
- 🔵 **青信号**: 11件 (100%)
- 🟡 **黄信号**: 0件 (0%)
- 🔴 **赤信号**: 0件 (0%)

### フェーズ別信頼性

| フェーズ | 🔵 青 | 🟡 黄 | 🔴 赤 | 合計 |
|---------|-------|-------|-------|------|
| Phase 1 | 4 | 0 | 0 | 4 |
| Phase 2 | 4 | 0 | 0 | 4 |
| Phase 3 | 3 | 0 | 0 | 3 |

**品質評価**: 高品質

## クリティカルパス

```
TASK-0044 → TASK-0045 → TASK-0046 → TASK-0047 → TASK-0048 → TASK-0049 → TASK-0052
```

**クリティカルパス工数**: 50時間
**並行作業可能工数**: 26時間 (TASK-0042, TASK-0043, TASK-0050, TASK-0051)

## 次のステップ

タスクを実装するには:
- 全タスク順番に実装: `/tsumiki:kairo-implement`
- 特定タスクを実装: `/tsumiki:kairo-implement TASK-0042`
- 範囲指定で一括実装: `/tsumiki:kairo-loop daily-note-template-link TASK-0042 TASK-0052`
