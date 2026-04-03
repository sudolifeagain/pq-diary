# entry-ops-cli タスク概要

**作成日**: 2026-04-04
**推定工数**: 60時間 (15タスク × 4時間)
**総タスク数**: 15件

## 関連文書

- **要件定義書**: [requirements.md](../spec/entry-ops-cli/requirements.md)
- **設計文書**: [architecture.md](../design/entry-ops-cli/architecture.md)
- **データフロー**: [dataflow.md](../design/entry-ops-cli/dataflow.md)
- **型定義**: [types.rs](../design/entry-ops-cli/types.rs)
- **コンテキストノート**: [note.md](../spec/entry-ops-cli/note.md)

## フェーズ構成

| フェーズ | 成果物 | タスク数 | 工数 |
|---------|--------|----------|------|
| Phase 1 | Core エントリモジュール | 7 | 28h |
| Phase 2 | CLI パスワード + エディタ + コマンド | 8 | 32h |

## タスク番号管理

**使用済みタスク番号**: TASK-0001 ~ TASK-0041
**次回開始番号**: TASK-0042

## 全体進捗

- [ ] Phase 1: Core エントリモジュール
- [ ] Phase 2: CLI パスワード + エディタ + コマンド

---

## Phase 1: Core エントリモジュール

**目標**: `core/src/entry.rs` にエントリ CRUD ロジック、タグ・IDプレフィックス型を実装
**成果物**: 暗号化エントリの作成・一覧・取得・更新・削除が動作する core ライブラリ

### タスク一覧

- [ ] [TASK-0027: EntryPlaintext + Tag + IdPrefix 型定義](TASK-0027.md) - 4h (TDD) 🔵
- [ ] [TASK-0028: Tag バリデーション + 前方一致フィルタ](TASK-0028.md) - 4h (TDD) 🔵
- [ ] [TASK-0029: create_entry 実装](TASK-0029.md) - 4h (TDD) 🔵
- [ ] [TASK-0030: list_entries + EntryMeta 実装](TASK-0030.md) - 4h (TDD) 🔵
- [ ] [TASK-0031: get_entry + IdPrefix解決](TASK-0031.md) - 4h (TDD) 🔵
- [ ] [TASK-0032: update_entry + delete_entry 実装](TASK-0032.md) - 4h (TDD) 🔵
- [ ] [TASK-0033: DiaryCore ファサード拡張](TASK-0033.md) - 4h (TDD) 🔵

### 依存関係

```
TASK-0027 (型定義)
├── TASK-0028 (Tag)
├── TASK-0029 (create_entry)
│   └── TASK-0031 (get_entry)
│       └── TASK-0032 (update/delete)
│           └── TASK-0033 (DiaryCore)
└── TASK-0030 (list_entries)
    └── TASK-0031 (get_entry)
```

---

## Phase 2: CLI パスワード + エディタ + コマンド

**目標**: CLI 層のパスワード入力、$EDITOR 制御、全コマンドハンドラを実装
**成果物**: `pq-diary new/list/show/edit/delete` が完全動作する CLI バイナリ

### タスク一覧

- [ ] [TASK-0034: パスワード3段階取得](TASK-0034.md) - 4h (TDD) 🔵
- [ ] [TASK-0035: セキュア一時ディレクトリ + zeroize削除](TASK-0035.md) - 4h (TDD) 🔵
- [ ] [TASK-0036: $EDITOR起動 + ヘッダーコメントパース](TASK-0036.md) - 4h (TDD) 🔵
- [ ] [TASK-0037: clap定義更新 + new コマンド](TASK-0037.md) - 4h (TDD) 🔵
- [ ] [TASK-0038: list + show コマンド](TASK-0038.md) - 4h (TDD) 🔵
- [ ] [TASK-0039: edit コマンド](TASK-0039.md) - 4h (TDD) 🔵
- [ ] [TASK-0040: delete コマンド + 確認プロンプト](TASK-0040.md) - 4h (TDD) 🔵
- [ ] [TASK-0041: 統合テスト + doc comments](TASK-0041.md) - 4h (TDD) 🔵

### 依存関係

```
TASK-0034 (パスワード) ← TASK-0027
TASK-0035 (セキュアtmp) ← なし (並行可能)
TASK-0036 ($EDITOR) ← TASK-0027, TASK-0035

TASK-0037 (new) ← TASK-0033, TASK-0034, TASK-0036
TASK-0038 (list/show) ← TASK-0033, TASK-0034
TASK-0039 (edit) ← TASK-0033, TASK-0034, TASK-0036
TASK-0040 (delete) ← TASK-0033, TASK-0034

TASK-0041 (統合テスト) ← TASK-0037, TASK-0038, TASK-0039, TASK-0040
```

---

## クリティカルパス

```
TASK-0027 → TASK-0029 → TASK-0031 → TASK-0032 → TASK-0033 → TASK-0037 → TASK-0041
```

**クリティカルパス工数**: 28時間 (7タスク × 4h)

**並行作業可能**: TASK-0028 / TASK-0030 / TASK-0034 / TASK-0035 はクリティカルパスと並行実行可能

---

## 信頼性レベルサマリー

### 全タスク統計

- **総タスク数**: 15件
- 🔵 **青信号**: 15件 (100%)
- 🟡 **黄信号**: 0件 (0%)
- 🔴 **赤信号**: 0件 (0%)

### フェーズ別信頼性

| フェーズ | 🔵 青 | 🟡 黄 | 🔴 赤 | 合計 |
|---------|-------|-------|-------|------|
| Phase 1 | 7 | 0 | 0 | 7 |
| Phase 2 | 8 | 0 | 0 | 8 |

**品質評価**: 高品質 — 全タスクが要件定義書・設計文書に裏付けられている

## 次のステップ

タスクを実装するには:
- 全タスク順番に実装: `/tsumiki:kairo-implement`
- 特定タスクを実装: `/tsumiki:kairo-implement TASK-0027`
