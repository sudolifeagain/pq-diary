# 検索 + 統計 + インポート + 技術的負債 タスク概要

**作成日**: 2026-04-09
**推定工数**: 80時間 (14タスク)
**総タスク数**: 14件

## 関連文書

- **要件定義書**: [requirements.md](../../spec/search-stats-import/requirements.md)
- **設計文書**: [architecture.md](../../design/search-stats-import/architecture.md)
- **データフロー**: [dataflow.md](../../design/search-stats-import/dataflow.md)
- **型定義**: [types.rs](../../design/search-stats-import/types.rs)
- **コンテキストノート**: [note.md](../../spec/search-stats-import/note.md)

## フェーズ構成

| フェーズ | 成果物 | タスク数 | 工数 | ファイル |
|---------|--------|----------|------|----------|
| Phase A | 技術的負債修正 | 5件 | 28h | [TASK-0053~0057](#phase-a-技術的負債修正) |
| Phase B | search コマンド | 2件 | 14h | [TASK-0058~0059](#phase-b-search-コマンド) |
| Phase C | stats コマンド | 2件 | 12h | [TASK-0060~0061](#phase-c-stats-コマンド) |
| Phase D | import + 統合 | 5件 | 26h | [TASK-0062~0066](#phase-d-import--統合) |

## タスク番号管理

**使用済みタスク番号**: TASK-0053 ~ TASK-0066
**次回開始番号**: TASK-0067

## 全体進捗

- [ ] Phase A: 技術的負債修正
- [ ] Phase B: search コマンド
- [ ] Phase C: stats コマンド
- [ ] Phase D: import + 統合

---

## Phase A: 技術的負債修正

**目標**: S1-S5 コードレビューで特定されたセキュリティ負債の解消
**成果物**: vault 堅牢化、秘密データ保護強化、VaultGuard パターン

### タスク一覧

- [ ] [TASK-0053: vault reader/writer 堅牢化](TASK-0053.md) - 8h (TDD) 🔵
- [ ] [TASK-0054: 暗号・エントリ zeroize 修正](TASK-0054.md) - 6h (TDD) 🔵
- [ ] [TASK-0055: エディタ・パスワード セキュリティ修正](TASK-0055.md) - 4h (TDD) 🔵
- [ ] [TASK-0056: VaultGuard drop guard パターン](TASK-0056.md) - 8h (TDD) 🟡
- [ ] [TASK-0057: Win32 コンソール API ADR 作成](TASK-0057.md) - 2h (DIRECT) 🟡

### 依存関係

```
TASK-0053 → TASK-0054
TASK-0053 → TASK-0055
TASK-0054 → TASK-0056
TASK-0055 → TASK-0056
TASK-0057 (独立)
```

---

## Phase B: search コマンド

**目標**: 暗号化エントリの全文正規表現検索
**成果物**: core/src/search.rs + CLI search サブコマンド

### タスク一覧

- [ ] [TASK-0058: search コア モジュール](TASK-0058.md) - 8h (TDD) 🔵
- [ ] [TASK-0059: search CLI コマンド](TASK-0059.md) - 6h (TDD) 🔵

### 依存関係

```
TASK-0056 → TASK-0058 → TASK-0059
```

---

## Phase C: stats コマンド

**目標**: 執筆統計の集計・表示（テキスト/JSON/ヒートマップ）
**成果物**: core/src/stats.rs + CLI stats サブコマンド

### タスク一覧

- [ ] [TASK-0060: stats コア モジュール](TASK-0060.md) - 6h (TDD) 🔵
- [ ] [TASK-0061: stats CLI + ヒートマップ](TASK-0061.md) - 6h (TDD) 🔵

### 依存関係

```
TASK-0056 → TASK-0060 → TASK-0061
```

---

## Phase D: import + 統合

**目標**: Obsidian/プレーン MD 一括取り込み + 全機能統合テスト
**成果物**: core/src/importer.rs + CLI import サブコマンド + 統合テスト

### タスク一覧

- [ ] [TASK-0062: import コア — Markdown パーサ](TASK-0062.md) - 8h (TDD) 🔵
- [ ] [TASK-0063: import バッチ書き込み + ディレクトリ走査](TASK-0063.md) - 6h (TDD) 🔵
- [ ] [TASK-0064: import CLI コマンド](TASK-0064.md) - 4h (TDD) 🔵
- [ ] [TASK-0065: 統合テスト + doc comments](TASK-0065.md) - 6h (TDD) 🔵
- [ ] [TASK-0066: run-sprint.sh S6 設定更新](TASK-0066.md) - 2h (DIRECT) 🔵

### 依存関係

```
TASK-0056 → TASK-0062 → TASK-0063 → TASK-0064
TASK-0059, TASK-0061, TASK-0064 → TASK-0065
TASK-0066 (独立)
```

---

## クリティカルパス

```
TASK-0053 → TASK-0054 → TASK-0056 → TASK-0062 → TASK-0063 → TASK-0064 → TASK-0065
```

**クリティカルパス工数**: 46時間
**並行作業可能**: TASK-0057, TASK-0066 (独立), Phase B/C (Phase A 完了後に並行可)

## 信頼性レベルサマリー

| フェーズ | 🔵 青 | 🟡 黄 | 🔴 赤 | 合計 |
|---------|-------|-------|-------|------|
| Phase A | 3 | 2 | 0 | 5 |
| Phase B | 2 | 0 | 0 | 2 |
| Phase C | 2 | 0 | 0 | 2 |
| Phase D | 5 | 0 | 0 | 5 |
| **合計** | **12** | **2** | **0** | **14** |

**品質評価**: ✅ 高品質 (🔵 86%, 🟡 14%)

## 次のステップ

タスクを実装するには:
- 全タスク順番に実装: `/tsumiki:kairo-implement`
- 特定タスクを実装: `/tsumiki:kairo-implement TASK-0053`
- 自動化スクリプトで実行: `bash scripts/run-sprint.sh` (TASK-0066 で設定更新後)
