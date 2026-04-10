# S7 Access Control + Claude タスク概要

**作成日**: 2026-04-10
**推定工数**: 30時間
**総タスク数**: 7件

## 関連文書

- **要件定義書**: [requirements.md](../spec/s7-access-control-claude/requirements.md)
- **設計文書**: [architecture.md](../design/s7-access-control-claude/architecture.md)
- **データフロー図**: [dataflow.md](../design/s7-access-control-claude/dataflow.md)
- **型定義**: [types.rs](../design/s7-access-control-claude/types.rs)
- **コンテキストノート**: [note.md](../spec/s7-access-control-claude/note.md)

## フェーズ構成

| フェーズ | 成果物 | タスク数 | 工数 | ファイル |
|---------|--------|----------|------|----------|
| Phase 1 | コアポリシーエンジン | 2 | 7h | [TASK-0067~0068](#phase-1-コアポリシーエンジン) |
| Phase 2 | Vault管理CRUD | 2 | 9h | [TASK-0069~0070](#phase-2-vault管理crud) |
| Phase 3 | CLI統合 + テスト | 3 | 14h | [TASK-0071~0073](#phase-3-cli統合--テスト) |

## タスク番号管理

**使用済みタスク番号**: TASK-0067 ~ TASK-0073
**次回開始番号**: TASK-0074

## 全体進捗

- [ ] Phase 1: コアポリシーエンジン
- [ ] Phase 2: Vault管理CRUD
- [ ] Phase 3: CLI統合 + テスト

## マイルストーン

- **M1: ポリシーエンジン完成**: AccessPolicy enum + 4層チェックロジック + AccessSection移行
- **M2: Vault CRUD完成**: create/list/set_policy/delete がcore層で動作
- **M3: S7完了**: CLI統合 + 全テスト通過 + doc comments

---

## Phase 1: コアポリシーエンジン

**目標**: AccessPolicy型システムとポリシー評価ロジックをcore/に構築
**成果物**: policy.rs 新規実装、config.rs enum移行、DiaryCore アクセサ

### タスク一覧

- [ ] [TASK-0067: AccessPolicy enum + ポリシー評価ロジック](TASK-0067.md) - 4h (TDD) 🔵
- [ ] [TASK-0068: AccessSection enum化 + DiaryCore アクセサ](TASK-0068.md) - 3h (TDD) 🔵

### 依存関係

```
TASK-0067 → TASK-0068
```

---

## Phase 2: Vault管理CRUD

**目標**: VaultManager にcreate/list/set_policy/deleteメソッドを実装
**成果物**: VaultManager 拡張（init.rs）

### タスク一覧

- [ ] [TASK-0069: VaultManager create_vault + validate_vault_name](TASK-0069.md) - 4h (TDD) 🔵
- [ ] [TASK-0070: VaultManager list/set_policy/delete](TASK-0070.md) - 5h (TDD) 🔵

### 依存関係

```
TASK-0068 → TASK-0069
TASK-0068 → TASK-0070
```

TASK-0069 と TASK-0070 は並行実行可能。

---

## Phase 3: CLI統合 + テスト

**目標**: CLIコマンドハンドラ実装 + ポリシーチェック統合 + 統合テスト
**成果物**: main.rs/commands.rs 更新、統合テスト

### タスク一覧

- [ ] [TASK-0071: CLI vault サブコマンド実装](TASK-0071.md) - 5h (TDD) 🔵
- [ ] [TASK-0072: 既存コマンドへのポリシーチェック統合](TASK-0072.md) - 5h (TDD) 🔵
- [ ] [TASK-0073: 統合テスト + doc comments](TASK-0073.md) - 4h (TDD) 🔵

### 依存関係

```
TASK-0069 → TASK-0071
TASK-0070 → TASK-0071
TASK-0068 → TASK-0072
TASK-0071 → TASK-0073
TASK-0072 → TASK-0073
```

TASK-0071 と TASK-0072 は並行実行可能。

---

## 信頼性レベルサマリー

### 全タスク統計

- **総タスク数**: 7件
- 🔵 **青信号**: 7件 (100%)
- 🟡 **黄信号**: 0件 (0%)
- 🔴 **赤信号**: 0件 (0%)

**品質評価**: 高品質 — 全タスクが要件定義・設計文書・ヒアリングで確認済み

## クリティカルパス

```
TASK-0067 → TASK-0068 → TASK-0069 → TASK-0071 → TASK-0073
                       → TASK-0070 ↗        ↗
                       → TASK-0072 ──────────
```

**クリティカルパス工数**: 20h（0067→0068→0069→0071→0073）
**並行作業可能工数**: 10h（TASK-0069/0070並行 + TASK-0071/0072並行）

## 次のステップ

タスクを実装するには:
- 全タスク順番に実装: `/tsumiki:kairo-implement s7-access-control-claude`
- 特定タスクを実装: `/tsumiki:kairo-implement s7-access-control-claude TASK-0067`
