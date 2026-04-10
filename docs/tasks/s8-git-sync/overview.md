# S8 Git Sync タスク概要

**作成日**: 2026-04-10
**推定工数**: 32時間
**総タスク数**: 6件

## 関連文書

- **要件定義書**: [requirements.md](../spec/s8-git-sync/requirements.md)
- **設計文書**: [architecture.md](../design/s8-git-sync/architecture.md)
- **データフロー図**: [dataflow.md](../design/s8-git-sync/dataflow.md)
- **型定義**: [types.rs](../design/s8-git-sync/types.rs)
- **コンテキストノート**: [note.md](../spec/s8-git-sync/note.md)
- **ADR-0006**: [0006-git-sync-strategy.md](../adr/0006-git-sync-strategy.md)

## フェーズ構成

| フェーズ | 成果物 | タスク数 | 工数 | ファイル |
|---------|--------|----------|------|----------|
| Phase 1 | Git基盤 + プライバシー | 2 | 9h | [TASK-0074~0075](#phase-1-git基盤--プライバシー) |
| Phase 2 | Git同期コマンド | 2 | 13h | [TASK-0076~0077](#phase-2-git同期コマンド) |
| Phase 3 | CLI統合 + テスト | 2 | 10h | [TASK-0078~0079](#phase-3-cli統合--テスト) |

## タスク番号管理

**使用済みタスク番号**: TASK-0074 ~ TASK-0079
**次回開始番号**: TASK-0080

## 全体進捗

- [ ] Phase 1: Git基盤 + プライバシー
- [ ] Phase 2: Git同期コマンド
- [ ] Phase 3: CLI統合 + テスト

## マイルストーン

- **M1: Git基盤完成**: git-init + プライバシーヘルパー動作確認
- **M2: 同期コマンド完成**: git-push/pull/merge がcore層で動作
- **M3: S8完了**: CLI統合 + 全テスト通過 + doc comments

---

## Phase 1: Git基盤 + プライバシー

**目標**: git.rsにGitOperations構造体とプライバシー強化ヘルパーを構築
**成果物**: check_git_available, git_init, プライバシー関数群

### タスク一覧

- [ ] [TASK-0074: Git基盤 — check_git_available + GitOperations + git-init](TASK-0074.md) - 5h (TDD) 🔵
- [ ] [TASK-0075: プライバシー — author匿名化 + タイムスタンプファジング](TASK-0075.md) - 4h (TDD) 🔵

### 依存関係

```
TASK-0074 → TASK-0075
```

---

## Phase 2: Git同期コマンド

**目標**: git-push（プライバシーパイプライン付き）とgit-pull（3-wayマージ）を実装
**成果物**: git_push, git_pull_merge 関数

### タスク一覧

- [ ] [TASK-0076: git-push — パディング + プライバシーパイプライン](TASK-0076.md) - 6h (TDD) 🔵
- [ ] [TASK-0077: git-pull + 3-wayマージ — UUID/HMAC照合](TASK-0077.md) - 7h (TDD) 🔵

### 依存関係

```
TASK-0075 → TASK-0076
TASK-0074 → TASK-0077
```

TASK-0076 と TASK-0077 は並行実行可能（TASK-0074完了後）。

---

## Phase 3: CLI統合 + テスト

**目標**: CLIコマンドハンドラ + 統合テスト + ドキュメント
**成果物**: 5つのcmd_git_*ハンドラ + 統合テスト

### タスク一覧

- [ ] [TASK-0078: CLI統合 — git-init/push/pull/sync/status ハンドラ](TASK-0078.md) - 5h (TDD) 🔵
- [ ] [TASK-0079: 統合テスト + doc comments + run-sprint.sh更新](TASK-0079.md) - 5h (TDD) 🔵

### 依存関係

```
TASK-0076 → TASK-0078
TASK-0077 → TASK-0078
TASK-0078 → TASK-0079
```

---

## 信頼性レベルサマリー

- **総タスク数**: 6件
- 🔵 **青信号**: 6件 (100%)
- 🟡 **黄信号**: 0件 (0%)
- 🔴 **赤信号**: 0件 (0%)

**品質評価**: 高品質

## クリティカルパス

```
TASK-0074 → TASK-0075 → TASK-0076 → TASK-0078 → TASK-0079
                       → TASK-0077 ↗
```

**クリティカルパス工数**: 25h (0074→0075→0076→0078→0079)
**並行作業可能工数**: 7h (TASK-0077)

## 次のステップ

タスクを実装するには:
- 全タスク順番に実装: `/tsumiki:kairo-implement s8-git-sync`
- 特定タスクを実装: `/tsumiki:kairo-implement s8-git-sync TASK-0074`
- 自動実行: `bash scripts/run-sprint.sh` (run-sprint.sh更新後)
