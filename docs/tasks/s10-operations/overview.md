# S10 運用機能 + CLI整合性 タスク概要

**作成日**: 2026-05-17
**スプリント期間**: 2 週間 (10 営業日想定)
**推定工数**: 64 時間 (8 営業日相当)
**総タスク数**: 12 件

## 関連文書

- **要件定義書**: [📋 requirements.md](../../spec/s10-operations/requirements.md)
- **ユーザストーリー**: [📖 user-stories.md](../../spec/s10-operations/user-stories.md)
- **受け入れ基準**: [✅ acceptance-criteria.md](../../spec/s10-operations/acceptance-criteria.md) (72 テストケース)
- **設計文書**: [📐 architecture.md](../../design/s10-operations/architecture.md)
- **データフロー**: [🔄 dataflow.md](../../design/s10-operations/dataflow.md)
- **型定義**: [📝 types.rs](../../design/s10-operations/types.rs)
- **スキーマ**: [🗄️ schema.md](../../design/s10-operations/schema.md)
- **CLI 仕様**: [🔌 cli-commands.md](../../design/s10-operations/cli-commands.md)
- **コンテキスト**: [📝 note.md](../../spec/s10-operations/note.md)

## フェーズ構成

| フェーズ | 内容 | タスク数 | 工数 | ファイル |
|---------|------|----------|------|----------|
| Phase 1 | 基盤層 (依存追加 + core + security API) | 3 | 15h | TASK-0086〜0088 |
| Phase 2 | CLI コマンド実装 (init/sync/cp/info/export) | 6 | 42h | TASK-0089〜0094 |
| Phase 3 | CLI 整合性 + ドキュメント | 3 | 7h | TASK-0095〜0097 |
| **合計** | | **12** | **64h** | |

## タスク番号管理

- **使用済みタスク番号**: TASK-0086 〜 TASK-0097 (S10 範囲)
- **S10 開始番号**: TASK-0086 (S9 が TASK-0080〜0085 で終了)
- **次回開始番号**: TASK-0098

## 全体進捗

- [ ] Phase 1: 基盤層
- [ ] Phase 2: CLI コマンド実装
- [ ] Phase 3: CLI 整合性 + ドキュメント

## マイルストーン

- **M1: 基盤完了** (Day 2): dirs クレート追加、AppConfig、harden_status() 実装完了
- **M2: 読み取り系 CLI 完了** (Day 5): init / sync / info 完了
- **M3: 書き込み系 CLI 完了** (Day 8): change-password / export 完了
- **M4: 整合性確保** (Day 10): hide 化、smoke test、DoD 強化完了 → main マージ可能

---

## Phase 1: 基盤層

**目標**: AppConfig 型と harden_status API を整備し、Phase 2 で使える土台を作る
**成果物**: `~/.pq-diary/config.toml` 構造体、プロセス状態取得 API

### タスク一覧

- [ ] [TASK-0086: dirs クレート依存追加](TASK-0086.md) - 1h (DIRECT) 🔵
- [ ] [TASK-0087: AppConfig 実装](TASK-0087.md) - 6h (TDD) 🔵
- [ ] [TASK-0088: harden_status() API 追加](TASK-0088.md) - 8h (TDD) 🔵

### 依存関係

```
TASK-0086 → TASK-0087
TASK-0088 (独立)
```

---

## Phase 2: CLI コマンド実装

**目標**: 5 つの運用コマンド (init/sync/change-password/info/export) を完成させる
**成果物**: ヘルプに出るすべてのコマンドが動作する pq-diary

### タスク一覧

- [ ] [TASK-0089: init コマンド実装](TASK-0089.md) - 8h (TDD) 🔵
- [ ] [TASK-0090: sync コマンド実装](TASK-0090.md) - 4h (TDD) 🔵
- [ ] [TASK-0091: change-password 再暗号化コアロジック](TASK-0091.md) - 8h (TDD) 🔵
- [ ] [TASK-0092: change-password CLI コマンド](TASK-0092.md) - 6h (TDD) 🔵
- [ ] [TASK-0093: info / info --security 実装](TASK-0093.md) - 8h (TDD) 🔵
- [ ] [TASK-0094: export 実装 (slugify + YAML 手書き)](TASK-0094.md) - 8h (TDD) 🔵

### 依存関係

```
TASK-0087 → TASK-0089 (init は AppConfig 必須)
TASK-0087 → TASK-0090 (sync は AppConfig 必須)
TASK-0087, TASK-0088 → TASK-0093 (info --security は harden_status 必須)
TASK-0091 → TASK-0092 (change-password CLI は再暗号化コア必須)
TASK-0094 (独立)
```

### 並列実行可能タスク

- Phase 1 完了後: TASK-0089, TASK-0090, TASK-0091, TASK-0094 (4 並列可)
- TASK-0091 完了後: TASK-0092
- TASK-0087, TASK-0088 完了後: TASK-0093

---

## Phase 3: CLI 整合性 + ドキュメント

**目標**: 未実装スケルトンをヘルプから隠し、CI smoke test と DoD で品質を恒久化
**成果物**: ヘルプと実装の乖離が CI で検出される状態

### タスク一覧

- [ ] [TASK-0095: legacy/daemon hide 化 + メッセージ統一](TASK-0095.md) - 2h (DIRECT) 🔵
- [ ] [TASK-0096: CI smoke test スクリプト作成](TASK-0096.md) - 4h (DIRECT) 🔵
- [ ] [TASK-0097: DoD に CLI 整合性セクション追加](TASK-0097.md) - 1h (DIRECT) 🔵

### 依存関係

```
TASK-0089, 0090, 0092, 0093, 0094, 0095 → TASK-0096 (smoke test は全コマンド + hide 化必須)
TASK-0096 → TASK-0097 (DoD は smoke スクリプト存在前提)
```

---

## 信頼性レベルサマリー

### 全タスク統計

- **総タスク数**: 12 件
- 🔵 **青信号**: 12 件 (100%)
- 🟡 **黄信号**: 0 件
- 🔴 **赤信号**: 0 件

### フェーズ別信頼性

| フェーズ | 🔵 青 | 🟡 黄 | 🔴 赤 | 合計 |
|---------|-------|-------|-------|------|
| Phase 1 | 3 | 0 | 0 | 3 |
| Phase 2 | 6 | 0 | 0 | 6 |
| Phase 3 | 3 | 0 | 0 | 3 |

**品質評価**: 最高品質。要件定義 (🔵 100%) + 設計文書 (🔵 100%) を継承し、全タスクで出典明示。

## クリティカルパス

```
TASK-0086 (1h) → TASK-0087 (6h) → TASK-0089 (8h) → TASK-0096 (4h) → TASK-0097 (1h)
                              \→ TASK-0093 (8h) ↗
TASK-0088 (8h) ↗
TASK-0091 (8h) → TASK-0092 (6h) ↗
TASK-0094 (8h) ↗
```

**クリティカルパス工数** (逐次最長経路): 約 27h (TASK-0086 → 0087 → 0091 → 0092 → 0096 → 0097)
**並行実行で短縮可能**: Phase 1 (15h) → Phase 2 (最長 14h: 0091→0092 or 0093) → Phase 3 (5h) = **計 34h** (8 営業日が現実的)

## タスク登録状況 (--task オプション)

このスプリントは `/tsumiki:kairo-tasks s10-operations --task` で起動されたため、各タスクが Claude Code タスクシステムに登録されています (TASK-0086 〜 TASK-0097)。

依存関係も TaskUpdate の addBlockedBy で設定済み。

## 次のステップ

タスクを実装するには:
- 全タスク順番に実装: `/tsumiki:kairo-implement s10-operations`
- 特定タスクを実装: `/tsumiki:kairo-implement s10-operations TASK-0086`
- TaskList ツールで登録済み Claude Code タスクの状態を確認可能
