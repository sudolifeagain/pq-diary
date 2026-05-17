# 開発ワークフロー

## 1. 初回セットアップ (1回だけ)

```
git init
git checkout -b main

/tsumiki:init-tech-stack
  → docs/tech-stack.md 生成
  → CLAUDE.md に Tech Stack が既にあるためスキップ可
```

## 2. スプリント開始

```bash
# ブランチ作成
git checkout -b sprint/s{N}
```

`docs/sprint-status.md` の Current を更新。

## 3. 要件定義

```
/tsumiki:kairo-requirements {スプリント名}
```

- 入力: スプリント名 (例: `s1-foundation`)、PRDとして `requirements.md` を指定可
- 出力: `docs/spec/{スプリント名}-requirements.md`
- 内容: EARS記法の要件定義、ユーザーストーリー、受け入れ基準、信頼性レベル (青/黄/赤)

## 4. 設計

```
/tsumiki:kairo-design {スプリント名}
```

- 入力: 要件定義書を自動参照
- 出力: `docs/design/{スプリント名}/`
  - `architecture.md` — アーキテクチャ設計
  - `dataflow.md` — データフロー (Mermaid)
  - その他 (API仕様、スキーマ等、該当するもの)

## 5. タスク分割

```
/tsumiki:kairo-tasks {スプリント名} --task
```

- 入力: 設計文書を自動参照
- 出力:
  - `docs/tasks/{スプリント名}/overview.md` — タスク一覧・依存関係
  - `docs/tasks/{スプリント名}/TASK-XXXX.md` — 個別タスク (TDD/DIRECT判定付き)
- `--task` で Claude Code のタスクシステムにも登録

## 6. 実装 (TDDサイクル)

### 一括実行 (推奨)

```
/tsumiki:kairo-implement {スプリント名}
```

TASK-ID省略時は、blockedByが空かつpendingの最初のタスクを自動選択。
1タスク完了後に次のタスクへ進むには再度実行、または `kairo-loop` で範囲指定:

```
/tsumiki:kairo-loop {スプリント名} TASK-0001 TASK-XXXX
```

### kairo-implement 内部で自動実行されるTDDサイクル

```
tdd-tasknote       コンテキスト収集 → docs/implements/{名前}/{task_id}/note.md
    ↓
tdd-requirements   TDD用要件整理 → {feature}-requirements.md
    ↓
tdd-testcases      テストケース洗い出し → {feature}-testcases.md
    ↓
tdd-red            失敗するテスト作成 → テストファイル + {feature}-red-phase.md
    ↓
tdd-green          テストを通す最小実装 → 実装ファイル + {feature}-green-phase.md
    ↓
tdd-refactor       品質改善 → {feature}-refactor-phase.md
    ↓
tdd-verify-complete  全テスト実行・網羅率チェック
    ├── テストケース不足 → tdd-red に戻る
    ├── 実装不足 → tdd-green に戻る
    └── 全パス → タスク完了
```

### 手動で個別実行する場合

```
/tsumiki:tdd-red {スプリント名} TASK-0001
/tsumiki:tdd-green {スプリント名} TASK-0001
/tsumiki:tdd-refactor {スプリント名} TASK-0001
/tsumiki:tdd-verify-complete {スプリント名} TASK-0001
```

## 7. スプリント完了

```
1. docs/definition-of-done.md のチェックリストを確認
2. docs/sprint-status.md を更新 (Status → completed)
3. docs/backlog.md の該当アイテムにチェック
4. CHANGELOG.md の [Unreleased] セクションを更新

# マージ (S14 以降、スプリント単位のタグは打たない)
git checkout main
git merge --no-ff sprint/s{N} -m "Sprint {N}: {テーマ}"

# Phase 完了時のみタグを打つ
# 例: git tag phase2-done
```

スプリント完了の証跡は **PR マージコミット** が担う (`git log --merges`)。
過去の `s1-done` 〜 `s13-done` + `phase1-done` タグは残し、CHANGELOG.md の
History 表で参照する。

## 8. 生成ファイルマップ

```
docs/
├── tech-stack.md                           # init-tech-stack (1回)
├── spec/
│   └── {スプリント名}-requirements.md       # kairo-requirements
├── design/
│   └── {スプリント名}/
│       ├── architecture.md                 # kairo-design
│       └── dataflow.md
├── tasks/
│   └── {スプリント名}/
│       ├── overview.md                     # kairo-tasks
│       └── TASK-XXXX.md
└── implements/
    └── {スプリント名}/
        └── {task_id}/
            ├── note.md                     # tdd-tasknote
            ├── {feature}-requirements.md   # tdd-requirements
            ├── {feature}-testcases.md      # tdd-testcases
            ├── {feature}-red-phase.md      # tdd-red
            ├── {feature}-green-phase.md    # tdd-green
            ├── {feature}-refactor-phase.md # tdd-refactor
            └── {feature}-memo.md           # tdd-verify-complete
```

---

## ブランチ戦略

### ブランチ構成

```
main                    常に安定・DoD通過済み
├── sprint/s1           Sprint 1 作業ブランチ
├── sprint/s2           Sprint 2 作業ブランチ
│   ...
└── sprint/s9           Sprint 9 作業ブランチ
```

### ルール

- `main` への直接コミット禁止
- 各スプリントは `sprint/s{N}` ブランチで作業
- スプリント完了後 `main` へ `--no-ff` マージ (PR 経由)
- スプリント内のコミットは機能単位で細かく (1タスク1コミット目安)
- マージ前に DoD チェックリスト通過必須

### コミットメッセージ規約

```
{type}(s{N}): {概要}

type:
  feat     新機能
  fix      バグ修正
  refactor リファクタ
  test     テスト追加・修正
  docs     ドキュメント
  chore    ビルド・CI・依存関係
```

例: `feat(s1): add SecureBuffer with zeroize-on-drop`

### タグ

| タグ | タイミング | 状態 |
|------|-----------|------|
| `s1-done` 〜 `s13-done` | スプリント N 完了・main マージ後 | 既存 (S14 以降は打たない) |
| `phase1-done` | Sprint 11 完了後 (クロスプラットフォーム検証含む) | 既存 |
| `phase2-done` | Phase 2 全機能完了後 (未着手) | 予定 |
| `v0.x.0` | 初リリース時 (バイナリ配布開始) | 未定 |

**S14 以降の運用**: スプリント単位の `s{N}-done` タグは廃止。スプリント完了の証跡は
PR マージコミット (`git log --merges`) と `CHANGELOG.md` で担保する。Phase 全完了時のみ
`phaseN-done` タグを切る。
