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
    └── 全パス → 回帰・変更リスク・DoDを確認してタスク完了
```

### 手動で個別実行する場合

```
/tsumiki:tdd-red {スプリント名} TASK-0001
/tsumiki:tdd-green {スプリント名} TASK-0001
/tsumiki:tdd-refactor {スプリント名} TASK-0001
/tsumiki:tdd-verify-complete {スプリント名} TASK-0001
```

### 軽量CIと変更リスクに応じた検証

通常PRと `main` pushではLinuxの短い検証を標準とする。ブランチpushとPRで
同じCIを二重実行せず、新しいコミットが来たら同じPRの古いrunを取り消す。
標準の検証コマンドは次のとおり（CIは同じjobのbuild成果物をsmokeに再利用）:

```bash
cargo fmt --all -- --check
cargo build --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --locked --all-targets -- -D warnings
bash ci/smoke-test.sh ./target/debug/pq-diary
```

`cargo test --workspace` にはintegration testとdoctestも含まれる。
別jobで同じテストを重ねない。脆弱性を確認する `cargo audit` と、
依存ポリシーを確認する `cargo deny check bans licenses sources` は役割が異なるため維持する。
監査は `cargo audit --deny unsound --deny yanked` を使い、unsound advisoryやyanked依存も失敗として扱う。
依存変更がなくても新しい脆弱性情報が出るため、監査はpath filterで省略しない。

全OS/ARM・release・Miri・性能・大量データ・長時間検証は毎PRの一律必須にしない。
必要な検証を作業環境または手動で選ぶ:

- OS API / unsafe / 対象依存を変更: 該当OSでテストする。MiriはOS FFIの実動作確認の代わりにはならない
- 保存形式 / 鍵更新 / 書込みを変更: 日記・テンプレート・添付など該当する混在データ、旧形式互換性、失敗時の原本・設定保全と再読込を確認する
- 性能や容量上限を変更: 該当するignoredテストを作業環境で選んで実行する。全ignored一括実行には環境変数・OS状態を変更するテストも含まれるため、対象と実行条件を確認する
- 全環境を確認する場合: Actions → CI → Run workflowで対象branchを選び、`full_matrix=true` にする。既存3 OSのbuild/test/Clippyと、Linux x64/ARM・macOS・Windowsのrelease smokeが追加される。新しい手動入力はworkflowがdefault branchに存在してから利用可能になる

不具合修正では修正前に失敗・修正後に成功する小さい回帰テストを優先する。
件数や網羅率だけで完了とせず、失敗時の状態や機能の組合せも確認する。
PRテンプレートに環境（OS/Rust）、コマンド、結果、実測時間、cold/warm cacheの区別、
未実施の検証と理由を書く。秒数の上限を根拠なく設けず、実測を比較して
重複jobや不要な再ビルドから減らす。GitHub Actionsのstep所要時間も測定に使える。

### Rustの判断根拠

- [Rust Book: panicとResultの使い分け](https://doc.rust-lang.org/book/ch09-03-to-panic-or-not-to-panic.html)
- [Clippy: restrictionは必要なlintを個別選択](https://doc.rust-lang.org/clippy/usage.html)
- [zeroize: Dropと複製・再割当ての注意](https://docs.rs/zeroize/latest/zeroize/)
- [Cargo: CIの検証範囲と所要時間のバランス](https://doc.rust-lang.org/cargo/guide/continuous-integration.html)
- [Cargo: test対象とdoctest](https://doc.rust-lang.org/cargo/commands/cargo-test.html)

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
| `phase1-done` | Sprint 9 完了後 (2026-04-11; S11 完了は `s11-done` で追跡) | 既存 |
| `phase2-done` | Phase 2 全機能完了後 (未着手) | 予定 |
| `v0.x.0` | 初リリース時 (バイナリ配布開始) | 未定 |

**S14 以降の運用**: スプリント単位の `s{N}-done` タグは廃止。スプリント完了の証跡は
PR マージコミット (`git log --merges`) と `CHANGELOG.md` で担保する。Phase 全完了時のみ
`phaseN-done` タグを切る。

### Environment-sensitive Rust tests

Process environment is shared by every test thread, including unrelated library
readers and subprocess launches. A mutex used only by writers is insufficient.
Do not add `set_var` / `remove_var` to a parallel parent test harness.

- Prefer exercising the CLI with `Command::env` / `env_remove`, explicit temporary
  vault paths, synthetic passwords, and noninteractive stdin. The password
  integration tests cover real environment selection and flag precedence this way.
- For unit coverage requiring process environment changes, call
  `crate::test_environment::isolated()` first and return when it returns `true`.
  The shared `test-support/environment.rs` re-executes only that exact test in a
  child. It sets temporary HOME/USERPROFILE/config directories and PQ_DIARY_HOME,
  removes inherited PQ_DIARY_PASSWORD/EDITOR, and closes stdin before execution.
  Construct fixtures only after this boundary. This uses `Command`, not raw fork.
  Dispatch mismatches fail closed instead of recursing; the parent requires one
  passing, non-ignored child test so an empty selection cannot silently pass.
- Keep normal workspace parallelism. The child's single-test harness does not
  serialize other tests. A child panic fails the parent test without leaking
  environment changes; the temporary home remains owned by the waiting parent.
  HomeOverride also refuses use outside its isolated test process.
- PATH mutation tests now run normally instead of being ignored. PATH stays
  intact while creating their fixture and is cleared only inside the child.
  Password environment removal in production remains tested in that child.
- Audit completed: the former HOME_LOCK callers (including the shared init
  rollback fixture), password unit ENV_LOCK callers, and all three missing-git
  PATH tests are isolated. The config-root tests explicitly cover unset and custom
  PQ_DIARY_HOME values in isolated children. The two integration-test-local ENV_LOCK instances were
  unrelated locks and are removed. Resolver/config readers, other git tests,
  editor environment reads, and the existing stderr subprocess test no longer
  race with these parent-process writers. Production password consumption is
  unchanged. No new test framework or broader CI matrix is required.

Optional local stress check (not added to normal CI): repeat
`cargo test -p pq-diary --bin pq-diary -- --test-threads=16` with a temporary
HOME/USERPROFILE/PQ_DIARY_HOME and a synthetic PQ_DIARY_PASSWORD supplied to the
cargo command. Preserve explicit CARGO_HOME/RUSTUP_HOME if changing HOME would
otherwise hide your toolchain. Never use actual vaults or credentials.
