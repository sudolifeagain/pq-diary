# S8 Git Sync アーキテクチャ設計

**作成日**: 2026-04-10
**関連要件定義**: [requirements.md](../../spec/s8-git-sync/requirements.md)
**ヒアリング記録**: [design-interview.md](design-interview.md)

**【信頼性レベル凡例】**:
- 🔵 **青信号**: EARS要件定義書・設計文書・ユーザヒアリングを参考にした確実な設計

---

## システム概要 🔵

**信頼性**: 🔵 *要件定義書概要 + ADR-0006 + ヒアリング確認済*

S8では以下の3層構成でGit同期機能を実装する:

1. **core/src/git.rs**（コアロジック層）: Git操作・マージアルゴリズム・プライバシーパイプライン
2. **cli/src/commands.rs**（CLIハンドラ層）: 5つの新規コマンドハンドラ（git-init/push/pull/sync/status）
3. **git CLI**（外部プロセス層）: `std::process::Command` 経由でシステムの `git` を呼び出し（ADR-0006）

## アーキテクチャパターン 🔵

**信頼性**: 🔵 *既存アーキテクチャ + CLAUDE.md規約 + ADR-0006*

- **パターン**: 既存のファサード + RAII Guard パターンを維持
- **外部プロセス呼び出し**: `std::process::Command` でgit CLIを実行（git2クレート不使用）
- **プライバシーパイプライン**: anonymize author → fixed message → extra padding → fuzz timestamp → git add/commit/push
- **マージ戦略**: エントリ単位UUID照合 + content_hmac変更検出 + last-write-wins（updated_at比較）
- **アトミック書き込み**: 既存の write_vault() パターンを使用（.tmp → sync_all() → rename）

## コンポーネント構成

### core/src/git.rs — Git操作モジュール 🔵

**信頼性**: 🔵 *REQ-001〜054, ADR-0006 + ヒアリング確認済*

`core/src/git.rs` のスタブを完全実装。以下の型と関数を提供:

```rust
// --- 型定義 ---

/// Git操作を束ねる構造体
pub struct GitOperations {
    vault_dir: PathBuf,
    config: VaultConfig,
}

/// マージ結果
pub struct MergeResult {
    /// リモートから追加されたエントリ数
    pub added: usize,
    /// updated_at比較で更新されたエントリ数
    pub updated: usize,
    /// リモートで削除されたエントリ数
    pub deleted: usize,
    /// 両側変更によるコンフリクト一覧
    pub conflicts: Vec<MergeConflict>,
}

/// マージコンフリクト情報
pub struct MergeConflict {
    /// エントリのUUID
    pub uuid: [u8; 16],
    /// ローカル側のEntryRecord
    pub local: EntryRecord,
    /// リモート側のEntryRecord
    pub remote: EntryRecord,
}

/// コンフリクト解決方針
pub enum ConflictResolution {
    /// ローカル側を保持（--claude時のデフォルト）
    KeepLocal,
    /// リモート側を採用
    KeepRemote,
    /// ユーザー選択（対話式プロンプト）
    UserChoice,
}

// --- 公開関数 ---

/// gitコマンドの利用可能性チェック (`git --version`)
pub fn check_git_available() -> Result<(), DiaryError>;

/// Vaultディレクトリ内でgit initを実行
pub fn git_init(
    vault_dir: &Path,
    remote: Option<&str>,
) -> Result<(), DiaryError>;

/// プライバシーパイプライン付きgit push
pub fn git_push(
    vault_dir: &Path,
    config: &VaultConfig,
    engine: &CryptoEngine,
    vault_path: &Path,
) -> Result<(), DiaryError>;

/// git fetch + エントリ単位マージ
pub fn git_pull_merge(
    vault_dir: &Path,
    config: &VaultConfig,
    engine: &CryptoEngine,
    vault_path: &Path,
) -> Result<(Vec<EntryRecord>, Vec<MergeConflict>), DiaryError>;

/// git statusのラップ表示
pub fn git_status(vault_dir: &Path) -> Result<String, DiaryError>;

// --- プライベートヘルパー ---

/// vault.toml のauthor情報からgit authorフォーマット文字列を生成
fn make_author(config: &VaultConfig) -> String;

/// 前回コミット時刻より単調増加するファジングされたタイムスタンプを生成
fn fuzz_timestamp(prev: DateTime<Utc>, fuzz_hours: u64) -> DateTime<Utc>;

/// vault.pqd に追加パディングを付与（write_vault()を再実行）
fn generate_extra_padding(max_bytes: usize) -> Vec<u8>;

/// .gitignore の内容を生成
fn generate_gitignore() -> String;

/// 8桁hex + @localhost 形式のランダムメールアドレスを生成
fn generate_random_author_email() -> String;
```

### cli/src/commands.rs — コマンドハンドラ追加 🔵

**信頼性**: 🔵 *REQ-402 + 既存コマンドパターン準拠*

5つの新規コマンドハンドラを追加:

```rust
/// git-init: Vaultディレクトリにgitリポジトリを初期化
pub fn cmd_git_init(cli: &Cli, remote: Option<&str>) -> Result<()>;

/// git-push: プライバシーパイプライン付きpush
pub fn cmd_git_push(cli: &Cli) -> Result<()>;

/// git-pull: fetch + エントリ単位マージ + コンフリクト解決
pub fn cmd_git_pull(cli: &Cli) -> Result<()>;

/// git-sync: pull → push の順序実行
pub fn cmd_git_sync(cli: &Cli) -> Result<()>;

/// git-status: git statusのラップ表示
pub fn cmd_git_status(cli: &Cli) -> Result<()>;
```

**cmd_git_init** フロー:
1. `check_git_available()` でgitインストール確認
2. `.git` ディレクトリ存在チェック（既存ならエラー: EDGE-006）
3. `git_init(vault_dir, remote)` を呼び出し
4. author_email を生成し vault.toml に保存（REQ-003, REQ-004）
5. 成功メッセージ表示

**cmd_git_push** フロー:
1. `check_git_available()`
2. `.git` 存在確認（EDGE-003）
3. パスワード入力（`get_password()`）— パディング再書き込みのため（REQ-016）
4. DiaryCore::unlock()
5. `git_push(vault_dir, config, engine, vault_path)` 実行
6. 成功メッセージ表示

**cmd_git_pull** フロー:
1. `check_git_available()`
2. `.git` 存在確認（EDGE-003）
3. パスワード入力（REQ-022）
4. DiaryCore::unlock()
5. `git_pull_merge(vault_dir, config, engine, vault_path)` 実行
6. コンフリクトがある場合:
   - `--claude`: ローカル優先で自動解決（REQ-026）
   - 通常: 対話式プロンプト（REQ-025）
7. 結果表示（added/updated/deleted件数）

**cmd_git_sync** フロー:
1. `cmd_git_pull(cli)` 実行
2. `cmd_git_push(cli)` 実行

**cmd_git_status** フロー:
1. `check_git_available()`
2. `.git` 存在確認（EDGE-003）
3. `git_status(vault_dir)` 実行
4. 結果表示

### cli/src/main.rs — clap定義変更 🔵

**信頼性**: 🔵 *既存Commands enum + REQ-001〜040*

既存の引数なしスタブを更新し、適切な引数を追加:

```rust
// Before (現行)
/// Initialize a git repository for the vault
GitInit,

/// Push vault to the remote git repository
GitPush,

/// Pull vault from the remote git repository
GitPull,

/// Sync vault with remote (pull then push)
GitSync,

/// Show git sync status
GitStatus,

// After (S8)
/// Initialize a git repository for the vault
GitInit {
    /// Remote repository URL (optional, added as 'origin')
    #[arg(long)]
    remote: Option<String>,
},

/// Push vault to the remote git repository
GitPush,

/// Pull vault from the remote git repository
GitPull,

/// Sync vault with remote (pull then push)
GitSync,

/// Show git sync status
GitStatus,
```

ディスパッチ部の更新:

```rust
// Before
Commands::GitInit => not_implemented("git-init", "Sprint 8"),
Commands::GitPush => not_implemented("git-push", "Sprint 8"),
Commands::GitPull => not_implemented("git-pull", "Sprint 8"),
Commands::GitSync => not_implemented("git-sync", "Sprint 8"),
Commands::GitStatus => not_implemented("git-status", "Sprint 8"),

// After
Commands::GitInit { remote } => cmd_git_init(&cli, remote.as_deref()),
Commands::GitPush => cmd_git_push(&cli),
Commands::GitPull => cmd_git_pull(&cli),
Commands::GitSync => cmd_git_sync(&cli),
Commands::GitStatus => cmd_git_status(&cli),
```

## マージアルゴリズム 🔵

**信頼性**: 🔵 *REQ-020〜028 + ヒアリング「last-write-wins by updated_at」確認済*

### アルゴリズム手順

1. **ローカルvault.pqd読み取り**: `read_vault(vault_path)` → ローカルEntryRecord一覧
2. **バックアップ作成**: `vault.pqd` → `vault.pqd.bak` にコピー
3. **リモート取得**: `git fetch` + `git checkout FETCH_HEAD -- vault.pqd` でリモート版を取得
4. **リモートvault.pqd読み取り**: `read_vault(vault_path)` → リモートEntryRecord一覧
5. **ローカル復元**: `vault.pqd.bak` → `vault.pqd` にリネーム（ローカル版を復元）
6. **UUID照合**: ローカル・リモートのEntryRecordをUUIDでマッチング
7. **変更検出**: 同一UUIDのエントリについて content_hmac を比較
   - **同一**: 変更なし → ローカル版を保持
   - **異なる**: コンフリクト → 解決ロジックへ
8. **新規エントリ**: リモートにのみ存在するUUID → ローカルに追加
9. **ローカルのみ**: ローカルにのみ存在するUUID → そのまま保持
10. **コンフリクト解決**:
    - `--claude` 時: ローカル側を自動採用（REQ-026）
    - 通常時: updated_at 比較で新しい方を推奨 + 対話式プロンプト（REQ-025）
11. **アトミック書き込み**: マージ結果を `write_vault()` で vault.pqd に書き込み（REQ-028）

### UUID → content_hmac マッチング詳細

```
ローカル: {UUID_A: hmac_1, UUID_B: hmac_2, UUID_C: hmac_3}
リモート: {UUID_A: hmac_1, UUID_B: hmac_4, UUID_D: hmac_5}

結果:
  UUID_A: hmac同一 → スキップ（変更なし）
  UUID_B: hmac異なる → コンフリクト（updated_at比較 / 対話式）
  UUID_C: ローカルのみ → 保持
  UUID_D: リモートのみ → 追加
```

## プライバシーパイプライン 🔵

**信頼性**: 🔵 *REQ-010〜017, REQ-050〜054, ADR-0006*

git-push実行時のプライバシー保護パイプライン:

1. **Author匿名化**: vault.toml の `[git].author_name` + `[git].author_email` を使用
   - フォーマット: `pq-diary <{8桁hex}@localhost>`
   - `git commit --author` オプションで指定
2. **メッセージ定型化**: vault.toml の `[git].commit_message` を使用（デフォルト: `"Update vault"`）
   - `git commit -m` オプションで指定
3. **追加パディング**: vault.pqd を write_vault() で再書き込み
   - `extra_padding_bytes_max > 0` の場合: 0 〜 max のランダムバイト数を追加
   - `extra_padding_bytes_max == 0` の場合: パディング無効（REQ-054）
   - **重要**: バイナリ末尾追記ではなく、write_vault() 再実行（ヒアリングQ1確認済）
4. **タイムスタンプファジング**: GIT_AUTHOR_DATE / GIT_COMMITTER_DATE 環境変数を設定
   - `timestamp_fuzz_hours > 0` の場合: ランダム範囲内でファジング
   - 単調増加保証: ファジング後の時刻 > 前回コミットのファジング後の時刻（REQ-015）
   - `timestamp_fuzz_hours == 0` の場合: ファジング無効
5. **git add/commit/push**: `std::process::Command` で順次実行

### Extra Padding実装詳細 🔵

**信頼性**: 🔵 *ヒアリングQ1「write_vault()再実行」確認済*

```
パディング適用フロー:
1. read_vault(vault_path) → (header, records)
2. generate_extra_padding(max_bytes) → random_padding: Vec<u8>
3. records にパディングレコードを追加（またはheaderのpadding領域を更新）
4. write_vault(vault_path, header, &records) → vault.pqd 再書き込み
```

### タイムスタンプファジング実装詳細 🔵

**信頼性**: 🔵 *REQ-014, REQ-015, ADR-0006*

```
単調増加保証フロー:
1. git log -1 --format=%aI で前回コミットの GIT_AUTHOR_DATE を取得
2. prev_time = 前回コミット時刻（初回コミット時は epoch）
3. fuzz_offset = OsRng::gen_range(0..timestamp_fuzz_hours * 3600) 秒
4. fuzzed_time = max(Utc::now() - fuzz_offset, prev_time + 1秒)
5. GIT_AUTHOR_DATE = GIT_COMMITTER_DATE = fuzzed_time.to_rfc3339()
```

## システム構成図 🔵

**信頼性**: 🔵 *既存アーキテクチャ + S8設計*

```
┌──────────────────────────────────────────────────────┐
│                  cli/src/main.rs                      │
│  ┌────────────────────────────────────────────────┐   │
│  │ Cli { --claude, --vault, --password }          │   │
│  │ Commands::GitInit { remote }                   │   │
│  │ Commands::GitPush / GitPull / GitSync / GitSts │   │
│  └───────────────────┬────────────────────────────┘   │
│                      │                                │
│  ┌───────────────────▼────────────────────────────┐   │
│  │ cli/src/commands.rs                            │   │
│  │  cmd_git_init(cli, remote)                     │   │
│  │  cmd_git_push(cli)                             │   │
│  │  cmd_git_pull(cli)   ← コンフリクト対話式解決  │   │
│  │  cmd_git_sync(cli)   ← pull → push            │   │
│  │  cmd_git_status(cli)                           │   │
│  └───────────────────┬────────────────────────────┘   │
└──────────────────────┼────────────────────────────────┘
                       │
┌──────────────────────▼────────────────────────────────┐
│                core/src/                               │
│  ┌────────────────────────────────────────────────┐   │
│  │ git.rs                                         │   │
│  │  GitOperations { vault_dir, config }           │   │
│  │  MergeResult { added, updated, deleted, ... }  │   │
│  │  MergeConflict { uuid, local, remote }         │   │
│  │  check_git_available()                         │   │
│  │  git_init(vault_dir, remote)                   │   │
│  │  git_push(vault_dir, config, engine, path)     │   │
│  │  git_pull_merge(vault_dir, config, engine, ..) │   │
│  │  git_status(vault_dir)                         │   │
│  │  make_author() / fuzz_timestamp()              │   │
│  │  generate_extra_padding()                      │   │
│  │  generate_gitignore()                          │   │
│  │  generate_random_author_email()                │   │
│  └────────────────────────────────────────────────┘   │
│  ┌────────────────────────────────────────────────┐   │
│  │ vault/config.rs (既存)                         │   │
│  │  GitSection { author_name, author_email,       │   │
│  │    commit_message, privacy: GitPrivacySection } │   │
│  │  GitPrivacySection { timestamp_fuzz_hours,     │   │
│  │    extra_padding_bytes_max }                    │   │
│  └────────────────────────────────────────────────┘   │
│  ┌────────────────────────────────────────────────┐   │
│  │ vault/reader.rs + writer.rs (既存)             │   │
│  │  read_vault() → (VaultHeader, Vec<EntryRecord>)│   │
│  │  write_vault() — アトミック書き込み             │   │
│  └────────────────────────────────────────────────┘   │
│  ┌────────────────────────────────────────────────┐   │
│  │ error.rs (既存)                                │   │
│  │  DiaryError::Git(String) — 既定義              │   │
│  └────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────┘
                       │
         ┌─────────────▼──────────────┐
         │   ~/.pq-diary/vaults/      │
         │   └── default/             │
         │       ├── .git/            │  ← git-init で生成
         │       ├── .gitignore       │  ← entries/*.md 除外
         │       ├── vault.pqd        │  ← git管理対象
         │       ├── vault.toml       │  ← git管理対象
         │       │  [git]             │
         │       │  author_name =     │
         │       │    "pq-diary"      │
         │       │  author_email =    │
         │       │    "a1b2c3d4@..."  │
         │       │  commit_message =  │
         │       │    "Update vault"  │
         │       │  [git.privacy]     │
         │       │  timestamp_fuzz_h  │
         │       │    ours = 6        │
         │       │  extra_padding_by  │
         │       │    tes_max = 4096  │
         │       └── entries/         │  ← .gitignore で除外
         └────────────────────────────┘
                       │
         ┌─────────────▼──────────────┐
         │   git CLI (外部プロセス)    │
         │   std::process::Command    │
         │   ├── git init             │
         │   ├── git remote add       │
         │   ├── git add              │
         │   ├── git commit --author  │
         │   │   GIT_AUTHOR_DATE env  │
         │   │   GIT_COMMITTER_DATE   │
         │   ├── git push             │
         │   ├── git fetch            │
         │   ├── git checkout         │
         │   │   FETCH_HEAD -- file   │
         │   ├── git status           │
         │   └── git log              │
         └────────────────────────────┘
```

## 変更対象ファイル一覧 🔵

**信頼性**: 🔵 *設計分析*

| ファイル | 変更種別 | 内容 |
|---------|----------|------|
| `core/src/git.rs` | **完全実装** | GitOperations, MergeResult, MergeConflict, check_git_available(), git_init(), git_push(), git_pull_merge(), git_status(), プライバシーヘルパー群 |
| `cli/src/main.rs` | **変更** | Commands::GitInit に remote 引数追加、ディスパッチ部の not_implemented() 呼び出しを実コマンドハンドラに置換 |
| `cli/src/commands.rs` | **拡張** | cmd_git_init(), cmd_git_push(), cmd_git_pull(), cmd_git_sync(), cmd_git_status() の5ハンドラ追加 |

## 非機能要件の実現方法

### パフォーマンス 🔵

**信頼性**: 🔵 *NFR-001〜002*

- **git --version チェック < 100ms**: `Command::new("git").arg("--version")` の単純実行。タイムアウトは設定しない（OSプロセス起動のみ）
- **git-push / git-pull**: 主なボトルネックはネットワークI/O（git push/fetch）とArgon2id鍵導出（unlock時）。プライバシーパイプラインは数ms程度

### セキュリティ 🔵

**信頼性**: 🔵 *NFR-101〜102, REQ-050〜054*

- **author匿名化**: vault.toml の定義済みauthor情報のみ使用。git global configは使用しない
- **メッセージ定型化**: vault.toml の `commit_message` のみ使用。エントリ内容の漏洩なし
- **.gitignore**: `entries/*.md` を除外し、プレーンテキストエントリがgitに混入しない
- **タイムスタンプファジング**: 実際のコミット時刻を隠蔽し、日記の作成時間パターンを保護

### エラーハンドリング 🔵

**信頼性**: 🔵 *EDGE-001〜006*

- **git未インストール**: `check_git_available()` が `DiaryError::Git("git is not installed or not in PATH")` を返す
- **リモート未設定**: git push/pull のexit codeから `DiaryError::Git` に変換
- **.git未初期化**: vault_dir 内の `.git` ディレクトリ存在チェック
- **既にgit初期化済み**: `.git` ディレクトリ存在チェックで `DiaryError::Git("already initialized")` を返す
- **バックアップ復元失敗**: vault.pqd.bak からの復元失敗時はパニックせず `DiaryError::Io` を返す

## 関連文書

- **データフロー**: [dataflow.md](dataflow.md)
- **型定義**: [types.rs](types.rs)
- **要件定義**: [requirements.md](../../spec/s8-git-sync/requirements.md)
- **受け入れ基準**: [acceptance-criteria.md](../../spec/s8-git-sync/acceptance-criteria.md)
- **ADR-0006**: [0006-git-sync-strategy.md](../../adr/0006-git-sync-strategy.md)

## 信頼性レベルサマリー

- 🔵 青信号: 全件 (100%)
- 🟡 黄信号: 0件 (0%)
- 🔴 赤信号: 0件 (0%)

**品質評価**: 高品質 -- 全項目が要件定義書・ADR-0006・ヒアリングで確認済み
