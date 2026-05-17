# S10 CLI コマンド仕様

**作成日**: 2026-05-17
**関連設計**: [architecture.md](architecture.md), [types.rs](types.rs)
**関連要件定義**: [requirements.md](../../spec/s10-operations/requirements.md)

**【信頼性レベル】**: 全項目🔵 (要件定義 + 設計ヒアリング 2026-05-17 + 既存 clap 定義パターン)

---

## 共通仕様

### グローバルフラグ 🔵 (S1 既存、変更なし)

| フラグ | 用途 |
|---|---|
| `-v`, `--vault <VAULT>` | vault path or name |
| `--password <PASSWORD>` | パスワード (insecure、警告付き) |
| `--claude` | Claude AI 連携モード (一部コマンドでブロック) |
| `--debug` | デバッグ出力 |
| `-h`, `--help` | ヘルプ |
| `-V`, `--version` | バージョン |

### パスワード取得優先順位 🔵 (PRD §4.2、既存)

1. `--password` フラグ (insecure, 警告)
2. `PQ_DIARY_PASSWORD` 環境変数
3. TTY プロンプト (デフォルト)

### エラー出力 🔵 (既存パターン)

- stderr に `Error: {message}` を赤色で出力
- exit code: 成功 = 0、エラー = 非ゼロ

---

## サブコマンド一覧 (S10 で追加・変更分)

### 1. `pq-diary init` 🔵 (新規)

**関連要件**: REQ-101 〜 REQ-112

**説明**: 初回セットアップ。`~/.pq-diary/config.toml` を作成し、"default" vault を `policy=none` で初期化する。

**clap 定義**:
```rust
Commands::Init  // 引数なし (--password はグローバル経由)
```

**サブコマンド固有フラグ**: なし

**期待される動作**:

| シナリオ | 動作 |
|---|---|
| `~/.pq-diary/config.toml` 不在 | パスワード TTY 取得 → config.toml 作成 → default vault 作成 → `Initialized pq-diary at ~/.pq-diary/` |
| `~/.pq-diary/config.toml` 既存 | `Error: Already initialized at ~/.pq-diary/` (exit 1) |
| 空パスワード | `Error: New password must not be empty` (exit 1) |
| vault 作成途中で失敗 | config.toml と部分ディレクトリを zeroize 削除 → `Error: {元エラー}` |

**dispatch 変更** (cli/src/main.rs):
```rust
- Commands::Init => not_implemented("init", "Sprint 2"),
+ Commands::Init => commands::cmd_init(cli),
```

---

### 2. `pq-diary sync` 🔵 (新規)

**関連要件**: REQ-201 〜 REQ-212

**説明**: AppConfig の `sync_backend` を読み、対応するバックエンドにディスパッチ。Phase 1 では `"git"` のみサポート。

**clap 定義**:
```rust
Commands::Sync  // 引数なし
```

**期待される動作**:

| シナリオ | 動作 |
|---|---|
| `sync_backend = "git"` (or 省略) | `cmd_git_sync(cli)` を呼ぶ |
| `sync_backend = "github"` (不明値) | `Error: Unknown sync backend: github` (exit 1) |
| AppConfig 不在 | `Error: pq-diary init を先に実行してください (~/.pq-diary/config.toml が見つかりません)` |
| AppConfig 破損 (TOML エラー) | `Error: Invalid config.toml: {detail}` (exit 1) |

**dispatch 変更** (cli/src/main.rs):
```rust
- Commands::Sync => not_implemented("sync", "Sprint 8"),
+ Commands::Sync => commands::cmd_sync(cli),
```

---

### 3. `pq-diary change-password` 🔵 (新規)

**関連要件**: REQ-301 〜 REQ-314

**説明**: vault のマスターパスワードを変更。全エントリと vault ヘッダーを新パスワードで再暗号化し、`.tmp + rename` でアトミックに差し替える。

**clap 定義**:
```rust
Commands::ChangePassword  // 引数なし
```

**期待される動作**:

| シナリオ | 動作 |
|---|---|
| 正常系 | 旧パス TTY 取得 → unlock → 新パス TTY 取得 × 2 → 再暗号化 → rename → `Password changed successfully` |
| 旧パスワード不正 | `Error: Old password is incorrect` (vault.pqd 無変更) |
| 新パスワード空 | `Error: New password must not be empty` (vault.pqd 無変更) |
| 新パスワード 2 回不一致 | `Error: Passwords do not match` (vault.pqd 無変更) |
| 新旧同一 | `Warning: New password is identical to old password.` → 処理続行 |
| 書き込み失敗 | `vault.pqd.tmp` zeroize 削除 → `Error: {元エラー}` (旧 vault.pqd 維持) |
| SIGINT (Ctrl+C) | メモリ Drop で zeroize → exit (旧 vault.pqd 維持、tmp は残存可能性) |
| `--claude` フラグ | `Error: change-password is not permitted with --claude` (exit 1) |

**dispatch 変更** (cli/src/main.rs):
```rust
- Commands::ChangePassword => not_implemented("change-password", "Sprint 3"),
+ Commands::ChangePassword => commands::cmd_change_password(cli),
```

---

### 4. `pq-diary info [--security]` 🔵 (新規)

**関連要件**: REQ-401 〜 REQ-412

**説明**: vault のメタ情報を表示。`--security` フラグで暗号パラメータとプロセス強化状態も追加表示。

**clap 定義**:
```rust
Commands::Info { security: bool }  // --security フラグ
```

**サブコマンド固有フラグ**:

| フラグ | 用途 |
|---|---|
| `--security` | セキュリティ詳細を追加表示 |

**期待される動作**:

| シナリオ | 動作 |
|---|---|
| `info` (デフォルト) | vault 名・policy・エントリ数・created・updated を表示 |
| `info --security` | 上記 + Argon2 params + KEM/DSA 名 + mlock/coredump/debugger 状態 |
| パスワード不正 | `Error: Vault unlock failed` |
| vault.toml 破損 | `Error: Invalid vault.toml: {detail}` |

**出力サンプル** (`--security` なし):
```
=== Vault Info ===
Name:           default
Policy:         none
Entries:        42
Created:        2026-04-15 09:23:11 UTC
Last updated:   2026-05-17 11:42:03 UTC
```

**出力サンプル** (`--security` あり):
```
=== Vault Info ===
Name:           default
Policy:         none
Entries:        42
Created:        2026-04-15 09:23:11 UTC
Last updated:   2026-05-17 11:42:03 UTC

=== Security ===
KEM algorithm:        ML-KEM-768
Signature algorithm:  ML-DSA-65
Argon2 memory:        65536 KB
Argon2 time cost:     3
Argon2 parallelism:   1
mlock active:         yes
Coredump disabled:    yes
Debugger detected:    no
```

**dispatch 変更** (cli/src/main.rs):
```rust
- Commands::Info { .. } => not_implemented("info", "Sprint 2"),
+ Commands::Info { security } => commands::cmd_info(cli, *security),
```

---

### 5. `pq-diary export <DIR>` 🔵 (新規)

**関連要件**: REQ-501 〜 REQ-521

**説明**: 全エントリを復号して指定ディレクトリへ Markdown ファイルで書き出す。

**clap 定義**:
```rust
Commands::Export(ExportArgs)

#[derive(Args)]
struct ExportArgs {
    dir: PathBuf,
}
```

**サブコマンド固有引数**:

| 引数 | 用途 |
|---|---|
| `<DIR>` | 出力先ディレクトリ (既存である必要あり) |

**期待される動作**:

| シナリオ | 動作 |
|---|---|
| 正常系 | --claude チェック → DIR 存在チェック → 警告 + y/N → unlock → 各エントリを `YYYY-MM-DD-slug-id8.md` で書き出し → `Exported N entries to {DIR}` |
| `--claude` フラグ | `Error: export is not permitted with --claude` (exit 1) |
| DIR 不在 | `Error: Directory does not exist: {DIR}` (exit 1) |
| 警告で `y` 以外 | `キャンセルしました` (exit 0) |
| 空 vault | `No entries to export` (ディレクトリ作成せず、exit 0) |
| 出力先に同名ファイル既存 | `Error: File exists: {path}` (exit 1) |
| タイトル空 | slug = `untitled` |

**dispatch 変更** (cli/src/main.rs):
```rust
- Commands::Export => not_implemented("export", "Sprint 5"),
+ Commands::Export(args) => commands::cmd_export(cli, args.dir.clone()),
```

**Commands enum 変更**:
```rust
- Export,
+ Export(ExportArgs),
```

---

## サブコマンド一覧 (S10 で hide 化)

### 6. `pq-diary legacy <subcommand>` 🔵 (隠す)

**関連要件**: REQ-702

**現状**: clap で定義済み、`not_implemented("legacy {sub}", "Sprint 9")` を返す。

**変更**: `#[command(hide = true)]` でヘルプから除外。`not_implemented` メッセージを "Planned for Phase 2" に統一。

**clap 定義変更**:
```rust
#[derive(Subcommand)]
enum Commands {
    // ...
+   #[command(hide = true)]
    Legacy {
        #[command(subcommand)]
        subcommand: LegacyCommands,
    },
+   #[command(hide = true)]
    LegacyAccess,
+   #[command(hide = true)]
    Daemon {
        #[command(subcommand)]
        subcommand: DaemonCommands,
    },
}
```

**dispatch メッセージ更新**:
```rust
- LegacyCommands::Init => not_implemented("legacy init", "Sprint 9"),
+ LegacyCommands::Init => not_implemented("legacy init", "Phase 2"),
```

---

## CLI 階層 (`--help` 表示) 🔵

S10 完了後の `pq-diary --help` 出力 (主要部のみ):

```
Post-quantum cryptography CLI journal

Usage: pq-diary [OPTIONS] <COMMAND>

Commands:
  init             Initialize pq-diary (~/.pq-diary/ + default vault)
  vault            Manage vaults (create, list, policy, delete)
  new              Create a new diary entry
  list             List diary entries
  show             Show a diary entry
  edit             Edit a diary entry
  delete           Delete a diary entry
  sync             Sync diary entries with configured remotes
  export           Export diary entries to an external format
  change-password  Change the vault master password
  info             Show vault information
  git-init         Initialize a git repository for the vault
  git-push         Push vault to the remote git repository
  git-pull         Pull vault from the remote git repository
  git-sync         Sync vault with remote (pull then push)
  git-status       Show git sync status
  today            Open or create today's diary entry
  search           Search entries by regex pattern
  stats            Show vault statistics
  import           Import Markdown files from a directory
  template         Manage entry templates
  help             Print this message or the help of the given subcommand(s)
```

**注目**: `legacy`, `legacy-access`, `daemon` がリストから消える。

---

## core 公開 API (S10 で追加・変更分) 🔵

### core/src/vault/config.rs 追加

```rust
/// 🔵 REQ-601 〜 REQ-611
pub struct AppConfig { pub app: AppSection }
pub struct AppSection {
    pub default_vault: String,
    pub sync_backend: String,
}
impl Default for AppConfig { /* default_vault="default", sync_backend="git" */ }
impl AppConfig {
    pub fn default_path() -> Result<PathBuf, DiaryError>;     // ~/.pq-diary/config.toml
    pub fn default_vaults_dir() -> Result<PathBuf, DiaryError>; // ~/.pq-diary/vaults/
    pub fn from_file(path: &Path) -> Result<Self, DiaryError>;
    pub fn to_file(&self, path: &Path) -> Result<(), DiaryError>;  // Unix で 0o600
}
```

### cli/src/security.rs 追加

```rust
/// 🔵 REQ-411, REQ-412, NFR-104
pub struct HardenStatus {
    pub mlock_active: bool,
    pub coredump_disabled: bool,
    pub debugger_detected: bool,
}
impl HardenStatus {
    pub fn current() -> Self;  // 実プロセス状態を反映
}

pub fn harden_status() -> HardenStatus;  // HardenStatus::current() のラッパー
```

### cli/src/commands.rs 追加関数

```rust
pub fn cmd_init(cli: &Cli) -> anyhow::Result<()>;
pub fn cmd_sync(cli: &Cli) -> anyhow::Result<()>;
pub fn cmd_change_password(cli: &Cli) -> anyhow::Result<()>;
pub fn cmd_info(cli: &Cli, security: bool) -> anyhow::Result<()>;
pub fn cmd_export(cli: &Cli, dir: PathBuf) -> anyhow::Result<()>;

// プライベートヘルパー
fn slugify(title: &str) -> String;
fn yaml_escape(s: &str) -> String;
fn build_export_filename(entry: &EntryPlaintext) -> String;
fn build_export_content(entry: &EntryPlaintext) -> String;
```

---

## CI smoke test スクリプト 🔵 (新規)

`ci/smoke-test.sh` (Unix) と `ci/smoke-test.ps1` (Windows) の 2 種類を新規追加。

### Unix 版骨子 (`ci/smoke-test.sh`)
```bash
#!/usr/bin/env bash
set -euo pipefail
BIN="${1:-./target/release/pq-diary}"
PASS=0; FAIL=0
pass() { echo "[PASS] $*"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $*" >&2; FAIL=$((FAIL+1)); }

# 1. 全ヘルプ exit 0
for cmd in init sync change-password info export new list show edit delete today search stats import vault git-init git-push git-pull git-sync git-status template; do
  if "$BIN" "$cmd" --help >/dev/null 2>&1; then pass "$cmd --help"; else fail "$cmd --help"; fi
done

# 2. ヘルプに legacy/daemon が無い
HELP=$("$BIN" --help 2>&1)
if echo "$HELP" | grep -q legacy; then fail "help contains 'legacy'"; else pass "help no 'legacy'"; fi
if echo "$HELP" | grep -q daemon; then fail "help contains 'daemon'"; else pass "help no 'daemon'"; fi

# 3. E2E
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT
export HOME="$TMPDIR"  # ~/.pq-diary/ を一時化
export PQ_DIARY_PASSWORD="SmokeTest123!"
"$BIN" init && pass "E2E: init" || fail "E2E: init"
"$BIN" new "smoke" --body "smoke body" && pass "E2E: new" || fail "E2E: new"
"$BIN" list | grep -q smoke && pass "E2E: list contains" || fail "E2E: list contains"
"$BIN" info && pass "E2E: info" || fail "E2E: info"
mkdir "$TMPDIR/out"
echo y | "$BIN" export "$TMPDIR/out" && \
  [ "$(ls "$TMPDIR/out" | wc -l)" -eq 1 ] && pass "E2E: export 1 file" || fail "E2E: export"

echo "===== $PASS passed, $FAIL failed ====="
[ "$FAIL" -eq 0 ]
```

### Windows 版骨子 (`ci/smoke-test.ps1`)

同等の処理を PowerShell で実装。`HOME` の代わりに `USERPROFILE` を一時化。

### CI 統合

`.github/workflows/ci.yml` (or 既存 CI 設定) に以下を追加:
```yaml
- name: CLI smoke test
  run: ./ci/smoke-test.sh ./target/release/pq-diary
```

---

## 関連文書

- **アーキテクチャ**: [architecture.md](architecture.md)
- **データフロー**: [dataflow.md](dataflow.md)
- **型定義**: [types.rs](types.rs)
- **スキーマ**: [schema.md](schema.md)
- **要件定義**: [requirements.md](../../spec/s10-operations/requirements.md)

## 信頼性レベルサマリー

- 🔵 青信号: 全項目 (100%)
- 🟡 黄信号: 0 件
- 🔴 赤信号: 0 件

**品質評価**: 最高品質。全コマンド仕様が要件定義 + 設計ヒアリング + 既存 clap パターンで確定済み。
