# S7 Access Control + Claude アーキテクチャ設計

**作成日**: 2026-04-10
**関連要件定義**: [requirements.md](../../spec/s7-access-control-claude/requirements.md)
**ヒアリング記録**: [design-interview.md](design-interview.md)

**【信頼性レベル凡例】**:
- 🔵 **青信号**: EARS要件定義書・設計文書・ユーザヒアリングを参考にした確実な設計

---

## システム概要 🔵

**信頼性**: 🔵 *要件定義書概要 + PRD 4.4*

S7では以下の3つの機能領域を実装する:

1. **ポリシー評価エンジン** (`core/src/policy.rs`): `AccessPolicy` enum と4層ポリシーチェック
2. **Vault管理CRUD** (`core/src/vault/init.rs` 拡張): create/list/policy/delete
3. **CLI統合** (`cli/src/commands.rs`): 各コマンドハンドラへのポリシーチェック組み込み

## アーキテクチャパターン 🔵

**信頼性**: 🔵 *既存アーキテクチャ + CLAUDE.md規約*

- **パターン**: 既存のファサード + RAII Guard パターンを維持
- **ポリシー評価**: `core/` に配置。`cli/` は結果を受け取るのみ（REQ-401, REQ-402）
- **ポリシーチェック位置**: 各コマンドハンドラ（`cmd_*`）の先頭（ヒアリング「各コマンド内」）

## コンポーネント構成

### core/src/policy.rs — ポリシー評価エンジン 🔵

**信頼性**: 🔵 *REQ-001〜003, REQ-010, REQ-020〜025*

新規実装。以下の型と関数を提供:

```rust
// --- 型定義 ---

/// アクセスポリシー（vault.toml [access].policy）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessPolicy {
    None,
    WriteOnly,
    Full,
}

/// 操作の読み書き分類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationType {
    Read,
    Write,
}

/// ポリシーチェック結果
#[derive(Debug)]
pub enum PolicyDecision {
    /// 許可（通常処理へ進む）
    Allow,
    /// 拒否（復号不要で即時エラー）
    DenyNoDecrypt { vault_name: String, policy: AccessPolicy, reason: String },
    /// 拒否（操作種別不一致）
    DenyOperation { vault_name: String, policy: AccessPolicy, operation: OperationType, reason: String },
}

// --- 関数 ---

/// 4層ポリシーチェック
///   Layer 1: claude=false → Allow
///   Layer 2: policy=None → DenyNoDecrypt
///   Layer 3: policy=WriteOnly + Read → DenyOperation
///   Layer 3: policy=WriteOnly + Write → Allow
///   Layer 4: policy=Full → Allow
pub fn check_access(
    claude: bool,
    policy: AccessPolicy,
    operation: OperationType,
    vault_name: &str,
) -> PolicyDecision;

/// CLIコマンドからOperationTypeを判定
pub fn classify_operation(command: &str) -> OperationType;

/// PolicyDecisionからDiaryError::Policyを生成
impl PolicyDecision {
    pub fn into_result(self) -> Result<(), DiaryError>;
}
```

### core/src/vault/config.rs — AccessSection変更 🔵

**信頼性**: 🔵 *REQ-003, REQ-404*

既存の `AccessSection.policy: String` を `AccessPolicy` に置き換え:

```rust
// Before (現行)
pub struct AccessSection {
    pub policy: String,
}

// After (S7)
use crate::policy::AccessPolicy;

pub struct AccessSection {
    pub policy: AccessPolicy,
}
```

serde `#[serde(rename_all = "snake_case")]` により既存vault.toml（`policy = "none"`）との後方互換性を維持。

### core/src/vault/init.rs — VaultManager拡張 🔵

**信頼性**: 🔵 *REQ-030〜037 + ヒアリング「VaultManager拡張」*

既存の `VaultManager` に以下のメソッドを追加:

```rust
impl VaultManager {
    // 既存
    pub fn init_vault(&self, name: &str, password: &[u8]) -> Result<(), DiaryError>;
    pub fn list_vaults(&self) -> Result<Vec<String>, DiaryError>;
    pub fn vault_path(&self, name: &str) -> PathBuf;
    pub fn default_vault(&self) -> String;

    // S7 新規
    pub fn create_vault(&self, name: &str, password: &[u8], policy: AccessPolicy)
        -> Result<(), DiaryError>;
    pub fn list_vaults_with_policy(&self) -> Result<Vec<VaultInfo>, DiaryError>;
    pub fn set_policy(&self, name: &str, policy: AccessPolicy) -> Result<(), DiaryError>;
    pub fn delete_vault(&self, name: &str, zeroize: bool) -> Result<(), DiaryError>;
    pub fn validate_vault_name(name: &str) -> Result<(), DiaryError>;
}

/// vault list の出力用情報
pub struct VaultInfo {
    pub name: String,
    pub policy: AccessPolicy,
}
```

**create_vault()** は内部で `init_vault()` を呼び出し、その後 `set_policy()` でポリシーを設定。

**validate_vault_name()** は静的メソッドとして:
- 空文字列チェック
- パストラバーサル文字（`/`, `\`, `..`）チェック
- ファイルシステム無効文字チェック

**delete_vault()** の `zeroize=true` 時:
1. vault.pqd のファイルサイズを取得
2. 同サイズのランダムデータで上書き（`OsRng`）
3. `sync_all()` でフラッシュ
4. ディレクトリ全体を `std::fs::remove_dir_all()` で削除

**set_policy()** のアトミック書き込み:
1. vault.toml を読み込み
2. policy フィールドを更新
3. temp ファイルに書き込み → rename（S6 atomic write パターン）

### core/src/lib.rs — DiaryCore拡張 🔵

**信頼性**: 🔵 *既存API設計 + REQ-021*

DiaryCore に policy アクセサを追加:

```rust
impl DiaryCore {
    /// 現在のVaultのアクセスポリシーを返す（vault.toml から読み取り済み）
    pub fn access_policy(&self) -> AccessPolicy {
        self.config.access.policy
    }

    /// Vault名を返す
    pub fn vault_name(&self) -> &str {
        &self.config.vault.name
    }
}
```

### cli/src/commands.rs — コマンドハンドラ 🔵

**信頼性**: 🔵 *REQ-020〜025 + ヒアリング「各コマンド内」*

各 `cmd_*` 関数の先頭にポリシーチェックを挿入:

```rust
fn cmd_show(cli: &Cli, id: &str) -> Result<()> {
    // ---- ポリシーチェック（vault.toml のみ読み取り） ----
    if cli.claude {
        let vault_path = resolve_vault_path(cli)?;
        let config = VaultConfig::from_file(&vault_path.join("vault.toml"))?;
        let decision = policy::check_access(
            true,
            config.access.policy,
            OperationType::Read,
            &config.vault.name,
        );
        decision.into_result()?;  // DenyならここでEarlyReturn
    }

    // ---- 既存フロー（PW取得 → unlock → 操作 → lock） ----
    let password = get_password(cli.password.as_deref())?;
    // ... 以降は既存実装
}
```

**None ポリシーの場合**: `check_access()` が `DenyNoDecrypt` を返すため、パスワード取得も復号も行われない（REQ-101, NFR-101）。

### cli/src/commands.rs — Vault管理コマンド 🔵

**信頼性**: 🔵 *REQ-030〜037*

新規コマンドハンドラ:

```rust
/// vault create <name> [--policy <POLICY>]
pub fn cmd_vault_create(cli: &Cli, name: &str, policy: Option<&str>) -> Result<()>;

/// vault list
pub fn cmd_vault_list(cli: &Cli) -> Result<()>;

/// vault policy <name> <POLICY>
pub fn cmd_vault_policy(cli: &Cli, name: &str, policy_str: &str) -> Result<()>;

/// vault delete <name> [--zeroize]
pub fn cmd_vault_delete(cli: &Cli, name: &str, zeroize: bool) -> Result<()>;
```

**cmd_vault_create** フロー:
1. `VaultManager::validate_vault_name(name)?`
2. ポリシー文字列を `AccessPolicy` にパース（デフォルト: None）
3. `full` ならfull警告 → [y/N] 確認
4. パスワード入力（`get_password()`）
5. `VaultManager::create_vault(name, password, policy)?`
6. 成功メッセージ表示

**cmd_vault_list** フロー:
1. `VaultManager::list_vaults_with_policy()?`
2. 列形式で名前・ポリシーを表示（パスワード不要）

**cmd_vault_policy** フロー:
1. ポリシー文字列を `AccessPolicy` にパース
2. `full` ならfull警告 → [y/N] 確認
3. `VaultManager::set_policy(name, policy)?`（パスワード不要）
4. 成功メッセージ表示

**cmd_vault_delete** フロー:
1. Vault存在確認
2. デフォルトVault判定 → 追加確認
3. 通常確認プロンプト（`--claude` 時スキップ）
4. `VaultManager::delete_vault(name, zeroize)?`（パスワード不要）
5. 成功メッセージ表示

### cli/src/main.rs — clap定義変更 🔵

**信頼性**: 🔵 *既存VaultCommands enum*

```rust
pub enum VaultCommands {
    Create {
        name: String,
        #[arg(long, value_parser = parse_policy)]
        policy: Option<AccessPolicy>,
    },
    List,
    Policy {
        name: String,
        policy: String,  // clap でパース後に AccessPolicy に変換
    },
    Delete {
        name: String,
        #[arg(long)]
        zeroize: bool,
    },
}
```

## システム構成図 🔵

**信頼性**: 🔵 *既存アーキテクチャ + S7設計*

```
┌─────────────────────────────────────────────────┐
│                 cli/src/main.rs                  │
│  ┌───────────────────────────────────────────┐   │
│  │ Cli { --claude, --vault, --password }     │   │
│  │ Commands match → cmd_* handlers           │   │
│  └────────────────────┬──────────────────────┘   │
│                       │                          │
│  ┌────────────────────▼──────────────────────┐   │
│  │ cli/src/commands.rs                       │   │
│  │ ┌──────────────────────────────────────┐  │   │
│  │ │ Policy Check (if --claude)           │  │   │
│  │ │   VaultConfig::from_file()           │  │   │
│  │ │   policy::check_access()             │  │   │
│  │ │   → Allow / Deny                     │  │   │
│  │ └──────────────┬───────────────────────┘  │   │
│  │                │ Allow                     │   │
│  │ ┌──────────────▼───────────────────────┐  │   │
│  │ │ get_password() → DiaryCore::unlock() │  │   │
│  │ │ VaultGuard → operations → auto-lock  │  │   │
│  │ └─────────────────────────────────────┘   │   │
│  │                                           │   │
│  │ cmd_vault_create / list / policy / delete │   │
│  └───────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────┐
│               core/src/                          │
│  ┌───────────────────────────────────────────┐   │
│  │ policy.rs                                 │   │
│  │  AccessPolicy { None, WriteOnly, Full }   │   │
│  │  OperationType { Read, Write }            │   │
│  │  check_access() → PolicyDecision          │   │
│  │  classify_operation()                     │   │
│  └───────────────────────────────────────────┘   │
│  ┌───────────────────────────────────────────┐   │
│  │ vault/init.rs (VaultManager)              │   │
│  │  create_vault(name, pw, policy)           │   │
│  │  list_vaults_with_policy()                │   │
│  │  set_policy(name, policy)                 │   │
│  │  delete_vault(name, zeroize)              │   │
│  │  validate_vault_name(name)                │   │
│  └───────────────────────────────────────────┘   │
│  ┌───────────────────────────────────────────┐   │
│  │ vault/config.rs                           │   │
│  │  AccessSection { policy: AccessPolicy }   │   │
│  └───────────────────────────────────────────┘   │
│  ┌───────────────────────────────────────────┐   │
│  │ lib.rs (DiaryCore)                        │   │
│  │  access_policy() → AccessPolicy           │   │
│  │  vault_name() → &str                      │   │
│  └───────────────────────────────────────────┘   │
└──────────────────────────────────────────────────┘
                       │
         ┌─────────────▼──────────────┐
         │   ~/.pq-diary/vaults/      │
         │   ├── private/             │
         │   │   ├── vault.pqd        │
         │   │   ├── vault.toml       │
         │   │   │  [access]          │
         │   │   │  policy = "none"   │
         │   │   └── entries/         │
         │   └── work/                │
         │       ├── vault.pqd        │
         │       ├── vault.toml       │
         │       │  [access]          │
         │       │  policy="write_only│
         │       └── entries/         │
         └────────────────────────────┘
```

## 変更対象ファイル一覧 🔵

**信頼性**: 🔵 *設計分析*

| ファイル | 変更種別 | 内容 |
|---------|----------|------|
| `core/src/policy.rs` | **新規実装** | AccessPolicy, OperationType, check_access(), classify_operation() |
| `core/src/vault/config.rs` | **変更** | AccessSection.policy: String → AccessPolicy |
| `core/src/vault/init.rs` | **拡張** | create_vault, list_vaults_with_policy, set_policy, delete_vault, validate_vault_name |
| `core/src/lib.rs` | **拡張** | access_policy(), vault_name() アクセサ追加 |
| `cli/src/main.rs` | **変更** | VaultCommands enum 引数追加、ディスパッチ更新 |
| `cli/src/commands.rs` | **拡張** | cmd_vault_create/list/policy/delete、既存cmd_*にポリシーチェック追加 |

## 非機能要件の実現方法

### パフォーマンス 🔵

**信頼性**: 🔵 *NFR-001〜003*

- **ポリシーチェック < 10ms**: vault.toml の読み取り（toml::from_str）のみ。vault.pqd 復号なし
- **vault list O(n)**: `std::fs::read_dir` + 各vault.toml読み取り
- **vault create < 3s**: 既存 init_vault() 相当（Argon2id鍵導出がボトルネック）

### セキュリティ 🔵

**信頼性**: 🔵 *NFR-101〜103, REQ-101*

- **None拒否時の鍵保護**: ポリシーチェックがパスワード取得より前に実行されるため、`None` 時は鍵素材がメモリに一切展開されない
- **不正ポリシー値**: serde enum デシリアライズが `DiaryError::Config` を返す。フォールバックなし
- **vault.toml アトミック書き込み**: temp + rename パターン（S6 writer.rs:171-228 と同一）

### 互換性 🔵

**信頼性**: 🔵 *REQ-404*

- `serde(rename_all = "snake_case")` により `"none"` / `"write_only"` / `"full"` 文字列との互換性維持
- 既存 vault.toml（`policy = "none"` 文字列）はそのままパース可能

## 関連文書

- **データフロー**: [dataflow.md](dataflow.md)
- **型定義**: [types.rs](types.rs)
- **要件定義**: [requirements.md](../../spec/s7-access-control-claude/requirements.md)
- **受け入れ基準**: [acceptance-criteria.md](../../spec/s7-access-control-claude/acceptance-criteria.md)

## 信頼性レベルサマリー

- 🔵 青信号: 全件 (100%)
- 🟡 黄信号: 0件 (0%)
- 🔴 赤信号: 0件 (0%)

**品質評価**: 高品質 — 全項目が要件定義書・ヒアリングで確認済み
