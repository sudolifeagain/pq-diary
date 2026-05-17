# S12 デジタル遺言 アーキテクチャ設計

**作成日**: 2026-05-17
**関連要件**: [requirements.md](../../spec/s12-legacy/requirements.md)

**【信頼性レベル】**: 全項目🔵

---

## システム概要

デジタル遺言は **二重暗号化方式** を採用する:
- 全 INHERIT エントリの K_entry は **K_master + K_legacy 両方** で暗号化保存される
- `legacy-access` 時、K_master 不要で K_legacy のみで INHERIT エントリを復号可能
- DESTROY エントリは K_master でしか復号できないため、legacy-access 時に消去される

```
通常時:
  master pwd → K_master → 全 entry 復号 OK

legacy-access:
  legacy code → K_legacy → INHERIT entry のみ復号 OK
                                  ↓
                       新 vault.pqd 生成 (K_legacy で再暗号化)
                       DESTROY entry は zeroize 削除
```

## アーキテクチャパターン

既存 3 層構造を踏襲。新規モジュール `core/src/legacy.rs` を追加。

```
┌─────────────────────────────────────────────────────────┐
│                 cli/ (バイナリ層)                        │
│  cli/src/main.rs:                                       │
│    Commands::Legacy { subcommand } (hide 解除)          │
│    Commands::LegacyAccess (hide 解除)                   │
│  cli/src/commands.rs:                                   │
│    cmd_legacy_init, cmd_legacy_set, cmd_legacy_list,    │
│    cmd_legacy_rotate, cmd_legacy_access (新規)          │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│              core/ (pq-diary-core)                       │
│  core/src/legacy.rs (新規):                             │
│    trait LegacyKeyDeriver                               │
│    struct Argon2LegacyDeriver (デフォルト実装)          │
│    fn set_legacy_flag(vault_dir, id, flag, K_legacy)    │
│    fn list_legacy_status(core)                          │
│    fn rotate_legacy_code(vault_dir, old, new)           │
│    fn execute_legacy_access(vault_dir, code, confirm)   │
│                                                          │
│  core/src/vault/config.rs (改訂):                       │
│    struct VaultConfig (+ legacy: LegacySection)         │
│    struct LegacySection {                                │
│        initialized: bool,                                │
│        destroy_confirmation: ConfirmationMode,           │
│    }                                                     │
│    enum ConfirmationMode { Timer30, Yn, Phrase }         │
│                                                          │
│  core/src/vault/init.rs (改訂):                         │
│    init_vault() で legacy_salt 生成 (既存)              │
│    derive_legacy_key(code, salt) (新規 helper)          │
│                                                          │
│  core/src/entry.rs (改訂):                              │
│    update_entry_legacy_block(uuid, K_legacy?, flag)     │
│      (legacy 鍵ブロックの追加/削除)                     │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│           ストレージ層 (S3 で予約済み)                  │
│  vault.pqd v4:                                          │
│    header.legacy_salt: [u8; 32] (S3 で予約済み)         │
│  entry record:                                          │
│    legacy_flag: u8 (S3 で予約)                          │
│    legacy_key_block_len: u32 (S3 で予約)                │
│    legacy_key_block: Vec<u8> (S3 で予約)                │
│  vault.toml (S12 拡張):                                 │
│    [legacy]                                             │
│    initialized = true                                    │
│    destroy_confirmation = "timer30"                      │
└─────────────────────────────────────────────────────────┘
```

## コンポーネント設計

### 1. `core/src/legacy.rs` (新規モジュール)

```rust
//! デジタル遺言機能。INHERIT/DESTROY フラグ、K_legacy 導出・rotate、legacy-access。

use crate::error::DiaryError;
use secrecy::SecretString;
use std::path::Path;
use zeroize::Zeroizing;

// =============================================================================
// LegacyKeyDeriver trait (Phase 3 Shamir 拡張のため抽象化)
// =============================================================================

/// 死後アクセスコードから K_legacy を導出するトレイト。
///
/// Phase 1 (S12): `Argon2LegacyDeriver` のみ。
/// Phase 3: `ShamirLegacyDeriver` を追加 (M-of-N コード合成 → K_legacy)。
pub trait LegacyKeyDeriver: Send + Sync {
    /// 入力コード (生 bytes) と vault のソルトから K_legacy を導出。
    fn derive(&self, code: &[u8], salt: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, DiaryError>;
}

pub struct Argon2LegacyDeriver {
    pub params: crate::crypto::kdf::Argon2Params,
}

impl LegacyKeyDeriver for Argon2LegacyDeriver {
    fn derive(&self, code: &[u8], salt: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, DiaryError> {
        crate::crypto::kdf::derive_key(code, salt, &self.params)
    }
}

// =============================================================================
// 公開 API
// =============================================================================

pub enum LegacyFlag { Inherit, Destroy }

pub fn initialize_legacy(
    vault_dir: &Path,
    master_pwd: &SecretString,
    legacy_code: &SecretString,
    confirmation: ConfirmationMode,
    deriver: &dyn LegacyKeyDeriver,
) -> Result<(), DiaryError>;

pub fn set_entry_flag(
    vault_dir: &Path,
    master_pwd: &SecretString,
    legacy_code_opt: Option<&SecretString>,  // Inherit にする場合のみ必要
    id_prefix: &str,
    flag: LegacyFlag,
    deriver: &dyn LegacyKeyDeriver,
) -> Result<(), DiaryError>;

pub fn list_legacy_status(
    vault_dir: &Path,
    master_pwd: &SecretString,
) -> Result<Vec<LegacyEntryStatus>, DiaryError>;

pub fn rotate_legacy_code(
    vault_dir: &Path,
    master_pwd: &SecretString,
    old_code: &SecretString,
    new_code: &SecretString,
    deriver: &dyn LegacyKeyDeriver,
) -> Result<usize, DiaryError>;  // returns: 再暗号化エントリ数

pub fn execute_legacy_access(
    vault_dir: &Path,
    legacy_code: &SecretString,
    deriver: &dyn LegacyKeyDeriver,
    confirm_callback: impl FnOnce(ConfirmationMode) -> Result<bool, DiaryError>,
) -> Result<LegacyAccessReport, DiaryError>;

pub struct LegacyEntryStatus {
    pub uuid_prefix: String,
    pub title: String,
    pub flag: LegacyFlag,
    pub updated_at: u64,
}

pub struct LegacyAccessReport {
    pub inherited: usize,
    pub destroyed: usize,
}
```

### 2. `core/src/vault/config.rs` 拡張

```rust
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct VaultConfig {
    pub vault: VaultSection,
    pub access: AccessSection,
    pub git: GitSection,
    pub argon2: Argon2Section,
    #[serde(default)]               // S12 追加、後方互換性
    pub legacy: LegacySection,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct LegacySection {
    #[serde(default)]
    pub initialized: bool,
    #[serde(default = "default_confirmation")]
    pub destroy_confirmation: ConfirmationMode,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationMode {
    Timer30,
    Yn,
    Phrase,
}

fn default_confirmation() -> ConfirmationMode { ConfirmationMode::Timer30 }
```

### 3. `cli/src/commands.rs` 拡張

```rust
pub fn cmd_legacy_init(cli: &Cli) -> anyhow::Result<()>;
pub fn cmd_legacy_set(cli: &Cli, id_prefix: &str, inherit: bool, destroy: bool) -> anyhow::Result<()>;
pub fn cmd_legacy_list(cli: &Cli) -> anyhow::Result<()>;
pub fn cmd_legacy_rotate(cli: &Cli) -> anyhow::Result<()>;
pub fn cmd_legacy_access(cli: &Cli) -> anyhow::Result<()>;

// ヘルパー
fn prompt_confirmation_mode(reader: &mut impl BufRead) -> anyhow::Result<ConfirmationMode>;
fn run_destroy_confirmation(mode: ConfirmationMode) -> anyhow::Result<bool>;
fn timer30_with_yn() -> anyhow::Result<bool>;
fn prompt_yn(message: &str) -> anyhow::Result<bool>;
fn prompt_phrase(expected: &str) -> anyhow::Result<bool>;
```

### 4. `cli/src/main.rs` 改訂

```rust
// hide 解除
- #[command(hide = true)]
  Legacy { ... },
- #[command(hide = true)]
  LegacyAccess,

// dispatch
- LegacyCommands::Init => not_implemented(...),
+ LegacyCommands::Init => commands::cmd_legacy_init(cli),
+ LegacyCommands::Rotate => commands::cmd_legacy_rotate(cli),
+ LegacyCommands::Set { id, inherit, destroy } =>
+     commands::cmd_legacy_set(cli, id, *inherit, *destroy),
+ LegacyCommands::List => commands::cmd_legacy_list(cli),
+ Commands::LegacyAccess => commands::cmd_legacy_access(cli),
```

## エラーハンドリング

新規 `DiaryError` バリアントは追加しない (既存 `Vault` / `Config` / `Crypto` で十分):
- `DiaryError::Vault("Legacy not initialized...")` — REQ-501-E02
- `DiaryError::Vault("Invalid legacy code")` — REQ-503
- `DiaryError::Config("Invalid vault.toml [legacy]: ...")` — EDGE-004
- `DiaryError::Crypto("AEAD verification failed")` — 既存

`--claude` ブロックは `anyhow::bail!` で commands.rs 内で対応。

## 既存実装との統合

| S12 機能 | 統合先 | 統合方法 |
|---|---|---|
| K_legacy 導出 | `core/src/crypto/kdf.rs::derive_key` | 既存関数を Argon2LegacyDeriver から呼び出す |
| legacy_salt 取得 | `vault.pqd` ヘッダー | 既に S3 で生成済み、reader.rs から読み出すだけ |
| legacy 鍵ブロック書き込み | `core/src/vault/writer.rs` | エントリレコードの予約フィールドへ書き込む経路を有効化 |
| 全エントリスキャン | `core/src/entry.rs::list_entries_with_body` | 既存 API 流用 |
| 新 vault 生成 | `core/src/vault/init.rs::init_vault` | 改造または専用 `init_vault_with_legacy_key` を追加 |
| password 入力 | `cli/src/password.rs::prompt_password` | S10 hotfix で追加した API を再利用 |

## 非機能要件の実現

| NFR | 設計上の充足策 |
|---|---|
| NFR-001 (init < 5 秒) | K_master + K_legacy の Argon2 2 回 (各 1〜3 秒) で達成 |
| NFR-002 (set < 500ms) | 1 エントリ AES-GCM 復号 + 再暗号化のみ |
| NFR-003 (rotate < 30 秒/100 件) | change-password と同等の規模 |
| NFR-004 (access < 60 秒/1000 件) | Argon2 + 1000 件 AES-GCM 復号 + 新 vault 書き出し |
| NFR-101 (zeroize) | Zeroizing / SecretString / SecretBytes 徹底 |
| NFR-102 (Shamir 拡張可能) | `trait LegacyKeyDeriver` で抽象化 |
| NFR-103 (DESTROY 物理消去) | tmp + rename + 旧 vault.pqd を zeroize 上書き |
| NFR-104 (--claude timing safe) | check_claude_policy → 即 bail!、Argon2 呼び出し前 |

## ロールバック戦略

| ロールバック対象 | 方法 |
|---|---|
| `legacy init` 失敗 | vault.toml の `[legacy]` セクション削除 (or initialized=false) |
| `legacy set` 失敗 | エントリレコードの旧バージョンを zeroize 削除、新バージョン採用 (既存 update_entry パターン) |
| `legacy rotate` 失敗 | vault.pqd.tmp 削除、旧 vault.pqd 維持 |
| `legacy-access` 失敗 | 新 vault.pqd.tmp 削除、旧 vault.pqd 維持 (= DESTROY 未実行) |

## 関連文書

- データフロー: [dataflow.md](dataflow.md)
- 型定義: [types.rs](types.rs)
- スキーマ: [schema.md](schema.md)
- CLI 仕様: [cli-commands.md](cli-commands.md)
- ヒアリング: [design-interview.md](design-interview.md)
- 要件: [requirements.md](../../spec/s12-legacy/requirements.md)

## 信頼性

🔵 100%
