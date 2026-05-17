# S13 添付ファイル アーキテクチャ設計

**作成日**: 2026-05-18
**関連要件**: [../../spec/s13-attachments/requirements.md](../../spec/s13-attachments/requirements.md)
**ヒアリング**: [design-interview.md](design-interview.md)

**【信頼性レベル凡例】**: 🔵 確実 / 🟡 妥当な推測 / 🔴 推測のみ

---

## システム概要 🔵

**信頼性**: 🔵 *ヒアリング Q1/Q2/Q3/Q4 + 既存実装*

添付ファイルは **メタデータ/本体分離方式** を採用する:
- **メタデータ**: vault.pqd v5 内の attachment レコード (新 `RECORD_TYPE_ATTACHMENT = 0x03`)。
  ファイル名・MIME・サイズ・SHA-256・FileKey は `AttachmentPlaintext` として
  K_master で暗号化する (既存 entry record と同じ HMAC + signature モデル)
- **本体**: `<vault_dir>/.attachments/<blob_uuid>.bin`。
  OsRng 生成の添付専用 FileKey で AES-256-GCM 1MB chunk ストリーミング暗号化

```
通常時:
  master pwd → K_master → 全 entry + attachment メタデータ復号 OK
                       → 必要な .attachments/*.bin を chunk 復号

legacy-access:
  legacy code → K_legacy → INHERIT のみ復号、新 vault に再構築
                        → DESTROY 添付の .bin を zeroize 削除
```

## アーキテクチャパターン 🔵

既存 3 層構造を踏襲、新規 `core/src/attachment.rs` モジュール追加。

```
┌─────────────────────────────────────────────────────────┐
│                 cli/ (バイナリ層)                        │
│  cli/src/main.rs:                                       │
│    Commands::Attachment { subcommand: AttachmentCommands }│
│  cli/src/commands.rs:                                   │
│    cmd_attachment_add, cmd_attachment_list,             │
│    cmd_attachment_extract, cmd_attachment_delete,       │
│    cmd_attachment_set (新規)                             │
│    cmd_new (拡張: --attach 受付)                         │
│    cmd_show / cmd_export / cmd_import (拡張)             │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│              core/ (pq-diary-core)                       │
│  core/src/attachment.rs (新規):                         │
│    struct AttachmentRecord                              │
│    struct AttachmentMeta (CLI 表示用)                   │
│    fn add_attachment(vault, entry_uuid, path)           │
│    fn list_attachments(vault, entry_uuid?)              │
│    fn extract_attachment(vault, entry_uuid, name, out)  │
│    fn delete_attachment(vault, entry_uuid, name)        │
│    fn set_attachment_legacy_flag(...)                   │
│                                                          │
│  core/src/crypto/streaming.rs (新規):                   │
│    fn encrypt_stream<R, W>(file_key, reader, writer, blob_uuid)│
│    fn decrypt_stream<R, W>(file_key, reader, writer, blob_uuid)│
│    (1MB chunk 単位の AES-GCM + AAD)                      │
│                                                          │
│  core/src/vault/format.rs (改訂):                       │
│    const RECORD_TYPE_ATTACHMENT: u8 = 0x03               │
│    struct AttachmentRecord (新)                          │
│    EntryRecord はそのまま (attachment_count 使用開始 / attachment_offset は 0)│
│                                                          │
│  core/src/vault/reader.rs (改訂):                       │
│    read_vault() が AttachmentRecord も読む               │
│                                                          │
│  core/src/vault/writer.rs (改訂):                       │
│    write_entries() が AttachmentRecord も書く            │
│                                                          │
│  core/src/legacy.rs (改訂):                             │
│    execute_legacy_access が attachment も処理             │
│    rotate_legacy_code が attachment レコードも対象        │
│                                                          │
│  core/src/entry.rs (拡張):                              │
│    create_entry は attachment_offset=0 のまま             │
│                                                          │
│  core/src/importer.rs (拡張):                           │
│    parse_obsidian_attachment_links()                    │
│                                                          │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│           ストレージ層                                   │
│  vault.pqd v5:                                          │
│    EntryRecord.attachment_count: u16 (使用開始)         │
│    EntryRecord.attachment_offset: u64 (0 固定)           │
│    AttachmentRecord (新タイプ 0x03)                      │
│  <vault_dir>/.attachments/:                              │
│    <blob_uuid>.bin (chunk 暗号化バイナリ、重複時は共有)   │
└─────────────────────────────────────────────────────────┘
```

## コンポーネント設計

### 1. `core/src/attachment.rs` (新規モジュール) 🟡

**信頼性**: 🟡 *既存 entry CRUD パターンの拡張、API シグネチャは設計判断*

```rust
//! Attachment CRUD + legacy 連動。
//!
//! 添付メタデータは vault.pqd v5 の AttachmentRecord (新タイプ 0x03)、
//! 本体は <vault_dir>/.attachments/<blob_uuid>.bin に AES-GCM 1MB chunk で保管。

use crate::error::DiaryError;
use crate::vault::format::AttachmentRecord;
use secrecy::SecretString;
use std::path::Path;
use uuid::Uuid;

pub struct AttachmentMeta {
    pub uuid: Uuid,
    pub entry_uuid: [u8; 16],
    pub filename: String,
    pub mime_type: String,
    pub size_bytes: u64,
    pub sha256: [u8; 32],
    pub created_at: u64,
    pub legacy_flag: crate::legacy::LegacyFlag,
}

pub fn add_attachment(
    vault_dir: &Path,
    master_pwd: &SecretString,
    entry_id_prefix: &str,
    source_path: &Path,
) -> Result<Uuid, DiaryError>;

pub fn list_attachments(
    vault_dir: &Path,
    master_pwd: &SecretString,
    entry_id_prefix: Option<&str>,
) -> Result<Vec<AttachmentMeta>, DiaryError>;

pub fn extract_attachment(
    vault_dir: &Path,
    master_pwd: &SecretString,
    entry_id_prefix: &str,
    filename: &str,
    out_path: &Path,
) -> Result<(), DiaryError>;

pub fn delete_attachment(
    vault_dir: &Path,
    master_pwd: &SecretString,
    entry_id_prefix: &str,
    filename: &str,
) -> Result<(), DiaryError>;

pub fn set_attachment_legacy_flag(
    vault_dir: &Path,
    master_pwd: &SecretString,
    legacy_code_opt: Option<&SecretString>,
    entry_id_prefix: &str,
    filename: &str,
    flag: crate::legacy::LegacyFlag,
    deriver: &dyn crate::legacy::LegacyKeyDeriver,
) -> Result<(), DiaryError>;
```

### 2. `core/src/crypto/streaming.rs` (新規) 🟡

**信頼性**: 🟡 *chunk size 1MB、AAD 設計は妥当な推測*

```rust
//! Streaming AES-256-GCM for attachment payloads.
//!
//! Bin layout (variable repetitions per chunk):
//!   [chunk_iv: 12B][chunk_ct + tag: chunk_size + 16B]
//!
//! AAD per chunk = chunk_index (LE u32) || total_chunks (LE u32) || blob_uuid (16B)
//! → chunk reorder / truncation / file substitution detection.

pub const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB

pub fn encrypt_stream<R: std::io::Read, W: std::io::Write>(
    key: &[u8; 32],
    blob_uuid: &[u8; 16],
    reader: &mut R,
    writer: &mut W,
) -> Result<(u64, [u8; 32]), DiaryError>;  // returns (total_bytes_read, sha256_plain)

pub fn decrypt_stream<R: std::io::Read, W: std::io::Write>(
    key: &[u8; 32],
    blob_uuid: &[u8; 16],
    expected_size: u64,
    expected_sha256: &[u8; 32],
    reader: &mut R,
    writer: &mut W,
) -> Result<(), DiaryError>;
```

### 3. `AttachmentRecord` 定義 (vault::format) 🟡

```rust
pub const RECORD_TYPE_ATTACHMENT: u8 = 0x03;

#[derive(Debug, Clone)]
pub struct AttachmentRecord {
    pub record_type: u8,                  // 0x03
    pub uuid: [u8; 16],                   // attachment record UUID
    pub iv: [u8; 12],
    pub ciphertext: Vec<u8>,              // encrypted AttachmentPlaintext
    pub content_hmac: [u8; 32],
    pub signature: Vec<u8>,
    pub legacy_flag: u8,
    pub legacy_key_block: Vec<u8>,
    pub padding: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct AttachmentPlaintext {
    pub entry_uuid: [u8; 16],
    pub blob_uuid: [u8; 16],
    pub created_at: u64,
    pub filename: String,
    pub mime_type: String,
    pub size_bytes: u64,
    pub chunk_count: u32,
    pub sha256: [u8; 32],
    pub file_key: [u8; 32],               // Zeroizing in implementation
}
```

Reader / Writer は `record_type` で分岐し、Entry / Template / Attachment を
区別する。EntryRecord の `attachment_count` は表示・境界チェック用に使用し、
`attachment_offset` は v5 でも 0 固定。紐付けは復号後の
`AttachmentPlaintext.entry_uuid` で行う。

### 4. CLI 構造拡張 🟡

```rust
// cli/src/main.rs
Commands::Attachment {
    #[command(subcommand)]
    subcommand: AttachmentCommands,
},

#[derive(Subcommand)]
pub enum AttachmentCommands {
    Add { entry: String, path: PathBuf },
    List { entry: Option<String> },
    Extract { entry: String, filename: String, #[arg(long)] out: PathBuf },
    Delete { entry: String, filename: String, #[arg(long)] force: bool },
    Set {
        entry: String,
        filename: String,
        #[arg(long, conflicts_with = "destroy")]
        inherit: bool,
        #[arg(long, conflicts_with = "inherit")]
        destroy: bool,
    },
}
```

`new` コマンドに `--attach <FILE>` (繰り返し可) を追加:
```rust
#[arg(long = "attach", value_name = "FILE")]
attach: Vec<PathBuf>,
```

## エラーハンドリング

新規 `DiaryError` バリアントは追加しない (既存で十分):
- `DiaryError::Io` — `.attachments/` の I/O 失敗、ファイル不存在
- `DiaryError::Crypto` — chunk decrypt 失敗 (AEAD tag mismatch / SHA-256 不一致)
- `DiaryError::Entry` — attachment 不存在、複数マッチ
- `DiaryError::InvalidArgument` — サイズ超過、上限超過、名前重複
- `DiaryError::Vault` — record_type 不正、後方互換違反

## 既存実装との統合

| S13 機能 | 統合先 | 統合方法 |
|---|---|---|
| chunk 暗号化 | `core/src/crypto/aead.rs` | FileKey で既存 `encrypt` / `decrypt` を内部で繰り返し呼ぶ |
| sha256 | `core/src/crypto/hmac_util.rs` 周辺 | 新規 `streaming::compute_sha256_streaming` |
| メタデータ署名 | `engine.dsa_sign` | AttachmentRecord.ciphertext を message に |
| HMAC | `engine.hmac` | AttachmentRecord.ciphertext に対して既存 API 流用 |
| vault.pqd I/O | `reader.rs` / `writer.rs` | record_type 分岐拡張 |
| change-password | `change_password::re_encrypt_vault` | AttachmentPlaintext を新 K_master で再暗号化、FileKey と `.bin` は維持 |
| legacy-access | `legacy::execute_legacy_access` | attachment INHERIT/DESTROY 処理追加 |
| export | `commands::cmd_export` | `<DIR>/attachments/` 生成、`![[FILE]]` 埋め込み |
| import | `importer.rs` | `attachments/` スキャン、`![[...]]` パース |

## 非機能要件の実現

| NFR | 設計上の充足策 |
|---|---|
| NFR-001 (100MB ≤ 60s) | AES-GCM 1MB chunk、HW AES サポート前提 ~100-300 MB/s |
| NFR-002 (メモリピーク ≤ chunk + vault) | streaming I/O、chunk plaintext は Zeroizing<Vec<u8>> |
| NFR-003 (1GB extract ≤ 5 分) | ~3-4 MB/s 換算 (CI runner 想定で余裕) |
| NFR-101 (chunk IV 再利用検出) | AAD に chunk_index 含める |
| NFR-102 (zeroize) | 全 chunk plaintext を ZeroizeOnDrop |
| NFR-103 (SHA-256 改ざん検出) | decrypt 後に sha256_actual == sha256_expected で検証 |
| NFR-104 (ML-DSA-65 署名) | attachment レコードも entry 同等の署名検証対象 |

## ロールバック戦略

| 失敗 | 対応 |
|---|---|
| `.bin.tmp` 書き込み失敗 | zeroize 上書き → 削除、vault.pqd 無変更 |
| vault.pqd 更新失敗 | 直前に rename 済みの `.bin` を zeroize 削除、attachment レコード未追加 |
| extract 失敗 | `--out` tmp ファイル削除 |
| delete 失敗 | attachment レコードはそのまま、ユーザーに警告 |
| legacy-access 失敗 | 新 vault.pqd.tmp + 新規 .attachments/ tmp dir を削除 |

クラッシュ等で vault.pqd に参照されない `.attachments/*.bin` が残った場合は、
次回の attachment 操作または `pq-diary verify --repair` で全 AttachmentRecord を復号し、
未参照 blob を zeroize 削除する。

## 関連文書

- [dataflow.md](dataflow.md): Mermaid シーケンス図
- [types.rs](types.rs): Rust 型定義
- [schema.md](schema.md): vault.pqd / .attachments/ フォーマット
- [cli-commands.md](cli-commands.md): CLI 仕様
- [design-interview.md](design-interview.md): 設計ヒアリング
- [../../spec/s13-attachments/requirements.md](../../spec/s13-attachments/requirements.md)

## 信頼性

- 🔵: システム概要、3 層構造、エラー型 (3 件)
- 🟡: 残り全て (chunk size 1MB、RECORD_TYPE_ATTACHMENT=0x03、API シグネチャ、
       AAD 設計、メタデータ構造)
- 🔴: なし
