//! S13 添付ファイル 型定義 (設計参照用)
//!
//! 実際の実装では:
//! - core/src/attachment.rs (新規モジュール)
//! - core/src/crypto/streaming.rs (新規モジュール)
//! - core/src/vault/format.rs (RECORD_TYPE_ATTACHMENT + AttachmentRecord 追加)
//! - core/src/legacy.rs (execute_legacy_access の拡張)
//! - cli/src/commands.rs (cmd_attachment_*)
//! - cli/src/main.rs (Commands::Attachment + AttachmentCommands)
//!
//! 信頼性レベル: 全項目 🟡 (PRD §10 明示なし、設計判断)

use crate::error::DiaryError;
use secrecy::SecretString;
use std::path::Path;
use uuid::Uuid;
use zeroize::Zeroizing;

// ============================================================================
// 1. RECORD_TYPE_ATTACHMENT + AttachmentRecord
//    配置: core/src/vault/format.rs
//    関連要件: REQ-103, REQ-902
// ============================================================================

/// 新レコードタイプ (既存 ENTRY=0x01, TEMPLATE=0x02 に並列)。
pub const RECORD_TYPE_ATTACHMENT: u8 = 0x03;

/// vault.pqd 内の添付メタデータレコード。
///
/// 本体 (バイナリ) は別ファイル `<vault_dir>/.attachments/<uuid>.bin` に
/// 1MB chunk の AES-256-GCM で保存される。このレコードは:
/// - 添付の同定情報 (uuid, entry_uuid, filename)
/// - 整合性検証 (sha256, content_hmac, signature)
/// - サイズ情報 (size_bytes, chunk_count)
/// - 表示メタデータ (mime_type, created_at)
/// - S12 legacy 連動 (legacy_flag, legacy_key_block)
/// を保持する。
#[derive(Debug, Clone)]
pub struct AttachmentRecord {
    pub record_type: u8,           // 0x03
    pub uuid: [u8; 16],            // attachment UUID
    pub entry_uuid: [u8; 16],      // 紐付くエントリ UUID
    pub created_at: u64,           // Unix seconds
    pub filename: String,          // 元ファイル名 (extension 含む)
    pub mime_type: String,         // 例: "image/jpeg"、"application/pdf"
    pub size_bytes: u64,           // plaintext サイズ
    pub chunk_count: u32,          // ceil(size_bytes / 1MB)
    pub sha256: [u8; 32],          // plaintext の SHA-256
    pub content_hmac: [u8; 32],    // メタデータ全体の HMAC-SHA256
    pub signature: Vec<u8>,        // ML-DSA-65 over (sha256 || filename || size)
    pub legacy_flag: u8,           // S12 連動: 0x00 = Destroy, 0x01 = Inherit
    pub legacy_key_block: Vec<u8>, // S12 連動: K_legacy で暗号化されたアクセス情報
    pub padding: Vec<u8>,          // 0-255B のランダムパディング
}

// ============================================================================
// 2. EntryRecord の attachment_count / attachment_offset 使用
//    配置: core/src/vault/format.rs (既存)
//    関連要件: REQ-902
// ============================================================================

// EntryRecord は変更なし。以下の既存フィールドの意味づけが変わる:
//
// pub attachment_count: u16,
//   このエントリに紐付く AttachmentRecord の個数。
//   0 なら添付なし、最大 65535 (Phase 1 では 256 に制限)。
//
// pub attachment_offset: u64,
//   vault.pqd 内の attachment レコード群の起点バイトオフセット (LE)。
//   実装上は不要 (record_type で線形スキャン可能) だが、将来の
//   ランダムアクセス最適化のため予約継続。Phase 1 ではゼロでも可。

// ============================================================================
// 3. streaming AES-256-GCM
//    配置: core/src/crypto/streaming.rs
//    関連要件: REQ-105, NFR-101, NFR-102
// ============================================================================

/// chunk size = 1 MiB。1GB ファイルで chunk_count = 1024。
pub const CHUNK_SIZE: usize = 1024 * 1024;

/// 添付ファイル本体 (.bin) の chunk ごとの構造:
///
///   [chunk_iv: 12B][chunk_ciphertext_with_tag: chunk_len + 16B]
///
/// AAD = chunk_index (LE u32) || total_chunks (LE u32) || file_uuid (16B)
///
/// reader は plaintext を `writer` に書き出し、(total_bytes_read, sha256) を返す。
pub fn encrypt_stream<R: std::io::Read, W: std::io::Write>(
    key: &[u8; 32],
    file_uuid: &[u8; 16],
    reader: &mut R,
    writer: &mut W,
) -> Result<(u64, [u8; 32]), DiaryError> {
    todo!()
}

/// 復号は逆順に chunk を読み、AAD 一致と SHA-256 一致を検証。
pub fn decrypt_stream<R: std::io::Read, W: std::io::Write>(
    key: &[u8; 32],
    file_uuid: &[u8; 16],
    expected_size: u64,
    expected_sha256: &[u8; 32],
    reader: &mut R,
    writer: &mut W,
) -> Result<(), DiaryError> {
    todo!()
}

// ============================================================================
// 4. AttachmentMeta (CLI 表示用、本体取り出さない)
//    配置: core/src/attachment.rs
//    関連要件: REQ-201, NFR-201
// ============================================================================

#[derive(Debug, Clone)]
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

// ============================================================================
// 5. core/src/attachment.rs 公開 API
// ============================================================================

/// `pq-diary attachment add <ENTRY_ID> <FILE>` 相当。戻り値: 添付 UUID。
///
/// 🟡 REQ-101 〜 REQ-105
pub fn add_attachment(
    vault_dir: &Path,
    master_pwd: &SecretString,
    entry_id_prefix: &str,
    source_path: &Path,
) -> Result<Uuid, DiaryError> {
    todo!()
}

/// `pq-diary attachment list [<ENTRY_ID>]` 相当。
/// `entry_id_prefix == None` で vault 全体の添付を一覧。
///
/// 🟡 REQ-201
pub fn list_attachments(
    vault_dir: &Path,
    master_pwd: &SecretString,
    entry_id_prefix: Option<&str>,
) -> Result<Vec<AttachmentMeta>, DiaryError> {
    todo!()
}

/// `pq-diary attachment extract <ENTRY_ID> <FILE> --out <PATH>` 相当。
///
/// 🟡 REQ-202, REQ-203
pub fn extract_attachment(
    vault_dir: &Path,
    master_pwd: &SecretString,
    entry_id_prefix: &str,
    filename: &str,
    out_path: &Path,
) -> Result<(), DiaryError> {
    todo!()
}

/// `pq-diary attachment delete <ENTRY_ID> <FILE>` 相当。
/// メタデータ削除 + `.attachments/<uuid>.bin` を zeroize 上書きして物理削除。
///
/// 🟡 REQ-301, REQ-302
pub fn delete_attachment(
    vault_dir: &Path,
    master_pwd: &SecretString,
    entry_id_prefix: &str,
    filename: &str,
) -> Result<(), DiaryError> {
    todo!()
}

/// `pq-diary attachment set <ENTRY_ID> <FILE> --inherit | --destroy` 相当。
///
/// 🟡 REQ-501 〜 REQ-503
pub fn set_attachment_legacy_flag(
    vault_dir: &Path,
    master_pwd: &SecretString,
    legacy_code_opt: Option<&SecretString>,
    entry_id_prefix: &str,
    filename: &str,
    flag: crate::legacy::LegacyFlag,
    deriver: &dyn crate::legacy::LegacyKeyDeriver,
) -> Result<(), DiaryError> {
    todo!()
}

// ============================================================================
// 6. CLI 引数構造体 (clap derive)
//    配置: cli/src/main.rs
//    関連要件: REQ-401, REQ-501, etc.
// ============================================================================

use clap::Subcommand;
use std::path::PathBuf;

/// `Commands::Attachment { subcommand: AttachmentCommands }` の中身。
/// 🟡 cli-commands.md の仕様を反映
#[derive(Subcommand, Debug)]
pub enum AttachmentCommands {
    /// Add a binary file to an entry.
    Add {
        /// Entry ID prefix
        entry: String,
        /// Path to the file to attach
        path: PathBuf,
    },
    /// List attachments (entire vault if no entry given).
    List {
        /// Optional entry ID prefix
        entry: Option<String>,
    },
    /// Extract an attachment to a file path.
    Extract {
        entry: String,
        filename: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Delete an attachment (zeroize-overwrite + remove).
    Delete {
        entry: String,
        filename: String,
        #[arg(long)]
        force: bool,
    },
    /// Set the legacy flag on an attachment (S12 integration).
    Set {
        entry: String,
        filename: String,
        #[arg(long, conflicts_with = "destroy")]
        inherit: bool,
        #[arg(long, conflicts_with = "inherit")]
        destroy: bool,
    },
}

// `new` コマンドへの追加引数:
// #[arg(long = "attach", value_name = "FILE")]
// pub attach: Vec<PathBuf>,

// ============================================================================
// 7. legacy 統合 (S12 拡張)
//    配置: core/src/legacy.rs (改訂)
// ============================================================================

/// 既存 `LegacyAccessReport` を拡張:
///
/// pub struct LegacyAccessReport {
///     pub inherited_entries: usize,
///     pub destroyed_entries: usize,
///     pub inherited_attachments: usize,   // S13 追加
///     pub destroyed_attachments: usize,   // S13 追加
/// }

// 内部処理の擬似コード:
//
// for each entry in old_vault:
//   if entry.legacy_flag == INHERIT:
//     inherited_entries++
//     for each attachment in entry's attachments:
//       if attachment.legacy_flag == INHERIT:
//         decrypt with K_legacy + AAD
//         move .attachments/<uuid>.bin to new vault
//         inherited_attachments++
//       else:  // DESTROY
//         zeroize + delete .attachments/<uuid>.bin
//         destroyed_attachments++
//   else:  // DESTROY entry → 全 attachment も DESTROY (REQ-504)
//     destroyed_entries++
//     for each attachment in entry's attachments:
//       zeroize + delete .attachments/<uuid>.bin
//       destroyed_attachments++

// ============================================================================
// 8. export/import 統合
//    配置: cli/src/commands.rs (cmd_export), core/src/importer.rs (拡張)
// ============================================================================

// export の MD 内リンク追加:
//
// pub fn cmd_export(cli: &Cli, dir: PathBuf) -> anyhow::Result<()> {
//     // ... 既存処理
//     for entry in entries:
//         let attachments = list_attachments(&vault, &master, Some(entry.id))?;
//         for att in attachments:
//             extract_attachment(&vault, &master, &entry.id, &att.filename,
//                                &dir.join("attachments").join(&att.filename))?;
//             body.push_str(&format!("\n\n![[{}]]", att.filename));
//         write_md(...)
// }
//
// import の `![[FILE]]` パース (importer.rs):
//
// pub fn parse_obsidian_attachment_links(body: &str) -> Vec<String> {
//     // regex: \!\[\[([^\]]+)\]\]
//     // returns: ["a.png", "b.pdf", ...]
// }

// ============================================================================
// 信頼性レベル
// ============================================================================
// 🟡: 全 8 セクション (PRD §10 明示なし、設計判断)
// 🔵: 該当なし
// 🔴: 該当なし
//
// PR review で🟡→🔵に昇格させたい項目:
// - CHUNK_SIZE = 1MB の妥当性
// - RECORD_TYPE_ATTACHMENT = 0x03 (新タイプ vs entry 拡張)
// - メタデータ構造 (filename / MIME / sha256 で足りるか)
