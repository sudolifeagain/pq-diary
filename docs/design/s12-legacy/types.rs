//! S12 デジタル遺言 型定義 (設計参照用)
//!
//! 実際の実装では:
//! - core/src/legacy.rs (新規モジュール)
//! - core/src/vault/config.rs (LegacySection 追加)
//! - cli/src/commands.rs (cmd_legacy_*)
//!
//! 信頼性: 全項目🔵

use crate::error::DiaryError;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::Zeroizing;

// ============================================================================
// 1. LegacyKeyDeriver trait (Phase 3 Shamir 拡張のため抽象化)
//    配置: core/src/legacy.rs
//    関連要件: NFR-102, ヒアリング Q7
// ============================================================================

/// 死後アクセスコードから K_legacy を導出するトレイト。
///
/// Phase 1 (S12): `Argon2LegacyDeriver` のみ実装。
/// Phase 3: `ShamirLegacyDeriver` (M-of-N コード合成) を追加予定。
///
/// 🔵 NFR-102 + ヒアリング Q7 (Shamir 拡張余地)
pub trait LegacyKeyDeriver: Send + Sync {
    /// `code` (生 bytes) と vault の `legacy_salt` から K_legacy [u8; 32] を導出する。
    ///
    /// # Errors
    /// Argon2id 計算失敗 (極稀) で `DiaryError::Crypto`。
    fn derive(
        &self,
        code: &[u8],
        salt: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, DiaryError>;
}

/// Phase 1 デフォルト実装。`crypto::kdf::derive_key` (Argon2id) をラップ。
///
/// 🔵 設計判断 Q3: K_master と同じ Argon2 パラメータを使う
pub struct Argon2LegacyDeriver {
    pub params: crate::crypto::kdf::Argon2Params,
}

impl LegacyKeyDeriver for Argon2LegacyDeriver {
    fn derive(
        &self,
        code: &[u8],
        salt: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, DiaryError> {
        crate::crypto::kdf::derive_key(code, salt, &self.params)
    }
}

// ============================================================================
// 2. LegacyFlag (INHERIT / DESTROY)
//    配置: core/src/legacy.rs (or core/src/vault/format.rs)
//    関連要件: REQ-201, REQ-202
// ============================================================================

/// エントリの遺言フラグ。
/// vault.pqd エントリレコードの 1 バイトフィールドにマップ。
///
/// 🔵 PRD §7.2 + REQ-201/202
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LegacyFlag {
    Destroy = 0x00,  // デフォルト
    Inherit = 0x01,
}

impl LegacyFlag {
    pub fn from_byte(b: u8) -> Result<Self, DiaryError> {
        match b {
            0x00 => Ok(LegacyFlag::Destroy),
            0x01 => Ok(LegacyFlag::Inherit),
            other => Err(DiaryError::Vault(format!("unknown legacy flag: 0x{:02x}", other))),
        }
    }
}

// ============================================================================
// 3. LegacySection (vault.toml [legacy])
//    配置: core/src/vault/config.rs
//    関連要件: REQ-701〜704, ヒアリング Q4
// ============================================================================

/// vault.toml の `[legacy]` セクション。
/// 🔵 REQ-701〜704
#[derive(Debug, PartialEq, Serialize, Deserialize, Default)]
pub struct LegacySection {
    /// `legacy init` 完了したら true。
    #[serde(default)]
    pub initialized: bool,

    /// `legacy-access` 実行時の確認 UI 方式。デフォルト `Timer30`。
    #[serde(default = "default_confirmation")]
    pub destroy_confirmation: ConfirmationMode,
}

/// 確認方式の選択肢。
/// 🔵 ヒアリング Q4/Q5
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationMode {
    /// 30 秒タイマー + y/N (デフォルト、UX バランス良)
    Timer30,
    /// 即時 y/N (シンプル)
    Yn,
    /// コンフィルフレーズ手動入力 `DESTROY ALL` (最厳格)
    Phrase,
}

impl Default for ConfirmationMode {
    fn default() -> Self {
        ConfirmationMode::Timer30
    }
}

fn default_confirmation() -> ConfirmationMode {
    ConfirmationMode::Timer30
}

/// VaultConfig に `legacy` フィールド追加 (S12)。
/// 🔵 既存 VaultConfig 拡張、後方互換性のため `#[serde(default)]`
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct VaultConfig {
    pub vault: VaultSection,
    pub access: AccessSection,
    pub git: GitSection,
    pub argon2: Argon2Section,
    #[serde(default)]  // 既存 Phase 1 vault でも問題なく読める
    pub legacy: LegacySection,
}

// (VaultSection / AccessSection / GitSection / Argon2Section は既存、変更なし)
pub struct VaultSection { /* 既存 */ }
pub struct AccessSection { /* 既存 */ }
pub struct GitSection { /* 既存 */ }
pub struct Argon2Section { /* 既存 */ }

// ============================================================================
// 4. LegacyEntryStatus (legacy list 用)
//    配置: core/src/legacy.rs
//    関連要件: REQ-301
// ============================================================================

#[derive(Debug, Clone)]
pub struct LegacyEntryStatus {
    pub uuid_prefix: String,    // 8 文字
    pub title: String,
    pub flag: LegacyFlag,
    pub updated_at: u64,        // UNIX timestamp
}

// ============================================================================
// 5. LegacyAccessReport (legacy-access 完了報告)
//    配置: core/src/legacy.rs
//    関連要件: REQ-508
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub struct LegacyAccessReport {
    pub inherited: usize,  // 継承したエントリ数
    pub destroyed: usize,  // 削除したエントリ数
}

// ============================================================================
// 6. core/src/legacy.rs 公開関数
// ============================================================================

/// `pq-diary legacy init` 相当の処理。
///
/// 🔵 REQ-101〜111
pub fn initialize_legacy(
    vault_dir: &Path,
    master_pwd: &SecretString,
    legacy_code: &SecretString,
    confirmation: ConfirmationMode,
    deriver: &dyn LegacyKeyDeriver,
) -> Result<(), DiaryError> { todo!() }

/// `pq-diary legacy set <id> --inherit | --destroy` 相当。
///
/// 🔵 REQ-201〜205
pub fn set_entry_flag(
    vault_dir: &Path,
    master_pwd: &SecretString,
    legacy_code: Option<&SecretString>,
    id_prefix: &str,
    flag: LegacyFlag,
    deriver: &dyn LegacyKeyDeriver,
) -> Result<(), DiaryError> { todo!() }

/// `pq-diary legacy list` 相当。
///
/// 🔵 REQ-301〜303
pub fn list_legacy_status(
    vault_dir: &Path,
    master_pwd: &SecretString,
) -> Result<Vec<LegacyEntryStatus>, DiaryError> { todo!() }

/// `pq-diary legacy rotate` 相当。
/// 戻り値: 再暗号化した INHERIT エントリ数
///
/// 🔵 REQ-401〜405
pub fn rotate_legacy_code(
    vault_dir: &Path,
    master_pwd: &SecretString,
    old_code: &SecretString,
    new_code: &SecretString,
    deriver: &dyn LegacyKeyDeriver,
) -> Result<usize, DiaryError> { todo!() }

/// `pq-diary legacy-access` 相当。
///
/// `confirm_callback` で UI 確認を CLI 側に委譲 (core はテスト容易性のため UI に依存しない)。
///
/// 🔵 REQ-501〜508
pub fn execute_legacy_access<F>(
    vault_dir: &Path,
    legacy_code: &SecretString,
    deriver: &dyn LegacyKeyDeriver,
    confirm_callback: F,
) -> Result<LegacyAccessReport, DiaryError>
where
    F: FnOnce(ConfirmationMode) -> Result<bool, DiaryError>,
{ todo!() }

// ============================================================================
// 7. CLI 引数構造体 (clap derive)
//    配置: cli/src/main.rs
//    関連要件: REQ-205, REQ-801〜802
// ============================================================================

use clap::Subcommand;

/// `Commands::Legacy { subcommand: LegacyCommands }` の中身
/// 🔵 既存 (S10 で hide 化、S12 で hide 解除 + Set 引数追加)
#[derive(Subcommand, Debug)]
pub enum LegacyCommands {
    Init,
    Rotate,
    Set {
        /// Entry ID prefix
        id: String,
        /// Mark entry as INHERIT
        #[arg(long, conflicts_with = "destroy")]
        inherit: bool,
        /// Mark entry as DESTROY
        #[arg(long, conflicts_with = "inherit")]
        destroy: bool,
    },
    List,
}

// ============================================================================
// 信頼性レベル
// ============================================================================
// 🔵: 全 7 セクション (100%)
