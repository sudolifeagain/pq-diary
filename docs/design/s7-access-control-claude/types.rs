//! S7 Access Control + Claude 型定義
//!
//! 作成日: 2026-04-10
//! 関連設計: architecture.md
//!
//! 信頼性レベル:
//! - 🔵 青信号: EARS要件定義書・設計文書・既存実装を参考にした確実な型定義

// ========================================
// core/src/policy.rs — ポリシー評価エンジン
// ========================================

use serde::{Deserialize, Serialize};

/// アクセスポリシー（vault.toml `[access].policy`）
///
/// 🔵 信頼性: PRD 4.4 + REQ-001 + ヒアリングQ7「enum化」
///
/// serde rename_all により vault.toml との相互変換:
///   None      ↔ "none"
///   WriteOnly ↔ "write_only"
///   Full      ↔ "full"
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessPolicy {
    /// 全拒否（プライベート日記）
    None,
    /// 書き込み・sync・deleteのみ（業務メモ）
    WriteOnly,
    /// 読み書き全許可（Claude分析活用メモ）
    Full,
}

/// 🔵 信頼性: REQ-002 + AccessPolicy のデフォルト値
impl Default for AccessPolicy {
    fn default() -> Self {
        AccessPolicy::None
    }
}

/// 🔵 信頼性: REQ-050 エラーメッセージ用の表示実装
impl std::fmt::Display for AccessPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessPolicy::None => write!(f, "none"),
            AccessPolicy::WriteOnly => write!(f, "write_only"),
            AccessPolicy::Full => write!(f, "full"),
        }
    }
}

/// 🔵 信頼性: REQ-050 CLIからの文字列パース
impl std::str::FromStr for AccessPolicy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(AccessPolicy::None),
            "write_only" => Ok(AccessPolicy::WriteOnly),
            "full" => Ok(AccessPolicy::Full),
            _ => Err(format!(
                "invalid policy '{}': expected 'none', 'write_only', or 'full'",
                s
            )),
        }
    }
}

/// 操作の読み書き分類
///
/// 🔵 信頼性: PRD 4.4 Layer 3 + REQ-010 + ヒアリングQ8
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationType {
    /// read操作: list, show, search, stats, template show, template list
    Read,
    /// write操作: new, edit, delete, sync, today, template add, template delete, import
    Write,
}

/// ポリシーチェック結果
///
/// 🔵 信頼性: REQ-020〜025 4層チェック + REQ-050 エラーメッセージ
#[derive(Debug)]
pub enum PolicyDecision {
    /// 許可（通常処理へ進む）
    Allow,
    /// 拒否: ポリシーがNoneのため復号不要で即時エラー
    /// 🔵 REQ-022, REQ-101, NFR-101
    DenyNoDecrypt {
        vault_name: String,
        policy: AccessPolicy,
    },
    /// 拒否: WriteOnlyポリシーでread操作が要求された
    /// 🔵 REQ-023
    DenyOperation {
        vault_name: String,
        policy: AccessPolicy,
        operation: OperationType,
    },
}

// ========================================
// core/src/vault/init.rs — VaultManager 拡張型
// ========================================

/// vault list の出力用情報
///
/// 🔵 信頼性: REQ-033 + NFR-201 + 追加確認「名前+ポリシーのみ」
pub struct VaultInfo {
    /// Vault名（ディレクトリ名）
    pub name: String,
    /// アクセスポリシー
    pub policy: AccessPolicy,
}

// ========================================
// core/src/vault/config.rs — 変更箇所
// ========================================

// Before (現行 S6):
//   pub struct AccessSection {
//       pub policy: String,  // "none" | "write_only" | "full"
//   }

// After (S7):
//   use crate::policy::AccessPolicy;
//
//   pub struct AccessSection {
//       pub policy: AccessPolicy,  // AccessPolicy enum (serde互換)
//   }

// 🔵 信頼性: REQ-003, REQ-404 — serde(rename_all) により既存vault.toml後方互換

// ========================================
// cli/src/main.rs — clap定義変更
// ========================================

// 🔵 信頼性: REQ-030〜037 + 既存VaultCommands定義

// pub enum VaultCommands {
//     /// Create a new vault
//     Create {
//         /// Name of the new vault
//         name: String,
//         /// Access policy (none, write_only, full). Default: none
//         #[arg(long, value_parser = parse_policy)]
//         policy: Option<AccessPolicy>,
//     },
//     /// List all vaults
//     List,
//     /// Change access policy for a vault
//     Policy {
//         /// Vault name
//         name: String,
//         /// New policy (none, write_only, full)
//         policy: String,
//     },
//     /// Delete a vault
//     Delete {
//         /// Vault name
//         name: String,
//         /// Securely overwrite vault.pqd before deletion
//         #[arg(long)]
//         zeroize: bool,
//     },
// }

// ========================================
// 関数シグネチャ
// ========================================

// --- core/src/policy.rs ---

// 🔵 信頼性: REQ-020〜025 4層ポリシーチェック
// pub fn check_access(
//     claude: bool,
//     policy: AccessPolicy,
//     operation: OperationType,
//     vault_name: &str,
// ) -> PolicyDecision;

// 🔵 信頼性: REQ-010 操作分類
// pub fn classify_operation(command: &str) -> OperationType;

// --- core/src/vault/init.rs (VaultManager impl) ---

// 🔵 信頼性: REQ-030〜032
// pub fn create_vault(&self, name: &str, password: &[u8], policy: AccessPolicy)
//     -> Result<(), DiaryError>;

// 🔵 信頼性: REQ-033, REQ-201
// pub fn list_vaults_with_policy(&self) -> Result<Vec<VaultInfo>, DiaryError>;

// 🔵 信頼性: REQ-034, REQ-202
// pub fn set_policy(&self, name: &str, policy: AccessPolicy) -> Result<(), DiaryError>;

// 🔵 信頼性: REQ-035〜037
// pub fn delete_vault(&self, name: &str, zeroize: bool) -> Result<(), DiaryError>;

// 🔵 信頼性: EDGE-101, EDGE-102
// pub fn validate_vault_name(name: &str) -> Result<(), DiaryError>;

// --- core/src/lib.rs (DiaryCore impl) ---

// 🔵 信頼性: REQ-021
// pub fn access_policy(&self) -> AccessPolicy;

// 🔵 信頼性: REQ-050
// pub fn vault_name(&self) -> &str;

// --- cli/src/commands.rs ---

// 🔵 信頼性: REQ-030
// pub fn cmd_vault_create(cli: &Cli, name: &str, policy: Option<AccessPolicy>) -> Result<()>;

// 🔵 信頼性: REQ-033
// pub fn cmd_vault_list(cli: &Cli) -> Result<()>;

// 🔵 信頼性: REQ-034
// pub fn cmd_vault_policy(cli: &Cli, name: &str, policy_str: &str) -> Result<()>;

// 🔵 信頼性: REQ-035〜037
// pub fn cmd_vault_delete(cli: &Cli, name: &str, zeroize: bool) -> Result<()>;

// ========================================
// 信頼性レベルサマリー
// ========================================
// - 🔵 青信号: 全件 (100%)
// - 🟡 黄信号: 0件 (0%)
// - 🔴 赤信号: 0件 (0%)
//
// 品質評価: 高品質
