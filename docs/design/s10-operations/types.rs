//! S10 運用機能 + CLI整合性 型定義 (設計参照用)
//!
//! 作成日: 2026-05-17
//! 関連設計: architecture.md, dataflow.md
//!
//! このファイルは設計参照用の Rust 構造体定義です。実際の実装では
//! core/src/vault/config.rs, cli/src/security.rs, cli/src/commands.rs に
//! 配置されます。
//!
//! 信頼性レベル: 全項目🔵 (要件定義 + 設計ヒアリング 2026-05-17 + 既存実装パターン)

// ============================================================================
// 1. AppConfig (~/.pq-diary/config.toml)
//    配置先: core/src/vault/config.rs
//    関連要件: REQ-601 〜 REQ-611
// ============================================================================

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// アプリケーション全体の設定 (`~/.pq-diary/config.toml`)
///
/// init コマンドで作成され、sync / info などのコマンドから参照される。
/// 🔵 信頼性: REQ-601 + ヒアリング Q8 (S10 で新規実装)
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AppConfig {
    /// `[app]` セクション
    pub app: AppSection,
}

/// `[app]` セクションの中身
/// 🔵 信頼性: REQ-602, REQ-603 (デフォルト値ヒアリング確定)
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AppSection {
    /// 引数 `--vault` 省略時に使う vault 名 (デフォルト: "default")
    pub default_vault: String,
    /// `sync` コマンドが使うバックエンド名 (デフォルト: "git")
    pub sync_backend: String,
}

impl Default for AppConfig {
    /// 🔵 REQ-602, REQ-603: デフォルト値を返す
    fn default() -> Self {
        Self {
            app: AppSection {
                default_vault: "default".to_owned(),
                sync_backend: "git".to_owned(),
            },
        }
    }
}

impl AppConfig {
    /// `~/.pq-diary/config.toml` の絶対パスを返す
    ///
    /// 🔵 信頼性: ヒアリング Q1 (dirs クレート採用)
    /// 🔵 戻り値: DiaryError::Config (ホーム解決失敗時)
    pub fn default_path() -> Result<PathBuf, DiaryError> {
        let home = dirs::home_dir()
            .ok_or_else(|| DiaryError::Config("Cannot determine home directory".to_string()))?;
        Ok(home.join(".pq-diary").join("config.toml"))
    }

    /// `~/.pq-diary/vaults/` ディレクトリの絶対パスを返す
    /// 🔵 init / sync が利用
    pub fn default_vaults_dir() -> Result<PathBuf, DiaryError> {
        let home = dirs::home_dir()
            .ok_or_else(|| DiaryError::Config("Cannot determine home directory".to_string()))?;
        Ok(home.join(".pq-diary").join("vaults"))
    }

    /// TOML ファイルから読み込み
    /// 🔵 信頼性: VaultConfig::from_file パターン踏襲 (REQ-604)
    pub fn from_file(path: &Path) -> Result<Self, DiaryError> {
        let content = std::fs::read_to_string(path)?;
        toml::from_str(&content).map_err(|e| DiaryError::Config(e.to_string()))
    }

    /// TOML ファイルへ書き込み (Unix では 0o600 パーミッション設定)
    /// 🔵 信頼性: REQ-611, VaultConfig::to_file パターン踏襲
    pub fn to_file(&self, path: &Path) -> Result<(), DiaryError> {
        let content = toml::to_string(self).map_err(|e| DiaryError::Config(e.to_string()))?;
        std::fs::write(path, content)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
}

// ============================================================================
// 2. HardenStatus (info --security 用)
//    配置先: cli/src/security.rs
//    関連要件: REQ-411, REQ-412
// ============================================================================

/// プロセス強化状態のスナップショット
///
/// `info --security` コマンドから呼ばれる `harden_status()` の戻り値。
/// 各フィールドは実プロセス状態を反映する (REQ-NFR-104: ハードコード禁止)。
///
/// 🔵 信頼性: REQ-411, REQ-412, NFR-104 (S9 既存実装をリファクタ)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardenStatus {
    /// mlock / VirtualLock が有効か (現プロセスでロック済みページがあるか)
    pub mlock_active: bool,
    /// PR_SET_DUMPABLE=0 + RLIMIT_CORE=0 が両方有効か (Unix のみ意味あり、Windows では常に true)
    pub coredump_disabled: bool,
    /// 現在デバッガが接続されているか (TracerPid != 0 / IsDebuggerPresent != 0)
    pub debugger_detected: bool,
}

impl HardenStatus {
    /// 🔵 NFR-104: 各フィールドを実プロセス状態から取得
    ///
    /// Unix:
    /// - mlock_active: `secure_mem::is_locked()` (S9 で実装済み API を想定)
    /// - coredump_disabled: `/proc/self/status` の `Dumpable: 0` AND `getrlimit(RLIMIT_CORE) == (0, 0)`
    /// - debugger_detected: `/proc/self/status` の `TracerPid` を読み判定
    ///
    /// Windows:
    /// - mlock_active: `secure_mem::is_locked()` (VirtualLock の状態)
    /// - coredump_disabled: 常に true (Windows にコアダンプ概念なし)
    /// - debugger_detected: `IsDebuggerPresent()`
    pub fn current() -> Self {
        Self {
            mlock_active: query_mlock_active(),
            coredump_disabled: query_coredump_disabled(),
            debugger_detected: query_debugger_detected(),
        }
    }
}

// 内部ヘルパー (実装時に security.rs 内で定義)
fn query_mlock_active() -> bool { todo!("S9 secure_mem.rs の is_locked() を呼ぶ") }
fn query_coredump_disabled() -> bool { todo!("Unix: /proc/self/status Dumpable + getrlimit / Windows: true") }
fn query_debugger_detected() -> bool { todo!("check_debugger() ロジックを bool 返却で再利用") }

// ============================================================================
// 3. ExportEntry (export コマンド用中間表現)
//    配置先: cli/src/commands.rs (関数内のプライベート型)
//    関連要件: REQ-501 〜 REQ-503
// ============================================================================

use secrecy::SecretBox;

/// export 時の中間表現 (YAML フロントマター生成用)
///
/// `EntryPlaintext` から生成され、ファイル書き出し直後に Drop で zeroize。
///
/// 🔵 信頼性: REQ-502, REQ-503, ヒアリング 2026-05-17 確定提案 F
#[derive(Debug)]
pub struct ExportEntry {
    /// UUID v4 (生成時に固定)
    pub id: uuid::Uuid,
    /// 元エントリのタイトル
    pub title: String,
    /// タグ (順序保持)
    pub tags: Vec<String>,
    /// 作成日時 (UTC, RFC 3339)
    pub created: chrono::DateTime<chrono::Utc>,
    /// 更新日時 (UTC, RFC 3339)
    pub updated: chrono::DateTime<chrono::Utc>,
    /// 本文 (zeroize 対象)
    pub body: SecretBox<String>,
}

impl ExportEntry {
    /// 出力ファイル名を生成
    /// 🔵 REQ-502: `YYYY-MM-DD-{slug}-{id8}.md`
    pub fn filename(&self) -> String {
        let date = self.created.format("%Y-%m-%d");
        let slug = slugify(&self.title);
        let id8 = self.id.to_string().chars().take(8).collect::<String>();
        format!("{date}-{slug}-{id8}.md")
    }

    /// YAML フロントマター + 本文を生成
    /// 🔵 REQ-503: 手書き YAML (ヒアリング Q2)
    pub fn to_markdown(&self) -> String {
        // 実装時の擬似コード:
        // let mut s = String::new();
        // s.push_str("---\n");
        // s.push_str(&format!("id: {}\n", self.id));
        // s.push_str(&format!("title: \"{}\"\n", yaml_escape(&self.title)));
        // if self.tags.is_empty() {
        //     s.push_str("tags: []\n");
        // } else {
        //     s.push_str("tags:\n");
        //     for tag in &self.tags {
        //         s.push_str(&format!("  - {}\n", yaml_escape(tag)));
        //     }
        // }
        // s.push_str(&format!("created: {}\n", self.created.to_rfc3339()));
        // s.push_str(&format!("updated: {}\n", self.updated.to_rfc3339()));
        // s.push_str("---\n\n");
        // s.push_str(self.body.expose_secret());
        // s
        todo!()
    }
}

/// タイトルからファイル名に使える slug を生成
///
/// 🔵 EDGE-103: 空・制御文字のみは "untitled"
/// - 空白/タブ/改行 → `-`
/// - パス禁止文字 (`/\:*?"<>|`) → 除去
/// - 連続する `-` を 1 つに圧縮
/// - 先頭末尾の `-` を除去
/// - 結果が空なら "untitled"
fn slugify(title: &str) -> String { todo!() }

/// YAML 文字列内でエスケープが必要な文字 (`"` と `\`) を処理
fn yaml_escape(s: &str) -> String { todo!() }

// ============================================================================
// 4. ChangePasswordContext (change-password の中間状態)
//    配置先: cli/src/commands.rs (関数内のプライベート型)
//    関連要件: REQ-301 〜 REQ-314
// ============================================================================

use secrecy::SecretString;

/// change-password 実行中の状態を保持する一時構造体
///
/// Drop で全フィールドが zeroize される (各フィールドが ZeroizeOnDrop 系)。
///
/// 🔵 信頼性: REQ-302, NFR-101, NFR-105
pub struct ChangePasswordContext {
    /// 旧パスワード
    pub old_password: SecretString,
    /// 新パスワード
    pub new_password: SecretString,
    /// 旧鍵 (Argon2 で導出)
    pub old_key: ZeroizingKey,
    /// 新鍵 (Argon2 で導出)
    pub new_key: ZeroizingKey,
    /// 全エントリの平文 (中間バッファ)
    pub entries: Vec<EntryPlaintext>,
}

// 既存型の参照 (実装は core/ にあり)
pub struct ZeroizingKey(/* [u8; 32] zeroize on drop */);
pub struct EntryPlaintext { /* ... ZeroizeOnDrop */ }

// ============================================================================
// 5. CLI 引数構造体 (clap derive)
//    配置先: cli/src/main.rs (Commands enum 内)
//    関連要件: REQ-501 (export DIR 引数)
// ============================================================================

use clap::Args;

/// `export` サブコマンドの引数
///
/// 🔵 REQ-501: ディレクトリ引数を受け取る
#[derive(Args, Debug)]
pub struct ExportArgs {
    /// 出力先ディレクトリ (既存である必要あり、REQ-512)
    pub dir: PathBuf,
}

/// `info` サブコマンドの引数
///
/// 🔵 REQ-411: --security フラグ
#[derive(Args, Debug)]
pub struct InfoArgs {
    /// セキュリティ詳細を表示
    #[arg(long)]
    pub security: bool,
}

// ============================================================================
// 6. DiaryError バリアント (既存、追加なし)
//    配置先: core/src/error.rs
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum DiaryError {
    /// vault.toml / config.toml パース・検証エラー
    #[error("config error: {0}")]
    Config(String),
    /// パスワード関連エラー (空、不正等)
    #[error("password error: {0}")]
    Password(String),
    /// vault 操作エラー (既存・不存在等)
    #[error("vault error: {0}")]
    Vault(String),
    /// 暗号操作エラー (Argon2, AES-GCM 等)
    #[error("crypto error: {0}")]
    Crypto(String),
    /// I/O エラー
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// 引数不正
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}

// ============================================================================
// 信頼性レベルサマリー
// ============================================================================
// 🔵 青信号: 全 6 セクション (100%)
// 🟡 黄信号: 0 件
// 🔴 赤信号: 0 件
//
// 品質評価: 最高品質。全項目が要件定義 + 設計ヒアリング (Q1〜Q3) + 既存 VaultConfig パターン
// で確定済み。実装時に todo!() の中身を埋めるのみ。
