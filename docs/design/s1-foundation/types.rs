// ========================================
// s1-foundation Rust型定義（設計ドキュメント）
// ========================================
//
// 作成日: 2026-04-03
// 関連設計: architecture.md
// 注意: これは設計ドキュメントであり、実際のソースコードではない。
//       実装時は core/src/ 配下の各モジュールに配置する。
//
// 信頼性レベル:
// - 🔵 青信号: PRD・要件定義・ヒアリングを参考にした確実な型定義
// - 🟡 黄信号: 妥当な推測による型定義
// - 🔴 赤信号: 推測による型定義

// ========================================
// core/src/error.rs — DiaryError
// ========================================

// 🔵 PRDセクション全体 + ヒアリングQ3 (全Phase分のバリアント)
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DiaryError {
    // --- Phase 1 ---
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),                    // 🔵 基本エラー

    #[error("configuration error: {0}")]
    Config(String),                                 // 🔵 vault.toml/config.toml パースエラー

    #[error("vault error: {0}")]
    Vault(String),                                  // 🔵 PRDセクション6 (Vaultフォーマット)

    #[error("entry error: {0}")]
    Entry(String),                                  // 🔵 PRDセクション4 (エントリ操作)

    #[error("crypto error: {0}")]
    Crypto(String),                                 // 🔵 PRDセクション5 (暗号要件)

    #[error("vault is locked")]
    NotUnlocked,                                    // 🔵 PRDセクション1.3 (施錠定義)

    #[error("git error: {0}")]
    Git(String),                                    // 🔵 PRDセクション11 (Git同期)

    #[error("editor error: {0}")]
    Editor(String),                                 // 🔵 PRDセクション4.3 ($EDITOR制御)

    // --- Phase 1 追加機能 ---
    #[error("search error: {0}")]
    Search(String),                                 // 🔵 Obsidian比較から追加

    #[error("import error: {0}")]
    Import(String),                                 // 🔵 Obsidian比較から追加

    #[error("template error: {0}")]
    Template(String),                               // 🔵 Obsidian比較から追加

    // --- Phase 2 ---
    #[error("legacy error: {0}")]
    Legacy(String),                                 // 🔵 PRDセクション7 (デジタル遺言)

    #[error("policy error: {0}")]
    Policy(String),                                 // 🔵 PRDセクション4.4 (アクセスポリシー)

    #[error("daemon error: {0}")]
    Daemon(String),                                 // 🔵 PRDセクション10 (デーモン)

    #[error("password error: {0}")]
    Password(String),                               // 🔵 PRDセクション4.2 (パスワード入力)

    #[error("invalid argument: {0}")]
    InvalidArgument(String),                        // 🔵 CLI引数バリデーション
}

// ========================================
// core/src/crypto.rs — セキュアメモリ型
// ========================================

// 🔵 PRDセクション8.1 + ヒアリングQ1 (全型定義) + ヒアリングQ2 (Box<[u8]>)
use zeroize::{Zeroize, ZeroizeOnDrop};
use secrecy::Secret;

/// ドロップ時に自動ゼロ埋めされるバイト列バッファ。
/// 内部は Box<[u8]> で固定長。再アロケートによるデータ残存リスクなし。
/// 🔵 PRDセクション8.1・ヒアリングQ2より
pub struct SecureBuffer {
    inner: Box<[u8]>,
}

impl SecureBuffer {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            inner: data.into_boxed_slice(),
        }
    }

    pub fn as_ref(&self) -> &[u8] {
        &self.inner
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl ZeroizeOnDrop for SecureBuffer {}

/// 固定長32バイト鍵のzeroize付きラッパー。
/// 🔵 PRDセクション8.1より
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ZeroizingKey {
    inner: [u8; 32],
}

impl ZeroizingKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self { inner: key }
    }

    pub fn as_ref(&self) -> &[u8; 32] {
        &self.inner
    }
}

/// マスターパスワードから導出された鍵セット。
/// 全フィールドがDrop時に自動ゼロ埋め。
/// 🔵 PRDセクション8.1より
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    pub sym_key: [u8; 32],   // AES-256-GCM 対称鍵
    pub dsa_sk: Box<[u8]>,   // ML-DSA-65 秘密鍵
    pub kem_sk: Box<[u8]>,   // ML-KEM-768 秘密鍵
}

/// 暗号エンジン。鍵の保持と施錠/解錠の状態管理。
/// 🔵 PRDセクション8.1-8.2より
pub struct CryptoEngine {
    master_key: Option<Secret<MasterKey>>,
    legacy_key: Option<Secret<[u8; 32]>>,
}

impl CryptoEngine {
    /// 施錠状態で新規作成
    pub fn new() -> Self {
        Self {
            master_key: None,
            legacy_key: None,
        }
    }

    /// 解錠状態かどうか
    pub fn is_unlocked(&self) -> bool {
        self.master_key.is_some()
    }

    // unlock() / lock() の中身は Sprint 2 で実装
}

// ========================================
// core/src/lib.rs — 公開API スケルトン
// ========================================

// 🔵 PRDセクション2.3より
pub struct DiaryCore {
    // vault_path: PathBuf,  // S3で追加
    // engine: CryptoEngine, // S2で追加
}

// DiaryCore の各メソッド (new, unlock, lock, new_entry, ...) は
// 後続Sprintで順次実装。Sprint 1 では型定義のみ。

// ========================================
// 信頼性レベルサマリー
// ========================================
// - 🔵 青信号: 全項目 (100%)
// - 🟡 黄信号: 0件 (0%)
// - 🔴 赤信号: 0件 (0%)
//
// 品質評価: 最高品質
