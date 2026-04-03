// S3: Vault フォーマット + ストレージ — Rust 型定義
//
// スプリント: S3 (s3-vault-storage)
// ステータス: 全項目 DECIDED
//
// このファイルは設計ドキュメントであり、実装時の型定義リファレンスとして使用する。
// 実際のコードは core/src/vault/ 以下の各モジュールに配置する。

// =============================================================================
// vault/format.rs — 定数・構造体
// =============================================================================

/// vault.pqd マジックバイト
pub const MAGIC: &[u8; 8] = b"PQDIARY\0";

/// 現行スキーマバージョン (v4)
pub const SCHEMA_VERSION: u8 = 0x04;

/// 固定ヘッダ部分のサイズ (バイト)
/// マジック(8) + バージョン(1) + フラグ(1) + 予約(2) + ペイロードサイズ(4)
/// + KDFソルト(32) + Legacyソルト(32) + 検証IV(12) + 検証暗号文(48)
/// + KEM公開鍵オフセット(32) + DSA公開鍵ハッシュ(32) = 204
pub const HEADER_SIZE: usize = 204;

/// レコード種別: エントリ
pub const RECORD_TYPE_ENTRY: u8 = 0x01;

/// レコード種別: テンプレート
pub const RECORD_TYPE_TEMPLATE: u8 = 0x02;

/// vault.pqd v4 ヘッダ構造体
///
/// バイナリフォーマットの固定ヘッダ部分 + 可変長秘密鍵ブロックを保持する。
/// マジックバイトとスキーマバージョンは読み込み時に検証済みのため、
/// 構造体には含めない (schema_version は情報として保持)。
pub struct VaultHeader {
    /// スキーマバージョン (0x04)
    pub schema_version: u8,

    /// フラグ (将来拡張用)
    pub flags: u8,

    /// ペイロードサイズ (エントリセクション + パディングの合計、LE u32)
    pub payload_size: u32,

    /// KDF ソルト (Argon2id 用、32バイト)
    pub kdf_salt: [u8; 32],

    /// Legacy ソルト (Legacy 継承用、32バイト)
    pub legacy_salt: [u8; 32],

    /// 検証トークン IV (AES-256-GCM 用、12バイト)
    pub verification_iv: [u8; 12],

    /// 検証トークン暗号文 (32バイト平文 + 16バイト GCM タグ = 48バイト)
    pub verification_ct: Vec<u8>,

    /// ML-KEM 公開鍵オフセット (32バイト)
    pub kem_pk_offset: [u8; 32],

    /// ML-DSA 公開鍵ハッシュ (SHA-256、32バイト)
    pub dsa_pk_hash: [u8; 32],

    /// ML-KEM 暗号化済み秘密鍵 (可変長)
    pub kem_encrypted_sk: Vec<u8>,

    /// ML-DSA 暗号化済み秘密鍵 (可変長)
    pub dsa_encrypted_sk: Vec<u8>,
}

/// エントリレコード構造体
///
/// vault.pqd のエントリセクション内の 1 レコードを表す。
/// 各フィールドはバイナリフォーマットの順序に対応する。
pub struct EntryRecord {
    /// エントリ UUID (16バイト、UUID v4)
    pub uuid: [u8; 16],

    /// 作成日時 (Unix タイムスタンプ、LE u64)
    pub created_at: u64,

    /// 更新日時 (Unix タイムスタンプ、LE u64)
    pub updated_at: u64,

    /// AES-256-GCM 初期化ベクトル (12バイト)
    pub iv: [u8; 12],

    /// 暗号文 + GCM タグ (可変長)
    pub ciphertext: Vec<u8>,

    /// ML-DSA-65 署名 (可変長)
    pub signature: Vec<u8>,

    /// コンテンツ HMAC-SHA256 (32バイト)
    pub content_hmac: [u8; 32],

    /// Legacy フラグ (0x00 = DESTROY, 0x01 = INHERIT)
    pub legacy_flag: u8,

    /// Legacy 鍵ブロック (可変長、通常は空)
    pub legacy_key_block: Vec<u8>,

    /// 添付ファイルカウント (Phase 2 予約、0 固定)
    pub attachment_count: u16,

    /// 添付ファイルオフセット (Phase 2 予約、0 固定)
    pub attachment_offset: u64,

    /// パディング (ランダム、可変長)
    pub padding: Vec<u8>,
}

// =============================================================================
// vault/config.rs — serde 構造体
// =============================================================================

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// vault.toml のトップレベル構造体
#[derive(Serialize, Deserialize)]
pub struct VaultConfig {
    /// Vault 基本設定
    pub vault: VaultSection,

    /// アクセス制御設定
    pub access: AccessSection,

    /// Git 連携設定
    pub git: GitSection,

    /// Argon2id パラメータ
    pub argon2: Argon2Section,
}

/// vault.toml [vault] セクション
#[derive(Serialize, Deserialize)]
pub struct VaultSection {
    /// Vault 名 (ディレクトリ名と一致)
    pub name: String,

    /// スキーマバージョン
    pub schema_version: u32,
}

/// vault.toml [access] セクション
#[derive(Serialize, Deserialize)]
pub struct AccessSection {
    /// アクセスポリシー: "none" | "write_only" | "full"
    pub policy: String,
}

/// vault.toml [git] セクション
#[derive(Serialize, Deserialize)]
pub struct GitSection {
    /// Git コミット著者名
    pub author_name: String,

    /// Git コミット著者メール
    pub author_email: String,

    /// Git コミットメッセージテンプレート
    pub commit_message: String,

    /// Git プライバシー設定
    pub privacy: GitPrivacySection,
}

/// vault.toml [git.privacy] セクション
#[derive(Serialize, Deserialize)]
pub struct GitPrivacySection {
    /// タイムスタンプのファジング幅 (時間)
    pub timestamp_fuzz_hours: u64,

    /// 追加パディング最大バイト数
    pub extra_padding_bytes_max: usize,
}

/// vault.toml [argon2] セクション
#[derive(Serialize, Deserialize)]
pub struct Argon2Section {
    /// メモリコスト (KB)
    pub memory_cost_kb: u32,

    /// 時間コスト (反復回数)
    pub time_cost: u32,

    /// 並列度
    pub parallelism: u32,
}

/// config.toml のトップレベル構造体
#[derive(Serialize, Deserialize)]
pub struct AppConfig {
    /// デフォルト設定
    pub defaults: DefaultsSection,

    /// デーモン設定
    pub daemon: DaemonSection,
}

/// config.toml [defaults] セクション
#[derive(Serialize, Deserialize)]
pub struct DefaultsSection {
    /// デフォルト Vault 名
    pub vault: String,
}

/// config.toml [daemon] セクション
#[derive(Serialize, Deserialize)]
pub struct DaemonSection {
    /// ソケットディレクトリ
    pub socket_dir: String,

    /// タイムアウト秒数
    pub timeout_secs: u64,
}

// =============================================================================
// vault/init.rs — VaultManager
// =============================================================================

/// マルチ Vault 管理構造体
///
/// `~/.pq-diary/` を基点として、複数の Vault の作成・一覧取得・
/// デフォルト Vault の解決を行う。
pub struct VaultManager {
    /// ベースディレクトリ (~/.pq-diary/)
    base_dir: PathBuf,

    /// アプリケーション設定 (config.toml から読み込み)
    app_config: AppConfig,
}

impl VaultManager {
    /// 新しい VaultManager を生成する。
    /// base_dir 内の config.toml を読み込み、存在しなければデフォルト設定で作成する。
    pub fn new(base_dir: PathBuf) -> Result<Self, DiaryError> {
        todo!()
    }

    /// 指定名の Vault を初期化する。
    /// ディレクトリ作成、鍵生成 (ML-KEM, ML-DSA)、vault.pqd 書き出し、
    /// vault.toml 生成、entries/ ディレクトリ作成を行う。
    pub fn init_vault(&self, name: &str, password: &[u8]) -> Result<(), DiaryError> {
        todo!()
    }

    /// 利用可能な Vault 名の一覧を返す。
    /// ~/.pq-diary/vaults/ 以下のディレクトリ名を列挙する。
    pub fn list_vaults(&self) -> Result<Vec<String>, DiaryError> {
        todo!()
    }

    /// 指定名の Vault ディレクトリパスを返す。
    /// ~/.pq-diary/vaults/{name}/
    pub fn vault_path(&self, name: &str) -> PathBuf {
        todo!()
    }

    /// デフォルト Vault 名を返す。
    /// config.toml の defaults.vault の値を返す。
    pub fn default_vault(&self) -> &str {
        todo!()
    }
}

// =============================================================================
// vault/reader.rs — 読み込み関数
// =============================================================================

use std::io::Read;
use std::path::Path;

/// vault.pqd ファイルを読み込み、ヘッダとエントリレコードの一覧を返す。
///
/// マジックバイト検証、バージョン検証を行い、不正な場合は DiaryError::Vault を返す。
pub fn read_vault(path: &Path) -> Result<(VaultHeader, Vec<EntryRecord>), DiaryError> {
    todo!()
}

/// バイトストリームからヘッダを読み込む。
/// 固定 204 バイト + 可変長秘密鍵ブロックをパースする。
pub fn read_header(reader: &mut impl Read) -> Result<VaultHeader, DiaryError> {
    todo!()
}

/// バイトストリームからエントリレコードを逐次読み込む。
/// レコード長が 0 のとき読み込み完了とみなす。
pub fn read_entries(reader: &mut impl Read) -> Result<Vec<EntryRecord>, DiaryError> {
    todo!()
}

// =============================================================================
// vault/writer.rs — 書き込み関数
// =============================================================================

use std::io::Write;

/// vault.pqd ファイルにヘッダとエントリレコードを書き込む。
///
/// ファイル末尾に 512-4096 バイトのランダムパディングを付与する。
/// ファイル権限は 0o600 で設定する。
pub fn write_vault(
    path: &Path,
    header: &VaultHeader,
    entries: &[EntryRecord],
) -> Result<(), DiaryError> {
    todo!()
}

/// バイトストリームにヘッダを書き出す。
/// マジックバイト、バージョン、固定フィールド、可変長秘密鍵ブロックの順で出力する。
pub fn write_header(writer: &mut impl Write, header: &VaultHeader) -> Result<(), DiaryError> {
    todo!()
}

/// バイトストリームにエントリレコードを逐次書き出す。
/// 各レコードの先頭にレコード長 (LE u32) を付与する。
/// 全レコード書き出し後、レコード長 0 を終端マーカーとして出力する。
pub fn write_entries(
    writer: &mut impl Write,
    entries: &[EntryRecord],
) -> Result<(), DiaryError> {
    todo!()
}
