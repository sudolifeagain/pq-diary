// =============================================================================
// 型定義ドキュメント: s2-crypto-core
// =============================================================================
// 要件名: s2-crypto-core (Sprint 2 — 暗号コア)
// 日付: 2026-04-03
// ステータス: 確定
//
// 本ファイルはRust型定義の設計ドキュメントである。
// 実装時にcrypto/配下の各サブモジュールへ分割配置する。
//
// 設計方針:
// - 暗号文 (ciphertext) は秘密データではないため Vec<u8> を許可
// - 復号結果 (plaintext) は秘密データであるため SecureBuffer で返却
// - 全秘密鍵は SecureBuffer / ZeroizingKey で保持し、スコープ離脱時に zeroize
//
// 信頼性: 全項目 🔵 確定 (100%)
// =============================================================================

// ---------------------------------------------------------------------------
// crypto/kdf.rs — Argon2id 鍵導出
// ---------------------------------------------------------------------------

/// Argon2idパラメータ
///
/// デフォルト値:
///   memory_cost_kb = 65536 (64 MiB)
///   time_cost      = 3
///   parallelism    = 4
///
/// 最低保証値 (下回ると警告):
///   memory_cost_kb >= 19456
///   time_cost      >= 2
pub struct Argon2Params {
    pub memory_cost_kb: u32,  // デフォルト 65536
    pub time_cost: u32,       // デフォルト 3
    pub parallelism: u32,     // デフォルト 4
}

/// パスワードとソルトからマスターキー (32バイト) を導出する
///
/// Argon2idアルゴリズムを使用。
/// パラメータが最低保証値を下回る場合は警告を出力するがエラーにはしない。
pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    params: &Argon2Params,
) -> Result<ZeroizingKey, DiaryError>;

/// パラメータの最低保証値チェック
///
/// 最低保証値を下回るパラメータがある場合、該当する警告メッセージのリストを返す。
/// 全パラメータが最低保証値以上であれば空のVecを返す。
pub fn validate_params(params: &Argon2Params) -> Vec<String>;

// ---------------------------------------------------------------------------
// crypto/aead.rs — AES-256-GCM 暗号化/復号
// ---------------------------------------------------------------------------

/// Nonce サイズ (12バイト)
pub const NONCE_SIZE: usize = 12;

/// GCM 認証タグサイズ (16バイト)
pub const TAG_SIZE: usize = 16;

/// AES-256-GCMで暗号化する
///
/// - Nonceは内部でOsRngにより12バイト生成 (再利用禁止)
/// - 戻り値: (暗号文 + GCMタグ, nonce)
/// - 暗号文はVec<u8> (秘密データではないため)
pub fn encrypt(
    key: &ZeroizingKey,
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; NONCE_SIZE]), DiaryError>;

/// AES-256-GCMで復号する
///
/// - 復号結果はSecureBufferで返却 (平文は秘密データであるため)
/// - 認証タグ検証に失敗した場合はエラーを返す
pub fn decrypt(
    key: &ZeroizingKey,
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
) -> Result<SecureBuffer, DiaryError>;

// ---------------------------------------------------------------------------
// crypto/kem.rs — ML-KEM-768 鍵カプセル化
// ---------------------------------------------------------------------------

/// ML-KEM-768 鍵ペア
pub struct KemKeyPair {
    /// カプセル化鍵 (公開鍵)
    pub encapsulation_key: Vec<u8>,
    /// 脱カプセル化鍵 (秘密鍵, zeroize保護)
    pub decapsulation_key: SecureBuffer,
}

/// ML-KEM-768鍵ペアを生成する
pub fn keygen() -> Result<KemKeyPair, DiaryError>;

/// 公開鍵 (カプセル化鍵) を使って共有秘密をカプセル化する
///
/// 戻り値: (KEM暗号文, 共有秘密)
/// - KEM暗号文はVec<u8> (秘密データではない)
/// - 共有秘密はSecureBuffer (秘密データ)
pub fn encapsulate(ek: &[u8]) -> Result<(Vec<u8>, SecureBuffer), DiaryError>;

/// 秘密鍵 (脱カプセル化鍵) を使って共有秘密を復元する
///
/// 戻り値: 共有秘密 (SecureBuffer)
pub fn decapsulate(dk: &SecureBuffer, ct: &[u8]) -> Result<SecureBuffer, DiaryError>;

// ---------------------------------------------------------------------------
// crypto/dsa.rs — ML-DSA-65 デジタル署名
// ---------------------------------------------------------------------------

/// ML-DSA-65 鍵ペア
pub struct DsaKeyPair {
    /// 検証鍵 (公開鍵)
    pub verifying_key: Vec<u8>,
    /// 署名鍵 (秘密鍵, zeroize保護)
    pub signing_key: SecureBuffer,
}

/// ML-DSA-65鍵ペアを生成する
pub fn keygen() -> Result<DsaKeyPair, DiaryError>;

/// 秘密鍵でメッセージに署名する
///
/// 戻り値: 署名バイト列
pub fn sign(sk: &SecureBuffer, message: &[u8]) -> Result<Vec<u8>, DiaryError>;

/// 公開鍵で署名を検証する
///
/// 戻り値: 署名が有効ならtrue、無効ならfalse
pub fn verify(pk: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, DiaryError>;

// ---------------------------------------------------------------------------
// crypto/hmac_util.rs — HMAC-SHA256
// ---------------------------------------------------------------------------

/// HMAC-SHA256を計算する
///
/// 戻り値: 32バイトのMAC値
pub fn compute(key: &[u8], data: &[u8]) -> [u8; 32];

/// HMAC-SHA256を検証する
///
/// 定数時間比較を使用してタイミング攻撃を防止する。
/// 戻り値: MACが一致すればtrue
pub fn verify_hmac(key: &[u8], data: &[u8], expected: &[u8; 32]) -> bool;

// ---------------------------------------------------------------------------
// crypto/mod.rs — CryptoEngine 拡張
// ---------------------------------------------------------------------------

/// CryptoEngine: 暗号操作の統一エントリポイント
///
/// S1で定義済みの Option<Secret<MasterKey>> を内部に保持し、
/// 全暗号操作を提供する。
///
/// MasterKey構成:
///   - sym_key: ZeroizingKey (AES-256-GCM用 対称鍵)
///   - dsa_sk: SecureBuffer (ML-DSA-65 署名鍵)
///   - kem_sk: SecureBuffer (ML-KEM-768 脱カプセル化鍵)
impl CryptoEngine {
    /// パスワードからマスターキーを導出し、検証トークンで正当性を確認する
    ///
    /// 処理フロー:
    /// 1. Argon2idでpassword + saltから32バイト鍵を導出
    /// 2. 導出した鍵で検証トークン (verification_iv + verification_ct) を復号
    /// 3. 復号結果が元の32バイト平文と一致すれば成功
    /// 4. MasterKeyを構築しSecret<>で保持
    ///
    /// 想定レイテンシ: 1〜3秒 (Argon2id)
    pub fn unlock(
        &mut self,
        password: &[u8],
        salt: &[u8],
        params: &Argon2Params,
        verification_iv: &[u8; 12],
        verification_ct: &[u8],
    ) -> Result<(), DiaryError>;

    /// マスターキーを安全に消去しロック状態にする
    ///
    /// master_key.take() + zeroize
    pub fn lock(&mut self);

    /// AES-256-GCMで暗号化する
    ///
    /// 内部保持のsym_keyを使用。NonceはOsRngで生成。
    /// 戻り値: (暗号文, nonce)
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, [u8; NONCE_SIZE]), DiaryError>;

    /// AES-256-GCMで復号する
    ///
    /// 内部保持のsym_keyを使用。
    /// 戻り値: 平文 (SecureBuffer — 秘密データ保護)
    pub fn decrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        ciphertext: &[u8],
    ) -> Result<SecureBuffer, DiaryError>;

    /// ML-KEM-768鍵ペアを生成する
    pub fn kem_keygen(&self) -> Result<KemKeyPair, DiaryError>;

    /// ML-KEM-768でカプセル化する
    ///
    /// 戻り値: (KEM暗号文, 共有秘密)
    pub fn kem_encapsulate(&self, ek: &[u8]) -> Result<(Vec<u8>, SecureBuffer), DiaryError>;

    /// ML-KEM-768で脱カプセル化する
    ///
    /// 内部保持のkem_skを使用。
    /// 戻り値: 共有秘密 (SecureBuffer)
    pub fn kem_decapsulate(&self, ct: &[u8]) -> Result<SecureBuffer, DiaryError>;

    /// ML-DSA-65で署名する
    ///
    /// 内部保持のdsa_skを使用。
    /// 戻り値: 署名バイト列
    pub fn dsa_sign(&self, message: &[u8]) -> Result<Vec<u8>, DiaryError>;

    /// ML-DSA-65で署名を検証する
    ///
    /// 外部公開鍵を指定して検証。
    /// 戻り値: 署名が有効ならtrue
    pub fn dsa_verify(
        &self,
        pk: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, DiaryError>;

    /// HMAC-SHA256を計算する
    ///
    /// 内部保持のsym_keyを使用。
    /// 戻り値: 32バイトMAC値
    pub fn hmac(&self, data: &[u8]) -> [u8; 32];

    /// HMAC-SHA256を検証する
    ///
    /// 内部保持のsym_keyを使用。定数時間比較。
    /// 戻り値: MACが一致すればtrue
    pub fn hmac_verify(&self, data: &[u8], expected: &[u8; 32]) -> bool;
}
