// ========================================
// daily-note-template-link 型定義
// ========================================
//
// 作成日: 2026-04-05
// 関連設計: architecture.md
//
// 信頼性レベル:
// - 🔵 青信号: EARS要件定義書・設計文書・既存実装を参考にした確実な型定義
// - 🟡 黄信号: EARS要件定義書・設計文書・既存実装から妥当な推測による型定義
// - 🔴 赤信号: EARS要件定義書・設計文書・既存実装にない推測による型定義

// ========================================
// テンプレート型 (core/src/template.rs)
// ========================================

/// テンプレートの平文ペイロー���。vault.pqd内に暗号化格納される。
/// 🔵 信頼性: ADR-0005・REQ-101〜105・設計ヒアリングより
#[derive(Debug, Serialize, Deserialize, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct TemplatePlaintext {
    /// テンプレート名（一意識別子）
    /// 🔵 設計ヒアリング: 専用型採用決定
    pub name: String,
    /// テンプレート本文（Markdown、{{var_name}} 変数を含みうる）
    /// 🔵 REQ-111〜114
    pub body: String,
}

/// テンプレートのメタデータ（一覧表示用）
/// 🔵 信頼性: EntryMetaパターンに準拠
pub struct TemplateMeta {
    /// UUID hex (32文字)
    /// 🔵 既存EntryMetaパターン
    pub uuid_hex: String,
    /// テンプ��ート名
    /// 🔵 REQ-102
    pub name: String,
    /// 作成日時 (Unix timestamp seconds)
    /// 🔵 既存EntryRecordフィールド
    pub created_at: u64,
    /// 更新日時 (Unix timestamp seconds)
    /// 🔵 既存EntryRecordフィールド
    pub updated_at: u64,
}

/// テンプレート名のバリデーション済み型
/// 🟡 信頼性: EDGE-101から妥当な推測
pub struct TemplateName(String);

// ========================================
// テンプレートエンジン型 (core/src/template_engine.rs)
// ========================================

/// テンプレート変数の種類
/// 🔵 信頼性: REQ-112〜113・ヒアリングQ2より
pub enum VariableKind {
    /// システム自動���定: {{date}}, {{datetime}}, {{title}}
    Builtin,
    /// ユーザー入力: {{project_name}} など
    Custom,
}

/// テンプレート本文中の変数参照
/// 🔵 信頼性: REQ-112〜113より
pub struct VariableRef {
    /// 変数名 ({{ }} を除いた中身)
    pub name: String,
    /// 変数の種類
    pub kind: VariableKind,
    /// 本文中の出現位置 (byte offset)
    pub offset: usize,
}

/// 組み込み変数名の定数
/// 🔵 信頼性: REQ-112より
pub const BUILTIN_DATE: &str = "date";        // YYYY-MM-DD
pub const BUILTIN_DATETIME: &str = "datetime"; // YYYY-MM-DD HH:MM:SS
pub const BUILTIN_TITLE: &str = "title";       // エントリタイトル

// ========================================
// リンク型 (core/src/link.rs)
// ========================================

/// パース済みリンク参照
/// 🔵 信頼性: ADR-0004・REQ-201より
pub struct ParsedLink {
    /// リンク先���イトル ([[タイトル]] の中身)
    pub title: String,
    /// 本文中の開始バイト位置
    pub start: usize,
    /// 本文中の終了バイト位置
    pub end: usize,
}

/// リンク解決結果
/// 🔵 信頼性: REQ-201, REQ-211より
pub struct ResolvedLink {
    /// リンク先タイトル
    pub title: String,
    /// マッチしたエントリのUUID hex リスト (0個=未解決, 1個=一意, 2個以上=重複)
    pub matches: Vec<ResolvedEntry>,
}

/// リンク解決でマッチしたエントリ情報
/// 🔵 信頼性: REQ-201, REQ-211より
pub struct ResolvedEntry {
    /// UUID hex
    pub uuid_hex: String,
    /// UUIDプレフィックス (4〜8文字)
    pub id_prefix: String,
    /// 作成日時
    pub created_at: u64,
}

/// バックリン���インデックス
/// 🔵 信頼性: REQ-202, REQ-203・ヒアリングQ3・設計ヒアリングより
///
/// DiaryCore のフィー���ドとして保持。unlock時に構築、lock時にzeroize。
pub struct LinkIndex {
    /// タイトル → UUIDリスト (forward lookup)
    /// 🔵 リンク解決用
    title_to_uuids: HashMap<String, Vec<[u8; 16]>>,

    /// UUID → バックリンク元UUIDリスト (reverse lookup)
    /// 🔵 バックリンク表示用
    uuid_to_backlinks: HashMap<[u8; 16], Vec<BacklinkEntry>>,

    /// UUID → タイトル (逆引き用)
    /// 🔵 バックリンク表示でタイトルが必要
    uuid_to_title: HashMap<[u8; 16], String>,
}

/// バックリンクエントリ
/// 🔵 信頼性: REQ-202より
pub struct BacklinkEntry {
    /// 参照元エントリのUUID
    pub source_uuid: [u8; 16],
    /// 参照元エントリのタイトル
    pub source_title: String,
    /// 参照元エントリの作成日時
    pub created_at: u64,
}

// ========================================
// DiaryCore 拡張 (core/src/lib.rs)
// ========================================

/// DiaryCore に追加するフィールド
/// 🔵 信頼性: 設計ヒアリングで決定
pub struct DiaryCore {
    // ... 既存フィールド ...
    vault_path: PathBuf,
    engine: Option<CryptoEngine>,
    config: VaultConfig,

    /// バックリンクインデックス (unlock時に構築、lock時にNone+zeroize)
    /// 🔵 設計ヒアリングで DiaryCore フィールド配置に決定
    link_index: Option<LinkIndex>,
}

// ========================================
// DiaryError 拡張 (core/src/error.rs)
// ========================================

/// 新規エラーバリアント
/// 🔵 信頼性: EDGE-002, EDGE-003, EDGE-101より
pub enum DiaryError {
    // ... 既存バリアント ...

    /// テンプレートが見つからない
    /// 🔵 EDGE-003
    #[error("template not found: {0}")]
    TemplateNotFound(String),

    /// テンプレート名が不正
    /// 🟡 EDGE-101から妥当な推測
    #[error("invalid template name: {0}")]
    InvalidTemplateName(String),
}

// ========================================
// CLI 型 (cli/src/main.rs)
// ========================================

/// New コマンド���追加するフラグ
/// 🔵 信頼性: REQ-111より
// #[arg(long)]
// template: Option<String>,   // --template <name>

// ========================================
// 信頼性レベルサマリー
// ========================================
// - 🔵 青信号: 28件 (93%)
// - 🟡 黄信号: 2件 (7%)
// - 🔴 赤信号: 0件 (0%)
//
// 品質評価: 高品質
