# S4: エントリ操作 + CLI — アーキテクチャ設計

> **スプリント**: S4 (entry-ops-cli)
> **ステータス**: 全項目 DECIDED
> **関連要件定義**: [requirements.md](../../spec/entry-ops-cli/requirements.md)

---

## 1. システム概要 🔵

*PRD §2.2, §4.1, 要件定義書より*

`core/src/entry.rs` にエントリ CRUD ロジックを実装し、`cli/` にパスワード入力・$EDITOR 制御・コマンドハンドラを配置する。

S3 で実装済みの vault.pqd 読み書き (`vault::reader` / `vault::writer`) と `CryptoEngine` (暗号化・署名・HMAC) を基盤とし、エントリの作成・一覧・表示・編集・削除の全操作を提供する。

---

## 2. モジュール構成 🔵

*既存プロジェクト構造 + PRD §2.1, §2.2より*

### core/ (新規・変更)

| ファイル | 責務 | 状態 |
|---------|------|------|
| `core/src/entry.rs` | エントリ CRUD ロジック、`EntryPlaintext` シリアライズ、IDプレフィックス解決、タグバリデーション | **新規実装** |
| `core/src/lib.rs` | `DiaryCore` ファサードにエントリ操作メソッド追加 | **変更** |
| `core/src/error.rs` | `DiaryError` に S4 固有バリアントを必要に応じて追加 | **変更（軽微）** |

### cli/ (新規・変更)

| ファイル | 責務 | 状態 |
|---------|------|------|
| `cli/src/password.rs` | 3段階パスワード取得 (`--password` > env > TTY)、プラットフォーム別 TTY 実装 | **新規** |
| `cli/src/editor.rs` | $EDITOR 起動、セキュア一時ファイル管理、ヘッダーコメントパース、zeroize 削除 | **新規** |
| `cli/src/commands.rs` | new / list / show / edit / delete コマンドハンドラ | **新規** |
| `cli/src/main.rs` | clap 定義に S4 フィールド追加、dispatch を commands.rs に委譲 | **変更** |

---

## 3. 依存追加 🔵

*要件 REQ-081 (serde_json)、ADR-0003 (termios/windows-sys)より*

### core/Cargo.toml

```toml
serde_json = "1"         # EntryPlaintext のシリアライズ/デシリアライズ
```

### cli/Cargo.toml

```toml
[target.'cfg(unix)'.dependencies]
nix = { version = "0.29", features = ["term"] }    # termios (ECHO 無効化)

[target.'cfg(windows)'.dependencies]
windows-sys = { version = "0.59", features = [
    "Win32_System_Console",          # SetConsoleMode, GetConsoleMode
    "Win32_Security",                # ACL 操作
    "Win32_Storage_FileSystem",      # CreateFileW
] }
```

---

## 4. 主要型 🔵

*要件 REQ-081, PRD §2.3, 既存 EntryRecord + CryptoEngine より*

| 型名 | 配置 | 概要 |
|------|------|------|
| `EntryPlaintext` | `entry.rs` | エントリの平文ペイロード。`{ title, tags, body }` を serde_json でシリアライズ |
| `EntryMeta` | `entry.rs` | list 表示用メタデータ。UUID プレフィックス・タイトル・タグ・日時 |
| `Tag` | `entry.rs` | バリデーション済みタグ (ネスト対応、Obsidian 互換) |
| `IdPrefix` | `entry.rs` | バリデーション済み ID プレフィックス (最小 4 文字) |
| `PasswordSource` | `password.rs` | パスワード取得元の列挙型 (Flag / Env / Tty) |
| `EditorConfig` | `editor.rs` | $EDITOR 設定 (コマンド名、vim オプション、セキュア一時ディレクトリ) |
| `HeaderComment` | `editor.rs` | ヘッダーコメントパース結果 `{ title, tags, body }` |

---

## 5. core 層の設計 🔵

*PRD §2.3 公開 API、要件 REQ-001〜REQ-005より*

### 5.1 EntryPlaintext (暗号化ペイロード)

```rust
#[derive(Serialize, Deserialize)]
pub struct EntryPlaintext {
    pub title: String,
    pub tags: Vec<String>,
    pub body: String,
}
```

暗号化フロー: `EntryPlaintext` → `serde_json::to_vec()` → `CryptoEngine::encrypt()` → `EntryRecord.ciphertext`

復号フロー: `EntryRecord.ciphertext` → `CryptoEngine::decrypt()` → `serde_json::from_slice()` → `EntryPlaintext`

OQ-7 (`--debug` JSON 出力) との親和性が高い。

### 5.2 エントリ CRUD 関数

`core/src/entry.rs` に配置。vault.pqd の read-modify-write パターンで操作する。

```rust
/// エントリを新規作成し vault.pqd に追記して UUID を返す
pub fn create_entry(
    vault_path: &Path,
    engine: &CryptoEngine,
    plaintext: &EntryPlaintext,
) -> Result<Uuid, DiaryError>;

/// 全エントリのメタデータを復号して返す (ソート・フィルタは呼び出し側)
pub fn list_entries(
    vault_path: &Path,
    engine: &CryptoEngine,
) -> Result<Vec<EntryMeta>, DiaryError>;

/// ID プレフィックスでエントリを検索し復号して返す
pub fn get_entry(
    vault_path: &Path,
    engine: &CryptoEngine,
    prefix: &IdPrefix,
) -> Result<(EntryRecord, EntryPlaintext), DiaryError>;

/// エントリのメタデータ・本文を更新する
pub fn update_entry(
    vault_path: &Path,
    engine: &CryptoEngine,
    uuid: [u8; 16],
    plaintext: &EntryPlaintext,
) -> Result<(), DiaryError>;

/// エントリを削除する
pub fn delete_entry(
    vault_path: &Path,
    engine: &CryptoEngine,
    uuid: [u8; 16],
) -> Result<(), DiaryError>;
```

### 5.3 IDプレフィックス解決 🔵

*要件 REQ-041〜REQ-043より*

```rust
pub struct IdPrefix(String);

impl IdPrefix {
    /// 最小 4 文字の hex 文字列を検証
    pub fn new(s: &str) -> Result<Self, DiaryError>;

    /// EntryRecord の UUID と前方一致比較
    pub fn matches(&self, uuid: &[u8; 16]) -> bool;
}
```

解決ロジック:
1. 全 EntryRecord の UUID を hex 化してプレフィックス比較
2. 一意マッチ → Ok
3. 複数マッチ → `DiaryError::Entry("複数のエントリがマッチしました: ...")`
4. マッチなし → `DiaryError::Entry("エントリが見つかりません")`

### 5.4 タグバリデーション 🔵

*要件 REQ-071〜REQ-073、Obsidian タグ仕様より*

```rust
pub struct Tag(String);

impl Tag {
    /// タグ文字列をバリデーション・正規化
    /// - 先頭/末尾スラッシュ除去
    /// - スペース禁止、空文字禁止
    /// - 英数字・Unicode・_・-・/ 許容
    pub fn new(s: &str) -> Result<Self, DiaryError>;

    /// 前方一致フィルタ: self が other のプレフィックスか
    pub fn is_prefix_of(&self, other: &Tag) -> bool;
}
```

### 5.5 DiaryCore ファサード拡張 🔵

*PRD §2.3より*

```rust
impl DiaryCore {
    pub fn new(vault_path: &str) -> Result<Self, DiaryError>;
    pub fn unlock(&mut self, password: SecretString) -> Result<(), DiaryError>;
    pub fn lock(&mut self);
    pub fn new_entry(&self, title: &str, body: &str, tags: Vec<String>) -> Result<String, DiaryError>;
    pub fn list_entries(&self, query: Option<&str>) -> Result<Vec<EntryMeta>, DiaryError>;
    pub fn get_entry(&self, id: &str) -> Result<(EntryRecord, EntryPlaintext), DiaryError>;
    pub fn update_entry(&self, id: &str, plaintext: &EntryPlaintext) -> Result<(), DiaryError>;
    pub fn delete_entry(&self, id: &str) -> Result<(), DiaryError>;
}
```

---

## 6. cli 層の設計 🔵

*ADR-0003、要件 REQ-051〜REQ-065より*

### 6.1 パスワード入力 (password.rs)

3 段階の優先順位で取得:

| 優先順位 | ソース | 実装 |
|---------|--------|------|
| 1 | `--password` フラグ | `Cli.password` → `SecretString` に変換 + 警告表示 |
| 2 | `PQ_DIARY_PASSWORD` 環境変数 | `std::env::var()` → `SecretString` に変換 |
| 3 | TTY プロンプト | Unix: `termios` ECHO 無効化 / Windows: `SetConsoleMode` |

TTY 実装:
- **Unix**: `nix::sys::termios` で `ECHO` フラグを無効化。1 バイトずつ読み取り `SecretString` に直接追加。終了後に `ECHO` 復元
- **Windows**: `windows_sys::Win32::System::Console` の `SetConsoleMode` で `ENABLE_ECHO_INPUT` を無効化。`ReadConsoleW` で読み取り

### 6.2 $EDITOR 制御 (editor.rs)

**セキュア一時ディレクトリ** 🔵

*要件 REQ-061, REQ-065より*

```rust
fn secure_tmpdir() -> Result<PathBuf, DiaryError> {
    #[cfg(unix)] {
        // /dev/shm > /run/user/$UID > /tmp (フォールバック + 警告)
    }
    #[cfg(windows)] {
        // %LOCALAPPDATA%\pq-diary\tmp\ (ACL 設定)
    }
}
```

**エディタ起動** 🔵

*要件 REQ-062, REQ-063より*

```rust
fn launch_editor(tmpfile: &Path) -> Result<(), DiaryError> {
    let editor = std::env::var("EDITOR")
        .unwrap_or_else(|_| if cfg!(windows) { "notepad".into() } else { "vi".into() });

    let mut cmd = Command::new(&editor);

    // vim/neovim: swap/backup/undo 無効化
    if editor.contains("vim") || editor.contains("nvim") {
        cmd.args(["-c", "set noswapfile nobackup noundofile"]);
    }

    cmd.arg(tmpfile)
       .env("TMPDIR", secure_tmpdir)
       .env("TEMP", secure_tmpdir)
       .env("TMP", secure_tmpdir)
       .status()?;
}
```

**ヘッダーコメント形式** 🔵

*要件 REQ-082, REQ-083より*

書き出しフォーマット:
```
# Title: {title}
# Tags: {tag1}, {tag2}, {tag3}
# ---

{body}
```

パース: `# Title:` / `# Tags:` / `# ---` 行を順に読み取り、`# ---` 以降を本文とする。
ヘッダー不正時: エラーを表示し、元のメタデータを保持。本文の変更のみ適用。

**zeroize 削除** 🔵

*要件 REQ-064より*

```rust
fn secure_delete(path: &Path) -> Result<(), DiaryError> {
    let len = fs::metadata(path)?.len() as usize;
    let mut buf = vec![0u8; len];
    OsRng.fill_bytes(&mut buf);
    fs::write(path, &buf)?;
    fs::remove_file(path)?;
    Ok(())
}
```

### 6.3 clap 定義更新 🔵

*要件 REQ-001〜REQ-005, REQ-011〜REQ-022より*

```rust
#[derive(Subcommand)]
pub enum Commands {
    /// 新規エントリ作成
    New {
        /// エントリタイトル
        title: Option<String>,
        /// 本文 (指定時は $EDITOR を起動しない)
        #[arg(short, long)]
        body: Option<String>,
        /// タグ (複数指定可)
        #[arg(short, long)]
        tag: Vec<String>,
    },
    /// エントリ一覧
    List {
        /// タグフィルタ (前方一致)
        #[arg(long)]
        tag: Option<String>,
        /// タイトル検索クエリ
        #[arg(short, long)]
        query: Option<String>,
        /// 表示件数 (デフォルト 20)
        #[arg(short, long, default_value = "20")]
        number: usize,
    },
    /// エントリ全文表示
    Show {
        /// ID プレフィックス (最小 4 文字)
        id: String,
    },
    /// エントリ編集
    Edit {
        /// ID プレフィックス (最小 4 文字)
        id: String,
        /// タイトル変更 ($EDITOR を起動しない)
        #[arg(long)]
        title: Option<String>,
        /// タグ追加 ($EDITOR を起動しない)
        #[arg(long)]
        add_tag: Vec<String>,
        /// タグ削除 ($EDITOR を起動しない)
        #[arg(long)]
        remove_tag: Vec<String>,
    },
    /// エントリ削除
    Delete {
        /// ID プレフィックス (最小 4 文字)
        id: String,
        /// 確認プロンプトをスキップ
        #[arg(short, long)]
        force: bool,
    },
    // ... 他のコマンド (変更なし)
}
```

---

## 7. read-modify-write パターン 🔵

*既存 vault::reader/writer の設計より*

全エントリ操作は以下のパターンに従う:

1. `reader::read_vault()` で vault.pqd 全体を読み込み `(VaultHeader, Vec<EntryRecord>)` を取得
2. メモリ上で `Vec<EntryRecord>` を変更 (追加・更新・削除)
3. `writer::write_vault()` で vault.pqd 全体を再書き込み (ランダムパディング再生成)

**注意**: vault.pqd がロック中にクラッシュした場合のデータ喪失リスクがある。Phase 2 のデーモン方式で排他制御を導入予定。S4 では単一プロセスアクセスを前提とする。

---

## 8. セキュリティ考慮事項 🔵

*PRD §1.2 設計原則、§4.2, §4.3, §16.1より*

- **パスワード**: `SecretString` で保持。使用後は `zeroize` 自動実行。`--password` の値も即座に `SecretString` に変換
- **復号データ**: `CryptoEngine::decrypt()` が返す `SecureBuffer` はスコープ終了時に zeroize
- **一時ファイル**: セキュアディレクトリに作成。編集完了後にランダム上書き + 削除
- **$TMPDIR 上書き**: エディタが `/tmp` を使わないよう環境変数を制御
- **vim swap/backup/undo**: 明示的に無効化
- **Windows ACL**: セキュア一時ディレクトリにオーナーのみ RW 権限を設定
- **EntryPlaintext の寿命**: JSON デシリアライズ結果は表示後に即スコープ破棄（`String` の zeroize は保証外だが、mlock は Phase 2）

---

## 9. パフォーマンス考慮 🔵

*PRD §12.1より*

| 操作 | 目標 | 実現方法 |
|------|------|---------|
| new / edit | < 200ms | Argon2id は unlock 時のみ。暗号化・書き込みは軽量 |
| list (100件) | < 500ms | 全エントリ復号が必要だが、EntryPlaintext の title/tags のみ使用。body の parse は遅延不可 (JSON 全体を復号する必要があるため) |
| unlock | 1-3s | Argon2id (64MB, 3反復) による意図的な遅延 |

**最適化候補** (S4 スコープ外):
- list 高速化: タイトル・タグのみの暗号化フィールドを別途持つ (vault.pqd v5 で検討)
- キャッシュ: デーモンモード (Phase 2) で復号済みメタデータをメモリキャッシュ

---

## 10. 関連文書

- **データフロー**: [dataflow.md](dataflow.md)
- **型定義**: [types.rs](types.rs)
- **要件定義**: [requirements.md](../../spec/entry-ops-cli/requirements.md)
- **ユーザストーリー**: [user-stories.md](../../spec/entry-ops-cli/user-stories.md)
- **受け入れ基準**: [acceptance-criteria.md](../../spec/entry-ops-cli/acceptance-criteria.md)
- **S3 設計**: [../s3-vault-storage/architecture.md](../s3-vault-storage/architecture.md)

## 信頼性レベルサマリー

- 🔵 青信号: 全項目 (100%)
- 🟡 黄信号: 0件
- 🔴 赤信号: 0件

**品質評価**: 高品質 — 全設計項目が PRD・ADR・要件定義・ヒアリング・既存実装に裏付けられている
