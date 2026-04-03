# pq-diary 要件定義書 v4.0（統合・確定版）

**言語**: Rust  
**ステータス**: 定義済み・未実装  
**作成日**: 2026-04-02  
**改訂履歴**:
- v0.1: 初版（Python実装、暗号化基本設計）
- v0.2: Git同期・セキュアメモリ消去追加
- v0.3: 静的・動的解析防御追加
- v1.0: 言語をRustに変更。全要件をRustの観点で再検討・統合
- v2.0: PQCライブラリ選定確定・パスワード渡し方式確定・マルチVault設計・Claudeアクセスポリシー設計追加
- v3.0: Gitプライバシー強化・デジタル遺言機能・モバイル対応準備のためのクレート分割設計・Argon2idメモリコスト設定可能化
- v4.0: **多角的暗号攻撃分析による未対策盲点2件の発見と対処・FDE脅威モデル整理・HQCロードマップ追加・AES-256量子耐性根拠の文書化・OQ追加**

---

## 0. v3.0 → v4.0 の変更点サマリー

| 変更項目 | v3.0の状態 | v4.0での決定 |
|---|---|---|
| $EDITOR一時ファイル | **未対策（盲点）** | **$TMPDIRの制御・vimオプション強制・Phase 1で対処** |
| vault.tomlメタデータ | **平文漏洩（未対策）** | **機密タイムスタンプフィールドを削除・最小化** |
| 暗号攻撃分析 | 未整理 | **15種の攻撃ベクター分析を追加（新セクション16）** |
| FDE脅威モデル | 簡略記述のみ | **FDEとpq-diaryの役割分担を明文化** |
| HQCロードマップ | 「将来検討」のみ | **Phase 4として具体的スケジュールと組み込み方針を追加** |
| AES-256量子耐性 | 主張のみ | **米国科学アカデミー・IETFの根拠を明記** |
| OQ | 19件 | **OQ-20〜OQ-22を追加（固定ブロックサイズ化・vault.toml最小化・HQCハイブリッド）** |

---

## 1. プロジェクト概要

### 1.1 目的

量子コンピュータによる将来の解読（Harvest Now, Decrypt Later攻撃を含む）と、
現在のフォレンジック・マルウェアによる解析の両方に耐える、
CLI日記ツールをRustで実装する。

### 1.2 設計原則

1. **Vault = Single Source of Truth**: `vault.pqd`が唯一の正データ。`entries/*.md`はローカルキャッシュ
2. **平文はメモリ内に最小時間だけ存在する**: 操作完了後は即座に`zeroize`
3. **ディスクに平文を書かない**: 一時ファイルを含む（$EDITORの一時ファイルも含む）
4. **防御は多層で**: アプリ層の対策を第一層とし、OS・ハードウェア層の対策をドキュメントで案内する
5. **限界は正直に文書化する**: 実現不可能な保証をユーザーに与えない
6. **アクセス可用性はユーザーが明示的に選択する**: Claudeへの公開範囲はセットアップ時に確認・承認を取る
7. **コアロジックはライブラリクレートとして分離する**: `pq-diary-core`クレートにすべてのドメインロジックを集約し、CLIバイナリは薄いラッパーとする。将来のモバイル対応（UniFFI経由）に備える
8. **メタデータも機密である**: vault.tomlに記録するフィールドは最小限とし、タイムスタンプ等の機密性の高い情報は含めない

### 1.3 用語定義

| 用語 | 定義 |
|---|---|
| Vault | `vault.pqd` ファイルと `vault.toml`（ポリシー設定）の組 |
| 解錠 | マスターパスワードを使って対称鍵をメモリに展開した状態 |
| 施錠 | 対称鍵・秘密鍵をメモリから完全消去した状態 |
| SecretBytes | `zeroize`クレートで保護された、ドロップ時に自動ゼロ埋めされるバイト列 |
| entries/ | 平文Markdownファイルのローカルキャッシュディレクトリ（Vault単位で独立） |
| アクセスポリシー | VaultごとのClaude Codeからのアクセス可用性設定（`none`/`write_only`/`full`） |
| INHERIT | 遺言設定：死後アクセスコードで復号可能なエントリ |
| DESTROY | 遺言設定：死後アクセスコード実行時に即座に消去されるエントリ |
| K_master | マスターパスワードから導出された対称鍵 |
| K_legacy | 死後アクセスコードから導出された遺言専用対称鍵 |
| K_entry | 各エントリの暗号化に使われるランダムな対称鍵 |
| FDE | Full Disk Encryption（ディスク全体暗号化）。pq-diaryが守れない物理攻撃への唯一の対策 |

---

## 2. クレート構成（モバイル対応準備）

### 2.1 Cargoワークスペース構成

```
pq-diary/
├── Cargo.toml              # workspace定義
├── core/                   # pq-diary-core（ライブラリクレート）
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs          # 公開API（UniFFI互換型シグネチャ）
│       ├── vault.rs        # Vaultフォーマット読み書き
│       ├── crypto.rs       # 暗号化ロジック全体
│       ├── entry.rs        # エントリCRUD
│       ├── git.rs          # Git同期（プラットフォーム分岐）
│       ├── legacy.rs       # デジタル遺言機能
│       └── policy.rs       # アクセスポリシー判定
└── cli/                    # pq-diary（CLIバイナリ）
    ├── Cargo.toml
    └── src/
        └── main.rs         # 薄いラッパー（termios・PR_SET_DUMPABLE・$EDITOR制御）
```

### 2.2 coreに入れるもの / 入れないもの

**coreに入れる（プラットフォーム非依存）：**
- 暗号化・復号ロジック全体
- Vaultフォーマットの読み書き
- エントリのCRUD
- Git同期ロジック（プラットフォーム別分岐込み）
- アクセスポリシー判定
- パスワード処理（SecretString）
- デジタル遺言ロジック

**coreに入れない（プラットフォーム依存）：**
- termiosプロンプト → cli/
- `PR_SET_DUMPABLE` → cli/
- `mlock` → `#[cfg(unix)]`で条件分岐
- `$EDITOR`制御・一時ファイル管理 → cli/
- `TMPDIR`環境変数の上書き → cli/

### 2.3 公開API設計（UniFFI互換）

```rust
pub struct DiaryCore { /* ... */ }

impl DiaryCore {
    pub fn new(vault_path: &str) -> Result<Self, DiaryError>;
    pub fn unlock(&mut self, password: SecretString) -> Result<(), DiaryError>;
    pub fn lock(&mut self);
    pub fn new_entry(&self, title: &str, body: &str, tags: Vec<String>) -> Result<String, DiaryError>;
    pub fn list_entries(&self, query: Option<&str>) -> Result<Vec<EntryMeta>, DiaryError>;
    pub fn get_entry(&self, id: &str) -> Result<Entry, DiaryError>;
    pub fn delete_entry(&self, id: &str) -> Result<(), DiaryError>;
    pub fn sync_git(&self) -> Result<(), DiaryError>;
    pub fn legacy_access(&mut self, code: SecretString) -> Result<LegacyAccessResult, DiaryError>;
}
```

### 2.4 git操作のプラットフォーム分岐

```rust
#[cfg(not(any(target_os = "ios", target_os = "android")))]
fn git_push_impl(repo_path: &Path, opts: &GitOptions) -> Result<()> {
    // git CLIを呼び出す（デスクトップ）
    std::process::Command::new("git").args(["push"]).current_dir(repo_path).status()?;
    Ok(())
}

#[cfg(any(target_os = "ios", target_os = "android"))]
fn git_push_impl(repo_path: &Path, opts: &GitOptions) -> Result<()> {
    // git2クレートを使用（Phase 3で実装）
    Err(DiaryError::NotImplemented("mobile git"))
}
```

---

## 3. ディレクトリ構造

### 3.1 マルチVault構造

```
~/.pq-diary/
├── config.toml
└── vaults/
    ├── private/
    │   ├── vault.pqd
    │   ├── vault.toml
    │   ├── entries/
    │   └── .git/
    └── notes/
        ├── vault.pqd
        ├── vault.toml
        └── entries/
```

### 3.2 vault.toml 仕様（v4.0・メタデータ最小化）

v3.0から`created`・`policy_confirmed_at`などのタイムスタンプフィールドを削除する。
これらはGitコミット履歴から漏洩する平文情報であり、攻撃者に「Vault作成日時」「ポリシー変更日時」を与える。

```toml
[vault]
name = "private"
schema_version = 4

[access]
# none / write_only / full
policy = "none"

[git]
author_name  = "pq-diary"
author_email = "a3f9b2c1@localhost"   # Vault初期化時に生成・固定
commit_message = "update"

[git.privacy]
timestamp_fuzz_hours = 6
extra_padding_bytes_max = 4096

[argon2]
memory_cost_kb = 65536
time_cost = 3
parallelism = 4
```

**削除したフィールド（v3.0比）：**
- `[vault].created` → Gitの最初のコミット日時から推測可能なので削除しても意味なし、かつ明示的な情報提供を避ける
- `[access].policy_confirmed_at` → ポリシー変更の日時を平文で残さない

### 3.3 config.toml 仕様

```toml
[defaults]
vault = "private"

[daemon]
socket_dir = ""
timeout_secs = 3600
```

---

## 4. 機能要件

### 4.1 コマンド体系

```
# === Vault管理 ===
pq-diary init
pq-diary vault create <n> [--policy <POLICY>]
pq-diary vault list
pq-diary vault policy <n> <POLICY>
pq-diary vault delete <n>

# === エントリ操作 ===
pq-diary [-v VAULT] new [TITLE] [-t TAG] [-b BODY]
pq-diary [-v VAULT] list [--tag TAG] [-q QUERY] [-n N]
pq-diary [-v VAULT] show <ID_PREFIX>
pq-diary [-v VAULT] edit <ID_PREFIX>
pq-diary [-v VAULT] delete <ID_PREFIX>
pq-diary [-v VAULT] sync
pq-diary [-v VAULT] export [DIR]

# === Vault設定 ===
pq-diary [-v VAULT] change-password
pq-diary [-v VAULT] info [--security]

# === Git同期 ===
pq-diary [-v VAULT] git-init [--remote URL]
pq-diary [-v VAULT] git-push
pq-diary [-v VAULT] git-pull
pq-diary [-v VAULT] git-sync
pq-diary [-v VAULT] git-status

# === デジタル遺言 ===
pq-diary [-v VAULT] legacy init
pq-diary [-v VAULT] legacy rotate
pq-diary [-v VAULT] legacy set <ID> --inherit
pq-diary [-v VAULT] legacy set <ID> --destroy
pq-diary [-v VAULT] legacy list
pq-diary [-v VAULT] legacy-access

# === デーモン（Phase 2） ===
pq-diary daemon start [-v VAULT]
pq-diary daemon stop
pq-diary daemon status
pq-diary daemon lock

# === Claude Code向け ===
pq-diary --claude [-v VAULT] new [TITLE]
pq-diary --claude [-v VAULT] list
pq-diary --claude [-v VAULT] show <ID>
pq-diary --claude [-v VAULT] sync
```

### 4.2 パスワード入力（優先順位付き）

1. `--password` フラグ（最優先・非推奨）
   - シェル履歴に平文記録・`/proc/<pid>/cmdline`からworld-readable
   - MITRE ATT&CK T1552.003として分類
   - 使用時に警告を表示

2. `PQ_DIARY_PASSWORD` 環境変数（推奨）
   - `/proc/<pid>/environ`はオーナーとrootのみ読み取り可能
   - Phase 1のClaude Code連携ではこれを推奨

3. TTYプロンプト（デフォルト・最も安全）
   - termiosを自前実装（`rpassword`クレートは不採用）
   - 入力を直接`SecretString`に格納

### 4.3 $EDITORの一時ファイル制御（v4.0新規）

`pq-diary edit`でエントリを編集する際、$EDITORが以下に平文を書き出す可能性がある：

```
/tmp/            # world-readable
~/.vim/swapfiles/ # vimのswapファイル
~/.local/share/recently-used.xbel # 最近使ったファイル履歴
```

**対策（cli/src/main.rsで実装）：**

```rust
fn launch_editor(tmpfile: &Path) -> Result<()> {
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());

    // 一時ファイルを /dev/shm または /run/user/$UID/ に作成
    let secure_tmp = secure_tmpdir()?;

    // vimの場合はswapファイルを無効化
    let args: Vec<String> = if editor.contains("vim") || editor.contains("nvim") {
        vec!["-c".into(), "set noswapfile nobackup noundofile".into(),
             tmpfile.to_string_lossy().into()]
    } else {
        vec![tmpfile.to_string_lossy().into()]
    };

    // $TMPDIR を安全なディレクトリに上書き（エディタが/tmpを使わないように）
    std::process::Command::new(&editor)
        .args(&args)
        .env("TMPDIR", &secure_tmp)
        .env("TEMP",   &secure_tmp)
        .env("TMP",    &secure_tmp)
        .status()?;

    Ok(())
}

fn secure_tmpdir() -> Result<PathBuf> {
    // 優先順位: /dev/shm > /run/user/$UID > /tmp（最終フォールバック）
    let uid = nix::unistd::getuid().as_raw();
    let candidates = [
        PathBuf::from("/dev/shm"),
        PathBuf::from(format!("/run/user/{}", uid)),
    ];
    for dir in &candidates {
        if dir.exists() {
            return Ok(dir.clone());
        }
    }
    Ok(PathBuf::from("/tmp"))  // フォールバック（警告を表示）
}
```

編集終了後に一時ファイルをzeroize（ランダムデータで上書き）してから削除する。

### 4.4 Claude Code連携

#### ポリシーチェック

```
Layer 1: --claude フラグ確認
Layer 2: アクセスポリシー確認
         → none      : 即時拒否（復号試行なし）
         → write_only: 操作種別チェックへ
         → full      : 通常処理
Layer 3: write_only時 read系は拒否
Layer 4: 通常処理
```

#### アクセスポリシー

| ポリシー | 操作 | 用途 |
|---|---|---|
| `none` | 全拒否 | プライベート日記 |
| `write_only` | 書き込み・sync・deleteのみ | 業務メモ |
| `full` | 読み書き全許可 | Claude分析活用メモ |

`full`選択時の警告（セットアップ時）：
```
警告: "full"を設定すると日記内容がAnthropicのAPIサーバーを通過します。
      間接プロンプトインジェクション等のリスクがあります。
      本当に許可しますか？ [y/N]:
```

---

## 5. 暗号要件

### 5.1 暗号スタック（確定版）

| レイヤー | アルゴリズム | クレート | 規格 | 量子耐性 |
|---|---|---|---|---|
| 鍵導出 | Argon2id | `argon2` | — | ✅ |
| データ暗号化 | AES-256-GCM | `aes-gcm` | — | ✅（128bit相当残存・後述） |
| 鍵カプセル化 | ML-KEM-768 | `ml-kem`（RustCryptoフォーク） | NIST FIPS 203 | ✅ |
| デジタル署名 | ML-DSA-65 | `ml-dsa`（RustCryptoフォーク） | NIST FIPS 204 | ✅ |
| セキュアメモリ | — | `zeroize`, `secrecy` | — | — |
| HMAC | — | `hmac` + `sha2` | — | — |

### 5.2 AES-256-GCMの量子耐性について

AES-256はGroverアルゴリズムにより理論上128bit相当に安全性が低下する。ただしこれが現実的な脅威にならない根拠：

- **Groverの非並列性**: 量子演算は直列実行が必要であり、古典コンピュータのような並列化ができない。2^128回の直列量子演算は宇宙の年齢を超えるオーダー
- **機関のコンセンサス**: 米国科学・工学・医学アカデミー（2019年連邦議会報告書）は「AES-256のGrover攻撃は事実上不可能」と結論。IETF PQCガイドも同様の見解
- **NISTの立場**: NISTはAES-256をセキュリティレベル5（最高）のベースラインとして使用し続けている

唯一の残存懸念はGroverより高速な「未知の量子アルゴリズム」の発見可能性だが、これは現時点でオープン問題であり、実装上の対策は取れない。

### 5.3 PQCライブラリ選定経緯（ADR）

1. `pqcrypto-mlkem/mldsa` → AArch64サイドチャネル残存・NIST KATなし → **却下**
2. `oqs`（liboqs）→ 本番非推奨明記・SecretKeyにZeroize未実装 → **却下**
3. `ml-kem`/`ml-dsa`（RustCrypto）→ FIPS対応・NIST KAT通過 → **採用（フォーク）**

フォーク修正内容：
- `ml-dsa`: Drop漏れ4フィールド（`s1_hat`/`s2_hat`/`t0_hat`/`A_hat`）にzeroize追加 + CVE-2026-22705パッチ
- `ml-kem`: DecapsulationKeyのzeroize完全性確認・補完
- CIに`cargo audit`を組み込み

### 5.4 格子問題一本依存リスクとHQCロードマップ

ML-KEM・ML-DSAはともに格子問題（LWE）を安全性の根拠とする。格子問題に対する数学的ブレークスルーが発見された場合、両方が同時に無効化されるリスクがある。

NISTはこのリスクを認識し、2025年3月にHQC（符号理論ベースKEM）を第5のPQCアルゴリズムとして選定した。

**HQCスケジュール：**

```
2025年3月  ← 選定発表（完了）
2026年春頃 ← ドラフト標準（FIPS）公開予定
2026年夏秋 ← 90日パブリックコメント期間
2027年     ← FIPS最終標準公開予定
2027〜2028 ← RustCrypto pure Rust実装登場（予測）
```

**pq-diaryへの組み込み方針（Phase 4）：**

現時点の`pqcrypto-hqc`クレートは「この実装は定数時間ではなく、セキュアではない」と明記されており採用不可。2027年FIPS確定後にRustCrypto品質の実装が登場してから対応する。

組み込み方式はML-KEMとのハイブリッドKEM：

```
現在（Phase 1〜3）:
  K_entry を K_master（Argon2id由来）で保護
  + ML-KEM-768で鍵カプセル化

Phase 4（HQC標準化後）:
  K_entry を ML-KEM-768 + HQC ハイブリッドで保護
  → 格子問題・符号理論問題のどちらが破られても安全
```

vault.pqdのスキーマバージョンを v4 → v5 に更新して対応する。

### 5.5 Argon2idパラメータ設定

```toml
[argon2]
memory_cost_kb = 65536  # デフォルト 64MB（OWASP推奨）
time_cost      = 3
parallelism    = 4
```

最低保証値（警告表示）：`memory_cost_kb` 19456・`time_cost` 2

---

## 6. Vaultファイルフォーマット（v4、バイナリ）

### 6.1 ファイル全体構造

```
Offset  Size   内容
------  -----  ----
0       8      マジックバイト: "PQDIARY\0"
8       1      スキーマバージョン: 0x04
9       1      フラグ（予約: 0x00）
10      2      予約（0x0000）
12      4      ペイロードサイズ (LE u32)
16      32     KDFソルト (Argon2id用)
48      32     Legacyソルト (K_legacy導出用)
80      12     検証トークンIV
92      48     検証トークン暗号文 (AES-GCM: 32B平文 + 16B tag)
140     32     ML-KEM公開鍵オフセット予約
172     32     ML-DSA公開鍵ハッシュ（SHA-256）
204     ?      ML-KEM暗号化済み秘密鍵ブロック（可変長）
?       ?      ML-DSA暗号化済み秘密鍵ブロック（可変長）
?       ?      エントリセクション（可変長）
末尾    512〜  ランダムパディング
        4096B
```

`strings vault.pqd`でフィールド名・アルゴリズム名が一切露出しない設計。

### 6.2 エントリレコード構造（v4）

```
[4B: レコード長=0で終端]
[16B: UUID]
[8B: ts (作成日時 u64 LE)]
[8B: updated (更新日時 u64 LE)]
[12B: IV]
[4B: 暗号文長]
[暗号文+GCMタグ]
[4B: ML-DSA署名長]
[ML-DSA署名]
[32B: content_hmac (HMAC-SHA256)]
[1B: legacyフラグ  0x00=DESTROY / 0x01=INHERIT]
[4B: legacy鍵ブロック長 (0ならDESTROY)]
[legacy鍵ブロック (INHERITの場合のみ)]
[1B: パディング長]
[Nバイト: ランダムパディング]
```

Phase 1では`legacyフラグ = 0x00`・`legacy鍵ブロック長 = 0`で全エントリを初期化する。

### 6.3 後方互換性

| スキーマ | 読み込み | 書き込み |
|---|---|---|
| v1〜v3 (旧版) | ✅ マイグレーション | ❌ v4に自動アップグレード |
| v4 (現行) | ✅ | ✅ |
| v5 (HQC・将来) | — | Phase 4で実装 |

---

## 7. デジタル遺言機能

### 7.1 概要・設計原則

「明示的な意思表示がないものは消える」。未設定エントリはDESTROYとして扱う。

| 設定 | 説明 | フラグ値 |
|---|---|---|
| DESTROY（デフォルト） | 死後アクセスコード実行時に即座に消去 | 0x00 |
| INHERIT | 死後アクセスコードで復号可能 | 0x01 |

### 7.2 暗号設計（二重鍵方式）

```
K_master  = Argon2id(マスターパスワード, KDFソルト)
K_legacy  = Argon2id(死後アクセスコード, Legacyソルト)

INHERITエントリ:
  K_entryをK_masterで暗号化（通常用）
  K_entryをK_legacyで暗号化（legacy鍵ブロック）

DESTROYエントリ:
  K_entryをK_masterで暗号化のみ（legacy鍵ブロックなし）
```

### 7.3 `legacy-access` の動作

```
1. 死後アクセスコード入力 → K_legacy導出
2. K_masterでの解錠は試みない
3. 各エントリをスキャン:
   INHERIT → K_legacyでK_entryを復号 → 復号成功
   DESTROY/未設定 → zeroize・上書き削除
4. INHERITエントリのみを含む新vault.pqdをK_legacyで再暗号化
5. 元vault.pqdを安全に削除
6. K_masterは一切残さない
```

### 7.4 死後アクセスコードの管理

`pq-diary legacy init`で生成。保管方法のドキュメント推奨：
- 紙に印刷して物理保管（最もシンプル）
- 弁護士・信頼できる人物に預ける
- 秘密分散（Phase 3以降・OQ-17）

---

## 8. セキュアメモリ消去要件

### 8.1 鍵管理構造体

```rust
#[derive(ZeroizeOnDrop)]
struct MasterKey {
    sym_key: [u8; 32],
    dsa_sk:  Box<[u8]>,
    kem_sk:  Box<[u8]>,
}

struct CryptoEngine {
    master_key: Option<Secret<MasterKey>>,
    legacy_key: Option<Secret<[u8; 32]>>,
}
```

### 8.2 lock() の動作

```rust
fn lock(&mut self) {
    let _master = self.master_key.take();
    let _legacy = self.legacy_key.take();
    self.entries.clear();
    self.entries.shrink_to_fit();
    self.munlock_all();
}
```

### 8.3 mlock / VirtualLock

```rust
#[cfg(unix)]    fn mlock_buffer(buf: &[u8]) -> Result<()> { /* nix */ }
#[cfg(windows)] fn mlock_buffer(buf: &[u8]) -> Result<()> { /* windows-sys */ }
#[cfg(any(target_os = "ios", target_os = "android"))]
fn mlock_buffer(_buf: &[u8]) -> Result<()> { Ok(()) }  // OSサンドボックスで代替
```

失敗時: 警告表示 + 続行確認。

---

## 9. 静的・動的解析防御要件

### 9.1 静的解析防御

- vault.pqdはバイナリフォーマット（文字列が一切露出しない）
- エントリごとの可変長パディング（0〜255B）+ ファイル末尾パディング（512〜4096B）
- mlockでスワップ防止
- コアダンプ無効化（`setrlimit(RLIMIT_CORE, 0, 0)`）
- 一時ファイルは `/dev/shm` または `/run/user/$UID/` に作成後SecureDelete

### 9.2 動的解析防御

- `PR_SET_DUMPABLE=0`（`/proc/<pid>/mem`アクセスブロック・ptrace保護）
- デバッガ接続検知（警告のみ）

---

## 10. デーモン方式（Phase 2）

### 10.1 概要

SSHエージェントと同パターン。

```bash
pq-diary daemon start  # TTYでパスワード入力→鍵をメモリに保持
pq-diary daemon stop   # zeroize後に終了
pq-diary daemon lock   # zeroizeのみ
```

### 10.2 ソケット・認証

```
/run/user/$UID/pq-diary.sock  # パーミッション 0600
```

双方向SO_PEERCRED認証。UCred構造体を直接参照（文字列化禁止）。root（uid=0）を含む他UIDは全拒否。

### 10.3 既知脆弱性と対策

| # | 脆弱性 | 事例 | 対策 |
|---|---|---|---|
| V-1 | SO_PEERCRED文字列変換 | dirty_sock (CVE-2019-7304) | UCred直接参照 |
| V-2 | rootなりすまし | LXD LPE | uid != my_uidで全拒否 |
| V-3 | ソケット事前占拠 | X11 local privesc | `/run/user/$UID/`配置 + 双方向検証 |
| V-4 | ロック状態メモリ | パスワードマネージャー研究 | lock時確実にzeroize |
| V-5 | コールドブート | Princeton 2008 | FDE必須明記 |
| V-6 | ptrace | — | PR_SET_DUMPABLE=0 |
| V-7 | DoS | — | 接続数1に制限 |
| V-8 | レースコンディション | gpg-agent既知問題 | bind成功/失敗で排他制御 |

---

## 11. Git同期要件

### 11.1 実装方式

デスクトップ: git CLIを直接呼び出す。起動時に`git --version`で存在確認。  
モバイル（Phase 3）: git2クレート。HTTPS + PAT認証。トークンはiOS Keychain / Android Keystoreに保管。

### 11.2 同期対象ファイル

| ファイル | 同期対象 | 理由 |
|---|---|---|
| `vault.pqd` | ✅ | 完全暗号化済み |
| `vault.toml` | ✅ | メタデータ最小化済み（v4.0） |
| `entries/*.md` | ❌ | 平文。`.gitignore`で除外 |

### 11.3 Gitプライバシー強化

**コミットauthor匿名化：**

```rust
fn make_vault_author(config: &VaultConfig) -> String {
    format!("pq-diary <{}@localhost>", config.git.author_email)
}
// Vault初期化時にランダムID生成・vault.tomlに保存・以後固定
```

**コミットメッセージ定型化：** デフォルト `"update"` のみ。

**コミット毎の追加パディング：**

```rust
fn random_extra_padding(max_bytes: usize) -> Vec<u8> {
    let size = OsRng.gen_range(0..max_bytes);
    let mut buf = vec![0u8; size];
    OsRng.fill_bytes(&mut buf);
    buf  // vault.pqdの末尾に追記してからコミット
}
```

**タイムスタンプファジング：**

```rust
fn fuzz_timestamp(real: DateTime<Utc>, prev: DateTime<Utc>, fuzz_hours: u64) -> DateTime<Utc> {
    let max_secs = fuzz_hours as i64 * 3600;
    let offset: i64 = OsRng.gen_range(0..=max_secs);
    let candidate = prev + Duration::seconds(offset + 1);
    candidate.min(real)
}
// GIT_AUTHOR_DATE / GIT_COMMITTER_DATE 環境変数で設定
```

### 11.4 マージ戦略

エントリ単位の3-wayマージ（UUID + content_hmacで同一性確認）。コンフリクト時は対話式解決プロンプトを表示。

---

## 12. 非機能要件

### 12.1 パフォーマンス目標

| 操作 | 目標 |
|---|---|
| `init`（鍵生成含む） | < 3秒 |
| `unlock`（Argon2id） | 1〜3秒 |
| `new` / `edit` | < 200ms |
| `list`（100エントリ） | < 500ms |
| `lock()` | < 50ms |
| `legacy-access`（1000エントリ） | < 10秒 |

### 12.2 クロスプラットフォームビルド

| ターゲット | デーモン対応 |
|---|---|
| Linux x86_64 / aarch64 | ✅ |
| macOS aarch64 | ✅ |
| Windows x86_64 | ❌（Phase 2以降） |
| iOS / Android（Phase 3） | ❌（OSサンドボックスで代替） |

### 12.3 依存クレート方針

| カテゴリ | クレート | 方針 |
|---|---|---|
| ML-KEM-768 | `ml-kem` (RustCrypto) | フォーク |
| ML-DSA-65 | `ml-dsa` (RustCrypto) | フォーク |
| AES-256-GCM | `aes-gcm` | 外部依存維持 |
| Argon2id | `argon2` | 外部依存維持 |
| HMAC-SHA256 | `hmac` + `sha2` | 外部依存維持 |
| セキュアメモリ | `zeroize`, `secrecy` | 外部依存維持 |
| Unix syscall | `nix` | 外部依存維持 |
| Windows API | `windows-sys` | 外部依存維持 |
| CLI | `clap` | 外部依存維持 |
| Git操作（デスクトップ） | git CLI呼び出し | クレート不使用 |
| Git操作（モバイル・Phase 3） | `git2` | 条件付き依存 |
| パスワードプロンプト | 自前実装（termios） | クレート不使用 |
| バイナリシリアライズ | 自前実装 | クレート不使用 |
| UUID | `uuid` | 外部依存維持 |
| 日時 | `chrono` | 外部依存維持 |
| HQC（Phase 4） | TBD（RustCrypto待ち） | 2027年以降 |

---

## 13. FDEとpq-diaryの役割分担

### 13.1 脅威モデルによる役割分離

```
FDE（AES-256-XTS）が守る脅威:
  → ディスクを物理取得した攻撃者がオフラインで解読する
  → 現時点のAES-256に対する現実的な量子攻撃は存在しない
  → プロセス停止中の静止データに対して有効

pq-diaryが守る脅威:
  → vault.pqdがネットワーク経由（Git）で外部に渡るシナリオ
  → Harvest Now, Decrypt Later（今取得して将来解読）
  → ML-KEM-768で防御（格子問題ベース・Shorのアルゴリズム適用不可）
```

### 13.2 「FDEにPQCを自前実装すべきか」への回答

**やめるべき。理由：**

- FDEのバグはOS起動不能・ディスク全体喪失に直結
- FDEが守る物理盗難の脅威にPQCは不要（AES-256で十分）
- 脅威モデル上のメリットがほぼゼロ

### 13.3 正常シャットダウン後のディスクに対する国家支援型攻撃

```
攻撃の流れ:
  Step 1: FDE（AES-256-XTS）突破
          → Groverで128bit相当に低下
          → 2026年現在、これを破れる量子コンピュータは存在しない
          → Step 1は現時点で突破不可

  仮にFDEが突破された場合:
  Step 2: vault.pqdに到達
          → AES-256-GCM（128bit相当）+ ML-KEM-768で保護
          → ML-KEM-768は格子問題ベース・量子解読手段なし
          → 日記内容に到達できない
```

**結論：** FDEのPQC非対応によって脆弱になる現実的な攻撃者は、2026年時点では存在しない。

### 13.4 ユーザー向けFDE推奨設定

| OS | FDE実装 | 設定方法 |
|---|---|---|
| Linux | dm-crypt + LUKS2 | インストール時に「ディスク全体を暗号化」を選択 |
| macOS | FileVault | システム設定 → プライバシーとセキュリティ |
| Windows | BitLocker | 設定 → デバイスの暗号化 |

**ハイバネーション使用時の注意：** スワップパーティションも必ず暗号化すること。ハイバネーション中はK_masterを含むメモリ内容がディスクに書き出されるため。

---

## 14. アプリケーション層で守れない脅威

| 脅威 | 対策 |
|---|---|
| root/管理者によるメモリダンプ | FDE **必須** |
| コールドブートアタック | FDE + 電源断後の物理保護 |
| SSD wear leveling | FDE が唯一の完全対策 |
| ハイパーバイザーからのメモリ読み取り | ベアメタル動作を推奨 |
| GitHubコミット差分からの行動パターン推測 | タイムスタンプファジング + パディングで緩和（完全隠蔽不可） |
| GitHubリポジトリ公開・アーカイブ（Zombie Data） | セルフホストGiteaを推奨 |
| `full`ポリシーVaultへの間接プロンプトインジェクション | 使用最小限を推奨 |

---

## 15. Phase計画

### Phase 1（実装対象）

- Cargoワークスペース構成（`core/` + `cli/`）
- マルチVault構造 + アクセスポリシー + セットアップ対話フロー
- パスワード入力（優先順位付き3段階・自前termios）
- PQCフォーク作成（ml-dsa Drop漏れ・CVEパッチ）
- Vault v4バイナリフォーマット（legacyフィールド予約込み）
- SecureBuffer / ZeroizingKey 自前実装
- `--claude` フラグとポリシーチェック
- git CLIによるGit同期
- Gitプライバシー強化3点セット + タイムスタンプファジング
- **$EDITOR一時ファイル制御（$TMPDIR上書き・vimオプション強制）← v4.0新規**
- vault.tomlのメタデータ最小化（タイムスタンプフィールド削除）← v4.0新規

### Phase 2（延期）

- デジタル遺言機能（K_legacy・INHERIT/DESTROY・`legacy-access`）
- Unixソケット + ロックデーモン（V-1〜V-8対策込み）
- 鍵素材のXOR分散保持
- 固定ブロックサイズ化によるファイルサイズ差分の完全隠蔽（OQ-20）

### Phase 3（モバイル・将来）

- UniFFIバインディング（Swift / Kotlin）
- iOS / Androidアプリ
- git2クレートによるGit同期（モバイル向け）
- デジタル遺言の秘密分散（Shamir's Secret Sharing）

### Phase 4（HQC標準化後・2027年以降）

- HQC FIPS最終標準の確認
- RustCrypto品質のpure Rust HQC実装の採用（定数時間保証・zeroize対応が条件）
- ML-KEM + HQCのハイブリッドKEM実装
- vault.pqdスキーマバージョン v4 → v5 への移行

---

## 16. 暗号攻撃分析

### 16.1 攻撃分類と対策状況

| # | 攻撃 | 対策状況 | Phase 1対処 |
|---|---|---|---|
| A | AES-GCM Nonceリユース | ✅ ランダムnonce | — |
| B | Harvest Now, Decrypt Later | ✅ ML-KEM-768 | — |
| C | PQCタイミングサイドチャネル（CVE-2026-22705） | ✅ フォークにパッチ | 継続監視 |
| D | メモリフォレンジック（稼働中） | ✅ mlock + zeroize | FDE必須明記 |
| E | コールドブートアタック | ✅ 部分対策 | FDE必須明記 |
| F | スワップ平文漏洩 | ✅ mlock | FDE必須明記 |
| **G** | **$EDITOR一時ファイル平文露出** | **✅ v4.0で対処** | **$TMPDIR制御実装** |
| H | Argon2id低コスト設定 | ✅ 警告表示 | — |
| I | Gitコミット差分解析 | ✅ 部分対策（OQ-20残） | パディング実装 |
| **J** | **vault.tomlメタデータ漏洩** | **✅ v4.0でフィールド削除** | **最小化実装** |
| K | GitHub Zombie Data | ❌ アプリ層対応不可 | ドキュメント推奨 |
| L | SSD wear leveling | ❌ アプリ層対応不可 | ドキュメント必須 |
| M | ハイパーバイザーメモリ読み取り | ❌ アプリ層対応不可 | ドキュメント推奨 |
| N | サプライチェーン攻撃 | ✅ cargo audit CI | 継続監視 |
| O | zeroize最適化除去 | ✅ compiler_fence | フォーク確認 |

### 16.2 AES-GCM Nonceリユースの補足

同一K_masterで生涯暗号化するエントリ数が2^48回を超えるとバースデー問題で衝突確率が上昇する。日記用途では現実的な脅威ではないが、パスワード変更時に全エントリを新しいK_masterで再暗号化する設計にしておくと理論的に整合する。

### 16.3 $EDITOR一時ファイル問題の詳細（v4.0で解決）

問題：vimは`~/.vim/swapfiles/`・nanoは`/tmp/`・最近使ったファイル履歴（`~/.local/share/recently-used.xbel`）に平文が残る。

解決策（セクション4.3参照）：`$TMPDIR`を`/dev/shm`または`/run/user/$UID/`に上書きしてエディタを起動。vimには`-c 'set noswapfile nobackup noundofile'`オプションを渡す。

---

## 17. 未解決問題（Open Questions）

| # | 問題 | 状態 | 方針 |
|---|---|---|---|
| OQ-1 | force push後のmerge-base失敗 | 引き継ぎ | タイムスタンプ優先の簡易実装でスタート |
| OQ-2 | mlock失敗時の通知レベル | **解決** | 警告+続行確認 |
| OQ-3 | content_hmacサイズ影響 | **解決** | 32B/エントリ、許容範囲 |
| OQ-4 | git CLI問題 | **解決** | git CLI（デスクトップ）/ git2（モバイル）分岐 |
| OQ-5 | コミットメッセージ情報範囲 | **解決** | 定型文 `"update"` のみ |
| OQ-6 | SSD wear levelingのユーザー周知 | 引き継ぎ | FDE必須とドキュメント明記 |
| OQ-7 | バイナリ形式のデバッグ手段 | 引き継ぎ | `--debug`フラグでJSON出力 |
| OQ-8 | 鍵分散のアドレス保証 | 延期 | Phase 2以降 |
| OQ-9 | Windows VirtualLock | **解決** | `windows-sys`クレートで実装可能 |
| OQ-10 | `--secure`モードとClaude連携の排他 | **解決** | マルチVault + アクセスポリシーで代替 |
| OQ-11 | rpasswordがSecretStringを返すか | **解決** | 返さない→termios自前実装 |
| OQ-12 | git2バイナリサイズ | **解決** | git2廃止（デスクトップ）でそもそも問題なし |
| OQ-13 | pqcryptoクレートのFIPS対応 | **解決** | RustCryptoフォーク採用で解消 |
| OQ-14 | ClaudeアクセスポリシーのVault持たせ方 | **解決** | vault.tomlの`access.policy` |
| OQ-15 | デーモン方式のSO_PEERCRED実装 | Phase 2で対処 | UCred直接参照、文字列化禁止 |
| OQ-16 | `full`ポリシーVaultへの間接プロンプトインジェクション | オープン | ドキュメント警告が主な対策 |
| OQ-17 | デジタル遺言の秘密分散方式 | Phase 3に延期 | Shamir's Secret Sharing |
| OQ-18 | legacy-access後のvaultの暗号鍵 | オープン | K_legacyで再暗号化する方針 |
| OQ-19 | タイムスタンプファジングとmerge-baseの関係 | オープン | content_hmac依存なので軽微。要検証 |
| OQ-20 | 固定ブロックサイズ化による差分完全隠蔽 | **Phase 2検討** | 64KB単位切り上げ。トレードオフあり |
| OQ-21 | vault.tomlのcreatedフィールド削除による利便性への影響 | **v4.0で削除** | Gitの最初のコミット日時で代替可能 |
| OQ-22 | HQCハイブリッドKEM追加時のvault.pqdフォーマット（v5設計） | 2027年以降 | RustCrypto HQC実装登場後に設計 |
