# search-stats-import 開発コンテキストノート

## 作成日時
2026-04-08

## プロジェクト概要

### プロジェクト名
pq-diary

### プロジェクトの目的
量子コンピュータによる将来の解読（Harvest Now, Decrypt Later攻撃を含む）と、現在のフォレンジック・マルウェアによる解析の両方に耐える、Rust製CLI日記ツール。Vault = Single Source of Truth の設計原則に基づき、vault.pqd が唯一の正データとして機能する。

**参照元**: [CLAUDE.md](CLAUDE.md), [requirements.md](requirements.md) 1.1-1.2

## 技術スタック

### 使用技術・フレームワーク
- **言語**: Rust (2021 edition, rust-version 1.94)
- **ワークスペース**: `core/` (pq-diary-core ライブラリ) + `cli/` (バイナリ)
- **暗号**: `aes-gcm`, `argon2`, `ml-kem`/`ml-dsa` (RustCryptoフォーク), `zeroize`, `secrecy`
- **CLI**: `clap` v4 (derive)
- **シリアライズ**: `serde` + `serde_json`, `toml`
- **UUID**: `uuid` v1 (v4 feature)
- **日時**: `chrono` v0.4
- **Unix**: `nix` v0.29 (termios)
- **Windows**: `windows-sys` v0.59

### アーキテクチャパターン
- **アーキテクチャスタイル**: ワークスペース分離 — core/ (プラットフォーム非依存ドメインロジック) + cli/ (薄いラッパー)
- **設計パターン**: Facade パターン (`DiaryCore` が公開API), Builder パターン (clap derive)
- **ディレクトリ構造**:
  ```
  pq-diary/
  ├── core/src/
  │   ├── lib.rs       — DiaryCore facade
  │   ├── entry.rs     — EntryPlaintext, EntryMeta, Tag, IdPrefix, CRUD
  │   ├── error.rs     — DiaryError (thiserror)
  │   ├── crypto/      — CryptoEngine, MasterKey, SecureBuffer, AES-GCM, Argon2id, ML-KEM, ML-DSA, HMAC
  │   ├── vault/       — VaultHeader, EntryRecord, VaultConfig, VaultManager, reader/writer
  │   ├── git.rs       — スタブ (S8)
  │   ├── legacy.rs    — スタブ (Phase 2)
  │   └── policy.rs    — スタブ (S7)
  └── cli/src/
      ├── main.rs      — clap derive CLI定義 + dispatch
      ├── commands.rs   — コマンドハンドラ (S4実装済み: new/list/show/edit/delete)
      ├── editor.rs     — $EDITOR起動 + ヘッダーコメントパース
      └── password.rs   — 3段階パスワード入力
  ```

**参照元**:
- [CLAUDE.md](CLAUDE.md)
- [requirements.md](requirements.md) 2.1-2.2

## 開発ルール

### プロジェクト固有のルール
- `unsafe` は mlock/VirtualLock/PR_SET_DUMPABLE のみ許可。それ以外は禁止
- 秘密データは必ず `zeroize` / `SecretString` / `SecretBytes` で保持。生の `Vec<u8>` / `String` 禁止
- `unwrap()` / `expect()` はテストコードのみ許可。本番コードは `Result` を返す
- エラーは `thiserror` で定義。`anyhow` は cli/ のみ許可
- プラットフォーム分岐は `#[cfg()]` で。core/ にプラットフォーム依存UIコードを入れない
- ディスクに平文を書かない（一時ファイルは /dev/shm + zeroize削除）

### コーディング規約
- **命名規則**: Rust標準 (snake_case for functions/variables, CamelCase for types)
- **コミットメッセージ**: `{type}(s{N}): {概要}` (feat/fix/refactor/test/docs/chore)
- **フォーマット**: `cargo clippy --workspace -- -D warnings` 必須

### テスト要件
- **テスト配置**: 各モジュールに `#[cfg(test)] mod tests` で配置
- **テストでのみ許可**: `unwrap()` / `expect()`
- **CI**: `cargo test --workspace`, `cargo clippy`, `cargo audit`

**参照元**:
- [CLAUDE.md](CLAUDE.md)
- [docs/definition-of-done.md](docs/definition-of-done.md)

## 既存の要件定義

### 要件定義書
S6 スコープは requirements.md v4.0 および docs/backlog.md で定義されている。S6 固有の kairo-requirements はまだ生成されていない。

**参照元**:
- [requirements.md](requirements.md) 4.1 (コマンド体系)
- [docs/backlog.md](docs/backlog.md) S6 セクション

### S6: 検索 + 統計 + インポート — バックログ項目

requirements.md 4.1 のコマンド体系には search/stats/import の個別コマンドは明記されていないが、backlog.md S6 に以下が定義されている:

1. **search コマンド** — 復号後インメモリ正規表現 grep
2. **検索結果のコンテキスト表示** — 前後N行
3. **stats コマンド** — 執筆頻度、文字数推移、タグ分布
4. **import \<dir\>** — プレーンMD一括取り込み
5. **\[\[wiki-link\]\] → \[\[タイトル\]\] 自動変換**
6. **#ネスト/タグ 自動変換**
7. **インポート結果サマリー表示**

### 設計決定事項（ADR）関連
- **ADR-0004**: `[[タイトル]]` リンク記法（Obsidian互換）— import での wiki-link 変換に直接関連
- **CLAUDE.md 設計決定事項**: インポート時に Obsidian `[[wiki-link]]` / `#ネスト/タグ` を pq-diary 形式に自動変換

### 主要な非機能要件
- NFR: `list`（100エントリ）< 500ms — search も同等のパフォーマンスが期待される
- NFR: 秘密データはメモリ内に最小時間だけ存在し、操作完了後は即座に zeroize
- NFR: ディスクに平文を書かない

## 既存の設計文書

S6 用の設計文書はまだ生成されていない。以下は参考になる既存の設計決定:

### ADR一覧
| ADR | タイトル | 関連度 |
|-----|---------|--------|
| 0001 | PQCライブラリ選定 | 低 |
| 0002 | Vaultバイナリフォーマット v4 | 高（エントリ読み書きフォーマット） |
| 0003 | パスワード入力方式 | 中（unlock が前提） |
| 0004 | エントリ間リンク記法 | 高（import の wiki-link 変換） |
| 0005 | テンプレート保存方式 | 低 |
| 0006 | Git同期方式 | 低 |

**参照元**:
- [docs/adr/](docs/adr/)

## 関連実装

### S4 で実装済みの既存機能（S6 で利用・拡張するもの）

#### DiaryCore facade (`core/src/lib.rs`)
- `new(vault_path)` → VaultConfig ロード
- `unlock(password)` → CryptoEngine 初期化
- `lock()` → 鍵 zeroize
- `new_entry(title, body, tags)` → エントリ作成 — **import で大量呼び出し**
- `list_entries(query)` → 全エントリのメタ情報取得 — **stats / search の基盤**
- `get_entry(id)` → 単一エントリ復号 — **search の本文検索で利用**
- `update_entry(id, plaintext)` → エントリ更新
- `delete_entry(id)` → エントリ削除

#### Entry types (`core/src/entry.rs`)
- `EntryPlaintext` — `{ title, tags, body }` (JSON シリアライズ)
- `EntryMeta` — `{ uuid_hex, title, tags, created_at, updated_at }`
- `Tag` — バリデーション付きタグ型（ネスト対応、`is_prefix_of()` メソッドあり）
- `IdPrefix` — 4文字以上の hex プレフィックス

#### CLI commands (`cli/src/commands.rs`)
- `filter_and_sort()` — タグフィルタ + キーワードフィルタ + ソート + 件数制限
- `format_timestamp()` — Unix timestamp → `YYYY-MM-DD` 表示
- `resolve_vault_path()` — vault パス解決

#### Vault I/O (`core/src/vault/`)
- `reader::read_vault()` — vault.pqd 全レコード読み込み
- `writer::write_vault()` — vault.pqd 全レコード書き込み
- `EntryRecord` — uuid, created_at, updated_at, iv, ciphertext, signature, content_hmac, legacy_flag, legacy_key_block, padding 等

#### CryptoEngine (`core/src/crypto/`)
- `encrypt()` / `decrypt()` — AES-256-GCM
- `sign()` / `verify()` — ML-DSA-65
- `hmac()` — HMAC-SHA256

### S6 で新規追加が必要な機能

#### search コマンド
- **core 側**: 全エントリを復号しインメモリで正規表現マッチング。`regex` クレートの追加が必要
- **cli 側**: search サブコマンド定義、コンテキスト表示（前後N行）

#### stats コマンド
- **core 側**: 全エントリの統計情報集計（執筆頻度、文字数、タグ分布）
- **cli 側**: stats サブコマンド定義、表示フォーマット

#### import コマンド
- **core 側**: Markdown パース、wiki-link 変換ロジック、タグ変換ロジック
- **cli 側**: import サブコマンド定義、ディレクトリ走査、サマリー表示、確認プロンプト

### 依存関係・追加クレート候補
- `regex` — 正規表現検索（search コマンド）
- `walkdir` or `std::fs::read_dir` — ディレクトリ走査（import コマンド）

**参照元**:
- [core/src/lib.rs](core/src/lib.rs)
- [core/src/entry.rs](core/src/entry.rs)
- [cli/src/commands.rs](cli/src/commands.rs)
- [cli/src/main.rs](cli/src/main.rs)

## 技術的制約

### パフォーマンス制約
- search は全エントリを復号してインメモリで検索するため、エントリ数に比例して処理時間が増加
- `list`（100エントリ）< 500ms が目標 — search/stats もこの範囲を目安とする
- 復号は1エントリずつストリーミング的に行い、メモリ使用量を抑制する必要がある

### セキュリティ制約
- 復号した平文はメモリ上に最小時間保持し、zeroize で消去
- import 時に元の MD ファイルを読み込むが、読み込み後のバッファも zeroize 対象
- import 後の元ファイル削除はユーザー判断（自動削除しない）
- search 結果の表示内容も秘密データ — ターミナル出力後のメモリ消去が必要

### 互換性制約
- クロスプラットフォーム: Linux x86_64/aarch64, macOS aarch64, Windows x86_64
- core/ にプラットフォーム依存コードを入れない
- import 対象: Obsidian 形式の Markdown ファイル（`[[wiki-link]]`, `#ネスト/タグ`）

### データ制約
- vault.pqd はバイナリフォーマット v4 — エントリ追加は write_vault() で全体を再書き込み
- import で大量エントリを一括追加する場合、write_vault() の呼び出し回数を最適化する必要あり（バッチ書き込み）

**参照元**: [requirements.md](requirements.md) 12.1, [CLAUDE.md](CLAUDE.md)

## 注意事項

### 開発時の注意点
- S5 (デイリーノート + テンプレート + リンク) は未実装（sprint-status.md では blocked by S4）。S6 は S5 の `[[タイトル]]` リンク解決と独立して実装可能だが、import の wiki-link 変換は S5 のリンク記法と整合性が必要
- wiki-link 変換は「`[[wiki-link]]` → `[[タイトル]]`」の形式変換のみ。リンク先の存在チェックは S5 のバックリンクインデックスに依存するため、S6 では変換のみ実装
- stats コマンドの出力フォーマットは要件定義で詳細未定義 — kairo-requirements で明確化が必要

### セキュリティ上の注意点
- search の正規表現パターンは秘密情報を含む可能性がある — シェル履歴に残る点をドキュメントで注意喚起
- import 元のファイルパスも vault 構造の手がかりになり得る — ログ出力を最小限に
- 大量エントリの復号時にメモリ上に同時展開される平文量を制限する設計が必要

### パフォーマンス上の注意点
- 全エントリの復号は O(n) — エントリ数が多い場合に search/stats が遅くなる可能性
- import のバッチ処理: 1エントリごとに write_vault() を呼ぶと O(n^2) になる恐れ — 全エントリを一括で書き込む最適化が必須

## Git情報

### 現在のブランチ
`worktree-kind-leaping-cat` (origin/main と同期)

### 最近のコミット
```
fd9876a Merge sprint/s4: エントリ操作 + CLI
2a8665b fix(s4): replace UB post-drop memory reads with ManuallyDrop in zeroize tests
0d9be29 feat(s4): implement TASK-0041 - integration tests and doc comments
25d04e9 feat(s4): implement TASK-0040 - delete command with confirmation
ea3f1ab feat(s4): implement TASK-0039 - edit command
0972a77 feat(s4): implement TASK-0038 - list and show commands
9cf8470 feat(s4): implement TASK-0037 - clap update and new command
e266d1b feat(s4): implement TASK-0036 - editor launch and header comment parsing
06e5a5e feat(s4): implement TASK-0035 - secure tmpdir and zeroize delete
eee4c50 feat(s4): implement TASK-0034 - three-tier password input
```

### 開発状況
- S1-S4 完了・main にマージ済み
- S5 (デイリーノート + テンプレート + リンク) は未着手
- S6 (検索 + 統計 + インポート) はこれから着手
- sprint/s6 ブランチはまだ作成されていない
- 既存ブランチ: main, sprint/s1-s5, worktree-kind-leaping-cat

## 収集したファイル一覧

### プロジェクト基本情報
- [CLAUDE.md](CLAUDE.md)
- [requirements.md](requirements.md)

### 要件定義・仕様書
- [docs/backlog.md](docs/backlog.md) — S6 スコープ定義
- [docs/sprint-status.md](docs/sprint-status.md) — スプリント進捗
- [docs/definition-of-done.md](docs/definition-of-done.md) — 完了基準
- [docs/workflow.md](docs/workflow.md) — 開発フロー

### 設計文書
- [docs/adr/README.md](docs/adr/README.md) — ADR インデックス
- [docs/adr/0004-entry-link-notation.md](docs/adr/0004-entry-link-notation.md) — wiki-link 記法 (import に関連)

### 関連実装
- [core/src/lib.rs](core/src/lib.rs) — DiaryCore facade
- [core/src/entry.rs](core/src/entry.rs) — EntryPlaintext, EntryMeta, Tag, CRUD
- [core/src/error.rs](core/src/error.rs) — DiaryError
- [core/src/vault/](core/src/vault/) — Vault フォーマット読み書き
- [core/src/crypto/](core/src/crypto/) — CryptoEngine
- [cli/src/main.rs](cli/src/main.rs) — CLI 定義
- [cli/src/commands.rs](cli/src/commands.rs) — コマンドハンドラ
- [core/Cargo.toml](core/Cargo.toml) — core 依存関係
- [cli/Cargo.toml](cli/Cargo.toml) — cli 依存関係

### 既存スプリントの参考ノート
- [docs/spec/entry-ops-cli/note.md](docs/spec/entry-ops-cli/note.md) — S4 コンテキストノート (テンプレート参考)

---

**注意**: すべてのファイルパスはプロジェクトルートからの相対パスで記載しています。
