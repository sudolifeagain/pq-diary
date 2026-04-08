# daily-note-template-link コンテキストノート

**作成日**: 2026-04-05
**対象スプリント**: S5 — デイリーノート + テンプレート + リンク

## 技術スタック

- **言語**: Rust (2021 edition)
- **ワークスペース**: `core/` (pq-diary-core) + `cli/` (バイナリ)
- **暗号**: `aes-gcm`, `argon2`, `ml-kem`/`ml-dsa`, `zeroize`, `secrecy`
- **CLI**: `clap` (derive)
- **その他**: `uuid`, `chrono`, `regex`(リンクパース用)

## 開発ルール

- `unsafe` は mlock/VirtualLock/PR_SET_DUMPABLE のみ許可
- 秘密データは `zeroize` / `SecretString` / `SecretBytes` で保持
- `unwrap()` / `expect()` はテストコードのみ
- エラーは `thiserror` (core) / `anyhow` (cli)
- core/ にプラットフォーム依存UIコードを入れない

## 既存実装の状況

### テンプレート基盤
- `RECORD_TYPE_TEMPLATE = 0x02` が `core/src/vault/format.rs` に定義済み
- `EntryRecord` はエントリとテンプレートで同一構造（record_typeで区別）
- reader/writer でテンプレートレコードの読み書きテスト済み
- **高レベルCRUD関数は未実装**（create_template, list_templates 等）

### CLIスケルトン
- `Commands::Today` が `cli/src/main.rs` に定義済み（not_implemented）
- `TemplateCommands { Add, List, Show, Delete }` が定義済み（not_implemented）
- `new --template` フラグは **未定義**

### エディタ制御
- `cli/src/editor.rs` に vim/nvim 検出 + セキュリティオプション注入済み
- `-c` オプションで追加コマンド注入可能（補完関数の拡張ポイント）
- `write_header_file()` / `read_header_file()` でヘッダーコメント形式対応済み

### リンク・バックリンク
- **完全に未実装**（パーサー、インデックス、解決ロジックすべてゼロベース）

## 設計決定事項 (ADR)

- **ADR-0004**: `[[タイトル]]` Obsidian互換リンク記法採用
  - タイトル重複時はリスト表示で選択
  - vim補完用一覧は /dev/shm 上の一時ファイルに書き出し、zeroize削除
- **ADR-0005**: テンプレートはvault.pqd内に暗号化格納
  - テンプレート内容も秘匿される
  - 追加・編集にはVault解錠が必要

## 注意事項

- テンプレート変数展開は Mustache 風 `{{var_name}}` 記法
- バックリンクインデックスはunlock時にインメモリ構築
- vim/neovim以外のエディタでは補完が効かない
- 補完用一時ファイルは `/dev/shm`(Linux) / secure_tmpdir(Windows) に配置
