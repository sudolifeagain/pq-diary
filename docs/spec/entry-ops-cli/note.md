# entry-ops-cli コンテキストノート

**Sprint**: S4
**作成日**: 2026-04-03

## 技術スタック

- **言語**: Rust (2021 edition)
- **ワークスペース**: `core/` (pq-diary-core) + `cli/` (バイナリ)
- **暗号**: `aes-gcm`, `argon2`, `ml-kem`/`ml-dsa` (RustCryptoフォーク), `zeroize`, `secrecy`
- **CLI**: `clap` (derive)
- **UUID**: `uuid` v4
- **日時**: `chrono`
- **Unix**: `nix` (termios)
- **Windows**: `windows-sys` (SetConsoleMode, VirtualLock)

## 開発ルール

- `unsafe` は mlock/VirtualLock/PR_SET_DUMPABLE のみ許可
- 秘密データは必ず `zeroize` / `SecretString` / `SecretBytes` で保持
- `unwrap()` / `expect()` はテストコードのみ
- エラーは `thiserror` (core) / `anyhow` (cli)
- テストは `#[cfg(test)] mod tests` で配置

## 既存実装（S1-S3完了）

### core/src/ 構成
- `lib.rs` — 公開API (`DiaryCore` ファサード)
- `error.rs` — `DiaryError` (16バリアント)
- `entry.rs` — **スタブ（S4で実装予定）**
- `crypto/` — `CryptoEngine`, `MasterKey`, `SecureBuffer`, `ZeroizingKey`, AES-GCM, Argon2id, ML-KEM, ML-DSA, HMAC
- `vault/` — `VaultHeader`, `EntryRecord`, `VaultConfig`, `VaultManager`, reader/writer

### cli/src/ 構成
- `main.rs` — clap derive による全コマンド定義済み（dispatch は placeholder）

### 主要型
- `EntryRecord`: uuid, created_at, updated_at, iv, ciphertext, signature, content_hmac, legacy_flag, legacy_key_block, attachment_count, attachment_offset, padding
- `CryptoEngine`: unlock/lock/encrypt/decrypt
- `VaultManager`: init_vault/list_vaults/vault_path

## S4で利用する既存機能

- `CryptoEngine::encrypt()` / `decrypt()` — エントリ暗号化/復号
- `vault::reader::read_vault()` / `vault::writer::write_vault()` — vault.pqd読み書き
- `VaultManager` — Vault解決・パス取得
- `VaultConfig::from_file()` — vault.toml読み込み（Argon2パラメータ取得）
- `DiaryError` — エラー型（必要に応じてバリアント追加）

## 設計決定事項（ADR）

- ADR-0002: カスタムバイナリフォーマット v4
- ADR-0003: パスワード入力3段階（--password / env / TTY termios自前実装）
- ADR-0004: [[タイトル]] リンク記法（Obsidian互換）— S5で実装

## 注意事項

- `entry.rs` は現在スタブ。S4でフル実装する
- `DiaryCore` の公開APIメソッド（new_entry, list_entries, get_entry, delete_entry）は requirements.md §2.3 で定義済み
- Windows環境での開発 — termios → SetConsoleMode, /dev/shm → %LOCALAPPDATA%\pq-diary\tmp\
