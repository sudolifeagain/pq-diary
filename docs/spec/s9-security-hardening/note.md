# S9 Security Hardening + Technical Debt + Integration Tests - Context Note

## Tech Stack

- **Language**: Rust 2021 edition
- **Workspace**: `core/` (pq-diary-core ライブラリ) + `cli/` (バイナリ)
- **Platform**: `nix` (Unix), `windows-sys` (Windows)
- **CLI**: clap (derive)
- **暗号**: `aes-gcm`, `argon2`, `ml-kem`/`ml-dsa` (RustCryptoフォーク), `zeroize`, `secrecy`
- **エラー**: `thiserror` (core) / `anyhow` (cli)

## Existing Infrastructure

### unsafe ブロック状況
- 8個の unsafe ブロック（大部分はテスト内）
- `password.rs`: Win32 Console API (`GetConsoleMode`/`SetConsoleMode`/`ReadConsoleW`) の unsafe
- mlock / VirtualLock / PR_SET_DUMPABLE は未実装

### プラットフォーム分岐パターン
- `#[cfg(unix)]` / `#[cfg(windows)]`: `password.rs`, `editor.rs` で確立済み
- core/ にプラットフォーム依存UIコードなし（CLAUDE.md規約）

### 技術的負債 現状
- **[H-1]**: `Cli.password` が `Option<String>` → `SecretString` 化が必要（S1残存）
- **[M-1]**: `not_implemented()` が `process::exit` を使用 → `bail!` に変更が必要（4箇所 + legacy/daemonスタブ）
- **[M-2]**: `MasterKey.sym_key` コピー時の中間 `Vec<u8>` → `Zeroizing` でラップが必要（S1残存）
- **[M-3]**: `ml-kem` / `ml-dsa` の依存が `branch = "pq-diary"` → `rev = "commit_hash"` でpin が必要（S1/S2残存）
- **[M-4]**: `unlock_with_vault` の中間 `Vec<u8>` → `Zeroizing` でラップが必要（S2残存）
- **[M-5]**: `verify_hmac` が `bool` 返却 → `Result` 返却に変更が必要（S2/S6繰越）
- **署名/HMAC検証**: 読み取り時の署名・HMAC検証が未実装（S4/S6繰越）

### DiaryError (`core/src/error.rs`)
- `DiaryError::Crypto(String)` variant が既に存在
- 検証失敗エラーはここに追加

## Development Rules

- `unsafe` only for mlock/VirtualLock/PR_SET_DUMPABLE/Win32 Console API (GetConsoleMode/SetConsoleMode/ReadConsoleW)
- Secrets must use zeroize / SecretString / SecretBytes
- No unwrap()/expect() in production code
- Errors via thiserror (core) / anyhow (cli only)
- Tests in `#[cfg(test)] mod tests` per module
- Platform branching via `#[cfg()]`

## Related Files

- `requirements.md`: PRD v4.0 (section 8: メモリ保護, section 9: プロセス硬化, section 12: パフォーマンス)
- `docs/backlog.md`: S9スコープ + 技術的負債一覧
- `core/src/crypto/`: 暗号モジュール群（secure_mem.rs を新規追加予定）
- `core/src/crypto/hmac.rs`: verify_hmac（M-5対象）
- `core/src/vault/reader.rs`: エントリ読み取り（署名/HMAC検証追加先）
- `core/src/key.rs`: MasterKey（M-2対象）
- `core/src/vault/init.rs`: unlock_with_vault（M-4対象）
- `cli/src/main.rs`: Cli構造体（H-1対象）、not_implemented()（M-1対象）
- `cli/src/commands.rs`: コマンド実装
- `core/Cargo.toml`, `cli/Cargo.toml`: PQC依存ピン（M-3対象）
- `core/src/password.rs`: Win32 Console API unsafe
- `core/src/editor.rs`: プラットフォーム分岐パターン

## Key Decisions from Interview

1. **S9フルスコープ**: 全バックログ技術的負債（H-1, M-1〜M-5, 署名/HMAC検証）+ セキュリティ硬化（mlock/VirtualLock, PR_SET_DUMPABLE, RLIMIT_CORE, デバッガ検知）+ E2Eテスト + パフォーマンス検証をすべてS9で実装
2. **mlock対象**: Unix mlock + Windows VirtualLock の両方を実装。Unix側はコンパイルテストのみ（CI環境でのmlock制限を考慮）
3. **PR_SET_DUMPABLE + RLIMIT_CORE**: Unix のみ。Windows は対応不要
4. **デバッガ検知**: TracerPid（Unix）+ IsDebuggerPresent（Windows）。検知時は警告のみ、プロセスは中断しない
5. **mlock失敗時**: warn + continue（非特権ユーザーでのulimit制限を考慮）
6. **全技術的負債**: H-1, M-1〜M-5, 署名/HMAC検証の全項目をS9で対応確定
