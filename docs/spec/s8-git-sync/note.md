# S8 Git Sync - Context Note

## Tech Stack

- **Language**: Rust 2021 edition
- **Workspace**: `core/` (pq-diary-core) + `cli/` (binary)
- **Git操作**: git CLI直接呼び出し (`std::process::Command`)。git2クレートはデスクトップでは不使用
- **CLI**: clap (derive)
- **Config**: toml, serde

## Existing Infrastructure

### Git Module (`core/src/git.rs`)
- Pure stub: 4行（doc commentのみ）
- `//! Git synchronisation operations.`
- `//! Full implementation is planned for Sprint 8.`

### Error型 (`core/src/error.rs`)
- `DiaryError::Git(String)` variant が既に存在

### Vault Config (`core/src/vault/config.rs`)
- `GitSection` 構造体:
  - `author_name: String`（デフォルト: 空文字列）
  - `author_email: String`（デフォルト: 空文字列）
  - `commit_message: String`（デフォルト: `"Update vault"`）
  - `privacy: GitPrivacySection`
- `GitPrivacySection` 構造体:
  - `timestamp_fuzz_hours: u64`（デフォルト: 0）
  - `extra_padding_bytes_max: usize`（デフォルト: 0）
- vault.toml `[git]` / `[git.privacy]` セクション対応済み

### Writer (`core/src/vault/writer.rs`)
- `write_vault`: 512-4096B のランダム末尾パディングを付与
- エントリ単位の padding フィールド（最大255B）
- git-push用の追加パディングは未実装（S8で実装）

### ADR-0006: Git同期方式
- デスクトップ: git CLI直接呼び出し
- モバイル(Phase 3): git2クレート
- プライバシー強化3点セット: author匿名化 + メッセージ定型化 + コミット毎パディング
- タイムスタンプファジング: GIT_AUTHOR_DATE/GIT_COMMITTER_DATE でランダム化、単調増加保証

### CLI (`cli/src/main.rs`)
- `--claude` グローバルフラグ
- VaultGuard RAIIパターン（lock/unlock）

## Development Rules

- `unsafe` only for mlock/VirtualLock/PR_SET_DUMPABLE/Win32 Console API
- Secrets must use zeroize / SecretString / SecretBytes
- No unwrap()/expect() in production code
- Errors via thiserror (core) / anyhow (cli only)
- Tests in `#[cfg(test)] mod tests` per module

## Related Files

- `requirements.md` section 11: Git同期要件
- `docs/adr/0006-git-sync-strategy.md`: Git同期方式ADR
- `core/src/git.rs`: Stub to implement
- `core/src/vault/config.rs`: GitSection / GitPrivacySection
- `core/src/vault/writer.rs`: パディング実装（基盤）
- `core/src/error.rs`: DiaryError::Git exists
- `cli/src/main.rs`: --claude flag, VaultCommands
- `cli/src/commands.rs`: Command implementations

## Key Decisions from Interview

1. **S8フルスコープ**: git-init / git-push / git-pull / git-sync / git-status + プライバシー3点セット + タイムスタンプファジング + 3-wayマージ + コンフリクト解決をすべてS8で実装
2. **author_email生成タイミング**: git-init時に生成（vault create時ではない）。8桁ランダムhex + `@localhost`
3. **sync = pull → push**: git-syncはpullを先に実行し、その後pushを実行する
4. **--claude コンフリクト解決**: ローカル側が自動的に勝つ（対話プロンプトなし）
5. **git-pullのパスワード要否**: パスワード必要（vault.pqd復号によるUUID/HMACマージのため）
6. **エントリ同一性判定**: UUID + content_hmac（タイムスタンプではない）。OQ-19に準拠
7. **git-init/push/statusのパスワード要否**: git-initとgit-statusはPW不要。git-pushはPW必要（vault.pqdに追加パディングを書き込むため再暗号化が必要）
8. **.gitignore**: `entries/*.md` を除外対象に含める
