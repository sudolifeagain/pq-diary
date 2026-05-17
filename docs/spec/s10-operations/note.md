# S10 運用機能 + CLI整合性 - Context Note

## Tech Stack

- **Language**: Rust 2021 edition
- **Workspace**: `core/` (pq-diary-core ライブラリ) + `cli/` (バイナリ)
- **CLI**: clap (derive)
- **暗号**: `aes-gcm`, `argon2`, `ml-kem`/`ml-dsa` (RustCryptoフォーク), `zeroize`, `secrecy`
- **設定**: `toml` (serde)
- **エラー**: `thiserror` (core) / `anyhow` (cli)

## Existing Infrastructure

### vault 管理 (core/src/vault/init.rs)

- `VaultManager::init_vault(name, password)` — 個別 vault 初期化 (vault.pqd + vault.toml + entries/)
- `VaultManager::create_vault(name, password, policy)` — `init_vault` + 名前検証 + base_dir 作成 + set_policy
- `VaultManager::list_vaults()` / `list_vaults_with_policy()`
- `VaultManager::set_policy(name, policy)`
- `VaultManager::delete_vault(name, zeroize)`
- `VaultManager::default_vault()` — default vault 名取得 (現状ハードコード?)

### vault 設定 (core/src/vault/config.rs)

- `VaultConfig` (vault.toml) — `[vault]`/`[access]`/`[git]`/`[argon2]` セクション
- `VaultConfig::from_file()` / `to_file()`
- **AppConfig (config.toml) は未実装** — S10 で新規追加

### エントリ操作 (core/src/entry.rs)

- `create_entry`, `get_entry`, `update_entry`, `delete_entry`
- `list_entries`, `list_entries_with_body`
- 内部で AES-256-GCM 復号 + 署名/HMAC 検証 (S9 追加分)

### DiaryCore (core/src/lib.rs)

- `DiaryCore::new(vault_path)` — vault.pqd と vault.toml を読み込み
- `DiaryCore::unlock(password)` — マスターパスワードで復号
- 内部に `config: VaultConfig` を保持

### policy (core/src/policy.rs)

- `OperationType::Read` / `OperationType::Write` の 2 値分類
- `AccessPolicy::None` / `WriteOnly` / `Full`
- `check_access(is_claude, policy, op, vault_name)` で 4 層チェック
- `classify_operation(command)` — コマンド名から OperationType を返す
- **export は新規 OperationType として扱うか、Write 相当とするかが設計判断**

### git バックエンド (core/src/git.rs)

- `git_init`, `git_push`, `git_pull`, `git_sync`, `git_status` の高レベル API
- `sync` コマンドはこの `git_sync` を呼ぶラッパー

### CLI 共通 (cli/src/commands.rs)

- `resolve_vault_path(cli)` — `--vault` を vault.pqd or vault ディレクトリに解決
- `resolve_vaults_base_dir(cli)` — `--vault` を vaults 親ディレクトリに解決
- `get_password(cli.password.as_ref())` — 3段階パスワード取得 (flag/env/TTY)
- `check_claude_policy(cli, OperationType)` — 4層ポリシーチェック
- `VaultGuard` — DiaryCore のドロップ時 zeroize 保証

### CLI ディスパッチ (cli/src/main.rs)

- `Commands` enum で全コマンド clap 定義
- `dispatch()` 関数で `Commands::*` を `cmd_*` 実装に振り分け
- `not_implemented(cmd, sprint)` で未実装スケルトンを `anyhow::bail!` 化 (S9 完了済み)

### security (cli/src/security.rs)

- `harden_process()` — mlock + PR_SET_DUMPABLE + RLIMIT_CORE (S9 完了)
- `check_debugger()` — TracerPid / IsDebuggerPresent (S9 完了)
- **info --security から読み出す API は未整備** — S10 で追加

## S10 で実装する機能

### 1. `pq-diary init` (新規)

- グローバル設定 `~/.pq-diary/config.toml` (AppConfig) を作成
- "default" vault を policy=none で作成 (`VaultManager::create_vault` 流用)
- 既に init 済み (config.toml + default vault 両方存在) なら "Already initialized" エラー
- 性能目標: < 3 秒 (PRD L712)

### 2. `pq-diary sync` (新規)

- AppConfig の `sync_backend` を読んでディスパッチ
- Phase 1 では `"git"` のみ。不明値は `DiaryError::Config` で停止
- Git バックエンドの場合は `cmd_git_sync` を呼び出す薄いラッパー

### 3. `pq-diary change-password` (新規)

- 旧パスワード + 新パスワード両方を TTY 取得 (insecure フラグでは新パスワード渡せない)
- 全エントリをメモリ上に復号 → 新パスワードで全エントリ + ヘッダーを再暗号化
- `vault.pqd.tmp` に新 vault を書き出し → `rename` でアトミック差し替え
- 失敗時は旧 vault.pqd を維持、`vault.pqd.tmp` を zeroize 削除
- メモリ上の旧鍵・新鍵は `ZeroizingKey` でラップ

### 4. `pq-diary info` / `info --security` (新規)

- `info`: vault 名、policy、エントリ数、作成日時、最終更新
- `info --security`: 追加で Argon2 パラメータ、KEM/署名アルゴリズム、mlock 状態、コアダンプ無効化状態、デバッガ検知状態
- `security.rs` に `harden_status()` 等の状態取得 API を追加

### 5. `pq-diary export [DIR]` (新規)

- 全エントリを復号して指定ディレクトリへ平文 MD で書き出し
- ファイル名: `YYYY-MM-DD-{slug}-{id8}.md` (slug = タイトルから生成、id8 = UUID 先頭 8 文字)
- `--claude` 時は完全ブロック (`check_claude_policy` で `OperationType::Export` (新規)、または `Write` 相当)
- 実行前に警告 + [y/N] 確認プロンプト

### 6. AppConfig (~/.pq-diary/config.toml)

- 新規実装。`core/src/vault/config.rs` に `AppConfig` 構造体を追加
- フィールド: `default_vault: String`, `sync_backend: String` (デフォルト "git")
- `AppConfig::default_path()` でホームディレクトリ解決 (`dirs` クレート or 手書き)

### 7. DoD 強化

- `docs/definition-of-done.md` に「CLI 整合性」セクション追加
- CI smoke test スクリプト (`ci/smoke-test.sh` or `.ps1`)

### 8. 未実装スケルトン整理

- `legacy*` / `legacy-access` / `daemon*` を `#[command(hide = true)]` でヘルプから除外
- `not_implemented()` のメッセージを "Planned for Phase 2" に統一

## Development Rules (CLAUDE.md準拠)

- `unsafe` は既存許可リストのみ (mlock/VirtualLock/PR_SET_DUMPABLE/IsDebuggerPresent/Win32 Console API)
- 秘密データは `zeroize` / `SecretString` / `SecretBytes` 必須
- `unwrap()` / `expect()` はテストコードのみ
- core/ にプラットフォーム依存 UI コード禁止
- テストは `#[cfg(test)] mod tests` で各モジュールに

## Related Files

- `requirements.md`: PRD v4.0 (L218 init, L230 sync, L231 export, L234 change-password, L235 info, L712 性能)
- `docs/backlog.md`: Phase 2 セクションに change-password / info --security / export が並ぶ
- `core/src/vault/init.rs`: VaultManager (init_vault, create_vault 等)
- `core/src/vault/config.rs`: VaultConfig (AppConfig 追加先)
- `core/src/vault/writer.rs`: アトミック書き込み (change-password で参考)
- `core/src/entry.rs`: エントリ CRUD (change-password で全エントリ取得)
- `core/src/lib.rs`: DiaryCore (info で metadata 取得)
- `core/src/git.rs`: git_sync (sync コマンドで呼び出す)
- `core/src/policy.rs`: OperationType (export 追加判断)
- `cli/src/main.rs`: Commands enum (init/sync 既存スケルトン、legacy/daemon hide 化)
- `cli/src/commands.rs`: cmd_* 実装、check_claude_policy
- `cli/src/security.rs`: harden_process (info --security で状態取得 API 追加)

## Key Decisions from Interview

1. **作業規模**: フル機能開発 (詳細 EARS / 包括ユーザーストーリー / 完全受け入れ基準 / 非機能要件 / エッジケース)
2. **既存コードベース分析**: 実施 (init_vault と create_vault の関係、AppConfig 未実装等を確認)
3. **init と vault create の関係**: 責務切り分け (init = グローバル初期化 + default vault、vault create = 追加 vault)
4. **AppConfig (~/.pq-diary/config.toml)**: S10 で新規実装。default_vault + sync_backend を保持
5. **change-password アトミック性**: vault.pqd 全体を tmp + rename 方式。中断時は旧 vault.pqd 維持
6. **export ファイル名**: `YYYY-MM-DD-{slug}-{id8}.md` で UUID 8 文字プレフィックス付与 (衰突回避)
7. **legacy/daemon の取扱い**: `#[command(hide = true)]` でヘルプから隠す。Phase 2 で実装するため削除はしない
