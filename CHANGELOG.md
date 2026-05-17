# Changelog

All notable changes to pq-diary are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Sprint tags (`s{N}-done`) mark the merge of each scope into `main`.

## [Unreleased]

### Documentation
- Phase 2 棚卸し: CHANGELOG.md 新規作成、`docs/backlog.md` の古い `[ ]` 表現補正、`requirements.md` に vault.pqd v4 → v5 migration ノート追加 (S14)

## [s13.1] - 2026-05-18

### Added
- `pq-diary import` で `![[FILE]]` 参照を `<DIR>/attachments/<FILE>` から自動取り込み (`importer::parse_obsidian_attachment_links` を統合)
- export → import の双方向 Obsidian 互換 round-trip 成立

### Tests
- `TC-S13-110-01` / `TC-S13-110-02` (取り込み成立 / 不在時 warning)

## [s13] - 2026-05-18 — 添付ファイル

### Added
- 新規モジュール `core/src/attachment.rs` (5 公開 API: `add/list/extract/delete/set_attachment_legacy_flag`)
- 新規モジュール `core/src/crypto/streaming.rs` (1MB chunk + AES-256-GCM、AAD = chunk_index || total || blob_uuid)
- `RECORD_TYPE_ATTACHMENT = 0x03` を新設、`AttachmentRecord` 構造体追加
- `AttachmentPlaintext` (K_master 暗号化) + `AttachmentLegacyPlaintext` (K_legacy 暗号化) の分離設計
- CLI `attachment add/list/extract/delete/set` + `new --attach <FILE>` + `show` 拡張 (Attachments セクション)
- `export <DIR>` で `<DIR>/attachments/` 別ディレクトリ + `![[FILE]]` 埋め込み
- legacy 連動: ファイル個別 INHERIT/DESTROY フラグ、エントリ DESTROY 時の自動連動 (REQ-504)
- SHA-256 重複排除 + 参照カウント方式の delete

### Changed
- vault.pqd `schema_version` を `0x04` → `0x05` に更新
- reader は `SCHEMA_VERSION_MIN (0x04)` 〜 `SCHEMA_VERSION (0x05)` を受理 (後方互換 EDGE-301)
- `change-password` で attachment メタデータも再暗号化 (`.bin` 本体は不変 — ランダム FileKey 設計)
- `legacy-access` の `LegacyAccessReport` を attachment 統計まで拡張 (`inherited_attachments` / `destroyed_attachments`)

### Security
- 添付本体は per-blob FileKey で暗号化 (K_master からの独立) → change-password で `.bin` 再暗号化が不要
- chunk AAD で reorder / truncation / file substitution を検出
- 1GB chunk 処理でメモリピーク ≤ 6MB

## [s12] - 2026-05-18 — デジタル遺言

### Added
- 新規モジュール `core/src/legacy.rs` — `LegacyKeyDeriver` trait, `Argon2LegacyDeriver`, `LegacyFlag`, `LegacyEntryStatus`, `LegacyAccessReport`
- 5 つの core API: `initialize_legacy`, `set_entry_flag`, `list_legacy_status`, `rotate_legacy_code`, `execute_legacy_access`
- `vault.toml [legacy]` セクション追加 (`initialized`, `destroy_confirmation`, `verification_iv_b64`, `verification_ct_b64`)
- 確認 UI 3 モード: `timer30` (30秒タイマー + y/N), `yn` (即時), `phrase` (`DESTROY ALL` 入力)
- CLI: `pq-diary legacy init/set/list/rotate` + `pq-diary legacy-access`
- legacy/legacy-access の `#[command(hide)]` を解除

### Changed
- `vault.toml` 既存セクションは `#[serde(default)]` で後方互換性維持

### Security
- 死後アクセスコードは Argon2 で K_legacy に導出、K_master と独立
- `--claude` ブロックは Argon2 cycle 消費前に行う (NFR-104)
- `legacy-access` 後、新 vault は K_legacy をマスター鍵として再構築、DESTROY エントリは zeroize 削除

## [s11] - 2026-05-17 — クロスプラットフォーム検証 + toolchain 固定

### Added
- `rust-toolchain.toml` で Rust 1.95.0 を固定 (CI と local の同期)
- CI matrix を ubuntu / macos / windows + ubuntu-24.04-arm に拡張
- `cargo audit` を独立ジョブに分離

### Fixed
- macOS で `prctl` が利用不能 → `#[cfg(target_os = "linux")]` で gate
- `cargo audit` の rand 0.8 警告は既存仕様として allowed-warnings 化

### Documentation
- Phase 1「クロスプラットフォームビルド」項目を完了マーク

## [s10] - 2026-05-17 — 運用機能 + CLI 整合性

### Added
- `pq-diary init` — `~/.pq-diary/config.toml` 生成 + default vault 初期化
- `pq-diary sync` — config-driven dispatcher (Phase 1 は git バックエンド固定)
- `pq-diary change-password` — 全エントリの再暗号化、`vault.pqd.tmp` → atomic rename
- `pq-diary info [--security]` — vault メタ情報 + 鍵パラメータ + harden_status
- `pq-diary export [DIR]` — 全エントリ復号 + YAML フロントマター手書き、`<DIR>/<date>-<slug>-<id>.md`
- `ci/smoke-test.{sh,ps1}` — CLI 整合性検証 + 主要 E2E (init/new/list/info/export)
- DoD に「CLI ヘルプと実装の整合性」項目追加

### Changed
- legacy/daemon サブコマンドを `#[command(hide = true)]` でヘルプから除外 (legacy は S12 で解除)
- `not_implemented` メッセージを統一

### Hotfix (post-merge)
- `Cargo.lock` を `.gitignore` から外して commit (CI 依存ドリフト解消)
- `nix 0.29` API 変更 (`mlock`/`munlock` が `NonNull<c_void>` 要求) に追従
- Rust 1.95 新 clippy lints (`manual_checked_ops`, `unnecessary_sort_by`, `suspicious_open_options`) 対応

## [s9] - 2026-04-11 — セキュリティ硬化 + 統合テスト + 技術的負債

### Added
- Linux `mlock` / Windows `VirtualLock` でマスター鍵のスワップ防止
- Linux `prctl(PR_SET_DUMPABLE, 0)` + `RLIMIT_CORE = 0` でコアダンプ抑止
- Windows `IsDebuggerPresent` チェック
- 統合テスト + パフォーマンス検証 (`#[ignore]` 付きで CI sandbox 制約を回避)

### Fixed
- **[M-5]** `crypto::hmac_util` を `Result<bool, DiaryError>` 返却に変更 (S2 技術的負債)
- **[H-3]** 読み取り時の ML-DSA 署名 + HMAC 検証 (S4 技術的負債)
- `Cli.password` を `Option<SecretString>` に変更 (S9 H-1)
- `not_implemented` を `anyhow::bail!` 化 (S9 M-1)

### Documentation
- ADR 0007: Win32 Console API unsafe の正当化

## [s8] - 2026-04-11 — Git 連携

### Added
- `pq-diary git-init/push/pull/sync/status` — git CLI 経由の同期
- Git privacy 強化: 匿名 author, 定型 commit message, padding, タイムスタンプ ファジング
- 3-way マージ (UUID + content_hmac ベース、`--claude` 自動解決パターン)

## [s7] - 2026-04-10 — アクセス制御 + Claude 連携

### Added
- vault.toml `access.policy` (`none` / `write_only` / `full`)
- `pq-diary vault create --policy` + `pq-diary vault policy <name> <policy>`
- `--claude` フラグ + 4 層ポリシーチェック (CLI / DiaryCore / 操作毎 / 出力)

## [s6] - 2026-04-09 — 検索 + 統計 + インポート

### Added
- `pq-diary search` — 全エントリ復号 + インメモリ正規表現 grep + コンテキスト表示
- `pq-diary stats` — 執筆頻度 / 文字数推移 / タグ分布 / `--heatmap`
- `pq-diary import <DIR>` — Obsidian 互換 (`[[link|alias]]` → `[[link]]`, `#tag` 抽出)

### Fixed
- S1-S5 の技術的負債回収: vault reader フィールドサイズ上限、`init_vault` 空パスワードガード、`writer` `try_from`、atomic write、vim の `nowritebackup/viminfo=NONE`、tmp ファイル `0o600`

## [s5] - 2026-04-08 — デイリーノート + テンプレート + リンク

### Added
- `pq-diary today` — `YYYY-MM-DD` エントリの自動生成 / 開く
- テンプレート CRUD (`template add/list/show/delete`, `new --template <name>`)
- `[[タイトル]]` リンク解決 + バックリンクインデックス
- `$EDITOR` 内 vim カスタム補完関数 (`[[` 入力時にタイトル候補表示)

## [s4] - 2026-04-05 — エントリ操作 + CLI

### Added
- Entry CRUD: `new` / `list` / `show` / `edit` / `delete`
- パスワード入力 3 段階: `--password` / `PQ_DIARY_PASSWORD` env / TTY (termios echo OFF)
- `$EDITOR` 一時ファイル制御 (`$TMPDIR` 上書き, vim オプション強制)、tmp ファイル zeroize 削除
- ネストタグ (`#親/子/孫`、前方一致検索)

## [s3] - 2026-04-03 — Vault フォーマット + ストレージ

### Added
- vault.pqd v4 バイナリ読み書き (添付ファイル予約フィールド含む)
- `vault.toml` / `config.toml` パース
- マルチ vault ディレクトリ構造 (`~/.pq-diary/vaults/`)
- 検証トークンによるパスワード正当性チェック

## [s2] - 2026-04-03 — 暗号コア

### Added
- ML-KEM-768 / ML-DSA-65 (RustCrypto フォーク、`zeroize` 補完 + `Drop` 漏れ修正 + CVE-2026-22705)
- Argon2id 鍵導出 (memory 64MB / time 3 / parallelism 4)
- AES-256-GCM 暗号化 / 復号
- HMAC-SHA-256

## [s1] - 2026-04-03 — 基盤構築

### Added
- Cargo workspace (`core/` + `cli/`)
- `DiaryError` (thiserror) / `SecureBuffer` / `ZeroizingKey`
- `clap` CLI スケルトン (全コマンドの subcommand 定義)
- CI (`cargo test`, `clippy`, `audit`)

---

## Migration Notes

### vault.pqd v4 → v5 (S13)

S13 で `schema_version` を `0x04` → `0x05` に bump。物理レイアウトは v4 と同一だが、
新たに `RECORD_TYPE_ATTACHMENT (0x03)` レコードが payload に出現する可能性がある。

- **読み込み**: S13+ クライアントは v4 / v5 両方を受け入れる (`SCHEMA_VERSION_MIN = 0x04`)
- **書き込み**: 常に v5 を書く — v4 vault は次回 write で自動的に v5 化される
- **古いクライアント (S12 以前) → v5 vault**: `schema_version` チェックで拒絶される。基本的に S13+ クライアントのみで開く運用を推奨。
