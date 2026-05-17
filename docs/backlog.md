# Product Backlog

## Phase 1 (Sprint 1-9)

### S1: 基盤構築
- [x] Cargoワークスペース (core/ + cli/)
- [x] DiaryError定義 (thiserror)
- [x] SecureBuffer / ZeroizingKey自前実装
- [x] clap CLIスケルトン (全コマンドのサブコマンド定義)
- [x] CI (cargo test, clippy, audit)

### S2: 暗号コア
- [x] PQCフォーク作成 (ml-kem: zeroize補完, ml-dsa: Drop漏れ修正+CVE-2026-22705)
- [x] Argon2id鍵導出 (memory_cost 64MB, time_cost 3, parallelism 4)
- [x] AES-256-GCM暗号化/復号
- [x] ML-KEM-768鍵カプセル化/脱カプセル化
- [x] ML-DSA-65署名/検証
- [x] HMAC-SHA256 (content_hmac)

### S3: Vaultフォーマット + ストレージ
- [x] vault.pqd v4バイナリ読み書き
- [x] エントリレコード (legacy予約+添付ファイル予約フィールド含む)
- [x] テンプレートレコードタイプ
- [x] vault.toml パース/書き込み (メタデータ最小化)
- [x] config.toml パース
- [x] マルチVaultディレクトリ構造 (~/.pq-diary/vaults/)
- [x] 検証トークンによるパスワード正当性チェック

### S4: エントリ操作 + CLI
- [x] new (タイトル, ボディ, タグ指定)
- [x] list (タグフィルタ, クエリ, 件数制限)
- [x] show (ID_PREFIX指定)
- [x] edit ($EDITOR起動)
- [x] delete (確認プロンプト付き)
- [x] パスワード入力3段階 (--password / env / TTY termios)
- [x] $EDITOR一時ファイル制御 ($TMPDIR上書き, vimオプション強制)
- [x] 一時ファイルzeroize削除
- [x] ネストタグ (#親/子/孫, 前方一致検索)

### S5: デイリーノート + テンプレート + リンク
- [x] today コマンド (YYYY-MM-DDエントリ自動生成/開く)
- [x] テンプレートCRUD (template add/list/show/delete)
- [x] new --template <name>
- [x] [[タイトル]] リンク解決
- [x] バックリンクインデックス構築
- [x] show時にバックリンク表示
- [x] $EDITOR内vimカスタム補完関数 ([[入力時タイトル候補表示)
- [x] 補完用一時ファイル (/dev/shm, zeroize削除)

### S6: 検索 + 統計 + インポート + S1-S5技術的負債
- [x] search コマンド (復号後インメモリ正規表現grep)
- [x] 検索結果のコンテキスト表示 (前後N行)
- [x] stats コマンド (執筆頻度, 文字数推移, タグ分布)
- [x] import <dir> (プレーンMD一括取り込み)
- [x] [[wiki-link]] → [[タイトル]] 自動変換
- [x] #ネスト/タグ 自動変換
- [x] インポート結果サマリー表示
- [x] **[C-1/C-2]** vault reader にフィールドサイズ上限チェック追加 (S3) — reader.rs MAX_FIELD_SIZE=16MiB
- [x] **[H-3]** init_vault に空パスワードガード追加 (S3) — init.rs password.is_empty()
- [x] **[H-4]** writer の as u32/u8 を try_from に変換 (S3) — writer.rs 全箇所 u32::try_from
- [x] **[M-6]** write_vault をアトミック write (temp + rename) に変更 (S3) — writer.rs .tmp + rename
- [x] **[M-7]** vim に nowritebackup / viminfo=NONE 追加 (S4) — editor.rs viminfo=''/shada=''
- [x] **[M-8]** PQ_DIARY_PASSWORD 読み取り後に env::remove_var (S4) — password.rs
- [x] **[M-9]** tmp ファイルパーミッションを 0600 に (S4) — editor.rs mode(0o600)
- [x] **[M-5]** HMAC エラー時にゼロMAC返却でなくResult返却 (S2) — S9 で `hmac_util::compute` を `Result<[u8;32], DiaryError>` 化
- [x] EntryPlaintext に Zeroize/ZeroizeOnDrop 追加 (S4/S5技術的負債 H-1)
- [x] list_entries_with_body の中間 Vec<String> zeroize 対応 (S5 H-2) — Zeroizing<String>
- [x] 読み取り時の署名/HMAC 検証 (S4技術的負債 H-3) — S9 で `list_entries_with_body` / `get_entry` に `hmac_verify` + `dsa_verify_entry` を追加
- [x] Win32コンソールAPI unsafe の ADR 作成 (S5 M-7) — docs/adr/0007
- [x] CLI vault操作のボイラープレート抽出 (S5 L-2) — VaultGuard パターン

### S7: アクセス制御 + Claude連携
- [x] vault.toml access.policy (none/write_only/full)
- [x] vault create --policy <POLICY>
- [x] vault policy <name> <POLICY> (変更)
- [x] fullポリシー選択時の警告・承認フロー
- [x] --claude フラグ
- [x] 4層ポリシーチェック
- [x] --claude 全コマンド対応 (PRDの4コマンドから拡張)
- [x] vault list (名前+ポリシー表示)
- [x] vault delete [--zeroize]

### S8: Git連携
- [x] git-init [--remote URL]
- [x] git-push / git-pull / git-sync / git-status
- [x] .gitignore生成 (entries/*.md除外)
- [x] author匿名化 (ランダムID@localhost)
- [x] コミットメッセージ定型化 ("update")
- [x] 末尾ランダムパディング (0-4096B)
- [x] タイムスタンプファジング (単調増加保証)
- [x] 3-wayマージ (UUID + content_hmac, last-write-wins)
- [x] コンフリクト対話式解決 (--claude時ローカル優先自動解決)

### S9: セキュリティ硬化 + 統合テスト + S1-S6技術的負債残り
- [x] mlock (unix) / VirtualLock (windows) — secure_mem.rs mlock_buffer/munlock_buffer
- [x] PR_SET_DUMPABLE=0 — cli/src/security.rs harden_process()
- [x] setrlimit(RLIMIT_CORE, 0, 0) — cli/src/security.rs harden_process()
- [x] デバッガ接続検知 (警告) — cli/src/security.rs check_debugger()
- [x] クロスプラットフォームビルド (Linux x86_64/aarch64, macOS aarch64, Windows x86_64) — **S11 で CI matrix 化により完了** (全 8 ジョブ green)
- [x] 統合テスト (全コマンドのE2Eテスト)
- [x] パフォーマンス検証 (init<3s, unlock 1-3s, new/edit<200ms, list<500ms, lock<50ms) — #[ignore]で分離、単独実行で検証
- [x] **[H-1]** Cli.password を SecretString 化 (S1) — Option<SecretString> + parse_secret_string
- [x] **[H-2]** tc_015_05 テストの UB 修正 (ManuallyDrop) (S1/S2)
- [x] **[M-2]** MasterKey中間バッファのcopy_from_slice化 (S1) — .clone()を排除
- [x] **[M-4]** unlock_with_vault の中間バッファ直接コピー (S2) — copy_from_slice
- [x] **[M-3]** PQC 依存を commit hash で pin (S1/S2) — rev指定に変更
- [x] **[M-1]** not_implemented() を anyhow::bail! に変更 (S1)
- [x] **[M-5]** verify_hmac を Result<bool, DiaryError> 返却に変更 (S2/S6)
- [x] 読み取り時の署名/HMAC 検証 (S4/S6) — entry.rs get_entry/list_entries_with_body

### S10: 運用機能 + CLI整合性
- [x] init コマンド実装 (新規、PRD L218) — cmd_init: config.toml + default vault
- [x] sync コマンド実装 (新規、config 駆動ディスパッチャ) — cmd_sync: cmd_git_sync を委譲
- [x] change-password (全エントリ再暗号化、Phase 2 から繰上げ) — core/src/vault/change_password.rs + cmd_change_password (TTY 2回入力 echo OFF)
- [x] info / info --security (Phase 2 から繰上げ) — cmd_info: Vault Info + Security ブロック (harden_status())
- [x] export [DIR] (Phase 2 から繰上げ) — cmd_export: YAML フロントマター手書き、`YYYY-MM-DD-{slug}-{id8}.md`、--claude ブロック
- [x] AppConfig (~/.pq-diary/config.toml) 新規実装 — core/src/vault/config.rs::AppConfig (default_vault + sync_backend)
- [x] harden_status() API + HardenStatus 構造体 — cli/src/security.rs (mlock/coredump/debugger 実プロセス状態)
- [x] legacy*/legacy-access/daemon* を hide 化 — `#[command(hide = true)]` でヘルプから除外
- [x] not_implemented メッセージを "Planned for Phase 2" に統一 (9 箇所)
- [x] CI smoke test スクリプト追加 — ci/smoke-test.sh + ci/smoke-test.ps1 + .github/workflows/ci.yml smoke ジョブ
- [x] DoD 強化「CLI 整合性」セクション追加 — definition-of-done.md
- [x] dirs クレート依存追加 — cli/Cargo.toml + core/Cargo.toml
- [x] password.rs read_password_tty(prompt) パラメータ化 — change-password の echo OFF 対応 (PRD §4.2 第3項遵守)

### S11: クロスプラットフォーム検証 + toolchain 固定
- [x] `rust-toolchain.toml` 固定 (channel = "1.95.0", components = clippy/rustfmt, profile = minimal) — CI と local の rustc 同期恒久化
- [x] CI check ジョブを 3 OS matrix 化 (ubuntu/macos/windows, fail-fast: false)
- [x] CI smoke ジョブを 4 OS matrix 化 (+ macos-latest + ubuntu-24.04-arm preview)
- [x] cargo audit を独立ジョブに分離 (ubuntu のみ、重複排除)
- [x] **Phase 1 取りこぼし「クロスプラットフォームビルド」完了** (S9 セクション参照)
- [x] **発覚バグ修正**: `cli/src/security.rs` の `prctl(PR_SET_DUMPABLE)` を `#[cfg(target_os = "linux")]` でガード (macOS libc に prctl 不在のため) — S9 で書かれた荒い `#[cfg(unix)]` 分岐の修正
- [x] hotfix branch も CI trigger 対象に追加 (`branches: [main, "sprint/**", "hotfix/**"]`)
- [x] S10 hotfix (PR #3) の Cargo.lock コミット + --locked 強制と組み合わせて、ローカル/CI 完全同期環境を達成

---

## Phase 2 (未スケジュール、change-password / info --security / export / legacy は S10–S12 で完了)

- [x] デジタル遺言 (K_legacy, INHERIT/DESTROY, legacy-access) — S12 で完了
- [ ] Unixソケット + ロックデーモン (V-1〜V-8対策)
- [ ] 鍵素材のXOR分散保持
- [ ] 固定ブロックサイズ化 (64KB単位, OQ-20)
- [x] 添付ファイル (バイナリ暗号化, v4予約フィールド使用) — S13 で完了 (PR #7 設計 + 実装 PR)
- [ ] Web Clipper連携 (clip --url / パイプ入力)
- [ ] Basesライクビュー (list拡張: 複合フィルタ・ソート・JSON出力)
- [x] change-password (全エントリ再暗号化) — S10 で完了
- [x] info --security — S10 で完了
- [x] export [DIR] — S10 で完了

## Phase 3 (モバイル・将来)

- [ ] UniFFIバインディング (Swift / Kotlin)
- [ ] iOS / Androidアプリ
- [ ] git2クレートによるGit同期
- [ ] Shamir's Secret Sharing (デジタル遺言秘密分散)

## Phase 4 (HQC標準化後 2027年〜)

- [ ] HQC FIPS最終標準確認
- [ ] RustCrypto品質 pure Rust HQC実装の採用
- [ ] ML-KEM + HQCハイブリッドKEM
- [x] vault.pqd v4 → v5マイグレーション — S13 で attachment record (`RECORD_TYPE=0x03`) を追加するため schema_version を v5 に bump、reader は v4/v5 両受理 (v5→v6 への将来 migration は HQC 標準化後を想定)

## Open Questions

| # | 問題 | 状態 |
|---|------|------|
| OQ-1 | force push後のmerge-base失敗 | オープン |
| OQ-6 | SSD wear levelingのユーザー周知 | ドキュメント |
| OQ-7 | バイナリ形式のデバッグ手段 (--debug JSON出力) | S4で実装 |
| OQ-16 | fullポリシーへの間接プロンプトインジェクション | ドキュメント |
| OQ-18 | legacy-access後のvault暗号鍵 | S12で確定: K_legacy が新マスター鍵、kdf_salt=元 legacy_salt、KEM/DSA は新規生成 |
| OQ-19 | タイムスタンプファジングとmerge-baseの関係 | S8で検証 |
