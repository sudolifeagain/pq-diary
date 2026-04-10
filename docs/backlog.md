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
- [ ] new (タイトル, ボディ, タグ指定)
- [ ] list (タグフィルタ, クエリ, 件数制限)
- [ ] show (ID_PREFIX指定)
- [ ] edit ($EDITOR起動)
- [ ] delete (確認プロンプト付き)
- [ ] パスワード入力3段階 (--password / env / TTY termios)
- [ ] $EDITOR一時ファイル制御 ($TMPDIR上書き, vimオプション強制)
- [ ] 一時ファイルzeroize削除
- [ ] ネストタグ (#親/子/孫, 前方一致検索)

### S5: デイリーノート + テンプレート + リンク
- [ ] today コマンド (YYYY-MM-DDエントリ自動生成/開く)
- [ ] テンプレートCRUD (template add/list/show/delete)
- [ ] new --template <name>
- [ ] [[タイトル]] リンク解決
- [ ] バックリンクインデックス構築
- [ ] show時にバックリンク表示
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
- [ ] **[M-5]** HMAC エラー時にゼロMAC返却でなくResult返却 (S2) → S9で対応
- [x] EntryPlaintext に Zeroize/ZeroizeOnDrop 追加 (S4/S5技術的負債 H-1)
- [x] list_entries_with_body の中間 Vec<String> zeroize 対応 (S5 H-2) — Zeroizing<String>
- [ ] 読み取り時の署名/HMAC 検証 (S4技術的負債 H-3) → S9で対応
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
- [ ] mlock (unix) / VirtualLock (windows)
- [ ] PR_SET_DUMPABLE=0
- [ ] setrlimit(RLIMIT_CORE, 0, 0)
- [ ] デバッガ接続検知 (警告)
- [ ] クロスプラットフォームビルド (Linux x86_64/aarch64, macOS aarch64, Windows x86_64)
- [ ] 統合テスト (全コマンドのE2Eテスト)
- [ ] パフォーマンス検証 (init<3s, unlock 1-3s, new/edit<200ms, list<500ms, lock<50ms)
- [ ] **[H-1]** Cli.password を SecretString 化 (S1, zeroize対応) — 現在 Option<String>
- [x] **[H-2]** tc_015_05 テストの UB 修正 (ManuallyDrop パターン適用) (S1/S2) — dsa.rs/kem.rs ManuallyDrop済
- [ ] **[M-2]** MasterKey.sym_key コピー時の zeroize 対応 (S1)
- [ ] **[M-4]** unlock_with_vault の中間 Vec<u8> を Zeroizing でラップ (S2)
- [ ] **[M-3]** PQC 依存 (ml-kem/ml-dsa) を commit hash で pin (S1/S2) — 現在 branch指定
- [ ] **[M-1]** not_implemented() を process::exit から anyhow::bail! に変更 (S1) — 4箇所残存
- [ ] **[M-5]** verify_hmac をbool返却からResult返却に変更 (S2/S6繰越)
- [ ] 読み取り時の署名/HMAC 検証 (S4/S6繰越)

---

## Phase 2 (未スケジュール)

- [ ] デジタル遺言 (K_legacy, INHERIT/DESTROY, legacy-access)
- [ ] Unixソケット + ロックデーモン (V-1〜V-8対策)
- [ ] 鍵素材のXOR分散保持
- [ ] 固定ブロックサイズ化 (64KB単位, OQ-20)
- [ ] 添付ファイル (バイナリ暗号化, v4予約フィールド使用)
- [ ] Web Clipper連携 (clip --url / パイプ入力)
- [ ] Basesライクビュー (list拡張: 複合フィルタ・ソート・JSON出力)
- [ ] change-password (全エントリ再暗号化)
- [ ] info --security
- [ ] export [DIR]

## Phase 3 (モバイル・将来)

- [ ] UniFFIバインディング (Swift / Kotlin)
- [ ] iOS / Androidアプリ
- [ ] git2クレートによるGit同期
- [ ] Shamir's Secret Sharing (デジタル遺言秘密分散)

## Phase 4 (HQC標準化後 2027年〜)

- [ ] HQC FIPS最終標準確認
- [ ] RustCrypto品質 pure Rust HQC実装の採用
- [ ] ML-KEM + HQCハイブリッドKEM
- [ ] vault.pqd v4 → v5マイグレーション

## Open Questions

| # | 問題 | 状態 |
|---|------|------|
| OQ-1 | force push後のmerge-base失敗 | オープン |
| OQ-6 | SSD wear levelingのユーザー周知 | ドキュメント |
| OQ-7 | バイナリ形式のデバッグ手段 (--debug JSON出力) | S4で実装 |
| OQ-16 | fullポリシーへの間接プロンプトインジェクション | ドキュメント |
| OQ-18 | legacy-access後のvault暗号鍵 | Phase 2 |
| OQ-19 | タイムスタンプファジングとmerge-baseの関係 | S8で検証 |
