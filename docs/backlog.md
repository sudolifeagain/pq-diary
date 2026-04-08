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

### S6: 検索 + 統計 + インポート
- [ ] search コマンド (復号後インメモリ正規表現grep)
- [ ] 検索結果のコンテキスト表示 (前後N行)
- [ ] stats コマンド (執筆頻度, 文字数推移, タグ分布)
- [ ] import <dir> (プレーンMD一括取り込み)
- [ ] [[wiki-link]] → [[タイトル]] 自動変換
- [ ] #ネスト/タグ 自動変換
- [ ] インポート結果サマリー表示

### S7: アクセス制御 + Claude連携
- [ ] vault.toml access.policy (none/write_only/full)
- [ ] vault create --policy <POLICY>
- [ ] vault policy <name> <POLICY> (変更)
- [ ] fullポリシー選択時の警告・承認フロー
- [ ] --claude フラグ
- [ ] 4層ポリシーチェック
- [ ] --claude new / list / show / sync

### S8: Git連携
- [ ] git-init [--remote URL]
- [ ] git-push / git-pull / git-sync / git-status
- [ ] .gitignore生成 (entries/*.md除外)
- [ ] author匿名化 (ランダムID@localhost)
- [ ] コミットメッセージ定型化 ("update")
- [ ] 末尾ランダムパディング (0-4096B)
- [ ] タイムスタンプファジング (単調増加保証)
- [ ] 3-wayマージ (UUID + content_hmac)
- [ ] コンフリクト対話式解決

### S9: セキュリティ硬化 + 統合テスト
- [ ] mlock (unix) / VirtualLock (windows)
- [ ] PR_SET_DUMPABLE=0
- [ ] setrlimit(RLIMIT_CORE, 0, 0)
- [ ] デバッガ接続検知 (警告)
- [ ] クロスプラットフォームビルド (Linux x86_64/aarch64, macOS aarch64, Windows x86_64)
- [ ] 統合テスト (全コマンドのE2Eテスト)
- [ ] パフォーマンス検証 (init<3s, unlock 1-3s, new/edit<200ms, list<500ms, lock<50ms)

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
