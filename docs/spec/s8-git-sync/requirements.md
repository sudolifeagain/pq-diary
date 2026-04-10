# S8 Git Sync 要件定義書

## 概要

Sprint 8ではGit同期機能を実装する。`core/src/git.rs` のスタブを完全実装し、git-init / git-push / git-pull / git-sync / git-status の5コマンドを提供する。プライバシー強化3点セット（author匿名化・メッセージ定型化・追加パディング）とタイムスタンプファジングにより、Gitコミット履歴からの情報漏洩を最小化する。git-pullではエントリ単位の3-wayマージ（UUID + content_hmac）を実行し、コンフリクト時は対話式解決または `--claude` 時のローカル優先自動解決を提供する。

## 関連文書

- **ヒアリング記録**: [interview-record.md](interview-record.md)
- **ユーザストーリー**: [user-stories.md](user-stories.md)
- **受け入れ基準**: [acceptance-criteria.md](acceptance-criteria.md)
- **コンテキストノート**: [note.md](note.md)
- **PRD**: [requirements.md](../../requirements.md) (v4.0, section 11)
- **ADR-0006**: [0006-git-sync-strategy.md](../../adr/0006-git-sync-strategy.md)

## 機能要件（EARS記法）

**【信頼性レベル凡例】**:
- 🔵 **青信号**: PRD・設計文書・ユーザヒアリングを参考にした確実な要件

### Git Init（REQ-001〜005）

- REQ-001: `git-init` はVaultディレクトリ内で `.git` を初期化しなければならない 🔵 *PRD 4.1 + PRD 11.1*
- REQ-002: `git-init` は `.gitignore` を生成し、`entries/*.md` を除外対象に含めなければならない 🔵 *PRD 11.2*
- REQ-003: `git-init` はランダムな `author_email`（8桁hex + `@localhost`）を生成し、vault.toml の `[git].author_email` に保存しなければならない 🔵 *PRD 11.3 + ADR-0006 + ヒアリングQ2「git-init時に生成」*
- REQ-004: `git-init` は `author_name` を `"pq-diary"` に設定し、vault.toml の `[git].author_name` に保存しなければならない 🔵 *PRD 11.3 + ADR-0006*
- REQ-005: `git-init --remote URL` は `origin` としてリモートリポジトリを追加しなければならない 🔵 *PRD 4.1*

### Git Push（REQ-010〜017）

- REQ-010: `git-push` は `vault.pqd` と `vault.toml` をステージング対象にしなければならない 🔵 *PRD 11.2*
- REQ-011: `git-push` は vault.toml に保存された匿名化author情報（`pq-diary <{random}@localhost>`）をコミットに使用しなければならない 🔵 *PRD 11.3 + ADR-0006*
- REQ-012: `git-push` は vault.toml の `[git].commit_message` に設定された定型メッセージ（デフォルト `"Update vault"`）をコミットメッセージに使用しなければならない 🔵 *PRD 11.3 + ADR-0006*
- REQ-013: `git-push` はコミット前に vault.pqd に対してランダムな追加パディング（0 〜 `extra_padding_bytes_max` バイト）を付与しなければならない 🔵 *PRD 11.3 + ADR-0006*
- REQ-014: `git-push` は `GIT_AUTHOR_DATE` / `GIT_COMMITTER_DATE` 環境変数を設定し、タイムスタンプファジングを適用しなければならない 🔵 *PRD 11.3 + ADR-0006*
- REQ-015: タイムスタンプファジングは単調増加を保証しなければならない（ファジング後の時刻 > 前回ファジング後の時刻） 🔵 *PRD 11.3 + ADR-0006*
- REQ-016: `git-push` はパスワード入力を要求しなければならない（vault.pqd の追加パディング付き再書き込みのため） 🔵 *ヒアリングQ3「pushはPW必要（パディング再書き込み）」*
- REQ-017: `git-push` は `git add` → `git commit` → `git push` を `std::process::Command` で実行しなければならない 🔵 *ADR-0006*

### Git Pull + Merge（REQ-020〜028）

- REQ-020: `git-pull` はリモートリポジトリからフェッチしなければならない 🔵 *PRD 4.1*
- REQ-021: `git-pull` はエントリ単位の3-wayマージ（UUID + content_hmac）を実行しなければならない 🔵 *PRD 11.4*
- REQ-022: `git-pull` は vault.pqd 復号のためにパスワード入力を要求しなければならない 🔵 *ヒアリングQ3「pullはPW必要（UUID/HMACマージのため）」*
- REQ-023: マージはエントリの同一性をUUIDで判定しなければならない 🔵 *PRD 11.4*
- REQ-024: マージはエントリの変更をcontent_hmac比較で検出しなければならない 🔵 *PRD 11.4 + OQ-19*
- REQ-025: 両側で同一UUIDのエントリが変更された場合（コンフリクト）、対話式プロンプトでユーザーに解決を求めなければならない（CLI） 🔵 *PRD 11.4*
- REQ-026: `--claude` フラグ使用時のコンフリクトは、ローカル側を自動的に優先して解決しなければならない 🔵 *ヒアリングQ3「--claudeコンフリクト: ローカル勝ち」*
- REQ-027: リモートにのみ存在する新規エントリは追加し、リモートで削除されたエントリは削除しなければならない 🔵 *標準マージ動作*
- REQ-028: マージ完了後、vault.pqd を再暗号化しアトミックに書き込まなければならない 🔵 *既存write_vaultパターン*

### Git Sync（REQ-030〜031）

- REQ-030: `git-sync` は `pull` → `push` の順序で実行しなければならない 🔵 *ヒアリングQ3「sync = pull → push」*
- REQ-031: `git-sync` はパスワード入力を要求しなければならない（pullがPWを必要とするため） 🔵 *ヒアリングQ3*

### Git Status（REQ-040）

- REQ-040: `git-status` は `git status` コマンドの出力をラップして表示しなければならない 🔵 *PRD 4.1*

### プライバシー要件（REQ-050〜054）

- REQ-050: すべてのgitコマンド実行前に `git --version` チェックを行い、gitが利用可能であることを確認しなければならない 🔵 *PRD 11.1 + ADR-0006*
- REQ-051: `.gitignore` は `entries/*.md` 除外を含まなければならない 🔵 *PRD 11.2*
- REQ-052: コミットauthorは常に `pq-diary <{random}@localhost>` 形式でなければならない 🔵 *PRD 11.3 + ADR-0006*
- REQ-053: コミットメッセージは常に vault.toml の `[git].commit_message` の値でなければならない 🔵 *PRD 11.3 + ADR-0006*
- REQ-054: `extra_padding_bytes_max = 0` の場合、追加パディングを無効化しなければならない 🔵 *config.rs デフォルト値仕様*

### 制約要件

- REQ-401: git操作は `std::process::Command` を使用しなければならない（git2クレート不使用） 🔵 *ADR-0006*
- REQ-402: gitロジックは `core/src/git.rs` に配置し、CLIハンドラは `cli/src/commands.rs` に配置しなければならない 🔵 *CLAUDE.md規約*
- REQ-403: Phase 1ではデスクトップのみ対応（モバイルgitはPhase 3） 🔵 *PRD 11.1*

## 非機能要件

### パフォーマンス

- NFR-001: `git --version` チェックは 100ms 未満で完了しなければならない 🔵 *ADR-0006「起動時に確認」*
- NFR-002: git-push / git-pull / git-sync は既存パフォーマンス目標を遵守しなければならない 🔵 *PRD 12.1*

### セキュリティ

- NFR-101: gitコミットメッセージおよびauthorフィールドに秘密情報を含めてはならない 🔵 *PRD 11.3*
- NFR-102: `entries/*.md` がgitにコミットされてはならない 🔵 *PRD 11.2*

## Edgeケース

### エラー処理

- EDGE-001: gitが未インストールの場合、分かりやすいエラーメッセージを表示する 🔵 *PRD 11.1 + ADR-0006*
- EDGE-002: リモートが未設定の場合、git-push / git-pull でエラーを返す 🔵 *標準git動作*
- EDGE-003: `.git` が未初期化の場合、git-push / git-pull / git-sync / git-status でエラーを返す 🔵 *標準git動作*
- EDGE-004: リモートが空（エントリなし）の場合、マージはno-opとなる 🔵 *標準マージ動作*
- EDGE-005: ローカルが空（エントリなし）の場合、リモートの全エントリを受け入れる 🔵 *標準マージ動作*
- EDGE-006: 既にgit初期化済みのVaultで `git-init` を実行した場合、エラーを返す 🔵 *重複初期化防止*
