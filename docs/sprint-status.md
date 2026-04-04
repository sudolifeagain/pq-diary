# Sprint Status

## Current: Sprint 4 — エントリ操作 + CLI (completed)

## Progress

| Sprint | テーマ | Status | Week |
|--------|--------|--------|------|
| S1 | 基盤構築 | completed (s1-done) | 1 |
| S2 | 暗号コア | completed (s2-done) | 2 |
| S3 | Vaultフォーマット | completed (s3-done) | 3 |
| S4 | エントリ操作 + CLI | completed (s4-done) | 4 |
| S5 | デイリーノート + テンプレート + リンク | blocked by S4 | 5 |
| S6 | 検索 + 統計 + インポート | blocked by S4 | 6 |
| S7 | アクセス制御 + Claude連携 | blocked by S4 | 7 |
| S8 | Git連携 | blocked by S4 | 8 |
| S9 | セキュリティ硬化 + 統合テスト | blocked by S5-S8 | 9 |

## Sprint Scope

### S1: 基盤構築
- Cargoワークスペース (core/ + cli/)
- DiaryError (thiserror)
- SecureBuffer / ZeroizingKey 自前実装
- clap CLIスケルトン
- CI (cargo test, cargo clippy, cargo audit)

### S2: 暗号コア
- PQCフォーク (ml-kem/ml-dsa) セットアップ
- Argon2id鍵導出
- AES-256-GCM暗号化/復号
- ML-KEM-768鍵カプセル化
- ML-DSA-65署名・検証
- HMAC-SHA256

### S3: Vaultフォーマット + ストレージ
- vault.pqd v4バイナリ読み書き (添付ファイル予約フィールド含む)
- vault.toml / config.toml パース
- マルチVaultディレクトリ構造
- テンプレート格納領域

### S4: エントリ操作 + CLI
- Entry CRUD (new/list/show/edit/delete)
- パスワード入力3段階 (flag/env/TTY termios)
- $EDITOR一時ファイル制御
- ネストタグ (#親/子/孫)

**完了タスク** (2026-04-04):
- TASK-0036: エディタ起動 + ヘッダーコメントパース
- TASK-0037: clapアップデート + newコマンド
- TASK-0038: list / show コマンド
- TASK-0039: edit コマンド
- TASK-0040: delete コマンド + 確認プロンプト
- TASK-0041: 統合テスト + doc comments

### S5: デイリーノート + テンプレート + リンク
- today コマンド
- テンプレート (vault.pqd暗号化格納, new --template)
- [[タイトル]] リンク + バックリンク
- $EDITOR内リンク自動補完

### S6: 検索 + 統計 + インポート
- search コマンド (正規表現, インメモリ)
- stats コマンド
- import (Obsidian/MD, wiki-link/タグ自動変換)

### S7: アクセス制御 + Claude連携
- ポリシー (none/write_only/full)
- セットアップ対話フロー
- --claude フラグ + 4層チェック

### S8: Git連携
- git CLI同期 (init/push/pull/sync/status)
- プライバシー強化 (匿名author, 定型メッセージ, パディング)
- タイムスタンプファジング
- 3-wayマージ (UUID + content_hmac)

### S9: セキュリティ硬化 + 統合テスト
- mlock / VirtualLock
- PR_SET_DUMPABLE, コアダンプ無効化
- クロスプラットフォームビルド確認
- 統合テスト + パフォーマンス検証
