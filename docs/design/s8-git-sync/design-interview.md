# S8 Git Sync 設計ヒアリング記録

**作成日**: 2026-04-10
**ヒアリング実施**: step4 既存情報ベースの差分ヒアリング

## ヒアリング目的

要件定義書（全項目🔵）とADR-0006の設計方針を基に、S8の技術設計に必要な実装判断を確定するためのヒアリングを実施しました。

## 質問と回答

### Q1: Extra Padding の適用方式

**質問日時**: 2026-04-10
**カテゴリ**: アーキテクチャ
**背景**: ADR-0006では「コミット毎パディング: vault.pqd末尾に0-4096Bランダム追記」と記載されている。実装方式としてバイナリファイル末尾への直接追記（seek → write）と、write_vault() を新しいパディングで再実行する方式の二択がある。バイナリ追記はシンプルだが vault フォーマットの整合性が崩れるリスクがあり、write_vault() 再実行はフォーマット整合性が保証されるがパスワード（CryptoEngine）が必要になる。

**回答**: write_vault() を新しいパディングで再実行する方式を採用

**信頼性への影響**:
- Extra Padding の実装方式が確定（🔵）
- git-push がパスワード入力を必要とする理由が明確化（REQ-016との整合性確認）
- vault.pqd のフォーマット整合性が常に保証される設計が決定
- 既存の read_vault() → write_vault() パターンを再利用できることが確認

---

### Q2: マージのベース戦略（コンフリクト解決方式）

**質問日時**: 2026-04-10
**カテゴリ**: アーキテクチャ
**背景**: エントリ単位マージでUUID一致 + content_hmac不一致の場合（両側変更コンフリクト）の解決方式として、(a) last-write-wins（updated_at比較で新しい方を採用）、(b) 全件ユーザー確認、(c) ハイブリッド（推奨表示 + 確認）の選択肢がある。OQ-1「コンフリクト解決」が未解決課題として残っていた。また `--claude` フラグ使用時の自動解決ルールも確定が必要。

**回答**: last-write-wins（updated_at比較）をデフォルトとし、対話式CLIプロンプトオプションを提供。`--claude` 時はローカル側を自動優先。

**信頼性への影響**:
- マージ戦略が確定（🔵）。OQ-1が解決
- 対話式プロンプトでは updated_at の新しい方を推奨として表示し、ユーザーが最終判断
- `--claude` 時はローカル優先の自動解決で、人間の介入なしにスクリプト実行可能
- MergeConflict 構造体に local/remote の EntryRecord を含める設計が決定

---

## ヒアリング結果サマリー

### 確認できた事項
- Extra Padding: write_vault() 再実行方式（バイナリ末尾追記ではない）
- マージ戦略: last-write-wins by updated_at + 対話式プロンプト
- --claude コンフリクト: ローカル優先で自動解決
- エントリ同一性: UUID照合 + content_hmac変更検出

### 設計方針の決定事項
- git_push() は CryptoEngine を受け取る（パディング再書き込みのため）
- git_pull_merge() は未解決コンフリクトを Vec<MergeConflict> として返し、CLIが解決方針を適用
- author_email は git-init 時に8桁hex + @localhost 形式で生成し vault.toml に永続保存
- タイムスタンプファジングは前回コミット時刻からの単調増加を保証（git log -1 で取得）
- コアロジックは core/src/git.rs、CLIハンドラは cli/src/commands.rs に配置

### 残課題
- なし（全項目確認済み。OQ-1もQ2で解決）

### 信頼性レベル分布

**ヒアリング前**:
- 🔵 青信号: 全件（要件定義フェーズで確認済み。OQ-1のみ未解決）

**ヒアリング後**:
- 🔵 青信号: 全件（OQ-1解決。設計判断も全件確定）

## 関連文書

- **アーキテクチャ設計**: [architecture.md](architecture.md)
- **データフロー**: [dataflow.md](dataflow.md)
- **型定義**: [types.rs](types.rs)
- **要件定義**: [requirements.md](../../spec/s8-git-sync/requirements.md)
- **ADR-0006**: [0006-git-sync-strategy.md](../../adr/0006-git-sync-strategy.md)
