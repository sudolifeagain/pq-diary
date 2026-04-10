# S8 Git Sync ヒアリング記録

**作成日**: 2026-04-10
**ヒアリング実施**: step4 既存情報ベースの差分ヒアリング

## ヒアリング目的

PRD v4.0（section 11）、ADR-0006、既存実装（git.rs stub, GitSection/GitPrivacySection in config.rs, DiaryError::Git）を精査し、S8実装のスコープ・設計判断の不明点を明確化するためのヒアリングを実施しました。

## 質問と回答

### Q1: S8のスコープ

**質問日時**: 2026-04-10
**カテゴリ**: 影響範囲
**背景**: PRDのsection 11ではgit-init/push/pull/sync/statusの5コマンドとプライバシー強化3点セット+タイムスタンプファジング+3-wayマージ+コンフリクト解決が定義されている。S8で全て実装するか、段階的に分割するかを確認する必要があった。

**回答**: S8でフルスコープ実装（git-init / git-push / git-pull / git-sync / git-status + プライバシー3点セット + タイムスタンプファジング + 3-wayマージ + コンフリクト解決）

**信頼性への影響**:
- 全REQ（001〜054）のスコープが確定（🔵）
- S8が大規模スプリントとなることが確認された

---

### Q2: author_email生成タイミング

**質問日時**: 2026-04-10
**カテゴリ**: 未定義部分詳細化
**背景**: PRD 11.3ではauthor_emailをVault初期化時に生成と記述。しかし既存のVaultConfig::default()ではauthor_emailは空文字列。vault create時に生成するか、git-init時に生成するかで実装箇所が変わる。

**回答**: git-init時に生成（vault create時ではない）。8桁ランダムhex + `@localhost` 形式。

**信頼性への影響**:
- REQ-003 が確定（🔵）
- vault create時にはauthor_emailを空のままにしておき、git-init時に初めて設定する設計が確定
- author_nameも同様にgit-init時に `"pq-diary"` に設定

---

### Q3: sync順序・コンフリクト・パスワード要否

**質問日時**: 2026-04-10
**カテゴリ**: 未定義部分詳細化
**背景**: PRDにはsyncの順序（pull先かpush先か）、コンフリクト解決の--claude時の動作、各コマンドのパスワード要否が明確に定義されていなかった。

**回答**:
- sync = pull → push の順序
- --claude コンフリクト: ローカル側が自動的に勝つ
- git-pull: パスワード必要（vault.pqd復号によるUUID/HMACマージのため）
- git-push: パスワード必要（vault.pqdに追加パディングを付与して再書き込みするため）
- git-init / git-status: パスワード不要

**信頼性への影響**:
- REQ-016, REQ-022, REQ-026, REQ-030, REQ-031 が確定（🔵）
- パスワード要否の全コマンド分類が明確化

---

### Q4: 仕様確認 + OQ-19

**質問日時**: 2026-04-10
**カテゴリ**: 既存設計確認
**背景**: 残りの設計判断事項を一括で確認。特にOQ-19（エントリ同一性判定方式）がマージ戦略に直接影響するため、方針を確定する必要があった。

**回答**:
1. エントリ同一性判定: UUID + content_hmac（タイムスタンプではない）。OQ-19に準拠
2. .gitignore: `entries/*.md` を除外
3. git-init済みVaultへの再git-init: エラー
4. リモート空の場合のマージ: no-op
5. ローカル空の場合のマージ: リモート全エントリ受け入れ
6. extra_padding_bytes_max=0: パディング無効化
7. timestamp_fuzz_hours=0: ファジング無効化

**信頼性への影響**:
- REQ-021, REQ-023, REQ-024, REQ-054, EDGE-004, EDGE-005, EDGE-006 が確定（🔵）
- OQ-19の方針がS8実装に組み込まれることが確定

---

## ヒアリング結果サマリー

### 確認できた事項
- S8スコープ: 5コマンド + プライバシー3点セット + タイムスタンプファジング + 3-wayマージ + コンフリクト解決
- author_email: git-init時に8桁ランダムhex生成
- sync順序: pull → push
- --claude コンフリクト: ローカル優先自動解決
- PW要否: git-pull/push/sync = 必要、git-init/status = 不要
- エントリ同一性: UUID + content_hmac（OQ-19準拠）
- .gitignore: entries/*.md 除外
- 各種Edgeケース: git-init重複 → エラー、リモート空 → no-op、ローカル空 → 全受入

### 追加/変更要件
- **詳細化**: author_email生成タイミングがgit-init時に確定
- **詳細化**: sync = pull → push の順序が確定
- **詳細化**: --claudeコンフリクトのローカル優先が確定
- **詳細化**: 各コマンドのPW要否が確定

### 残課題
- なし（全項目確認済み）

### 信頼性レベル分布

**ヒアリング前**:
- 🔵 青信号: 15件
- 🟡 黄信号: 12件
- 🔴 赤信号: 0件

**ヒアリング後（最終）**:
- 🔵 青信号: 全件 (+12)
- 🟡 黄信号: 0件 (-12)
- 🔴 赤信号: 0件 (0)

## 関連文書

- **要件定義書**: [requirements.md](requirements.md)
- **ユーザストーリー**: [user-stories.md](user-stories.md)
- **受け入れ基準**: [acceptance-criteria.md](acceptance-criteria.md)
