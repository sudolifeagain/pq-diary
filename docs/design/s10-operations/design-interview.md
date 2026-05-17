# S10 運用機能 + CLI整合性 設計ヒアリング記録

**作成日**: 2026-05-17
**ヒアリング実施**: kairo-design step4 既存情報ベースの差分ヒアリング

## ヒアリング目的

要件定義 (信頼性🔵 100%) を踏まえ、設計フェーズで追加の技術判断 (依存追加・出力フォーマット) を確定するためのヒアリングを実施した。

## 質問と回答

### Q1: AppConfig のホームディレクトリ解決方法

**質問日時**: 2026-05-17
**カテゴリ**: 技術選択 (依存追加)
**背景**: `~/.pq-diary/config.toml` を読み書きするためにホームディレクトリパスが必要。既存コードでは `dirs` クレートは未使用。`std::env::var("HOME")` を直接使うか、`dirs` クレートを追加するか判断が必要。

**回答**: 「dirs クレート追加 (Recommended)」を選択。`dirs::home_dir()` で Unix の $HOME と Windows の %USERPROFILE% の差をクレートに任せる。

**信頼性への影響**:
- AppConfig::default_path() の実装方針確定 (信頼性: 🔵)
- 新規依存 `dirs = "5"` を `cli/Cargo.toml` に追加することが確定

---

### Q2: export の YAML フロントマター生成

**質問日時**: 2026-05-17
**カテゴリ**: 技術選択 (依存追加)
**背景**: export の MD ファイル先頭に YAML フロントマター (id, title, tags, created, updated) を含める。`serde_yaml` クレートを追加するか、手書きするか判断が必要。フィールドは固定。

**回答**: 「手書き (Recommended)」を選択。フィールドが固定 (5 個)、エスケープ規則も限定的 (`"` と `\` のみ) なので 30 行以下で実装可能。依存追加せず。

**信頼性への影響**:
- ExportEntry::to_markdown() の実装方針確定 (信頼性: 🔵)
- 依存追加なし、cargo audit の診断面を増やさない

---

### Q3: info 出力の --json モード追加

**質問日時**: 2026-05-17
**カテゴリ**: スコープ調整
**背景**: `info` 出力を人間可読のみにするか、スクリプト連携用に `--json` モードを追加するか。

**回答**: 「人間可読のみ (Recommended)」を選択。`pq-diary stats` と同じスタイル (左寄せラベル + 値) で統一。JSON 出力は Phase 2 の Bases ライクビュー (list 拡張) とあわせて検討。

**信頼性への影響**:
- cmd_info() の出力仕様確定 (信頼性: 🔵)
- スコープが小さく保たれ、S10 内で確実に完了可能

---

## ヒアリング結果サマリー

### 確認できた事項

1. AppConfig パス解決は `dirs` クレートを採用 → cli/Cargo.toml に依存追加
2. export YAML フロントマターは手書き → 依存追加なし
3. info 出力は人間可読のみ → JSON モードは Phase 2 で再検討
4. CLI 整合性チェックは `ci/smoke-test.sh` + `ci/smoke-test.ps1` の 2 種類で実装 (依存ヒアリングなし、設計判断)

### 設計方針の決定事項

| 項目 | 決定 |
|---|---|
| AppConfig パス | `dirs::home_dir().join(".pq-diary").join("config.toml")` |
| AppConfig パーミッション (Unix) | `0o600` (vault.toml と同等) |
| export YAML エスケープ | 手書き (ダブルクォート + `"`/`\` のみエスケープ) |
| export 日時形式 | RFC 3339 (UTC, `Z` サフィックス) |
| export タグ空時 | `tags: []` (インライン) |
| info 出力スタイル | `=== Vault Info ===` ヘッダー + `Label:    value` 左寄せ (stats と統一) |
| change-password メモリ管理 | ChangePasswordContext 構造体に集約、Drop で全フィールド zeroize |
| vault.pqd 更新範囲 (change-password) | kdf_salt 再生成 + verification + KEM/DSA seed 暗号化 + 全エントリ。KEM/DSA seed 自体は不変 |
| smoke test スクリプト | bash 版 (Unix) と PowerShell 版 (Windows) の 2 種類 |

### 残課題

- なし。設計は実装に進める品質。実装フェーズ (kairo-implement) で `todo!()` を埋める作業のみ。

### 信頼性レベル分布

**ヒアリング前 (要件定義完了時点)**:
- 🔵 青信号: 100% (requirements + user-stories + acceptance-criteria)

**ヒアリング Q1〜Q3 後 (設計完了時点)**:
- 🔵 青信号: architecture (100%) + dataflow (100%) + types (100%) + schema (100%) + cli-commands (100%)
- 🟡 黄信号: 0 件
- 🔴 赤信号: 0 件

**全体**: 🔵 100% で維持。

## 関連文書

- **アーキテクチャ設計**: [architecture.md](architecture.md)
- **データフロー**: [dataflow.md](dataflow.md)
- **型定義**: [types.rs](types.rs)
- **スキーマ**: [schema.md](schema.md)
- **CLI 仕様**: [cli-commands.md](cli-commands.md)
- **要件定義**: [requirements.md](../../spec/s10-operations/requirements.md)
- **要件ヒアリング**: [interview-record.md](../../spec/s10-operations/interview-record.md)
