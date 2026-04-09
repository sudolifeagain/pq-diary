# 検索 + 統計 + インポート 設計ヒアリング記録

**作成日**: 2026-04-09
**ヒアリング実施**: step4 既存情報ベースの差分ヒアリング

## ヒアリング目的

要件定義フェーズで確定した仕様に基づき、実装アーキテクチャの方針決定が必要な2点について設計ヒアリングを実施した。

## 質問と回答

### Q1: search の復号方式

**カテゴリ**: アーキテクチャ
**背景**: search コマンドは全エントリを復号して検索する必要がある。一括復号方式とストリーミング方式の2択があり、メモリ使用量とコード複雑さにトレードオフがある。

**回答**: **ストリーミング方式** — 1エントリずつ復号→検索→zeroize

**信頼性への影響**:
- architecture.md の search コンポーネント設計が 🟡 → 🔵 に向上
- dataflow.md の search フローが確定 (🔵)
- `search_entries()` の関数シグネチャが確定

---

### Q2: import のバッチ書き込み方式

**カテゴリ**: アーキテクチャ
**背景**: import は大量のエントリを一括で vault に追加する。既存の `write_vault` を使うか、専用の `batch_create_entries` を新設するか。前者はシンプルだが全体再書き込み、後者は複雑だが効率的。

**回答**: **専用バッチ関数** `batch_create_entries()` — read_vault → records.extend → write_vault を1回のみ

**信頼性への影響**:
- architecture.md の import コンポーネントが 🟡 → 🔵 に向上
- dataflow.md の import フローが確定 (🔵)
- types.rs の `ImportResult` が確定

---

## ヒアリング結果サマリー

### 確認できた事項
- search はストリーミング復号方式（メモリ O(1エントリ)）
- import は専用バッチ関数で vault I/O O(1)

### 設計方針の決定事項
- `core/src/search.rs` の `search_entries()` はイテレータ風にレコード単位で復号
- `core/src/importer.rs` の `batch_create_entries()` は `read_vault` + `extend` + `write_vault` の3ステップ

### 残課題
- frontmatter パースに `serde_yaml` クレートを追加するか手動パースか（軽量パースで十分な可能性）
- ヒートマップの ASCII 表現の具体的デザイン

### 信頼性レベル分布

**ヒアリング前**:
- 🔵 青信号: 8件
- 🟡 黄信号: 4件

**ヒアリング後**:
- 🔵 青信号: 10件 (+2)
- 🟡 黄信号: 2件 (-2)

## 関連文書

- **アーキテクチャ設計**: [architecture.md](architecture.md)
- **データフロー**: [dataflow.md](dataflow.md)
- **型定義**: [types.rs](types.rs)
- **要件定義**: [requirements.md](../../spec/search-stats-import/requirements.md)
