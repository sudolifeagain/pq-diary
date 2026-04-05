# daily-note-template-link 設計ヒアリング記録

**作成日**: 2026-04-05
**ヒアリング実施**: step4 既存情報ベースの差分ヒアリング

## ヒアリング目的

S5 の技術設計にあたり、要件定義フェーズで決まらなかったデータモデルとアーキテクチャの設計判断についてヒアリングを実施しました。

## 質問と回答

### Q1: テンプレートの内部データ構造

**質問日時**: 2026-04-05
**カテゴリ**: データモデル
**背景**: テンプレートをvault.pqd内に格納する際、暗号化ペイロードの構造として既存の EntryPlaintext (title/tags/body) を再利用するか、テンプレート専用型を定義するかの判断が必要。

**回答**: **専用型 TemplatePlaintext (name + body)** を採用

**比較検討**:
| 観点 | 専用型 | EntryPlaintext再利用 |
|------|--------|---------------------|
| フィールド | name, body のみ | title, tags, body (tagsは常に空) |
| 拡張性 | variables 等を自由に追加可能 | エントリとテンプレートの差分が増えると破綻 |
| 意味の明確性 | テンプレート専用で混同なし | title→name の暗黙変換が必要 |
| 実装コスト | Serialize/Deserialize追加 | 追加コストなし |

**信頼性への影響**:
- テンプレート関連型の信頼性が 🟡 → 🔵 に向上
- 将来の拡張（変数定義フィールド等）が安全に行える

---

### Q2: バックリンクインデックスの保持場所

**質問日時**: 2026-04-05
**カテゴリ**: アーキテクチャ
**背景**: LinkIndex をどこに保持するか。DiaryCore のフィールドとして管理するか、CLI側で独立管理するかの選択。

**回答**: **DiaryCore のフィールド** として保持

**比較検討**:
| 観点 | DiaryCore フィールド | CLI側独立管理 |
|------|---------------------|--------------|
| ライフサイクル | unlock/lockと自動連動 | CLI が手動管理 |
| zeroize保証 | lock()時に確実に消去 | 消し忘れリスクあり |
| API使い勝手 | `core.backlinks_for()` で完結 | CLI が index を渡す必要 |
| core責務 | やや増加 | 最小限維持 |
| モバイル対応 | 自動的に恩恵 | モバイル側でも管理コード必要 |

**信頼性への影響**:
- バックリンクのセキュリティ（zeroize保証）が 🟡 → 🔵 に向上
- DiaryCore API の使い勝手が向上

---

## ヒアリング結果サマリー

### 確認できた事項
- テンプレートは専用型 `TemplatePlaintext { name, body }` で定義
- バックリンクインデックスは DiaryCore フィールド（unlock/lockと連動）

### 設計方針の決定事項
- `TemplatePlaintext` は `Zeroize + ZeroizeOnDrop` を実装
- `LinkIndex` は `DiaryCore.link_index: Option<LinkIndex>` として保持
- lock時に `link_index = None` で自動zeroize

### 残課題
- なし（設計上の主要判断は完了）

### 信頼性レベル分布

**ヒアリング前**:
- 🔵 青信号: 5件
- 🟡 黄信号: 3件
- 🔴 赤信号: 0件

**ヒアリング後**:
- 🔵 青信号: 7件 (+2)
- 🟡 黄信号: 1件 (-2)
- 🔴 赤信号: 0件

## 関連文書

- **アーキテクチャ設計**: [architecture.md](architecture.md)
- **データフロー**: [dataflow.md](dataflow.md)
- **型定義**: [types.rs](types.rs)
- **要件定義**: [requirements.md](../../spec/daily-note-template-link/requirements.md)
