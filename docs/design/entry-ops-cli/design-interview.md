# entry-ops-cli 設計ヒアリング記録

**作成日**: 2026-04-03
**ヒアリング実施**: step4 既存情報ベースの差分ヒアリング

## ヒアリング目的

S1-S3 の既存設計・実装と S4 要件定義書を確認し、技術設計上の不明点を明確化するためのヒアリングを実施しました。

## 質問と回答

### Q1: エントリ平文ペイロードのシリアライズ方式

**カテゴリ**: データモデル
**背景**: `EntryPlaintext { title, tags, body }` を AES-256-GCM で暗号化する前にバイト列に変換する必要がある。serde_json / カスタムバイナリ / serde_cbor の 3 案を提示。OQ-7 (`--debug` JSON 出力) との親和性、デバッグ容易性、依存追加のトレードオフ。

**回答**: **serde_json** を採用。

**信頼性への影響**:
- EntryPlaintext のシリアライズ方式が確定 → architecture.md / types.rs の全型定義が 🔵 に
- core/Cargo.toml に `serde_json = "1"` 依存追加が確定

---

### Q2: 既存実装の詳細分析

**カテゴリ**: 技術制約
**背景**: S4 設計が既存の CryptoEngine / vault::reader / vault::writer の API と整合するか確認が必要。

**回答**: **必要** → Explore エージェントで分析実施。

**分析結果**:
- `CryptoEngine::encrypt()` は `(Vec<u8>, [u8; 12])` を返す → EntryRecord の ciphertext / iv に直接マッピング可能
- `CryptoEngine::decrypt()` は `SecureBuffer` を返す → serde_json::from_slice で EntryPlaintext にデシリアライズ
- `CryptoEngine::dsa_sign()` / `hmac()` は既存シグネチャで S4 要件を満たす
- `VaultManager` は init_vault / list_vaults / vault_path / default_vault を提供 → S4 ではこれらを利用してコマンド実行前の Vault 解決を行う
- clap の Commands enum は New / List / Show / Edit / Delete を既にスタブ定義済み → フィールド追加で対応

---

## ヒアリング結果サマリー

### 確認できた事項
- serde_json によるシリアライズ方式
- 既存 CryptoEngine API との完全な整合性
- 既存 vault::reader / writer の read-modify-write パターンが S4 でもそのまま使える
- clap 定義の拡張方針

### 設計方針の決定事項
- `EntryPlaintext` は `serde_json::to_vec()` でシリアライズ
- `core/src/entry.rs` に CRUD ロジックを集約
- `cli/src/password.rs` と `cli/src/editor.rs` をプラットフォーム依存モジュールとして新設
- `cli/src/commands.rs` にコマンドハンドラを配置

### 残課題
- なし (全設計項目が確定)

### 信頼性レベル分布

**ヒアリング前**:
- 🔵 青信号: 大半 (要件定義フェーズで確定済み)
- 🟡 黄信号: 1件 (シリアライズ方式)
- 🔴 赤信号: 0件

**ヒアリング後**:
- 🔵 青信号: 全項目 (+1)
- 🟡 黄信号: 0件 (-1)
- 🔴 赤信号: 0件

## 関連文書

- **アーキテクチャ設計**: [architecture.md](architecture.md)
- **データフロー**: [dataflow.md](dataflow.md)
- **型定義**: [types.rs](types.rs)
- **要件定義**: [requirements.md](../../spec/entry-ops-cli/requirements.md)
