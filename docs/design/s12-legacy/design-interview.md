# S12 デジタル遺言 設計ヒアリング記録

**作成日**: 2026-05-17

## ヒアリング目的

PRD §7 を実装するための設計判断 (特に OQ-18) と UX 仕様を確定。

## 質問と回答 (要件定義段階のヒアリングを継承)

設計判断は要件定義 [interview-record.md](../../spec/s12-legacy/interview-record.md) で確定済み。
設計フェーズで追加のヒアリングは行わなかった。

### 確定事項サマリー

| # | 判断 | 設計への反映 |
|---|---|---|
| Q1 | legacy-access 後 K_legacy 残留 | schema.md §4 で新 vault.pqd 構造を K_legacy 暗号化に確定 |
| Q2 | legacy rotate 全 INHERIT 即時再暗号化 | architecture.md cmd_legacy_rotate 設計 |
| Q3 | 死後アクセスコード強度 = K_master 同等 | types.rs Argon2LegacyDeriver で kdf_params 共用 |
| Q4 | 確認方式選択可能化 | schema.md vault.toml `[legacy]` 追加、types.rs ConfirmationMode enum |
| Q5 | デフォルト timer30 | schema.md `default_confirmation()` 関数 |
| Q6 | --claude 全ブロック | dataflow.md フロー先頭で check_claude_policy |
| Q7 | Shamir 拡張余地 | types.rs `trait LegacyKeyDeriver` 抽象化 |

## 設計フェーズで新規に確定した事項 (ヒアリング不要)

以下は仕様・既存パターンから機械的に決定:

- **legacy ブロック構造**: 12B IV + EntryPlaintext JSON ciphertext + 16B AEAD tag (可変長)。現行 v4 は per-entry DEK を持たないため、予約済み `legacy_key_block` に K_legacy 暗号化済み payload copy を格納する
- **vault.toml の serde 互換性**: `#[serde(default)]` で既存 Phase 1 vault と後方互換 (EDGE-201/202)
- **エラー型**: 既存 `DiaryError` バリアントで十分 (新規追加なし)
- **smoke test 拡張**: ヘルプ + legacy init E2E のみ追加 (legacy-access は不可逆のため smoke 対象外)

## 残課題

なし。実装スプリント (kairo-tasks → kairo-implement) で詳細 (関数シグネチャ最終化、テストケース細部) を確定。

## 信頼性

🔵 100%

## 関連

- [architecture.md](architecture.md)
- [dataflow.md](dataflow.md)
- [types.rs](types.rs)
- [schema.md](schema.md)
- [cli-commands.md](cli-commands.md)
- [要件定義 interview-record](../../spec/s12-legacy/interview-record.md)
