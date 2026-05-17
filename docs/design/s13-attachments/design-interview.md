# S13 添付ファイル 設計ヒアリング記録

**作成日**: 2026-05-18

## ヒアリング目的

backlog の「添付ファイル (バイナリ暗号化, v4 予約フィールド使用)」項目を
S13 で実装するための設計判断 (特にストレージ位置・サイズ上限・legacy 連動)
を確定する。PRD §10 では添付ファイルへの明示言及がないため、設計判断の
信頼性は妥当な推測 (🟡) が中心になる。

## 質問と回答 (要件定義段階のヒアリングを継承)

設計判断は要件定義 [interview-record.md](../../spec/s13-attachments/interview-record.md)
で 4 つの中核判断を確定。設計フェーズで追加のヒアリングは行わず、PR review で
🟡 → 🔵 の昇格を狙う方針。

### 確定事項サマリー

| # | 判断 | 設計への反映 |
|---|---|---|
| Q1 | 1GB chunk 処理 | streaming.rs 1MB chunk、AAD で改ざん検出 |
| Q2 | vault.pqd + .attachments/ 分離 | architecture.md でメタ/本体分離 |
| Q3 | ファイル個別 legacy フラグ | AttachmentRecord に legacy_flag / legacy_key_block 追加 |
| Q4 | 双方向 Obsidian 互換 | export で `![[FILE]]` 埋め込み、import で `attachments/` スキャン |

## 設計フェーズで新規に確定した事項 (ヒアリング不要)

仕様・既存パターンから機械的に決定:

### 1. CHUNK_SIZE = 1MB 🟡
- 1GB ファイル → 1024 chunks → IV 衝突確率 ≪ 2^-96
- メモリピーク ≤ 6MB (chunk + overhead)
- AES-GCM ベンチで write 100-300 MB/s 達成可能 (HW AES 前提)

### 2. RECORD_TYPE_ATTACHMENT = 0x03 🟡
- 既存 RECORD_TYPE_ENTRY=0x01, RECORD_TYPE_TEMPLATE=0x02 と並列
- 新 record type を追加するため vault.pqd schema_version は v5 に上げる
- record_type byte で reader 側を分岐し、v4 client は v5 vault を拒否する
- entry record の attachment_count は境界チェックに使い、attachment_offset は 0 固定

### 3. chunk AAD = chunk_index || total_chunks || blob_uuid (24B) 🟡
- chunk reorder 検出
- truncation 検出
- ファイル入れ替え検出

### 4. ファイル本体は K_master ではなくランダム FileKey で暗号化 🟡
- OsRng で attachment blob ごとに FileKey (32B) を生成
- AttachmentPlaintext は K_master で暗号化し、その中に FileKey を保存
- legacy_key_block には K_legacy で AttachmentLegacyPlaintext (blob_uuid + FileKey + 検証情報) を暗号化
- change-password は AttachmentPlaintext を再ラップするだけで `.bin` 本体の再暗号化不要

### 5. 添付名重複時の挙動 🟡
- SHA-256 一致 → 既存 blob_uuid + FileKey を共有し、レコードのみ追加
- SHA-256 不一致 → `InvalidArgument` で reject (rename を促す)
- delete / legacy DESTROY は参照数を確認し、最後の参照でのみ blob を zeroize 削除

### 6. メタデータ署名範囲 🟡
- ML-DSA-65 の署名対象: `AttachmentRecord.ciphertext`
- chunk ごとに署名すると ML-DSA-65 で 3309B × chunk_count → 1024 chunks で 3.4MB は過剰
- HMAC + SHA-256 + ML-DSA-65 で 3 重防御

### 7. ディレクトリ構造 🟡
- `<vault_dir>/.attachments/<blob_uuid>.bin` 一階層
- entry 別サブディレクトリ不要 (削除時は AttachmentRecord から uuid 引く)
- git add 対象

## 残課題 (PR review で確認)

| # | 項目 | 推奨案 | 代替案 |
|---|---|---|---|
| R1 | `attachment list --claude` の許可 | access=full なら許可 | 一律ブロック |
| R2 | `new --attach` の --claude 動作 | --attach 指定をエラー | 静かに無視 |
| R3 | 添付メタデータの追加フィールド | sha256/filename/MIME/size で十分 | tag, comment, exif も保存 |
| R4 | export の `![[FILE]]` 位置 | エントリ末尾 | 元の MD 内挿入位置を保持 |
| R5 | import で `attachments/` 不在の場合 | warning + 該当リンク skip | エラー停止 |

実装スプリント (S13-impl) 開始前に R1〜R5 を確定する。

## 信頼性

- 🔵: 該当なし
- 🟡: 全項目 (PRD §10 明示なし、設計判断)
- 🔴: 該当なし

## 関連

- [architecture.md](architecture.md)
- [dataflow.md](dataflow.md)
- [types.rs](types.rs)
- [schema.md](schema.md)
- [cli-commands.md](cli-commands.md)
- [要件定義 interview-record](../../spec/s13-attachments/interview-record.md)
