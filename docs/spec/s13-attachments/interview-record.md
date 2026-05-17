# S13 添付ファイル ヒアリング記録

**作成日**: 2026-05-18
**ヒアリング実施**: kairo-requirements step4

## ヒアリング目的

vault.pqd v4 で予約済みの attachment フィールドを使うにあたり、
ストレージ位置・サイズ上限・legacy 連動・export/import の 4 つの
最重要設計判断を確定する。

## 質問と回答

### Q1: 1 ファイルあたりのサイズ上限

**質問日時**: 2026-05-18
**カテゴリ**: 未定義部分詳細化 (パフォーマンス・スコープ)
**背景**: ファイルサイズ上限はメモリ使用量・暗号化方式 (chunk 単位 vs 一括) を決定する。

**選択肢**:
- 10MB (推奨, メモリ上で一括処理)
- 100MB (PDFや動画以外をカバー)
- **1GB (chunk 処理, 動画もサポート)** ← 選択
- 制限なし

**回答**: **1GB (chunk 処理)**

**信頼性への影響**:
- REQ-104 (1GB 上限) が 🔵 に確定
- REQ-105 (chunk 暗号化), NFR-002 (メモリ上限) が 🟡 に向上 (chunk 処理が必須化)
- ML-DSA 署名は chunk ごとではなく全体 SHA-256 に対して 1 つ (実装容易性)

---

### Q2: 添付ファイルのストレージ位置

**質問日時**: 2026-05-18
**カテゴリ**: アーキテクチャ確定
**背景**: vault.pqd 内に同梱するか、別ファイルにするか。git 同期・I/O パターンに影響。

**選択肢**:
- vault.pqd 内部 (エントリ同梱) — 1 ファイル完結、read 一括負荷
- **vault.pqd + 別ファイル (.attachments/)** ← 選択 — メタデータは vault.pqd、本体は個別

**回答**: **vault.pqd + 別ファイル (.attachments/)**

**信頼性への影響**:
- REQ-102 (`.attachments/<blob_uuid>.bin`) が 🔵 確定
- REQ-902 (vault.pqd には attachment レコードのみ) が 🟡 に向上
- git 同期戦略: `.attachments/` 配下も git add 対象、暗号化済みなので問題なし
- read_vault が肥大化しない (Phase 1 と同等)

**設計判断**: ファイル命名は `.attachments/<blob_uuid>.bin` 一階層 (UUID 衝突確率
～ 0)。エントリ別ディレクトリは不要、削除時の検索は attachment レコードから引く。

---

### Q3: legacy-access (S12) との連部

**質問日時**: 2026-05-18
**カテゴリ**: S12 拡張・データ整合性
**背景**: エントリ INHERIT/DESTROY と添付の継承単位を揃えるか、別個か。

**選択肢**:
- エントリの INHERIT/DESTROY に連動 — 単純、UI 1 操作
- **ファイル個別にフラグ設定可能** ← 選択 — `attachment set --inherit/--destroy`
- S13 では保留 (Phase 3) — スコープ縮小

**回答**: **ファイル個別にフラグ設定可能**

**信頼性への影響**:
- REQ-501〜503 (ファイル個別フラグ) が 🟡 に向上
- 設計: attachment レコードに `legacy_flag` + `legacy_key_block` を持たせる (S12 entry と同じ構造)
- UX 詳細: `pq-diary attachment set <ENTRY_ID> <FILE_NAME> --inherit | --destroy`
  またはまとめて `--all-inherit`
- データ整合性ルール: エントリが DESTROY なら添付は自動 DESTROY (REQ-504)。
  逆 (エントリ INHERIT で添付 DESTROY) は許容。

---

### Q4: export / import でのファイル扱い

**質問日時**: 2026-05-18
**カテゴリ**: I/F 仕様・互換性
**背景**: Obsidian との往復、export の表現形式。

**選択肢**:
- **export: 別ディレクトリ、import: Obsidian 互換** ← 選択
- export のみ対応 (import は Phase 3)
- export/import 両方対応

**回答**: **export: 別ディレクトリ、import: Obsidian 互換** (双方向 Obsidian 互換)

**信頼性への影響**:
- REQ-601〜603 (双方向) が 🔵 確定
- export 形式: `<DIR>/<date>-<slug>-<id>.md` + `<DIR>/attachments/<file_name>`
- MD 内リンク: `![[file_name]]` (Obsidian 標準)
- import: `attachments/` フォルダをスキャン、MD 内 `![[...]]` をパースして紐付け
- 重複排除: SHA-256 一致で既存 blob_uuid + FileKey を共有し、本体書き込みスキップ (REQ-604)

---

## 設計フェーズで新規に確定した事項 (ヒアリング不要)

以下は確定 4 判断と既存実装パターンから機械的に決定:

### 1. レコードタイプ拡張 🟡
- `RECORD_TYPE_ATTACHMENT = 0x03` を新設 (既存 ENTRY=0x01, TEMPLATE=0x02 に並列)
- 新 record type を追加するため vault.pqd schema_version は v5 に更新
- attachment レコードは entry record と同じ length-prefixed フォーマット
- `EntryRecord.attachment_count` は境界チェックに使い、`attachment_offset` は 0 固定

### 2. chunk size 🟡
- **1MB** (1 048 576 bytes)
- 根拠: 1GB ファイルで 1024 chunks → IV 衝突確率 ≪ 2^-96、メモリピーク制御容易、
  Argon2/AES-GCM ベンチでバランス良好

### 3. chunk IV 設計 🟡
- 各 chunk に OsRng で fresh IV (12B)
- AAD = `chunk_index (LE u32) || total_chunks (LE u32) || blob_uuid (16B)`
- chunk plaintext の最後に GCM tag (16B) を追加
- bin 構造: `[chunk_iv | chunk_ct | tag][chunk_iv | chunk_ct | tag]...`

### 4. 添付メタデータレコード形式 🟡
```
[record_type: 0x03]
[uuid: 16B]              // attachment record UUID
[iv: 12B]
[ciphertext_len: u32]
[ciphertext: variable]   // AES-256-GCM(K_master, AttachmentPlaintext)
[signature_len: u32]
[signature: variable]    // ML-DSA-65 over ciphertext
[content_hmac: 32B]      // HMAC over ciphertext
[legacy_flag: u8]        // S12 統合
[legacy_key_block_len: u32]
[legacy_key_block: variable] // K_legacy encrypted AttachmentLegacyPlaintext
[padding_len: u8]
[padding: variable]
```

`AttachmentPlaintext` には `entry_uuid`, `blob_uuid`, `created_at`, `filename`,
`mime_type`, `size_bytes`, `chunk_count`, `sha256`, `file_key` を格納する。

### 5. アトミック書き込み 🟡
- 添付追加: `.attachments/<blob_uuid>.bin.tmp` → rename → vault.pqd 更新
- vault.pqd 更新失敗時: rename 済み `.bin` を zeroize 上書き → 削除
- クラッシュで残った orphan blob は verification/repair command で検出して zeroize 削除

### 6. CLI 構造 🟡
- `pq-diary attachment add <ENTRY_ID> <FILE>`
- `pq-diary attachment list [<ENTRY_ID>]` (引数なしで全 vault 横断)
- `pq-diary attachment extract <ENTRY_ID> <FILE_NAME> --out <PATH>`
- `pq-diary attachment delete <ENTRY_ID> <FILE_NAME> [--force]`
- `pq-diary attachment set <ENTRY_ID> <FILE_NAME> --inherit | --destroy`
- `pq-diary new --attach <FILE>` (繰り返し可)

### 7. --claude policy 🟡
- attachment add / extract / delete / set は --claude 一律ブロック
- attachment list は read-only として access policy `full` なら許可、それ以外ブロック

---

## ヒアリング結果サマリー

### 確認できた事項
- ファイルサイズ上限 1GB + chunk 処理
- vault.pqd + .attachments/ 別ファイル方式
- ファイル個別 legacy フラグ
- 双方向 Obsidian 互換 export/import

### 追加要件 (確定済み判断に基づく)
- REQ-105 (chunk 暗号化必須化)
- REQ-501〜504 (個別 legacy フラグ + エントリ連動)
- REQ-603〜604 (import + 重複排除)

### 残課題 (PR review で確認すべき)
- chunk size 1MB の妥当性 (フィードバック歓迎)
- RECORD_TYPE_ATTACHMENT=0x03 (新タイプ vs entry 拡張)
- メタデータの保存粒度 (暗号化 AttachmentPlaintext の filename / MIME / sha256 で足りるか、tag や comment も必要か)
- 添付名重複時の挙動 (SHA-256 一致は blob 共有、不一致は reject)
- `--claude attachment list` の許可ポリシー

### 信頼性レベル分布

| | 質問前 | 質問後 |
|---|---|---|
| 🔵 青信号 | 0 件 | 8 件 |
| 🟡 黄信号 | 12 件 | 39 件 |
| 🔴 赤信号 | 6 件 | 0 件 |

赤信号 6 件 (ファイルサイズ上限・ストレージ位置・legacy 連動・export 形式・
import 対応有無・chunk 処理) が全て黄〜青に向上。

## 関連

- [requirements.md](requirements.md)
- [user-stories.md](user-stories.md)
- [acceptance-criteria.md](acceptance-criteria.md)
- [../../design/s13-attachments/architecture.md](../../design/s13-attachments/architecture.md)
