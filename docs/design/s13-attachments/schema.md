# S13 添付ファイル スキーマ設計

**作成日**: 2026-05-18
**関連設計**: [architecture.md](architecture.md), [types.rs](types.rs)
**信頼性**: 🟡 (PRD §10 明示なし、設計判断)

---

## 1. vault.pqd v5 ヘッダー (S13 で schema_version 更新) 🔵

S13 ではヘッダーの物理レイアウト (204B 固定領域 + 可変 KEM/DSA SK)
は変更しない。ただし `RECORD_TYPE_ATTACHMENT = 0x03` を payload に追加するため、
`schema_version` は **v5** に更新する。v4 予約済みの
`attachment_count`/`attachment_offset` は entry record レベルで引き続き使用する。

## 2. EntryRecord (既存予約フィールドを使用開始) 🔵

```
[record_len: LE u32]
[record_type: 0x01]
[uuid: 16B]
[created_at: LE u64]
[updated_at: LE u64]
[iv: 12B]
[ciphertext_len: LE u32]
[ciphertext: variable]
[signature_len: LE u32]
[signature: variable]
[content_hmac: 32B]
[legacy_flag: u8]
[legacy_key_block_len: LE u32]
[legacy_key_block: variable]
[attachment_count: LE u16]        ← S3 予約、S13 で使用開始
[attachment_offset: LE u64]       ← S3 予約、S13 では 0 固定 (将来最適化用)
[padding_len: u8]
[padding: variable]
```

**S13 での値**:
- `attachment_count`: 紐付く AttachmentRecord の個数 (0〜256、257 個目を拒否)
- `attachment_offset`: 0 固定。紐付けは暗号化済み `AttachmentPlaintext.entry_uuid` を復号して判定する

## 3. AttachmentRecord (新タイプ 0x03) 🟡

```
[record_len: LE u32]
[record_type: 0x03]
[uuid: 16B]                       // attachment record UUID (ランダム、表示 ID)
[iv: 12B]
[ciphertext_len: LE u32]
[ciphertext: variable]            // AES-256-GCM(K_master, AttachmentPlaintext)
[signature_len: LE u32]
[signature: variable]             // ML-DSA-65 over ciphertext
[content_hmac: 32B]               // HMAC-SHA256 over ciphertext
[legacy_flag: u8]                 // 0x00 (Destroy default) / 0x01 (Inherit)
[legacy_key_block_len: LE u32]
[legacy_key_block: variable]      // INHERIT 時のみ: K_legacy で暗号化された AttachmentLegacyPlaintext
[padding_len: u8]
[padding: variable]
```

### AttachmentPlaintext (K_master で暗号化) 🔵

ユーザー可視メタデータと本体復号鍵は vault.pqd 内で平文にしない。
`AttachmentRecord.ciphertext` の平文は以下の canonical binary とする:

```
[entry_uuid: 16B]                 // 紐付くエントリ UUID
[blob_uuid: 16B]                  // .attachments/<blob_uuid>.bin
[created_at: LE u64]              // Unix seconds
[filename_len: LE u16]
[filename: utf-8]                 // 元ファイル名 (拡張子含む)
[mime_type_len: LE u16]
[mime_type: utf-8]                // 例: "image/jpeg"
[size_bytes: LE u64]              // plaintext サイズ
[chunk_count: LE u32]             // ceil(size_bytes / 1MB)
[sha256: 32B]                     // plaintext の SHA-256
[file_key: 32B]                   // 添付本体専用 FileKey (Zeroizing<[u8; 32]>)
```

### 主要フィールドの設計判断

| フィールド | 設計判断 | 信頼性 |
|---|---|---|
| `uuid` | attachment record の表示 ID。`.bin` のファイル名には使わない | 🟡 |
| `entry_uuid` | 暗号化メタデータ内に保存。復号後に線形スキャンで親エントリ検索 | 🟡 |
| `blob_uuid` | `.attachments/<blob_uuid>.bin` のファイル名。重複排除時は複数レコードで共有 | 🟡 |
| `filename` | 暗号化メタデータ内に UTF-8 で保存、実用上限 255 chars | 🟡 |
| `mime_type` | 暗号化メタデータ内に保存。mime_guess crate で detect、判定不能なら `application/octet-stream` | 🟡 |
| `size_bytes` | 暗号化メタデータ内のオリジナルサイズ (chunk オーバーヘッド除く) | 🔵 |
| `chunk_count` | 暗号化メタデータ内の `ceil(size_bytes / 1MB)`、復号時の検証用 | 🟡 |
| `sha256` | 暗号化メタデータ内の plaintext 全体 SHA-256、改ざん検出と重複排除 | 🟡 |
| `file_key` | OsRng 生成の添付本体専用 32B 鍵。K_master 変更後も本体再暗号化不要 | 🔵 |
| `content_hmac` | ciphertext の整合性、change-password で再計算 | 🔵 |
| `signature` | ML-DSA-65 で ciphertext を署名、entry record と同じ検証モデル | 🔵 |
| `legacy_flag` | S12 と同じ semantics (0x00=Destroy, 0x01=Inherit) | 🟡 |
| `legacy_key_block` | S12 と同じ形式: `[12B IV][AES-GCM ciphertext]`、INHERIT 時のみ | 🟡 |
| `padding` | 0-255B、size analysis 緩和 | 🔵 |

### legacy_key_block の中身 (INHERIT 時) 🟡

`legacy_key_block` には、K_master なしで INHERIT 添付を取り出すために必要な
最小情報を K_legacy で暗号化して保存する:

```
AttachmentLegacyPlaintext:
  [blob_uuid: 16B]
  [file_key: 32B]
  [filename_len + filename]
  [size_bytes: LE u64]
  [chunk_count: LE u32]
  [sha256: 32B]
```

これにより heir は `K_master` を取得することなく、INHERIT 添付の本体のみ
復号できる。FileKey はランダム生成であり `K_master` から導出しないため、
`change-password` では `.bin` 本体を再暗号化せず、AttachmentRecord の
暗号化メタデータと HMAC/signature だけを新 K_master で再ラップする。

## 4. .attachments/<blob_uuid>.bin フォーマット 🟡

```
chunk 0:
  [chunk_iv_0: 12B][chunk_ct_0: 1048576B + 16B GCM tag]
chunk 1:
  [chunk_iv_1: 12B][chunk_ct_1: 1048576B + 16B GCM tag]
...
chunk N-1 (最後):
  [chunk_iv_N-1: 12B][chunk_ct_N-1: (size_bytes mod 1MB)B + 16B GCM tag]
```

### chunk ごとの AAD (Additional Authenticated Data) 🟡

```
AAD = [chunk_index: LE u32][total_chunks: LE u32][blob_uuid: 16B]
    = 24 bytes
```

**目的**:
- chunk 順序の改ざん検出 (chunk_index が違うと tag mismatch)
- 全 chunk 数の改ざん検出 (truncation 検出)
- ファイル間入れ替え検出 (blob_uuid)

### ファイルサイズ計算 🟡

`.attachments/<blob_uuid>.bin` のサイズ:
```
total = chunk_count × (12 + 1MB + 16) bytes - (1MB - last_chunk_size)
      = size_bytes + chunk_count × 28
```

1GB ファイル → 1024 chunks → overhead 28KB (0.003%)

## 5. ディレクトリ構造 🟡

```
<vault_dir>/                          (e.g., ~/.pq-diary/vaults/default/)
├── vault.pqd                         (entries + templates + attachment records)
├── vault.toml                        (config; S12 legacy section も)
├── .attachments/                     ← S13 新規ディレクトリ
│   ├── 3c6b775f-1234-5678-9abc-def012345678.bin
│   ├── 08a9e139-aaaa-bbbb-cccc-dddddddddddd.bin
│   └── ...
└── .git/                             (git 同期時のみ)
```

`.attachments/` は git add 対象 (暗号化済みなので問題なし)。
ファイル名は `blob_uuid` 直接 (元ファイル名は暗号化メタデータに記録)。

### 重複排除と削除 🟡

SHA-256 が同じ添付を追加する場合は、新しい AttachmentRecord を作成し、
既存の `blob_uuid` と `file_key` を暗号化メタデータ内で参照する。
`.attachments/<blob_uuid>.bin` は共有するため、delete / legacy DESTROY は
vault 内の全 AttachmentRecord を復号して参照数を確認し、最後の参照を削除する時だけ
zeroize 上書きして本体を削除する。

## 6. 後方互換性 🔵

### Phase 1 vault → S13 クライアント

- 既存 vault では全 entry が `attachment_count = 0`、`attachment_offset = 0`
- S13 reader は `attachment_count == 0` ならスキップ、空の attachment 一覧を返す
- 既存テスト全パス

### S13 vault → Phase 1 クライアント (S12 以前)

- S13 vault は `schema_version = 5` として書き込む
- S12 以前の reader は schema_version > 4 を unsupported として拒否する
- v4 vault は S13 初回書き込み時に v5 へ migration する

## 7. メタデータ署名 🟡

`signature` の対象メッセージ:
```
AttachmentRecord.ciphertext
```

これにより、暗号化済みメタデータ全体を entry record と同じ方式で検証する:
- ciphertext 改ざん → HMAC / signature mismatch
- ファイル名・size_bytes・sha256・file_key の改ざん → ciphertext 改ざんとして検出
- `.bin` 本体を別物に → AEAD tag または SHA-256 検証で不一致

3 重防御 (HMAC + Signature + SHA-256) で改ざん耐性を強化。

## 8. CLI 表示時のサイズフォーマット 🟡

| size_bytes | 表示 |
|---|---|
| 0 - 1023 | `42 B` |
| 1024 - 1,048,575 | `1.5 KB` (一桁) |
| 1,048,576 - 1,073,741,823 | `2.4 MB` (一桁) |
| 1,073,741,824+ | `1.2 GB` (一桁) |

## 関連

- [architecture.md](architecture.md)
- [types.rs](types.rs)
- [dataflow.md](dataflow.md)
- [cli-commands.md](cli-commands.md)
