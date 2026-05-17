# S13 添付ファイル スキーマ設計

**作成日**: 2026-05-18
**関連設計**: [architecture.md](architecture.md), [types.rs](types.rs)
**信頼性**: 🟡 (PRD §10 明示なし、設計判断)

---

## 1. vault.pqd v4 ヘッダー (S13 で変更なし) 🔵

S13 ではヘッダーレベルの変更なし。既存の 204B 固定領域 + 可変 KEM/DSA SK
で十分。`attachment_count`/`attachment_offset` は entry record レベルで
保持済み。

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
[attachment_offset: LE u64]       ← S3 予約、S13 で使用開始 (将来最適化用、Phase 1 は 0 でも可)
[padding_len: u8]
[padding: variable]
```

**S13 での値**:
- `attachment_count`: 紐付く AttachmentRecord の個数 (0〜256)
- `attachment_offset`: 0 (Phase 1)、将来は最初の AttachmentRecord の vault.pqd 内オフセット

## 3. AttachmentRecord (新タイプ 0x03) 🟡

```
[record_len: LE u32]
[record_type: 0x03]
[uuid: 16B]                       // attachment UUID
[entry_uuid: 16B]                 // 紐付くエントリ UUID
[created_at: LE u64]              // Unix seconds
[filename_len: LE u16]
[filename: utf-8]                 // 元ファイル名 (拡張子含む)
[mime_type_len: LE u16]
[mime_type: utf-8]                // 例: "image/jpeg"
[size_bytes: LE u64]              // plaintext サイズ
[chunk_count: LE u32]             // ceil(size_bytes / 1MB)
[sha256: 32B]                     // plaintext の SHA-256
[content_hmac: 32B]               // HMAC-SHA256 over [record_type..chunk_count..sha256..]
[signature_len: LE u32]
[signature: variable]             // ML-DSA-65 over (sha256 || filename_utf8 || size_bytes_le)
[legacy_flag: u8]                 // 0x00 (Destroy default) / 0x01 (Inherit)
[legacy_key_block_len: LE u32]
[legacy_key_block: variable]      // INHERIT 時のみ: K_legacy で暗号化された FileKey
[padding_len: u8]
[padding: variable]
```

### 主要フィールドの設計判断

| フィールド | 設計判断 | 信頼性 |
|---|---|---|
| `uuid` | uuid v4、`.attachments/<uuid>.bin` のファイル名としても使用 | 🟡 |
| `entry_uuid` | 削除時のオフセット計算不要、線形スキャンで親エントリ検索 | 🟡 |
| `filename` | UTF-8、長さ上限は record_len の制限内 (実用 256 chars) | 🟡 |
| `mime_type` | mime_guess crate で detect、判定不能なら `application/octet-stream` | 🟡 |
| `size_bytes` | plaintext のオリジナルサイズ (chunk オーバーヘッド除く) | 🔵 |
| `chunk_count` | `ceil(size_bytes / 1MB)`、復号時の検証用 | 🟡 |
| `sha256` | plaintext 全体の SHA-256、改ざん検出と重複排除 | 🟡 |
| `content_hmac` | レコード自体の整合性、change-password で再計算 | 🔵 |
| `signature` | ML-DSA-65 で sha256+filename+size を署名、改ざん検出 | 🟡 |
| `legacy_flag` | S12 と同じ semantics (0x00=Destroy, 0x01=Inherit) | 🟡 |
| `legacy_key_block` | S12 と同じ形式: `[12B IV][AES-GCM ciphertext]`、INHERIT 時のみ | 🟡 |
| `padding` | 0-255B、size analysis 緩和 | 🔵 |

### legacy_key_block の中身 (INHERIT 時) 🟡

`legacy_key_block` には、添付固有の "FileKey" を K_legacy で暗号化して保存する:

```
plaintext を K_legacy で暗号化したものではなく、
.attachments/<uuid>.bin を復号できる情報。

Phase 1 案: K_master と同じ鍵で chunk 暗号化していたら、K_master を共有する
            ことになり legacy 隔離の意味が薄い。
Phase 1 採用案: legacy_key_block には、AES-GCM(K_legacy, K_master_subkey) を保存。
            K_master_subkey は K_master と attachment uuid から HKDF-derive した
            32B 鍵で、`.attachments/<uuid>.bin` の chunk 暗号化に使う。
            legacy-access 時、heir は K_legacy で K_master_subkey を取り出し、
            chunk 復号できる。
```

これにより heir は `K_master` を取得することなく、INHERIT 添付の本体のみ
復号できる。

## 4. .attachments/<file_uuid>.bin フォーマット 🟡

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
AAD = [chunk_index: LE u32][total_chunks: LE u32][file_uuid: 16B]
    = 24 bytes
```

**目的**:
- chunk 順序の改ざん検出 (chunk_index が違うと tag mismatch)
- 全 chunk 数の改ざん検出 (truncation 検出)
- ファイル間入れ替え検出 (file_uuid)

### ファイルサイズ計算 🟡

`.attachments/<uuid>.bin` のサイズ:
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
ファイル名は UUID 直接 (元ファイル名は記録しない、メタデータレコードに記録)。

## 6. 後方互換性 🔵

### Phase 1 vault → S13 クライアント

- 既存 vault では全 entry が `attachment_count = 0`、`attachment_offset = 0`
- S13 reader は `attachment_count == 0` ならスキップ、空の attachment 一覧を返す
- 既存テスト全パス

### S13 vault → Phase 1 クライアント (S12 以前)

- S12 以前の reader は RECORD_TYPE_ATTACHMENT (0x03) を unknown として
  エラーにする可能性 → reader 拡張時に "unknown record type は skip" にしておく
- 安全性: S13 vault は S13+ クライアントのみで開く運用を推奨 (vault.toml の
  `schema_version = 4` で識別)

## 7. メタデータ署名 🟡

`signature` の対象メッセージ:
```
sha256 (32B) || filename_utf8 || size_bytes_le (8B)
```

これにより、攻撃者が攻撃:
- ファイル名のみ書き換え → signature mismatch
- size_bytes を偽装 → signature mismatch
- sha256 を別物に → signature mismatch
- .bin 本体を別物に → sha256 検証で不一致

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
