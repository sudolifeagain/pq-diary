# S12 デジタル遺言 スキーマ設計

**作成日**: 2026-05-17
**関連設計**: [architecture.md](architecture.md), [types.rs](types.rs)
**信頼性**: 全項目🔵

---

## 1. `vault.toml` 改訂 (S12 拡張) 🔵

### Before (S1〜S11)

```toml
[vault]
name = "default"
schema_version = 4

[access]
policy = "none"

[git]
author_name = ""
author_email = ""
commit_message = "Update vault"

[git.privacy]
timestamp_fuzz_hours = 0
extra_padding_bytes_max = 0

[argon2]
memory_cost_kb = 65536
time_cost = 3
parallelism = 1
```

### After (S12)

```toml
[vault]
name = "default"
schema_version = 4

[access]
policy = "none"

[git]
author_name = ""
author_email = ""
commit_message = "Update vault"

[git.privacy]
timestamp_fuzz_hours = 0
extra_padding_bytes_max = 0

[argon2]
memory_cost_kb = 65536
time_cost = 3
parallelism = 1

# S12 で追加。
[legacy]
initialized = true                  # bool, default false
destroy_confirmation = "timer30"    # "timer30" | "yn" | "phrase", default "timer30"
```

### 後方互換性 🔵

- 既存 Phase 1 vault は `[legacy]` セクション無し → `#[serde(default)]` で `initialized = false`, `destroy_confirmation = "timer30"` (Default) で読まれる
- `legacy init` 未実行の vault では `initialized = false`、全エントリは DESTROY として list される (REQ-704, EDGE-201)

### バリデーション

- `destroy_confirmation` の不正値 (例: `"timer60"`) → `DiaryError::Config("Invalid vault.toml [legacy]: unknown destroy_confirmation: timer60")`

---

## 2. `vault.pqd` v4 ヘッダー (S12 で変更なし) 🔵

S3 で `legacy_salt` (32B) を予約済み。S12 では既存フィールドを利用するのみ、フォーマット変更なし。

| フィールド | サイズ | S12 での扱い |
|---|---|---|
| schema_version | u32 | 変更なし (4 固定) |
| flags | u32 | 変更なし |
| payload_size | u64 | 変更なし |
| kdf_salt | [u8; 32] | 変更なし (K_master 用) |
| **legacy_salt** | [u8; 32] | **S12 で使用開始** (K_legacy 用、`init_vault` で既にランダム生成済み) |
| verification_iv / verification_ct | - | 変更なし (K_master の verification token) |
| kem_pk_offset | [u8; 32] | 変更なし (Phase 2 予約) |
| dsa_pk_hash | [u8; 32] | 変更なし |
| kem_encrypted_sk | Vec<u8> | 変更なし (K_master で暗号化) |
| dsa_encrypted_sk | Vec<u8> | 変更なし |

### legacy-access 後の vault.pqd ヘッダー 🔵

`legacy-access` で生成される新 vault.pqd では:

| フィールド | 値 |
|---|---|
| schema_version | 4 (維持) |
| kdf_salt | **元の legacy_salt を kdf_salt として使う** (K_legacy がマスター鍵相当になるため) |
| legacy_salt | (使わない、ゼロまたは新規ランダム; 将来 rotate で再 init するため) |
| verification_iv / verification_ct | **K_legacy で再生成** |
| kem_encrypted_sk / dsa_encrypted_sk | **K_legacy で再暗号化** (KEM/DSA seed 自体は不変、署名検証維持) |

---

## 3. エントリレコードフォーマット (S12 で書き込み開始) 🔵

S3 で予約済みフィールド。

```
[16B: UUID]
[8B: created_ts]
[8B: updated_ts]
[12B: AES-GCM IV]
[4B: ciphertext_len]
[Vec<u8>: ciphertext (本体)]
[3309B: ML-DSA-65 signature]
[32B: HMAC-SHA256 content_hmac]
[1B: legacyフラグ]               ← S3 予約、S12 で書き込み開始 (0x00 or 0x01)
[4B: legacy鍵ブロック長]          ← S3 予約、S12 で書き込み開始 (0 or N)
[N B: legacy鍵ブロック]           ← S12 で書き込み開始: K_entry を K_legacy で AES-GCM 暗号化
[1B: パディング長]
[パディング]
```

### legacy 鍵ブロック の内訳 (INHERIT エントリのみ) 🔵

```
[12B: AES-GCM IV (legacy 用、entry IV とは別)]
[N B: AES-GCM ciphertext (= K_entry [32B] を K_legacy で暗号化、16B の tag 含む)]
```

**長さ**: 12 + 32 + 16 = **60B** (固定、INHERIT エントリのみ)

DESTROY エントリでは `legacy鍵ブロック長 = 0` で legacy鍵ブロック自体は省略。

### サイズインパクト 🔵

| エントリ種別 | 追加サイズ |
|---|---|
| Phase 1 vault (legacy 未対応) | 既に 5B (フラグ 1 + 長さ 4) 予約済み |
| DESTROY (S12) | +0 (既存 5B のまま) |
| INHERIT (S12) | +60B (legacy 鍵ブロック) |

100 INHERIT エントリで +6KB 程度。許容範囲。

---

## 4. legacy-access 後の新 vault.pqd 構造 🔵

`legacy-access` 完了時、新 vault.pqd には:
- ヘッダー: K_legacy 用に再生成 (上記 §2 参照)
- ペイロード: INHERIT エントリのみ (DESTROY エントリは zeroize 削除)
- 各 INHERIT エントリの legacy 鍵ブロック: 残してもよい (rotate 時の冗長性) or 削除 (legacy-access 後は K_master 不要なので K_legacy ベースのみ)

**設計判断**: `legacy-access` 後はシンプルに legacy 鍵ブロックを削除し、新 vault は「K_legacy が新マスター鍵」とする。

```
旧 vault.pqd 構造:
  K_master で暗号化された vault
  各エントリに [legacy フラグ, legacy 鍵ブロック]

legacy-access 後の新 vault.pqd:
  K_legacy で暗号化された vault (K_legacy がマスター鍵相当)
  全エントリは元 INHERIT だったもののみ
  各エントリの [legacy フラグ = 0x00 (デフォルト), legacy 鍵ブロック長 = 0]
  vault.toml [legacy] initialized = false (新規 vault として扱う)
```

これにより、骨梧者は同じ death-access code で vault を継続利用し、必要なら `legacy init` を再実行して自分の遺族向けに設定可。

---

## 5. CLI コマンドの引数フォーマット 🔵

### `legacy init`
```
pq-diary [-v VAULT] [--password PASSWORD] [--claude(=>block)] legacy init
```
対話のみ (引数なし)。確認方式選択は対話 prompt。

### `legacy set`
```
pq-diary [-v VAULT] [--password PASSWORD] [--claude(=>block)] legacy set <ID_PREFIX> [--inherit | --destroy]
```
- `<ID_PREFIX>`: 必須、8 文字以上推奨
- `--inherit` と `--destroy` は排他 (clap conflicts_with)
- どちらも指定なしならエラー (`--inherit or --destroy is required`)

### `legacy list`
```
pq-diary [-v VAULT] [--password PASSWORD] [--claude(=>block)] legacy list
```
引数なし。

### `legacy rotate`
```
pq-diary [-v VAULT] [--password PASSWORD] [--claude(=>block)] legacy rotate
```
引数なし。master + old + new (×2) 全 TTY 入力。

### `legacy-access`
```
pq-diary [-v VAULT] [--claude(=>block)] legacy-access
```
master 不要、legacy code のみ TTY 入力。

---

## 関連

- [architecture.md](architecture.md)
- [types.rs](types.rs)
- [dataflow.md](dataflow.md)
- [cli-commands.md](cli-commands.md)

## 信頼性

🔵 100%
