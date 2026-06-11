# vault.pqd v0x07 フォーマット仕様 (キースロット封筒 + MDK)

> 本書は ADR-0009 の実装仕様。全多バイト整数は **リトルエンディアン**。
> `strings vault.pqd` でフィールド名・アルゴリズム名が露出しない設計を維持する
> (ADR-0002 を踏襲)。
>
> v0x07 は S15 実装済みの v0x06 (ADR-0008 整合性 MAC) の**次**であり、整合性
> トレーラの仕組みを継承しつつ MAC 鍵を MDK 由来に再鍵化する。固定ヘッダは
> キースロット節の導入に伴い再定義される (下記 §0)。

## 0. 全体構造

```
Offset / 順序           内容
----------------------  ------------------------------------------------------
[0..8]                  マジック "PQDIARY\0"
[8]                     schema_version = 0x07
[9]                     flags          (bit0 FLAG_INTEGRITY=0x01 … v6/v7 は常時セット)
[10..12]                予約 (0x0000)
[12..16]                payload_size (LE u32)         … エントリ/添付ペイロード節のバイト長
[16..48]                legacy_salt (32B)             … S12 K_legacy 導出用 (役割不変)
[48..52]                keyslot_section_len (LE u32)  … キースロット節のバイト長
[52 .. 52+S]            キースロット節 (S = keyslot_section_len)
[.. ]                   ペイロード節 (エントリ+添付+ゼロsentinel, K_data で暗号化)
[.. ]                   ランダムパディング (512..4096B)
[末尾 32B]              整合性トレーラ HMAC-SHA256
```

旧 v4/v5 固定ヘッダ (204B) からの差分:

- **削除**: `kdf_salt` (→ 各スロットの per-slot salt へ移動)、`verification_iv` /
  `verification_ct` (→ スロットの AEAD 復号成否が検証になるため廃止)、
  `kem_pk_offset` (未使用)、`dsa_pk_hash` (DSA は非 load-bearing のため削除)、
  ヘッダ末尾の `kem_encrypted_sk` / `dsa_encrypted_sk` (所有者 KEM 秘密鍵は鍵
  ファイル側へ。convenience vault では不要)。
- **追加**: `keyslot_section_len` + キースロット節、末尾の整合性トレーラ。

## 1. キースロット節

スロットレコードの連続。個数は `keyslot_section_len` を消費し切るまで読む
(各レコードが自己記述的な長さを持つ)。

### スロットレコード

```
[slot_len: LE u32]                 … 以降 (slot_type〜label) の総バイト長
  [slot_type: 1B]                  … 0x01 password / 0x02 password+keyfile
                                       0x03 recipient / 0x04 recovery
  [slot_id: 16B]                   … UUID v4 (keyslot remove の参照子)
  [kdf_algo: 1B]                   … 0x00 none / 0x01 Argon2id
  [kdf_m_cost: LE u32]             … Argon2id memory_cost_kb (kdf_algo=0x01 時)
  [kdf_t_cost: LE u32]             … Argon2id time_cost
  [kdf_p_cost: LE u32]             … Argon2id parallelism
  [salt: 32B]                      … Argon2 salt (kdf_algo=0x00 のとき zero)
  [kem_alg: 1B]                    … 0x00 none / 0x01 ML-KEM-768
                                       0x02 ML-KEM-768+HQC (将来; HQC 標準化後)
  [kem_ct_len: LE u32][kem_ct]     … KEM 暗号文 (slot 0x02/0x03)。他は len=0
  [wrap_iv: 12B]                   … MDK ラップ用 AES-256-GCM IV
  [wrapped_mdk_len: LE u32]        … = 48 (MDK 32B + GCM tag 16B)
  [wrapped_mdk]                    … AES-256-GCM(slot_key, MDK)
  [label_len: LE u32][label]       … 任意 UTF-8 ラベル ("laptop" / "heir:alice")
```

### slot_key 導出

| slot_type | slot_key |
|---|---|
| 0x01 password | `Argon2id(password, salt, kdf_*)` |
| 0x04 recovery | `Argon2id(recovery_code, salt, kdf_*)` |
| 0x03 recipient | `ss = ML-KEM.Decaps(recipient_sk, kem_ct)`; `HKDF-SHA256(ss, "pq-diary/keyslot/recipient/v1")` |
| 0x02 password+keyfile | `ss = ML-KEM.Decaps(keyfile_sk, kem_ct)`; `K_pw = Argon2id(password, salt, kdf_*)`; `HKDF-SHA256(K_pw ‖ ss, "pq-diary/keyslot/keyfile/v1")` |

HKDF は RFC 5869 の Extract → Expand を用い、出力長は 32B。`info` には上表の
ASCII ラベルに加えて `slot_id` を含める。ラベルは用途別に固定し、別用途で再利用しない。

unlock 手順: 提示された資格情報で開けるスロットを順に試行し、最初に
`wrapped_mdk` の AEAD 復号に成功したスロットの平文を **MDK** とする
(GCM タグ不一致 = そのスロットの資格情報が誤り)。

`wrap_iv` は 96-bit の CSPRNG 乱数とし、同一 `slot_key` で再利用してはならない。
スロットの再ラップ・MDK ローテーション・ラベル変更に伴う再書込時も必ず新しい
`wrap_iv` を生成する。

## 2. MDK サブ鍵階層 (鍵分離)

```
K_data            = HKDF-SHA256(MDK, "pq-diary/data/v1")            … 本文/添付 AES-256-GCM
K_content_hmac    = HKDF-SHA256(MDK, "pq-diary/content-hmac/v1")    … per-record content_hmac
K_vault_integrity = HKDF-SHA256(MDK, "pq-diary/vault-integrity/v1") … vault 全体トレーラ
```

監査 Low-1 (暗号鍵と HMAC 鍵の使い回し) を解消。`EntryRecord` /
`AttachmentRecord` の物理レイアウトは v5 と不変で、暗号化鍵が `sym_key` から
`K_data`、`content_hmac` 鍵が `sym_key` から `K_content_hmac` に変わるのみ。

## 3. 整合性トレーラ

```
trailer (末尾 32B) = HMAC-SHA256( K_vault_integrity, file[0 .. len-32] )
```

ファイル先頭からトレーラ直前までの全バイトを対象 (S15 実装済みの ADR-0008
トレーラを継承し、MAC 鍵のみ `derive_vault_mac_key(sym_key)` → `HKDF(MDK, …)`
に再鍵化)。検証は `DiaryCore::unlock` で MDK 復元直後・全レコード読込前に
`hmac::verify_slice` の定数時間比較。失敗時は `DiaryError::Crypto`、エンジンは
unlocked にしない。`FLAG_INTEGRITY` の downgrade / 全体ロールバックが対象外で
ある点も ADR-0008 のまま。

## 4. 鍵ファイル形式 (slot 0x02 / 所有者の第2要素)

```
[0..8]    マジック "PQDKEYF\0"
[8]       version = 0x01
[9..11]   予約
[11..75]  ML-KEM-768 復号鍵シード (64B)
[75..107] このシードに対応する公開鍵の SHA-256 (照合用)
[107..111] CRC32 (破損検出)
```

- パーミッション: Unix 0600 / Windows owner-only ACL。メモリ上は `SecureBuffer`
  で zeroize。
- **vault.pqd と同じ場所に同期してはならない** (別所保管で初めて第2要素になる)。
  この警告を `keyslot add-keyfile` 実行時に表示する。
- 鍵ファイル単体では vault を開けない (slot_key が password とも束縛されるため)。

## 5. 復旧コード (slot 0x04)

- 256bit の OsRng 乱数を Crockford Base32 でグループ表示 (例: `XXXX-XXXX-…`)。
- 生成時に一度だけ標準エラーへ表示し、平文では一切保存しない。
- 導出は `Argon2id(recovery_code, salt)` (パスワードと同等のストレッチ)。

## 6. 後方互換と移行

- reader は `0x04..=0x07` を受理。v4/v5 は従来パス (sym_key 直接) で読み、v6 は
  sym_key + 整合性トレーラ、v7 は MDK + キースロットで読む。
- 書込は常に v0x07。v6→v7 初回書込で MDK 生成 + 全エントリ/添付を K_data で
  再暗号化 + content_hmac を K_content_hmac で再計算 + 既定 `password` スロット
  作成 + K_vault_integrity でトレーラ再計算。
- `MAX_FIELD_SIZE` (16 MiB) 上限は全可変長フィールド (kem_ct / wrapped_mdk /
  label / slot_len) に引き続き適用し、巨大 alloc DoS を防ぐ。

## 7. テスト観点 (TDD)

- ラウンドトリップ: 各 slot_type で wrap→unwrap→MDK 一致。
- GCM nonce: 同一 slot_key で複数回 wrap/rewrap しても `wrap_iv` が再利用されない。
- マルチスロット: 同一 MDK を ①②③④ でラップし、いずれの資格情報でも開けること。
- 設定式モード: `high` で password 単独スロットが存在しないこと、`convenience`
  で存在すること (構造アサーション)。
- 整合性: 1 バイト改ざん・末尾レコード切り詰め・スロット並べ替えで unlock 失敗。
- 失効: スロット削除 + MDK ローテーション後、旧鍵ファイル/旧受信者鍵で開けないこと。
- 移行: v5 vault → v6 自動移行後に全エントリが読めること、トレーラが付くこと。
- 鍵ファイル: 単体では開けない / パスワード併用で開ける / 破損 CRC を検出。
```
