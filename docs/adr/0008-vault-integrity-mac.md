# ADR-0008: vault.pqd の vault レベル整合性 MAC (schema v0x06)

Status: 提案
Date: 2026-06-10

## Context

セキュリティ監査 (S15) で、`vault.pqd` の at-rest 改ざんに対する保護が
不十分であることが判明した。

監査で特定された高深刻度の問題:

- **H1 (切り詰め・並べ替え・ロールバック)**: レコードは個別に
  `content_hmac` / ML-DSA 署名で認証されるが、いずれも各レコードの
  `ciphertext` のみを対象とする。レコードの**総数・順序**を認証する仕組みが
  なく、`vault.pqd` に書き込める攻撃者は末尾レコードの削除 (切り詰め)、
  レコードの並べ替え、過去バージョンのレコードへの差し戻し (部分ロールバック)
  を検知されずに行える。
- **H2 (メタデータの改ざん可能性)**: AES-GCM を空 AAD で使用しているため、
  平文で格納される `record_type` / `uuid` / `created_at` / `updated_at` /
  `attachment_count` / `attachment_offset` やヘッダ各フィールド
  (`schema_version` / `flags` / `kdf_salt` 等) が HMAC/署名に束縛されておらず、
  攻撃者が自由に書き換えられる。

## Decision

`vault.pqd` のスキーマを **0x06** に上げ、ヘッダ `flags` の
`FLAG_INTEGRITY (0x01)` ビットが立っている場合、ファイル末尾に
**32 バイトの HMAC-SHA256 トレーラ**を付与する。

### MAC の対象範囲

```
HMAC-SHA256( mac_key, header || records || sentinel || padding )
```

ファイル先頭から MAC トレーラ直前までの**全バイト**を対象とする。これにより
ヘッダ全フィールド (version/flags/salts/kem_pk_offset/dsa_pk_hash/鍵ブロック) と、
全レコードの平文メタデータ・順序・件数 (sentinel 含む)・パディングが
一括で認証される。H1・H2 を**単一の仕組み**で同時に閉じる。

### 鍵 (ドメイン分離)

```
mac_key = HMAC-SHA256( sym_key, "pq-diary/vault-integrity/v1" )
```

per-record `content_hmac` (sym_key を直接使用) とは別のサブ鍵を用い、
2 つの MAC が混同・再利用されないようにする。

### 検証点

`DiaryCore::unlock` の単一チョークポイントで、鍵導出・検証トークン照合の
**直後・全レコードを読む前**に `verify_vault_integrity` を呼ぶ。検証は
`hmac::verify_slice` による定数時間比較。失敗時は `DiaryError::Crypto` を返し、
エンジンは unlocked 状態にしない。

### 移行

- 既存の v0x04 / v0x05 vault は MAC を持たない。読込時は受理し
  (`verify_vault_integrity` は flag 未設定なら no-op)、**次回の認証付き書込で
  v0x06 へ移行**する。これは既存の v4→v5 移行方針と整合する。
- 本番の全書込経路は認証版 (`write_vault_authenticated` /
  `write_vault_with_attachments_authenticated`) を使用する。MAC なしの
  `write_vault` / `write_vault_with_attachments` はテスト/レガシー専用に残す。

## 残存リスク (本質的限界)

ローカルファイルを完全に書き換えられる攻撃者に対し、**外部の信頼アンカー
(TPM カウンタ等) なしには防げない**以下は本 ADR の対象外とする:

- **Downgrade**: 攻撃者が `flags` の `FLAG_INTEGRITY` をクリアし MAC トレーラを
  除去すると、reader は legacy vault とみなし検証をスキップする。
- **全体ロールバック**: 正しい鍵で過去に生成された有効な v0x06 vault 全体へ
  差し戻す。

緩和策として、移行済み vault では `vault.toml` に最小スキーマを記録するなどの
best-effort 防御を将来検討する。現時点では本限界を明記するに留める。

なお、暗号文の偽造 (攻撃者が選んだ平文への復号) は AES-GCM + HMAC により
依然不可能であり、影響は「改ざんの検知」と「ロールバック/DoS」に限定される。

## Consequences

- v0x06 vault は tamper-evident になり、H1 (切り詰め・並べ替え・部分ロールバック)
  と H2 (メタデータ改ざん) を unlock 時に検知できる。
- ファイルは 32 バイト増加する。検証は unlock 時に全ファイルを 1 回読む
  (vault は小さく、各フィールドに 16 MiB 上限があるため許容)。
- 既存テストへの影響: `SCHEMA_VERSION` は 0x06、`init_vault` 出力の `flags` は
  `FLAG_INTEGRITY` を持つ。該当アサーションを更新済み。
