# ADR-0009: キースロット封筒 + Master Data Key (schema v0x07)

Status: 提案
Date: 2026-06-11

## Context

S15 セキュリティ監査で、看板機能である **ML-KEM-768 が実データ保護経路で
一切使われていない**ことが判明した (`core/src/entry.rs` に `kem` 呼び出し皆無)。
日記本文は `AES-256-GCM(sym_key, …)` で直接暗号化され、`sym_key` は
`Argon2id(パスワード)` から導出した K_master そのもの。ML-KEM の鍵ペアは
K_master で暗号化して同じファイルに保管されるだけで、データ鍵のラップにも
カプセル化にも使われていない。

機密性自体は AES-256 (Grover 耐性) + Argon2id が担保しており耐量子だが、
要件定義 §5.4 / 脅威表の「ML-KEM-768 で鍵カプセル化 / Harvest Now, Decrypt
Later を防御」という記述は実装と乖離している。本 ADR はこの乖離 (監査 High-1)
を閉じ、ML-KEM を**実際に load-bearing にする**。

### 単一パスワードモデルの理論的限界

攻撃者が持つのは `vault.pqd` のみ。`{ファイル + パスワード}` から再構成できる
鍵は、パスワードを当てた攻撃者も再構成できる。**パスワード以外の秘密 (第2要素
または受信者の秘密鍵) がない限り、KEM は機密性を 1 ビットも追加できない。**
したがって ML-KEM を「本当に機能」させるには第2の秘密を導入する:

- **B**: 所有者自身の KEM 秘密鍵を**鍵ファイル**に置き、第2要素にする。
- **C**: 相続人・別デバイスの **KEM 公開鍵**に対し vault 鍵をカプセル化する。

ユーザー合意: **B と C を併用**し、「用途ごとに選べる設定式」とする。

### 既存実装・ロードマップとの関係

- **ADR-0008 は S15 で実装・プッシュ済み** (schema **v0x06**, vault レベル
  整合性 MAC, commit 478ed43〜)。本 ADR はこれを**置き換えず、その上に積む**。
- **要件 §5.4** が HQC ハイブリッドを将来の v6 で想定 → 本フォーマットの
  スロット種別 (`kem_alg=0x02`) の追加で実現でき、**新たな schema bump は不要**。

本フォーマットは v0x06 の次として **v0x07** とする。

## Decision

### 1. Master Data Key (MDK) 封筒モデル

ランダムな **MDK (32B)** を vault ごとに生成し、これが全エントリ・添付を
暗号化する。MDK 自体は **複数のキースロット**で多重ラップする (age / LUKS
keyslot / PGP マルチ受信者と同じ封筒方式)。各スロットは MDK への独立した
復元経路を 1 つ提供する。

```
ランダム MDK(32B)
  └─ HKDF-SHA256(MDK, label) で用途別サブ鍵を派生 (監査 Low-1: 鍵分離を解消)
        K_data            = HKDF(MDK, "pq-diary/data/v1")            … 本文/添付 AES-256-GCM
        K_content_hmac    = HKDF(MDK, "pq-diary/content-hmac/v1")    … per-record HMAC
        K_vault_integrity = HKDF(MDK, "pq-diary/vault-integrity/v1") … vault 全体 MAC (ADR-0008 再鍵化)

各スロット slot_key で MDK をラップ: wrapped_mdk = AES-256-GCM(slot_key, MDK)
  ① password         slot_key = Argon2id(pw, salt)
  ② password+keyfile slot_key = HKDF(Argon2id(pw) ‖ ML-KEM.Decaps(keyfile_sk, kem_ct))   ← 真の2要素
  ③ recipient        slot_key = HKDF(ML-KEM.Decaps(recipient_sk, kem_ct))                 ← C
  ④ recovery         slot_key = Argon2id(印刷復旧コード, salt)
```

- ② で **所有者の ML-KEM 秘密鍵を鍵ファイルに置く**ことで、`vault.pqd +
  パスワード総当たり`では開けなくなる = ML-KEM が所有者向けに本物の役割を持つ。
  パスワードと鍵ファイルの**両方**が必要 (HKDF で K_pw と KEM 共有秘密を束縛)。
- ③ で相続人/別デバイスの公開鍵にカプセル化 = KEM 本来の用途。
- スロット追加 (端末・相続人登録) は **MDK を 1 回ラップするだけ**。本文の
  再暗号化は不要。再暗号化が要るのは失効 (スロット削除 + MDK ローテーション) のみ。
- **パスワード検証トークンは廃止**。スロットの `wrapped_mdk` を AEAD 復号できるか
  否か (GCM タグ) がそのまま正否判定になる。
- 本 ADR の `HKDF(...)` 表記はすべて RFC 5869 の HKDF-SHA256
  (Extract → Expand, 出力 32B) を指す。`info` は表示された ASCII ラベルをそのまま使い、
  スロット鍵導出では `slot_id` も `info` に含めて同じ共有秘密から同じ鍵が再利用されない
  ようにする。

### 2. 設定式セキュリティモード (init 時のスロット選択に還元)

`create-vault --security <high|convenience>` で**作成時に作るスロット**を選ぶ。
保証はフラグではなく**ディスク上に実在するスロット集合**で構造的に決まる。

| モード | 初期スロット | 性質 |
|---|---|---|
| `high` | ② password+keyfile, ④ recovery | 鍵ファイル必須・パスワード単独経路なし。盗難/HNDL に第2の壁。紛失時は復旧コードで救済 |
| `convenience` | ① password | 従来通りパスワードのみ。後から②③を足せるが①が残る限り B は実質無効 |

どちらのモードでも ③ recipient は後から `keyslot add-recipient` で追加可能。
`vault.toml` にモードを記録するが、これは CLI/UX 上のヒントであり、真の保証は
スロット構造側にある。

### 3. 整合性 MAC は ADR-0008 を継承・再鍵化

S15 実装済みの vault レベル整合性 MAC (`flags` の `FLAG_INTEGRITY`, 末尾 32B
HMAC トレーラ) は v0x07 でも維持する。ただし MAC 鍵を MDK モデルに合わせ
`derive_vault_mac_key(sym_key)` → **`K_vault_integrity = HKDF(MDK, …)`** に
移行する (v0x06→v0x07 昇格時)。MAC の対象範囲・検証チョークポイント・残存リスク
(downgrade / 全体ロールバック) は ADR-0008 のまま。

### 4. HQC をスロット種別に格下げ (将来の bump 不要)

HQC ハイブリッドは ②/③ スロットの `kem_alg=0x02 (ML-KEM-768 + HQC)` の追加で
表現する。スロット構造が可変・自己記述的なので **HQC 対応に新たな schema bump
は不要** (要件 §5.4 の「v6 で HQC」は本フォーマットのスロット拡張として実現)。

### スキーマバージョン

本フォーマットを **v0x07** とする。詳細なバイトレイアウトは
`docs/design/vault-v6-keyslot-format.md`。reader は v0x04〜v0x07 を受理し、
書込は常に v0x07。

### 移行 (v0x06 → v0x07)

既存 vault (v4/v5: sym_key 直接, v6: +整合性MAC) の初回書込時に: ① MDK 生成 →
② 全エントリ/添付を K_data で再暗号化 + content_hmac を K_content_hmac で再計算 →
③ 既定で `password` スロット 1 個を作成 (現行 UX 維持) → ④ K_vault_integrity で
整合性トレーラを再計算。`high` モードへの昇格は移行後に `keyslot add-keyfile` →
`keyslot remove <password-slot>`。本文再暗号化は一度きり。

### 未決の細目と推奨デフォルト

| 項目 | 推奨デフォルト |
|---|---|
| 鍵ファイル形式 | versioned magic + ML-KEM-768 復号鍵シード(64B) + CRC、0600/owner-only ACL、メモリは zeroize |
| 復旧コード | 256bit 乱数を Crockford Base32 でグループ表示、Argon2id でストレッチ。生成時に一度だけ表示し平文保存しない |
| vault マニフェスト署名 | 既定は HMAC(K_vault_integrity)。ML-DSA 署名は任意 (下記参照) |

### ML-DSA の扱い (正直な位置づけ)

本設計で **ML-KEM はスロット ②③ で load-bearing になる**が、**ML-DSA は
ローカル用途では依然 load-bearing ではない** (整合性は HMAC で足りる)。
ML-DSA に実用途を与えるには「**MDK を持たない第三者が検証できる署名付き
エクスポート**」が必要で、これは将来の任意拡張とする。過大広告を避け、現時点で
ML-DSA を「署名付きエクスポート用の予約」と正直に記載する。

## Consequences

- ML-KEM が実データ保護で本当に機能する (所有者2要素 + 受信者共有)。監査
  High-1 (最大の設計乖離) が解消する。
- 監査 Low-1 (鍵分離) も MDK→HKDF サブ鍵化で同時に解消。整合性 MAC (ADR-0008)
  は MDK 鍵化されつつ機能継続。
- HQC が schema bump 不要のスロット拡張になり、要件 §5.4 のロードマップが軽量化。
- **副作用 (重要)**: ML-KEM が飾りから基幹へ昇格するため、ADR-0001 のフォーク
  (`ml-kem`/`ml-dsa`, 個人フォーク・未監査・pre-1.0) のリスク重大度が上がる。
  本実装と必ずセットで `cargo audit`/`cargo deny` の CI 必須化・upstream 還元・
  リビジョン固定方針の明文化を行う (監査 Medium-1)。
- フォーマット改修は大きい (固定ヘッダ縮小 + 可変スロット節 + 既存トレーラ流用)。
  自前バイナリのため migration コードのテストを厚くする (ADR-0002 の方針を踏襲)。
- **残存リスク (ADR-0008 から継承)**: downgrade (FLAG クリア + トレーラ除去) /
  正しい鍵で生成済みの過去 vault への全体ロールバック は外部信頼アンカー (TPM 等)
  なしには防げず本 ADR の対象外。
- AES-256-GCM の nonce/IV は同一鍵で再利用してはならない。特に `wrapped_mdk`
  の `wrap_iv` は各スロットの作成・再ラップごとに CSPRNG で新規生成し、同一
  `slot_key` で再利用しない。

## 実装計画 (PR 分割)

監査の他の未対応項目と合わせ、レビュー粒度を保つため PR を分割する:

1. **PR: パスワード強度強制** (監査 High-2) — 本フォーマットに依存しない独立 PR
2. **PR: 署名検証 fail-open 修正** (監査 Low-2) — 独立 PR
3. **PR: サプライチェーン CI** (監査 Medium-1) — `cargo deny`/`audit` + フォーク ADR
4. **PR: キースロット設計** — 本 ADR + `docs/design/vault-v6-keyslot-format.md` (本コミット)
5. **PR 群: キースロット実装 (v0x07)** — `core/src/vault/keyslot.rs` 新規 + format/
   reader/writer の v0x07 対応 → CLI (`create-vault --security`,
   `keyslot {list,add-keyfile,add-recipient,add-recovery,remove}`, `export-pubkey`) →
   移行 → requirements/CHANGELOG 訂正。Tsumiki TDD フローで実施。
