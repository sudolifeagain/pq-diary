# S16 キースロット封筒 + MDK 受け入れ基準

**作成日**: 2026-06-11
**関連要件**: [requirements.md](requirements.md) / [ADR-0009](../../adr/0009-keyslot-envelope-mdk-v6.md)

**【信頼性レベル】**: 🔵 ADR/仕様準拠 / 🟡 妥当な推測

> 実装は TDD で行う。各 TC は `cargo test` で機械的に検証できる粒度に落とすこと。
> 暗号系 TC は fast Argon2 params を用い CI を高速に保つこと。

---

## REQ-100: MDK とサブ鍵 🔵

### 正常系
- [ ] **TC-S16-MDK-01**: vault 作成で 32B MDK が生成され、ディスク上に MDK 平文が存在しない (vault.pqd を走査して MDK バイト列が出現しないこと) 🔵
- [ ] **TC-S16-MDK-02**: `K_data`/`K_content_hmac`/`K_vault_integrity` が HKDF-SHA256 で MDK + 各 info から決定的に導出され、互いに異なる 🔵
- [ ] **TC-S16-MDK-03**: 同一 MDK + 同一 info → 同一サブ鍵 (決定性)、info 違い → 異なるサブ鍵 🔵

### 異常系
- [ ] **TC-S16-MDK-E01**: MDK / サブ鍵を保持する構造体が `ZeroizeOnDrop` を実装し、drop 後に当該メモリが 0 埋めされる (ManuallyDrop パターンで検証) 🔵

---

## REQ-105〜106: メタデータ機密化 🟡

### 正常系
- [ ] **TC-S16-META-01**: v0x07 vault に既知タイムスタンプのエントリを書き、vault.pqd を走査して `created_at`/`updated_at` に相当する平文 LE u64 が露出しない (暗号化ペイロード内のみに存在) 🟡
- [ ] **TC-S16-META-02**: git pull merge が**復号後の `updated_at`** で last-write-wins を正しく判定する (同一 UUID・新しい updated_at が勝つ) 🟡
- [ ] **TC-S16-META-03**: `content_hmac` が `K_content_hmac` (sym_key 直接でない) で計算・検証される (REQ-102 内包) 🔵

### 境界値
- [ ] **TC-S16-META-B01**: 平文に残す構造メタデータ (record_type/各長さ) の改ざんが整合性トレーラ検証で検知される (ADR-0008) 🔵

---

## REQ-200: スロット共通 🔵

### 正常系
- [ ] **TC-S16-SLOT-01**: 1 つの MDK を複数スロット種別でラップし、いずれの資格情報でも同一 MDK を回復できる 🔵
- [ ] **TC-S16-SLOT-02**: `wrapped_mdk` は 48B (MDK 32B + GCM tag 16B)。正しい slot_key で復号成功、誤 slot_key で AEAD タグ失敗 🔵
- [ ] **TC-S16-SLOT-03**: スロットのラウンドトリップ (シリアライズ→パース) で `slot_id`/型/salt/kem_ct/wrapped_mdk/label が保存される 🔵
- [ ] **TC-S16-SLOT-04**: 同一 `slot_key` で複数回 wrap/rewrap しても `wrap_iv` が再利用されない 🔵

### 異常系
- [ ] **TC-S16-SLOT-E01**: `slot_len`/`kem_ct_len`/`wrapped_mdk_len`/`label_len` が 16 MiB 超 → `DiaryError::Vault` (DoS 防止) 🔵
- [ ] **TC-S16-SLOT-E02**: 未知の `slot_type` バイト → `DiaryError::Vault` (厳格パース) 🔵

---

## REQ-210: slot① password 🔵

### 正常系
- [ ] **TC-S16-PW-01**: password スロットで `slot_key = Argon2id(pw, salt)` を導出し MDK をラップ→正しい pw で MDK 回復 🔵
- [ ] **TC-S16-PW-02**: 誤 pw → MDK 回復失敗 (AEAD タグ失敗、`invalid credentials`) 🔵
- [ ] **TC-S16-PW-03**: 異なる vault は異なる salt を持ち、同一 pw でも slot_key/wrapped_mdk が異なる 🔵

---

## REQ-220: slot② password+keyfile (ML-KEM 2要素) 🔵

### 正常系
- [ ] **TC-S16-KF-01**: `add-keyfile` で ML-KEM 鍵ペア生成、鍵ファイル (magic+seed64B+pkhash+CRC) が 0600 で書き出される 🔵
- [ ] **TC-S16-KF-02**: `slot_key = HKDF(K_pw ‖ ss, "…/keyfile/v1" ‖ slot_id)` で MDK をラップ。**正しい pw + 正しい鍵ファイル**で MDK 回復成功 🔵
- [ ] **TC-S16-KF-03**: `encaps(ek)`→格納した `kem_ct` を `decaps(keyfile_dk, kem_ct)` で復号し、encaps 側 `ss` と一致 🔵

### 異常系
- [ ] **TC-S16-KF-E01**: 正しい pw + **鍵ファイル無し/誤** → MDK 回復失敗 🔵
- [ ] **TC-S16-KF-E02**: **誤 pw** + 正しい鍵ファイル → MDK 回復失敗 (両方必須) 🔵
- [ ] **TC-S16-KF-E03**: 鍵ファイル CRC 破損 → 読み込みエラー 🔵
- [ ] **TC-S16-KF-E04**: 鍵ファイル単体では vault を開けない (パスワード未提示時に拒否) 🔵

### 境界値
- [ ] **TC-S16-KF-B01**: `add-keyfile` 実行時、鍵ファイルを別保管するよう警告が stderr に出る (REQ-225) 🔵

---

## REQ-230: slot③ recipient (共有/遺産) 🔵

### 正常系
- [ ] **TC-S16-RCP-01**: 受信者 ML-KEM 鍵ペアを別途生成→その `ek` で `add-recipient`→受信者の `dk` で MDK を回復できる 🔵
- [ ] **TC-S16-RCP-02**: `export-pubkey` の出力を `add-recipient` に渡してスロット追加が成功 🟡
- [ ] **TC-S16-RCP-03**: recipient スロット追加で本文 ciphertext が不変 (再暗号化なし、REQ-234) 🔵

### 異常系
- [ ] **TC-S16-RCP-E01**: 不正/サイズ違いの受信者公開鍵 → FIPS 203 入力検証で拒否 (`DiaryError::Crypto`) 🔵
- [ ] **TC-S16-RCP-E02**: 受信者でない第三者の `dk` では MDK を回復できない 🔵

---

## REQ-240: slot④ recovery 🔵

### 正常系
- [ ] **TC-S16-REC-01**: `add-recovery`/`--security high` で 256bit 復旧コードが生成され Crockford Base32 で**一度だけ**表示される 🔵
- [ ] **TC-S16-REC-02**: 復旧コードで `slot_key = Argon2id(code, salt)` を導出し MDK 回復成功 🔵

### 異常系
- [ ] **TC-S16-REC-E01**: 復旧コードが vault.pqd / vault.toml に平文で保存されていない 🔵

---

## REQ-300: スロット管理 🔵

### 正常系
- [ ] **TC-S16-MGMT-01**: `keyslot list` が全スロットの id/型/label を表示し、秘密値を一切表示しない 🔵
- [ ] **TC-S16-MGMT-02**: `keyslot remove <id>` 後、削除スロットの資格情報では開けず、残存スロットでは開ける 🔵
- [ ] **TC-S16-MGMT-03**: remove は MDK ローテーション (新 MDK で全再暗号化 + 残存スロット再ラップ) を行い、ローテーション後の vault は旧 MDK 由来のラップを含まない 🔵

### 異常系
- [ ] **TC-S16-MGMT-E01**: **最後の 1 スロット**の remove → 拒否 (ロックアウト防止、REQ-302) 🔵
- [ ] **TC-S16-MGMT-E02**: remove 中の失敗 (ディスクフル等) → `.tmp` 削除、旧 vault.pqd 維持 🔵
- [ ] **TC-S16-MGMT-E03**: 存在しない `slot_id` の remove → エラー 🟡

---

## REQ-400: 設定式モード 🔵

### 正常系
- [ ] **TC-S16-MODE-01**: `--security convenience` (既定) → slot① のみ作成、password で開ける 🔵
- [ ] **TC-S16-MODE-02**: `--security high` → slot② + slot④ 作成、**slot① が存在しない** (構造アサーション) 🔵
- [ ] **TC-S16-MODE-03**: `high` で作成後、(pw + keyfile) で開け、pw 単独では開けない 🔵

### 異常系
- [ ] **TC-S16-MODE-E01**: `--security` 不正値 → clap/引数エラー 🟡

---

## REQ-500: unlock フロー 🔵

### 正常系
- [ ] **TC-S16-UNL-01**: v0x07 vault を正しい資格情報で unlock→整合性トレーラ検証 OK→全エントリ読める 🔵
- [ ] **TC-S16-UNL-02**: 整合性検証は MDK 回復直後・全レコード読込前に実行される (1 バイト改ざんで unlock 失敗) 🔵

### 異常系
- [ ] **TC-S16-UNL-E01**: 全スロットで MDK 回復不可 → `invalid credentials` 相当のエラー、unlocked にならない 🔵
- [ ] **TC-S16-UNL-E02**: 整合性トレーラ改ざん → `DiaryError::Crypto`、unlocked にならない 🔵

---

## REQ-600: 移行 (v0x06 → v0x07) 🔵

### 正常系
- [ ] **TC-S16-MIG-01**: 既存 v6 vault を開いて 1 度書込→schema が v0x07 に、`password` スロット 1 個が生成される 🔵
- [ ] **TC-S16-MIG-02**: 移行後、移行前と同じパスワードで全エントリが読める (非破壊・冪等) 🔵
- [ ] **TC-S16-MIG-03**: 移行で本文が `K_data` で再暗号化され、`content_hmac` が `K_content_hmac` で再計算され、整合性トレーラが `K_vault_integrity` で再計算される 🔵
- [ ] **TC-S16-MIG-04**: v4/v5/v6/v7 すべて reader が受理する (`SCHEMA_VERSION_MIN=0x04`) 🔵

### 異常系
- [ ] **TC-S16-MIG-E01**: 移行中の書込失敗 → `.tmp` 削除、旧 vault.pqd 維持 🔵

---

## REQ-700: CLI 🟡

### 正常系
- [ ] **TC-S16-CLI-01**: `vault create --security high` / `keyslot {list,add-keyfile,add-recipient,add-recovery,remove}` / `export-pubkey` が `--help` で表示され smoke test を通る 🔵
- [ ] **TC-S16-CLI-02**: `keyslot` 系コマンドは password 取得 3 段階 (flag/env/TTY) を踏む 🟡

### 異常系
- [ ] **TC-S16-CLI-E01**: `--claude` 付きで keyslot 系コマンド → 全て拒否 (REQ-702) 🔵

---

## REQ-800: HQC 予約 🟡

- [ ] **TC-S16-HQC-01**: スロットの `kem_alg` フィールドが将来値 `0x02` を**パースできる** (未知値で即エラーにせず、未実装アルゴは明確なエラー) — 前方互換の構造確認 🟡

---

## DoD (S16)

- [ ] `cargo build/test/clippy --workspace` 全パス、`cargo audit` クリーン
- [ ] セキュリティ不変条件 (requirements.md 末尾) を全て満たす
- [ ] `requirements.md` (PRD) §5.1/§5.4/§6 と脅威表を v0x07 実装に合わせて訂正
- [ ] `CHANGELOG.md` [Unreleased] に v0x06→v0x07 Migration Notes を追記
- [ ] CLI smoke test に新コマンドを追加
