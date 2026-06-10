# S16 キースロット コンテキストノート

## 背景

S15 監査の最大の設計乖離 (High-1): 看板の **ML-KEM-768 が実データ保護で未使用**。
本スプリントで MDK + キースロット封筒に移行し、ML-KEM を真に load-bearing にする。
設計の確定版は **ADR-0009** と **`docs/design/vault-v6-keyslot-format.md`**。

## 公式仕様・ベストプラクティス出典 (実装時に必ず参照)

- **FIPS 203 (ML-KEM)** — NIST 最終版。ek/dk/ct/ss サイズ、カプセル化鍵の入力検証。
  <https://csrc.nist.gov/pubs/fips/203/final>
- **NIST SP 800-227 (KEM 運用推奨)** — 共有秘密からの鍵導出は承認 KDF、鍵確認推奨。
  <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-227.pdf>
- **NIST SP 800-56C** — 鍵導出/コンバイナの承認方式。
- **IETF draft-ounsworth-cfrg-kem-combiners** — `KDF(counter‖K_1‖…‖K_n‖fixedInfo)` の
  ハイブリッド KEM コンバイナ (slot② の K_pw + ss 結合に適用)。
  <https://datatracker.ietf.org/doc/draft-ounsworth-cfrg-kem-combiners/>
- **RFC 5869 (HKDF)** — MDK サブ鍵導出。
- **LUKS2 on-disk format** — 複数キースロットが同一マスター鍵を独立ラップ、削除時
  anti-forensic 消去 (本設計の MDK ローテーション相当)。
  <https://fossies.org/linux/cryptsetup/docs/on-disk-format-luks2.pdf>

## 既存コードの足場 (S15 までに存在)

- `core/src/crypto/kem.rs` — ML-KEM-768 keygen/encaps/decaps (64B シード)。
- `core/src/crypto/kdf.rs` — Argon2id。
- `core/src/crypto/derive_vault_mac_key` — 整合性 MAC 鍵 (v0x06)。**v0x07 で MDK 鍵化**。
- `core/src/vault/format.rs` — `SCHEMA_VERSION=0x06` / `FLAG_INTEGRITY` / `MAX_FIELD_SIZE`。
- `core/src/vault/{reader,writer}.rs` — `write_vault_authenticated*` / 整合性トレーラ。
- HKDF クレートは未導入 → `hkdf` crate (RustCrypto) を追加するか、`hmac` で HKDF を実装。

## 実装 PR 分割指針 (issue と対応)

レビュー粒度を保つため、以下に分割する (各 issue 参照):

1. **S16-1 (core 基盤)**: HKDF サブ鍵 + MDK + slot① password + format v0x07 +
   v0x06→v0x07 移行 + 整合性 MAC の MDK 鍵化。**単一パスワードで現行と機能等価**にする。
2. **S16-2 (core 所有者2要素)**: slot② password+keyfile (ML-KEM コンバイナ) + 鍵ファイル
   形式 + slot④ recovery。
3. **S16-3 (core 共有)**: slot③ recipient + export-pubkey + add/remove + MDK ローテーション。
4. **S16-4 (CLI)**: `vault create --security` / `keyslot *` / `export-pubkey` / unlock の
   鍵ファイル要求 + smoke test。
5. **S16-5 (docs)**: PRD `requirements.md` §5/§6・脅威表の訂正 + CHANGELOG。

依存: S16-1 → (S16-2, S16-3) → S16-4 → S16-5。

## 実装上の注意

- `core/` に UI を入れない (鍵ファイルパス対話・端末出力は cli)。
- 新規 `unsafe` 禁止。秘密は全て zeroize。
- slot② の結合は**固定長・固定順序・ドメイン束縛** (順序曖昧性回避)。
- スロット削除は MDK ローテーション必須 (論理削除だけでは旧資格情報で開けてしまう)。
- 最後のスロット削除は拒否 (ロックアウト防止)。
- 移行はアトミック・非破壊・冪等。
