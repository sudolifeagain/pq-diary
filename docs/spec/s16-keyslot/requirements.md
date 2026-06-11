# S16 キースロット封筒 + Master Data Key 要件定義書

**作成日**: 2026-06-11
**スプリント**: S16
**vault.pqd schema**: v0x06 → **v0x07**

## 概要

監査 (S15) で、看板機能の **ML-KEM-768 が実データ保護経路で未使用**であることが
判明した (High-1)。本スプリントは、ランダムな **Master Data Key (MDK)** を導入し、
MDK を複数の**キースロット**で多重ラップする封筒方式 (age / LUKS2 keyslot / PGP
マルチ受信者と同型) に移行することで、ML-KEM を**実際に load-bearing** にする。

- 所有者は鍵ファイル (ML-KEM 秘密鍵) を**第2要素**にできる (slot②)。
- 相続人・別デバイスの **ML-KEM 公開鍵**に MDK をカプセル化できる (slot③)。
- 設計の詳細は ADR-0009 / `docs/design/vault-v6-keyslot-format.md` を**正**とする。
  本書はそれを EARS 要件・受け入れ基準に落としたもの。

## 関連文書

- **ADR**: [ADR-0009 キースロット封筒 + MDK](../../adr/0009-keyslot-envelope-mdk-v6.md)
- **フォーマット仕様**: [vault-v6-keyslot-format.md](../../design/vault-v6-keyslot-format.md)
- **前提**: [ADR-0008 vault 整合性 MAC (v0x06, S15 実装済)](../../adr/0008-vault-integrity-mac.md)
- **受け入れ基準**: [✅ acceptance-criteria.md](acceptance-criteria.md)
- **コンテキスト/出典**: [📝 note.md](note.md)
- **PRD**: [requirements.md](../../../requirements.md) §5 / Phase 4 (HQC ロードマップ)

## 公式仕様・ベストプラクティスの根拠 (要約)

- **FIPS 203 (ML-KEM)**: ML-KEM-768 は `ek=1184B` / `dk` (RustCrypto は 64B シード保持) /
  `ct=1088B` / **共有秘密 `ss=32B`**。カプセル化鍵 `ek` は**入力検証 (modulus check)** を
  経てから使用する。
- **NIST SP 800-227 (KEM 運用)**: KEM の共有秘密からさらに鍵導出する場合は
  **SP 800-108 / SP 800-56C で承認された KDF** (HKDF-SHA256 / KMAC / SHAKE) を用いる。
  **鍵確認 (key confirmation) を推奨** — 本設計では `wrapped_mdk` の AEAD タグ照合が
  暗黙の鍵確認に相当する。
- **SP 800-56C / IETF draft-ounsworth-cfrg-kem-combiners**: 複数の秘密を束ねる際は
  `KDF(counter ‖ K_1 ‖ … ‖ K_n ‖ fixedInfo)` 形の**コンバイナ**を用い、各入力は
  **固定長・固定順序**とし、`fixedInfo` でドメイン束縛する (順序曖昧性の回避)。
  slot② の `K_pw` と `ss` の結合に適用する。
- **RFC 5869 (HKDF)**: MDK からの用途別サブ鍵導出に使用する。
- **LUKS2**: 各キースロットが**同一のマスター鍵を独立にラップ**し、いずれか 1 つで
  開錠でき、スロット削除時は**anti-forensic に消去**する。本設計の MDK ローテーションは
  これに相当する。

---

## 機能要件 (EARS記法)

**【信頼性レベル凡例】**: 🔵 ADR-0009/仕様/監査に基づく確実な要件 / 🟡 妥当な推測 / 🔴 推測のみ

### REQ-100番台: Master Data Key とサブ鍵階層

- REQ-101: システムは vault 作成時に `OsRng` から 32 バイトの **MDK** を生成し、
  これを全エントリ・添付・テンプレートの実データ暗号化の根としなければならない 🔵
- REQ-102: システムは MDK から **HKDF-SHA256** (RFC 5869) で用途別サブ鍵を導出し、
  鍵を用途間で使い回してはならない (監査 Low-1 解消) 🔵
  - `K_data = HKDF(MDK, "pq-diary/data/v1")` — 本文/添付 AES-256-GCM
  - `K_content_hmac = HKDF(MDK, "pq-diary/content-hmac/v1")` — per-record `content_hmac`
  - `K_vault_integrity = HKDF(MDK, "pq-diary/vault-integrity/v1")` — vault 全体 MAC
- REQ-103: MDK・全サブ鍵は `SecureBuffer`/`Zeroizing`/`SecretBox` で保持し、drop 時に
  zeroize されなければならない。生の `Vec<u8>`/`[u8;32]` を裸で保持してはならない 🔵
- REQ-104: システムは MDK を平文でディスクに書いてはならない。MDK はキースロットで
  ラップされた形でのみ vault.pqd に存在しなければならない 🔵

### REQ-105〜106: メタデータ機密化 (監査 Medium-2 / 旧 PR-F を S16 に統合)

- REQ-105: システムは v0x07 で `created_at`/`updated_at` 等の機密メタデータを**暗号化
  エントリペイロード側**に保持し、平文レコードには残さない (粗いタイムスタンプも残さない)
  ことを目標としなければならない 🟡 *S15 整合性 MAC は改ざんを検知できるが、可読性 (機密性)
  は別問題。要件原則 #8「タイムスタンプ等の機密情報は含めない」に整合させる*
  - 平文に残さざるを得ない構造メタデータ (record_type・各長さ・スロット構造) は整合性
    トレーラ (ADR-0008) で認証されること。
- REQ-106: git last-write-wins マージは `updated_at` を用いるため、暗号化に伴いマージ経路は
  **復号後の `updated_at`** を参照するよう調整しなければならない (sync 時はエンジン unlocked)。
  これにより機密化とマージ整合性を両立する 🟡 *git.rs の現行は平文 updated_at 比較*
  - 注: `content_hmac` の鍵分離 (sym_key 直接 → `K_content_hmac`) は REQ-102 で内包済み。

### REQ-200番台: キースロット (共通)

- REQ-201: 各キースロットは MDK への独立した復元経路を 1 つ提供し、`wrapped_mdk =
  AES-256-GCM(slot_key, MDK)` を保持しなければならない 🔵
- REQ-202: システムは unlock 時、提示された資格情報で開けるスロットを順に試行し、
  最初に `wrapped_mdk` の AEAD 復号 (タグ照合) に成功したスロットの平文を MDK と
  しなければならない。これが暗黙の鍵確認 (SP 800-227) を兼ねる 🔵
- REQ-203: スロットは自己記述的長さ・型タグ・`slot_id` (UUID v4) を持ち、フォーマットは
  `docs/design/vault-v6-keyslot-format.md` §1 に従わなければならない 🔵
- REQ-204: **検証トークン (v4/v5) は廃止**し、パスワード等の正否はスロット復号の成否で
  判定しなければならない 🔵
- REQ-205: 全可変長フィールド (kem_ct/wrapped_mdk/label/slot_len) は既存 `MAX_FIELD_SIZE`
  (16 MiB) 上限を適用し、巨大 alloc DoS を防がなければならない 🔵

### REQ-210番台: slot① password

- REQ-211: `password` スロットの `slot_key` は `Argon2id(password, slot.salt, slot.kdf_params)`
  でなければならない。salt はスロット毎に `OsRng` で生成する 🔵
- REQ-212: Argon2id パラメータは既存 `validate_params` の最低保証値を満たし、各スロットの
  メタデータに記録しなければならない 🔵

### REQ-220番台: slot② password+keyfile (所有者の第2要素・ML-KEM)

- REQ-221: システムは `keyslot add-keyfile` (および `--security high` での vault 作成) 時、
  **ML-KEM-768 鍵ペアを生成**し、復号鍵シード (64B) を**鍵ファイル**に書き出さなければ
  ならない 🔵
- REQ-222: 鍵ファイルは `docs/design/vault-v6-keyslot-format.md` §4 の形式 (magic +
  ML-KEM 秘密鍵シード + 公開鍵 SHA-256 + CRC32) で、Unix 0600 / Windows owner-only ACL で
  保存し、メモリ上は `SecureBuffer` で zeroize しなければならない 🔵
- REQ-223: システムは生成した `ek` に自分でカプセル化 (`encaps(ek) → (kem_ct, ss)`) し、
  `kem_ct` をスロットに格納しなければならない。unlock 時は `decaps(keyfile_dk, kem_ct) → ss` で
  同じ `ss` を回復する 🔵
- REQ-224: slot② の `slot_key` は **SP 800-56C / IETF コンバイナ形**で導出しなければならない:
  `slot_key = HKDF-SHA256(IKM = K_pw ‖ ss, info = "pq-diary/keyslot/keyfile/v1" ‖ slot_id)`。
  ここで `K_pw = Argon2id(password, slot.salt)`、`K_pw` と `ss` はともに固定 32B・固定順序で
  連結する。**パスワードと鍵ファイルの両方**が揃わなければ `slot_key` を再現できない 🔵
- REQ-225: システムは `keyslot add-keyfile` 実行時、鍵ファイルを vault.pqd と**別の場所で
  保管する**よう警告を表示しなければならない (同一同期に乗せると第2要素として無意味) 🔵
- REQ-226: 鍵ファイル単体 (パスワードなし) では vault を開けてはならない (REQ-224 の束縛による) 🔵

### REQ-230番台: slot③ recipient (相続人・別デバイス共有・ML-KEM)

- REQ-231: システムは `keyslot add-recipient <PUBKEY>` で、与えられた ML-KEM-768 公開鍵 `ek`
  に対し `encaps(ek) → (kem_ct, ss)` し、`slot_key = HKDF-SHA256(ss,
  "pq-diary/keyslot/recipient/v1" ‖ slot_id)` で MDK をラップしたスロットを追加しなければ
  ならない 🔵
- REQ-232: システムは受信者公開鍵 `ek` を**使用前に FIPS 203 の入力検証**にかけ、不正な
  公開鍵を拒否しなければならない 🔵
- REQ-233: システムは `export-pubkey` で、自身の (鍵ファイル由来の) ML-KEM 公開鍵を
  他デバイス/相続人が `add-recipient` に渡せる形式で出力しなければならない 🟡
- REQ-234: recipient スロット追加は **MDK の再ラップのみ**で完了し、全エントリ本文の
  再暗号化を伴ってはならない 🔵

### REQ-240番台: slot④ recovery (オフライン復旧コード)

- REQ-241: システムは `--security high` 作成時および `keyslot add-recovery` 時、256bit の
  `OsRng` 乱数を **Crockford Base32** でグループ表示した復旧コードを生成し、`slot_key =
  Argon2id(recovery_code, slot.salt)` で MDK をラップしたスロットを追加しなければならない 🔵
- REQ-242: 復旧コードは**生成時に一度だけ** stderr に表示し、平文では一切保存しては
  ならない 🔵

### REQ-300番台: スロット管理

- REQ-301: システムは `keyslot list` で、各スロットの `slot_id`・型 (password/keyfile/
  recipient/recovery)・任意ラベルを表示しなければならない。秘密値は表示してはならない 🔵
- REQ-302: システムは `keyslot remove <SLOT_ID>` でスロットを削除できなければならない。
  ただし**最後の 1 スロットの削除は拒否**し、vault を開けなくする事故を防がなければならない 🔵
- REQ-303: スロット削除 (失効) は MDK の機密性を回復するため、**新 MDK へローテーション**
  (全エントリ/添付の再暗号化 + 残存スロットの再ラップ) を行わなければならない。これにより
  削除されたスロットの資格情報では新 vault を開けなくなる (LUKS2 anti-forensic 相当) 🔵
- REQ-304: スロット追加/削除/ローテーションはアトミック (`.tmp` + rename) で行い、失敗時は
  旧 vault.pqd を維持しなければならない (既存 write_vault パターン踏襲) 🔵

### REQ-400番台: 設定式セキュリティモード

- REQ-401: システムは `vault create --security <high|convenience>` を受け付けなければ
  ならない。指定なしの既定は `convenience` とする 🟡
- REQ-402: `convenience` モードは slot① (password) のみを作成しなければならない 🔵
- REQ-403: `high` モードは slot② (password+keyfile) と slot④ (recovery) を作成し、
  **password 単独スロット (slot①) を作成してはならない** (鍵ファイル必須) 🔵
- REQ-404: システムは選択モードを `vault.toml` に記録してよいが、これは UX ヒントに留め、
  真のセキュリティ保証は**ディスク上に実在するスロット集合**で担保しなければならない 🔵

### REQ-500番台: unlock フロー

- REQ-501: システムは v0x07 vault の unlock 時、必要に応じて鍵ファイル (slot②) のパスを
  `--keyfile <PATH>` または対話で要求しなければならない 🟡
- REQ-502: システムは MDK 回復**直後・全レコード読込前**に、`K_vault_integrity` で
  vault 整合性トレーラ (ADR-0008) を検証しなければならない。失敗時は `DiaryError::Crypto` を
  返し、エンジンを unlocked にしてはならない 🔵
- REQ-503: いずれのスロットでも MDK を回復できない場合、システムは
  `DiaryError::Crypto("invalid credentials")` 相当を返さなければならない 🔵

### REQ-600番台: 移行 (v0x06 → v0x07)

- REQ-601: reader は schema `0x04..=0x07` を受理しなければならない。v4/v5 は従来パス
  (sym_key 直接)、v6 は sym_key + 整合性トレーラ、v7 は MDK + キースロットで読む 🔵
- REQ-602: 書込は常に v0x07 とする。既存 vault の**初回書込時**に、MDK 生成 → 全エントリ/
  添付を `K_data` で再暗号化 → `content_hmac` を `K_content_hmac` で再計算 → 既定で
  `password` スロット 1 個を作成 → `K_vault_integrity` でトレーラ再計算、を行い v0x07 へ
  移行しなければならない 🔵
- REQ-603: 移行は**冪等**かつ**非破壊**でなければならない (アトミック書込、失敗時は旧 vault 維持)。
  移行後、移行前のパスワードで引き続き開けなければならない 🔵
- REQ-604: 整合性 MAC 鍵を `derive_vault_mac_key(sym_key)` から `HKDF(MDK,
  "pq-diary/vault-integrity/v1")` へ移行しなければならない (ADR-0008 を MDK 鍵化) 🔵

### REQ-700番台: CLI コマンド

- REQ-701: システムは以下のコマンドを提供しなければならない 🟡
  - `vault create --security <high|convenience> [--keyfile <PATH>]`
  - `keyslot list`
  - `keyslot add-keyfile [--keyfile <PATH>]`
  - `keyslot add-recipient <PUBKEY>`
  - `keyslot add-recovery`
  - `keyslot remove <SLOT_ID>`
  - `export-pubkey`
- REQ-702: `keyslot` / `export-pubkey` 系コマンドは vault の master 資格情報を要し、
  `--claude` 起動時は**全て拒否**しなければならない (S10/S12 と同じ規則) 🔵
- REQ-703: CLI smoke test に新コマンドの `--help` と正常終了を追加しなければならない (DoD) 🔵

### REQ-800番台: HQC 将来拡張 (設計予約のみ・本スプリント非実装)

- REQ-801: スロットの `kem_alg` フィールドは将来の `0x02 (ML-KEM-768 + HQC ハイブリッド)` を
  受理できる拡張余地を持たなければならない。**HQC 標準化後に schema bump 不要**でスロット
  種別追加として対応できること 🟡

---

## 非機能要件

### パフォーマンス

- NFR-001: unlock の追加コスト (スロット試行 + KEM decaps) は既存 Argon2id コストに対し
  無視できる範囲 (< 50ms 追加) でなければならない 🟡 *ML-KEM は数十µs*
- NFR-002: スロット追加 (recipient/keyfile) は MDK 再ラップのみで完了し、本文再暗号化を
  伴わないこと (REQ-234) 🔵
- NFR-003: v0x06→v0x07 移行 (全再暗号化) は 1000 エントリで 30 秒以内でなければならない 🟡

### セキュリティ

- NFR-101: ML-KEM の共有秘密からの鍵導出は SP 800-56C 承認 KDF (HKDF-SHA256) のみを
  用いなければならない 🔵
- NFR-102: slot② は SP 800-56C/IETF コンバイナ形で `K_pw` と `ss` を固定長・固定順序・
  ドメイン束縛付きで結合し、片方のみでは復号不能でなければならない 🔵
- NFR-103: 受信者公開鍵は FIPS 203 入力検証を通さなければ使用してはならない 🔵
- NFR-104: スロット削除時は MDK ローテーションにより旧資格情報での復号を不能にしなければ
  ならない 🔵

### 互換性

- NFR-201: 既存 v4/v5/v6 vault は読み取り可能で、初回書込で v0x07 へ自動移行しなければ
  ならない (REQ-601〜603) 🔵

---

## 制約要件

- REQ-901: 暗号アルゴリズムは既存スタック (ML-KEM-768 / AES-256-GCM / Argon2id /
  HKDF-SHA256 / HMAC-SHA256) を用い、新規プリミティブを導入してはならない 🔵
- REQ-902: `core/` にプラットフォーム依存 UI コード (鍵ファイルパス対話・端末出力) を
  入れてはならない。鍵スロットの暗号ロジックは `core`、対話/パス解決は `cli` に置く 🔵
- REQ-903: 新規 `unsafe` を追加してはならない (CLAUDE.md の許可リスト外) 🔵
- REQ-904: 復旧コード・鍵ファイル・パスワード・MDK・各 slot_key・ss は全て zeroize 対象と
  しなければならない 🔵

---

## セキュリティ不変条件 (実装時チェック)

- [ ] MDK・サブ鍵・slot_key・ss・K_pw が drop で zeroize される
- [ ] 鍵分離: 暗号鍵 (`K_data`) と MAC 鍵 (`K_content_hmac`/`K_vault_integrity`) が別サブ鍵
- [ ] slot② は password と keyfile の両方が必要 (片方では不能)
- [ ] 受信者公開鍵の FIPS 203 入力検証あり
- [ ] スロット削除で MDK ローテーション (旧資格情報で開けないこと)
- [ ] 最後のスロット削除を拒否 (ロックアウト防止)
- [ ] 移行はアトミック・非破壊・冪等
- [ ] 整合性トレーラ検証が MDK 回復直後・全レコード読込前
- [ ] `--claude` で keyslot 系コマンド全拒否
- [ ] ディスクに平文 (MDK/復旧コード/鍵シード) を書かない
