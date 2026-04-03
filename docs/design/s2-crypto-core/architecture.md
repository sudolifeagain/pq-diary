# アーキテクチャ設計: s2-crypto-core

| 項目 | 値 |
|------|-----|
| 要件名 | s2-crypto-core (Sprint 2 — 暗号コア) |
| 日付 | 2026-04-03 |
| ステータス | 確定 |

---

## 1. システム概要

S1で単一ファイルとして実装されたcrypto.rsをサブモジュール構成に展開し、以下の6つの暗号アルゴリズムを実装する。

- **Argon2id**: パスワードベース鍵導出
- **AES-256-GCM**: 認証付き暗号化/復号
- **ML-KEM-768**: 耐量子鍵カプセル化メカニズム
- **ML-DSA-65**: 耐量子デジタル署名
- **HMAC-SHA256**: メッセージ認証コード
- **検証トークン**: パスワード正当性の簡易チェック

**信頼性**: 🔵 確定

---

## 2. サブモジュール構成

| モジュール | 責務 | 依存クレート |
|-----------|------|-------------|
| crypto/mod.rs | CryptoEngine実装、公開API | - |
| crypto/secure_mem.rs | SecureBuffer, ZeroizingKey, MasterKey (S1から移動) | zeroize, secrecy |
| crypto/kdf.rs | Argon2id鍵導出、パラメータ検証 | argon2 |
| crypto/aead.rs | AES-256-GCM暗号化/復号 | aes-gcm |
| crypto/kem.rs | ML-KEM-768カプセル化/脱カプセル化 | ml-kem (フォーク) |
| crypto/dsa.rs | ML-DSA-65署名/検証 | ml-dsa (フォーク) |
| crypto/hmac_util.rs | HMAC-SHA256 | hmac, sha2 |

**信頼性**: 🔵 確定

---

## 3. 依存クレート (core/Cargo.toml への追加)

```toml
argon2 = "0.5"
aes-gcm = "0.10"
ml-kem = { git = "https://github.com/sudolifeagain/ml-kem", branch = "pq-diary" }
ml-dsa = { git = "https://github.com/sudolifeagain/ml-dsa", branch = "pq-diary" }
hmac = "0.12"
sha2 = "0.10"
rand = "0.8"
```

**PQCフォークについて**:
- **ml-dsa**: s1_hat/s2_hat/t0_hat/A_hat に対するzeroize追加、およびCVE-2026-22705パッチ適用
- **ml-kem**: DecapsulationKey に対するzeroize補完

**信頼性**: 🔵 確定

---

## 4. CryptoEngine 実装設計

CryptoEngineはS1で定義済みの`Option<Secret<MasterKey>>`を内部に保持し、暗号操作の統一的なエントリポイントとして機能する。

### 4.1 ライフサイクル管理

| メソッド | 説明 |
|---------|------|
| `unlock(password, salt, verification_token)` | Argon2idで鍵導出 → 検証トークンをAES-GCMで復号し一致確認 → MasterKeyをSecret<>で保持 |
| `lock()` | master_key.take() + zeroize による安全な鍵消去 |

### 4.2 対称暗号 (AES-256-GCM)

| メソッド | 説明 |
|---------|------|
| `encrypt(plaintext)` | ランダムnonce(12B)生成 → AES-256-GCM暗号化 → (nonce, ciphertext) を返却 |
| `decrypt(nonce, ciphertext)` | AES-256-GCM復号 → plaintext を返却 |

### 4.3 鍵カプセル化 (ML-KEM-768)

| メソッド | 説明 |
|---------|------|
| `kem_keygen()` | ML-KEM-768鍵ペア生成 |
| `kem_encapsulate(pk)` | 公開鍵でカプセル化 → (ciphertext, shared_secret) |
| `kem_decapsulate(sk, ct)` | 秘密鍵で脱カプセル化 → shared_secret |

### 4.4 デジタル署名 (ML-DSA-65)

| メソッド | 説明 |
|---------|------|
| `dsa_keygen()` | ML-DSA-65鍵ペア生成 |
| `dsa_sign(sk, msg)` | 秘密鍵でメッセージに署名 → signature |
| `dsa_verify(pk, msg, sig)` | 公開鍵で署名検証 → bool |

### 4.5 メッセージ認証 (HMAC-SHA256)

| メソッド | 説明 |
|---------|------|
| `hmac(key, data)` | HMAC-SHA256を計算 → [u8; 32] |
| `hmac_verify(key, data, mac)` | HMAC-SHA256を検証 → bool |

**信頼性**: 🔵 確定

---

## 5. セキュリティ制約

| 制約 | 詳細 |
|------|------|
| 秘密鍵の保護 | 全秘密鍵はSecureBuffer/ZeroizingKeyで保持し、スコープ離脱時にzeroize |
| Nonce再利用禁止 | 全NonceはOsRngによるランダム12バイト生成。再利用を構造的に防止 |
| Argon2id最低保証値 | memory_cost_kb >= 19456、time_cost >= 2 を下回る場合は警告ログを出力 |
| 検証トークン | 32バイトランダム平文をK_masterでAES-GCM暗号化。unlock時に復号して一致確認 |

**信頼性**: 🔵 確定

---

## 6. パフォーマンス

| 操作 | 目標レイテンシ | 備考 |
|------|---------------|------|
| unlock (Argon2id鍵導出) | 1〜3秒 | memory_cost_kb=65536, time_cost=3, parallelism=4 |

**信頼性**: 🔵 確定

---

## 7. 技術的制約

| 制約 | 詳細 |
|------|------|
| unsafe使用制限 | テストコードのzeroize検証のみに限定。プロダクションコードではunsafe禁止 |
| PQCフォーク依存 | ml-kem/ml-dsaはgit依存として管理。crates.ioからは取得しない |
| S1との互換 | SecureBuffer, ZeroizingKey, MasterKey, CryptoEngineはS1の定義を維持しつつ拡張 |

**信頼性**: 🔵 確定

---

## 信頼性サマリー

| セクション | 信頼性 |
|-----------|--------|
| 1. システム概要 | 🔵 確定 |
| 2. サブモジュール構成 | 🔵 確定 |
| 3. 依存クレート | 🔵 確定 |
| 4. CryptoEngine実装設計 | 🔵 確定 |
| 5. セキュリティ制約 | 🔵 確定 |
| 6. パフォーマンス | 🔵 確定 |
| 7. 技術的制約 | 🔵 確定 |

**全体信頼性**: 🔵 100%
