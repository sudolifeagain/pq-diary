# S3: Vault フォーマット + ストレージ — アーキテクチャ設計

> **スプリント**: S3 (s3-vault-storage)
> **ステータス**: 全項目 DECIDED

---

## 1. システム概要

`vault.rs` モジュールに vault.pqd バイナリフォーマットの読み書きを実装する。
設定ファイル (vault.toml / config.toml) のシリアライズ・デシリアライズも同モジュール内に配置し、
Vault の初期化からエントリの永続化までを一貫して扱う。

S2 で実装済みの `CryptoEngine` (AES-256-GCM, ML-KEM-768, ML-DSA-65, HMAC-SHA256, Argon2id) を暗号プリミティブとして利用し、
S1 で実装済みの `SecureBuffer`, `ZeroizingKey`, `MasterKey`, `DiaryError` をデータ保持・エラー処理の基盤とする。

マルチ Vault 対応として `~/.pq-diary/vaults/{name}/` 以下に vault.pqd + vault.toml + entries/ + .git/ を配置する。

---

## 2. モジュール構成

| ファイル | 責務 |
|---------|------|
| `core/src/vault.rs` | Vault ファイル I/O、バイナリフォーマット、ヘッダ読み書き (モジュールルート) |
| `core/src/vault/format.rs` | vault.pqd v4 バイナリフォーマット定数・構造体定義 |
| `core/src/vault/reader.rs` | vault.pqd 読み込み (ヘッダパース、エントリレコード逐次読み込み) |
| `core/src/vault/writer.rs` | vault.pqd 書き込み (ヘッダ書き出し、エントリレコード逐次書き出し) |
| `core/src/vault/config.rs` | vault.toml / config.toml の serde シリアライズ・デシリアライズ |
| `core/src/vault/init.rs` | Vault 初期化 (ディレクトリ作成、鍵生成、ファイル生成)、VaultManager |

---

## 3. 依存追加 (core/Cargo.toml)

```toml
serde = { version = "1", features = ["derive"] }
toml = "0.8"
uuid = { version = "1", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
```

- `serde` + `toml`: vault.toml / config.toml の構造化読み書き
- `uuid`: エントリレコードの一意識別子 (UUID v4)
- `chrono`: タイムスタンプ処理 (created_at / updated_at)

---

## 4. 主要型

| 型名 | 配置 | 概要 |
|------|------|------|
| `VaultHeader` | `format.rs` | vault.pqd v4 ヘッダ構造体。マジックバイト検証、KDF ソルト、検証トークン、PQ 公開鍵情報を保持 |
| `EntryRecord` | `format.rs` | エントリレコード構造体。UUID、暗号文、署名、HMAC、legacy フィールドを保持 |
| `VaultConfig` | `config.rs` | vault.toml のデシリアライズ先。VaultSection, AccessSection, GitSection, Argon2Section を含む |
| `AppConfig` | `config.rs` | config.toml のデシリアライズ先。DefaultsSection, DaemonSection を含む |
| `VaultManager` | `init.rs` | マルチ Vault 管理。初期化・一覧取得・デフォルト Vault 解決を担当 |

---

## 5. vault.pqd v4 ヘッダレイアウト

| オフセット | サイズ | フィールド |
|-----------|--------|-----------|
| 0 | 8B | マジックバイト `PQDIARY\0` |
| 8 | 1B | スキーマバージョン (`0x04`) |
| 9 | 1B | フラグ |
| 10 | 2B | 予約 (ゼロ埋め) |
| 12 | 4B | ペイロードサイズ (LE u32) |
| 16 | 32B | KDF ソルト |
| 48 | 32B | Legacy ソルト |
| 80 | 12B | 検証トークン IV |
| 92 | 48B | 検証トークン暗号文 (32B 平文 + 16B GCM タグ) |
| 140 | 32B | ML-KEM 公開鍵オフセット |
| 172 | 32B | ML-DSA 公開鍵ハッシュ |
| 204 | 可変 | 秘密鍵ブロック (KEM暗号化SK + DSA暗号化SK) |
| ... | 可変 | エントリセクション |
| ... | 512-4096B | ランダムパディング |

固定ヘッダ部分: 204 バイト

---

## 6. エントリレコードレイアウト

| オフセット (相対) | サイズ | フィールド |
|------------------|--------|-----------|
| 0 | 4B | レコード長 (LE u32) |
| 4 | 16B | UUID |
| 20 | 8B | 作成日時 (Unix timestamp, LE u64) |
| 28 | 8B | 更新日時 (Unix timestamp, LE u64) |
| 36 | 12B | IV (AES-256-GCM) |
| 48 | 4B | 暗号文長 (LE u32) |
| 52 | 可変 | 暗号文 + GCM タグ (16B) |
| ... | 4B | 署名長 (LE u32) |
| ... | 可変 | ML-DSA-65 署名 |
| ... | 32B | HMAC-SHA256 |
| ... | 1B | Legacy フラグ (0x00=DESTROY, 0x01=INHERIT) |
| ... | 4B | Legacy 鍵ブロック長 (LE u32) |
| ... | 可変 | Legacy 鍵ブロック |
| ... | 2B | 添付カウント (LE u16, Phase 2 予約 = 0) |
| ... | 8B | 添付オフセット (LE u64, Phase 2 予約 = 0) |
| ... | 1B | パディング長 |
| ... | 可変 | パディング (ランダム) |

---

## 7. セキュリティ考慮事項

- **メモリ安全性**: 秘密鍵・パスワード派生鍵は `SecureBuffer` / `ZeroizingKey` で保持し、スコープ終了時にゼロクリアする
- **strings 漏洩防止**: バイナリフォーマット内に平文文字列を含めない。メタデータ (Vault 名等) は vault.toml に分離
- **パディングランダム化**: ファイル末尾に 512-4096 バイトのランダムパディングを付与し、エントリ数の推測を困難にする
- **Legacy フィールド初期化**: legacy_flag = 0x00 (DESTROY)、legacy_key_block は空 (長さ 0) で初期化
- **ファイル権限**: vault.pqd は 0o600 (所有者のみ読み書き) で作成
