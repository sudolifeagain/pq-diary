# S10 運用機能 + CLI整合性 スキーマ定義

**作成日**: 2026-05-17
**関連設計**: [architecture.md](architecture.md), [types.rs](types.rs)
**関連要件定義**: [requirements.md](../../spec/s10-operations/requirements.md)

**【信頼性レベル】**: 全項目🔵 (要件定義 + 設計ヒアリング 2026-05-17 + 既存 vault.pqd v4 / vault.toml スキーマで確定済み)

---

## 1. AppConfig (`~/.pq-diary/config.toml`) 🔵

S10 で新規追加。アプリケーション全体の設定。

### TOML スキーマ

```toml
[app]
default_vault = "default"   # 文字列、デフォルト "default"
sync_backend = "git"        # 文字列、デフォルト "git" (将来: "socket", "kms" 等)
```

### ファイルレイアウト

| パス | 内容 |
|---|---|
| `~/.pq-diary/config.toml` | AppConfig (本ファイル) |
| `~/.pq-diary/vaults/` | vault 群の親ディレクトリ (init で作成) |
| `~/.pq-diary/vaults/default/vault.pqd` | デフォルト vault のバイナリ |
| `~/.pq-diary/vaults/default/vault.toml` | デフォルト vault の設定 (VaultConfig) |
| `~/.pq-diary/vaults/default/entries/` | (Phase 1 では空、将来の添付ファイル用) |

### パーミッション 🔵

- Unix: `0o600` (REQ-611)
- Windows: ACL 設定なし (デフォルトのユーザー権限のみ、vault.toml と同等)

### バージョニング戦略 🔵

S10 では `[app]` セクションに `schema_version` フィールドを **入れない**。

**理由**: Phase 1 では config 拡張の頻度が低く、フィールド追加は serde の `#[serde(default)]` で後方互換を取れる。明示的バージョニングは Phase 2 で必要になった時点で導入する。

### サンプル

```toml
# 初期状態 (pq-diary init 直後)
[app]
default_vault = "default"
sync_backend = "git"
```

### 解析エラー時の挙動 🔵

- TOML パースエラー: `DiaryError::Config("Invalid config.toml: {error}")`
- ファイル不在: `DiaryError::Io` (`from_file` の `read_to_string` から発生)
- 不明な `sync_backend`: パース成功するが、`cmd_sync` で `anyhow::bail!("Unknown sync backend: {value}")` (REQ-203)

---

## 2. VaultConfig (`vault.toml`) 既存スキーマ (S10 で変更なし) 🔵

S10 では VaultConfig には変更を加えない。参考までに既存スキーマを記載。

### TOML スキーマ (参考)

```toml
[vault]
name = "default"
schema_version = 4

[access]
policy = "none"   # "none" | "write_only" | "full"

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

詳細は `core/src/vault/config.rs` を参照。

---

## 3. vault.pqd バイナリフォーマット (S10 で変更なし) 🔵

S10 では既存の v4 フォーマットを維持する。change-password 実行時も同じスキーマで再書き出しするだけ。

### v4 ヘッダー (固定長) 🔵

| フィールド | 型 / サイズ | 説明 |
|---|---|---|
| schema_version | u32 (4B) | 4 固定 |
| flags | u32 (4B) | 予約フィールド (現在 0) |
| payload_size | u64 (8B) | エントリペイロード合計バイト数 |
| kdf_salt | [u8; 32] | Argon2id 用ランダムソルト |
| legacy_salt | [u8; 32] | デジタル遺言用ランダムソルト (Phase 2 で使用) |
| verification_iv | [u8; 12] | 検証トークン IV |
| verification_ct | [u8; N] | AES-256-GCM 検証トークン暗号文 |
| kem_pk_offset | [u8; 32] | 予約 (Phase 2 で KEM 公開鍵ストア用) |
| dsa_pk_hash | [u8; 32] | ML-DSA-65 公開鍵の SHA-256 ハッシュ |
| kem_encrypted_sk | Vec<u8> | IV + AES-GCM 暗号化された ML-KEM-768 secret seed |
| dsa_encrypted_sk | Vec<u8> | IV + AES-GCM 暗号化された ML-DSA-65 signing key seed |

### change-password での更新範囲 🔵

| フィールド | 更新? | 理由 |
|---|---|---|
| schema_version | NO | スキーマ変更なし |
| flags | NO | 予約 |
| payload_size | YES (同値) | 再計算するが内容は変わらない |
| **kdf_salt** | **YES** | 新パスワードに対応する Argon2id ソルトを再生成 (旧鍵を派生不可能にするため) |
| legacy_salt | NO | デジタル遺言は別マスター鍵で派生するため変更不要 |
| **verification_iv / verification_ct** | **YES** | 新鍵で再暗号化 |
| kem_pk_offset | NO | 予約 |
| dsa_pk_hash | NO | 公開鍵は不変 |
| **kem_encrypted_sk** | **YES** | 同じ KEM seed を新鍵で再暗号化 |
| **dsa_encrypted_sk** | **YES** | 同じ DSA seed を新鍵で再暗号化 |
| エントリペイロード | YES | 各エントリを新鍵で再暗号化 |

**重要**: KEM/DSA の鍵そのもの (seed) は変更しない。鍵を変えると公開鍵が変わり、過去エントリの署名検証が壊れる。マスター鍵 (Argon2id 出力) の変更のみで、KEM/DSA seed を「暗号化する鍵」が変わるという構造。

### エントリレコード (S10 で変更なし) 🔵

| フィールド | サイズ | 説明 |
|---|---|---|
| record_type | u8 | 0x01 = エントリ, 0x02 = テンプレート (S5 で追加) |
| uuid | [u8; 16] | エントリ UUID v4 |
| created_ts | u64 | UNIX タイムスタンプ (秒) |
| updated_ts | u64 | UNIX タイムスタンプ (秒) |
| iv | [u8; 12] | AES-GCM IV |
| ciphertext_len | u32 | 暗号文長 |
| ciphertext | Vec<u8> | AES-256-GCM 暗号文 (タイトル+タグ+本文をシリアライズ) |
| signature | [u8; 3309] | ML-DSA-65 署名 (S4 で追加) |
| hmac | [u8; 32] | HMAC-SHA256 (S6 で追加) |

---

## 4. export 出力ファイル形式 🔵

### ファイル名 🔵

```
YYYY-MM-DD-{slug}-{id8}.md
```

| 部分 | 値の例 |
|---|---|
| YYYY-MM-DD | エントリの `created_ts` を UTC で日付化 (例: `2026-05-17`) |
| slug | タイトルを `slugify()` で変換 (詳細は types.rs 参照) |
| id8 | UUID の先頭 8 桁 (例: `3c6b775f`) |

例:
- `2026-05-17-今日の出来事-1-3c6b775f.md`
- `2026-04-01-untitled-d65004a8.md` (タイトル空のエントリ)

### ファイル中身 🔵

```markdown
---
id: 3c6b775f-4d8e-4c2b-9a1f-8d5e1f0a2b3c
title: "今日の出来事 #1"
tags:
  - test
  - smoke
created: 2026-05-17T09:23:11Z
updated: 2026-05-17T11:42:03Z
---

ここからエントリ本文。
複数行 OK。

行末や `**Markdown 記法**` もそのまま保持される。
```

### YAML フロントマター仕様 🔵

| キー | 型 | 必須 | 備考 |
|---|---|---|---|
| id | UUID 文字列 | YES | ハイフン付き 36 文字 |
| title | quoted string | YES | 常にダブルクォート、空タイトルは `""` |
| tags | YAML リスト | YES | 空時は `tags: []` (インライン) |
| created | RFC 3339 | YES | UTC タイムゾーン (`Z` サフィックス) |
| updated | RFC 3339 | YES | UTC タイムゾーン |

### YAML エスケープ規則 🔵

文字列値 (title, tags 個別要素) で以下をエスケープ:
- `"` → `\"`
- `\` → `\\`
- 改行 (`\n`) → `\n` (リテラル文字列に変換)
- 制御文字 (U+0000〜U+001F の他) → 削除

### Markdown ボディ 🔵

エントリ本文 (`EntryPlaintext::body`) を **そのままコピー**。再フォーマットや改行統一は行わない (round-trip 保証)。

---

## 5. CLI smoke test スクリプト出力形式 🔵

`ci/smoke-test.sh` / `smoke-test.ps1` が CI で実行され、以下の判定を行う:

### 検証項目

1. `pq-diary --help` の終了コード == 0
2. ヘルプ出力に `legacy` / `daemon` 文字列が含まれない
3. 以下の各サブコマンドの `--help` 終了コード == 0:
   - init, sync, change-password, info, export
   - new, list, show, edit, delete, today, search, stats, import, template
   - vault, git-init, git-push, git-pull, git-sync, git-status
4. 最小 E2E フロー:
   - 一時ディレクトリで `init` → exit 0
   - `new --body "test"` → exit 0
   - `list` 出力に "test" を含む → exit 0
   - `info` exit 0
   - `export ./out` (`y` 入力) → 1 ファイル生成

### 出力スキーマ

```
=== pq-diary smoke test ===
[PASS] pq-diary --help exits 0
[PASS] help does not contain 'legacy'
[PASS] help does not contain 'daemon'
[PASS] init --help exits 0
... (各サブコマンドの help)
[PASS] E2E: init
[PASS] E2E: new entry
[PASS] E2E: list contains entry
[PASS] E2E: info
[PASS] E2E: export creates 1 file

All checks passed (N/N).
```

失敗時は `[FAIL] ...` を stderr に出力し exit ≠ 0。

---

## 関連文書

- **アーキテクチャ**: [architecture.md](architecture.md)
- **データフロー**: [dataflow.md](dataflow.md)
- **型定義**: [types.rs](types.rs)
- **CLI 仕様**: [cli-commands.md](cli-commands.md)
- **要件定義**: [requirements.md](../../spec/s10-operations/requirements.md)
- **vault.pqd 既存フォーマット定義**: `core/src/vault/format.rs`
- **VaultConfig 既存定義**: `core/src/vault/config.rs`

## 信頼性レベルサマリー

- 🔵 青信号: 全項目 (100%)
- 🟡 黄信号: 0 件
- 🔴 赤信号: 0 件

**品質評価**: 最高品質。全スキーマが要件定義 + 設計ヒアリング + 既存 v4 フォーマットで確定済み。
