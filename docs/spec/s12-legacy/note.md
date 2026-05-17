# S12 デジタル遺言 (legacy) - Context Note

## Tech Stack

- Rust 2021、core/ + cli/、Argon2id、AES-256-GCM、ML-KEM-768、ML-DSA-65、zeroize、secrecy

## PRD §7 サマリー

| 用語 | 定義 |
|---|---|
| INHERIT | 死後アクセスコードで復号可能なエントリ (フラグ 0x01) |
| DESTROY | 死後アクセスコード実行時に即座に消去されるエントリ (フラグ 0x00、デフォルト) |
| K_master | マスターパスワード → Argon2id → 対称鍵 |
| K_legacy | 死後アクセスコード → Argon2id (Legacy ソルト) → 対称鍵 |
| legacyブロック | INHERIT エントリの平文 JSON を K_legacy で暗号化した追加ブロック |

## 既存実装の土台 (S3 で予約済み)

### vault.pqd v4 ヘッダー (`core/src/vault/format.rs`)
- `kdf_salt: [u8; 32]` (K_master 用、既に使用中)
- **`legacy_salt: [u8; 32]`** (K_legacy 用、予約済み・S12 で使用開始)

### エントリレコード
```
[1B: legacyフラグ  0x00=DESTROY / 0x01=INHERIT]   ← S3 予約、Phase 1 では常に 0x00
[4B: legacy鍵ブロック長 (0ならDESTROY)]            ← S3 予約
[legacyブロック (INHERITの場合のみ)]              ← S3 予約、INHERIT 時はエントリ平文 JSON を K_legacy で暗号化
[1B: パディング長]
[パディング]
```

S3 で予約済みなので、S12 ではフォーマット変更不要 (Phase 1 vault との後方互換維持)。

### CLI スケルトン (cli/src/main.rs、S10 で hide 化済み)
- `Commands::Legacy { subcommand: LegacyCommands }` with Init/Rotate/Set/List
- `Commands::LegacyAccess`
- 現状全て `not_implemented("legacy ..", "Phase 2")` を返す
- S12 で実装 → hide を解除

## 設計判断 (2026-05-17 ヒアリング)

| # | 項目 | 確定内容 |
|---|---|---|
| 1 | **OQ-18** legacy-access 後の新 vault 暗号鍵 | K_legacy を通常 master key として残留 (骨梧者が継続利用可、シンプル) |
| 2 | **legacy rotate** の挙動 | 全 INHERIT エントリを即時再暗号化 (vault.pqd アトミック書き換え) |
| 3 | **死後アクセスコード強度** | K_master と同じ Argon2 パラメータ + TTY 2 回入力 |
| 4 | **legacy-access 確認方式** | ユーザー選択可能 (timer30 / yn / phrase)、`legacy init` で設定し `vault.toml [legacy]` に保存 |
| 5 | **デフォルト確認方式** | `timer30` (30 秒タイマー + y/N) |
| 6 | **--claude 扱い** | `legacy*` / `legacy-access` 全て完全ブロック |
| 7 | **Shamir 拡張余地** | K_legacy 導出関数を trait 化、将来 Shamir's Secret Sharing (Phase 3) を差し込み可能 |

## 関連ファイル

- `requirements.md` v4.0 §7 (デジタル遺言、5-9 行)
- `core/src/vault/format.rs`: legacy_salt 予約フィールド
- `core/src/vault/reader.rs` / `writer.rs`: エントリのフラグ + 鍵ブロック読み書き (S3 で予約)
- `core/src/vault/init.rs::VaultManager::init_vault`: legacy_salt をランダム生成済み
- `core/src/vault/config.rs::VaultConfig`: `[legacy]` セクション追加先
- `core/src/crypto/kdf.rs`: Argon2id 共通 (K_legacy 導出に再利用)
- `core/src/crypto/aead.rs`: AES-GCM (legacy ブロック暗号化に再利用)
- `core/src/entry.rs`: entry CRUD (legacy フラグ書き込みパス追加先)
- `cli/src/main.rs`: Commands::Legacy / LegacyAccess (S10 で hide 化済み、S12 で unhide)
- `cli/src/commands.rs`: cmd_legacy_* 実装先
- `cli/src/password.rs::prompt_password(prompt)`: S10 hotfix で追加、死後アクセスコード入力に再利用可

## 開発ルール (CLAUDE.md)

- `unsafe` 新規追加禁止 (既存許可リストのみ)
- 秘密データ (K_legacy, 死後アクセスコード, legacy ブロック復号後のエントリ平文) は `Zeroizing` / `SecretString` / `SecretBytes`
- core/ にプラットフォーム依存 UI コード禁止
- エラーは `thiserror::DiaryError`

## Phase 3 への持ち越し

- Shamir's Secret Sharing による死後アクセスコード分散保持 (M-of-N 復元)
- legacy-access 後の新 vault の長期保管戦略 (cold storage, etc.)
- 法的有効性 (国別の electronic will 規制との整合)

## 注意事項

- S12 は **設計フェーズ Spike**。実装スプリント (S12 の TASK-XXXX 群) は別途切り出す
- vault.pqd フォーマットは S3 予約済みなので、後方互換性を維持できる
- 既存の Phase 1 vault は全エントリ `legacyフラグ = 0x00` (DESTROY) で正しく扱える
