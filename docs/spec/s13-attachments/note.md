# S13 添付ファイル コンテキストノート

**作成日**: 2026-05-18
**スプリント**: S13 — 添付ファイル機能 (Phase 2)

## スプリントの目的

vault.pqd v4 で予約済みの `attachment_count` (u16) / `attachment_offset` (u64)
を本実装し、画像・PDF・小〜中サイズのバイナリをエントリに紐付けて
暗号化保存できるようにする。Obsidian の attachments フォルダ運用との
往復インポート/エクスポートをサポート。

## 技術スタック (既存基盤を流用)

- **暗号**: AES-256-GCM (chunk 単位) + ML-DSA-65 (全体署名) + HMAC-SHA256 (整合性)
- **ストレージ**: `<vault_dir>/.attachments/<file_uuid>.bin` (本体)
  + vault.pqd 内の attachment レコード (メタデータ)
- **エディタ統合**: `pq-diary new --attach FILE` で新規エントリと同時添付、
  `pq-diary attachment add ENTRY_ID FILE` で既存エントリに追加
- **依存**: 既存 `core/src/crypto/aead.rs`、新規 chunk streaming layer

## 既存実装の関連箇所

| ファイル | 関連内容 |
|---|---|
| `core/src/vault/format.rs` | `EntryRecord.attachment_count: u16` + `attachment_offset: u64` 既存予約 |
| `core/src/vault/reader.rs` | attachment フィールド read 済み (使われていない) |
| `core/src/vault/writer.rs` | attachment フィールド write 済み (常に 0) |
| `core/src/entry.rs::create_entry` | `attachment_count=0, attachment_offset=0` でハードコード |
| `core/src/legacy.rs` | INHERIT/DESTROY 連動が必要 — `attachment set --inherit/--destroy` |
| `core/src/importer.rs` | Obsidian import 拡張点 |
| `cli/src/commands.rs::cmd_export` | export 拡張点 (`<DIR>/attachments/`) |

## 設計の核心 (確定 + 仮確定)

### 確定 (ヒアリング)
1. **サイズ上限**: 1 ファイル 1GB (1MB chunk のストリーミング暗号化)
2. **ストレージ**: vault.pqd は メタデータのみ、本体は `.attachments/<uuid>.bin`
3. **legacy 連動**: ファイル個別の INHERIT/DESTROY フラグ
4. **export/import**: 双方向 Obsidian 互換 (`![[file.png]]` リンク復元)

### 仮確定 (設計で🟡として明示、PR review で確認)
5. **chunk size**: 1MB (AES-GCM の IV 衝突確率と 1 chunk RAM 使用量のバランス)
6. **レコードタイプ**: `RECORD_TYPE_ATTACHMENT = 0x03` を新設 (entry/template と並列)
7. **chunk IV 衝突回避**: chunk index を AAD に含める (chunk 0..N で IV 再利用しても安全)
8. **アトミック書き込み**: `.bin.tmp` → rename。失敗時 zeroize 上書き → 削除
9. **添付メタデータの保存場所**: vault.pqd の attachment レコード (新タイプ 0x03)、entry record の `attachment_offset` がレコード群の起点を指す

## 開発ルール (CLAUDE.md より)

- `unsafe` は許可リスト (mlock 等) のみ
- 秘密データは `zeroize` / `SecretString` / `SecretBytes`
- `unwrap()` / `expect()` はテストコードのみ
- エラーは `thiserror` (core) / `anyhow` (cli)
- プラットフォーム分岐は `#[cfg()]`
- テストは `#[cfg(test)] mod tests` で同居

## 注意事項

- **1GB chunk 処理**: メモリに全体を載せない設計 (Read trait + Write trait のストリーム)
- **ML-DSA-65 署名対象**: 添付全体の SHA-256 (chunk ごとに署名するとサイズ爆発)
- **legacy 連動**: attachment レコードも `legacy_flag` + `legacy_key_block`
  を持つ。S12 と同じパターン。
- **テンプレートには添付不可**: テンプレートは構造化テキスト、添付は entry 限定
- **import の挙動**: 同名ファイル既存時の処理 (rename / skip / overwrite) を要設計
- **.attachments/ ディレクトリの git 同期**: git add 対象、暗号化済みなので問題なし

## Tsumiki ワークフロー位置

| ステップ | 状態 |
|---|---|
| kairo-requirements | 本ノート + requirements.md + user-stories.md + acceptance-criteria.md |
| kairo-design | architecture.md + dataflow.md + types.rs + schema.md + cli-commands.md |
| kairo-tasks | 実装スプリント開始時 |
| kairo-implement | 実装スプリント (S13-impl ブランチ) |

## 関連

- 要件: [requirements.md](requirements.md)
- ストーリー: [user-stories.md](user-stories.md)
- 受け入れ基準: [acceptance-criteria.md](acceptance-criteria.md)
- ヒアリング: [interview-record.md](interview-record.md)
- 設計: [../../design/s13-attachments/architecture.md](../../design/s13-attachments/architecture.md)
- PRD: [requirements.md (project root)](../../../requirements.md) §10 / Phase 2
- backlog: [../../backlog.md](../../backlog.md) Phase 2 item

## 信頼性

- 🔵: 既存予約フィールド (`attachment_count` / `attachment_offset`) 活用、
       Obsidian `![[file.png]]` 記法、AES-256-GCM 流用
- 🟡: chunk size 1MB、RECORD_TYPE_ATTACHMENT=0x03、.attachments/ ディレクトリ構造、
       添付メタデータ構造 (filename/MIME/sha256/size)
- 🔴: なし
