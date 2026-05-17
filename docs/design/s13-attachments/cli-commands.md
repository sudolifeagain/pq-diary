# S13 添付ファイル CLI コマンド仕様

**作成日**: 2026-05-18
**関連設計**: [architecture.md](architecture.md), [schema.md](schema.md)
**信頼性**: 全項目 🟡 (PRD §10 明示なし、設計判断)

---

## サブコマンド一覧 (S13 で実装)

### 1. `pq-diary attachment add <ENTRY_ID> <FILE>` 🟡

**説明**: エントリに任意のバイナリファイルを暗号化添付する。

**clap**:
```rust
AttachmentCommands::Add {
    entry: String,        // ID プレフィックス
    path: PathBuf,        // 添付するファイル
}
```

**動作**:
1. `--claude` チェック → ブロック
2. ファイル存在チェック (`path.is_file()`)
3. ファイルサイズチェック (`size <= 1GB`、超過なら `InvalidArgument`)
4. master password 取得 + unlock
5. ID プレフィックスでエントリ検索
6. 1 エントリの attachment_count が 255 → `InvalidArgument` (上限)
7. 同名ファイル既存チェック:
   - SHA-256 一致 → 重複排除、`.bin` 書き込みスキップ、メタデータレコードのみ追加
   - SHA-256 不一致 → `InvalidArgument` (rename を促す)
8. `<vault_dir>/.attachments/<file_uuid>.bin.tmp` を作成
9. `streaming::encrypt_stream(K_master, file_uuid, src, tmp)` で chunk 暗号化
   - 同時に SHA-256 計算
10. MIME type を `mime_guess` で判定
11. `AttachmentRecord` を組み立て、HMAC + ML-DSA 署名
12. vault.pqd に attachment レコード追加、entry の `attachment_count++`
13. アトミック書き込み → `.bin.tmp` を `.bin` に rename
14. メッセージ: `Added: <filename> (size_kb KB, mime <type>) → <entry_prefix>`

**出力サンプル**:
```
$ pq-diary attachment add 3c6b ~/photo.jpg
Master password: ***
Encrypting 1024 KB (1 chunks)...
Added: photo.jpg (1024 KB, mime image/jpeg) → 3c6b775f
```

**異常系**:
- ファイル不存在: `Error: file not found: ~/photo.jpg`
- 1GB 超: `Error: file size 1.2 GB exceeds the 1 GB limit`
- ID 不一致: `Error: no entry matches prefix '3c6b'`
- 256 個目: `Error: maximum 256 attachments per entry`

---

### 2. `pq-diary attachment list [<ENTRY_ID>]` 🟡

**説明**: エントリ (省略時は vault 全体) の添付一覧を表示する。

**clap**:
```rust
AttachmentCommands::List {
    entry: Option<String>,  // ID プレフィックス、省略可
}
```

**動作**:
1. `--claude` チェック: access policy が `full` なら許可、それ以外ブロック
2. master + unlock
3. attachment レコード全件取得
4. entry プレフィックス指定があれば filter
5. テーブル表示 (sortは updated_at 降順):

```
$ pq-diary attachment list 3c6b
ENTRY     FILE                SIZE     ADDED       FLAG     SHA256
3c6b775f  photo.jpg           1.5 MB   2026-05-18  INHERIT  ab12...
3c6b775f  receipt.pdf         234 KB   2026-04-30  DESTROY  cd34...

Summary: 2 attachments in entry 3c6b775f
```

`pq-diary attachment list` (ID 省略時):
```
ENTRY     FILE                SIZE     ADDED       FLAG     SHA256
3c6b775f  photo.jpg           1.5 MB   2026-05-18  INHERIT  ab12...
08a9e139  letter.pdf          50 KB    2026-04-30  INHERIT  ef56...

Summary: 2 attachments across 2 entries
```

---

### 3. `pq-diary attachment extract <ENTRY_ID> <FILE_NAME> --out <PATH>` 🟡

**説明**: 添付を復号して `<PATH>` に書き出す。

**clap**:
```rust
AttachmentCommands::Extract {
    entry: String,
    filename: String,
    #[arg(long)]
    out: PathBuf,
}
```

**動作**:
1. `--claude` チェック → ブロック
2. master + unlock
3. entry + filename で AttachmentRecord 検索 (unique 前提)
4. `<vault_dir>/.attachments/<file_uuid>.bin` を開く
5. `<out>.tmp` を作成
6. `streaming::decrypt_stream(K_master, file_uuid, size, sha256, src, tmp)` で復号
   - chunk ごとの AAD 検証
   - 全 chunk 完了後の SHA-256 検証
7. `<out>.tmp` を `<out>` に rename (アトミック)
8. メッセージ: `Extracted: <filename> (size KB) → <out>; SHA-256 verified.`

**出力サンプル**:
```
$ pq-diary attachment extract 3c6b photo.jpg --out /tmp/p.jpg
Master password: ***
Decrypting 1.5 MB (2 chunks)...
Extracted: photo.jpg (1.5 MB) → /tmp/p.jpg; SHA-256 verified.
```

**異常系**:
- 添付不存在: `Error: attachment 'photo.jpg' not found in entry 3c6b`
- AEAD tag mismatch: `Error: attachment is corrupted or tampered (chunk 5)`
- SHA-256 mismatch: `Error: attachment integrity check failed (sha256 mismatch)`
- `<out>` 書き込み不可: `Error: cannot write to /tmp/p.jpg: permission denied`

---

### 4. `pq-diary attachment delete <ENTRY_ID> <FILE_NAME> [--force]` 🟡

**説明**: 添付メタデータと本体ファイルを削除する (本体は zeroize 上書き)。

**clap**:
```rust
AttachmentCommands::Delete {
    entry: String,
    filename: String,
    #[arg(long)]
    force: bool,
}
```

**動作**:
1. `--claude` チェック → ブロック
2. `--force` でなければ確認 prompt (`Delete 'photo.jpg' from entry 3c6b? [y/N]:`)
3. master + unlock
4. AttachmentRecord 検索
5. `.attachments/<uuid>.bin` を zeroize 上書き → ファイル削除
6. vault.pqd から AttachmentRecord を削除、entry の `attachment_count--`
7. アトミック書き込み
8. メッセージ: `Deleted: photo.jpg (size_kb KB)`

---

### 5. `pq-diary attachment set <ENTRY_ID> <FILE_NAME> --inherit | --destroy` 🟡

**説明**: 添付個別の legacy フラグを設定する (S12 連動)。

**clap**:
```rust
AttachmentCommands::Set {
    entry: String,
    filename: String,
    #[arg(long, conflicts_with = "destroy")]
    inherit: bool,
    #[arg(long, conflicts_with = "inherit")]
    destroy: bool,
}
```

**動作**:
1. `--claude` チェック → ブロック
2. vault.toml の `[legacy] initialized = true` チェック → false なら `legacy init を先に実行`
3. master + unlock
4. `--inherit` なら legacy code も取得
5. AttachmentRecord 検索
6. flag 変更:
   - `--inherit`: legacy_flag = 0x01、legacy_key_block = AES-GCM(K_legacy, K_master_subkey)
   - `--destroy`: legacy_flag = 0x00、legacy_key_block = empty
7. アトミック書き戻し
8. メッセージ: `Attachment <FILE_NAME> set to INHERIT/DESTROY`

---

## new コマンド拡張 (REQ-401) 🟡

```rust
// 既存 cmd_new に追加
#[arg(long = "attach", value_name = "FILE")]
attach: Vec<PathBuf>,
```

**動作変更**:
1. 既存処理でエントリ作成 (UUID 確定)
2. `--attach` が指定されていれば各ファイルに対して `add_attachment` を実行
3. 1 つでも添付失敗ならエントリも rollback (atomicity)

**出力サンプル**:
```
$ pq-diary new --title "コーヒー" --attach ~/photo.jpg --body "豆: ケニア"
Created: 3c6b775f "コーヒー"
Attached: photo.jpg (1.5 MB)
```

---

## show コマンド拡張 (REQ-402) 🟡

`pq-diary show <ID>` の末尾に添付セクションを追加:

```
$ pq-diary show 3c6b
=== Entry 3c6b775f ===
Title: コーヒー
Tags: drink
Created: 2026-05-18 09:30 UTC
Updated: 2026-05-18 09:30 UTC

豆: ケニア

=== Attachments (2) ===
photo.jpg        1.5 MB  2026-05-18  INHERIT
receipt.pdf      234 KB  2026-05-18  DESTROY
```

添付 0 個ならセクション省略。

---

## export コマンド拡張 (REQ-601, REQ-602) 🟡

```
$ pq-diary export ~/out/
Continue? [y/N]: y
Master password: ***
Exporting 5 entries with 8 attachments...
  3c6b775f → ~/out/2026-05-18-coffee-3c6b.md (+2 attachments)
  ...
Exported: 5 entries, 8 attachments to ~/out/
```

ディレクトリ構造:
```
~/out/
├── 2026-05-18-coffee-3c6b.md
├── 2026-04-30-letter-08a9.md
└── attachments/
    ├── photo.jpg
    ├── receipt.pdf
    └── letter.pdf
```

MD 内の埋め込み:
```markdown
---
id: 3c6b775f
created: 2026-05-18
tags: [drink]
---

# コーヒー

豆: ケニア

![[photo.jpg]]
![[receipt.pdf]]
```

---

## import コマンド拡張 (REQ-603, REQ-604) 🟡

```
$ pq-diary import ~/in/
Master password: ***
Scanning ~/in/ ...
Found 5 .md files, 8 attachment files.
  note1.md → 3c6b775f (2 attachments linked)
  note2.md → 08a9e139 (1 attachment, 1 skipped: missing file)
  ...
Import complete: 5 entries, 7 attachments.
  Skipped: 1 missing attachment reference
```

---

## --claude policy (REQ-701) 🟡

| コマンド | --claude 動作 |
|---|---|
| `attachment add` | 一律ブロック |
| `attachment extract` | 一律ブロック |
| `attachment delete` | 一律ブロック |
| `attachment set` | 一律ブロック |
| `attachment list` | access policy `full` なら許可、それ以外ブロック |
| `new --attach` | --claude では `--attach` 指定をエラー |

PR review で要確認: `attachment list` を full policy で許可するか。

---

## dispatch 変更 (main.rs) 🟡

### Before (S13 以前)
```rust
// attachment コマンド存在せず
```

### After (S13)
```rust
Commands::Attachment { subcommand } => match subcommand {
    AttachmentCommands::Add { entry, path } =>
        commands::cmd_attachment_add(cli, entry.clone(), path.clone()),
    AttachmentCommands::List { entry } =>
        commands::cmd_attachment_list(cli, entry.clone()),
    AttachmentCommands::Extract { entry, filename, out } =>
        commands::cmd_attachment_extract(cli, entry.clone(), filename.clone(), out.clone()),
    AttachmentCommands::Delete { entry, filename, force } =>
        commands::cmd_attachment_delete(cli, entry.clone(), filename.clone(), *force),
    AttachmentCommands::Set { entry, filename, inherit, destroy } =>
        commands::cmd_attachment_set(cli, entry.clone(), filename.clone(), *inherit, *destroy),
},
```

---

## smoke test スクリプト追加候補 🟡

`ci/smoke-test.{sh,ps1}` に以下チェック追加:
1. `pq-diary attachment --help` exit 0
2. `pq-diary attachment add --help` exit 0
3. `pq-diary attachment list --help` exit 0
4. `pq-diary attachment extract --help` exit 0
5. ヘルプ表示に `attachment` が出る (= hide なし)
6. E2E: init → new → attachment add (テストファイル) → attachment list → attachment extract → SHA-256 比較

---

## 信頼性

🟡 100%

PR review で確定したい項目:
- `attachment list --claude` の許可ポリシー
- `attachment add` の同名重複時の挙動 (rename / skip / overwrite)
- `--attach` 複数指定時の rollback semantics
- `new --attach` の --claude 動作

## 関連

- [architecture.md](architecture.md)
- [types.rs](types.rs)
- [schema.md](schema.md)
- [dataflow.md](dataflow.md)
