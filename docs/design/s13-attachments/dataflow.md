# S13 添付ファイル データフロー

**作成日**: 2026-05-18
**関連設計**: [architecture.md](architecture.md)

**【信頼性レベル】**: 全フロー 🟡 (架空コードベース、PRD §10 明示なし、設計判断)

---

## 1. `attachment add` フロー 🟡

```mermaid
sequenceDiagram
    actor U as ユーザー
    participant CMD as cmd_attachment_add
    participant CC as check_claude_policy
    participant DC as DiaryCore
    participant ATT as attachment::add_attachment
    participant STR as streaming::encrypt_stream
    participant FS as filesystem (.attachments/)
    participant V as vault writer

    U->>CMD: attachment add 3c6b photo.jpg
    CMD->>CC: --claude?
    alt --claude
        CC-->>CMD: Blocked
        CMD-->>U: not permitted with --claude
    else OK
        CMD->>CMD: master pwd 取得 + size pre-check (>1GB → bail)
        CMD->>DC: unlock(master)
        DC-->>CMD: Ok
        CMD->>ATT: add_attachment(vault, entry_id, path)
        ATT->>ATT: locate entry by id_prefix
        alt エントリ不存在 / 複数マッチ
            ATT-->>CMD: Entry error
        else 一致
            ATT->>ATT: generate file_uuid
            ATT->>FS: create .attachments/<uuid>.bin.tmp
            ATT->>STR: encrypt_stream(K_master, file_uuid, src, tmp)
            loop chunk
                STR->>STR: read 1MB
                STR->>STR: AES-GCM encrypt with AAD (chunk_idx, total, file_uuid)
                STR->>STR: SHA-256 update
                STR->>FS: write chunk to .bin.tmp
            end
            STR-->>ATT: (size, sha256)
            ATT->>ATT: detect MIME (mime_guess)
            ATT->>ATT: build AttachmentRecord (ml-dsa sign)
            ATT->>V: append AttachmentRecord, update entry.attachment_count/offset
            V->>V: write vault.pqd.tmp + rename (atomic)
            alt success
                ATT->>FS: rename .bin.tmp → .bin
                ATT-->>CMD: file_uuid
                CMD-->>U: Added: photo.jpg (1.5MB, mime image/jpeg)
            else fail
                ATT->>FS: zeroize + delete .bin.tmp
                ATT-->>CMD: Io error
            end
        end
    end
```

## 2. `attachment list` フロー 🟡

```mermaid
sequenceDiagram
    actor U as ユーザー
    participant CMD as cmd_attachment_list
    participant DC as DiaryCore
    participant ATT as attachment::list_attachments
    participant R as vault reader

    U->>CMD: attachment list 3c6b
    CMD->>CMD: master pwd 取得 + unlock
    CMD->>ATT: list_attachments(vault, Some("3c6b"))
    ATT->>R: read_vault → entries + attachments
    ATT->>ATT: filter by entry_uuid (prefix match)
    ATT->>ATT: HMAC verify each AttachmentRecord
    ATT->>ATT: build AttachmentMeta list
    ATT-->>CMD: Vec<AttachmentMeta>
    CMD-->>U: テーブル表示 (filename, size, added_at, flag)
```

## 3. `attachment extract` フロー 🟡

```mermaid
sequenceDiagram
    actor U as ユーザー
    participant CMD as cmd_attachment_extract
    participant ATT as attachment::extract_attachment
    participant STR as streaming::decrypt_stream
    participant FS_in as .attachments/<uuid>.bin
    participant FS_out as --out path

    U->>CMD: attachment extract 3c6b photo.jpg --out /tmp/p.jpg
    CMD->>CMD: --claude? master? unlock
    CMD->>ATT: extract_attachment(entry, filename, out)
    ATT->>ATT: locate AttachmentRecord by entry+filename
    alt not found / multiple
        ATT-->>CMD: Entry error
    else found
        ATT->>FS_out: create /tmp/p.jpg.tmp
        ATT->>FS_in: open .attachments/<uuid>.bin
        ATT->>STR: decrypt_stream(K_master, file_uuid, size, sha256, src, dst)
        loop chunk
            STR->>FS_in: read [chunk_iv | chunk_ct + tag]
            STR->>STR: AES-GCM decrypt with AAD
            alt tag mismatch
                STR-->>ATT: Crypto error
            else OK
                STR->>STR: SHA-256 update
                STR->>FS_out: write plaintext chunk
            end
        end
        STR->>STR: verify sha256_actual == expected
        alt sha256 mismatch
            STR-->>ATT: Crypto error (tampered)
        else OK
            STR-->>ATT: Ok
            ATT->>FS_out: rename /tmp/p.jpg.tmp → /tmp/p.jpg
            ATT-->>CMD: Ok
            CMD-->>U: Extracted to /tmp/p.jpg (verified)
        end
    end
```

## 4. `attachment delete` フロー 🟡

```mermaid
sequenceDiagram
    actor U as ユーザー
    participant CMD as cmd_attachment_delete
    participant ATT as attachment::delete_attachment
    participant FS as filesystem
    participant V as vault writer

    U->>CMD: attachment delete 3c6b photo.jpg --force
    CMD->>CMD: master + unlock
    CMD->>ATT: delete_attachment(entry, filename)
    ATT->>ATT: locate AttachmentRecord
    ATT->>FS: zeroize overwrite .attachments/<uuid>.bin
    ATT->>FS: remove .attachments/<uuid>.bin
    ATT->>V: remove AttachmentRecord from vault.pqd
    V->>V: decrement entry.attachment_count
    V->>V: write atomic
    ATT-->>CMD: Ok
    CMD-->>U: Deleted photo.jpg
```

## 5. `legacy-access` 拡張フロー 🟡

```mermaid
sequenceDiagram
    actor H as 遺族
    participant CMD as cmd_legacy_access
    participant LEG as legacy::execute_legacy_access
    participant V as vault reader
    participant W as vault writer
    participant FS as .attachments/

    H->>CMD: legacy-access
    CMD->>CMD: --claude? legacy_code 取得 → 確認
    CMD->>LEG: execute_legacy_access(callback)
    LEG->>V: read vault → entries + attachments
    LEG->>LEG: derive K_legacy, verify token

    loop 各エントリ
        alt INHERIT
            LEG->>LEG: decrypt legacy block → plaintext
            LEG->>LEG: 新 vault に保存
            Note over LEG: 紐付く attachment も処理
            loop 紐付く各 attachment
                alt INHERIT
                    LEG->>LEG: decrypt attachment legacy block (K_legacy)
                    LEG->>LEG: 新 vault に AttachmentRecord 追加
                    LEG->>FS: .attachments/<uuid>.bin を新 vault dir に移動
                else DESTROY
                    LEG->>FS: zeroize + delete .attachments/<uuid>.bin
                end
            end
        else DESTROY
            LEG->>LEG: エントリ + 紐付く全 attachment を destroy
            loop 紐付く各 attachment
                LEG->>FS: zeroize + delete .attachments/<uuid>.bin
            end
        end
    end

    LEG->>W: write 新 vault.pqd
    LEG->>LEG: vault.toml [legacy] reset
    LEG-->>CMD: Report (entries_inherited, attachments_inherited, entries_destroyed, attachments_destroyed)
    CMD-->>H: Legacy access complete. N entries / M attachments inherited.
```

## 6. `export` 拡張フロー 🟡

```mermaid
sequenceDiagram
    actor U as ユーザー
    participant CMD as cmd_export
    participant ATT as attachment::list/extract
    participant FS_in as .attachments/
    participant FS_out as --out DIR

    U->>CMD: export ~/out/
    CMD->>CMD: master + unlock + 確認 prompt
    CMD->>FS_out: mkdir -p ~/out/attachments/
    loop 各エントリ
        CMD->>CMD: decrypt entry → MD body
        CMD->>ATT: list_attachments(entry_uuid)
        loop 各 attachment
            ATT->>FS_in: decrypt stream to memory or temp
            ATT->>FS_out: write attachments/<filename>
            CMD->>CMD: append `![[<filename>]]` to MD body
        end
        CMD->>FS_out: write <date>-<slug>-<id>.md
    end
    CMD-->>U: Exported N entries, M attachments.
```

## 7. `import` 拡張フロー 🟡

```mermaid
sequenceDiagram
    actor U as ユーザー
    participant CMD as cmd_import
    participant IMP as importer::import_directory
    participant ATT as attachment::add_attachment
    participant FS_in as input DIR

    U->>CMD: import ~/in/
    CMD->>CMD: master + unlock
    CMD->>IMP: import_directory(~/in/)
    IMP->>FS_in: find *.md files
    loop 各 MD
        IMP->>IMP: parse front matter + body
        IMP->>IMP: extract ![[FILE]] links
        IMP->>IMP: create entry (empty attachment list)
        loop 各 ![[FILE]] link
            IMP->>FS_in: check ~/in/attachments/FILE 存在
            alt found
                IMP->>ATT: add_attachment(entry, ~/in/attachments/FILE)
                Note over ATT: sha256 重複は本体書き込みスキップ
            else not found
                IMP->>IMP: warning, leave link as-is
            end
        end
    end
    IMP-->>CMD: ImportReport
    CMD-->>U: Imported N entries, M attachments.
```

## メモリ管理 (attachment add / extract)

| ステップ | 保持データ | 保護 |
|---|---|---|
| chunk read | 1MB buffer | `Zeroizing<Vec<u8>>` |
| chunk encrypt | chunk_ct (1MB + 16B tag) | non-secret (out put), but Vec cleared on drop |
| chunk decrypt | chunk_plaintext (1MB) | `Zeroizing<Vec<u8>>` |
| sha256 hasher | Sha256 state | non-secret |
| K_master | 32B | SecretBox / ZeroizeOnDrop |
| File handles | Read/Write trait objects | Drop closes |

## エラーフロー (共通)

```mermaid
flowchart TD
    A[attachment command] --> B{--claude?}
    B -->|YES write系| C[bail: not permitted]
    B -->|NO or read系 access=full| D{vault unlock OK?}
    D -->|NO| E[Crypto: invalid password]
    D -->|OK| F{entry/attachment found?}
    F -->|NO| G[Entry: not found]
    F -->|multiple| H[Entry: ambiguous]
    F -->|unique| I[実行]
    I --> J{chunk decrypt OK?}
    J -->|NO| K[Crypto: tampered]
    J -->|OK| L{sha256 match?}
    L -->|NO| M[Crypto: integrity fail]
    L -->|OK| N{書き込み成功?}
    N -->|NO| O[Io: zeroize tmp + bail]
    N -->|OK| P[Success]
    C --> EXIT[exit ≠ 0]
    E --> EXIT
    G --> EXIT
    H --> EXIT
    K --> EXIT
    M --> EXIT
    O --> EXIT
    P --> EXIT0[exit 0]
```

## vault.pqd 書き換え範囲 (各コマンド比較)

| コマンド | header | entry records | attachment records | .attachments/ |
|---|---|---|---|---|
| `attachment add` | (no change) | 1 entry: attachment_count++, attachment_offset 更新 | 1 record 追加 | 1 .bin 追加 |
| `attachment list` | (no change) | (no change) | (read) | (no change) |
| `attachment extract` | (no change) | (no change) | (read) | (read) |
| `attachment delete` | (no change) | 1 entry: attachment_count-- | 1 record 削除 | 1 .bin 削除 (zeroize) |
| `attachment set` | (no change) | (no change) | 1 record: legacy_flag / legacy_key_block | (no change) |
| `legacy-access` | 完全再構築 | INHERIT のみ保持 | INHERIT のみ保持 | DESTROY .bin 削除 |
| `change-password` | kdf_salt / verification 更新 | 全 re-encrypt | 全 re-encrypt | (no change, K_master 共用しない) |

## 関連

- [architecture.md](architecture.md)
- [types.rs](types.rs)
- [schema.md](schema.md)
- [cli-commands.md](cli-commands.md)
