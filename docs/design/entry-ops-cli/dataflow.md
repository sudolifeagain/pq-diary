# S4: エントリ操作 + CLI — データフロー図

> **スプリント**: S4 (entry-ops-cli)
> **ステータス**: 全項目 DECIDED
> **関連アーキテクチャ**: [architecture.md](architecture.md)

---

## 1. パスワード取得フロー 🔵

*ADR-0003、要件 REQ-051〜REQ-054より*

```mermaid
flowchart TD
    START[コマンド実行] --> FLAG{--password<br/>フラグあり?}
    FLAG -->|あり| WARN[stderr に警告表示]
    WARN --> SECRET1[SecretString に変換]
    FLAG -->|なし| ENV{PQ_DIARY_PASSWORD<br/>環境変数あり?}
    ENV -->|あり| SECRET2[SecretString に変換]
    ENV -->|なし| TTY{stdin は<br/>TTY?}
    TTY -->|はい| PROMPT[Password: プロンプト表示]
    PROMPT --> ECHO_OFF[エコー無効化<br/>Unix: termios<br/>Windows: SetConsoleMode]
    ECHO_OFF --> READ[1バイトずつ読み取り<br/>→ SecretString に直接格納]
    READ --> ECHO_ON[エコー復元]
    ECHO_ON --> SECRET3[SecretString 完成]
    TTY -->|いいえ| ERR[DiaryError::Password<br/>パスワードが指定されていません]

    SECRET1 --> UNLOCK[CryptoEngine::unlock]
    SECRET2 --> UNLOCK
    SECRET3 --> UNLOCK
```

---

## 2. エントリ作成フロー (new) 🔵

*要件 REQ-001, REQ-011〜REQ-013より*

```mermaid
sequenceDiagram
    participant CLI as cli/commands.rs
    participant PW as password.rs
    participant ED as editor.rs
    participant EN as entry.rs
    participant CE as CryptoEngine
    participant VR as vault/reader.rs
    participant VW as vault/writer.rs

    CLI->>PW: get_password(cli_args)
    PW-->>CLI: SecretString

    CLI->>CLI: resolve vault path (-v or default)
    CLI->>VR: read_vault(vault.pqd)
    VR-->>CLI: (header, entries)

    CLI->>CE: unlock(password, header.kdf_salt, ...)
    CE-->>CLI: Ok(())

    alt -b フラグ指定
        CLI->>CLI: body = args.body
    else stdin がパイプ
        CLI->>CLI: body = read_stdin()
    else TTY 接続
        CLI->>ED: launch_editor_for_new()
        ED->>ED: secure_tmpdir() → 一時ファイル作成
        ED->>ED: $EDITOR 起動
        ED-->>CLI: body (一時ファイル読み取り)
        ED->>ED: secure_delete(一時ファイル)
    end

    CLI->>EN: create_entry(vault_path, engine, plaintext)
    EN->>EN: EntryPlaintext { title, tags, body }
    EN->>EN: serde_json::to_vec(&plaintext)
    EN->>CE: encrypt(json_bytes)
    CE-->>EN: (ciphertext, iv)
    EN->>CE: dsa_sign(ciphertext)
    CE-->>EN: signature
    EN->>CE: hmac(record_data)
    CE-->>EN: content_hmac
    EN->>EN: EntryRecord 構築 (UUID v4, timestamps)
    EN->>VW: write_vault(header, entries + new_entry)
    VW-->>EN: Ok(())
    EN-->>CLI: Ok(uuid)

    CLI->>CE: lock()
    CLI->>CLI: "Created: {prefix} \"{title}\""
```

---

## 3. エントリ一覧フロー (list) 🔵

*要件 REQ-002, REQ-031〜REQ-033より*

```mermaid
sequenceDiagram
    participant CLI as cli/commands.rs
    participant EN as entry.rs
    participant CE as CryptoEngine
    participant VR as vault/reader.rs

    CLI->>VR: read_vault(vault.pqd)
    VR-->>CLI: (header, entries)
    CLI->>CE: unlock(password, ...)
    CE-->>CLI: Ok(())

    CLI->>EN: list_entries(vault_path, engine)
    loop 各 EntryRecord
        EN->>CE: decrypt(iv, ciphertext)
        CE-->>EN: SecureBuffer (JSON bytes)
        EN->>EN: serde_json::from_slice → EntryPlaintext
        EN->>EN: EntryMeta { uuid_hex, title, tags, created_at, updated_at }
    end
    EN-->>CLI: Vec<EntryMeta>

    CLI->>CLI: フィルタ適用
    alt --tag 指定
        CLI->>CLI: Tag 前方一致フィルタ
    end
    alt -q 指定
        CLI->>CLI: タイトル部分一致フィルタ
    end
    CLI->>CLI: updated_at 降順ソート
    CLI->>CLI: -n 件数制限 (デフォルト 20)
    CLI->>CLI: 表示: "{prefix}  {date}  {title}  #{tags}"

    CLI->>CE: lock()
```

---

## 4. エントリ表示フロー (show) 🔵

*要件 REQ-003, REQ-041〜REQ-043より*

```mermaid
sequenceDiagram
    participant CLI as cli/commands.rs
    participant EN as entry.rs
    participant CE as CryptoEngine

    CLI->>EN: IdPrefix::new(args.id)
    EN-->>CLI: IdPrefix (最小4文字検証済み)

    CLI->>CE: unlock(password, ...)
    CLI->>EN: get_entry(vault_path, engine, prefix)

    EN->>EN: 全 EntryRecord を走査
    alt 一意マッチ
        EN->>CE: decrypt(iv, ciphertext)
        CE-->>EN: SecureBuffer
        EN->>EN: serde_json::from_slice → EntryPlaintext
        EN-->>CLI: Ok((record, plaintext))
    else 複数マッチ
        EN-->>CLI: Err("複数のエントリがマッチ: a3f9b2, a3f9c1")
    else マッチなし
        EN-->>CLI: Err("エントリが見つかりません")
    end

    CLI->>CLI: 表示: タイトル / 日時 / タグ / 本文
    CLI->>CE: lock()
```

---

## 5. エントリ編集フロー (edit) 🔵

*要件 REQ-004, REQ-014〜REQ-016, REQ-082〜REQ-083より*

### 5.1 $EDITOR 経由 (フラグなし)

```mermaid
sequenceDiagram
    participant CLI as cli/commands.rs
    participant EN as entry.rs
    participant ED as editor.rs
    participant CE as CryptoEngine
    participant VW as vault/writer.rs

    CLI->>CE: unlock(password, ...)
    CLI->>EN: get_entry(vault_path, engine, prefix)
    EN-->>CLI: (record, plaintext)

    CLI->>ED: write_header_file(plaintext)
    Note over ED: # Title: 今日の振り返り<br/># Tags: 日記/振り返り, 仕事<br/># ---<br/><br/>今日は良い一日だった。
    ED->>ED: secure_tmpdir() → 一時ファイル作成
    ED->>ED: launch_editor(tmpfile)
    ED-->>CLI: Ok(())

    CLI->>ED: read_header_file(tmpfile)
    ED->>ED: ヘッダーパース (# Title: / # Tags: / # ---)
    alt ヘッダー正常
        ED-->>CLI: Ok(HeaderComment { title, tags, body })
    else ヘッダー不正
        ED-->>CLI: Err + 元のメタデータ保持、本文変更のみ適用
    end

    ED->>ED: secure_delete(tmpfile)

    alt 変更あり
        CLI->>EN: update_entry(vault_path, engine, uuid, new_plaintext)
        EN->>CE: encrypt(new_json)
        CE-->>EN: (ciphertext, iv)
        EN->>CE: dsa_sign(ciphertext)
        EN->>CE: hmac(record_data)
        EN->>VW: write_vault(header, updated_entries)
        EN-->>CLI: Ok(())
    else 変更なし
        CLI->>CLI: "変更がありませんでした"
    end

    CLI->>CE: lock()
```

### 5.2 CLI フラグ経由 (--title / --add-tag / --remove-tag)

```mermaid
flowchart TD
    START[edit a3f9 --title "新名" --add-tag "新タグ"] --> UNLOCK[unlock]
    UNLOCK --> GET[get_entry by prefix]
    GET --> MODIFY[メタデータ更新<br/>title / tags 変更]
    MODIFY --> REENC[再暗号化 + 再署名]
    REENC --> WRITE[write_vault]
    WRITE --> LOCK[lock]
```

$EDITOR を起動しない。メタデータのみ変更して再暗号化。

---

## 6. エントリ削除フロー (delete) 🔵

*要件 REQ-005, REQ-021〜REQ-022より*

```mermaid
sequenceDiagram
    participant CLI as cli/commands.rs
    participant EN as entry.rs
    participant CE as CryptoEngine
    participant VW as vault/writer.rs

    CLI->>CE: unlock(password, ...)
    CLI->>EN: get_entry(vault_path, engine, prefix)
    EN-->>CLI: (record, plaintext)

    alt --force または --claude
        CLI->>CLI: 確認スキップ
    else TTY
        CLI->>CLI: "Delete \"{title}\" ({date})? [y/N]: "
        alt y
            CLI->>CLI: 続行
        else N / その他
            CLI->>CLI: "キャンセルしました"
            CLI->>CE: lock()
        end
    end

    CLI->>EN: delete_entry(vault_path, engine, uuid)
    EN->>EN: entries から uuid 一致するレコードを除外
    EN->>VW: write_vault(header, remaining_entries)
    VW-->>EN: Ok(())
    EN-->>CLI: Ok(())

    CLI->>CLI: "Deleted: {prefix} \"{title}\""
    CLI->>CE: lock()
```

---

## 7. $EDITOR 一時ファイル制御フロー 🔵

*要件 REQ-061〜REQ-065、PRD §4.3より*

```mermaid
flowchart TD
    subgraph "セキュア一時ディレクトリ選択"
        PLATFORM{プラットフォーム}
        PLATFORM -->|Unix| SHM{/dev/shm 存在?}
        SHM -->|はい| USE_SHM[/dev/shm]
        SHM -->|いいえ| RUN{/run/user/$UID 存在?}
        RUN -->|はい| USE_RUN[/run/user/$UID]
        RUN -->|いいえ| USE_TMP[/tmp + 警告表示]
        PLATFORM -->|Windows| USE_LOCAL[%LOCALAPPDATA%\pq-diary\tmp\]
        USE_LOCAL --> ACL[ACL: オーナーのみ RW]
    end

    subgraph "エディタ起動"
        TMPDIR[一時ファイル作成] --> EDITOR{$EDITOR 判定}
        EDITOR -->|vim/nvim| VIM["-c set noswapfile nobackup noundofile"]
        EDITOR -->|その他| OTHER[引数なし]
        VIM --> ENV_SET["$TMPDIR/$TEMP/$TMP = セキュアディレクトリ"]
        OTHER --> ENV_SET
        ENV_SET --> LAUNCH[エディタ起動]
    end

    subgraph "後処理"
        LAUNCH --> EXIT{終了コード}
        EXIT -->|0| READ_FILE[一時ファイル読み取り]
        EXIT -->|非0| ABORT[編集破棄]
        READ_FILE --> ZEROIZE[ランダムデータ上書き]
        ABORT --> ZEROIZE
        ZEROIZE --> DELETE[ファイル削除]
    end
```

---

## 8. タグフィルタリングフロー 🔵

*要件 REQ-071〜REQ-073より*

```mermaid
flowchart TD
    INPUT["--tag \"仕事\""] --> VALIDATE[Tag::new で正規化]
    VALIDATE --> FILTER[全エントリの tags を走査]

    FILTER --> ENTRY1["#仕事"]
    FILTER --> ENTRY2["#仕事/設計"]
    FILTER --> ENTRY3["#仕事/設計/レビュー"]
    FILTER --> ENTRY4["#日記"]
    FILTER --> ENTRY5["#日記/振り返り"]

    ENTRY1 -->|"仕事".starts_with("仕事")| MATCH1[✅ マッチ]
    ENTRY2 -->|"仕事/設計".starts_with("仕事")| MATCH2[✅ マッチ]
    ENTRY3 -->|"仕事/設計/レビュー".starts_with("仕事")| MATCH3[✅ マッチ]
    ENTRY4 -->|"日記".starts_with("仕事")| NOMATCH1[❌ 非マッチ]
    ENTRY5 -->|"日記/振り返り".starts_with("仕事")| NOMATCH2[❌ 非マッチ]
```

前方一致ロジック: `entry_tag == filter_tag || entry_tag.starts_with(&format!("{}/", filter_tag))`

`--tag "仕事"` は `#仕事` 自体と `#仕事/...` の子孫すべてにマッチする。`#仕事人` にはマッチしない（`/` 区切りを要求）。

---

## 9. 全体コマンド実行フロー 🔵

*全要件の統合フロー*

```mermaid
flowchart TD
    START[pq-diary コマンド] --> PARSE[clap パース]
    PARSE --> RESOLVE[Vault 解決<br/>-v or config.toml default]
    RESOLVE --> PW[パスワード取得<br/>--password > env > TTY]
    PW --> READ[read_vault]
    READ --> UNLOCK[CryptoEngine::unlock]
    UNLOCK --> CMD{コマンド分岐}

    CMD -->|new| NEW[create_entry]
    CMD -->|list| LIST[list_entries → フィルタ → 表示]
    CMD -->|show| SHOW[get_entry → 表示]
    CMD -->|edit| EDIT[get_entry → $EDITOR or flags → update_entry]
    CMD -->|delete| DELETE[get_entry → 確認 → delete_entry]

    NEW --> LOCK[CryptoEngine::lock<br/>zeroize 完了]
    LIST --> LOCK
    SHOW --> LOCK
    EDIT --> LOCK
    DELETE --> LOCK
```

---

## 関連文書

- **アーキテクチャ**: [architecture.md](architecture.md)
- **型定義**: [types.rs](types.rs)
- **要件定義**: [requirements.md](../../spec/entry-ops-cli/requirements.md)
- **S3 データフロー**: [../s3-vault-storage/dataflow.md](../s3-vault-storage/dataflow.md)

## 信頼性レベルサマリー

- 🔵 青信号: 全フロー (100%)
- 🟡 黄信号: 0件
- 🔴 赤信号: 0件

**品質評価**: 高品質
