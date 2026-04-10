# S9 Security Hardening + Technical Debt データフロー図

**作成日**: 2026-04-10
**関連アーキテクチャ**: [architecture.md](architecture.md)

**【信頼性レベル凡例】**:
- 🔵 **青信号**: 既存実装・CLAUDE.md規約・コードレビュー指摘事項を参考にした確実なフロー

---

## メモリロックライフサイクル 🔵

**信頼性**: 🔵 *既存CryptoEngine unlock/lockフロー + secure_mem.rs構造*

```mermaid
sequenceDiagram
    participant CLI as cli/commands.rs
    participant CE as CryptoEngine
    participant SM as secure_mem.rs
    participant OS as OS (mlock/VirtualLock)

    Note over CLI: パスワード入力後
    CLI->>CE: unlock_with_vault(password, ...)

    Note over CE: Argon2id鍵導出
    CE->>CE: kdf::derive_key(password, salt, params)

    Note over CE: 検証トークン復号
    CE->>CE: aead::decrypt(sym_key, iv, ct)

    Note over CE: KEM/DSA秘密鍵復号
    CE->>CE: aead::decrypt(sym_key, iv, kem_ct)
    CE->>CE: aead::decrypt(sym_key, iv, dsa_ct)

    Note over CE: M-2/M-4: Zeroizing中間バッファ
    CE->>CE: Zeroizing::new(kem_sk.to_vec())
    CE->>CE: Zeroizing::new(dsa_sk.to_vec())

    Note over CE: MasterKey構築
    CE->>CE: MasterKey { sym_key, kem_sk, dsa_sk }
    CE->>CE: self.master_key = Some(SecretBox::new(...))

    Note over SM: メモリロック（スワップ防止）
    CE->>SM: mlock_master_key(&mk)
    SM->>OS: mlock(sym_key.as_ptr(), 32)
    OS-->>SM: Ok / ENOMEM
    SM->>OS: mlock(dsa_sk.as_ptr(), dsa_sk.len())
    OS-->>SM: Ok / ENOMEM
    SM->>OS: mlock(kem_sk.as_ptr(), kem_sk.len())
    OS-->>SM: Ok / ENOMEM

    alt mlock失敗
        SM-->>CE: Err (警告出力、処理続行)
    else mlock成功
        SM-->>CE: Ok(())
    end

    CE-->>CLI: Ok(()) — unlocked

    Note over CLI: === 通常操作 ===
    CLI->>CE: encrypt() / decrypt() / dsa_sign() / hmac()

    Note over CLI: ロック要求
    CLI->>CE: lock()

    Note over SM: メモリロック解除
    CE->>SM: munlock_master_key(&mk)
    SM->>OS: munlock(sym_key.as_ptr(), 32)
    SM->>OS: munlock(dsa_sk.as_ptr(), dsa_sk.len())
    SM->>OS: munlock(kem_sk.as_ptr(), kem_sk.len())
    SM-->>CE: Ok(())

    Note over CE: MasterKey Drop → ZeroizeOnDrop
    CE->>CE: self.master_key.take()

    CE-->>CLI: locked
```

## プロセス硬化フロー 🔵

**信頼性**: 🔵 *nix crate機能 + CLAUDE.md規約*

```mermaid
sequenceDiagram
    participant M as main()
    participant HP as harden_process()
    participant CD as check_debugger()
    participant OS as OS

    M->>HP: harden_process()

    Note over HP: Unix のみ有効
    alt cfg(unix)
        HP->>OS: prctl(PR_SET_DUMPABLE, 0)
        alt 成功
            OS-->>HP: Ok
        else 失敗
            OS-->>HP: Err
            HP->>HP: eprintln!("Warning: ...")
        end

        HP->>OS: setrlimit(RLIMIT_CORE, 0, 0)
        alt 成功
            OS-->>HP: Ok
        else 失敗
            OS-->>HP: Err
            HP->>HP: eprintln!("Warning: ...")
        end
    else cfg(not(unix))
        Note over HP: no-op
    end

    HP-->>M: return

    M->>CD: check_debugger()

    alt cfg(unix)
        CD->>OS: read /proc/self/status
        OS-->>CD: "TracerPid:\t12345"
        alt TracerPid != 0
            CD->>CD: eprintln!("Warning: debugger detected")
        end
    else cfg(windows)
        CD->>OS: IsDebuggerPresent()
        OS-->>CD: TRUE / FALSE
        alt TRUE
            CD->>CD: eprintln!("Warning: debugger detected")
        end
    else cfg(other)
        Note over CD: no-op
    end

    CD-->>M: return

    M->>M: Cli::parse()
    M->>M: dispatch(&cli)
```

## デバッガー検出フローチャート 🔵

**信頼性**: 🔵 *プラットフォーム分岐パターン（password.rs #[cfg] 準拠）*

```mermaid
flowchart TD
    START[check_debugger 開始] --> PLATFORM{プラットフォーム判定}

    PLATFORM -->|Unix| READ_PROC[/proc/self/status 読み取り]
    READ_PROC --> PARSE{TracerPid行をパース}
    PARSE -->|読み取り失敗| WARN_READ[eprintln! 警告<br/>処理続行]
    PARSE -->|TracerPid == 0| NO_DEBUG[デバッガーなし<br/>正常続行]
    PARSE -->|TracerPid != 0| WARN_DEBUG_U[eprintln!<br/>'Warning: debugger detected<br/>PID={TracerPid}']

    PLATFORM -->|Windows| IS_DEBUG[IsDebuggerPresent()]
    IS_DEBUG -->|FALSE| NO_DEBUG_W[デバッガーなし<br/>正常続行]
    IS_DEBUG -->|TRUE| WARN_DEBUG_W[eprintln!<br/>'Warning: debugger detected']

    PLATFORM -->|その他| NOOP[no-op]

    WARN_READ --> DONE[return]
    NO_DEBUG --> DONE
    WARN_DEBUG_U --> DONE
    NO_DEBUG_W --> DONE
    WARN_DEBUG_W --> DONE
    NOOP --> DONE

    style WARN_DEBUG_U fill:#ff6
    style WARN_DEBUG_W fill:#ff6
    style NO_DEBUG fill:#6f6
    style NO_DEBUG_W fill:#6f6
```

## エントリ読み取りパス（Before / After） 🔵

**信頼性**: 🔵 *既存entry.rs get_entry()構造 + HMAC/署名検証追加*

### Before（現行）

```mermaid
sequenceDiagram
    participant CLI as cli/commands.rs
    participant E as entry.rs
    participant RW as reader.rs
    participant CE as CryptoEngine

    CLI->>E: get_entry(vault_path, engine, prefix)
    E->>RW: read_vault(vault_path)
    RW-->>E: (header, records)

    E->>E: UUID prefix マッチング

    E->>CE: decrypt(&record.iv, &record.ciphertext)
    CE-->>E: SecureBuffer (plaintext JSON)

    E->>E: serde_json::from_slice → EntryPlaintext

    E-->>CLI: Ok((record, plaintext))

    Note over CLI: ※ HMAC未検証、署名未検証
```

### After（S9）

```mermaid
sequenceDiagram
    participant CLI as cli/commands.rs
    participant E as entry.rs
    participant RW as reader.rs
    participant CE as CryptoEngine

    CLI->>E: get_entry(vault_path, engine, prefix)
    E->>RW: read_vault(vault_path)
    RW-->>E: (header, records)

    E->>E: UUID prefix マッチング

    E->>CE: decrypt(&record.iv, &record.ciphertext)
    CE-->>E: SecureBuffer (plaintext JSON)

    Note over E: +++ S9: HMAC検証 +++
    E->>CE: hmac_verify(plaintext, &record.content_hmac)
    CE-->>E: Result<bool, DiaryError>
    alt HMAC不一致
        E-->>CLI: Err(DiaryError::Entry<br/>"content HMAC verification failed")
    end

    Note over E: +++ S9: DSA署名検証 +++
    E->>CE: dsa_verify(header.dsa_pk, plaintext, &record.signature)
    CE-->>E: Result<bool, DiaryError>
    alt 署名不正
        E-->>CLI: Err(DiaryError::Entry<br/>"signature verification failed")
    end

    E->>E: serde_json::from_slice → EntryPlaintext

    E-->>CLI: Ok((record, plaintext))

    Note over CLI: HMAC検証済み + 署名検証済み
```

## list_entries HMAC検証フロー 🔵

**信頼性**: 🔵 *既存list_entries構造 + パフォーマンス考慮*

```mermaid
flowchart TD
    START[list_entries 開始] --> READ[read_vault<br/>→ header, records]
    READ --> LOOP{各record}

    LOOP -->|次のrecord| TYPE{record_type<br/>== ENTRY?}
    TYPE -->|No| SKIP[スキップ]
    TYPE -->|Yes| DECRYPT[engine.decrypt<br/>→ plaintext]

    DECRYPT --> HMAC{engine.hmac_verify<br/>plaintext vs content_hmac}
    HMAC -->|Ok(true)| DESER[serde_json::from_slice<br/>→ EntryPlaintext]
    HMAC -->|Ok(false)| ERR_HMAC[DiaryError::Entry<br/>'HMAC verification failed']
    HMAC -->|Err| ERR_HMAC2[DiaryError伝播]

    DESER --> META[EntryMeta構築]
    META --> PUSH[metas.push(meta)]
    PUSH --> LOOP

    SKIP --> LOOP
    LOOP -->|全record処理完了| DONE[Ok(metas)]

    style ERR_HMAC fill:#f66,color:#fff
    style ERR_HMAC2 fill:#f66,color:#fff
    style DONE fill:#6f6
```

## H-1 SecretString 化フロー 🔵

**信頼性**: 🔵 *レビュー指摘 H-1 + 既存password.rs構造*

```mermaid
flowchart TD
    START[CLI起動] --> PARSE[Cli::parse<br/>password: Option&lt;SecretString&gt;]
    PARSE --> GET_PW[get_password<br/>flag_value: Option&lt;&SecretString&gt;]

    GET_PW --> FLAG{flag_value<br/>あり?}
    FLAG -->|Yes| EXPOSE[flag.expose_secret<br/>→ &str]
    EXPOSE --> PS_FLAG[PasswordSource::Flag<br/>SecretString]
    FLAG -->|No| ENV{PQ_DIARY_PASSWORD<br/>環境変数あり?}
    ENV -->|Yes| PS_ENV[PasswordSource::Env<br/>SecretString]
    ENV -->|No| TTY{stdin is_terminal?}
    TTY -->|Yes| PS_TTY[PasswordSource::Tty<br/>SecretString]
    TTY -->|No| ERR[DiaryError::Password]

    PS_FLAG --> USE[expose_secret<br/>→ &str → as_bytes]
    PS_ENV --> USE
    PS_TTY --> USE
    USE --> UNLOCK[engine.unlock<br/>password: &[u8]]

    Note over PARSE: String は即座に<br/>SecretString に変換

    style PARSE fill:#69f
    style PS_FLAG fill:#6f6
    style PS_ENV fill:#6f6
    style PS_TTY fill:#6f6
    style ERR fill:#f66,color:#fff
```

## M-1 not_implemented bail! 化フロー 🔵

**信頼性**: 🔵 *レビュー指摘 M-1 + anyhow::bail! パターン*

```mermaid
flowchart TD
    START[未実装コマンド呼び出し] --> DISPATCH[dispatch → not_implemented]

    subgraph Before
        NI_OLD[not_implemented] --> EPRINTLN[eprintln! メッセージ]
        EPRINTLN --> EXIT[process::exit 1]
        EXIT --> LEAK[SecretString等<br/>ZeroizeOnDrop<br/>未実行!]
    end

    subgraph After_S9[After S9]
        NI_NEW[not_implemented] --> BAIL[anyhow::bail!]
        BAIL --> UNWIND[スタック巻き戻し]
        UNWIND --> DROP[全Drop実行<br/>SecretString zeroize<br/>Zeroizing zeroize]
        DROP --> EXIT2[正常終了 exit 1]
    end

    style LEAK fill:#f66,color:#fff
    style DROP fill:#6f6
```

## E2Eテストカバレッジマップ 🔵

**信頼性**: 🔵 *既存コマンド一覧 + テスト網羅方針*

```mermaid
flowchart LR
    subgraph Core_Flow[コアフロー E2E]
        VC[vault create] --> NEW[new]
        NEW --> LIST[list]
        LIST --> SHOW[show]
        SHOW --> EDIT[edit]
        EDIT --> DELETE[delete]
    end

    subgraph Search_Stats[検索・統計 E2E]
        S_NEW[new x3] --> SEARCH[search]
        S_NEW --> STATS[stats]
        S_NEW --> IMPORT[import]
    end

    subgraph Template_Flow[テンプレート E2E]
        TA[template add] --> TL[template list]
        TL --> TS[template show]
        TS --> TD[template delete]
    end

    subgraph Daily[日次 E2E]
        TODAY1[today 1回目] --> TODAY2[today 2回目<br/>冪等性]
    end

    subgraph Perf[パフォーマンス]
        P_INIT[init+unlock < 5s]
        P_NEW[new+edit < 1s]
        P_LIST[list 100件 < 2s]
        P_SEARCH[search 100件 < 2s]
    end

    style Core_Flow fill:#e8f5e9
    style Search_Stats fill:#e3f2fd
    style Template_Flow fill:#fff3e0
    style Daily fill:#f3e5f5
    style Perf fill:#fce4ec
```

## 関連文書

- **アーキテクチャ**: [architecture.md](architecture.md)
- **型定義**: [types.rs](types.rs)
- **ヒアリング記録**: [design-interview.md](design-interview.md)

## 信頼性レベルサマリー

- 🔵 青信号: 全件 (100%)
- 🟡 黄信号: 0件 (0%)
- 🔴 赤信号: 0件 (0%)

**品質評価**: 高品質
