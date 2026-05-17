# S12 デジタル遺言 データフロー

**作成日**: 2026-05-17
**関連設計**: [architecture.md](architecture.md)

**【信頼性レベル】**: 全フロー🔵

---

## 1. `legacy init` フロー 🔵

```mermaid
sequenceDiagram
    actor U as ユーザー
    participant CMD as cmd_legacy_init
    participant CC as check_claude_policy
    participant PWD as get_password
    participant DC as DiaryCore
    participant DV as Argon2LegacyDeriver
    participant CFG as VaultConfig

    U->>CMD: legacy init
    CMD->>CC: --claude?
    alt --claude
        CC-->>CMD: Blocked
        CMD-->>U: not permitted with --claude
    else OK
        CMD->>CFG: vault.toml 読み込み
        alt [legacy] initialized = true
            CMD-->>U: Already initialized
        else まだ
            CMD->>PWD: master password 取得
            CMD->>DC: unlock(master)
            DC-->>CMD: Ok
            CMD->>CMD: prompt_password("Legacy code: ")
            CMD->>CMD: prompt_password("Confirm: ")
            alt 不一致 or 空
                CMD-->>U: Passwords do not match / empty
            else OK
                alt master == legacy
                    CMD->>U: Warning: identical to master
                end
                CMD->>U: Choose confirmation mode [timer30/yn/phrase]
                U->>CMD: 選択 (or Enter for default)
                CMD->>DV: derive(legacy_code, legacy_salt)
                Note over DV: K_legacy = Argon2id(code, salt)
                DV-->>CMD: K_legacy (Zeroizing)
                CMD->>CMD: K_legacy 用 verification token 生成
                CMD->>CFG: [legacy] initialized=true,<br/>destroy_confirmation=mode,<br/>verification_iv/ct
                CFG->>CFG: vault.toml.tmp + rename (atomic)
                CMD-->>U: Initialized. Mode: {mode}
            end
        end
    end
```

## 2. `legacy set --inherit` フロー 🔵

```mermaid
sequenceDiagram
    actor U as ユーザー
    participant CMD as cmd_legacy_set
    participant DC as DiaryCore
    participant E as entry module
    participant DV as Argon2LegacyDeriver
    participant V as vault writer

    U->>CMD: legacy set 3c6b --inherit
    CMD->>CMD: master + legacy code 取得 + unlock
    CMD->>E: get_entry(3c6b) → EntryPlaintext
    CMD->>DV: derive(legacy_code, legacy_salt)
    DV-->>CMD: K_legacy
    CMD->>CMD: serialize EntryPlaintext JSON
    CMD->>CMD: encrypt JSON with K_legacy → legacy_key_block
    CMD->>V: update_entry(uuid, flag=0x01, legacy_key_block)
    V->>V: read existing, replace record, write tmp, rename
    V-->>CMD: Ok
    CMD-->>U: Entry 3c6b set to INHERIT
```

## 3. `legacy set --destroy` フロー 🔵

```mermaid
sequenceDiagram
    actor U as ユーザー
    participant CMD as cmd_legacy_set
    participant DC as DiaryCore
    participant V as vault writer

    U->>CMD: legacy set 3c6b --destroy
    CMD->>CMD: master 取得 + unlock (legacy code 不要)
    CMD->>V: update_entry(uuid, flag=0x00, legacy_key_block=empty)
    V-->>CMD: Ok
    CMD-->>U: Entry 3c6b set to DESTROY
```

## 4. `legacy rotate` フロー 🔵

```mermaid
sequenceDiagram
    actor U as ユーザー
    participant CMD as cmd_legacy_rotate
    participant DC as DiaryCore
    participant DV_old as Argon2LegacyDeriver(old)
    participant DV_new as Argon2LegacyDeriver(new)
    participant CFG as VaultConfig
    participant E as entry module
    participant W as vault writer

    U->>CMD: legacy rotate
    CMD->>CMD: master, old_legacy, new_legacy×2 取得
    CMD->>DC: unlock(master)
    CMD->>DV_old: derive(old_code, salt) → K_legacy_old
    Note over CMD: vault.toml [legacy] の<br/>verification token で<br/>old code 正当性確認
    alt old code 不正
        CMD-->>U: Invalid old legacy code
    else OK
        CMD->>DV_new: derive(new_code, salt) → K_legacy_new
        CMD->>E: list_entries_with_body() → 全エントリ
        loop 各 INHERIT エントリ
            CMD->>CMD: decrypt legacy_key_block with K_legacy_old → EntryPlaintext JSON
            CMD->>CMD: encrypt JSON with K_legacy_new → new_legacy_key_block
        end
        CMD->>CFG: update verification token with K_legacy_new
        CMD->>W: write vault.pqd.tmp with new_legacy_key_blocks
        W->>W: rename(tmp, vault.pqd) atomic
        alt 書き込み失敗
            W-->>CMD: error
            CMD->>W: zeroize delete tmp
            CMD-->>U: error, vault.pqd unchanged
        else OK
            CMD-->>U: Rotated. N entries re-encrypted
        end
    end
```

## 5. `legacy-access` フロー (最重要、不可逆) 🔵

```mermaid
sequenceDiagram
    actor H as 遺族 (heir)
    participant CMD as cmd_legacy_access
    participant CC as check_claude_policy
    participant CFG as VaultConfig
    participant DV as Argon2LegacyDeriver
    participant V as vault reader
    participant CONF as confirm UI
    participant W as vault writer

    H->>CMD: legacy-access
    CMD->>CC: --claude?
    alt --claude
        CC-->>CMD: Blocked (before Argon2 → NFR-104)
        CMD-->>H: not permitted
    else OK
        CMD->>CFG: vault.toml [legacy]
        alt initialized = false
            CMD-->>H: Legacy not initialized
        else OK
            CMD->>CMD: prompt_password("Legacy code: ")
            CMD->>DV: derive(code, legacy_salt) → K_legacy
            CMD->>CFG: verify K_legacy with [legacy] verification token
            Note over CFG: vault.pqd ヘッダーの token は<br/>K_master 用なので使わない
            alt 不正
                CMD-->>H: Invalid legacy code
            else OK
                CMD->>CONF: run_destroy_confirmation(mode)
                Note over CONF: mode=timer30 → 30秒タイマー→y/N<br/>mode=yn → 即時y/N<br/>mode=phrase → 'DESTROY ALL'入力
                CONF-->>CMD: confirmed?
                alt false (cancel)
                    CMD-->>H: キャンセルしました
                else true (proceed)
                    CMD->>V: read_vault records
                    loop 各エントリ
                        alt legacy_flag = INHERIT
                            CMD->>CMD: decrypt legacy_key_block → EntryPlaintext JSON
                            CMD->>CMD: deserialize EntryPlaintext
                            CMD->>CMD: 新vault 用に保存
                        else DESTROY
                            CMD->>CMD: zeroize entry record buffer
                        end
                    end
                    CMD->>W: write vault.pqd.tmp encrypted with K_legacy
                    Note over W: new header: kdf_salt は元 legacy_salt<br/>新 KEM/DSA 鍵を生成<br/>verification_token は K_legacy で再生成
                    CMD->>CFG: [legacy] initialized=false, token clear
                    W->>W: rename(tmp, vault.pqd) atomic
                    CMD-->>H: Legacy access complete.<br/>N inherited, M destroyed.
                end
            end
        end
    end
```

## メモリ管理 (legacy-access)

| ステップ | 保持データ | 保護 |
|---|---|---|
| 1. legacy code 受取 | `SecretString` | Drop で zeroize |
| 2. K_legacy 導出 | `Zeroizing<[u8; 32]>` | scope 抜けで zeroize |
| 3. 全 INHERIT 復号 | `Vec<EntryPlaintext>` | EntryPlaintext は ZeroizeOnDrop |
| 4. 新 vault.pqd 構築 | tmp ファイル | 失敗時 zeroize 上書き → delete |
| 5. rename 完了 | 関数 scope 抜け | 全 zeroize |

## エラーフロー (共通)

```mermaid
flowchart TD
    A[legacy command] --> B{--claude?}
    B -->|YES| C[anyhow::bail: not permitted]
    B -->|NO| D{initialized?}
    D -->|init 未| E[bail: Legacy not initialized / Already init]
    D -->|OK| F[Argon2 derive]
    F --> G{verify ok?}
    G -->|NG| H[bail: Invalid legacy code]
    G -->|OK| I[操作実行]
    I --> J{書き込み失敗?}
    J -->|YES| K[tmp zeroize + bail]
    J -->|NO| L[Success message]
    C --> M[exit ≠ 0, vault unchanged]
    E --> M
    H --> M
    K --> M
    L --> N[exit 0]
```

## vault.pqd 書き換え範囲 (各コマンド比較)

| コマンド | header | entry records |
|---|---|---|
| `legacy init` | (no change) | (no change) — vault.toml のみ更新 |
| `legacy set --inherit` | (no change) | 1 entry: flag 0x00→0x01, legacy_key_block 追加 |
| `legacy set --destroy` | (no change) | 1 entry: flag 0x01→0x00, legacy_key_block 削除 |
| `legacy rotate` | (no change) | 全 INHERIT: legacy_key_block 再暗号化 |
| `legacy-access` | kdf_salt = 元 legacy_salt、verification_token を K_legacy で再生成 | DESTROY 削除、INHERIT を K_legacy で再構築 |

## 関連

- [architecture.md](architecture.md)
- [types.rs](types.rs)
- [schema.md](schema.md)
- [cli-commands.md](cli-commands.md)
