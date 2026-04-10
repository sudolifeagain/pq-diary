# S7 Access Control + Claude データフロー図

**作成日**: 2026-04-10
**関連アーキテクチャ**: [architecture.md](architecture.md)
**関連要件定義**: [requirements.md](../../spec/s7-access-control-claude/requirements.md)

**【信頼性レベル凡例】**:
- 🔵 **青信号**: EARS要件定義書・設計文書・ユーザヒアリングを参考にした確実なフロー

---

## 4層ポリシーチェックフロー 🔵

**信頼性**: 🔵 *PRD 4.4 + REQ-020〜025*

```mermaid
flowchart TD
    START[CLIコマンド実行] --> L1{Layer 1: --claude?}
    L1 -->|No| SKIP[ポリシーチェック不要<br/>通常処理へ]
    L1 -->|Yes| READ[vault.toml 読み取り<br/>AccessPolicy取得]
    READ --> L2{Layer 2: policy?}
    L2 -->|None| DENY_NONE["DenyNoDecrypt<br/>復号試行なし<br/>即時エラー"]
    L2 -->|WriteOnly| L3{Layer 3: 操作種別?}
    L2 -->|Full| ALLOW_FULL[Allow<br/>全操作許可]
    L3 -->|Read| DENY_OP["DenyOperation<br/>read操作拒否"]
    L3 -->|Write| ALLOW_WO[Allow<br/>write操作許可]

    SKIP --> PW[パスワード取得]
    ALLOW_FULL --> PW
    ALLOW_WO --> PW
    PW --> UNLOCK[DiaryCore::unlock]
    UNLOCK --> OP[操作実行]
    OP --> LOCK[VaultGuard::drop → lock]

    DENY_NONE --> ERR["DiaryError::Policy<br/>Access denied: vault 'X'<br/>has policy 'none'"]
    DENY_OP --> ERR2["DiaryError::Policy<br/>Access denied: vault 'X'<br/>has policy 'write_only'"]

    style DENY_NONE fill:#f66,color:#fff
    style DENY_OP fill:#f66,color:#fff
    style ALLOW_FULL fill:#6f6
    style ALLOW_WO fill:#6f6
    style SKIP fill:#6f6
```

## 操作分類マッピング 🔵

**信頼性**: 🔵 *REQ-010 + ヒアリングQ8*

```mermaid
flowchart LR
    subgraph Read操作
        LIST[list]
        SHOW[show]
        SEARCH[search]
        STATS[stats]
        TSHOW[template show]
        TLIST[template list]
    end

    subgraph Write操作
        NEW[new]
        EDIT[edit]
        DELETE[delete]
        SYNC[sync]
        TODAY[today]
        TADD[template add]
        TDEL[template delete]
        IMPORT[import]
    end

    Read操作 -->|WriteOnly| DENIED[拒否]
    Read操作 -->|Full| ALLOWED[許可]
    Write操作 -->|WriteOnly| ALLOWED
    Write操作 -->|Full| ALLOWED

    style DENIED fill:#f66,color:#fff
    style ALLOWED fill:#6f6
```

## vault create フロー 🔵

**信頼性**: 🔵 *REQ-030〜032, REQ-040*

```mermaid
sequenceDiagram
    participant U as ユーザー/Claude
    participant CLI as cli/commands.rs
    participant VM as VaultManager
    participant FS as FileSystem

    U->>CLI: vault create work --policy write_only
    CLI->>VM: validate_vault_name("work")
    VM-->>CLI: Ok(())

    CLI->>CLI: parse_policy("write_only") → WriteOnly

    alt policy == Full
        CLI->>U: 警告メッセージ表示
        U->>CLI: y/N
        alt N
            CLI-->>U: 中止
        end
    end

    CLI->>CLI: get_password()
    U->>CLI: パスワード入力

    CLI->>VM: create_vault("work", pw, WriteOnly)
    VM->>VM: init_vault("work", pw)
    VM->>FS: mkdir vaults/work/
    VM->>FS: mkdir vaults/work/entries/
    VM->>FS: write vault.pqd (暗号初期化)
    VM->>FS: write vault.toml (policy="none")
    VM->>VM: set_policy("work", WriteOnly)
    VM->>FS: read vault.toml
    VM->>FS: write vault.toml.tmp (policy="write_only")
    VM->>FS: rename vault.toml.tmp → vault.toml
    VM-->>CLI: Ok(())

    CLI-->>U: Created vault 'work' (policy: write_only)
```

## vault list フロー 🔵

**信頼性**: 🔵 *REQ-033, REQ-201*

```mermaid
sequenceDiagram
    participant U as ユーザー
    participant CLI as cli/commands.rs
    participant VM as VaultManager
    participant FS as FileSystem

    U->>CLI: vault list
    Note over CLI: パスワード不要

    CLI->>VM: list_vaults_with_policy()
    VM->>FS: read_dir(~/.pq-diary/vaults/)
    loop 各Vaultディレクトリ
        VM->>FS: read vault.toml
        VM->>VM: VaultInfo { name, policy }
    end
    VM-->>CLI: Vec<VaultInfo>

    CLI-->>U: NAME      POLICY<br/>private   none<br/>work      write_only<br/>analysis  full
```

## vault policy フロー 🔵

**信頼性**: 🔵 *REQ-034, REQ-040, REQ-202*

```mermaid
sequenceDiagram
    participant U as ユーザー
    participant CLI as cli/commands.rs
    participant VM as VaultManager
    participant FS as FileSystem

    U->>CLI: vault policy work full
    Note over CLI: パスワード不要

    CLI->>CLI: parse_policy("full") → Full

    CLI->>U: 警告: "full"を設定すると...<br/>本当に許可しますか？ [y/N]:
    U->>CLI: y

    CLI->>VM: set_policy("work", Full)
    VM->>FS: read vault.toml
    VM->>VM: config.access.policy = Full
    VM->>FS: write vault.toml.tmp
    VM->>FS: rename vault.toml.tmp → vault.toml
    VM-->>CLI: Ok(())

    CLI-->>U: Policy updated: work → full
```

## vault delete フロー 🔵

**信頼性**: 🔵 *REQ-035〜037, REQ-102*

```mermaid
sequenceDiagram
    participant U as ユーザー
    participant CLI as cli/commands.rs
    participant VM as VaultManager
    participant FS as FileSystem

    U->>CLI: vault delete old-notes --zeroize
    Note over CLI: パスワード不要

    CLI->>CLI: Vault存在確認
    CLI->>CLI: デフォルトVault判定

    alt デフォルトVault
        CLI->>U: Warning: 'old-notes' is the default vault.<br/>Are you sure? [y/N]:
        U->>CLI: y
    end

    alt --claude でない
        CLI->>U: Delete vault 'old-notes'?<br/>This cannot be undone. [y/N]:
        U->>CLI: y
    end

    CLI->>VM: delete_vault("old-notes", zeroize=true)

    alt zeroize=true
        VM->>FS: stat vault.pqd (サイズ取得)
        VM->>VM: OsRng で同サイズのランダムデータ生成
        VM->>FS: overwrite vault.pqd with random data
        VM->>FS: sync_all()
    end

    VM->>FS: remove_dir_all(vaults/old-notes/)
    VM-->>CLI: Ok(())

    CLI-->>U: Deleted vault 'old-notes'
```

## --claude コマンド実行フロー（全体） 🔵

**信頼性**: 🔵 *REQ-020〜025, REQ-101*

```mermaid
sequenceDiagram
    participant C as Claude Code
    participant CLI as pq-diary CLI
    participant P as policy.rs
    participant DC as DiaryCore
    participant FS as FileSystem

    C->>CLI: pq-diary --claude -v work new "title" -b "body"

    Note over CLI: Step 1: ポリシーチェック
    CLI->>FS: read vaults/work/vault.toml
    FS-->>CLI: config (policy=write_only)
    CLI->>P: check_access(claude=true, WriteOnly, Write, "work")
    P-->>CLI: Allow

    Note over CLI: Step 2: パスワード取得
    CLI->>CLI: get_password() → PQ_DIARY_PASSWORD env

    Note over CLI: Step 3: Vault操作
    CLI->>DC: new("vaults/work/vault.pqd")
    CLI->>DC: unlock(password)
    DC->>FS: read vault.pqd → Argon2id → decrypt
    CLI->>DC: create_entry("title", "body", tags)
    DC->>FS: write vault.pqd (atomic)
    CLI->>DC: lock() [via VaultGuard drop]

    CLI-->>C: Created entry abc12345
```

## エラーハンドリングフロー 🔵

**信頼性**: 🔵 *REQ-050, EDGE-001〜006*

```mermaid
flowchart TD
    A[エラー発生] --> B{エラー種別}
    B -->|ポリシー拒否 None| C["DiaryError::Policy<br/>Access denied: vault 'X' has policy 'none'.<br/>'--claude' requires 'write_only' or 'full'."]
    B -->|ポリシー拒否 WriteOnly+Read| D["DiaryError::Policy<br/>Access denied: vault 'X' has policy 'write_only'.<br/>Read operations require 'full'."]
    B -->|Vault名無効| E["DiaryError::InvalidArgument<br/>Invalid vault name: ..."]
    B -->|Vault重複| F["DiaryError::Vault<br/>Vault 'X' already exists"]
    B -->|Vault未存在| G["DiaryError::Vault<br/>Vault 'X' not found"]
    B -->|vault.toml破損| H["DiaryError::Config<br/>Failed to parse vault.toml: ..."]
    B -->|無効ポリシー値| I["DiaryError::Config<br/>unknown variant 'X', expected one of<br/>'none', 'write_only', 'full'"]

    C --> EXIT[exit(1)]
    D --> EXIT
    E --> EXIT
    F --> EXIT
    G --> EXIT
    H --> EXIT
    I --> EXIT
```

## 関連文書

- **アーキテクチャ**: [architecture.md](architecture.md)
- **型定義**: [types.rs](types.rs)
- **要件定義**: [requirements.md](../../spec/s7-access-control-claude/requirements.md)

## 信頼性レベルサマリー

- 🔵 青信号: 全件 (100%)
- 🟡 黄信号: 0件 (0%)
- 🔴 赤信号: 0件 (0%)

**品質評価**: 高品質
