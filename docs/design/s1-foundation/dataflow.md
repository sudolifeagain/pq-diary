# s1-foundation データフロー図

**作成日**: 2026-04-03
**関連アーキテクチャ**: [architecture.md](architecture.md)
**関連要件定義**: [requirements.md](../../spec/s1-foundation/requirements.md)

**【信頼性レベル凡例】**:
- 🔵 **青信号**: EARS要件定義書・PRD・ユーザヒアリングを参考にした確実なフロー
- 🟡 **黄信号**: 妥当な推測によるフロー
- 🔴 **赤信号**: 推測によるフロー

---

## クレート間の依存フロー 🔵

**信頼性**: 🔵 *PRDセクション2.1より*

```mermaid
graph LR
    CLI["cli/<br/>pq-diary (binary)"]
    CORE["core/<br/>pq-diary-core (library)"]
    CLAP["clap"]
    ANYHOW["anyhow"]
    THISERROR["thiserror"]
    ZEROIZE["zeroize"]
    SECRECY["secrecy"]

    CLI --> CORE
    CLI --> CLAP
    CLI --> ANYHOW
    CORE --> THISERROR
    CORE --> ZEROIZE
    CORE --> SECRECY
```

## CLI コマンドディスパッチフロー 🔵

**信頼性**: 🔵 *PRDセクション4.1・REQ-004より*

```mermaid
flowchart TD
    USER[ユーザー入力] --> CLAP_PARSE[clap::Parser::parse]
    CLAP_PARSE --> MATCH{サブコマンド判定}

    MATCH -->|init| INIT[pq-diary init]
    MATCH -->|vault| VAULT[vault サブコマンド群]
    MATCH -->|new/list/show/edit/delete| ENTRY[エントリ操作]
    MATCH -->|today/search/stats| EXTRA[追加機能]
    MATCH -->|git-*| GIT[Git同期]
    MATCH -->|legacy*| LEGACY[デジタル遺言]
    MATCH -->|daemon| DAEMON[デーモン]
    MATCH -->|import/export| IO[入出力]
    MATCH -->|template| TMPL[テンプレート]

    INIT --> UNIMPL["unimplemented!<br/>(Sprint N で実装)"]
    VAULT --> UNIMPL
    ENTRY --> UNIMPL
    EXTRA --> UNIMPL
    GIT --> UNIMPL
    LEGACY --> UNIMPL
    DAEMON --> UNIMPL
    IO --> UNIMPL
    TMPL --> UNIMPL
```

Sprint 1 では全コマンドが `unimplemented!` を返す。実装は各Sprintで埋める。

## SecureBuffer ライフサイクルフロー 🔵

**信頼性**: 🔵 *PRDセクション8.1-8.2・REQ-003・ヒアリングQ2より*

```mermaid
sequenceDiagram
    participant Caller as 呼び出し元
    participant SB as SecureBuffer
    participant Heap as ヒープメモリ

    Caller->>SB: SecureBuffer::new(data)
    SB->>Heap: Box::from(data) で固定アロケート
    Note over SB: data は Box<[u8]> として保持<br/>再アロケートなし

    Caller->>SB: sb.as_ref() で読み取り
    SB-->>Caller: &[u8] 参照

    Caller->>SB: drop(sb) または スコープ終了
    SB->>Heap: inner.zeroize() でゼロ埋め
    SB->>Heap: Box::drop() でメモリ解放
    Note over Heap: データは確実にゼロ化済み
```

## CryptoEngine 状態遷移 🔵

**信頼性**: 🔵 *PRDセクション1.3・8.1-8.2・REQ-003・EDGE-103より*

```mermaid
stateDiagram-v2
    [*] --> Locked: CryptoEngine::new()
    Locked --> Unlocked: unlock(password)
    Unlocked --> Locked: lock()
    Locked --> [*]: drop()
    Unlocked --> [*]: drop()

    note right of Locked
        master_key: None
        legacy_key: None
        全暗号操作 → DiaryError::NotUnlocked
    end note

    note right of Unlocked
        master_key: Some(Secret<MasterKey>)
        legacy_key: Option<Secret<[u8; 32]>>
        暗号操作が可能
    end note
```

Sprint 1 では unlock/lock の中身は未実装（S2 で暗号実装を追加）。型定義と状態遷移のスケルトンのみ。

## DiaryError フロー 🔵

**信頼性**: 🔵 *REQ-002・REQ-403・EDGE-001-002より*

```mermaid
flowchart LR
    IO_ERR[std::io::Error] -->|#[from]| DIARY_ERR[DiaryError::Io]
    TOML_ERR[toml::de::Error] -->|#[from]| DIARY_ERR2[DiaryError::Config]
    CUSTOM["カスタムエラー"] --> DIARY_ERR3[DiaryError::Vault 等]

    subgraph core/
        DIARY_ERR --> RESULT["Result<T, DiaryError>"]
        DIARY_ERR2 --> RESULT
        DIARY_ERR3 --> RESULT
    end

    subgraph cli/
        RESULT -->|?| ANYHOW["anyhow::Result"]
        ANYHOW --> DISPLAY["stderr に Display 出力"]
    end
```

## CI パイプラインフロー 🔵

**信頼性**: 🔵 *REQ-005・REQ-101-102より*

```mermaid
flowchart TD
    TRIGGER["push / pull_request"] --> BUILD["cargo build --workspace"]
    BUILD -->|成功| TEST["cargo test --workspace"]
    BUILD -->|失敗| FAIL[CI 失敗 ❌]
    TEST -->|全パス| CLIPPY["cargo clippy -- -D warnings"]
    TEST -->|失敗| FAIL
    CLIPPY -->|警告なし| AUDIT["cargo audit"]
    CLIPPY -->|警告あり| FAIL
    AUDIT -->|脆弱性なし| PASS[CI 成功 ✅]
    AUDIT -->|脆弱性あり| FAIL
```

## 関連文書

- **アーキテクチャ**: [architecture.md](architecture.md)
- **Rust型定義**: [types.rs](types.rs)
- **要件定義**: [requirements.md](../../spec/s1-foundation/requirements.md)

## 信頼性レベルサマリー

- 🔵 青信号: 6件 (100%)
- 🟡 黄信号: 0件 (0%)
- 🔴 赤信号: 0件 (0%)

**品質評価**: 最高品質
