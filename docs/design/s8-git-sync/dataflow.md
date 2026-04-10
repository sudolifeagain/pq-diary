# S8 Git Sync データフロー図

**作成日**: 2026-04-10
**関連アーキテクチャ**: [architecture.md](architecture.md)
**関連要件定義**: [requirements.md](../../spec/s8-git-sync/requirements.md)

**【信頼性レベル凡例】**:
- 🔵 **青信号**: EARS要件定義書・設計文書・ユーザヒアリングを参考にした確実なフロー

---

## git-init フロー 🔵

**信頼性**: 🔵 *REQ-001〜005, EDGE-006*

```mermaid
sequenceDiagram
    participant U as ユーザー
    participant CLI as cli/commands.rs
    participant GIT as core/git.rs
    participant FS as FileSystem
    participant CMD as git CLI

    U->>CLI: pq-diary git-init --remote https://...

    CLI->>GIT: check_git_available()
    GIT->>CMD: git --version
    CMD-->>GIT: git version 2.x.x
    GIT-->>CLI: Ok(())

    CLI->>FS: .git ディレクトリ存在チェック
    alt 既に初期化済み
        CLI-->>U: Error: Git already initialized
    end

    CLI->>GIT: git_init(vault_dir, Some("https://..."))
    GIT->>GIT: generate_random_author_email() → "a1b2c3d4@localhost"
    GIT->>GIT: generate_gitignore() → "entries/*.md\n..."
    GIT->>CMD: git init
    GIT->>FS: write .gitignore
    GIT->>CMD: git remote add origin https://...

    GIT->>FS: read vault.toml
    GIT->>GIT: config.git.author_name = "pq-diary"
    GIT->>GIT: config.git.author_email = "a1b2c3d4@localhost"
    GIT->>FS: write vault.toml.tmp → rename vault.toml
    GIT-->>CLI: Ok(())

    CLI-->>U: Initialized git repository<br/>Author: pq-diary <a1b2c3d4@localhost><br/>Remote: origin → https://...
```

## git-push フロー（プライバシーパイプライン付き） 🔵

**信頼性**: 🔵 *REQ-010〜017, REQ-050〜054, ADR-0006 + ヒアリングQ1「write_vault()再実行」*

```mermaid
sequenceDiagram
    participant U as ユーザー
    participant CLI as cli/commands.rs
    participant GIT as core/git.rs
    participant DC as DiaryCore
    participant RW as reader/writer
    participant CMD as git CLI

    U->>CLI: pq-diary git-push

    CLI->>GIT: check_git_available()
    CLI->>CLI: .git 存在確認

    CLI->>CLI: get_password()
    U->>CLI: パスワード入力
    CLI->>DC: unlock(password)

    Note over GIT: === プライバシーパイプライン ===

    Note over GIT: Step 1: 追加パディング
    alt extra_padding_bytes_max > 0
        GIT->>GIT: generate_extra_padding(max_bytes)
        GIT->>RW: read_vault(vault_path)
        RW-->>GIT: (header, records)
        GIT->>RW: write_vault(vault_path, header_with_padding, records)
        Note over RW: vault.pqd 再書き込み（.tmp→rename）
    end

    Note over GIT: Step 2: Author匿名化
    GIT->>GIT: make_author(config)
    Note over GIT: "pq-diary <a1b2c3d4@localhost>"

    Note over GIT: Step 3: タイムスタンプファジング
    alt timestamp_fuzz_hours > 0
        GIT->>CMD: git log -1 --format=%aI
        CMD-->>GIT: 前回コミット時刻
        GIT->>GIT: fuzz_timestamp(prev, fuzz_hours)
        Note over GIT: fuzzed > prev (単調増加保証)
    end

    Note over GIT: Step 4: git add/commit/push
    GIT->>CMD: git add vault.pqd vault.toml
    GIT->>CMD: git commit --author="pq-diary <...>"<br/>-m "Update vault"<br/>env: GIT_AUTHOR_DATE, GIT_COMMITTER_DATE
    GIT->>CMD: git push origin

    GIT-->>CLI: Ok(())
    CLI-->>U: Pushed to remote successfully
```

## git-pull + マージフロー 🔵

**信頼性**: 🔵 *REQ-020〜028 + ヒアリングQ2「last-write-wins by updated_at」*

```mermaid
sequenceDiagram
    participant U as ユーザー
    participant CLI as cli/commands.rs
    participant GIT as core/git.rs
    participant RW as reader/writer
    participant CMD as git CLI
    participant FS as FileSystem

    U->>CLI: pq-diary git-pull

    CLI->>GIT: check_git_available()
    CLI->>CLI: .git 存在確認

    CLI->>CLI: get_password()
    U->>CLI: パスワード入力
    CLI->>CLI: DiaryCore::unlock(password)

    Note over GIT: === マージアルゴリズム ===

    Note over GIT: Step 1: ローカル読み取り
    GIT->>RW: read_vault(vault_path)
    RW-->>GIT: (local_header, local_entries)

    Note over GIT: Step 2: バックアップ
    GIT->>FS: copy vault.pqd → vault.pqd.bak

    Note over GIT: Step 3: リモート取得
    GIT->>CMD: git fetch origin
    GIT->>CMD: git checkout FETCH_HEAD -- vault.pqd

    Note over GIT: Step 4: リモート読み取り
    GIT->>RW: read_vault(vault_path)
    RW-->>GIT: (remote_header, remote_entries)

    Note over GIT: Step 5: ローカル復元
    GIT->>FS: rename vault.pqd.bak → vault.pqd

    Note over GIT: Step 6-9: UUID照合 + HMAC比較
    GIT->>GIT: UUID照合 + content_hmac比較
    Note over GIT: 同一HMAC → スキップ<br/>リモートのみ → 追加<br/>ローカルのみ → 保持<br/>HMAC異なる → コンフリクト

    GIT-->>CLI: (merged_entries, conflicts)

    alt コンフリクトあり
        alt --claude
            CLI->>CLI: ローカル側を自動採用
        else 通常
            loop 各コンフリクト
                CLI->>U: UUID: xxxx<br/>Local updated_at: T1<br/>Remote updated_at: T2<br/>[L]ocal / [R]emote?
                U->>CLI: L or R
            end
        end
    end

    Note over GIT: Step 10: アトミック書き込み
    GIT->>RW: write_vault(vault_path, header, merged_entries)

    CLI-->>U: Merged: 2 added, 1 updated, 0 deleted, 1 conflict resolved
```

## git-sync フロー 🔵

**信頼性**: 🔵 *REQ-030〜031*

```mermaid
sequenceDiagram
    participant U as ユーザー
    participant CLI as cli/commands.rs

    U->>CLI: pq-diary git-sync

    Note over CLI: Phase 1: Pull
    CLI->>CLI: cmd_git_pull(cli)
    Note over CLI: (fetch + merge + conflict resolution)

    Note over CLI: Phase 2: Push
    CLI->>CLI: cmd_git_push(cli)
    Note over CLI: (privacy pipeline + push)

    CLI-->>U: Sync complete<br/>Pull: 2 added, 1 updated<br/>Push: committed and pushed
```

## git-status フロー 🔵

**信頼性**: 🔵 *REQ-040*

```mermaid
sequenceDiagram
    participant U as ユーザー
    participant CLI as cli/commands.rs
    participant GIT as core/git.rs
    participant CMD as git CLI

    U->>CLI: pq-diary git-status

    CLI->>GIT: check_git_available()
    CLI->>CLI: .git 存在確認

    CLI->>GIT: git_status(vault_dir)
    GIT->>CMD: git status
    CMD-->>GIT: "On branch main\nnothing to commit..."
    GIT-->>CLI: Ok(status_string)

    CLI-->>U: On branch main<br/>nothing to commit, working tree clean
```

## マージアルゴリズム フローチャート 🔵

**信頼性**: 🔵 *REQ-021〜028*

```mermaid
flowchart TD
    START[マージ開始] --> READ_LOCAL[ローカル vault.pqd 読み取り<br/>local_entries: HashMap UUID→EntryRecord]
    READ_LOCAL --> BACKUP[vault.pqd → vault.pqd.bak]
    BACKUP --> FETCH[git fetch + checkout FETCH_HEAD -- vault.pqd]
    FETCH --> READ_REMOTE[リモート vault.pqd 読み取り<br/>remote_entries: HashMap UUID→EntryRecord]
    READ_REMOTE --> RESTORE[vault.pqd.bak → vault.pqd 復元]
    RESTORE --> LOOP{全リモートUUIDを走査}

    LOOP -->|次のUUID| CHECK_LOCAL{ローカルに<br/>同一UUID存在?}
    CHECK_LOCAL -->|No| ADD[リモートエントリを追加<br/>added += 1]
    CHECK_LOCAL -->|Yes| HMAC{content_hmac<br/>一致?}
    HMAC -->|一致| SKIP[変更なし → スキップ]
    HMAC -->|不一致| CONFLICT[コンフリクト検出]

    ADD --> LOOP
    SKIP --> LOOP
    CONFLICT --> RESOLVE{解決方針}
    RESOLVE -->|--claude| LOCAL_WIN[ローカル優先]
    RESOLVE -->|通常CLI| UPDATED{updated_at<br/>比較}
    UPDATED -->|ローカルが新| SUGGEST_L[ローカル推奨<br/>ユーザーに確認]
    UPDATED -->|リモートが新| SUGGEST_R[リモート推奨<br/>ユーザーに確認]

    LOCAL_WIN --> LOOP
    SUGGEST_L --> LOOP
    SUGGEST_R --> LOOP

    LOOP -->|全UUID処理完了| KEEP_LOCAL[ローカルのみのUUIDを保持]
    KEEP_LOCAL --> WRITE[write_vault で<br/>マージ結果をアトミック書き込み]
    WRITE --> DONE[MergeResult 返却<br/>added / updated / deleted / conflicts]

    style ADD fill:#6f6
    style SKIP fill:#ccc
    style CONFLICT fill:#ff6
    style LOCAL_WIN fill:#69f
    style WRITE fill:#6f6
```

## プライバシーパイプライン フロー 🔵

**信頼性**: 🔵 *REQ-010〜017, ADR-0006*

```mermaid
flowchart TD
    START[git-push 開始] --> PAD{extra_padding_bytes_max > 0?}
    PAD -->|Yes| GEN_PAD[ランダムパディング生成<br/>0 〜 max バイト]
    GEN_PAD --> REWRITE[write_vault 再実行<br/>vault.pqd にパディング反映]
    PAD -->|No| AUTHOR

    REWRITE --> AUTHOR[Author匿名化<br/>pq-diary + random@localhost]
    AUTHOR --> MSG[コミットメッセージ定型化<br/>vault.toml の commit_message]
    MSG --> FUZZ{timestamp_fuzz_hours > 0?}
    FUZZ -->|Yes| GET_PREV[git log -1 で前回時刻取得]
    GET_PREV --> CALC[ファジング計算<br/>単調増加保証: fuzzed > prev]
    CALC --> SET_ENV[GIT_AUTHOR_DATE<br/>GIT_COMMITTER_DATE 設定]
    FUZZ -->|No| GIT_ADD

    SET_ENV --> GIT_ADD[git add vault.pqd vault.toml]
    GIT_ADD --> GIT_COMMIT[git commit<br/>--author / -m / env dates]
    GIT_COMMIT --> GIT_PUSH[git push origin]
    GIT_PUSH --> DONE[完了]

    style GEN_PAD fill:#69f
    style REWRITE fill:#69f
    style AUTHOR fill:#69f
    style CALC fill:#69f
    style GIT_PUSH fill:#6f6
```

## エラーハンドリングフロー 🔵

**信頼性**: 🔵 *EDGE-001〜006*

```mermaid
flowchart TD
    A[エラー発生] --> B{エラー種別}
    B -->|git未インストール| C["DiaryError::Git<br/>'git is not installed or not in PATH.<br/>Please install git to use sync features.'"]
    B -->|リモート未設定| D["DiaryError::Git<br/>'no remote repository configured.<br/>Run git-init --remote URL first.'"]
    B -->|.git未初期化| E["DiaryError::Git<br/>'not a git repository.<br/>Run git-init first.'"]
    B -->|既にgit初期化済み| F["DiaryError::Git<br/>'git repository already initialized<br/>in this vault.'"]
    B -->|リモートが空| G[No-op: マージ不要<br/>0 added, 0 updated]
    B -->|バックアップ復元失敗| H["DiaryError::Io<br/>'failed to restore vault.pqd<br/>from backup'"]
    B -->|git push失敗| I["DiaryError::Git<br/>'git push failed: {stderr}'"]
    B -->|git fetch失敗| J["DiaryError::Git<br/>'git fetch failed: {stderr}'"]

    C --> EXIT[exit 1]
    D --> EXIT
    E --> EXIT
    F --> EXIT
    H --> EXIT
    I --> EXIT
    J --> EXIT

    style C fill:#f66,color:#fff
    style D fill:#f66,color:#fff
    style E fill:#f66,color:#fff
    style F fill:#f66,color:#fff
    style G fill:#ccc
    style H fill:#f66,color:#fff
    style I fill:#f66,color:#fff
    style J fill:#f66,color:#fff
```

## 関連文書

- **アーキテクチャ**: [architecture.md](architecture.md)
- **型定義**: [types.rs](types.rs)
- **要件定義**: [requirements.md](../../spec/s8-git-sync/requirements.md)

## 信頼性レベルサマリー

- 🔵 青信号: 全件 (100%)
- 🟡 黄信号: 0件 (0%)
- 🔴 赤信号: 0件 (0%)

**品質評価**: 高品質
