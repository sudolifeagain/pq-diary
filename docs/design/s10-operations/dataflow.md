# S10 運用機能 + CLI整合性 データフロー図

**作成日**: 2026-05-17
**関連アーキテクチャ**: [architecture.md](architecture.md)
**関連要件定義**: [requirements.md](../../spec/s10-operations/requirements.md)

**【信頼性レベル】**: 全項目🔵 (要件定義 + 設計ヒアリング 2026-05-17 + 既存実装パターンで確定済み)

---

## システム全体のデータフロー 🔵

```mermaid
flowchart TD
    User[ユーザー] -->|CLI 起動| Main[cli/src/main.rs<br/>Commands enum]
    Main -->|dispatch| Cmd[cli/src/commands.rs<br/>cmd_init/cmd_sync/cmd_export/<br/>cmd_change_password/cmd_info]
    Cmd -->|--claude チェック| Policy[check_claude_policy]
    Cmd -->|パスワード取得| Pwd[get_password<br/>flag/env/TTY 3段階]
    Cmd -->|core API| Core[core/ ライブラリ]
    Core -->|VaultManager| Vault[(vault.pqd<br/>vault.toml)]
    Core -->|AppConfig| AppCfg[(~/.pq-diary/<br/>config.toml)]
    Core -->|git_sync| Git[git CLI 経由]
    Cmd -->|harden_status| Sec[security.rs]
    Sec -->|fs::read /proc<br/>getrlimit<br/>secure_mem| OS[OS]
```

## 主要機能のデータフロー

### 機能 1: `pq-diary init` 🔵

**関連要件**: REQ-101 〜 REQ-112

```mermaid
sequenceDiagram
    actor U as ユーザー
    participant M as main.rs
    participant CMD as cmd_init
    participant CFG as AppConfig
    participant VM as VaultManager
    participant FS as ファイルシステム

    U->>M: pq-diary init
    M->>CMD: cmd_init(cli)
    CMD->>CFG: default_path() → ~/.pq-diary/config.toml
    CFG-->>CMD: PathBuf
    CMD->>FS: exists? config.toml
    alt 既存
        FS-->>CMD: true
        CMD-->>U: Error: Already initialized at ~/.pq-diary/
    else 新規
        FS-->>CMD: false
        CMD->>U: TTY パスワード入力プロンプト
        U->>CMD: 新パスワード (SecretString)
        CMD->>FS: create_dir_all(~/.pq-diary/)
        CMD->>CFG: AppConfig::default().to_file(path)
        CFG->>FS: write config.toml (0600)
        CMD->>VM: VaultManager::new(~/.pq-diary/vaults/)
        VM->>VM: create_vault("default", pwd, Policy::None)
        VM->>FS: write vault.pqd / vault.toml / entries/
        alt vault 作成失敗
            VM-->>CMD: DiaryError
            CMD->>FS: remove config.toml + zeroize
            CMD-->>U: Error
        else 成功
            VM-->>CMD: Ok
            CMD-->>U: Initialized pq-diary at ~/.pq-diary/
        end
    end
```

### 機能 2: `pq-diary sync` 🔵

**関連要件**: REQ-201 〜 REQ-212

```mermaid
sequenceDiagram
    actor U as ユーザー
    participant M as main.rs
    participant CMD as cmd_sync
    participant CFG as AppConfig
    participant GIT as cmd_git_sync

    U->>M: pq-diary sync
    M->>CMD: cmd_sync(cli)
    CMD->>CFG: default_path() / from_file
    alt config.toml 不在
        CFG-->>CMD: DiaryError::Io
        CMD-->>U: Error: pq-diary init を先に実行してください
    else config.toml あり
        CFG-->>CMD: AppConfig
        alt sync_backend == "git"
            CMD->>GIT: cmd_git_sync(cli)
            GIT-->>CMD: Result
            CMD-->>U: (git_sync の結果)
        else 不明値
            CMD-->>U: Error: Unknown sync backend: {value}
        end
    end
```

### 機能 3: `pq-diary change-password` 🔵 (最重要)

**関連要件**: REQ-301 〜 REQ-314

```mermaid
sequenceDiagram
    actor U as ユーザー
    participant CMD as cmd_change_password
    participant PWD as get_password
    participant DC as DiaryCore
    participant E as entry module
    participant VM as VaultManager
    participant FS as ファイルシステム

    U->>CMD: pq-diary change-password
    CMD->>PWD: get_password() (旧)
    PWD->>U: TTY: Old password:
    U->>PWD: 旧パスワード
    PWD-->>CMD: SecretString(old)
    CMD->>DC: unlock(old)
    alt 旧パスワード不正
        DC-->>CMD: Crypto error
        CMD-->>U: Error: Old password is incorrect
    else 成功
        DC-->>CMD: Ok (vault unlocked)
        CMD->>U: TTY: New password:
        U->>CMD: 新パスワード1
        CMD->>U: TTY: Confirm new password:
        U->>CMD: 新パスワード2
        alt 新パスワード不一致
            CMD-->>U: Error: Passwords do not match
        else 新パスワード空
            CMD-->>U: Error: New password must not be empty
        else OK
            alt old == new
                CMD->>U: Warning: New password is identical to old
            end
            CMD->>E: list_entries_with_body(&core)
            E-->>CMD: Vec<EntryPlaintext> (SecretBytes 保持)
            CMD->>FS: write vault.pqd.tmp (新パスワードで init_vault)
            loop 各エントリ
                CMD->>E: create_entry into tmp with new key
            end
            alt 書き込み失敗
                CMD->>FS: zeroize delete vault.pqd.tmp
                CMD-->>U: Error: Write failed
            else 成功
                CMD->>FS: rename(vault.pqd.tmp, vault.pqd) アトミック
                CMD->>CMD: Drop で旧鍵・新鍵・全エントリ zeroize
                CMD-->>U: Password changed successfully
            end
        end
    end
```

#### change-password メモリ管理 🔵

| ステップ | 保持データ | 型 / 保護 |
|---|---|---|
| 1. 旧パスワード受取 | `old_pwd` | `SecretString` (Drop で zeroize) |
| 2. 旧鍵導出 | `old_key` | `ZeroizingKey` |
| 3. 全エントリ復号 | `entries: Vec<EntryPlaintext>` | `EntryPlaintext` は `ZeroizeOnDrop` (S5 で実装済み) |
| 4. 新パスワード受取 | `new_pwd` | `SecretString` |
| 5. 新鍵導出 | `new_key` | `ZeroizingKey` |
| 6. tmp に書き出し | (上記すべてスコープ内) | スコープ離脱で全部 zeroize |
| 7. rename 後 | (空) | メモリクリア完了 |

### 機能 4: `pq-diary info` / `info --security` 🔵

**関連要件**: REQ-401 〜 REQ-412

```mermaid
sequenceDiagram
    actor U as ユーザー
    participant CMD as cmd_info
    participant DC as DiaryCore
    participant VC as VaultConfig
    participant E as entry module
    participant SEC as security.rs::harden_status

    U->>CMD: pq-diary info [--security]
    CMD->>U: TTY: Password (or env/flag)
    U->>CMD: パスワード
    CMD->>DC: unlock(pwd)
    DC-->>CMD: Ok
    CMD->>VC: vault.toml 読み取り (DiaryCore 経由)
    VC-->>CMD: VaultConfig (name, policy, argon2)
    CMD->>E: list_entries (件数のみ)
    E-->>CMD: count
    CMD->>CMD: fs::metadata(vault.pqd) で created/modified
    alt --security
        CMD->>SEC: harden_status()
        SEC-->>CMD: HardenStatus { mlock, coredump, debugger }
        CMD->>U: 基本情報 + Argon2 + KEM/DSA + HardenStatus
    else
        CMD->>U: 基本情報のみ
    end
```

#### info 出力例 (`--security` あり) 🔵

```
=== Vault Info ===
Name:           default
Policy:         none
Entries:        42
Created:        2026-04-15 09:23:11 UTC
Last updated:   2026-05-17 11:42:03 UTC

=== Security ===
KEM algorithm:        ML-KEM-768
Signature algorithm:  ML-DSA-65
Argon2 memory:        65536 KB
Argon2 time cost:     3
Argon2 parallelism:   1
mlock active:         yes
Coredump disabled:    yes
Debugger detected:    no
```

### 機能 5: `pq-diary export DIR` 🔵

**関連要件**: REQ-501 〜 REQ-521

```mermaid
sequenceDiagram
    actor U as ユーザー
    participant CMD as cmd_export
    participant POL as check_claude_policy
    participant DC as DiaryCore
    participant E as entry module
    participant FS as ファイルシステム

    U->>CMD: pq-diary export ~/backup
    CMD->>POL: check (--claude?)
    alt --claude
        POL-->>CMD: Blocked
        CMD-->>U: Error: export is not permitted with --claude
    else OK
        CMD->>FS: exists? ~/backup
        alt 不在
            CMD-->>U: Error: Directory does not exist
        else 存在
            CMD->>U: 警告: 平文を ~/backup に書き出します。[y/N]
            U->>CMD: y / その他
            alt y 以外
                CMD-->>U: キャンセルしました
            else y
                CMD->>U: パスワードプロンプト
                U->>CMD: パスワード
                CMD->>DC: unlock
                CMD->>E: list_entries_with_body
                E-->>CMD: Vec<EntryPlaintext>
                alt 件数 0
                    CMD-->>U: No entries to export
                else 件数 ≥ 1
                    loop 各エントリ
                        CMD->>CMD: build_filename(date, title, id8)
                        CMD->>CMD: build_frontmatter + body
                        CMD->>FS: exists? target file
                        alt 既存
                            CMD-->>U: Error: File exists
                        else 新規
                            CMD->>FS: write MD ファイル
                        end
                    end
                    CMD-->>U: Exported N entries to ~/backup
                end
            end
        end
    end
```

#### export ファイル名生成ロジック 🔵

```
入力: created_date = 2026-05-17, title = "今日の出来事 #1", uuid = "3c6b775f-..."
処理:
  date_part = "2026-05-17"
  slug = slugify("今日の出来事 #1") = "今日の出来事-1"  (空白を - に、特殊文字を除去)
  id8 = "3c6b775f"
出力: "2026-05-17-今日の出来事-1-3c6b775f.md"

空タイトル時: slug = "untitled"
出力: "2026-05-17-untitled-3c6b775f.md"
```

#### export YAML フロントマター仕様 🔵

```markdown
---
id: 3c6b775f-4d8e-4c2b-9a1f-8d5e1f0a2b3c
title: "今日の出来事 #1"
tags:
  - test
  - smoke
created: 2026-05-17T09:23:11Z
updated: 2026-05-17T11:42:03Z
---

ここからエントリ本文
```

- YAML エスケープ: タイトルは常にダブルクォート括る + 内部の `"` と `\` をエスケープ
- tags が空の場合は `tags: []`
- 日時は ISO 8601 (RFC 3339) 形式、タイムゾーン UTC

## エラーハンドリングフロー 🔵

```mermaid
flowchart TD
    A[CLI コマンド実行] --> B{エラー種別}
    B -->|init: 既存 config.toml| C[anyhow::bail!: Already initialized]
    B -->|init/cp: 空パスワード| D[DiaryError::Password]
    B -->|sync: 不明 backend| E[anyhow::bail!: Unknown sync backend]
    B -->|sync: config 不在| F[anyhow::bail!: init を先に実行]
    B -->|cp: 旧パスワード不正| G[DiaryError::Crypto → anyhow]
    B -->|cp: 新パスワード不一致| H[anyhow::bail!: Passwords do not match]
    B -->|cp: write 失敗| I[zeroize tmp + anyhow]
    B -->|export: --claude| J[anyhow::bail!: not permitted]
    B -->|export: DIR 不在| K[anyhow::bail!: Directory does not exist]
    B -->|export: ファイル既存| L[anyhow::bail!: File exists]
    B -->|info: vault 破損| M[DiaryError::Config]
    C --> N[stderr 出力 + exit ≠ 0]
    D --> N
    E --> N
    F --> N
    G --> N
    H --> N
    I --> N
    J --> N
    K --> N
    L --> N
    M --> N
```

## 状態管理フロー 🔵

### AppConfig (config.toml) のライフサイクル

```mermaid
stateDiagram-v2
    [*] --> NotExists: 初期状態
    NotExists --> Created: pq-diary init
    Created --> Created: sync / info / list 等 (読み取りのみ)
    Created --> [*]: ユーザーが手動削除 → NotExists
```

### change-password 中の vault.pqd 状態遷移

```mermaid
stateDiagram-v2
    [*] --> Stable: vault.pqd (旧 key 暗号化)
    Stable --> Transitional: vault.pqd.tmp 書き込み開始
    Transitional --> Stable: 書き込み失敗 → tmp zeroize 削除
    Transitional --> Updated: rename(tmp, vault.pqd) アトミック
    Updated --> [*]: vault.pqd (新 key 暗号化)
```

## データ整合性の保証 🔵

| 操作 | 保証手段 |
|---|---|
| AppConfig 書き込み | `.tmp + rename` (writer.rs の既存パターン踏襲) |
| vault.pqd 書き込み (change-password) | 全エントリ再暗号化を tmp に完了してから rename。中断時は旧 vault.pqd 維持 |
| export 出力ファイル | 既存ファイルは上書きせずエラー (REQ-EDGE-004) |
| init の部分作成 | vault 作成失敗時に config.toml と作成済みディレクトリを zeroize 削除 (REQ-112) |

## 関連文書

- **アーキテクチャ**: [architecture.md](architecture.md)
- **型定義**: [types.rs](types.rs)
- **スキーマ**: [schema.md](schema.md)
- **CLI 仕様**: [cli-commands.md](cli-commands.md)
- **要件定義**: [requirements.md](../../spec/s10-operations/requirements.md)

## 信頼性レベルサマリー

- 🔵 青信号: 全項目 (100%)
- 🟡 黄信号: 0 件
- 🔴 赤信号: 0 件

**品質評価**: 最高品質。全フローが要件定義 + 設計ヒアリング + 既存実装で確定済み。
