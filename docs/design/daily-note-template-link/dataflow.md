# daily-note-template-link データフロー図

**作成日**: 2026-04-05
**関連アーキテクチャ**: [architecture.md](architecture.md)
**関連要件定義**: [requirements.md](../../spec/daily-note-template-link/requirements.md)

**【信頼性レベル凡例】**:
- 🔵 **青信号**: EARS要件定義書・設計文書・ユーザヒアリングを参考にした確実なフロー
- 🟡 **黄信号**: EARS要件定義書・設計文書・ユーザヒアリングから妥当な推測によるフロー
- 🔴 **赤信号**: EARS要件定義書・設計文書・ユーザヒアリングにない推測によるフロー

---

## 1. today コマンドフロー 🔵

**信頼性**: 🔵 *REQ-001〜004・ヒアリングQ1, Q6より*

```mermaid
sequenceDiagram
    participant U as ユーザー
    participant CLI as cli/commands
    participant DC as DiaryCore
    participant V as vault.pqd
    participant TE as TemplateEngine
    participant ED as $EDITOR

    U->>CLI: pq-diary today
    CLI->>CLI: get_password()
    CLI->>DC: new() + unlock(pw)
    DC->>V: read_vault() + 全エントリ復号
    DC->>DC: LinkIndex::build() (unlock拡張)

    CLI->>DC: list_entries(None)
    DC-->>CLI: Vec<EntryMeta>
    CLI->>CLI: 「YYYY-MM-DD」タイトルを検索

    alt 当日エントリが存在
        CLI->>DC: get_entry(id_prefix)
        DC-->>CLI: (EntryRecord, EntryPlaintext)
        CLI->>ED: write_header_file() + launch_editor()
        ED-->>CLI: ��集結果
        CLI->>CLI: read_header_file()
        CLI->>DC: update_entry(uuid, plaintext)
    else 当日エントリなし
        CLI->>DC: get_template("daily")
        alt dailyテンプレート存在
            DC-->>CLI: TemplatePlaintext
            CLI->>TE: expand(body, {date, datetime, title})
            TE-->>CLI: 展開済みbody
        else テン��レートなし
            CLI->>CLI: body = ""
        end
        CLI->>ED: write_header_file() + launch_editor()
        ED-->>CLI: 編集結果
        CLI->>CLI: read_header_file()
        CLI->>DC: new_entry(title, body, tags)
    end

    CLI->>DC: lock()
```

## 2. テンプレートCRUD フロー 🔵

**信頼性**: 🔵 *REQ-101〜105・ADR-0005より*

### template add

```mermaid
sequenceDiagram
    participant U as ユーザー
    participant CLI as cli/commands
    participant DC as DiaryCore
    participant CE as CryptoEngine
    participant V as vault.pqd
    participant ED as $EDITOR

    U->>CLI: pq-diary template add <name>
    CLI->>CLI: get_password()
    CLI->>DC: new() + unlock(pw)

    CLI->>DC: get_template(name)
    alt テンプレート既存
        DC-->>CLI: TemplatePlaintext
        CLI->>U: 上書き確認プロンプト
        alt ユーザーが拒否
            CLI->>DC: lock()
            CLI-->>U: 中止
        end
    end

    CLI->>ED: write_template_file(tmpdir) + launch_editor()
    ED-->>CLI: 編集結果
    CLI->>CLI: read_template_file()

    CLI->>DC: new_template(name, body)
    DC->>DC: TemplatePlaintext { name, body }
    DC->>CE: serde_json → encrypt()
    CE-->>DC: ciphertext + signature + hmac
    DC->>V: write_vault() with RECORD_TYPE_TEMPLATE
    DC-->>CLI: Ok(uuid_hex)

    CLI->>DC: lock()
    CLI-->>U: テンプレート作成完了
```

### template list / show / delete

```mermaid
sequenceDiagram
    participant U as ユーザー
    participant CLI as cli/commands
    participant DC as DiaryCore
    participant V as vault.pqd

    U->>CLI: pq-diary template list
    CLI->>CLI: get_password()
    CLI->>DC: new() + unlock(pw)
    CLI->>DC: list_templates()
    DC->>V: read_vault() → filter(type==0x02)
    DC-->>CLI: Vec<TemplateMeta>
    CLI->>CLI: アルファベット順ソート表示
    CLI->>DC: lock()
```

## 3. new --template フロー 🔵

**信頼性**: 🔵 *REQ-111〜114・ヒアリングQ2, Q4より*

```mermaid
sequenceDiagram
    participant U as ユーザー
    participant CLI as cli/commands
    participant DC as DiaryCore
    participant TE as TemplateEngine
    participant ED as $EDITOR

    U->>CLI: pq-diary new --template <name> "Title"
    CLI->>CLI: get_password()
    CLI->>DC: new() + unlock(pw)

    CLI->>DC: get_template(name)
    DC-->>CLI: TemplatePlaintext { name, body }

    CLI->>TE: extract_variables(body)
    TE-->>CLI: Vec<VariableRef>

    CLI->>CLI: 基本変数を自動設定
    Note right of CLI: date=YYYY-MM-DD<br/>datetime=YYYY-MM-DD HH:MM:SS<br/>title=引数のTitle

    loop カスタム変数ごと
        CLI->>U: プロンプト「{var_name} の値:」
        U-->>CLI: 入力値
    end

    CLI->>TE: expand(body, all_vars)
    TE-->>CLI: ��開済み body

    CLI->>ED: write_header_file() + launch_editor()
    ED-->>CLI: 編集結果
    CLI->>CLI: read_header_file()
    CLI->>DC: new_entry(title, body, tags)
    CLI->>DC: lock()
```

## 4. show コマンド（リンク解決 + バックリンク）フロー 🔵

**信頼性**: 🔵 *REQ-201〜211・ADR-0004・ヒアリングQ3, Q5より*

```mermaid
sequenceDiagram
    participant U as ユーザー
    participant CLI as cli/commands
    participant DC as DiaryCore
    participant LP as LinkParser
    participant LI as LinkIndex

    U->>CLI: pq-diary show <id>
    CLI->>CLI: get_password()
    CLI->>DC: new() + unlock(pw)
    Note right of DC: unlock時にLinkIndex構築済み

    CLI->>DC: get_entry(id_prefix)
    DC-->>CLI: (EntryRecord, EntryPlaintext)

    CLI->>DC: resolve_links(body)
    DC->>LP: parse(body) → Vec<&str> (タイトル抽出)
    LP-->>DC: ["エントリB", "エントリC"]
    DC->>LI: lookup("エントリB"), lookup("エントリC")
    LI-->>DC: ResolvedLink { title, uuids, resolved }
    DC-->>CLI: Vec<ResolvedLink>

    CLI->>CLI: 本文表示 (リンク情報付き)
    Note right of CLI: [[エントリB]] → [abcd1234]<br/>[[不明]] → (未解決)

    CLI->>DC: backlinks_for(this_title)
    DC->>LI: reverse_lookup(title)
    LI-->>DC: Vec<EntryMeta>
    DC-->>CLI: バックリンク一覧

    CLI->>CLI: --- Backlinks --- セクション表示
    CLI->>DC: lock()
```

## 5. vim補完フロー 🔵

**信頼性**: 🔵 *ADR-0004・REQ-301〜303より*

```mermaid
sequenceDiagram
    participant CLI as cli/commands
    participant DC as DiaryCore
    participant ED as editor.rs
    participant VIM as vim/nvim
    participant FS as secure_tmpdir

    CLI->>DC: all_titles()
    DC-->>CLI: Vec<String>

    CLI->>ED: write_completion_file(tmpdir, titles)
    ED->>FS: タイトル一覧書き出し (1行1タイトル)
    FS-->>ED: PathBuf

    CLI->>ED: vim_completion_options(completion_file_path)
    ED-->>CLI: ["-c", "set completefunc=... | set noswapfile ..."]

    CLI->>ED: launch_editor(tmpfile, config)
    Note right of ED: config.vim_options にセキュリティ<br/>+ 補完関数オプションを結合

    VIM->>VIM: ユーザーが [[  入力後 Ctrl-X Ctrl-U
    VIM->>FS: 補完フ��イル読み込み
    VIM-->>VIM: タイトル候補表示

    VIM-->>CLI: 編集完了

    CLI->>ED: zeroize_and_delete(completion_file)
    ED->>FS: zeroize → unlink
```

### vim補完関数の詳細 🔵

**信頼性**: 🔵 *ADR-0004より*

エディタ起動時に注入する `-c` オプション:

```vim
" completefunc の設定 (Ctrl-X Ctrl-U でトリガー)
set completefunc=PqDiaryComplete

function! PqDiaryComplete(findstart, base)
  if a:findstart
    " カーソル位置から [[ を逆方向検索
    let line = getline('.')
    let start = col('.') - 1
    while start > 1 && line[start-2:start-1] != '[['
      let start -= 1
    endwhile
    return start
  else
    " 補完候補ファイルから読み込み
    let titles = readfile('{completion_file_path}')
    return filter(titles, 'v:val =~ "^" . a:base')
  endif
endfunction
```

## 6. LinkIndex 構築フロー（unlock拡張）🔵

**信頼性**: 🔵 *REQ-203・ヒアリングQ3より*

```mermaid
flowchart TD
    A[DiaryCore::unlock] --> B[既存: CryptoEngine初期化]
    B --> C[list_entries で全エントリ取得]
    C --> D[各エン���リの body を LinkParser でパース]
    D --> E{[[タイトル]] あり?}
    E -->|Yes| F[forward_map: タイトル → Vec UUID に追加]
    E -->|No| G[スキップ]
    F --> H[reverse_map: 被参照UUID → 参照元UUID に追加]
    G --> I[次のエントリ]
    H --> I
    I --> D
    D -->|全エントリ処理済み| J[LinkIndex { forward_map, reverse_map, title_map }]
    J --> K[self.link_index = Some に設定]
```

## エラーハンドリングフロー 🔵

**信頼性**: 🔵 *既存エラーパターンより*

```
DiaryError (thiserror)
├── TemplateNotFound(String)     # NEW: テンプレート名が見つからない
├── TemplateAlreadyExists(String) # NEW: 同名テンプレートが既に存在
├── InvalidTemplateName(String)   # NEW: テンプレート名バリデーション失敗
├── LinkResolutionError(String)   # NEW: リンク解決エラー
├── VaultNotFound                 # 既存
├── NotUnlocked                   # 既存
├��─ Entry(String)                 # 既存
├── Crypto(String)                # 既存
└── InvalidArgument(String)       # 既存
```

## 状態管理 🔵

**信頼性**: 🔵 *既存パターンより*

```
DiaryCore 状態遷移:
  Locked (engine=None, link_index=None)
    → unlock(pw)
  Unlocked (engine=Some, link_index=Some)
    → lock()
  Locked (engine=None, link_index=None, zeroized)
```

LinkIndex のライフサイクルは CryptoEngine と完全に同期。

## 関連文書

- **アーキテクチャ**: [architecture.md](architecture.md)
- **型定義**: [types.rs](types.rs)
- **要件定義**: [requirements.md](../../spec/daily-note-template-link/requirements.md)

## 信頼性レベルサマリー

- 🔵 青信号: 7件 (100%)
- 🟡 黄信号: 0件 (0%)
- 🔴 赤信号: 0件 (0%)

**品質評価**: 高品質
