# daily-note-template-link アーキテクチャ設計

**作成日**: 2026-04-05
**関連要件定義**: [requirements.md](../../spec/daily-note-template-link/requirements.md)
**ヒアリング記録**: [design-interview.md](design-interview.md)

**【信頼性レベル凡例】**:
- 🔵 **青信号**: EARS要件定義書・設計文書・ユーザヒアリングを参考にした確実な設計
- 🟡 **黄信号**: EARS要件定義書・設計文書・ユーザヒアリングから妥当な推測による設計
- 🔴 **赤信号**: EARS要件定義書・設計文書・ユーザヒアリングにない推測による設計

---

## システム概要 🔵

**信頼性**: 🔵 *要件定義書・バックログS5より*

Sprint 5 はデイリーノート（todayコマンド）、テンプレートCRUD（暗号化格納）、`[[タイトル]]` リンク解決とバックリンク表示、vim補完関数の4機能を追加する。既存の core/cli 2層アーキテクチャを維持し、core にドメインロジック、cli にプラットフォーム依存UIを配置する。

## アーキテクチャパターン 🔵

**信頼性**: 🔵 *CLAUDE.md・既存設計より*

- **パターン**: ファサード + レイヤードアーキテクチャ（S1〜S4 と同一）
- **core/**: `DiaryCore` ファサード経由で全ドメインロジックにアクセス
- **cli/**: 薄いラッパー（パスワード入力・$EDITOR制御・UI表示）
- **選択理由**: 既存パターン踏襲。将来のUniFFI対応のため core にプラットフォーム依存コードを入れない

## コンポーネント構成

### 新規モジュール

#### `core/src/template.rs` 🔵

**信頼性**: 🔵 *ADR-0005・REQ-101〜105より*

テンプレートCRUDロジック。`entry.rs` と同パターンで実装。

```
TemplatePlaintext → serde_json → CryptoEngine::encrypt() → EntryRecord(type=0x02)
EntryRecord(type=0x02) → CryptoEngine::decrypt() → serde_json → TemplatePlaintext
```

主要関数:
- `create_template(vault_path, engine, template) -> Result<Uuid>`
- `list_templates(vault_path, engine) -> Result<Vec<TemplateMeta>>`
- `get_template(vault_path, engine, name) -> Result<TemplatePlaintext>`
- `delete_template(vault_path, engine, name) -> Result<()>`

#### `core/src/link.rs` 🔵

**信頼性**: 🔵 *ADR-0004・REQ-201〜211より*

`[[タイトル]]` リンクのパーサーとバックリンクインデックス。

主要型:
- `LinkParser`: `[[...]]` パターンの抽出。`regex` クレート使用
- `LinkIndex`: タイトル → UUID リスト、UUID → バックリンクUUID リストのマッピング
- `ResolvedLink`: 解決済みリンク情報（タイトル、UUID リスト、解決状態）

#### `core/src/template_engine.rs` 🔵

**信頼性**: 🔵 *REQ-111〜114・ヒアリングQ2, Q4より*

テンプレート変数展開エンジン。

主要関数:
- `extract_variables(body) -> Vec<VariableRef>`: `{{var_name}}` パターンを抽出
- `expand(body, vars: &HashMap<String, String>) -> String`: 変数展開

基本変数: `{{date}}`, `{{datetime}}`, `{{title}}`
カスタム変数: それ以外の `{{var_name}}`。CLI側でプロンプト入力。

### 既存モジュール拡張

#### `core/src/lib.rs` (DiaryCore) 🔵

**信頼性**: 🔵 *既存パターン・ヒアリングQ2より*

```rust
pub struct DiaryCore {
    vault_path: PathBuf,
    engine: Option<CryptoEngine>,
    config: VaultConfig,
    link_index: Option<LinkIndex>,  // NEW: バックリンクインデックス
}
```

追加メソッド:
- `new_template(name, body) -> Result<String>`
- `list_templates() -> Result<Vec<TemplateMeta>>`
- `get_template(name) -> Result<TemplatePlaintext>`
- `delete_template(name) -> Result<()>`
- `resolve_links(body) -> Vec<ResolvedLink>`
- `backlinks_for(title) -> Vec<EntryMeta>`
- `all_titles() -> Vec<String>` (vim補完用)

unlock 拡張: エントリスキャン → LinkIndex 構築
lock 拡張: LinkIndex の zeroize + None 化

#### `cli/src/main.rs` 🔵

**信頼性**: 🔵 *既存CLIスケルトンより*

- `Commands::New` に `--template <name>` フラグ追加
- `Commands::Today`, `Commands::Template { .. }` のディスパッチ実装

#### `cli/src/commands.rs` 🔵

**信頼性**: 🔵 *既存コマンドパターンより*

追加関数:
- `cmd_today(cli)`: 当日エントリ検索 → 存在すれば edit / なければ new（dailyテンプレート適用）
- `cmd_template_add(cli, name)`: $EDITOR → TemplatePlaintext → create_template
- `cmd_template_list(cli)`: list_templates → 表示
- `cmd_template_show(cli, name)`: get_template → 表示
- `cmd_template_delete(cli, name)`: 確認プロンプト → delete_template
- `cmd_new` 拡張: `--template` 指定時にテンプレート展開

#### `cli/src/editor.rs` 🔵

**信頼性**: 🔵 *ADR-0004・既存editor.rsより*

追加関数:
- `write_completion_file(tmpdir, titles) -> Result<PathBuf>`: タイトル一覧ファイル生成
- `vim_completion_options(completion_file) -> Vec<String>`: vim `-c` オプション生成
- `zeroize_and_delete(path)` は既存関数を再利用

## システム構成図 🔵

**信頼性**: 🔵 *既存設計・要件定義より*

```
┌─────────────────────────────────────────────────────┐
│                      cli/                            │
│                                                      │
│  main.rs ─── commands.rs ─┬─ cmd_today()             │
│       │                   ├─ cmd_template_add/...    │
│       │                   └─ cmd_new (--template)    │
│       │                                              │
│       └── editor.rs ──── write_completion_file()     │
│                     └─── vim_completion_options()     │
│                                                      │
│  password.rs (既存)                                  │
├──────────────────────────────────────────────────────┤
│                      core/                           │
│                                                      │
│  lib.rs (DiaryCore) ─── link_index: Option<LinkIndex>│
│       │                                              │
│       ├── template.rs ── TemplatePlaintext           │
│       │                  create/list/get/delete       │
│       │                                              │
│       ├── template_engine.rs ── expand(), extract()  │
│       │                                              │
│       ├── link.rs ── LinkParser, LinkIndex            │
│       │              ResolvedLink                     │
│       │                                              │
│       ├── entry.rs (既存拡張)                         │
│       │                                              │
│       └── vault/ (既存: format, reader, writer)      │
│              RECORD_TYPE_TEMPLATE = 0x02             │
└──────────────────────────────────────────────────────┘
```

## ディレクトリ構造 🔵

**信頼性**: 🔵 *既存プロジェクト構造より*

```
core/src/
├── lib.rs              # DiaryCore (link_index フィールド追加)
├── entry.rs            # 既存 (変更なし)
├── template.rs         # NEW: テンプレート CRUD
├── template_engine.rs  # NEW: 変数展開エンジン
├── link.rs             # NEW: リンクパーサー + バックリンクインデックス
├── error.rs            # DiaryError (TemplateNotFound 追加)
├── crypto/             # 既存 (変更なし)
└── vault/              # 既存 (変更なし)

cli/src/
├── main.rs             # --template フラグ追加 + ディスパッチ実装
├── commands.rs         # cmd_today + テンプレート系コマンド追加
├── editor.rs           # 補完ファイル生成 + vim補完オプション追加
└── password.rs         # 既存 (変更なし)
```

## 非機能要件の実現方法

### パフォーマンス 🟡

**信頼性**: 🟡 *NFR-001, NFR-002から妥当な推測*

- **バックリンクインデックス構築**: O(N*M) (N=エントリ数, M=平均リンク数)。100エントリ × 5リンク = 500回のタイトル照合。HashMap使用で各照合O(1)、目標200ms以内
- **テンプレート変数展開**: regex の `replace_all` で単一パスO(n)。目標10ms以内
- **リンクパース**: 正規表現 `\[\[([^\[\]]+)\]\]` で単一パス抽出

### セキュリティ 🔵

**信頼性**: 🔵 *CLAUDE.md・ADR-0004, ADR-0005・NFR-101, NFR-102より*

- **テンプレート暗号化**: エントリと同一パイプライン（AES-256-GCM + ML-DSA-65 + HMAC-SHA256）
- **補完用ファイル**: secure_tmpdir 上に配置。タイトルのみ（本文・タグなし）。zeroize削除
- **LinkIndex**: タイトル文字列を含むためlock時にゼロクリア。Zeroize trait 実装
- **TemplatePlaintext**: Zeroize trait 実装（テンプレート内容は秘密データ）

### テスト戦略 🔵

**信頼性**: 🔵 *既存テストパターンより*

- **unit tests**: 各モジュールに `#[cfg(test)] mod tests`
  - `template.rs`: CRUD ラウンドトリップ、重複名、境界値
  - `link.rs`: パース正確性、空リンク、バックリンク構築
  - `template_engine.rs`: 基本変数展開、カスタム変数、同一変数複数出現
- **integration tests**: `cli/tests/integration_test.rs` に追加
  - E2E: today → template add → new --template → show (リンク解決) → backlinks

## 技術的制約 🔵

**信頼性**: 🔵 *CLAUDE.md・要件定義より*

- `unsafe` 禁止（mlock/VirtualLock/PR_SET_DUMPABLE 以外）
- テンプレート・リンクインデックスの秘密データは `zeroize` 必須
- `unwrap()` / `expect()` はテストコードのみ
- core/ にプラットフォーム依存コード（$EDITOR起動・プロンプト）を入れない
- vim/neovim 以外のエディタでの補完は非サポート（フォールバック: 手動入力）

## 関連文書

- **データフロー**: [dataflow.md](dataflow.md)
- **型定義**: [types.rs](types.rs)
- **要件定義**: [requirements.md](../../spec/daily-note-template-link/requirements.md)
- **ADR-0004**: [エントリ間リンク記法](../../adr/0004-entry-link-notation.md)
- **ADR-0005**: [テンプレート保存方式](../../adr/0005-template-storage.md)

## 信頼性レベルサマリー

- 🔵 青信号: 14件 (93%)
- 🟡 黄信号: 1件 (7%)
- 🔴 赤信号: 0件 (0%)

**品質評価**: 高品質
