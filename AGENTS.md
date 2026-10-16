# pq-diary

Rust製・耐量子暗号CLIジャーナルツール。詳細は `requirements.md` (v4.0) を参照。

## Tech Stack

- **言語**: Rust (2021 edition)
- **ワークスペース**: `core/` (pq-diary-core ライブラリ) + `cli/` (バイナリ)
- **暗号**: `aes-gcm`, `argon2`, `ml-kem`/`ml-dsa` (RustCryptoフォーク), `zeroize`, `secrecy`
- **CLI**: `clap` (derive)
- **その他**: `uuid`, `chrono`, `nix`(unix), `windows-sys`(win)

## Rust規約

- Cargo workspaceの共有lintを各crateで継承し、`unsafe_code` / `unsafe_op_in_unsafe_fn` / `clippy::undocumented_unsafe_blocks` を deny（integration testなど別targetも対象）。例外は必要なOS呼出し境界だけに局所化し、各ブロックに `SAFETY:` で有効期間・境界・所有権などの根拠を書く。テストも例外にしない
- 許可するOS API: `mlock` / `munlock`、`VirtualLock` / `VirtualUnlock`、`prctl(PR_SET_DUMPABLE)`、`IsDebuggerPresent`、`GetErrorMode` / `SetErrorMode`、`GetStdHandle` / `GetConsoleMode` / `SetConsoleMode` / `ReadConsoleW`。これ以外の `unsafe` や、解放済みメモリを読むテストは禁止
- 秘密値の所有者は `Zeroizing` / `SecretString` / `SecureBuffer` / `ZeroizeOnDrop` 実装型で保護する。借用は必要な範囲に限定し、通常の `String` / `Vec<u8>` への複製や所有権移動で保護を失わない。秘密型の `Debug` は内容を伏せる
- 一時平文ファイルは作成時点から所有者を持たせる。cleanup失敗の警告と元のエラーの優先順位を、成功経路だけでなく失敗・早期return・unwindでもテストする
- 外部入力・I/Oなどの失敗は `Result` で返す。`unwrap()` はテストのみ許可。`expect()` も原則テストのみで、唯一の限定例外は開発者がソースに固定した不変の正規表現リテラルを一度だけコンパイルする初期化とする。この例外には、入力がリテラルである根拠のコメント、理由を説明する `expect` メッセージ、同じ定数をコンパイルする明示的な単体テストが必要。ユーザー入力・設定・I/O・実行時に構築したパターンには適用せず、`Result` を維持する。lintの広域無効化は禁止
- `unwrap_or_else(|_| unreachable!())` への書換えや空の結果へのfallbackで失敗を隠さない。失敗しないgetterや固定パターン利用APIまで規約のためだけに `Result` 化しない。固定値の根拠を明記する考え方は [Rust Book](https://doc.rust-lang.org/book/ch09-03-to-panic-or-not-to-panic.html#when-you-have-more-information-than-the-compiler) に従う
- エラーは `thiserror` で定義。`anyhow` はcli/のみ許可。失敗時に半端な状態や秘密値を残さず、検証が完了してから状態を反映する
- プラットフォーム分岐は `#[cfg()]` で。core/ にプラットフォーム依存UIコードを入れない
- 単体テストは各モジュールの `#[cfg(test)] mod tests`、機能の組合せはintegration testやCLI smokeで検証する

- コマンド認証のリファクタリングではpolicy/confirmationと秘密取得の既存順序を保ち、複数回利用する認証情報（newの添付・import等）は意図を明記する

## I/O変更時の契約

- 一時ファイル・stagingは排他的作成に成功してから所有し、rollbackは自分が作成したものだけを対象にする。既存ファイル・symlink・他者の追加物を削除しない。`core/src/vault/atomic_file.rs` の `OwnedTemp` / `write_atomic` と `init.rs` の `InitStaging` を参照し、親ディレクトリが管理下にある前提も保つ
- commit点を明示し、commit前の失敗では原本保全・rollbackを確認する。commit後のcleanup失敗を「保存されなかった」エラーに変えず、元の失敗とcleanup警告を区別する。atomic renameだけで物理消去やcrash耐久性まで保証したと扱わない
- 認証したバイト列そのものをparseし、検証後に同じパスを開き直さない。read-modify-writeは `read_vault_with_attachments_authenticated` の同一snapshotからレコードと添付を引き継ぐ
- 「存在しなければ作成」の分岐は `DiaryError::TemplateNotFound` 等の型付き不在だけに限定する。`is_err()` / `Err(_)` で破損・認証・権限・I/Oエラーまで不在扱いしない
- CLI出力は `cmd_template_show_with_writer` のようにfallibleなwriterと明示的 `flush` で失敗を返す。`Drop` の警告は `EditorSession` のようにstderr失敗でもpanicさせず、元のエラーを隠さない

## テスト・CI方針

- 個人運用のため、通常PRのCIは短いLinux検証を標準とする。fmt、build、workspace test（doctestを含む）、Clippy、既存debugバイナリを使うCLI smokeを実行する。脆弱性監査と依存ポリシー検査は維持する
- 全OS/ARM・release・Miri・長時間/性能/大量データの検証を毎PR必須にしない。変更リスクに応じ、作業環境または手動実行で必要な検証を行う。OS API/unsafe/依存・ツールチェーン変更では対象環境を、保存形式/鍵更新では混在データ・失敗時保全・互換性を重点確認する
- GitHub Actionsの `workflow_dispatch` で `full_matrix=true` にすると、macOS/Windowsのcheckと4環境のrelease smokeも実行できる。対象OSで検証できなかった場合は、成功扱いせずPRに未検証範囲と理由を残す
- 不具合修正は、修正前に失敗して修正後に成功する小さい回帰テストを優先する。テスト件数・網羅率だけを完了根拠にしない。I/O失敗は戻り値だけでなく原本・設定・再読込可能性を確認する
- テスト時間は環境・コマンド・cache状態と併記して測定する。根拠のない秒数上限を設けず、同じ検査の重複や不要な再ビルドから減らす。新しいlintは目的に沿って個別選択し、`restriction` / `pedantic` の一括強制はしない
- PRには再現手順、回帰テスト、検証結果・実測時間、実行しなかった検証と理由を書く。詳細は `docs/workflow.md` と `docs/definition-of-done.md` を参照

## ドキュメント

| ファイル | 用途 |
|---------|------|
| `requirements.md` | 要件定義書 v4.0 (正) |
| `docs/workflow.md` | 開発フロー・Tsumikiコマンド順・ブランチ戦略 |
| `docs/sprint-status.md` | 現在のスプリント状態・スコープ |
| `docs/backlog.md` | プロダクトバックログ (Phase 1-4 + OQ) |
| `docs/definition-of-done.md` | スプリント完了チェックリスト |
| `docs/adr/` | Architecture Decision Records |

## ディレクトリ構造

```
pq-diary/
├── AGENTS.md
├── requirements.md
├── docs/
│   ├── workflow.md
│   ├── sprint-status.md
│   ├── backlog.md
│   ├── definition-of-done.md
│   ├── adr/NNNN-*.md
│   ├── spec/               # kairo-requirements 出力
│   ├── design/             # kairo-design 出力
│   ├── tasks/              # kairo-tasks 出力
│   └── implements/         # TDDサイクル出力
├── core/                   # pq-diary-core
│   ├── Cargo.toml
│   └── src/
└── cli/                    # pq-diary (binary)
    ├── Cargo.toml
    └── src/
```

## 開発フロー

`docs/workflow.md` を参照。概要:

1. `git checkout -b sprint/s{N}`
2. `/tsumiki:kairo-requirements` → `/tsumiki:kairo-design` → `/tsumiki:kairo-tasks`
3. `/tsumiki:kairo-implement` (TDDサイクル自動実行)
4. `docs/definition-of-done.md` 確認
5. PR経由で `main` へマージ。S14以降はスプリントタグを付けず、Phase完了時のみタグを付ける

## 設計決定事項

- **リンク記法**: `[[タイトル]]` (Obsidian互換)。$EDITOR内でvim補完関数によるタイトル自動補完を提供
- **テンプレート**: vault.pqd内に暗号化格納
- **v4フォーマット**: 添付ファイル用予約フィールドを含める (実装はPhase 2)
- **インポート**: Obsidian `[[wiki-link]]` / `#ネスト/タグ` をpq-diary形式に自動変換
