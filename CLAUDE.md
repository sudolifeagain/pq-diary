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
- 外部入力・I/Oなどの失敗は `Result` で返す。`unwrap()` / `expect()` は原則テストのみ。不変条件に基づく本番コードの例外は根拠とテストを明示し、局所的に扱う。`unwrap_or_else(|_| unreachable!())` への書換えで規約を回避しない。失敗しないgetterまで `Result` 化しない
- エラーは `thiserror` で定義。`anyhow` はcli/のみ許可。失敗時に半端な状態や秘密値を残さず、検証が完了してから状態を反映する
- プラットフォーム分岐は `#[cfg()]` で。core/ にプラットフォーム依存UIコードを入れない
- 単体テストは各モジュールの `#[cfg(test)] mod tests`、機能の組合せはintegration testやCLI smokeで検証する

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
├── CLAUDE.md
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
