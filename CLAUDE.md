# pq-diary

Rust製・耐量子暗号CLIジャーナルツール。詳細は `requirements.md` (v4.0) を参照。

## Tech Stack

- **言語**: Rust (2021 edition)
- **ワークスペース**: `core/` (pq-diary-core ライブラリ) + `cli/` (バイナリ)
- **暗号**: `aes-gcm`, `argon2`, `ml-kem`/`ml-dsa` (RustCryptoフォーク), `zeroize`, `secrecy`
- **CLI**: `clap` (derive)
- **その他**: `uuid`, `chrono`, `nix`(unix), `windows-sys`(win)

## Rust規約

- `unsafe` は mlock/VirtualLock/PR_SET_DUMPABLE/Win32 Console API (GetConsoleMode/SetConsoleMode/ReadConsoleW) のみ許可。それ以外は禁止
- 秘密データは必ず `zeroize` / `SecretString` / `SecretBytes` で保持。生の `Vec<u8>` / `String` 禁止
- `unwrap()` / `expect()` はテストコードのみ許可。本番コードは `Result` を返す
- エラーは `thiserror` で定義。`anyhow` はcli/のみ許可
- プラットフォーム分岐は `#[cfg()]` で。core/ にプラットフォーム依存UIコードを入れない
- テストは各モジュールに `#[cfg(test)] mod tests` で配置

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
5. `main` へ `--no-ff` マージ + タグ `s{N}-done`

## 設計決定事項

- **リンク記法**: `[[タイトル]]` (Obsidian互換)。$EDITOR内でvim補完関数によるタイトル自動補完を提供
- **テンプレート**: vault.pqd内に暗号化格納
- **v4フォーマット**: 添付ファイル用予約フィールドを含める (実装はPhase 2)
- **インポート**: Obsidian `[[wiki-link]]` / `#ネスト/タグ` をpq-diary形式に自動変換
