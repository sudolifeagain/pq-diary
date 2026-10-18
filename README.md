# pq-diary

Rust製の、耐量子暗号を利用したCLIジャーナルツールです。日記、タグ、
テンプレート、添付ファイルを暗号化したvaultに保存します。

**利用手順は [ユーザーマニュアル](docs/user-guide.md) にまとめています。**
インストール、初期設定、日々の操作、バックアップ、更新、アンインストールを参照できます。

## 最初の日記を書く

Rustの導入とエディタの準備を済ませたターミナルで、リポジトリのルートから実行します。

```sh
cargo install --path cli --locked
pq-diary init
pq-diary new "はじめての日記" -t 日記
pq-diary list
```

`init` では新しいマスターパスワードを2回入力します。
日記本文は `$EDITOR` で編集し、保存してエディタを終了すると暗号化保存されます。
Unixの既定エディタは `vi`、Windowsは `notepad` です。

実行ファイルの削除は `cargo uninstall pq-diary` です。**日記や設定は残ります。**
必要なRust環境、PATH設定、保存先の変更方法はマニュアルを参照してください。

## 開発状況

現在はpre-1.0で、配布バイナリのリリースはまだありません。
暗号クレートには個人フォークを含み、すべての機能の安全性が外部監査済みという状態ではありません。
利用前に [現在の実装状況](docs/development-inventory.md) と
[変更履歴](CHANGELOG.md) を確認してください。Git同期には未完了のケースがあります。

## 開発者向け資料

- [要件定義](requirements.md)
- [開発フロー・検証手順](docs/workflow.md)
- [完了条件](docs/definition-of-done.md)
- [設計判断](docs/adr/README.md)

ライセンス: [GPL-3.0-or-later](LICENSE)
