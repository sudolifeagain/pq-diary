# pq-diary ユーザーマニュアル

## 1. 準備とインストール

現在の導入方法は、ソースコードからの `cargo install` です。
専用インストーラや配布済みバイナリはありません。

必要なもの:

- Git（ソース取得時。Git同期を使う場合も必要）
- Rust/Cargo。リポジトリは `rust-toolchain.toml` で **1.95.0** を指定しています。
  `rust-version` の下限は1.94ですが、この手順では指定ツールチェーンを使います。
- Rustのビルドに必要なリンカ。LinuxではディストリビューションのC開発環境、
  macOSではXcode Command Line Tools、WindowsのMSVC環境ではVisual StudioのC++ビルドツールを用意します。
- テキストエディタ（本文を編集する場合）

Rustは [公式の導入案内](https://rust-lang.org/tools/install/) に従って導入してください。
初回ビルドには依存クレートやGit依存を取得するネットワーク接続が必要です。

```sh
git clone https://github.com/sudolifeagain/pq-diary.git
cd pq-diary
cargo install --path cli --locked
pq-diary --version
```

すでにclone済みなら、そのリポジトリのルートで `cargo install` から実行します。
管理者権限や `sudo` は不要です。`--locked` はリポジトリの `Cargo.lock` に記録した依存を使います。

通常、実行ファイルは `~/.cargo/bin/`（Windowsは `%USERPROFILE%\.cargo\bin\`）に入ります。
コマンドが見つからない場合はターミナルを開き直してください。
一時的にPATHへ追加する例:

```sh
# Bash / Zsh
export PATH="$HOME/.cargo/bin:$PATH"
```

```powershell
# PowerShell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
```

Cargoの導入先は `--root`、`CARGO_INSTALL_ROOT`、`install.root`、`CARGO_HOME` により変わります。
独自の場所に置く場合は、導入・更新・削除で同じ `--root` を指定し、その `bin` をPATHに追加します。
例（Unix）:

```sh
cargo install --path cli --locked --root "$HOME/.local/pq-diary"
export PATH="$HOME/.local/pq-diary/bin:$PATH"
```

詳細は [Cargo installの公式仕様](https://doc.rust-lang.org/cargo/commands/cargo-install.html) を参照してください。
`cargo install pq-diary` はレジストリからの取得を意味するため、本手順の代用にはしません。

## 2. 初期設定

```sh
pq-diary init
```

新しいマスターパスワードを入力し、`Confirm new password:` でもう一度入力します。
入力内容は画面に表示されません。不一致や確認入力の失敗では設定やvaultを作成しません。
弱いパスワードの場合は、確認入力の前に続行確認があります。

既定では、以下を作成します。

```text
~/.pq-diary/
├── config.toml
└── vaults/default/
    ├── vault.pqd
    ├── vault.toml
    └── entries/
```

`vault.pqd` が暗号化された日記です。設定やディレクトリ全体もバックアップ対象にしてください。
初期化済みなら `init` を繰り返す必要はありません。更新・再インストール後もそのまま使えます。
マスターパスワードの再発行・リセット機能はありません。

試用データを分けるには、**初期化前に**専用の保存先を指定します。
以後のコマンドでも同じ設定を維持してください。

```sh
export PQ_DIARY_HOME="$HOME/.pq-diary-trial"
pq-diary init
```

```powershell
$env:PQ_DIARY_HOME = "$env:USERPROFILE\.pq-diary-trial"
pq-diary init
```

`PQ_DIARY_HOME` はアプリの設定・既定vaultの保存先です。
Cargoのインストール先 `--root` とは独立しています。

通常の操作ではパスワードを対話入力してください。
自動実行では `PQ_DIARY_PASSWORD` または `--password` を指定でき、この場合は新パスワードの確認入力を省略します。
`--password` はシェル履歴やプロセス一覧に値が残りうるため、日常操作には使わないでください。
環境変数も秘密値として扱い、自動処理の後は呼出し元で解除してください。

## 3. 日記を書く・読む・探す

エディタを選びます。インストール済みのものを指定してください。

```sh
export EDITOR=nano  # または vim / nvim
pq-diary new "今日のできごと" -t 日記 -t 生活/散歩
```

PowerShellでは `$env:EDITOR = "notepad"` のように指定します。
現在の `$EDITOR` は実行ファイル名またはパスで、引数を含む文字列は解釈しません。
GUIエディタに待機オプションが必要な場合は、ファイル引数を渡して待機する
ラッパースクリプトを用意し、その実行ファイルを指定してください。
エディタ内の `# Title:` と `# Tags:` はタイトル・タグを変更するヘッダです。
本文は `# ---` の後に書き、保存してエディタを終了します。
Nanoは `Ctrl+O` → Enter → `Ctrl+X`、Vimは `Esc` → `:wq` → Enterです。
Vim/Neovimにはswap・backup・undoファイルを無効にする設定を追加します。
他のエディタの自動保存・バックアップ機能は各エディタ側で確認してください。

```sh
pq-diary today                 # ローカル日付の今日の日記を開く。なければ作成
pq-diary list                  # 最大20件の一覧
pq-diary list --number 50
pq-diary list --tag 生活        # ネストしたタグも前方一致
pq-diary list --query 散歩      # タイトルの部分一致
pq-diary search "散歩|旅行"    # 本文を正規表現検索
pq-diary search "散歩" --tag 生活 --context 3
pq-diary stats
pq-diary stats --heatmap
```

一覧に表示されたIDで閲覧・編集・削除できます。
以下の `abcd1234` は実際のIDに置き換えてください。
IDは4文字以上の16進数の接頭辞を使えますが、複数に一致したら長くしてください。

```sh
pq-diary show abcd1234
pq-diary edit abcd1234
pq-diary edit abcd1234 --title "新しい題名" --add-tag 旅行 --remove-tag 日記
pq-diary delete abcd1234        # 確認してから削除
```

エディタを起動しない試用には `pq-diary new "動作確認" --body "テスト本文"` も使えます。
実際の秘密の本文を引数に書くと、シェル履歴等に残る可能性があります。

## 4. テンプレート・リンク・添付

```sh
pq-diary template add daily    # エディタで作成
pq-diary template list
pq-diary template show daily
pq-diary new "テンプレートから作成" --template daily
pq-diary template delete daily
```

テンプレートはvault内に暗号化保存されます。本文の `[[別の日記のタイトル]]` はリンク記法です。

```sh
pq-diary new "資料メモ" --attach ./document.pdf
pq-diary attachment add abcd1234 ./photo.png
pq-diary attachment list abcd1234
pq-diary attachment extract abcd1234 photo.png --out ./restored-photo.png
pq-diary attachment delete abcd1234 photo.png
```

抽出先には復号済みのファイルができます。抽出したファイルは利用者自身で管理してください。

## 5. 複数vaultと保存先

通常の日記コマンドは `config.toml` の `app.default_vault` を使います。
別vaultを作る場合の例（Unix。Windowsでもパスを置き換えて指定できます）:

```sh
pq-diary --vault "$HOME/.pq-diary/vaults" vault create work
pq-diary --vault "$HOME/.pq-diary/vaults" vault list
pq-diary --vault "$HOME/.pq-diary/vaults/work" new "仕事のメモ"
pq-diary --vault "$HOME/.pq-diary/vaults/work" list
```

**`vault` 管理コマンドの `--vault` はコレクションの親ディレクトリ、
日記コマンドの `--vault` は個別vaultのディレクトリです。**
管理コマンドで省略すると現在の作業ディレクトリが対象になります。
`PQ_DIARY_HOME` を変えている場合は、例のパスもその保存先に合わせてください。
`vault create` でも対話入力の新パスワードを2回確認します。

全機能を使うには、個別ディレクトリ内の標準名 `vault.pqd` と `vault.toml` を維持してください。
詳細は [保存先の解決規則](vault-selection.md) を参照してください。

## 6. バックアップ・取込み・パスワード変更

**バックアップは、pq-diaryの書込み・同期を止めて、アプリの保存先全体をコピーします。**
既定なら `~/.pq-diary/` 全体です。別途指定したvaultもそれぞれディレクトリ全体をコピーします。
設定、添付の関連データ、Git履歴も一緒に保存し、別の場所で復元・読取りできるか確認してください。
旧バックアップには旧パスワードでアクセスできるため、バックアップ自体も適切に保管します。

Markdownの取込み・書出し:

```sh
pq-diary import ./markdown-notes --dry-run
pq-diary import ./markdown-notes
mkdir ./exported-notes
pq-diary export ./exported-notes
```

書出し先は事前に作成します。exportは確認後、**平文Markdown**を書き出します。
添付・ID・時刻などを完全に復元するバックアップ形式ではありません。
取込みの対応範囲は [frontmatter互換性](frontmatter-import.md) を参照してください。

```sh
pq-diary change-password
```

旧パスワードと新パスワード、新パスワードの確認入力を求めます。

Git同期やデジタル遺産機能もあります。操作前に `pq-diary git-init --help`、
`pq-diary legacy --help` と [現在の実装状況](development-inventory.md) を確認してください。
Git同期には未完了のケースがあり、バックアップの代わりにはしません。
`legacy-access` は引継ぎと削除を伴う操作です。

## 7. 更新とアンインストール

更新前にバックアップを取ります。リポジトリで利用したい版を取得・確認した後、再インストールします。

```sh
git pull --ff-only
cargo install --path cli --locked
pq-diary --version
```

`--path` の再インストールは同じバージョン番号でもビルド・導入します。
通常 `--force` は不要です。他のパッケージや未管理ファイルとの同名衝突は、
上書きせず原因を確認してください。独自の `--root` を使った場合は更新時も同じ値を指定します。

実行ファイルの削除:

```sh
cargo uninstall pq-diary
```

独自の導入先を指定した例:

```sh
cargo uninstall pq-diary --root "$HOME/.local/pq-diary"
```

Cargo管理の実行ファイルが削除され、**日記・設定は保持されます**。
再インストール後は `init` を実行せず既存データを使えます。
`cargo uninstall` はPATH設定、ソースコード、ビルドキャッシュ、書き出した平文やバックアップを削除しません。
詳細は [Cargo uninstallの公式仕様](https://doc.rust-lang.org/cargo/commands/cargo-uninstall.html) を参照してください。

日記も削除する場合は、必要なバックアップを確認し、全操作を終了した後、
自分が使った保存先だけをファイルマネージャ等で削除します。
対象は既定の `~/.pq-diary/`、`PQ_DIARY_HOME` の指定先、追加vault、export・抽出先です。
他のアプリと共有する親ディレクトリは削除しないでください。
通常のファイル削除や上書きは、SSD・スナップショット・バックアップ等からの物理消去を保証しません。

## 8. 困ったとき

| 状況 | 確認すること |
|---|---|
| `cargo` が見つからない | Rustの導入とターミナルの再起動 |
| `pq-diary` が見つからない | `cargo install --list`、導入先の `bin` とPATH |
| ビルドに失敗 | 指定Rust、リンカ、ネットワーク、Git依存の取得状況。`--locked` を外す前に原因を確認 |
| `Already initialized` | 再初期化は不要。意図した `PQ_DIARY_HOME` か確認 |
| `Passwords do not match` | 新規作成は失敗。再実行し、同じ新パスワードを2回入力 |
| パスワード入力を求められない | `PQ_DIARY_PASSWORD` や `--password` が設定されていないか確認 |
| 設定が見つからない／別の日記が見える | `PQ_DIARY_HOME`、`--vault`、`config.toml` の `app.default_vault` を確認 |
| `No password provided and stdin is not a terminal` | 対話端末から起動。自動実行では秘密値を安全に提供 |
| エディタが起動しない | `$EDITOR` の実行ファイルと待機オプションを確認 |

全コマンドは `pq-diary --help`、個別の引数は `pq-diary <command> --help` で確認できます。
