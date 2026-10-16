# Definition of Done (全スプリント共通)

## 標準のビルド・CI
- [ ] `cargo fmt --all -- --check` が通る
- [ ] `cargo build --workspace --locked` が通る
- [ ] `cargo test --workspace --locked` が通る（単体・integration・doctest。ignoredは別途扱う）
- [ ] `cargo clippy --workspace --locked --all-targets -- -D warnings` が通る
- [ ] Linuxの `bash ci/smoke-test.sh ./target/debug/pq-diary` が通る（上記buildの成果物を再利用）
- [ ] `cargo audit --deny unsound --deny yanked` が通り、未対処の既知脆弱性・unsound advisory・yanked依存がない
- [ ] `cargo deny check bans licenses sources` が通る（フォークgitソース・ライセンス・重複検査; ADR-0010）

## 変更リスクに応じた検証
- [ ] 不具合修正では修正前に失敗・修正後に成功する回帰テストを確認した。再現できない場合は理由をPRに記載した
- [ ] 保存形式・鍵更新・複数ファイル更新では、該当する混在レコード、互換性、失敗時の原本/設定保全と再読込を確認した
- [ ] OS API・unsafe・依存/ツールチェーン変更では、対象プラットフォームや必要な追加検証を選び、結果または未実施理由を記録した
- [ ] 実行環境、コマンド、実測時間、cache状態をPRに記録し、実行済み・失敗・未実施を区別した

全OS/ARM・release・Miri・性能・大量データ・長時間の検証は毎PR必須にしない。
必要な検証を作業環境または手動実行で行う。全OS/release smokeはCIの
`workflow_dispatch` → `full_matrix=true` で選択できる。未検証範囲は成功と扱わない。

## セキュリティ不変条件
- [ ] 秘密値の所有者が `Zeroizing` / `SecretString` / `SecureBuffer` / `ZeroizeOnDrop` 実装型で保護され、複製先・移動先にも保護が引き継がれる
- [ ] 秘密型の `Debug` / エラー表示に秘密の内容が含まれない
- [ ] 新規 `unsafe` はAGENTS.mdのOS API許可一覧内の最小境界に限定し、各ブロックに有効期間・境界・所有権などを説明する `SAFETY:` がある。解放済みメモリを読むテストはない
- [ ] 意図しない平文のディスク書込みがない。既存のexport・editor一時ファイルは明示された用途とプラットフォーム別保護・後始末を維持する
- [ ] 秘密所有者のDrop時消去に漏れがなく、途中失敗でも秘密値や半端な状態を残さない

## I/O変更のレビュー（該当する項目）
- [ ] [AGENTS.mdのI/O契約](../AGENTS.md#io変更時の契約) に沿い、排他的作成・所有範囲・commit点を確認した。作成衝突、commit前の部分失敗、commit後のcleanup失敗を区別して確認した
- [ ] 認証とparseが同一snapshotを使い、更新後も添付を保持する。不在分岐が型付きエラーだけを扱い、破損・認証・I/O失敗を伝播することを確認した
- [ ] CLI出力のwrite/flush失敗とDrop警告の失敗を確認し、panicや秘密漏洩がない。回帰テストは [隔離・実バイナリの手順](workflow.md#回帰テストの隔離と実バイナリ) に従った

## コード品質
- [ ] 失敗しうる外部入力・I/Oは `Result` で扱う。失敗しないgetter等に不要な `Result` を追加していない
- [ ] core/ にプラットフォーム依存UIコードが入っていない
- [ ] `docs/backlog.md` の該当アイテムと実装状況が整合している

## CLI 整合性 (S10 から)
- [ ] 公開トップレベルコマンドの `--help` が成功し、追加コマンドはsmokeの一覧にも反映されている
- [ ] 最小E2Eの `init → new → list → info → export` が成功する。`--help` 成功だけを実操作の検証と扱っていない
- [ ] 変更したCLIの実操作に回帰テストがある。未実装スケルトンはclap定義から削除するか `#[command(hide = true)]` で隠す
- [ ] Unix/Windows smokeの期待値が整合している。通常PRはLinux版、必要な手動全環境検証ではWindows版も実行する
- [ ] スプリント完了時、`docs/backlog.md` のPhase整理が新コマンドの追加・hide化と整合している
