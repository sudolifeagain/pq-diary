# Definition of Done (全スプリント共通)

## ビルド・CI
- [ ] `cargo build --workspace` が警告なしで通る
- [ ] `cargo test --workspace` が全パス
- [ ] `cargo clippy --workspace -- -D warnings` が通る
- [ ] `cargo audit` で既知脆弱性なし
- [ ] `cargo deny check bans licenses sources` が通る (フォーク git ソース許可リスト・ライセンス・重複検査; ADR-0010)

## セキュリティ不変条件
- [ ] 秘密データに生の `String` / `Vec<u8>` を使っていない (zeroize/SecretString/SecretBytes)
- [ ] 新規 `unsafe` ブロックが mlock/VirtualLock/PR_SET_DUMPABLE 以外にない
- [ ] ディスクに平文を書く処理がない (一時ファイルは /dev/shm + zeroize削除)
- [ ] Drop実装で秘密フィールドのzeroize漏れがない

## コード品質
- [ ] 公開APIに `Result` を返さない関数がない (テストコード除く)
- [ ] core/ にプラットフォーム依存UIコードが入っていない
- [ ] `docs/backlog.md` の該当アイテムにチェックが入っている

## CLI 整合性 (S10 から)
- [ ] `cargo run -- <CMD> --help` で表示される全トップレベルコマンドが、実行時に `not_implemented` を返さず正常終了する (smoke test で検証)
- [ ] 未実装スケルトンは clap 定義から削除、または `#[command(hide = true)]` 属性でヘルプから除外する (`legacy*` / `daemon*` 等)
- [ ] CI に CLI smoke test (`ci/smoke-test.sh` / `ci/smoke-test.ps1`) が組み込まれており、各 PR で実行される
- [ ] スプリント完了時、`docs/backlog.md` の Phase 整理が新コマンドの追加・hide 化と整合している
