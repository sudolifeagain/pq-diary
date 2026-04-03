# Definition of Done (全スプリント共通)

## ビルド・CI
- [ ] `cargo build --workspace` が警告なしで通る
- [ ] `cargo test --workspace` が全パス
- [ ] `cargo clippy --workspace -- -D warnings` が通る
- [ ] `cargo audit` で既知脆弱性なし

## セキュリティ不変条件
- [ ] 秘密データに生の `String` / `Vec<u8>` を使っていない (zeroize/SecretString/SecretBytes)
- [ ] 新規 `unsafe` ブロックが mlock/VirtualLock/PR_SET_DUMPABLE 以外にない
- [ ] ディスクに平文を書く処理がない (一時ファイルは /dev/shm + zeroize削除)
- [ ] Drop実装で秘密フィールドのzeroize漏れがない

## コード品質
- [ ] 公開APIに `Result` を返さない関数がない (テストコード除く)
- [ ] core/ にプラットフォーム依存UIコードが入っていない
- [ ] `docs/backlog.md` の該当アイテムにチェックが入っている
