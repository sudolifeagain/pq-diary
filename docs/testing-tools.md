# Rust テストツールの選定と使い方

## 通常の検証に追加するもの

既存の rustfmt・Clippy・`cargo test`・cargo-audit・cargo-deny は維持し、
最初の追加は **proptest による keyslot codec のプロパティテスト**に絞る。
通常 PR のチェックを増やさず、既存の `cargo test` で実行する。

固定例のテストに加え、構造・長さ・Unicode の組合せを生成し、失敗する
入力を小さく縮めて原因を調べられる点を採用理由とする。
今回の対象はシリアライズ／パースであり、暗号方式そのものの安全性や
鍵の復元、vault 全体の完全性を保証するテストではない。

- proptest 1.12.0 を core の dev-dependency として完全固定する
- 必要な `std` と `handle-panics` のみ有効化し、fork・timeout・bit-set は追加しない
- 全入力を合成する。本物の鍵・パスワード・日記をテストや失敗ログへ入れない
- Keyslot のフィールドを直接作り、生成ケースごとに Argon2 や鍵生成を実行しない
- 既存の例示テスト・回帰テスト・doctest は残す

公式資料: [Proptest 入門](https://proptest-rs.github.io/proptest/proptest/getting-started.html)、
[設定 API](https://docs.rs/proptest/1.12.0/proptest/test_runner/struct.Config.html)、
[採用バージョン](https://crates.io/crates/proptest/1.12.0)

## 検査する性質と実行量

`core/src/vault/keyslot.rs` の `prop_keyslot*` が次を検査する。

1. 4種類の slot と通常／将来用 KEM タグを含む生成入力の、serialize → parse の完全一致
2. 単一レコード内のすべての切断位置を拒否すること（外側の長さを切断後に
   合わせた入力でも、内部フィールドの途中切断を検査する）
3. 残りのデータより大きいレコード長を拒否すること
4. 長さに含まれた余計な payload 末尾を拒否すること
5. 未定義の slot type を拒否すること
6. 不正な UTF-8 ラベルを拒否すること
7. 任意の短い bytes で panic せず、受理した bytes は再シリアライズで一致すること

空の section や完成したレコード間での切断は、有効な短い section に
なり得るため、2 の拒否対象には含めない。

各プロパティは64ケース、縮小は最大1024回。生成する section は最大4 slot、
ラベルは最大32 Unicode scalar values、任意 bytes は最大4096 bytes とする。
この上限は通常のテストを軽く保つためで、長時間 fuzzing の代わりにはしない。
ケース数はテスト側で固定しており、`PROPTEST_CASES` では増減しない。

```sh
# 通常の workspace 検証（doctest を含む）
cargo test --workspace --locked

# 今回のプロパティのみ
cargo test -p pq-diary-core --locked prop_keyslot

# seed を固定して再実行する例
PROPTEST_RNG_SEED=42 cargo test -p pq-diary-core --locked prop_keyslot
```

失敗時は表示された最小入力と seed を確認する。生成された
`proptest-regressions` 内の再現情報はレビューしてコミットし、見つかった
不具合には小さい固定入力の回帰テストも追加する。

## 必要になったときに検討するツール

通常 PR にこれらの必須ジョブや一括インストールは追加しない。

- [cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov):
  テストされていない処理を探す手動検証に向く。まず行／領域カバレッジを使い、
  数値だけを合否条件にしない。branch と doctest の計測には nightly が必要
- [cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz/setup.html):
  保存形式・パーサを広く壊して調べる段階で導入する。nightly と C++ コンパイラが
  必要。対象と実行時間、入力サイズを決めたローカル／手動実行にする
- [cargo-nextest](https://nexte.st/docs/design/how-it-works/):
  並列実行・テストごとのプロセス分離を提供する。まず同じ環境・cache 状態で
  `cargo test` と比較し、改善がある場合に採用する。doctest の検証は別途維持する
- [Miri](https://github.com/rust-lang/miri):
  unsafe の未定義動作を調べる専用検証に向く。nightly が必要で OS API／FFI に
  制限があり、mlock や Windows Console の実機テストの代替にはしない
- [cargo-mutants](https://mutants.rs/vs-coverage.html):
  コードを意図的に変えて、テストが誤りを検出するか調べる。繰り返しビルド／
  テストするため、重要なパーサや変更箇所に絞って手動実行する
- [cargo-hack](https://github.com/taiki-e/cargo-hack):
  feature の組合せ検証が必要になった時点で検討する。現在は独自 feature の
  定義がないため追加しない
- [Criterion](https://github.com/bheisler/criterion.rs):
  性能目標と比較対象を決めてから導入する。通常の正しさのテストとは分ける

lint は既存 Clippy に必要な規則を個別追加する方針とし、`restriction` や
`pedantic` 全体を一括で強制しない。
[Clippy 公式の設定説明](https://doc.rust-lang.org/clippy/usage.html)
