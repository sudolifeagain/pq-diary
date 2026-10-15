# 開発棚卸し（2026-10-16 JST）

対象: `main` の `0e085c06869223d8979ece642f073d0c2bcfe306`。
この記録は実装の棚卸しであり、完全なセキュリティ監査ではない。

## 現状

- Rust 2021、MSRV 1.94、固定ツールチェーン 1.95.0。`core/` と `cli/` の2クレート。
- 日記CRUD、日次ノート、テンプレート、検索、インポート・エクスポート、添付、パスワード変更、遺言アクセス、Git同期の実装あり。存在することと全組合せの正しさは別。
- 現行 writer は schema **0x06**。v4/v5 を読む互換経路あり。
- S16 は HKDF、MDK、各種キースロット、鍵ファイルの基礎実装までマージ済み。実際の作成・解錠・保存・CLIへの接続、v0x07移行は未完了。耐量子鍵カプセル化が通常のデータ保護経路に組み込まれたとは扱わない。
- 本PR作成前の2026-10-16棚卸し時点で open PR は0件。open issue は #15–20 と #23 の7件（S16 epicと6サブタスク）。リモートへの変更は実施していない。
- `requirements.md` の未実装表記、現行v5表記、暗号機能の説明と、現行コードには差異がある。S16の将来仕様を現在の保証として読まない。

## ベースライン

Linuxの新しい作業ディレクトリで Rust 1.95.0、固定 Cargo.lock の依存を使い、
`cargo test --workspace --locked` を実行した。

- CLI unit: 284 passed / 11 ignored
- CLI integration: 27 passed
- core unit: 470 passed / 4 ignored
- doc tests: 3 passed
- 合計 **784 passed / 15 ignored / 0 failed**

これは修正前の基準値。ignoredケース、Windows/macOS/ARM、性能目標の再検証を
含まない。既存テスト成功だけでは以下の未カバー障害を除外できなかった。

## S17: 既存データの保全を先に修正

1. **遺言アクセスの置換失敗時に原本を損なう問題**
   - `core/src/legacy.rs` は新ファイルへの置換前に原本の非継承レコードを上書きする。
   - vault または設定ファイルのバックアップ名をディレクトリで塞ぐ2ケースで、エラー後に原本バイトが変わることを再現した。
   - 両ファイルの置換成功まで原本を保持し、成功後に旧バックアップを消去する順序へ修正した。
2. **テンプレートを含むvaultでパスワード変更が失敗する問題**
   - `core/src/vault/change_password.rs` がテンプレートも `EntryPlaintext` として読むため、`missing field title` で失敗する。
   - 日記とテンプレートが混在する回帰テストで再現済み。レコード種別に対応する型で検証し、共通の再暗号化処理を維持する。

## 次の調査・修正候補（未修正、静的確認）

- Git pull後のcommitがリモート履歴を親に持たず、次のpushがnon-fast-forwardとなる可能性。ローカルbare remoteと2クローンで再現する。
- Git pushが添付blobをstageせず、pullがリモート添付レコードを採用しない。blobとメタデータの両方を扱う往復テストが必要。
- 現行Gitの「3-way」処理にmerge-base参照がなく、削除を復活させる可能性。HMACだけの比較では遺言フラグ変更も失われ得る。
- INHERIT設定後の編集で主本文だけ更新され、継承用コピーは古いまま。継承コードの再入力など更新手順を設計する必要があり、無断でDESTROYに戻さない。
- 添付・遺言の一部マスターパスワードAPIはvault全体のMAC検証を経由しない。破損fixtureで読み書き前の拒否を確認する。master keyを持たないlegacy-accessは別の設計課題。
- 長寿命のDiaryCoreでCRUD後のリンク索引が更新されない。unlock途中の索引検証失敗後にengineが残る可能性も別途確認する。

新しいS16機能の一括実装より、上記の再現・データ保全・互換性を優先する。

## S17 第1修正単位の検証

- 上記2件を修正。テンプレート1件、バックアップ失敗2件を修正前に失敗確認。
- 修正後 `cargo test --workspace --locked`: 787 passed / 15 ignored / 0 failed。
- `cargo clippy --workspace --locked --all-targets -- -D warnings` と build 成功。
- Linux CLI smoke: 34 passed / 0 failed（debug binary使用）。
- Windows/macOS/ARM、cargo audit/denyはこのローカル検証には含めず、PRの既存CIで確認する。
- クラッシュ・電源断に対する完全な2ファイル原子性、SSDの物理消去は保証しない。既存のcleanup/rollback警告処理は今回変更していない。
