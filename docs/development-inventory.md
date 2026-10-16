# 開発棚卸し（2026-10-16 JST）

旧スナップショットの更新時点: `main` の [`ed77e6cfeafaeaba2ff5f02b65714b18880d6da9`](https://github.com/sudolifeagain/pq-diary/commit/ed77e6cfeafaeaba2ff5f02b65714b18880d6da9)（PR #75 マージ後）。
以下のベースライン・第1修正単位の実行結果は、旧棚卸し対象 `0e085c06869223d8979ece642f073d0c2bcfe306` からの履歴であり、現在のmainで再実行した件数ではない。今回の更新はソースと既存回帰テストの静的照合のみ。
この記録は実装の棚卸しであり、完全なセキュリティ監査ではない。

## 提出済み実装とmainの区別（2026-10-16 03:30 UTC確認）

確認したmainは [`6eb1b5c`](https://github.com/sudolifeagain/pq-diary/commit/6eb1b5c09763974da9c283ad2681de55d8b46429)。以下は提出済みdraft PRの状態であり、mainで利用可能になったことを意味しない。レビュー・必要なCI・所有者によるマージを経て完了判定する。

- [PR #94](https://github.com/sudolifeagain/pq-diary/pull/94) は認証した共通baseによる削除・同一HMACのメタデータ変更の照合と、prepare → 選択 → 再検証 → applyを実装済み、未マージ。
- [PR #95](https://github.com/sudolifeagain/pq-diary/pull/95) は #94 の上に、remoteを第2親に記録するcommitと無関係なstagingを保つindex transactionを実装済み、未マージ。確認headは `5fba931`。#94のマージ後にbaseをmainへ変更して通常CIを確認する必要があり、新transactionのnative Windows検証も未完了。既存mainの全OS成功はこの変更の検証を代替しない。
- [PR #93](https://github.com/sudolifeagain/pq-diary/pull/93) はexportコマンドのモジュール分離、[PR #96](https://github.com/sudolifeagain/pq-diary/pull/96)・[PR #97](https://github.com/sudolifeagain/pq-diary/pull/97)・[PR #98](https://github.com/sudolifeagain/pq-diary/pull/98)・[PR #99](https://github.com/sudolifeagain/pq-diary/pull/99)・[PR #100](https://github.com/sudolifeagain/pq-diary/pull/100) は対象CLI経路の型付きエラーsource保全を提出済み。いずれも未マージ。#98は#95、#99は#93に積まれている。全経路の負債解消を意味しない。
- Git添付メタデータ/blob一体同期、header/key/config移行、S16のvault・CLI統合とv0x07移行は引き続き未完了。安全な拒否guardを機能完成とは扱わない。

以下の「現状」「PR #75 後の照合結果」「未完了の開発候補」は旧スナップショットの記録。共通base・削除・ancestryの「未完了」は当時のmainを指し、上記候補実装の不存在を意味しない。古いテスト件数・open PR件数を現在の値として使わない。

## 現状

- Rust 2021、MSRV 1.94、固定ツールチェーン 1.95.0。`core/` と `cli/` の2クレート。
- 日記CRUD、日次ノート、テンプレート、検索、インポート・エクスポート、添付、パスワード変更、遺言アクセス、Git同期の実装あり。存在することと全組合せの正しさは別。
- 現行 writer は schema **0x06**。v4/v5 を読む互換経路あり。
- S16 は HKDF、MDK、各種キースロット、鍵ファイルの基礎実装までマージ済み。実際の作成・解錠・保存・CLIへの接続、v0x07移行は未完了。耐量子鍵カプセル化が通常のデータ保護経路に組み込まれたとは扱わない。
- 今回の文書更新前の確認では open PR は0件、open issue は #15–20 と #23 の7件（S16 epicと6サブタスク）。これは確認時点の件数。
- `requirements.md` の未実装表記、現行v5表記、暗号機能の説明と、現行コードには差異がある。S16の将来仕様を現在の保証として読まない。

## 初回棚卸しのベースライン（履歴）

Linuxの新しい作業ディレクトリで Rust 1.95.0、固定 Cargo.lock の依存を使い、
`cargo test --workspace --locked` を実行した。

- CLI unit: 284 passed / 11 ignored
- CLI integration: 27 passed
- core unit: 470 passed / 4 ignored
- doc tests: 3 passed
- 合計 **784 passed / 15 ignored / 0 failed**

これは修正前の基準値。ignoredケース、Windows/macOS/ARM、性能目標の再検証を
含まない。既存テスト成功だけでは以下の未カバー障害を除外できなかった。

## S17 第1修正単位で扱った不具合（履歴）

1. **遺言アクセスの置換失敗時に原本を損なう問題**
   - `core/src/legacy.rs` は修正前、新ファイルへの置換前に原本の非継承レコードを上書きしていた。
   - vault または設定ファイルのバックアップ名をディレクトリで塞ぐ2ケースで、エラー後に原本バイトが変わることを再現した。
   - 両ファイルの置換成功まで原本を保持し、成功後に旧バックアップを消去する順序へ修正した。
2. **テンプレートを含むvaultでパスワード変更が失敗する問題**
   - `core/src/vault/change_password.rs` が修正前はテンプレートも `EntryPlaintext` として読んでいたため、`missing field title` で失敗していた。
   - 日記とテンプレートが混在する回帰テストで再現済み。レコード種別に対応する型で検証し、共通の再暗号化処理を維持するよう修正した。

## PR #75 後の照合結果（静的確認）

- 遺言アクセスのbackup失敗時保全、日記・テンプレート混在vaultのパスワード変更は修正済み。回帰テストは `core/src/legacy.rs` の `tc_s12_007_08_vault_backup_failure_keeps_original` / `tc_s12_007_09_toml_backup_failure_keeps_original`、`core/src/vault/change_password.rs` の `password_rotation_preserves_templates_and_entries`。
- 添付・master-password遺言APIの整合性検証は実装済み。両モジュールに `*_apis_reject_tampered_mac_without_side_effects` / `*_apis_reject_tampered_timestamp_without_side_effects` がある。master keyを持たないlegacy-accessの認証設計とは区別する。
- リンク照会は現在のsnapshotから索引を作り直す。unlock失敗後もlockedを保つ。`core/src/lib.rs` の `link_queries_follow_create_update_delete_without_reunlock` / `failed_unlock_does_not_publish_partial_state` / `failed_reunlock_clears_previous_session` で回帰を扱う。
- INHERIT編集は古い継承用コピーを残さないよう拒否する安全策が実装済み（`core/src/entry.rs::update_entry`）。継承コードを再取得し両コピーを更新する編集機能は未実装。現在は別エントリに改訂を作成する。
- Git pullは取得したsnapshotを検証してから更新し、添付付きvault、異なる鍵/header、異なる設定値を拒否する。guardによる拒否を同期機能の完成とは扱わない。
- 通常CIはLinuxのbuild/test/Clippy/fmt/debug smokeとaudit/deny。全OS/ARM・release smokeは手動 `full_matrix=true`。現在の設定は [ci.yml](../.github/workflows/ci.yml)、検証方針は [workflow.md](workflow.md) を参照。

## 未完了の開発候補

1. Gitの共通baseに基づく削除・同一HMACのメタデータ変更の照合と、完全に検証したmerge後のremote ancestry記録。`core/src/git.rs::git_pull_merge_inner` は現在UUID unionとローカルcommitのため、削除復活やpull後pushのnon-fast-forwardが残る。force-pushで回避しない。
2. Gitの添付メタデータ・暗号化blobの一体同期、および端末間のheader/key/config変更の移行設計。現行の拒否guardは実装完了まで維持する。
3. S16のv0x07 reader/writer、作成・解錠・保存・非破壊移行への統合。その後に鍵ファイル・recipient・recoveryの利用導線、MDKローテーション、メタデータ機密化、CLIを完成させる。[Epic #20](https://github.com/sudolifeagain/pq-diary/issues/20) と #15–19 / #23 は未完了。既存のMDK/keyslot単体APIを未着手とは扱わない。
4. Phase 2の残候補。`list` はtagとtitle queryの併用・固定降順・件数制限まで実装済みだが、選択可能なsort・list JSON・複数条件の拡張は未実装（`stats --json` は既存）。daemonはhidden stub。Web Clipper、固定ブロック、XOR分散は別の未完了項目。

小さいPRごとに回帰・失敗時保全・互換性を確認し、古いテスト件数やチェック済み表記だけで完了判定しない。

## S17 第1修正単位の検証（履歴）

- 上記2件を修正。テンプレート1件、バックアップ失敗2件を修正前に失敗確認。
- 修正後 `cargo test --workspace --locked`: 787 passed / 15 ignored / 0 failed。
- `cargo clippy --workspace --locked --all-targets -- -D warnings` と build 成功。
- Linux CLI smoke: 34 passed / 0 failed（debug binary使用）。
- Windows/macOS/ARM、cargo audit/denyはこのローカル検証には含めず、PRの既存CIで確認する。
- クラッシュ・電源断に対する完全な2ファイル原子性、SSDの物理消去は保証しない。既存のcleanup/rollback警告処理は今回変更していない。
