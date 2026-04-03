# s1-foundation 要件定義書

## 概要

pq-diaryプロジェクトの基盤を構築する。Cargoワークスペース、エラー型、セキュアメモリ型、CLIスケルトン、CIパイプラインを整備し、後続Sprint (S2-S9) の土台とする。

## 関連文書

- **ヒアリング記録**: [interview-record.md](interview-record.md)
- **ユーザストーリー**: [user-stories.md](user-stories.md)
- **受け入れ基準**: [acceptance-criteria.md](acceptance-criteria.md)
- **PRD**: [requirements.md](../../requirements.md)

## 機能要件（EARS記法）

**【信頼性レベル凡例】**:
- 🔵 **青信号**: PRD・ユーザヒアリングを参考にした確実な要件
- 🟡 **黄信号**: PRDから妥当な推測による要件
- 🔴 **赤信号**: PRDにない推測による要件

### 通常要件

- REQ-001: システムは Cargoワークスペースとして `core/` (pq-diary-core ライブラリクレート) と `cli/` (pq-diary バイナリクレート) を持たなければならない 🔵 *PRDセクション2.1より*
- REQ-002: core/ は `DiaryError` 列挙型を `thiserror` で定義し、全Phase (1-4) のエラーバリアント (Crypto, Vault, Entry, Git, Legacy, Policy, Io, Config, Editor, Import, Template, Search) を含まなければならない 🔵 *PRD + ヒアリングQ3より*
- REQ-003: core/ は以下のセキュアメモリ型を定義しなければならない 🔵 *PRDセクション8.1 + ヒアリングQ1より*
  - `SecureBuffer`: `zeroize::ZeroizeOnDrop` を実装したバイト列ラッパー
  - `ZeroizingKey`: 固定長鍵用ラッパー (`[u8; 32]`)
  - `MasterKey`: `sym_key`, `dsa_sk`, `kem_sk` フィールドを持つ構造体 (`ZeroizeOnDrop` 派生)
  - `CryptoEngine`: `master_key: Option<Secret<MasterKey>>`, `legacy_key: Option<Secret<[u8; 32]>>` を持つ構造体
- REQ-004: cli/ は `clap` (derive) で全Phase全コマンドのサブコマンドを定義しなければならない 🔵 *PRDセクション4.1 + ヒアリングQ2より*
  - Vault管理: init, vault (create/list/policy/delete)
  - エントリ操作: new, list, show, edit, delete, sync, export
  - Vault設定: change-password, info
  - Git同期: git-init, git-push, git-pull, git-sync, git-status
  - デジタル遺言: legacy (init/rotate/set/list), legacy-access
  - デーモン: daemon (start/stop/status/lock)
  - Claude連携: --claude フラグ
  - 追加機能: today, search, stats, import, template (add/list/show/delete)
  - グローバルオプション: -v/--vault, --password, --claude, --debug
  - 未実装コマンドは `unimplemented!("Planned for Sprint N")` で明示
- REQ-005: プロジェクトは GitHub Actions CI を持ち、`ubuntu-latest` で以下を実行しなければならない 🔵 *ヒアリングQ4より*
  - `cargo build --workspace`
  - `cargo test --workspace`
  - `cargo clippy --workspace -- -D warnings`
  - `cargo audit`

### 制約要件

- REQ-401: core/ にプラットフォーム依存のUIコード (termios, $EDITOR制御等) を含めてはならない 🔵 *PRDセクション2.2・CLAUDE.md規約より*
- REQ-402: 秘密データを保持する型は `zeroize::ZeroizeOnDrop` または `secrecy::Secret` で保護しなければならない。生の `Vec<u8>` / `String` での保持は禁止 🔵 *PRDセクション8.1・CLAUDE.md規約より*
- REQ-403: 本番コードで `unwrap()` / `expect()` を使用してはならない。すべての公開APIは `Result<T, DiaryError>` を返さなければならない 🔵 *CLAUDE.md規約より*
- REQ-404: `unsafe` ブロックは Sprint 1 では使用してはならない (mlock/VirtualLock/PR_SET_DUMPABLE は S9 で実装) 🔵 *CLAUDE.md規約・スプリントスコープより*
- REQ-405: MSRV は Rust 1.94 とする 🔵 *ヒアリング・環境確認より*

### 条件付き要件

- REQ-101: `cargo build --workspace` が警告なしで成功した場合、CIは成功としなければならない 🔵 *DoD要件より*
- REQ-102: `cargo clippy --workspace -- -D warnings` が警告を検出した場合、CIは失敗としなければならない 🔵 *DoD要件より*

## 非機能要件

### コード品質

- NFR-101: clippy警告ゼロ 🔵 *CLAUDE.md・DoD要件より*
- NFR-102: テストカバレッジ: SecureBuffer / ZeroizingKey のzeroize動作を検証するテストが含まれること 🔵 *PRDセクション8.1より*

### 保守性

- NFR-201: core/ の公開APIは `/// doc comment` を持つこと 🔵 *ヒアリングで必須と確定*
- NFR-202: エラーメッセージは英語で統一すること 🔵 *ヒアリングで英語統一と確定*

## エッジケース

### エラー処理

- EDGE-001: `DiaryError` の全バリアントが `std::fmt::Display` を実装し、人間が読めるエラーメッセージを返すこと 🔵 *thiserror使用で自動的に満たされる*
- EDGE-002: `DiaryError` が `std::error::Error` を実装し、`source()` でラップ元エラーを返せること 🔵 *thiserror #[from] で自動的に満たされる*

### 境界値

- EDGE-101: `SecureBuffer` が空 (0バイト) で作成された場合でも、Drop時にパニックしないこと 🔵 *ヒアリングで境界値テスト両方含めると確定*
- EDGE-102: `SecureBuffer` が大きなバッファ (1MB以上) で作成された場合でも、zeroizeが完了すること 🔵 *ヒアリングで境界値テスト両方含めると確定*
- EDGE-103: `CryptoEngine` の `master_key` が `None` の状態 (施錠状態) で暗号操作メソッドを呼んだ場合、`DiaryError::NotUnlocked` を返すこと 🔵 *PRDセクション1.3の「施錠」定義より*
