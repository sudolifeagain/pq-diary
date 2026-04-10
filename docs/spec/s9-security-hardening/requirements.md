# S9 Security Hardening + Technical Debt + Integration Tests 要件定義書

## 概要

Sprint 9ではセキュリティ硬化、技術的負債の解消、統合テスト・パフォーマンス検証の3領域を実装する。セキュリティ硬化として、鍵素材のメモリロック（Unix mlock / Windows VirtualLock）、プロセス硬化（PR_SET_DUMPABLE=0, RLIMIT_CORE=0）、デバッガ検知（TracerPid / IsDebuggerPresent）を導入する。技術的負債として、Cli.passwordのSecretString化、not_implemented()のbail!化、中間バッファのZeroizingラップ、PQC依存のコミットハッシュpin、verify_hmacのResult化、読み取り時署名/HMAC検証を実装する。品質保証として、全コマンドのE2Eテストとパフォーマンス検証を実施する。

## 関連文書

- **ヒアリング記録**: [interview-record.md](interview-record.md)
- **ユーザストーリー**: [user-stories.md](user-stories.md)
- **受け入れ基準**: [acceptance-criteria.md](acceptance-criteria.md)
- **コンテキストノート**: [note.md](note.md)
- **PRD**: [requirements.md](../../requirements.md) (v4.0, section 8, 9, 12)
- **バックログ**: [backlog.md](../../backlog.md)

## 機能要件（EARS記法）

**【信頼性レベル凡例】**:
- 🔵 **青信号**: PRD・設計文書・ユーザヒアリングを参考にした確実な要件

### メモリロック（REQ-001〜005）

- REQ-001: Vaultアンロック後、鍵素材バッファに対して Unix `mlock` を呼び出し、メモリをスワップから保護しなければならない 🔵 *PRD 8.3*
- REQ-002: Vaultアンロック後、鍵素材バッファに対して Windows `VirtualLock` を呼び出し、メモリをスワップから保護しなければならない 🔵 *PRD 8.3*
- REQ-003: `lock()` 実行時に `munlock`（Unix）/ `VirtualUnlock`（Windows）を呼び出し、メモリロックを解放しなければならない 🔵 *PRD 8.2*
- REQ-004: `mlock` / `VirtualLock` が失敗した場合、警告ログを出力し処理を継続しなければならない（プロセスを中断してはならない） 🔵 *PRD 8.3 + ヒアリングQ2「mlock失敗時: warn + continue」*
- REQ-005: メモリロック機能は `core/src/crypto/secure_mem.rs` に配置し、`#[cfg(unix)]` / `#[cfg(windows)]` でプラットフォーム分岐しなければならない 🔵 *CLAUDE.md規約*

### プロセス硬化（REQ-010〜013）

- REQ-010: プロセス起動時に `PR_SET_DUMPABLE=0` を設定し、コアダンプにプロセスメモリが含まれることを防止しなければならない（Unix のみ） 🔵 *PRD 9.2*
- REQ-011: プロセス起動時に `setrlimit(RLIMIT_CORE, 0, 0)` を設定し、コアダンプファイルの生成を防止しなければならない（Unix のみ） 🔵 *PRD 9.1*
- REQ-012: デバッガ接続を検知しなければならない。Unix では `/proc/self/status` の `TracerPid` を確認し、Windows では `IsDebuggerPresent` を呼び出す 🔵 *PRD 9.2*
- REQ-013: デバッガ接続を検知した場合、警告メッセージを出力するのみとし、プロセスを中断してはならない 🔵 *ヒアリングQ2「デバッガ検知: warning only, do not abort」*

### 技術的負債（REQ-020〜027）

- REQ-020: `Cli.password` フィールドを `Option<String>` から `Option<SecretString>` に変更し、パスワードの生値が平文メモリに残留しないようにしなければならない（H-1） 🔵 *backlog*
- REQ-021: `not_implemented()` 関数を `process::exit` の呼び出しから `anyhow::bail!` マクロに変更し、適切なエラーハンドリングチェーンに組み込まなければならない（M-1） 🔵 *backlog*
- REQ-022: `MasterKey` および `unlock_with_vault` の中間 `Vec<u8>` バッファを `Zeroizing<Vec<u8>>` でラップし、スコープ終了時に自動ゼロ化されるようにしなければならない（M-2/M-4） 🔵 *backlog*
- REQ-023: PQC依存クレート（`ml-kem`, `ml-dsa`）のGit参照を `branch = "pq-diary"` から `rev = "<commit_hash>"` に変更し、ビルドの再現性を保証しなければならない（M-3） 🔵 *backlog*
- REQ-024: `verify_hmac` 関数の戻り値を `bool` から `Result<bool, DiaryError>` に変更し、HMAC検証中のエラーを呼び出し元に伝播できるようにしなければならない（M-5） 🔵 *backlog*
- REQ-025: エントリ読み取り時に ML-DSA-65 署名を検証し、署名が不正な場合は `DiaryError::Crypto` エラーを返さなければならない 🔵 *backlog（S4/S6繰越）*
- REQ-026: エントリ読み取り時に HMAC-SHA256 を検証し、HMAC が不一致の場合は `DiaryError::Crypto` エラーを返さなければならない 🔵 *backlog（S4/S6繰越）*
- REQ-027: 署名/HMAC 検証失敗時のエラーメッセージは、改竄の可能性を明確に示す内容でなければならない（例: "Entry integrity check failed: signature mismatch"） 🔵 *セキュリティ設計*

### 品質保証（REQ-030〜035）

- REQ-030: 全コマンド（init, new, list, show, edit, delete, search, stats, today, template, import, vault, git）のE2Eテストを実装しなければならない 🔵 *backlog*
- REQ-031: パフォーマンステスト: `init` コマンドは 3秒未満で完了しなければならない 🔵 *PRD 12.1*
- REQ-032: パフォーマンステスト: `unlock`（パスワード検証 + 鍵導出）は 1〜3秒で完了しなければならない 🔵 *PRD 12.1*
- REQ-033: パフォーマンステスト: `new` / `edit` コマンドは 200ms 未満で完了しなければならない（エディタ起動時間を除く） 🔵 *PRD 12.1*
- REQ-034: パフォーマンステスト: `list`（100エントリ）は 500ms 未満で完了しなければならない 🔵 *PRD 12.1*
- REQ-035: パフォーマンステスト: `lock` コマンドは 50ms 未満で完了しなければならない 🔵 *PRD 12.1*

## 制約要件

- REQ-401: `unsafe` ブロックは mlock / VirtualLock / PR_SET_DUMPABLE / Win32 Console API（GetConsoleMode / SetConsoleMode / ReadConsoleW）の呼び出しにのみ使用しなければならない 🔵 *CLAUDE.md規約*
- REQ-402: プラットフォーム分岐は `#[cfg()]` 属性で実装しなければならない 🔵 *CLAUDE.md規約*
- REQ-403: セキュリティ硬化（PR_SET_DUMPABLE, RLIMIT_CORE, デバッガ検知）は `cli/` に配置し、メモリロックは `core/` に配置しなければならない 🔵 *CLAUDE.md規約（core/ にプラットフォーム依存UIコードを入れない）*

## 非機能要件

### パフォーマンス

- NFR-001: メモリロック / アンロック操作はVaultの unlock / lock パスのレイテンシに有意な影響を与えてはならない（< 10ms 増加） 🔵 *PRD 12.1*
- NFR-002: プロセス硬化（PR_SET_DUMPABLE, RLIMIT_CORE）は起動時に1回のみ実行し、ランタイムパフォーマンスに影響を与えてはならない 🔵 *PRD 9.1/9.2*
- NFR-003: デバッガ検知チェックはプロセス起動時に1回のみ実行しなければならない 🔵 *PRD 9.2*

### セキュリティ

- NFR-101: 鍵素材がスワップ領域に書き出されるリスクを最小化しなければならない 🔵 *PRD 8.3*
- NFR-102: コアダンプに鍵素材が含まれるリスクを排除しなければならない 🔵 *PRD 9.1*
- NFR-103: パスワード平文がプロセスメモリに残留するリスクを最小化しなければならない 🔵 *PRD 8.2*

### 互換性

- NFR-201: メモリロック・プロセス硬化は非特権ユーザー環境でも動作しなければならない（失敗時は warn + continue） 🔵 *ヒアリングQ2*
- NFR-202: 既存のVaultデータ形式との後方互換性を維持しなければならない 🔵 *既存設計*

## Edgeケース

### メモリロック

- EDGE-001: mlock の ulimit 上限を超えた場合、警告を出力し処理を継続する 🔵 *ヒアリングQ2*
- EDGE-002: VirtualLock のワーキングセット上限を超えた場合、警告を出力し処理を継続する 🔵 *ヒアリングQ2*
- EDGE-003: 既にロック済みのバッファに対して再度 mlock を呼び出した場合、エラーにならない（冪等性） 🔵 *POSIX仕様*

### プロセス硬化

- EDGE-010: PR_SET_DUMPABLE が非対応カーネルの場合、警告を出力し処理を継続する 🔵 *ヒアリングQ2*
- EDGE-011: /proc/self/status が読み取れない環境（コンテナ等）の場合、デバッガ検知をスキップする 🔵 *セキュリティ設計*

### 技術的負債

- EDGE-020: SecretString 化後の Cli.password が clap derive と互換であること 🔵 *実装制約*
- EDGE-021: verify_hmac の戻り値変更が既存呼び出し元すべてで正しくハンドリングされること 🔵 *リファクタリング*

### 検証

- EDGE-030: 改竄されたエントリの署名検証失敗時、他のエントリの読み取りに影響を与えない 🔵 *セキュリティ設計*
- EDGE-031: 改竄されたエントリのHMAC検証失敗時、他のエントリの読み取りに影響を与えない 🔵 *セキュリティ設計*
