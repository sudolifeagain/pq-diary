# S9 Security Hardening + Technical Debt + Integration Tests 受け入れ基準

**作成日**: 2026-04-10
**関連要件定義**: [requirements.md](requirements.md)
**関連ユーザストーリー**: [user-stories.md](user-stories.md)
**ヒアリング記録**: [interview-record.md](interview-record.md)

**【信頼性レベル凡例】**:
- 🔵 **青信号**: PRD・設計文書・ユーザヒアリングを参考にした確実な基準

---

## REQ-001〜005: メモリロック 🔵

**信頼性**: 🔵 *PRD 8.3 + ヒアリングQ2「mlock + VirtualLock 両対応、失敗時 warn + continue」*

### Given
- Vaultが作成済みでアンロック操作を実行する

### When
- パスワード入力後に鍵導出が完了する

### Then
- 鍵素材バッファがメモリロックされる（Unix: mlock, Windows: VirtualLock）
- lock() 時にメモリアンロックされる（Unix: munlock, Windows: VirtualUnlock）
- メモリロック失敗時は警告を出力し処理を継続する

### テストケース

#### 正常系

- [ ] **TC-S9-001-01**: Unix mlock 呼び出し確認 🔵
  - **入力**: Unix環境でVaultアンロック
  - **期待結果**: secure_mem::lock_memory() が鍵素材バッファに対して呼び出される
  - **信頼性**: 🔵 *PRD 8.3*
  - **備考**: `#[cfg(unix)]` テスト。CI環境ではulimit制限により失敗する可能性があるため、コンパイルテスト + モック検証を推奨

- [ ] **TC-S9-001-02**: Windows VirtualLock 呼び出し確認 🔵
  - **入力**: Windows環境でVaultアンロック
  - **期待結果**: secure_mem::lock_memory() が鍵素材バッファに対して呼び出される
  - **信頼性**: 🔵 *PRD 8.3*
  - **備考**: `#[cfg(windows)]` テスト

- [ ] **TC-S9-001-03**: munlock / VirtualUnlock の呼び出し確認 🔵
  - **入力**: ロック済みバッファに対して lock() を実行
  - **期待結果**: secure_mem::unlock_memory() が呼び出される
  - **信頼性**: 🔵 *PRD 8.2*

- [ ] **TC-S9-001-04**: mlock 失敗時の warn + continue 🔵
  - **入力**: mlock が ENOMEM で失敗する環境（ulimit -l 0）
  - **期待結果**: 警告ログが出力され、Vaultアンロックが正常に完了する
  - **信頼性**: 🔵 *ヒアリングQ2*

- [ ] **TC-S9-001-05**: secure_mem.rs の #[cfg] 分岐確認 🔵
  - **入力**: core/src/crypto/secure_mem.rs のソースコード
  - **期待結果**: `#[cfg(unix)]` と `#[cfg(windows)]` で分岐している
  - **信頼性**: 🔵 *CLAUDE.md規約*

#### 異常系

- [ ] **TC-S9-001-E01**: mlock の ulimit 上限超過 🔵
  - **入力**: ulimit -l が極小値の環境で大きなバッファをロック
  - **期待結果**: 警告出力、処理継続
  - **信頼性**: 🔵 *ヒアリングQ2*

- [ ] **TC-S9-001-E02**: 重複 mlock（冪等性） 🔵
  - **入力**: 既にロック済みのバッファに再度 mlock
  - **期待結果**: エラーにならない
  - **信頼性**: 🔵 *POSIX仕様*

---

## REQ-010〜013: プロセス硬化 🔵

**信頼性**: 🔵 *PRD 9.1 + PRD 9.2 + ヒアリングQ2「Unix のみ、デバッガ検知は warning only」*

### Given
- pq-diary プロセスが起動する

### When
- プロセス起動直後の初期化処理

### Then
- PR_SET_DUMPABLE=0 が設定される（Unix）
- RLIMIT_CORE=0 が設定される（Unix）
- デバッガ検知が実行される（Unix + Windows）
- デバッガ検知時は警告のみ

### テストケース

#### 正常系

- [ ] **TC-S9-010-01**: PR_SET_DUMPABLE=0 の設定確認 🔵
  - **入力**: Unix環境でpq-diary起動
  - **期待結果**: `prctl(PR_GET_DUMPABLE)` が 0 を返す
  - **信頼性**: 🔵 *PRD 9.2*
  - **備考**: `#[cfg(unix)]` テスト

- [ ] **TC-S9-010-02**: RLIMIT_CORE=0 の設定確認 🔵
  - **入力**: Unix環境でpq-diary起動
  - **期待結果**: `getrlimit(RLIMIT_CORE)` が (0, 0) を返す
  - **信頼性**: 🔵 *PRD 9.1*
  - **備考**: `#[cfg(unix)]` テスト

- [ ] **TC-S9-010-03**: TracerPid によるデバッガ非検知 🔵
  - **入力**: デバッガ未アタッチのUnix環境で起動
  - **期待結果**: 警告メッセージなし
  - **信頼性**: 🔵 *PRD 9.2*
  - **備考**: `#[cfg(unix)]` テスト

- [ ] **TC-S9-010-04**: IsDebuggerPresent によるデバッガ非検知 🔵
  - **入力**: デバッガ未アタッチのWindows環境で起動
  - **期待結果**: 警告メッセージなし
  - **信頼性**: 🔵 *PRD 9.2*
  - **備考**: `#[cfg(windows)]` テスト

- [ ] **TC-S9-010-05**: デバッガ検知時の警告出力 🔵
  - **入力**: デバッガがアタッチされた状態で起動
  - **期待結果**: 警告メッセージが出力される（例: "WARNING: Debugger detected."）
  - **信頼性**: 🔵 *ヒアリングQ2*

- [ ] **TC-S9-010-06**: デバッガ検知後もプロセス継続 🔵
  - **入力**: デバッガがアタッチされた状態で起動
  - **期待結果**: プロセスが中断されず、正常に動作を継続する
  - **信頼性**: 🔵 *ヒアリングQ2「warning only, do not abort」*

#### 異常系

- [ ] **TC-S9-010-E01**: /proc/self/status 読み取り不可 🔵
  - **入力**: /proc/self/status が存在しない環境（一部コンテナ等）
  - **期待結果**: デバッガ検知をスキップし、処理を継続する
  - **信頼性**: 🔵 *セキュリティ設計*

- [ ] **TC-S9-010-E02**: PR_SET_DUMPABLE 非対応カーネル 🔵
  - **入力**: PR_SET_DUMPABLE が非対応のカーネル
  - **期待結果**: 警告出力、処理継続
  - **信頼性**: 🔵 *ヒアリングQ2*

---

## REQ-020: Cli.password SecretString化 (H-1) 🔵

**信頼性**: 🔵 *backlog H-1 + ヒアリングQ3*

### Given
- CLI で --password フラグまたは環境変数でパスワードを受け取る

### When
- パスワードが Cli 構造体に格納される

### Then
- Option<SecretString> として格納される
- スコープ終了時に自動ゼロ化される

### テストケース

- [ ] **TC-S9-020-01**: Cli.password が SecretString 型 🔵
  - **入力**: Cli 構造体の型定義確認
  - **期待結果**: `password: Option<SecretString>` であること
  - **信頼性**: 🔵 *backlog H-1*

- [ ] **TC-S9-020-02**: --password フラグ経由のパスワード受け取り 🔵
  - **入力**: `pq-diary --password "test" list`
  - **期待結果**: パスワードが SecretString として正常に処理される
  - **信頼性**: 🔵 *backlog H-1*

- [ ] **TC-S9-020-03**: PQ_DIARY_PASSWORD 環境変数経由のパスワード受け取り 🔵
  - **入力**: `PQ_DIARY_PASSWORD=test pq-diary list`
  - **期待結果**: パスワードが SecretString として正常に処理される
  - **信頼性**: 🔵 *backlog H-1*

---

## REQ-021: not_implemented() の bail! 化 (M-1) 🔵

**信頼性**: 🔵 *backlog M-1 + ヒアリングQ3*

### Given
- not_implemented() が呼び出される箇所（4箇所 + legacy/daemonスタブ）

### When
- 未実装コマンドが実行される

### Then
- process::exit ではなく anyhow::bail! でエラーが返される

### テストケース

- [ ] **TC-S9-021-01**: not_implemented() が bail! に変更されている 🔵
  - **入力**: ソースコード確認
  - **期待結果**: `process::exit` の呼び出しが存在しない（テストコードを除く）
  - **信頼性**: 🔵 *backlog M-1*

- [ ] **TC-S9-021-02**: 未実装コマンド実行時のエラーメッセージ 🔵
  - **入力**: 未実装コマンドの実行
  - **期待結果**: anyhow エラーとして適切なメッセージが表示される
  - **信頼性**: 🔵 *backlog M-1*

---

## REQ-022: 中間 Vec<u8> の Zeroizing ラップ (M-2/M-4) 🔵

**信頼性**: 🔵 *backlog M-2/M-4 + ヒアリングQ3*

### Given
- MasterKey および unlock_with_vault で中間 Vec<u8> が使用される

### When
- 鍵素材の操作が行われる

### Then
- 中間バッファが Zeroizing<Vec<u8>> でラップされ、スコープ終了時に自動ゼロ化される

### テストケース

- [ ] **TC-S9-022-01**: MasterKey.sym_key コピー時の Zeroizing 🔵
  - **入力**: MasterKey のソースコード確認
  - **期待結果**: 中間 Vec<u8> が `Zeroizing<Vec<u8>>` でラップされている
  - **信頼性**: 🔵 *backlog M-2*

- [ ] **TC-S9-022-02**: unlock_with_vault の復号バッファの Zeroizing 🔵
  - **入力**: unlock_with_vault のソースコード確認
  - **期待結果**: 中間 Vec<u8> が `Zeroizing<Vec<u8>>` でラップされている
  - **信頼性**: 🔵 *backlog M-4*

- [ ] **TC-S9-022-03**: Vault アンロック成功 🔵
  - **入力**: 正しいパスワードでVaultアンロック
  - **期待結果**: アンロックが正常に完了する（Zeroizingラップが機能に影響しない）
  - **信頼性**: 🔵 *backlog M-2/M-4*

---

## REQ-023: PQC 依存のコミットハッシュ固定 (M-3) 🔵

**信頼性**: 🔵 *backlog M-3 + ヒアリングQ3*

### Given
- core/Cargo.toml に ml-kem / ml-dsa の Git 依存がある

### When
- 依存のバージョン指定を確認する

### Then
- `branch = "pq-diary"` ではなく `rev = "<commit_hash>"` で固定されている

### テストケース

- [ ] **TC-S9-023-01**: ml-kem の rev 指定確認 🔵
  - **入力**: core/Cargo.toml の ml-kem 依存
  - **期待結果**: `rev = "<40桁hex>"` 形式で固定されている
  - **信頼性**: 🔵 *backlog M-3*

- [ ] **TC-S9-023-02**: ml-dsa の rev 指定確認 🔵
  - **入力**: core/Cargo.toml の ml-dsa 依存
  - **期待結果**: `rev = "<40桁hex>"` 形式で固定されている
  - **信頼性**: 🔵 *backlog M-3*

- [ ] **TC-S9-023-03**: cargo build 成功 🔵
  - **入力**: `cargo build`
  - **期待結果**: ビルドが成功する
  - **信頼性**: 🔵 *backlog M-3*

- [ ] **TC-S9-023-04**: 既存暗号テストの通過 🔵
  - **入力**: `cargo test` (crypto モジュール)
  - **期待結果**: 全テストがパスする
  - **信頼性**: 🔵 *backlog M-3*

---

## REQ-024: verify_hmac の Result 化 (M-5) 🔵

**信頼性**: 🔵 *backlog M-5 + ヒアリングQ3*

### Given
- verify_hmac 関数が bool を返す

### When
- HMAC 検証を実行する

### Then
- Result<bool, DiaryError> を返す

### テストケース

- [ ] **TC-S9-024-01**: verify_hmac の戻り値型確認 🔵
  - **入力**: verify_hmac のシグネチャ確認
  - **期待結果**: `Result<bool, DiaryError>` を返す
  - **信頼性**: 🔵 *backlog M-5*

- [ ] **TC-S9-024-02**: 正常なHMAC検証で Ok(true) 🔵
  - **入力**: 正しいHMACでの検証
  - **期待結果**: `Ok(true)` が返る
  - **信頼性**: 🔵 *backlog M-5*

- [ ] **TC-S9-024-03**: 不一致HMACで Ok(false) 🔵
  - **入力**: 不正なHMACでの検証
  - **期待結果**: `Ok(false)` が返る
  - **信頼性**: 🔵 *backlog M-5*

- [ ] **TC-S9-024-04**: 全呼び出し元の修正確認 🔵
  - **入力**: verify_hmac の呼び出し箇所確認
  - **期待結果**: 全箇所が Result を適切にハンドリングしている
  - **信頼性**: 🔵 *backlog M-5*

---

## REQ-025〜027: 署名/HMAC 検証 🔵

**信頼性**: 🔵 *backlog（S4/S6繰越）+ ヒアリングQ3*

### Given
- Vault からエントリを読み取る

### When
- show / list / search / edit 等の読み取り操作

### Then
- 各エントリの ML-DSA-65 署名が検証される
- 各エントリの HMAC-SHA256 が検証される
- 検証失敗時は DiaryError::Crypto エラーが返される

### テストケース

#### 正常系

- [ ] **TC-S9-025-01**: 正常エントリの署名検証成功 🔵
  - **入力**: 正常に作成されたエントリの読み取り
  - **期待結果**: 署名検証が成功し、エントリが読み取れる
  - **信頼性**: 🔵 *backlog*

- [ ] **TC-S9-025-02**: 正常エントリのHMAC検証成功 🔵
  - **入力**: 正常に作成されたエントリの読み取り
  - **期待結果**: HMAC検証が成功し、エントリが読み取れる
  - **信頼性**: 🔵 *backlog*

- [ ] **TC-S9-025-03**: 既存の全コマンドが検証付きで動作 🔵
  - **入力**: show, list, search, edit, delete, stats 等の読み取り操作
  - **期待結果**: 正常エントリに対してすべてのコマンドが動作する
  - **信頼性**: 🔵 *backlog*

#### 異常系

- [ ] **TC-S9-025-E01**: 改竄エントリの署名検証失敗 🔵
  - **入力**: 署名が改竄されたエントリの読み取り
  - **期待結果**: DiaryError::Crypto エラー（改竄を示すメッセージ）
  - **信頼性**: 🔵 *セキュリティ設計*

- [ ] **TC-S9-025-E02**: 改竄エントリのHMAC検証失敗 🔵
  - **入力**: HMAC が改竄されたエントリの読み取り
  - **期待結果**: DiaryError::Crypto エラー（改竄を示すメッセージ）
  - **信頼性**: 🔵 *セキュリティ設計*

- [ ] **TC-S9-025-E03**: エラーメッセージの内容確認 🔵
  - **入力**: 検証失敗時のエラーメッセージ
  - **期待結果**: 改竄の可能性を明確に示す内容（例: "Entry integrity check failed"）
  - **信頼性**: 🔵 *セキュリティ設計*

- [ ] **TC-S9-025-E04**: 1エントリの検証失敗が他エントリに影響しない 🔵
  - **入力**: 3エントリ中1つが改竄された状態で list
  - **期待結果**: 改竄エントリのみエラー、他の2エントリは正常に表示される
  - **信頼性**: 🔵 *セキュリティ設計*

---

## REQ-030: E2Eテスト 🔵

**信頼性**: 🔵 *backlog + ヒアリングQ3「全13コマンド対象」*

### Given
- 全コマンドが実装済み（S1〜S8）

### When
- E2Eテストスイートを実行する

### Then
- 全コマンドのテストがパスする

### テストケース

- [ ] **TC-S9-030-01**: init コマンド E2E 🔵
  - **入力**: `pq-diary init --password "test"`
  - **期待結果**: Vaultが正常に初期化される
  - **信頼性**: 🔵 *backlog*

- [ ] **TC-S9-030-02**: new コマンド E2E 🔵
  - **入力**: `pq-diary new --title "Test" --body "Content" --password "test"`
  - **期待結果**: エントリが正常に作成される
  - **信頼性**: 🔵 *backlog*

- [ ] **TC-S9-030-03**: list コマンド E2E 🔵
  - **入力**: `pq-diary list --password "test"`
  - **期待結果**: エントリ一覧が表示される
  - **信頼性**: 🔵 *backlog*

- [ ] **TC-S9-030-04**: show コマンド E2E 🔵
  - **入力**: `pq-diary show <ID_PREFIX> --password "test"`
  - **期待結果**: エントリ内容が表示される
  - **信頼性**: 🔵 *backlog*

- [ ] **TC-S9-030-05**: edit コマンド E2E 🔵
  - **入力**: `pq-diary edit <ID_PREFIX> --password "test"`（EDITOR=cat 等で代替）
  - **期待結果**: エントリ編集フローが正常に動作する
  - **信頼性**: 🔵 *backlog*

- [ ] **TC-S9-030-06**: delete コマンド E2E 🔵
  - **入力**: `pq-diary delete <ID_PREFIX> --password "test" --force`
  - **期待結果**: エントリが削除される
  - **信頼性**: 🔵 *backlog*

- [ ] **TC-S9-030-07**: search コマンド E2E 🔵
  - **入力**: `pq-diary search "keyword" --password "test"`
  - **期待結果**: 検索結果が表示される
  - **信頼性**: 🔵 *backlog*

- [ ] **TC-S9-030-08**: stats コマンド E2E 🔵
  - **入力**: `pq-diary stats --password "test"`
  - **期待結果**: 統計情報が表示される
  - **信頼性**: 🔵 *backlog*

- [ ] **TC-S9-030-09**: today コマンド E2E 🔵
  - **入力**: `pq-diary today --password "test"`
  - **期待結果**: 当日のデイリーノートが作成/表示される
  - **信頼性**: 🔵 *backlog*

- [ ] **TC-S9-030-10**: template コマンド E2E 🔵
  - **入力**: `pq-diary template add/list/show/delete --password "test"`
  - **期待結果**: テンプレートCRUD操作が正常に動作する
  - **信頼性**: 🔵 *backlog*

- [ ] **TC-S9-030-11**: import コマンド E2E 🔵
  - **入力**: `pq-diary import <dir> --password "test"`
  - **期待結果**: Markdownファイルが正常にインポートされる
  - **信頼性**: 🔵 *backlog*

- [ ] **TC-S9-030-12**: vault コマンド E2E 🔵
  - **入力**: `pq-diary vault list` / `vault delete` / `vault policy`
  - **期待結果**: Vault管理操作が正常に動作する
  - **信頼性**: 🔵 *backlog*

- [ ] **TC-S9-030-13**: git コマンド E2E 🔵
  - **入力**: `pq-diary git-init` / `git-status` / `git-push` / `git-pull` / `git-sync`
  - **期待結果**: Git連携操作が正常に動作する
  - **信頼性**: 🔵 *backlog*

---

## REQ-031〜035: パフォーマンステスト 🔵

**信頼性**: 🔵 *PRD 12.1 + ヒアリングQ3*

### Given
- 全コマンドが実装済みで、100エントリを含むテスト用Vaultが準備されている

### When
- パフォーマンステストを実行する

### Then
- 各操作がPRD 12.1の目標値を満たす

### テストケース

- [ ] **TC-S9-031-01**: init < 3s 🔵
  - **測定項目**: `pq-diary init` の実行時間
  - **目標値**: < 3秒
  - **信頼性**: 🔵 *PRD 12.1*

- [ ] **TC-S9-032-01**: unlock 1-3s 🔵
  - **測定項目**: パスワード検証 + Argon2id鍵導出の実行時間
  - **目標値**: 1〜3秒
  - **信頼性**: 🔵 *PRD 12.1*

- [ ] **TC-S9-033-01**: new < 200ms 🔵
  - **測定項目**: `pq-diary new` の実行時間（エディタ起動時間を除く）
  - **目標値**: < 200ms
  - **信頼性**: 🔵 *PRD 12.1*

- [ ] **TC-S9-033-02**: edit < 200ms 🔵
  - **測定項目**: `pq-diary edit` の実行時間（エディタ起動時間を除く）
  - **目標値**: < 200ms
  - **信頼性**: 🔵 *PRD 12.1*

- [ ] **TC-S9-034-01**: list(100 entries) < 500ms 🔵
  - **測定項目**: 100エントリのVaultでの `pq-diary list` 実行時間
  - **目標値**: < 500ms
  - **信頼性**: 🔵 *PRD 12.1*

- [ ] **TC-S9-035-01**: lock < 50ms 🔵
  - **測定項目**: `lock` 操作の実行時間
  - **目標値**: < 50ms
  - **信頼性**: 🔵 *PRD 12.1*

---

## REQ-401〜403: 制約要件 🔵

**信頼性**: 🔵 *CLAUDE.md規約*

### テストケース

- [ ] **TC-S9-401-01**: unsafe ブロックの用途確認 🔵
  - **入力**: ソースコード全体の unsafe 使用箇所
  - **期待結果**: mlock/VirtualLock/PR_SET_DUMPABLE/Win32 Console API のみに使用されている
  - **信頼性**: 🔵 *CLAUDE.md規約*

- [ ] **TC-S9-402-01**: プラットフォーム分岐の #[cfg()] 使用確認 🔵
  - **入力**: ソースコード全体のプラットフォーム分岐箇所
  - **期待結果**: すべて `#[cfg(unix)]` / `#[cfg(windows)]` で分岐されている
  - **信頼性**: 🔵 *CLAUDE.md規約*

- [ ] **TC-S9-403-01**: セキュリティ硬化の配置確認 🔵
  - **入力**: PR_SET_DUMPABLE, RLIMIT_CORE, デバッガ検知のソース位置
  - **期待結果**: cli/ に配置されている
  - **信頼性**: 🔵 *CLAUDE.md規約*

- [ ] **TC-S9-403-02**: メモリロックの配置確認 🔵
  - **入力**: secure_mem.rs のソース位置
  - **期待結果**: core/src/crypto/ に配置されている
  - **信頼性**: 🔵 *CLAUDE.md規約*

---

## 非機能要件テスト

### NFR-001〜003: パフォーマンス 🔵

- [ ] **TC-S9-NFR-001-01**: メモリロックのレイテンシ影響 🔵
  - **測定項目**: メモリロック有無によるunlock時間の差分
  - **目標値**: < 10ms 増加
  - **信頼性**: 🔵 *PRD 12.1*

- [ ] **TC-S9-NFR-002-01**: プロセス硬化の起動時間影響 🔵
  - **測定項目**: PR_SET_DUMPABLE + RLIMIT_CORE 設定の実行時間
  - **目標値**: < 1ms（無視できるレベル）
  - **信頼性**: 🔵 *PRD 9.1/9.2*

### NFR-101〜103: セキュリティ 🔵

- [ ] **TC-S9-NFR-101-01**: スワップ保護の確認 🔵
  - **入力**: mlock 後のメモリ状態
  - **期待結果**: 鍵素材バッファがメモリロックされている
  - **信頼性**: 🔵 *PRD 8.3*

- [ ] **TC-S9-NFR-103-01**: パスワード残留確認 🔵
  - **入力**: SecretString 化後のCli.password
  - **期待結果**: スコープ終了後に平文パスワードがメモリに残留しない
  - **信頼性**: 🔵 *PRD 8.2*

---

## テストケースサマリー

### カテゴリ別件数

| カテゴリ | 正常系 | 異常系 | 合計 |
|---------|--------|--------|------|
| メモリロック (REQ-001〜005) | 5 | 2 | 7 |
| プロセス硬化 (REQ-010〜013) | 6 | 2 | 8 |
| SecretString化 (REQ-020) | 3 | 0 | 3 |
| not_implemented bail! (REQ-021) | 2 | 0 | 2 |
| 中間バッファ Zeroizing (REQ-022) | 3 | 0 | 3 |
| PQC依存ピン (REQ-023) | 4 | 0 | 4 |
| verify_hmac Result (REQ-024) | 4 | 0 | 4 |
| 署名/HMAC検証 (REQ-025〜027) | 3 | 4 | 7 |
| E2Eテスト (REQ-030) | 13 | 0 | 13 |
| パフォーマンス (REQ-031〜035) | 6 | 0 | 6 |
| 制約要件 (REQ-401〜403) | 4 | 0 | 4 |
| 非機能要件 (NFR) | 4 | 0 | 4 |
| **合計** | **57** | **8** | **65** |

### 信頼性レベル分布

- 🔵 青信号: 65件 (100%)
- 🟡 黄信号: 0件 (0%)
- 🔴 赤信号: 0件 (0%)

**品質評価**: 高品質 - 全項目PRD・バックログ・ヒアリングで確認済み

### 優先度別テストケース

- **Must Have**: 65件
- **Should Have**: 0件
- **Could Have**: 0件
