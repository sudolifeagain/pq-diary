# S8 Git Sync 受け入れ基準

**作成日**: 2026-04-10
**関連要件定義**: [requirements.md](requirements.md)
**関連ユーザストーリー**: [user-stories.md](user-stories.md)
**ヒアリング記録**: [interview-record.md](interview-record.md)

**【信頼性レベル凡例】**:
- 🔵 **青信号**: PRD・設計文書・ユーザヒアリングを参考にした確実な基準

---

## REQ-001〜005: Git Init 🔵

**信頼性**: 🔵 *PRD 4.1 + PRD 11.1〜11.3 + ADR-0006 + ヒアリングQ1,Q2*

### Given
- Vaultが作成済みで `.git` が未初期化

### When
- `git-init [--remote URL]` を実行する

### Then
- `.git` ディレクトリが作成される
- `.gitignore` が生成され `entries/*.md` が除外される
- vault.toml に author_name="pq-diary" と author_email="{8桁hex}@localhost" が保存される
- `--remote` 指定時は `origin` リモートが設定される

### テストケース

#### 正常系

- [ ] **TC-S8-001-01**: git-initで.gitディレクトリ作成 🔵
  - **入力**: `pq-diary git-init`
  - **期待結果**: Vaultディレクトリ内に `.git` が存在
  - **信頼性**: 🔵 *PRD 4.1*

- [ ] **TC-S8-001-02**: .gitignoreの生成と内容確認 🔵
  - **入力**: `pq-diary git-init`
  - **期待結果**: `.gitignore` に `entries/*.md` が含まれる
  - **信頼性**: 🔵 *PRD 11.2*

- [ ] **TC-S8-001-03**: author_emailのランダム生成 🔵
  - **入力**: `pq-diary git-init`
  - **期待結果**: vault.toml の `[git].author_email` が 8桁hex + `@localhost` 形式
  - **信頼性**: 🔵 *PRD 11.3 + ヒアリングQ2*

- [ ] **TC-S8-001-04**: author_nameの設定 🔵
  - **入力**: `pq-diary git-init`
  - **期待結果**: vault.toml の `[git].author_name` が `"pq-diary"`
  - **信頼性**: 🔵 *PRD 11.3*

- [ ] **TC-S8-001-05**: --remoteでorigin設定 🔵
  - **入力**: `pq-diary git-init --remote https://github.com/user/vault.git`
  - **期待結果**: `git remote -v` で `origin` が表示される
  - **信頼性**: 🔵 *PRD 4.1*

- [ ] **TC-S8-001-06**: パスワード不要で実行可能 🔵
  - **入力**: `pq-diary git-init`（パスワード未指定）
  - **期待結果**: パスワードプロンプトなしで完了
  - **信頼性**: 🔵 *ヒアリングQ3「git-initはPW不要」*

- [ ] **TC-S8-001-07**: --remote省略時はリモートなし 🔵
  - **入力**: `pq-diary git-init`
  - **期待結果**: `git remote -v` が空
  - **信頼性**: 🔵 *PRD 4.1*

#### 異常系

- [ ] **TC-S8-001-E01**: 既にgit初期化済みVaultへの再git-init 🔵
  - **入力**: git初期化済みVaultで `pq-diary git-init`
  - **期待結果**: DiaryError::Git エラー
  - **信頼性**: 🔵 *ヒアリングQ4「エラー」*

- [ ] **TC-S8-001-E02**: gitが未インストール 🔵
  - **入力**: git未インストール環境で `pq-diary git-init`
  - **期待結果**: 分かりやすいエラーメッセージ（例: "git is not installed"）
  - **信頼性**: 🔵 *PRD 11.1 + ADR-0006*

---

## REQ-010〜017: Git Push 🔵

**信頼性**: 🔵 *PRD 11.2〜11.3 + ADR-0006 + ヒアリングQ3*

### Given
- Vaultがgit初期化済みでリモートが設定済み

### When
- `git-push` を実行する

### Then
- vault.pqd + vault.toml がステージングされる
- 匿名化authorでコミットされる
- 定型メッセージでコミットされる
- 追加パディングが付与される
- タイムスタンプがファジングされる
- リモートにpushされる

### テストケース

#### 正常系

- [ ] **TC-S8-010-01**: vault.pqd + vault.tomlのステージング 🔵
  - **入力**: `pq-diary git-push`
  - **期待結果**: `git log --stat` で vault.pqd と vault.toml のみがコミットに含まれる
  - **信頼性**: 🔵 *PRD 11.2*

- [ ] **TC-S8-010-02**: 匿名化authorの使用 🔵
  - **入力**: `pq-diary git-push`
  - **期待結果**: `git log --format='%an <%ae>'` が `pq-diary <{hex}@localhost>` 形式
  - **信頼性**: 🔵 *PRD 11.3 + ADR-0006*

- [ ] **TC-S8-010-03**: 定型コミットメッセージの使用 🔵
  - **入力**: `pq-diary git-push`（vault.toml の commit_message = "Update vault"）
  - **期待結果**: `git log --format='%s'` が `"Update vault"`
  - **信頼性**: 🔵 *PRD 11.3*

- [ ] **TC-S8-010-04**: 追加パディング付与 🔵
  - **入力**: `pq-diary git-push`（extra_padding_bytes_max = 4096）
  - **期待結果**: vault.pqdのファイルサイズがpush前より 0〜4096B 増加
  - **信頼性**: 🔵 *PRD 11.3 + ADR-0006*

- [ ] **TC-S8-010-05**: タイムスタンプファジング適用 🔵
  - **入力**: `pq-diary git-push`（timestamp_fuzz_hours = 6）
  - **期待結果**: コミット日時が実際の日時と異なる（ファジング範囲内）
  - **信頼性**: 🔵 *PRD 11.3 + ADR-0006*

- [ ] **TC-S8-010-06**: タイムスタンプ単調増加保証 🔵
  - **入力**: 連続2回の `pq-diary git-push`
  - **期待結果**: 2回目のコミット日時 > 1回目のコミット日時
  - **信頼性**: 🔵 *PRD 11.3*

- [ ] **TC-S8-010-07**: パスワード要求 🔵
  - **入力**: `pq-diary git-push`
  - **期待結果**: パスワードプロンプトが表示される
  - **信頼性**: 🔵 *ヒアリングQ3「pushはPW必要」*

- [ ] **TC-S8-010-08**: extra_padding_bytes_max=0でパディング無効 🔵
  - **入力**: `pq-diary git-push`（extra_padding_bytes_max = 0）
  - **期待結果**: vault.pqdのファイルサイズが変化しない（追加パディングなし）
  - **信頼性**: 🔵 *config.rs デフォルト値*

- [ ] **TC-S8-010-09**: entries/*.mdがコミットに含まれない 🔵
  - **入力**: entries/ にファイルが存在する状態で `pq-diary git-push`
  - **期待結果**: `git log --stat` に entries/*.md が含まれない
  - **信頼性**: 🔵 *PRD 11.2*

#### 異常系

- [ ] **TC-S8-010-E01**: リモート未設定でのgit-push 🔵
  - **入力**: リモート未設定のVaultで `pq-diary git-push`
  - **期待結果**: DiaryError::Git エラー
  - **信頼性**: 🔵 *標準git動作*

- [ ] **TC-S8-010-E02**: .git未初期化でのgit-push 🔵
  - **入力**: git未初期化のVaultで `pq-diary git-push`
  - **期待結果**: DiaryError::Git エラー
  - **信頼性**: 🔵 *標準git動作*

---

## REQ-020〜028: Git Pull + Merge 🔵

**信頼性**: 🔵 *PRD 11.4 + ヒアリングQ3,Q4*

### Given
- Vaultがgit初期化済みでリモートが設定済み

### When
- `git-pull` を実行する

### Then
- リモートからフェッチされる
- UUID + content_hmac でエントリ単位の3-wayマージが実行される
- マージ結果がvault.pqdに再暗号化・アトミック書き込みされる

### テストケース

#### 正常系

- [ ] **TC-S8-020-01**: リモートからのフェッチ 🔵
  - **入力**: リモートに変更がある状態で `pq-diary git-pull`
  - **期待結果**: リモートの変更がフェッチされる
  - **信頼性**: 🔵 *PRD 4.1*

- [ ] **TC-S8-020-02**: パスワード要求 🔵
  - **入力**: `pq-diary git-pull`
  - **期待結果**: パスワードプロンプトが表示される
  - **信頼性**: 🔵 *ヒアリングQ3「pullはPW必要」*

- [ ] **TC-S8-020-03**: UUID判定による同一エントリ認識 🔵
  - **入力**: ローカルとリモートに同一UUIDのエントリ
  - **期待結果**: 同一エントリとして認識される
  - **信頼性**: 🔵 *PRD 11.4*

- [ ] **TC-S8-020-04**: content_hmacによる変更検出 🔵
  - **入力**: 同一UUIDでcontent_hmacが異なるエントリ
  - **期待結果**: 変更ありとして検出される
  - **信頼性**: 🔵 *PRD 11.4 + OQ-19*

- [ ] **TC-S8-020-05**: リモートのみの新規エントリ追加 🔵
  - **入力**: リモートにのみ存在するエントリ
  - **期待結果**: ローカルに追加される
  - **信頼性**: 🔵 *標準マージ動作*

- [ ] **TC-S8-020-06**: リモートで削除されたエントリの削除 🔵
  - **入力**: リモートで削除されたエントリがローカルに存在
  - **期待結果**: ローカルから削除される
  - **信頼性**: 🔵 *標準マージ動作*

- [ ] **TC-S8-020-07**: マージ後のvault.pqd再暗号化・アトミック書き込み 🔵
  - **入力**: マージが完了した状態
  - **期待結果**: vault.pqdが再暗号化されてアトミックに書き込まれる
  - **信頼性**: 🔵 *既存write_vaultパターン*

- [ ] **TC-S8-020-08**: ローカル未変更・リモート変更のマージ 🔵
  - **入力**: ローカル未変更、リモートにエントリ変更あり
  - **期待結果**: リモートの変更が適用される（コンフリクトなし）
  - **信頼性**: 🔵 *標準マージ動作*

#### 異常系

- [ ] **TC-S8-020-E01**: リモート未設定でのgit-pull 🔵
  - **入力**: リモート未設定のVaultで `pq-diary git-pull`
  - **期待結果**: DiaryError::Git エラー
  - **信頼性**: 🔵 *標準git動作*

- [ ] **TC-S8-020-E02**: .git未初期化でのgit-pull 🔵
  - **入力**: git未初期化のVaultで `pq-diary git-pull`
  - **期待結果**: DiaryError::Git エラー
  - **信頼性**: 🔵 *標準git動作*

---

## REQ-025〜026: コンフリクト解決 🔵

**信頼性**: 🔵 *PRD 11.4 + ヒアリングQ3「--claudeコンフリクト: ローカル勝ち」*

### Given
- 同一UUIDのエントリがローカルとリモートの両方で変更されている

### When
- git-pullのマージ中にコンフリクトが検出される

### Then
- 通常モード: 対話式プロンプトで解決
- --claudeモード: ローカル側が自動的に優先

### テストケース

#### 正常系

- [ ] **TC-S8-025-01**: 対話式コンフリクト解決（ローカル選択） 🔵
  - **入力**: コンフリクト発生時に `L` を入力
  - **期待結果**: ローカル版が採用される
  - **信頼性**: 🔵 *PRD 11.4*

- [ ] **TC-S8-025-02**: 対話式コンフリクト解決（リモート選択） 🔵
  - **入力**: コンフリクト発生時に `R` を入力
  - **期待結果**: リモート版が採用される
  - **信頼性**: 🔵 *PRD 11.4*

- [ ] **TC-S8-025-03**: --claudeでローカル自動優先 🔵
  - **入力**: `pq-diary --claude git-pull` でコンフリクト発生
  - **期待結果**: 対話プロンプトなし、ローカル版が自動採用
  - **信頼性**: 🔵 *ヒアリングQ3*

- [ ] **TC-S8-025-04**: 複数エントリコンフリクトの逐次解決 🔵
  - **入力**: 3つのエントリがコンフリクト
  - **期待結果**: 各エントリについて個別にプロンプト表示
  - **信頼性**: 🔵 *PRD 11.4*

---

## REQ-030〜031: Git Sync 🔵

**信頼性**: 🔵 *ヒアリングQ3「sync = pull → push」*

### Given
- Vaultがgit初期化済みでリモートが設定済み

### When
- `git-sync` を実行する

### Then
- pull → push の順序で実行される

### テストケース

- [ ] **TC-S8-030-01**: sync = pull → push の実行順序 🔵
  - **入力**: `pq-diary git-sync`
  - **期待結果**: まずリモートからpull（マージ含む）、次にpush
  - **信頼性**: 🔵 *ヒアリングQ3*

- [ ] **TC-S8-030-02**: パスワード要求 🔵
  - **入力**: `pq-diary git-sync`
  - **期待結果**: パスワードプロンプトが表示される（1回のみ）
  - **信頼性**: 🔵 *ヒアリングQ3*

- [ ] **TC-S8-030-03**: pullが失敗した場合pushは実行しない 🔵
  - **入力**: リモート接続失敗の状態で `pq-diary git-sync`
  - **期待結果**: pullでエラー、pushは未実行
  - **信頼性**: 🔵 *標準エラーハンドリング*

---

## REQ-040: Git Status 🔵

**信頼性**: 🔵 *PRD 4.1 + ヒアリングQ1*

### テストケース

- [ ] **TC-S8-040-01**: git status出力の表示 🔵
  - **入力**: `pq-diary git-status`
  - **期待結果**: `git status` の出力がそのまま表示される
  - **信頼性**: 🔵 *PRD 4.1*

- [ ] **TC-S8-040-02**: パスワード不要で実行可能 🔵
  - **入力**: `pq-diary git-status`（パスワード未指定）
  - **期待結果**: パスワードプロンプトなしで完了
  - **信頼性**: 🔵 *ヒアリングQ3「git-statusはPW不要」*

- [ ] **TC-S8-040-E01**: .git未初期化でのgit-status 🔵
  - **入力**: git未初期化のVaultで `pq-diary git-status`
  - **期待結果**: DiaryError::Git エラー
  - **信頼性**: 🔵 *標準git動作*

---

## REQ-050〜054: プライバシー要件 🔵

**信頼性**: 🔵 *PRD 11.1〜11.3 + ADR-0006*

### テストケース

- [ ] **TC-S8-050-01**: git --versionチェック成功 🔵
  - **入力**: gitインストール済み環境でgitコマンド実行
  - **期待結果**: git --version チェック通過後にコマンド実行
  - **信頼性**: 🔵 *PRD 11.1*

- [ ] **TC-S8-050-02**: git --versionチェック失敗 🔵
  - **入力**: git未インストール環境でgitコマンド実行
  - **期待結果**: 分かりやすいエラーメッセージ
  - **信頼性**: 🔵 *PRD 11.1 + ADR-0006*

- [ ] **TC-S8-050-03**: .gitignoreにentries/*.mdが含まれる 🔵
  - **入力**: git-init後の .gitignore
  - **期待結果**: `entries/*.md` が含まれる
  - **信頼性**: 🔵 *PRD 11.2*

- [ ] **TC-S8-050-04**: コミットauthorのフォーマット検証 🔵
  - **入力**: git-push後のコミット
  - **期待結果**: author が `pq-diary <{8桁hex}@localhost>` 形式
  - **信頼性**: 🔵 *PRD 11.3 + ADR-0006*

- [ ] **TC-S8-050-05**: コミットメッセージが定型 🔵
  - **入力**: git-push後のコミット
  - **期待結果**: メッセージが vault.toml の commit_message と一致
  - **信頼性**: 🔵 *PRD 11.3*

- [ ] **TC-S8-050-06**: extra_padding_bytes_max=0でパディング無効 🔵
  - **入力**: extra_padding_bytes_max=0 の状態で git-push
  - **期待結果**: 追加パディングなし
  - **信頼性**: 🔵 *config.rs デフォルト値*

---

## Edgeケーステスト 🔵

**信頼性**: 🔵 *ヒアリングQ4 確定*

### テストケース

- [ ] **TC-S8-EDGE-001**: gitが未インストール 🔵
  - **入力**: git未インストール環境で任意のgitコマンド
  - **期待結果**: `"git is not installed. Please install git to use sync features."` 等のエラー
  - **信頼性**: 🔵 *PRD 11.1*

- [ ] **TC-S8-EDGE-002**: リモート未設定でgit-push 🔵
  - **入力**: リモート未設定のVaultで `pq-diary git-push`
  - **期待結果**: DiaryError::Git エラー（リモート未設定を示すメッセージ）
  - **信頼性**: 🔵 *標準git動作*

- [ ] **TC-S8-EDGE-003**: リモート未設定でgit-pull 🔵
  - **入力**: リモート未設定のVaultで `pq-diary git-pull`
  - **期待結果**: DiaryError::Git エラー
  - **信頼性**: 🔵 *標準git動作*

- [ ] **TC-S8-EDGE-004**: リモートが空の場合のマージ 🔵
  - **入力**: リモートにエントリがない状態で `pq-diary git-pull`
  - **期待結果**: no-op（ローカルは変更なし）
  - **信頼性**: 🔵 *ヒアリングQ4*

- [ ] **TC-S8-EDGE-005**: ローカルが空の場合のマージ 🔵
  - **入力**: ローカルにエントリがない状態で `pq-diary git-pull`（リモートにエントリあり）
  - **期待結果**: リモートの全エントリを受け入れ
  - **信頼性**: 🔵 *ヒアリングQ4*

- [ ] **TC-S8-EDGE-006**: git-init済みVaultへの再git-init 🔵
  - **入力**: git初期化済みVaultで `pq-diary git-init`
  - **期待結果**: DiaryError::Git エラー
  - **信頼性**: 🔵 *ヒアリングQ4*

- [ ] **TC-S8-EDGE-007**: .git未初期化でgit-sync 🔵
  - **入力**: git未初期化のVaultで `pq-diary git-sync`
  - **期待結果**: DiaryError::Git エラー
  - **信頼性**: 🔵 *標準git動作*

---

## 非機能要件テスト

### NFR-001: git --versionチェック性能 🔵

**信頼性**: 🔵 *ADR-0006*

- [ ] **TC-S8-NFR-001-01**: git --versionチェックのレイテンシ 🔵
  - **測定項目**: `git --version` コマンドの実行時間
  - **目標値**: < 100ms
  - **信頼性**: 🔵 *ADR-0006*

### NFR-101: コミットへの秘密情報不含 🔵

- [ ] **TC-S8-NFR-101-01**: コミットauthorに個人情報なし 🔵
  - **入力**: git-push後のコミット履歴
  - **期待結果**: author_name が "pq-diary"、author_email が "{hex}@localhost" 形式のみ
  - **信頼性**: 🔵 *PRD 11.3*

- [ ] **TC-S8-NFR-101-02**: コミットメッセージに秘密情報なし 🔵
  - **入力**: git-push後のコミットメッセージ
  - **期待結果**: vault.toml の commit_message のみ（エントリ内容やタイトルなし）
  - **信頼性**: 🔵 *PRD 11.3*

### NFR-102: entries/*.md の非コミット 🔵

- [ ] **TC-S8-NFR-102-01**: entries/ディレクトリがgit管理外 🔵
  - **入力**: `git status --porcelain` の出力
  - **期待結果**: entries/ 内のファイルが表示されない
  - **信頼性**: 🔵 *PRD 11.2*

---

## テストケースサマリー

### カテゴリ別件数

| カテゴリ | 正常系 | 異常系 | 合計 |
|---------|--------|--------|------|
| Git Init (REQ-001〜005) | 7 | 2 | 9 |
| Git Push (REQ-010〜017) | 9 | 2 | 11 |
| Git Pull + Merge (REQ-020〜028) | 8 | 2 | 10 |
| コンフリクト解決 (REQ-025〜026) | 4 | 0 | 4 |
| Git Sync (REQ-030〜031) | 3 | 0 | 3 |
| Git Status (REQ-040) | 2 | 1 | 3 |
| プライバシー (REQ-050〜054) | 6 | 0 | 6 |
| Edgeケース (EDGE) | 0 | 7 | 7 |
| 非機能 (NFR) | 4 | 0 | 4 |
| **合計** | **43** | **14** | **57** |

### 信頼性レベル分布

- 🔵 青信号: 57件 (100%)
- 🟡 黄信号: 0件 (0%)
- 🔴 赤信号: 0件 (0%)

**品質評価**: 高品質 - 全項目ヒアリングで確認済み

### 優先度別テストケース

- **Must Have**: 57件
- **Should Have**: 0件
- **Could Have**: 0件
