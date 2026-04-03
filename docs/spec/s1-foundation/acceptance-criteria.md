# s1-foundation 受け入れ基準

**作成日**: 2026-04-03
**関連要件定義**: [requirements.md](requirements.md)
**関連ユーザストーリー**: [user-stories.md](user-stories.md)
**ヒアリング記録**: [interview-record.md](interview-record.md)

**【信頼性レベル凡例】**:
- 🔵 **青信号**: PRD・ユーザヒアリングを参考にした確実な基準
- 🟡 **黄信号**: PRDから妥当な推測による基準
- 🔴 **赤信号**: PRDにない推測による基準

---

## REQ-001: Cargoワークスペース 🔵

**信頼性**: 🔵 *PRDセクション2.1より*

### Given（前提条件）
- プロジェクトルートに `Cargo.toml`, `core/`, `cli/` が存在する

### When（実行条件）
- `cargo build --workspace` を実行する

### Then（期待結果）
- ビルドが警告なしで成功する
- `core/` が `pq-diary-core` ライブラリクレートとしてビルドされる
- `cli/` が `pq-diary` バイナリクレートとしてビルドされる

### テストケース

#### 正常系

- [ ] **TC-001-01**: ワークスペースビルド成功 🔵
  - **入力**: `cargo build --workspace`
  - **期待結果**: exit code 0、警告なし

- [ ] **TC-001-02**: core/ が独立してビルド可能 🔵
  - **入力**: `cargo build -p pq-diary-core`
  - **期待結果**: exit code 0

- [ ] **TC-001-03**: cli/ が core/ に依存してビルド可能 🔵
  - **入力**: `cargo build -p pq-diary`
  - **期待結果**: exit code 0、`pq-diary-core` がリンクされている

#### 異常系

- [ ] **TC-001-E01**: core/ のコンパイルエラーがcli/ビルドもブロックする 🔵
  - **入力**: core/src/lib.rs に構文エラーを混入し `cargo build --workspace`
  - **期待結果**: ビルド失敗
  - **信頼性**: 🔵 *Cargoワークスペースの標準動作*

---

## REQ-002: DiaryError 🔵

**信頼性**: 🔵 *PRD + ヒアリングQ3より*

### Given（前提条件）
- `core/src/error.rs` が存在する

### When（実行条件）
- DiaryError の各バリアントを生成する

### Then（期待結果）
- 各バリアントが `Display` トレイトで人間が読めるメッセージを返す
- `std::error::Error` が実装されている
- 外部エラーからの `From` 変換が機能する

### テストケース

#### 正常系

- [ ] **TC-002-01**: 全バリアントの Display 出力 🔵
  - **入力**: 各バリアントを生成
  - **期待結果**: 空でない英語のエラーメッセージ

- [ ] **TC-002-02**: std::io::Error からの変換 🔵
  - **入力**: `io::Error::new(io::ErrorKind::NotFound, "test")`
  - **期待結果**: `DiaryError::Io(_)` に変換される

- [ ] **TC-002-03**: source() チェイン 🔵
  - **入力**: ラップされたエラー
  - **期待結果**: `error.source()` が元のエラーを返す

#### 境界値

- [ ] **TC-002-B01**: 全バリアント網羅テスト 🔵
  - **入力**: Crypto, Vault, Entry, Git, Legacy, Policy, Io, Config, Editor, Import, Template, Search, NotUnlocked 等の全バリアント
  - **期待結果**: コンパイルが通り、各 Display が非空文字列

---

## REQ-003: セキュアメモリ型 🔵

**信頼性**: 🔵 *PRDセクション8.1 + ヒアリングQ1より*

### Given（前提条件）
- `zeroize` と `secrecy` クレートが依存に含まれる

### When（実行条件）
- SecureBuffer / ZeroizingKey をDropする

### Then（期待結果）
- 内部データがゼロ埋めされる

### テストケース

#### 正常系

- [ ] **TC-003-01**: SecureBuffer のzeroize動作 🔵
  - **入力**: `SecureBuffer::new(vec![0xAA; 32])` を作成しDropする
  - **期待結果**: Drop後に内部バッファの内容がゼロであることを検証（unsafeテスト）

- [ ] **TC-003-02**: ZeroizingKey のzeroize動作 🔵
  - **入力**: `ZeroizingKey::new([0xBB; 32])` を作成しDropする
  - **期待結果**: Drop後にキーの内容がゼロ

- [ ] **TC-003-03**: MasterKey のZeroizeOnDrop派生 🔵
  - **入力**: MasterKey構造体にダミーデータを設定
  - **期待結果**: `#[derive(ZeroizeOnDrop)]` によりDrop時に全フィールドがゼロ化

- [ ] **TC-003-04**: CryptoEngine の施錠状態 🔵
  - **入力**: `CryptoEngine { master_key: None, legacy_key: None }`
  - **期待結果**: 施錠状態であることを示すメソッドが `true` を返す

#### 異常系

- [ ] **TC-003-E01**: CryptoEngine 施錠状態での操作拒否 🔵
  - **入力**: `master_key: None` の状態で暗号操作を試行
  - **期待結果**: `DiaryError::NotUnlocked` が返る

#### 境界値

- [ ] **TC-003-B01**: 空のSecureBuffer 🔵
  - **入力**: `SecureBuffer::new(vec![])`
  - **期待結果**: パニックしない、正常にDropされる
  - **信頼性**: 🔵 *ヒアリングで境界値テスト含めると確定*

- [ ] **TC-003-B02**: 大きなSecureBuffer (1MB) 🔵
  - **入力**: `SecureBuffer::new(vec![0xFF; 1_048_576])`
  - **期待結果**: 正常にzeroize・Dropされる
  - **信頼性**: 🔵 *ヒアリングで境界値テスト含めると確定*

---

## REQ-004: CLIスケルトン 🔵

**信頼性**: 🔵 *PRDセクション4.1 + ヒアリングQ2より*

### Given（前提条件）
- cli/ が `clap` (derive) で構成されている

### When（実行条件）
- `pq-diary --help` を実行する

### Then（期待結果）
- 全サブコマンドが一覧表示される
- 各サブコマンドの `--help` が機能する

### テストケース

#### 正常系

- [ ] **TC-004-01**: トップレベル --help 🔵
  - **入力**: `pq-diary --help`
  - **期待結果**: init, vault, new, list, show, edit, delete 等の全コマンドが表示

- [ ] **TC-004-02**: サブコマンド --help 🔵
  - **入力**: `pq-diary vault --help`
  - **期待結果**: create, list, policy, delete サブコマンドが表示

- [ ] **TC-004-03**: グローバルオプション 🔵
  - **入力**: `pq-diary --help`
  - **期待結果**: -v/--vault, --password, --claude, --debug オプションが表示

- [ ] **TC-004-04**: 未実装コマンドの実行 🔵
  - **入力**: `pq-diary daemon start`
  - **期待結果**: "Planned for Sprint N" を含むメッセージが表示され、非ゼロ exit code

#### 異常系

- [ ] **TC-004-E01**: 存在しないコマンド 🔵
  - **入力**: `pq-diary nonexistent`
  - **期待結果**: clapのエラーメッセージ + 非ゼロ exit code
  - **信頼性**: 🔵 *clapの標準動作*

---

## REQ-005: GitHub Actions CI 🔵

**信頼性**: 🔵 *ヒアリングQ4より*

### Given（前提条件）
- `.github/workflows/ci.yml` が存在する

### When（実行条件）
- mainブランチまたはPRへのpush

### Then（期待結果）
- ubuntu-latest で4つのジョブが実行される

### テストケース

#### 正常系

- [ ] **TC-005-01**: CI設定ファイルの構文 🔵
  - **入力**: `.github/workflows/ci.yml` を検証
  - **期待結果**: 有効なYAML、trigger: push + pull_request、ubuntu-latest、4コマンド実行

- [ ] **TC-005-02**: cargo audit 含有 🔵
  - **入力**: CI設定を確認
  - **期待結果**: `cargo audit` ステップが含まれる

---

## テストケースサマリー

### カテゴリ別件数

| カテゴリ | 正常系 | 異常系 | 境界値 | 合計 |
|---------|--------|--------|--------|------|
| REQ-001 ワークスペース | 3 | 1 | 0 | 4 |
| REQ-002 DiaryError | 3 | 0 | 1 | 4 |
| REQ-003 セキュアメモリ | 4 | 1 | 2 | 7 |
| REQ-004 CLIスケルトン | 4 | 1 | 0 | 5 |
| REQ-005 CI | 2 | 0 | 0 | 2 |
| **合計** | **16** | **3** | **3** | **22** |

### 信頼性レベル分布

- 🔵 青信号: 22件 (100%)
- 🟡 黄信号: 0件 (0%)
- 🔴 赤信号: 0件 (0%)

**品質評価**: 最高品質 — 全テストケースがPRD・ヒアリングに裏付けられている

### 優先度別テストケース

- **Must Have**: 22件 (全件)
