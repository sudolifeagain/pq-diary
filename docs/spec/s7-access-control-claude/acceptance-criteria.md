# S7 Access Control + Claude 受け入れ基準

**作成日**: 2026-04-10
**関連要件定義**: [requirements.md](requirements.md)
**関連ユーザストーリー**: [user-stories.md](user-stories.md)
**ヒアリング記録**: [interview-record.md](interview-record.md)

**【信頼性レベル凡例】**:
- 🔵 **青信号**: PRD・設計文書・ユーザヒアリングを参考にした確実な基準

---

## REQ-001〜003: AccessPolicy enum定義 🔵

**信頼性**: 🔵 *PRD 4.4 + ヒアリングQ7「enum化」+ 追加確認Q10項目1,2承認*

### Given
- `core/src/policy.rs` が存在する

### When
- AccessPolicy enum を定義する

### Then
- `None`, `WriteOnly`, `Full` の3バリアントが定義されている
- serde で `"none"` / `"write_only"` / `"full"` と相互変換可能
- `AccessSection.policy` の型が `AccessPolicy` に変更されている

### テストケース

#### 正常系

- [ ] **TC-S7-001-01**: AccessPolicy::None のserialize結果が `"none"` 🔵
  - **入力**: `AccessPolicy::None`
  - **期待結果**: TOML文字列 `"none"`
  - **信頼性**: 🔵 *PRD 3.2 vault.toml仕様*

- [ ] **TC-S7-001-02**: AccessPolicy::WriteOnly のserialize結果が `"write_only"` 🔵
  - **入力**: `AccessPolicy::WriteOnly`
  - **期待結果**: TOML文字列 `"write_only"`
  - **信頼性**: 🔵 *PRD 3.2 vault.toml仕様*

- [ ] **TC-S7-001-03**: AccessPolicy::Full のserialize結果が `"full"` 🔵
  - **入力**: `AccessPolicy::Full`
  - **期待結果**: TOML文字列 `"full"`
  - **信頼性**: 🔵 *PRD 3.2 vault.toml仕様*

- [ ] **TC-S7-001-04**: `"none"` からAccessPolicy::None へのdeserialize 🔵
  - **入力**: TOML文字列 `policy = "none"`
  - **期待結果**: `AccessPolicy::None`
  - **信頼性**: 🔵 *PRD 3.2*

- [ ] **TC-S7-001-05**: `"write_only"` からAccessPolicy::WriteOnly へのdeserialize 🔵
  - **入力**: TOML文字列 `policy = "write_only"`
  - **期待結果**: `AccessPolicy::WriteOnly`
  - **信頼性**: 🔵 *PRD 3.2*

- [ ] **TC-S7-001-06**: `"full"` からAccessPolicy::Full へのdeserialize 🔵
  - **入力**: TOML文字列 `policy = "full"`
  - **期待結果**: `AccessPolicy::Full`
  - **信頼性**: 🔵 *PRD 3.2*

- [ ] **TC-S7-001-07**: 既存vault.toml（policy="none"文字列）との後方互換性 🔵
  - **入力**: S6以前で生成されたvault.toml
  - **期待結果**: 正常にパースされAccessPolicy::Noneが得られる
  - **信頼性**: 🔵 *追加確認Q10項目2承認*

#### 異常系

- [ ] **TC-S7-001-E01**: 無効なポリシー文字列のdeserialize 🔵
  - **入力**: TOML文字列 `policy = "read_only"`
  - **期待結果**: DiaryError::Config
  - **信頼性**: 🔵 *追加確認Q10項目5「デシリアライズエラー」+ Q11「エラーを返す」*

- [ ] **TC-S7-001-E02**: 空文字列のdeserialize 🔵
  - **入力**: TOML文字列 `policy = ""`
  - **期待結果**: DiaryError::Config
  - **信頼性**: 🔵 *追加確認Q11「エラーを返す」*

---

## REQ-010: 操作分類 🔵

**信頼性**: 🔵 *PRD 4.4 + ヒアリングQ2,Q8 確定*

### Given
- AccessPolicy と コマンド種別が定義されている

### When
- 各コマンドの操作種別を判定する

### Then
- read操作: list, show, search, stats, template-show, template-list
- write操作: new, edit, delete, sync, today, template-add, template-delete, import

### テストケース

- [ ] **TC-S7-010-01**: 全read操作の分類確認 🔵
  - **入力**: list, show, search, stats, template-show, template-list
  - **期待結果**: すべて `OperationType::Read` を返す
  - **信頼性**: 🔵 *ヒアリングQ8 確定*

- [ ] **TC-S7-010-02**: 全write操作の分類確認 🔵
  - **入力**: new, edit, delete, sync, today, template-add, template-delete, import
  - **期待結果**: すべて `OperationType::Write` を返す
  - **信頼性**: 🔵 *ヒアリングQ8 確定*

---

## REQ-020〜025: 4層ポリシーチェック 🔵

**信頼性**: 🔵 *PRD 4.4 + ヒアリングQ2,Q3,Q6,Q8*

### Given
- Vaultが存在しvault.tomlにポリシーが設定されている

### When
- `--claude` フラグ付きでコマンドを実行する

### Then
- Layer 1: --claudeなし → ポリシーチェックスキップ
- Layer 2: None → 即時拒否（復号なし）
- Layer 3: WriteOnly + read → 拒否
- Layer 3: WriteOnly + write → 許可
- Layer 4: Full → 全許可

### テストケース

#### 正常系

- [ ] **TC-S7-020-01**: --claudeなしでNoneポリシーVaultにアクセス可能 🔵
  - **入力**: `pq-diary -v private show abc123`（--claudeなし）
  - **期待結果**: 通常通りエントリ表示
  - **信頼性**: 🔵 *PRD 4.4 Layer 1*

- [ ] **TC-S7-020-02**: --claude + Full + read操作 → 許可 🔵
  - **入力**: `pq-diary --claude -v analysis show abc123`
  - **期待結果**: エントリ表示成功
  - **信頼性**: 🔵 *PRD 4.4 Layer 4*

- [ ] **TC-S7-020-03**: --claude + Full + write操作 → 許可 🔵
  - **入力**: `pq-diary --claude -v analysis new "test" -b "body"`
  - **期待結果**: エントリ作成成功
  - **信頼性**: 🔵 *PRD 4.4 Layer 4*

- [ ] **TC-S7-020-04**: --claude + WriteOnly + write操作 → 許可 🔵
  - **入力**: `pq-diary --claude -v work new "test" -b "body"`
  - **期待結果**: エントリ作成成功
  - **信頼性**: 🔵 *PRD 4.4 Layer 3*

- [ ] **TC-S7-020-05**: --claude + WriteOnly + delete操作 → 許可 🔵
  - **入力**: `pq-diary --claude -v work delete abc123`
  - **期待結果**: エントリ削除成功
  - **信頼性**: 🔵 *PRD 4.4 Layer 3 + ヒアリングQ8*

- [ ] **TC-S7-020-06**: --claude + WriteOnly + today操作 → 許可 🔵
  - **入力**: `pq-diary --claude -v work today`
  - **期待結果**: today実行成功
  - **信頼性**: 🔵 *ヒアリングQ8 write操作分類確定*

#### 異常系

- [ ] **TC-S7-020-E01**: --claude + None + write操作 → 即時拒否 🔵
  - **入力**: `pq-diary --claude -v private new "test" -b "body"`
  - **期待結果**: `DiaryError::Policy` エラー、復号なし
  - **信頼性**: 🔵 *PRD 4.4 Layer 2*

- [ ] **TC-S7-020-E02**: --claude + WriteOnly + show → 拒否 🔵
  - **入力**: `pq-diary --claude -v work show abc123`
  - **期待結果**: `DiaryError::Policy` エラー
  - **信頼性**: 🔵 *PRD 4.4 Layer 3*

- [ ] **TC-S7-020-E03**: --claude + WriteOnly + list → 拒否 🔵
  - **入力**: `pq-diary --claude -v work list`
  - **期待結果**: `DiaryError::Policy` エラー
  - **信頼性**: 🔵 *PRD 4.4 Layer 3*

- [ ] **TC-S7-020-E04**: --claude + WriteOnly + search → 拒否 🔵
  - **入力**: `pq-diary --claude -v work search "pattern"`
  - **期待結果**: `DiaryError::Policy` エラー
  - **信頼性**: 🔵 *PRD 4.4 Layer 3 + ヒアリングQ2「searchは拒否」*

- [ ] **TC-S7-020-E05**: --claude + WriteOnly + stats → 拒否 🔵
  - **入力**: `pq-diary --claude -v work stats`
  - **期待結果**: `DiaryError::Policy` エラー
  - **信頼性**: 🔵 *PRD 4.4 Layer 3 + ヒアリングQ8*

- [ ] **TC-S7-020-E06**: --claude + None + パスワード指定 → 復号せず拒否 🔵
  - **入力**: `pq-diary --claude --password pass -v private show abc123`
  - **期待結果**: `DiaryError::Policy` エラー、vault.pqd未読み取り
  - **信頼性**: 🔵 *PRD 4.4 Layer 2「復号試行なし」*

---

## REQ-030〜032: vault create 🔵

**信頼性**: 🔵 *PRD 4.1 + ヒアリングQ1「S7でvault createも実装」+ 追加確認Q10*

### Given
- `~/.pq-diary/` が初期化済み

### When
- `vault create <name> [--policy <POLICY>]` を実行

### Then
- `~/.pq-diary/vaults/<name>/` に vault.pqd, vault.toml, entries/ が作成される
- vault.tomlのポリシーが指定値（デフォルト: none）に設定される

### テストケース

#### 正常系

- [ ] **TC-S7-030-01**: デフォルトポリシーでVault作成 🔵
  - **入力**: `vault create mynotes`
  - **期待結果**: vault.toml の policy = "none"
  - **信頼性**: 🔵 *PRD 3.2 デフォルト値*

- [ ] **TC-S7-030-02**: write_onlyポリシー指定でVault作成 🔵
  - **入力**: `vault create work --policy write_only`
  - **期待結果**: vault.toml の policy = "write_only"
  - **信頼性**: 🔵 *PRD 4.1*

- [ ] **TC-S7-030-03**: fullポリシー指定でVault作成（警告承認後） 🔵
  - **入力**: `vault create analysis --policy full` → `y`
  - **期待結果**: vault.toml の policy = "full"
  - **信頼性**: 🔵 *PRD 4.4 full警告*

- [ ] **TC-S7-030-04**: vault.pqd, entries/ が正しく作成される 🔵
  - **入力**: `vault create test`
  - **期待結果**: vault.pqd, vault.toml, entries/ が存在
  - **信頼性**: 🔵 *既存init_vault実装 + ヒアリングQ1*

- [ ] **TC-S7-030-05**: vaults/未存在時に自動作成 🔵
  - **入力**: `~/.pq-diary/vaults/` が存在しない状態で `vault create test`
  - **期待結果**: vaults/ が自動作成されてVault作成成功
  - **信頼性**: 🔵 *追加確認Q10項目7承認*

#### 異常系

- [ ] **TC-S7-030-E01**: 既存Vault名での作成失敗 🔵
  - **入力**: `vault create existing`（既にexistingが存在）
  - **期待結果**: エラー「Vault 'existing' already exists」
  - **信頼性**: 🔵 *追加確認Q10項目3承認*

- [ ] **TC-S7-030-E02**: パストラバーサルVault名 🔵
  - **入力**: `vault create "../escape"`
  - **期待結果**: エラー（パストラバーサル拒否）
  - **信頼性**: 🔵 *追加確認Q10項目6承認*

- [ ] **TC-S7-030-E03**: 空のVault名 🔵
  - **入力**: `vault create ""`
  - **期待結果**: エラー
  - **信頼性**: 🔵 *追加確認Q10項目6承認*

- [ ] **TC-S7-030-E04**: 無効なポリシー値 🔵
  - **入力**: `vault create test --policy invalid`
  - **期待結果**: エラー（有効値: none, write_only, full）
  - **信頼性**: 🔵 *追加確認Q10項目5承認*

- [ ] **TC-S7-030-E05**: fullポリシー警告を拒否 🔵
  - **入力**: `vault create test --policy full` → `n`
  - **期待結果**: Vault作成中止
  - **信頼性**: 🔵 *PRD 4.4 full警告*

---

## REQ-033: vault list 🔵

**信頼性**: 🔵 *PRD 4.1 + ヒアリングQ5 + 追加確認「名前+ポリシーのみ」「createのみPW必要」*

### テストケース

- [ ] **TC-S7-033-01**: 複数Vault一覧表示 🔵
  - **入力**: 3つのVaultが存在する状態で `vault list`
  - **期待結果**: 3行の一覧（名前、ポリシー表示）
  - **信頼性**: 🔵 *追加確認「名前+ポリシーのみ」*

- [ ] **TC-S7-033-02**: Vaultが0件の場合 🔵
  - **入力**: Vaultが存在しない状態で `vault list`
  - **期待結果**: 空の一覧（またはメッセージ）
  - **信頼性**: 🔵 *追加確認Q10で仕様全体承認*

- [ ] **TC-S7-033-03**: パスワード不要で実行可能 🔵
  - **入力**: `vault list`（パスワード未指定）
  - **期待結果**: パスワードプロンプトなしで一覧表示
  - **信頼性**: 🔵 *追加確認「createのみPW必要」*

---

## REQ-034: vault policy 🔵

**信頼性**: 🔵 *PRD 4.1 + 4.4 + ヒアリングQ4 + 追加確認*

### テストケース

#### 正常系

- [ ] **TC-S7-034-01**: none → write_only への変更 🔵
  - **入力**: `vault policy private write_only`
  - **期待結果**: vault.toml更新成功
  - **信頼性**: 🔵 *PRD 4.1*

- [ ] **TC-S7-034-02**: write_only → full への変更（警告承認） 🔵
  - **入力**: `vault policy work full` → `y`
  - **期待結果**: vault.toml更新、警告表示あり
  - **信頼性**: 🔵 *PRD 4.4 full警告*

- [ ] **TC-S7-034-03**: full → none への変更（警告なし） 🔵
  - **入力**: `vault policy analysis none`
  - **期待結果**: vault.toml更新、警告なし
  - **信頼性**: 🔵 *ヒアリングQ4「ポリシー設定時のみ」= fullへの変更時のみ*

- [ ] **TC-S7-034-04**: パスワード不要で実行可能 🔵
  - **入力**: `vault policy private write_only`（パスワード未指定）
  - **期待結果**: パスワードプロンプトなしでポリシー変更
  - **信頼性**: 🔵 *追加確認「createのみPW必要」*

#### 異常系

- [ ] **TC-S7-034-E01**: 存在しないVault名 🔵
  - **入力**: `vault policy nonexistent full`
  - **期待結果**: エラー
  - **信頼性**: 🔵 *追加確認Q10で仕様全体承認*

- [ ] **TC-S7-034-E02**: full変更の警告を拒否 🔵
  - **入力**: `vault policy private full` → `n`
  - **期待結果**: ポリシー変更中止
  - **信頼性**: 🔵 *PRD 4.4 full警告*

---

## REQ-035〜037: vault delete 🔵

**信頼性**: 🔵 *PRD 4.1 + ヒアリングQ5,Q13 + 追加確認「vault delete仕様」*

### テストケース

- [ ] **TC-S7-035-01**: 確認プロンプト承認後に削除 🔵
  - **入力**: `vault delete old-notes` → `y`
  - **期待結果**: Vaultディレクトリ削除
  - **信頼性**: 🔵 *追加確認「vault delete仕様」承認*

- [ ] **TC-S7-035-02**: 確認プロンプト拒否 🔵
  - **入力**: `vault delete old-notes` → `n`
  - **期待結果**: 削除中止
  - **信頼性**: 🔵 *追加確認「vault delete仕様」承認*

- [ ] **TC-S7-035-03**: --claude時の確認スキップ 🔵
  - **入力**: `pq-diary --claude vault delete old-notes`
  - **期待結果**: 確認なしで削除
  - **信頼性**: 🔵 *追加確認「vault delete仕様」承認*

- [ ] **TC-S7-035-04**: --zeroizeオプションでvault.pqd上書き削除 🔵
  - **入力**: `vault delete old-notes --zeroize` → `y`
  - **期待結果**: vault.pqdがランダムデータで上書き後に削除
  - **信頼性**: 🔵 *追加確認Q13「オプションでzeroize」*

- [ ] **TC-S7-035-E01**: デフォルトVault削除の追加確認 🔵
  - **入力**: `vault delete default`（defaultがデフォルトVault）
  - **期待結果**: 追加確認メッセージ表示
  - **信頼性**: 🔵 *追加確認「vault delete仕様」項目2承認*

- [ ] **TC-S7-035-E02**: 存在しないVault削除 🔵
  - **入力**: `vault delete nonexistent`
  - **期待結果**: エラー
  - **信頼性**: 🔵 *追加確認Q10で仕様全体承認*

---

## REQ-040〜041: fullポリシー警告 🔵

**信頼性**: 🔵 *PRD 4.4 + ヒアリングQ4「ポリシー設定時のみ」*

### テストケース

- [ ] **TC-S7-040-01**: vault create --policy full で警告表示 🔵
  - **入力**: `vault create test --policy full`
  - **期待結果**: PRD定義の警告メッセージ表示
  - **信頼性**: 🔵 *PRD 4.4*

- [ ] **TC-S7-040-02**: vault policy <n> full で警告表示 🔵
  - **入力**: `vault policy test full`
  - **期待結果**: PRD定義の警告メッセージ表示
  - **信頼性**: 🔵 *PRD 4.4*

- [ ] **TC-S7-040-03**: --claude コマンド実行時に警告なし 🔵
  - **入力**: `pq-diary --claude -v analysis show abc123`
  - **期待結果**: 警告なしで実行
  - **信頼性**: 🔵 *ヒアリングQ4「ポリシー設定時のみ」*

- [ ] **TC-S7-040-04**: none/write_onlyへの変更では警告なし 🔵
  - **入力**: `vault policy test write_only`
  - **期待結果**: 警告なしでポリシー変更
  - **信頼性**: 🔵 *ヒアリングQ4*

---

## REQ-050: エラーメッセージ 🔵

**信頼性**: 🔵 *ヒアリングQ9「詳細エラー」*

### テストケース

- [ ] **TC-S7-050-01**: None拒否のエラーメッセージ 🔵
  - **入力**: `--claude -v private new "test"`（policy=none）
  - **期待結果**: `"Access denied: vault 'private' has policy 'none'. '--claude' requires 'write_only' or 'full'."`
  - **信頼性**: 🔵 *ヒアリングQ9*

- [ ] **TC-S7-050-02**: WriteOnly read拒否のエラーメッセージ 🔵
  - **入力**: `--claude -v work show abc123`（policy=write_only）
  - **期待結果**: `"Access denied: vault 'work' has policy 'write_only'. Read operations require 'full'."`
  - **信頼性**: 🔵 *ヒアリングQ9*

---

## 非機能要件テスト

### NFR-001: ポリシーチェック性能 🔵

**信頼性**: 🔵 *PRD 4.4「復号試行なし」*

- [ ] **TC-S7-NFR-001-01**: Noneポリシー拒否のレイテンシ 🔵
  - **測定項目**: --claude + None拒否のレスポンスタイム
  - **目標値**: < 10ms（vault.toml読み取りのみ）
  - **測定条件**: vault.pqd復号なし
  - **信頼性**: 🔵 *PRD 4.4 Layer 2*

### NFR-003: vault create 性能 🔵

- [ ] **TC-S7-NFR-003-01**: vault create完了時間 🔵
  - **測定項目**: パスワード入力後のVault作成完了時間
  - **目標値**: < 3s（Argon2id鍵導出含む）
  - **信頼性**: 🔵 *PRD 性能要件 init < 3s*

### NFR-103: 不正ポリシー値のエラー返却 🔵

- [ ] **TC-S7-NFR-103-01**: vault.toml手動改ざん時の挙動 🔵
  - **入力**: vault.tomlのpolicyを `"admin"` に手動変更後、--claudeで実行
  - **期待結果**: DiaryError::Config エラー（フォールバックしない）
  - **信頼性**: 🔵 *追加確認Q11「エラーを返す」*

---

## テストケースサマリー

### カテゴリ別件数

| カテゴリ | 正常系 | 異常系 | 境界値 | 合計 |
|---------|--------|--------|--------|------|
| ポリシー型 (REQ-001) | 7 | 2 | 0 | 9 |
| 操作分類 (REQ-010) | 2 | 0 | 0 | 2 |
| 4層チェック (REQ-020) | 6 | 6 | 0 | 12 |
| vault create (REQ-030) | 5 | 5 | 0 | 10 |
| vault list (REQ-033) | 3 | 0 | 0 | 3 |
| vault policy (REQ-034) | 4 | 2 | 0 | 6 |
| vault delete (REQ-035) | 4 | 2 | 0 | 6 |
| full警告 (REQ-040) | 4 | 0 | 0 | 4 |
| エラーメッセージ (REQ-050) | 2 | 0 | 0 | 2 |
| 非機能 (NFR) | 3 | 0 | 0 | 3 |
| **合計** | **40** | **17** | **0** | **57** |

### 信頼性レベル分布

- 🔵 青信号: 57件 (100%)
- 🟡 黄信号: 0件 (0%)
- 🔴 赤信号: 0件 (0%)

**品質評価**: 高品質 - 全項目ヒアリングで確認済み

### 優先度別テストケース

- **Must Have**: 57件
- **Should Have**: 0件
- **Could Have**: 0件
