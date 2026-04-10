# S7 Access Control + Claude ユーザストーリー

**作成日**: 2026-04-10
**関連要件定義**: [requirements.md](requirements.md)
**ヒアリング記録**: [interview-record.md](interview-record.md)

**【信頼性レベル凡例】**:
- 🔵 **青信号**: PRD・設計文書・ユーザヒアリングを参考にした確実なストーリー

---

## エピック1: アクセスポリシー管理

### ストーリー 1.1: ポリシー付きVault作成 🔵

**信頼性**: 🔵 *PRD 4.1 + ヒアリングQ1「S7でvault createも実装」*

**私は** pq-diaryユーザー **として**
**用途に応じたポリシーを指定してVaultを作成したい**
**そうすることで** プライベート日記とClaude活用メモを別Vaultで安全に管理できる

**関連要件**: REQ-030, REQ-031, REQ-032

**詳細シナリオ**:
1. ユーザーが `pq-diary vault create work --policy write_only` を実行
2. パスワードの入力を求められる
3. `~/.pq-diary/vaults/work/` にvault.pqd, vault.toml, entries/ が作成される
4. vault.tomlの `[access].policy` が `"write_only"` に設定される
5. 作成成功メッセージが表示される

**前提条件**:
- `~/.pq-diary/` が初期化済み（config.toml存在）
- 同名のVaultが存在しない

**制約事項**:
- Vault名にファイルシステム無効文字を含めない
- --policy省略時はデフォルト `none`

**優先度**: Must Have

---

### ストーリー 1.2: Vault一覧表示 🔵

**信頼性**: 🔵 *PRD 4.1 + ヒアリングQ5「全部実装」+ 追加確認「名前+ポリシーのみ」*

**私は** pq-diaryユーザー **として**
**保有するVaultの一覧とポリシー設定を確認したい**
**そうすることで** どのVaultがClaude連携可能かを把握できる

**関連要件**: REQ-033, REQ-201

**詳細シナリオ**:
1. ユーザーが `pq-diary vault list` を実行
2. パスワード入力なしで一覧が表示される
3. 各Vaultの名前とポリシーが列形式で表示される

**前提条件**:
- `~/.pq-diary/vaults/` が存在する

**優先度**: Must Have

---

### ストーリー 1.3: ポリシー変更 🔵

**信頼性**: 🔵 *PRD 4.1 + 4.4 + ヒアリングQ4「ポリシー設定時のみ警告」*

**私は** pq-diaryユーザー **として**
**既存VaultのClaude連携ポリシーを変更したい**
**そうすることで** 用途の変化に応じてアクセス制御を調整できる

**関連要件**: REQ-034, REQ-040, REQ-041, REQ-202

**詳細シナリオ**:
1. ユーザーが `pq-diary vault policy private full` を実行
2. fullポリシーの警告メッセージが表示される
3. ユーザーが `y` で承認する
4. vault.tomlの `[access].policy` が `"full"` に更新される
5. 変更成功メッセージが表示される

**前提条件**:
- 対象Vaultが存在する

**制約事項**:
- fullポリシーへの変更は警告+承認必須
- none/write_onlyへの変更は確認不要

**優先度**: Must Have

---

### ストーリー 1.4: Vault削除（zeroizeオプション付き） 🔵

**信頼性**: 🔵 *PRD 4.1 + ヒアリングQ5,Q13 + 追加確認「vault delete仕様」*

**私は** pq-diaryユーザー **として**
**不要になったVaultを完全に削除したい。機密性が高い場合はzeroizeオプションで安全に消去したい**
**そうすることで** ディスクスペースを解放し、必要に応じて機密データの残留を防げる

**関連要件**: REQ-035, REQ-036, REQ-037, REQ-102

**詳細シナリオ**:
1. ユーザーが `pq-diary vault delete old-notes --zeroize` を実行
2. 確認プロンプトが表示される: `Delete vault 'old-notes'? This cannot be undone. [y/N]:`
3. ユーザーが `y` で承認
4. vault.pqdファイルがランダムデータで上書きされる
5. `~/.pq-diary/vaults/old-notes/` ディレクトリが完全に削除される
6. 削除成功メッセージが表示される

**前提条件**:
- 対象Vaultが存在する
- デフォルトVault削除時は追加確認

**優先度**: Must Have

---

## エピック2: Claude Code連携

### ストーリー 2.1: Claudeによるエントリ作成（write_only） 🔵

**信頼性**: 🔵 *PRD 4.4 + ヒアリングQ6「全コマンド対応」*

**私は** Claude Codeを使うユーザー **として**
**Claude経由で業務メモVaultに新しいエントリを作成したい**
**そうすることで** Claudeとの対話中にメモを自動保存できる

**関連要件**: REQ-020, REQ-021, REQ-024, REQ-025

**詳細シナリオ**:
1. Claudeが `pq-diary --claude -v work new "Meeting Notes" -b "..." -t meeting` を実行
2. システムがvault.tomlからポリシー `write_only` を読み取る
3. `new` はwrite操作なので許可される
4. エントリが作成され、IDが出力される

**前提条件**:
- PQ_DIARY_PASSWORD環境変数が設定済み（推奨）
- 対象VaultのポリシーがwriteOnly以上

**優先度**: Must Have

---

### ストーリー 2.2: Claudeによるエントリ読み取り拒否（write_only） 🔵

**信頼性**: 🔵 *PRD 4.4 Layer 3 + ヒアリングQ2「searchは拒否」+ Q8「操作分類確定」*

**私は** pq-diaryユーザー **として**
**write_onlyポリシーのVaultでClaude経由の読み取りを拒否したい**
**そうすることで** 業務メモの内容がAPIサーバーを通過することを防げる

**関連要件**: REQ-023, REQ-050, REQ-101

**詳細シナリオ**:
1. Claudeが `pq-diary --claude -v work show abc123` を実行
2. システムがvault.tomlからポリシー `write_only` を読み取る
3. `show` はread操作なのでアクセス拒否
4. エラーメッセージ: `Access denied: vault 'work' has policy 'write_only'. Read operations require 'full'.`

**優先度**: Must Have

---

### ストーリー 2.3: Claudeによる全拒否（none） 🔵

**信頼性**: 🔵 *PRD 4.4 Layer 2*

**私は** pq-diaryユーザー **として**
**プライベート日記VaultへのClaude経由アクセスを完全に拒否したい**
**そうすることで** 最も機密性の高い日記が外部に一切漏れないことを保証できる

**関連要件**: REQ-022, REQ-101

**詳細シナリオ**:
1. Claudeが `pq-diary --claude -v private new "..." -b "..."` を実行
2. システムがvault.tomlからポリシー `none` を読み取る
3. 復号を試行せずに即時拒否
4. エラーメッセージ: `Access denied: vault 'private' has policy 'none'. '--claude' requires 'write_only' or 'full'.`

**前提条件**:
- パスワードが提供されていても復号しない

**優先度**: Must Have

---

### ストーリー 2.4: Claudeによるフルアクセス（full） 🔵

**信頼性**: 🔵 *PRD 4.4 Layer 4 + ヒアリングQ6「全コマンド対応」*

**私は** Claude Code活用ユーザー **として**
**fullポリシーのVaultでClaude経由で読み書き全操作を行いたい**
**そうすることで** Claudeに日記の分析や要約を依頼できる

**関連要件**: REQ-025

**詳細シナリオ**:
1. Claudeが `pq-diary --claude -v analysis list` を実行
2. ポリシー `full` → 全操作許可
3. エントリ一覧が表示される
4. Claudeが `pq-diary --claude -v analysis show abc123` を実行
5. エントリ内容が表示される

**優先度**: Must Have

---

## ストーリーマップ

```
エピック1: アクセスポリシー管理
├── ストーリー 1.1 (🔵 Must Have) vault create --policy
├── ストーリー 1.2 (🔵 Must Have) vault list
├── ストーリー 1.3 (🔵 Must Have) vault policy
└── ストーリー 1.4 (🔵 Must Have) vault delete --zeroize

エピック2: Claude Code連携
├── ストーリー 2.1 (🔵 Must Have) --claude write許可
├── ストーリー 2.2 (🔵 Must Have) --claude read拒否
├── ストーリー 2.3 (🔵 Must Have) --claude none全拒否
└── ストーリー 2.4 (🔵 Must Have) --claude full全許可
```

## 信頼性レベルサマリー

- 🔵 青信号: 8件 (100%)
- 🟡 黄信号: 0件 (0%)
- 🔴 赤信号: 0件 (0%)

**品質評価**: 高品質 - 全項目ヒアリングで確認済み
