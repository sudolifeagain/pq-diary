# S7 Access Control + Claude 要件定義書

## 概要

Sprint 7ではVault単位のアクセスポリシー管理とClaude Code連携を実装する。`core/src/policy.rs`にポリシー評価ロジックを構築し、`--claude`フラグ使用時にvault.tomlのポリシー設定に基づいてコマンドの実行可否を判定する4層チェックを実現する。併せて、vault管理サブコマンド（create/list/policy/delete）を完成させる。

## 関連文書

- **ヒアリング記録**: [interview-record.md](interview-record.md)
- **ユーザストーリー**: [user-stories.md](user-stories.md)
- **受け入れ基準**: [acceptance-criteria.md](acceptance-criteria.md)
- **コンテキストノート**: [note.md](note.md)
- **PRD**: [requirements.md](../../requirements.md) (v4.0, section 4.4)

## 機能要件（EARS記法）

**【信頼性レベル凡例】**:
- 🔵 **青信号**: PRD・設計文書・ユーザヒアリングを参考にした確実な要件

### 通常要件

#### ポリシー型定義

- REQ-001: システムは `AccessPolicy` enum を `core/src/policy.rs` に `None` / `WriteOnly` / `Full` の3バリアントで定義しなければならない 🔵 *PRD 4.4 + ヒアリングQ7「enum化」確定*
- REQ-002: システムは `AccessPolicy` に serde の Serialize/Deserialize を実装し、vault.toml の `[access].policy` フィールドと `"none"` / `"write_only"` / `"full"` 文字列で相互変換しなければならない 🔵 *PRD 3.2 vault.toml仕様 + ヒアリングQ7*
- REQ-003: システムは既存の `AccessSection.policy: String` を `AccessSection.policy: AccessPolicy` に置き換えなければならない 🔵 *ヒアリングQ7「enum化」確定 + 追加確認Q10項目1承認*

#### 操作分類

- REQ-010: システムは各CLIコマンドを `read` または `write` 操作に分類しなければならない 🔵 *PRD 4.4 Layer 3 + ヒアリングQ8 確定*
  - **read操作**: `list`, `show`, `search`, `stats`, `template show`, `template list`
  - **write操作**: `new`, `edit`, `delete`, `sync`, `today`, `template add`, `template delete`, `import`

#### 4層ポリシーチェック

- REQ-020: システムは `--claude` フラグが指定されていない場合、ポリシーチェックをスキップして通常処理を行わなければならない 🔵 *PRD 4.4 Layer 1*
- REQ-021: `--claude` フラグが指定された場合、システムはvault.tomlから `[access].policy` を読み取りポリシーチェックを実行しなければならない 🔵 *PRD 4.4 Layer 2*
- REQ-022: ポリシーが `None` の場合、システムは復号を試行せず即時にアクセス拒否エラーを返さなければならない 🔵 *PRD 4.4 Layer 2*
- REQ-023: ポリシーが `WriteOnly` の場合、read操作に対してアクセス拒否エラーを返さなければならない 🔵 *PRD 4.4 Layer 3 + ヒアリングQ2,Q8*
- REQ-024: ポリシーが `WriteOnly` の場合、write操作は通常処理を許可しなければならない 🔵 *PRD 4.4 Layer 3*
- REQ-025: ポリシーが `Full` の場合、すべての操作を通常処理として許可しなければならない 🔵 *PRD 4.4 Layer 4*

#### Vault管理コマンド

- REQ-030: `vault create <name> [--policy <POLICY>]` は新しいVaultを `~/.pq-diary/vaults/<name>/` に作成しなければならない。パスワード入力が必要 🔵 *PRD 4.1 + ヒアリングQ1「S7でvault createも実装」+ 追加確認「createのみPW必要」*
- REQ-031: `vault create` の `--policy` 省略時はデフォルトポリシー `none` を設定しなければならない 🔵 *PRD 3.2 デフォルト値*
- REQ-032: `vault create` は既に同名のVaultが存在する場合エラーを返さなければならない 🔵 *追加確認Q10項目3承認*
- REQ-033: `vault list` は `~/.pq-diary/vaults/` 配下の全Vaultの名前とポリシーを一覧表示しなければならない。パスワード不要 🔵 *PRD 4.1 + 追加確認「名前+ポリシーのみ」「createのみPW必要」*
- REQ-034: `vault policy <name> <POLICY>` はVaultのアクセスポリシーを変更しなければならない。パスワード不要 🔵 *PRD 4.1 + 追加確認「createのみPW必要」*
- REQ-035: `vault delete <name>` はVaultディレクトリを削除しなければならない。パスワード不要 🔵 *PRD 4.1 + ヒアリングQ5「全部実装」+ 追加確認「createのみPW必要」*
- REQ-036: `vault delete` は削除前に確認プロンプトを表示しなければならない（`--claude`時はスキップ） 🔵 *追加確認「vault delete仕様」承認*
- REQ-037: `vault delete` は `--zeroize` オプション指定時、vault.pqdファイルをランダムデータで上書きしてから削除しなければならない 🔵 *追加確認「オプションでzeroizeをできるようにして」*

#### full ポリシー警告

- REQ-040: `vault create --policy full` または `vault policy <name> full` 実行時、システムは以下の警告を表示し、[y/N] で承認を求めなければならない 🔵 *PRD 4.4 full警告*
  ```
  警告: "full"を設定すると日記内容がAnthropicのAPIサーバーを通過します。
        間接プロンプトインジェクション等のリスクがあります。
        本当に許可しますか？ [y/N]:
  ```
- REQ-041: full警告の承認はポリシー設定時のみとし、`--claude` コマンド実行時には表示しない 🔵 *ヒアリングQ4「ポリシー設定時のみ」*

#### エラーメッセージ

- REQ-050: ポリシー違反時のエラーメッセージはVault名・現在のポリシー・必要なポリシーを含まなければならない 🔵 *ヒアリングQ9「詳細エラー」*
  - 例: `Access denied: vault 'private' has policy 'none'. '--claude' requires 'write_only' or 'full'.`
  - 例: `Access denied: vault 'private' has policy 'write_only'. Read operations require 'full'.`

### 条件付き要件

- REQ-101: `--claude` フラグが指定されており、かつ対象Vaultのポリシーが `None` の場合、システムはvault.pqdの復号を一切行わずにエラーを返さなければならない 🔵 *PRD 4.4 Layer 2 「即時拒否（復号試行なし）」*
- REQ-102: `vault delete` がデフォルトVault（config.tomlの`defaults.vault`）を対象にした場合、追加の確認メッセージを表示しなければならない 🔵 *追加確認「vault delete仕様」項目2承認*

### 状態要件

- REQ-201: Vaultがロック状態にある場合でも、`vault list` はvault.tomlのみを参照してVault一覧を表示できなければならない 🔵 *追加確認「createのみPW必要」= list/policy/deleteはPW不要*
- REQ-202: Vaultがロック状態にある場合、`vault policy` はvault.tomlのみを更新できなければならない（vault.pqdの復号不要） 🔵 *追加確認「createのみPW必要」*

### 制約要件

- REQ-401: `AccessPolicy` enumは `core/src/policy.rs` に配置し、CLIにプラットフォーム依存コードを含めないこと 🔵 *CLAUDE.md規約*
- REQ-402: ポリシー評価ロジックは `core/` に配置し、`cli/` はポリシーチェック結果を受け取るのみとすること 🔵 *CLAUDE.md「core/にプラットフォーム依存UIコードを入れない」*
- REQ-403: vault.toml への書き込みはアトミック操作（temp + rename）で行うこと 🔵 *S6技術的負債 M-6 で実装済みのパターン + 追加確認Q10項目4承認*
- REQ-404: `AccessPolicy` enumは既存の vault.toml ファイルとの後方互換性を維持しなければならない（`"none"` 文字列でのデシリアライズが動作すること） 🔵 *追加確認Q10項目2承認*

## 非機能要件

### パフォーマンス

- NFR-001: ポリシーチェックは vault.toml の読み取りのみで完結し、vault.pqd の復号を行わないこと。`None` ポリシー時の拒否は 10ms 未満 🔵 *PRD 4.4 Layer 2「復号試行なし」 + 性能要件表*
- NFR-002: `vault list` は Vault 数に比例した O(n) で動作し、各 Vault の vault.toml のみを読み取ること 🔵 *追加確認「名前+ポリシーのみ」= vault.toml読み取りのみで確定*
- NFR-003: `vault create` はパスワード入力後 3 秒以内に完了すること（Argon2id 鍵導出を含む） 🔵 *PRD 性能要件 init < 3s*

### セキュリティ

- NFR-101: `None` ポリシーのVaultに対して `--claude` が指定された場合、暗号鍵のメモリ展開を行わないこと 🔵 *PRD 4.4 Layer 2*
- NFR-102: ポリシー文字列のバリデーションは信頼されない入力として扱い、未知の値に対してはデシリアライズエラーを返すこと 🔵 *追加確認Q11「エラーを返す」確定*
- NFR-103: vault.toml のポリシーフィールドが改ざんされた場合（無効な値）、システムはデシリアライズエラー（DiaryError::Config）を返さなければならない。フォールバックしない 🔵 *追加確認Q11「エラーを返す」確定*

### ユーザビリティ

- NFR-201: `vault list` の出力は名前・ポリシーを列形式で表示すること 🔵 *追加確認「名前+ポリシーのみ」確定*
- NFR-202: `vault create` 成功時は作成されたVaultのパスとポリシーを表示すること 🔵 *既存initコマンドの出力パターン + 追加確認Q10で仕様全体を承認*

## Edgeケース

### エラー処理

- EDGE-001: `vault create` で既にVaultが存在する場合、既存Vaultを上書きせずエラーを返す 🔵 *追加確認Q10項目3承認*
- EDGE-002: `vault policy` で存在しないVault名を指定した場合、エラーを返す 🔵 *追加確認Q10で仕様全体を承認*
- EDGE-003: `vault delete` で存在しないVault名を指定した場合、エラーを返す 🔵 *追加確認Q10で仕様全体を承認*
- EDGE-004: vault.toml が破損・欠落している場合、DiaryError::Config エラーを返す 🔵 *追加確認Q11「エラーを返す」+ 既存config.rsのエラーハンドリング*
- EDGE-005: `--policy` に無効な値（`"read_only"` 等）を指定した場合、有効な値を提示してエラーを返す 🔵 *追加確認Q10項目5「無効ポリシー値はデシリアライズエラー」承認*
- EDGE-006: `--claude` 使用時にポリシーが `None` で、かつ `--password` が指定されている場合でも復号を行わずに拒否する 🔵 *PRD「復号試行なし」*

### 境界値

- EDGE-101: Vault名が空文字列の場合エラーを返す 🔵 *追加確認Q10項目6承認*
- EDGE-102: Vault名にファイルシステムで無効な文字（`/`, `\`, `..` 等）が含まれる場合エラーを返す 🔵 *追加確認Q10項目6「パストラバーサル拒否」承認*
- EDGE-103: `~/.pq-diary/vaults/` ディレクトリが存在しない場合、`vault create` で自動作成する 🔵 *追加確認Q10項目7承認*
