# S7 Access Control + Claude 設計ヒアリング記録

**作成日**: 2026-04-10
**ヒアリング実施**: step4 既存情報ベースの差分ヒアリング

## ヒアリング目的

要件定義書（全項目🔵）と既存実装分析を基に、S7の技術設計に必要な設計判断を確定するためのヒアリングを実施しました。

## 質問と回答

### Q1: ポリシーチェックのCLIフロー内配置

**質問日時**: 2026-04-10
**カテゴリ**: アーキテクチャ
**背景**: --claude + None の場合は復号前に拒否する必要がある（REQ-101）。ディスパッチ前（main.rs match の前）に一括チェックする案と、各コマンドハンドラ内で個別チェックする案の二択。

**回答**: 各コマンド内

**信頼性への影響**:
- アーキテクチャ設計のポリシーチェック配置が確定（🔵）
- 各cmd_*関数の先頭でvault.toml読み取り → check_access() → Early Return パターンが決定

---

### Q2: Vault管理コマンドの実装先

**質問日時**: 2026-04-10
**カテゴリ**: アーキテクチャ
**背景**: 新規モジュール（vault/manager.rs）を作るか、既存のVaultManager（vault/init.rs）を拡張するかの判断。init.rsには既にlist_vaults(), vault_path(), default_vault()が存在。

**回答**: VaultManager拡張（推奨）

**信頼性への影響**:
- create_vault, list_vaults_with_policy, set_policy, delete_vault が既存VaultManager impl に追加される設計が確定（🔵）
- 既存のinit_vault()を内部で活用できることが確認

---

### Q3: 既存実装の詳細分析

**質問日時**: 2026-04-10
**カテゴリ**: アーキテクチャ
**背景**: 要件定義フェーズで基本分析は完了していたが、設計精度を高めるために追加分析が必要か確認。

**回答**: 必要

**信頼性への影響**:
- VaultManager, VaultGuard, DiaryCore, Error types, atomic write の詳細な行番号と実装パターンを把握
- 設計文書の精度が向上（全項目の実装可能性を確認済み）

---

## ヒアリング結果サマリー

### 確認できた事項
- ポリシーチェック: 各cmd_*関数の先頭に配置
- VaultManager拡張: 既存init.rsにメソッド追加
- 既存実装との整合性: VaultGuard RAII、atomic write、DiaryCore API すべて確認済み

### 設計方針の決定事項
- check_access() は純粋関数（ファイルI/Oなし）。vault.toml読み取りはCLI側で実施
- create_vault() は内部でinit_vault()を呼び出し後にset_policy()
- delete_vault()のzeroizeはOsRngでランダムデータ上書き後にremove_dir_all()
- VaultConfig::from_file()を使ったポリシーチェックはPW取得前に実行

### 残課題
- なし（全項目確認済み）

### 信頼性レベル分布

**ヒアリング前**:
- 🔵 青信号: 全件（要件定義フェーズで確認済み）

**ヒアリング後**:
- 🔵 青信号: 全件（設計判断も確定）

## 関連文書

- **アーキテクチャ設計**: [architecture.md](architecture.md)
- **データフロー**: [dataflow.md](dataflow.md)
- **型定義**: [types.rs](types.rs)
- **要件定義**: [requirements.md](../../spec/s7-access-control-claude/requirements.md)
