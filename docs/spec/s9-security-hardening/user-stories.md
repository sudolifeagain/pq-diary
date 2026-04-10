# S9 Security Hardening + Technical Debt + Integration Tests ユーザストーリー

**作成日**: 2026-04-10
**関連要件定義**: [requirements.md](requirements.md)
**ヒアリング記録**: [interview-record.md](interview-record.md)

**【信頼性レベル凡例】**:
- 🔵 **青信号**: PRD・設計文書・ユーザヒアリングを参考にした確実なストーリー

---

## エピック1: メモリ保護 + プロセス硬化（mlock/VirtualLock, PR_SET_DUMPABLE, デバッガ検知）

### ストーリー 1.1: 鍵素材のメモリロック 🔵

**信頼性**: 🔵 *PRD 8.3 + ヒアリングQ2「Unix mlock + Windows VirtualLock 両対応、失敗時 warn + continue」*

**私は** セキュリティ意識の高いpq-diaryユーザー **として**
**Vaultアンロック後の鍵素材がスワップ領域に書き出されないようにしたい**
**そうすることで** 物理アクセスやディスクフォレンジックから鍵素材を保護できる

**関連要件**: REQ-001, REQ-002, REQ-003, REQ-004, REQ-005

**詳細シナリオ**:
1. ユーザーがVaultをアンロック（パスワード入力）
2. 鍵導出後、鍵素材バッファに対してmlockまたはVirtualLockが呼び出される
3. mlock/VirtualLockが失敗した場合、警告メッセージが表示されるが処理は継続する
4. ユーザーがVaultをロック（lock）
5. munlock/VirtualUnlockが呼び出され、メモリロックが解放される
6. バッファはzeroizeされる

**前提条件**:
- Vaultが作成済み
- core/src/crypto/secure_mem.rs にメモリロック機能が実装済み

**制約事項**:
- Unix: mlock/munlock (libc)
- Windows: VirtualLock/VirtualUnlock (windows-sys)
- #[cfg(unix)] / #[cfg(windows)] でプラットフォーム分岐
- 失敗時はabortしない

**優先度**: Must Have

---

### ストーリー 1.2: コアダンプ防止 🔵

**信頼性**: 🔵 *PRD 9.1 + PRD 9.2 + ヒアリングQ2「Unix のみ」*

**私は** セキュリティ意識の高いpq-diaryユーザー **として**
**プロセスのコアダンプに鍵素材やパスワードが含まれないようにしたい**
**そうすることで** クラッシュ時のコアダンプファイルから秘密情報が漏洩することを防げる

**関連要件**: REQ-010, REQ-011

**詳細シナリオ**:
1. pq-diaryプロセスが起動する
2. 起動直後に PR_SET_DUMPABLE=0 が設定される（コアダンプにメモリが含まれなくなる）
3. 起動直後に setrlimit(RLIMIT_CORE, 0, 0) が設定される（コアダンプファイルが生成されなくなる）
4. 以降のVault操作が通常通り実行される

**前提条件**:
- Unix環境

**制約事項**:
- Unix のみ（Windows は対応不要）
- cli/ に配置（プロセスレベル設定）
- 非対応カーネルの場合は warn + continue

**優先度**: Must Have

---

### ストーリー 1.3: デバッガ接続検知 🔵

**信頼性**: 🔵 *PRD 9.2 + ヒアリングQ2「TracerPid + IsDebuggerPresent、warning only」*

**私は** セキュリティ意識の高いpq-diaryユーザー **として**
**デバッガがプロセスにアタッチされている場合に警告を受けたい**
**そうすることで** デバッガ経由での鍵素材メモリ読み取り攻撃に気づくことができる

**関連要件**: REQ-012, REQ-013

**詳細シナリオ**:
1. pq-diaryプロセスが起動する
2. Unix: /proc/self/status の TracerPid を確認する
3. Windows: IsDebuggerPresent() を呼び出す
4. デバッガが検知された場合、警告メッセージが表示される（例: "WARNING: Debugger detected. Key material may be exposed."）
5. プロセスは中断されず、通常通り動作を継続する

**前提条件**:
- なし（全環境で動作）

**制約事項**:
- 警告のみ、プロセスは中断しない
- /proc/self/status が読み取れない環境ではスキップ
- cli/ に配置

**優先度**: Must Have

---

## エピック2: コード品質・技術的負債解消（SecretString, Zeroizing, verify_hmac, 署名検証）

### ストーリー 2.1: パスワードのSecretString化 🔵

**信頼性**: 🔵 *backlog H-1 + ヒアリングQ3「全技術的負債をS9で対応」*

**私は** pq-diaryユーザー **として**
**CLIで入力したパスワードがプロセスメモリに平文で残留しないようにしたい**
**そうすることで** メモリダンプ攻撃からパスワードが保護される

**関連要件**: REQ-020

**詳細シナリオ**:
1. ユーザーが `--password` フラグまたはTTYでパスワードを入力
2. パスワードは即座に SecretString に格納される
3. SecretString はスコープ終了時に自動的にゼロ化される
4. 生の String としてメモリに残留しない

**前提条件**:
- `secrecy` クレートが依存に含まれている

**制約事項**:
- clap derive との互換性を維持（カスタムパーサーが必要な場合がある）
- cli/ での変更

**優先度**: Must Have

---

### ストーリー 2.2: 中間バッファのゼロ化と安全なエラーハンドリング 🔵

**信頼性**: 🔵 *backlog M-1, M-2, M-4, M-5 + ヒアリングQ3*

**私は** pq-diaryユーザー **として**
**暗号処理の中間バッファが確実にゼロ化され、エラーが適切に伝播されるようにしたい**
**そうすることで** 一時的な鍵素材のメモリ残留リスクが最小化され、エラー原因が明確になる

**関連要件**: REQ-021, REQ-022, REQ-024

**詳細シナリオ**:
1. MasterKey のsym_keyコピー時、中間 Vec<u8> が Zeroizing<Vec<u8>> で保護される
2. unlock_with_vault の復号バッファが Zeroizing<Vec<u8>> で保護される
3. verify_hmac がエラーを Result で返し、呼び出し元でハンドリングされる
4. not_implemented() が bail! に変更され、エラーがスタックトレースに含まれる

**前提条件**:
- `zeroize` クレートが依存に含まれている

**制約事項**:
- verify_hmac の戻り値変更は全呼び出し元の修正が必要
- not_implemented() の変更は4箇所 + legacy/daemonスタブ

**優先度**: Must Have

---

### ストーリー 2.3: PQC依存のコミットハッシュ固定 🔵

**信頼性**: 🔵 *backlog M-3 + ヒアリングQ3*

**私は** pq-diary開発者 **として**
**PQC依存クレート（ml-kem, ml-dsa）のバージョンを正確に固定したい**
**そうすることで** ブランチの先頭移動による意図しない変更を防ぎ、ビルドの再現性を保証できる

**関連要件**: REQ-023

**詳細シナリオ**:
1. core/Cargo.toml の ml-kem / ml-dsa 依存を確認
2. `branch = "pq-diary"` を `rev = "<current_commit_hash>"` に変更
3. `cargo update` で依存が正しく解決されることを確認
4. ビルドが成功することを確認

**前提条件**:
- pq-diary ブランチの最新コミットハッシュが取得可能

**制約事項**:
- 既存の暗号テストがすべてパスすること

**優先度**: Must Have

---

### ストーリー 2.4: エントリ読み取り時の署名/HMAC検証 🔵

**信頼性**: 🔵 *backlog（S4/S6繰越）+ ヒアリングQ3*

**私は** pq-diaryユーザー **として**
**エントリを読み取る際に署名とHMACが自動的に検証されるようにしたい**
**そうすることで** vault.pqdの改竄や破損を検出し、データの完全性を保証できる

**関連要件**: REQ-025, REQ-026, REQ-027

**詳細シナリオ**:
1. ユーザーが show / list / search / edit などでエントリを読み取る
2. 各エントリの ML-DSA-65 署名が検証される
3. 各エントリの HMAC-SHA256 が検証される
4. 署名またはHMACが不一致の場合、DiaryError::Crypto エラーが返される
5. エラーメッセージに改竄の可能性が明示される
6. 1つのエントリの検証失敗が他のエントリの読み取りに影響しない

**前提条件**:
- ML-DSA-65 検証機能とHMAC-SHA256検証機能が既存
- verify_hmac が Result を返すように変更済み（REQ-024）

**制約事項**:
- core/ で実装（reader.rs）
- パフォーマンスへの影響を最小化

**優先度**: Must Have

---

## エピック3: 品質保証（E2Eテスト, パフォーマンス検証）

### ストーリー 3.1: 全コマンドE2Eテスト 🔵

**信頼性**: 🔵 *backlog + ヒアリングQ3「全13コマンド対象」*

**私は** pq-diary開発者 **として**
**全コマンドのE2Eテストが実装されていることを確認したい**
**そうすることで** リグレッションを防ぎ、各コマンドが正しく動作することを保証できる

**関連要件**: REQ-030

**詳細シナリオ**:
1. init: Vault初期化のE2Eテスト
2. new: エントリ作成のE2Eテスト
3. list: エントリ一覧のE2Eテスト
4. show: エントリ表示のE2Eテスト
5. edit: エントリ編集のE2Eテスト
6. delete: エントリ削除のE2Eテスト
7. search: 検索のE2Eテスト
8. stats: 統計のE2Eテスト
9. today: デイリーノートのE2Eテスト
10. template: テンプレートCRUDのE2Eテスト
11. import: インポートのE2Eテスト
12. vault: Vault管理（list, delete, policy）のE2Eテスト
13. git: Git連携（init, push, pull, sync, status）のE2Eテスト

**前提条件**:
- 全コマンドが実装済み（S1〜S8）

**制約事項**:
- テスト環境でのファイルシステム分離（tempdir使用）
- パスワード入力は --password フラグまたは PQ_DIARY_PASSWORD 環境変数で代替

**優先度**: Must Have

---

### ストーリー 3.2: パフォーマンス検証 🔵

**信頼性**: 🔵 *PRD 12.1 + ヒアリングQ3「PRD 12.1の値をそのまま使用」*

**私は** pq-diary開発者 **として**
**主要操作がPRDのパフォーマンス目標を満たしていることを検証したい**
**そうすることで** ユーザー体験が許容範囲内であることを保証できる

**関連要件**: REQ-031, REQ-032, REQ-033, REQ-034, REQ-035

**詳細シナリオ**:
1. init: 3秒未満で完了することを計測
2. unlock: 1〜3秒で完了することを計測（Argon2id鍵導出を含む）
3. new/edit: 200ms未満で完了することを計測（エディタ起動時間を除く）
4. list(100 entries): 500ms未満で完了することを計測
5. lock: 50ms未満で完了することを計測

**前提条件**:
- 100エントリを含むテスト用Vault
- CI環境のスペック変動を考慮したマージン設定

**制約事項**:
- CI環境ではパフォーマンスが変動するため、目標値にマージンを持たせる
- #[ignore] 属性で通常テストから除外し、明示的に実行する形式も検討

**優先度**: Must Have

---

## ストーリーマップ

```
エピック1: メモリ保護 + プロセス硬化
├── ストーリー 1.1 (🔵 Must Have) mlock/VirtualLock + munlock/VirtualUnlock
├── ストーリー 1.2 (🔵 Must Have) PR_SET_DUMPABLE + RLIMIT_CORE (Unix)
└── ストーリー 1.3 (🔵 Must Have) デバッガ検知 (TracerPid + IsDebuggerPresent)

エピック2: コード品質・技術的負債解消
├── ストーリー 2.1 (🔵 Must Have) Cli.password SecretString化 (H-1)
├── ストーリー 2.2 (🔵 Must Have) Zeroizing + bail! + verify_hmac Result (M-1/M-2/M-4/M-5)
├── ストーリー 2.3 (🔵 Must Have) PQC依存コミットハッシュ固定 (M-3)
└── ストーリー 2.4 (🔵 Must Have) 署名/HMAC検証 (S4/S6繰越)

エピック3: 品質保証
├── ストーリー 3.1 (🔵 Must Have) 全コマンドE2Eテスト
└── ストーリー 3.2 (🔵 Must Have) パフォーマンス検証
```

## 信頼性レベルサマリー

- 🔵 青信号: 9件 (100%)
- 🟡 黄信号: 0件 (0%)
- 🔴 赤信号: 0件 (0%)

**品質評価**: 高品質 - 全項目ヒアリングで確認済み
