# S9 Security Hardening + Technical Debt + Integration Tests ヒアリング記録

**作成日**: 2026-04-10
**ヒアリング実施**: step4 既存情報ベースの差分ヒアリング

## ヒアリング目的

PRD v4.0（section 8: メモリ保護, section 9: プロセス硬化, section 12: パフォーマンス目標）、バックログの技術的負債一覧、および既存実装（unsafe ブロック状況、プラットフォーム分岐パターン）を精査し、S9実装のスコープ・設計判断の不明点を明確化するためのヒアリングを実施しました。

## 質問と回答

### Q1: S9のスコープ

**質問日時**: 2026-04-10
**カテゴリ**: 影響範囲
**背景**: バックログにはセキュリティ硬化（mlock, PR_SET_DUMPABLE, RLIMIT_CORE, デバッガ検知）、技術的負債（H-1, M-1〜M-5, 署名/HMAC検証）、統合テスト（E2E + パフォーマンス検証）が列挙されている。S9で全て実装するか、優先度に基づき分割するかを確認する必要があった。

**回答**: S9でフルスコープ実装。全バックログ技術的負債（H-1, M-1〜M-5, 署名/HMAC検証）+ セキュリティ硬化（mlock/VirtualLock, PR_SET_DUMPABLE, RLIMIT_CORE, デバッガ検知）+ E2Eテスト + パフォーマンス検証のすべてをS9で対応する。

**信頼性への影響**:
- 全REQ（001〜035, 401〜403）のスコープが確定（🔵）
- S9が3領域（セキュリティ硬化 / 技術的負債 / 品質保証）をカバーする大規模スプリントとなることが確認された

---

### Q2: mlock対象・プロセス硬化・デバッガ検知の詳細

**質問日時**: 2026-04-10
**カテゴリ**: 未定義部分詳細化
**背景**: PRDではmlock/VirtualLock、PR_SET_DUMPABLE、デバッガ検知を要求しているが、以下の詳細が未定義であった: (a) mlock対象プラットフォーム（Unix only? 両方?）、(b) mlock失敗時の挙動、(c) デバッガ検知時の挙動（abort or warn）、(d) PR_SET_DUMPABLE/RLIMIT_COREのWindows対応要否。

**回答**:
- **mlock対象**: Unix mlock + Windows VirtualLock の両方を実装する。Unix側はCI環境でのmlock制限を考慮し、コンパイルテストのみとする
- **mlock失敗時**: warn + continue。非特権ユーザー環境（ulimit制限）を考慮し、失敗してもプロセスを中断しない
- **デバッガ検知**: TracerPid（Unix）+ IsDebuggerPresent（Windows）の両方を実装。検知時は警告メッセージを出力するのみで、プロセスは中断しない
- **PR_SET_DUMPABLE + RLIMIT_CORE**: Unix のみ。Windows は対応不要（Windows には対応するAPIが存在しないため）

**信頼性への影響**:
- REQ-001〜005（メモリロック）が確定（🔵）
- REQ-010〜013（プロセス硬化）が確定（🔵）
- EDGE-001〜003, EDGE-010〜011 が確定（🔵）

---

### Q3: 仕様確認（技術的負債 + テスト）

**質問日時**: 2026-04-10
**カテゴリ**: 既存設計確認
**背景**: 残りの仕様項目を一括で確認。技術的負債の全項目がS9スコープ内か、E2Eテストの対象コマンド範囲、パフォーマンス目標値の正確性を確定する必要があった。

**回答**:
1. **技術的負債**: H-1, M-1〜M-5, 署名/HMAC検証の全項目をS9で対応確定
2. **E2Eテスト対象**: init, new, list, show, edit, delete, search, stats, today, template, import, vault, git の全コマンド
3. **パフォーマンス目標**: PRD 12.1の値をそのまま使用（init<3s, unlock 1-3s, new/edit<200ms, list(100entries)<500ms, lock<50ms）
4. **署名/HMAC検証失敗時**: DiaryError::Crypto に明確なメッセージ（改竄の可能性を示す）を含める
5. **REQ-023（M-3 PQCピン）**: 現在の `branch = "pq-diary"` を実装時点の最新コミットハッシュで `rev = "<hash>"` に置換する
6. **REQ-021（M-1 not_implemented）**: 4箇所の実使用箇所 + legacy/daemonスタブの全箇所を bail! に変更

**信頼性への影響**:
- REQ-020〜027（技術的負債）が確定（🔵）
- REQ-030〜035（品質保証）が確定（🔵）
- EDGE-020〜021, EDGE-030〜031 が確定（🔵）

---

## ヒアリング結果サマリー

### 確認できた事項
- S9スコープ: セキュリティ硬化 + 技術的負債全項目 + E2Eテスト + パフォーマンス検証
- mlock: Unix + Windows 両対応、失敗時は warn + continue
- PR_SET_DUMPABLE / RLIMIT_CORE: Unix のみ
- デバッガ検知: TracerPid (Unix) + IsDebuggerPresent (Windows)、warning only
- 技術的負債: H-1, M-1〜M-5, 署名/HMAC検証の全項目確定
- E2Eテスト: 全13コマンド対象
- パフォーマンス: PRD 12.1目標値を採用

### 追加/変更要件
- **詳細化**: mlock失敗時の挙動が warn + continue に確定
- **詳細化**: デバッガ検知時の挙動が warning only に確定
- **詳細化**: PR_SET_DUMPABLE/RLIMIT_CORE がUnix限定に確定
- **詳細化**: 署名/HMAC検証エラーメッセージの要件が確定

### 残課題
- なし（全項目確認済み）

### 信頼性レベル分布

**ヒアリング前**:
- 🔵 青信号: 20件
- 🟡 黄信号: 8件
- 🔴 赤信号: 0件

**ヒアリング後（最終）**:
- 🔵 青信号: 全件 (+8)
- 🟡 黄信号: 0件 (-8)
- 🔴 赤信号: 0件 (0)

## 関連文書

- **要件定義書**: [requirements.md](requirements.md)
- **ユーザストーリー**: [user-stories.md](user-stories.md)
- **受け入れ基準**: [acceptance-criteria.md](acceptance-criteria.md)
