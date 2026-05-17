# S11 クロスプラットフォーム検証 + toolchain 固定 ヒアリング記録

**作成日**: 2026-05-17
**ヒアリング実施**: kairo-requirements step4

## ヒアリング目的

S10 hotfix (PR #3) で表面化した CI 環境差異の恒久対策と、Phase 1 取りこぼし「クロスプラットフォームビルド」の回収を統合したスプリント (S11) のスコープと設計判断を確定。

## 質問と回答

### Q1: S11 のテーマと内容

**質問日時**: 2026-05-17
**カテゴリ**: スコープ決定
**背景**: ユーザーが「先に CI 修正してからクロスプラットフォーム検証スプリント」と指示。

**回答**: hotfix を先に対応 (PR #3 で完了)、その後 S11 として「クロスプラットフォーム検証 + toolchain 固定」を開始。

**信頼性への影響**: スプリント全体方針確定 🔵

---

### Q2: 作業規模

**質問日時**: 2026-05-17
**カテゴリ**: 作業規模
**背景**: S11 は DIRECT 中心の小スプリントだが、フォーマリズム選択。

**回答**: フル機能開発 (requirements + user-stories + acceptance-criteria + interview-record の 4 ファイル作成)。

**信頼性への影響**: ドキュメント網羅性向上 🔵

---

### Q3: rust-toolchain.toml の channel 指定方法

**質問日時**: 2026-05-17
**カテゴリ**: 技術選択 (toolchain pin)
**背景**: S10 hotfix で Rust 1.94 → 1.95 の clippy 差分が発生。CI と local の同期維持に rust-toolchain.toml を導入するが、`"stable"` (auto) と固定バージョンのどちらを選ぶか。

**回答**: 「固定バージョン (1.95.0)」を選択。再現性最優先、新版リリース時は明示的アップデート + 動作確認。

**信頼性への影響**: REQ-102 確定 🔵

---

### Q4: Linux aarch64 (ubuntu-24.04-arm public preview) を S11 でカバーするか

**質問日時**: 2026-05-17
**カテゴリ**: スコープ調整
**背景**: ubuntu-24.04-arm は 2026-05 時点で public preview。利用可能だが GA 前。

**回答**: 「S11 で対応」を選択。Phase 1 取りこぼし「Linux x86_64/aarch64」を一気に解消。preview EOL リスクは fail-fast: false でリスク隔離。

**信頼性への影響**: REQ-303 確定 🔵

---

### Q5: matrix ジョブの fail-fast 戦略

**質問日時**: 2026-05-17
**カテゴリ**: CI 設計
**背景**: matrix のデフォルトは `fail-fast: true` で 1 OS 失敗時に他をキャンセル。

**回答**: 「fail-fast: false」を選択。全 OS の状態を一度に把握、CI minutes は public で無料。

**信頼性への影響**: REQ-203 確定 🔵

---

## ヒアリング結果サマリー

### 確認できた事項

1. S11 はフル機能開発で進める
2. rust-toolchain.toml で固定バージョン (1.95.0) を pin
3. Linux aarch64 (ubuntu-24.04-arm) を S11 で対応
4. fail-fast: false で全 OS の状態を可視化
5. macOS smoke は bash 版で実行 (PowerShell スキップ)
6. cargo audit は別ジョブに分離 (ubuntu のみ)

### 追加/変更要件

- **追加**: REQ-101〜104 (toolchain pin)
- **追加**: REQ-201〜203 (check matrix 化)
- **追加**: REQ-301〜303 (smoke 拡張)
- **追加**: REQ-401〜402 (audit 分離)
- **追加**: REQ-501〜502 (backlog 更新)
- **追加**: REQ-601 (発覚バグ修正、条件付き)

### 残課題

- macOS / Linux aarch64 で初めて CI を回した時に発覚するバグが未知数 (REQ-601 で対応)
- 将来 stable バージョンアップ時の手順を CONTRIBUTING.md 等で明文化する必要があるかも (Phase 2 候補)

### 信頼性レベル分布

**ヒアリング前**: 全項目🔵 (S10 hotfix 実体験 + 既存 CI 知識で確定)
**ヒアリング後**: 全項目🔵 (変化なし、確認のみ)

- 🔵: 24 件 (requirements) + 6 件 (user-stories) + 28 件 (acceptance-criteria) = **58 件 (100%)**
- 🟡: 0
- 🔴: 0

## 関連文書

- **要件定義書**: [requirements.md](requirements.md)
- **ユーザストーリー**: [user-stories.md](user-stories.md)
- **受け入れ基準**: [acceptance-criteria.md](acceptance-criteria.md)
- **コンテキストノート**: [note.md](note.md)
