# S12 デジタル遺言 ヒアリング記録

**作成日**: 2026-05-17

## ヒアリング目的

PRD §7 の仕様を実装する S12 のスコープと、未確定だった OQ-18 を含む 6 つの設計判断を確定。

## 質問と回答

### Q1: OQ-18 — legacy-access 後の新 vault.pqd の暗号鍵は?

**カテゴリ**: 設計判断 (OQ-18 解消)
**背景**: PRD §7.3 step 4 で「INHERIT エントリのみを含む新 vault.pqd を K_legacy で再暗号化」とあるが、その後に骨梧者がどう使うかが未定義。

**回答**: 「K_legacy をそのまま残留」を選択。

**設計影響**: 骨梧者は同じ death-access code を通常の master password として vault を継続利用可能。`legacy-access` 自体は新 vault 化後に `[legacy] initialized=false` となるため再実行対象ではない。デメリットは「コード漏洩時の継続的リスク」だが、本人がコードを家族にしか教えない前提で許容。

---

### Q2: `legacy rotate` の振る舞いは?

**カテゴリ**: 設計判断
**背景**: 死後アクセスコード変更時、既存 INHERIT エントリの legacy ブロックをどう扱うか。

**回答**: 「全 INHERIT エントリを即時再暗号化」を選択。

**設計影響**: change-password と同パターン。vault.pqd.tmp + rename でアトミック。旧コードでの復号は完全に不可能になる (= rotate の本来の目的)。

---

### Q3: 死後アクセスコードの強度

**カテゴリ**: セキュリティ
**背景**: K_master と同等強度か、長期保管考慮で強化するか。

**回答**: 「K_master と同じ Argon2 パラメータ + TTY 入力 2 回」を選択。

**設計影響**: kdf::derive_key() を共用、同じ KdfParams (memory_cost_kb=65536, time_cost=3, parallelism=1) を使う。実装シンプル。

---

### Q4: `legacy-access` の不可逆性 UX

**カテゴリ**: UX 設計
**背景**: DESTROY 実行は取消不能。誤実行防止策の強度設計。

**当初提案**: 30 秒タイマー + y/N で固定
**ユーザー介入**: 「初期設定時にユーザーが選べるようにして」 → 設定可能化に変更

**最終回答**: 3 方式 (`timer30` / `yn` / `phrase`) を `legacy init` で選択 → `vault.toml [legacy] destroy_confirmation` に保存。

**設計影響**: vault.toml に `[legacy]` セクション追加。legacy-access はこの設定値に従って動作。デフォルト `timer30`。

---

### Q5: デフォルト確認方式

**カテゴリ**: UX
**回答**: 「30 秒タイマー + y/N」を選択。

**設計影響**: `legacy init` で確認方式選択を Enter のみで通過した場合 `timer30` を採用。

---

### Q6: `--claude` フラグでの扱い

**カテゴリ**: AI 連携セキュリティ
**回答**: 「全てブロック」を選択。

**設計影響**: legacy* / legacy-access すべて `check_claude_policy` の前段で拒否。Argon2 鍵導出に入る前にブロック (タイミングサイドチャネル回避、NFR-104)。

---

### Q7: Shamir's Secret Sharing (Phase 3) の意識

**カテゴリ**: 将来拡張
**回答**: 「今は単一コード、拡張作可能な設計」を選択。

**設計影響**: K_legacy 導出関数を trait `LegacyKeyDeriver` 化。デフォルト実装は `Argon2LegacyDeriver`、Phase 3 で `ShamirLegacyDeriver` (M-of-N コード合成) を追加できる構造。

---

## ヒアリング結果サマリー

### 確認できた事項
1. legacy-access 後は K_legacy 残留 (骨梧者が通常 unlock で継続利用可)
2. legacy rotate は全 INHERIT 即時再暗号化
3. 死後アクセスコードは K_master と同じ Argon2 強度
4. 確認方式は `legacy init` で選択可能 (vault.toml に保存)
5. デフォルト確認方式: `timer30`
6. --claude は全 legacy 系をブロック
7. K_legacy 導出は trait 化、Shamir 拡張可能

### 追加された要件
- REQ-107 (確認方式選択)
- REQ-701〜706 (vault.toml [legacy] セクション + K_legacy 検証 token)
- NFR-102 (LegacyKeyDeriver trait)
- NFR-104 (--claude タイミングサイドチャネル回避)

### 残課題
- なし。実装スプリント (kairo-tasks → kairo-implement) で詳細化のみ。

### 信頼性レベル分布
全要件 + 7 ストーリー + 追加 TC = **すべて🔵**。

## 関連文書

- [requirements.md](requirements.md)
- [user-stories.md](user-stories.md)
- [acceptance-criteria.md](acceptance-criteria.md)
- [note.md](note.md)
