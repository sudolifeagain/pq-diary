# S12 デジタル遺言 ユーザストーリー

**作成日**: 2026-05-17
**関連要件**: [requirements.md](requirements.md)
**ヒアリング**: [interview-record.md](interview-record.md)

**【信頼性レベル】**: 全ストーリー🔵 (PRD §7 + 2026-05-17 ヒアリング)

---

## エピック 1: 遺言の準備 (生前)

### ストーリー 1.1: 死後アクセスコードの初回設定 🔵
**信頼性**: 🔵 *PRD §7.1 + ヒアリング Q3/Q4/Q5*

**私は** pq-diary を長期利用する 40 代ユーザー **として**
**`pq-diary legacy init` で死後アクセスコードを設定したい**
**そうすることで** 万一のとき、遺族が指定したエントリを継承できる

**関連要件**: REQ-101 〜 REQ-111, NFR-001

**詳細シナリオ**:
1. ユーザーが `pq-diary legacy init` 実行
2. システムが「Master password:」プロンプト → ユーザーが入力
3. システムが vault unlock → 「Legacy code:」「Confirm legacy code:」プロンプト → ユーザーが入力
4. システムが新旧パスワード一致確認、空チェック、マスターと同一なら警告
5. システムが対話: `Choose destroy confirmation method: [1] timer30 (default) [2] yn [3] phrase` → ユーザーが選択 (or Enter で 1)
6. `vault.toml [legacy] initialized=true, destroy_confirmation="timer30"` に保存
7. `Legacy code initialized. Confirmation mode: timer30` 表示

**前提条件**: vault 作成済み (pq-diary init or vault create 完了)

**優先度**: Must Have

---

### ストーリー 1.2: エントリの遺言設定 🔵
**信頼性**: 🔵 *PRD §7.1 + REQ-201/202*

**私は** 一部のセンシティブな日記は遺族にも見せたくないユーザー **として**
**個別エントリを INHERIT (継承可) / DESTROY (即消去) に設定したい**
**そうすることで** 「家族写真の思い出は残し、職場の愚痴は消す」のような選別ができる

**関連要件**: REQ-201, REQ-202, REQ-203, REQ-204, REQ-205, NFR-002

**詳細シナリオ**:
1. ユーザーが `pq-diary legacy list` で現状確認 (デフォルト全て DESTROY)
2. ユーザーが `pq-diary legacy set 3c6b --inherit` で個別エントリを INHERIT に
3. システムが master unlock → 該当エントリの legacy ブロック (平文 JSON の K_legacy 暗号化コピー) を追加 → アトミック書き戻し
4. `Entry 3c6b775f set to INHERIT` 表示

**前提条件**: `legacy init` 完了

**優先度**: Must Have

---

### ストーリー 1.3: 遺言状態の確認 🔵
**信頼性**: 🔵 *PRD L249 + REQ-301*

**私は** どのエントリをどう設定したか忘れがちなユーザー **として**
**`pq-diary legacy list` で全エントリの遺言状態を一覧したい**
**そうすることで** 定期的にレビューして意図通りか確認できる

**関連要件**: REQ-301, REQ-302, REQ-303

**詳細シナリオ**:
1. ユーザーが `pq-diary legacy list` 実行
2. INHERIT グループ + DESTROY グループ + Summary が表示

**前提条件**: vault unlock 済み (password 取得)

**優先度**: Must Have

---

## エピック 2: コードのメンテナンス

### ストーリー 2.1: 死後アクセスコードの定期変更 🔵
**信頼性**: 🔵 *PRD L246 + ヒアリング Q2*

**私は** 死後アクセスコードを家族にメモで渡したが、書き換えたくなったユーザー **として**
**`pq-diary legacy rotate` で死後アクセスコードを安全に変更したい**
**そうすることで** 旧コードを無効化できる (旧コードでは新 vault は開けない)

**関連要件**: REQ-401 〜 REQ-405, NFR-003

**詳細シナリオ**:
1. ユーザーが `pq-diary legacy rotate` 実行
2. master + 旧 legacy code 取得 → 新 legacy code 2 回入力
3. 全 INHERIT エントリの legacy ブロックと検証 token を K_legacy_new で再暗号化
4. vault.pqd.tmp → rename でアトミック差し替え
5. `Legacy code rotated successfully (N entries re-encrypted)` 表示

**前提条件**: `legacy init` 完了

**優先度**: Must Have

---

## エピック 3: 遺族による継承 (死後)

### ストーリー 3.1: 遺族の死後アクセス実行 🔵
**信頼性**: 🔵 *PRD §7.3 + ヒアリング Q1*

**私は** ユーザーが亡くなった後、家族からメモで死後アクセスコードを受け取った遺族 **として**
**`pq-diary legacy-access` で INHERIT エントリのみを受け取り、DESTROY は消去したい**
**そうすることで** 故人の意思を尊重した形で日記を継承できる

**関連要件**: REQ-501 〜 REQ-508, NFR-004, NFR-101, NFR-103

**詳細シナリオ**:
1. 遺族が `pq-diary legacy-access` 実行 (master password は知らない)
2. システムが「Legacy code:」プロンプト → 遺族が入力
3. K_legacy 導出 + 検証トークン突合 (失敗時は安全に停止)
4. 確認方式 (vault.toml の `destroy_confirmation` 値) に従って警告:
   - `timer30`: 30 秒タイマー + y/N
5. ユーザー (遺族) が `y` 入力
6. システムが全エントリスキャン: INHERIT → 復号、DESTROY → zeroize
7. INHERIT のみを含む新 vault.pqd を K_legacy で再暗号化、アトミック書き戻し
8. `Legacy access complete. N entries inherited, M entries destroyed.` 表示
9. 遺族は以後、同じ legacy code で vault を normal 操作可能 (K_legacy をマスター鍵として継続使用)

**前提条件**: vault.toml `[legacy] initialized = true`

**制約**: **不可逆** (一度実行すると DESTROY は復元不能)

**優先度**: Must Have

---

### ストーリー 3.2: 誤実行の防止 🔵
**信頼性**: 🔵 *ヒアリング Q4 + REQ-504*

**私は** デジタル遺言を確認だけして実際の継承は将来したい遺族 **として**
**確認プロンプトで 30 秒考える時間が欲しい (誤って y を押さないように)**
**そうすることで** 不可逆操作を慎重に判断できる

**関連要件**: REQ-504 (timer30 モード), NFR-203

**詳細シナリオ**:
1. 遺族が `pq-diary legacy-access` 実行
2. 警告メッセージ + 「Wait 30 seconds before confirming...」表示
3. 残り秒数がリアルタイム更新 (29 → 28 → ... → 0)
4. 0 になったら y/N プロンプト
5. 遺族が「待っている間に考え直した」場合 N or Ctrl+C で中断
6. 何も変更されず終了

**優先度**: Must Have

---

## エピック 4: AI 連携時の安全性

### ストーリー 4.1: Claude による誤実行の防止 🔵
**信頼性**: 🔵 *ヒアリング Q6*

**私は** Claude Code から日常的に pq-diary を操作するユーザー **として**
**Claude が prompt injection 等で legacy-access を呼び出しても完全ブロックされてほしい**
**そうすることで** AI 経由での不可逆操作を防げる

**関連要件**: REQ-601, NFR-104

**詳細シナリオ**:
1. Claude (悪意あるプロンプトに誘導された場合) が `pq-diary --claude legacy-access` を実行
2. システムが Argon2 鍵導出に入る前に拒否
3. `Error: legacy operations are not permitted with --claude` 表示
4. 何も変更されず exit ≠ 0

**優先度**: Must Have

---

## ストーリーマップ

```
エピック 1: 遺言の準備 (生前)
├── 1.1 死後アクセスコード初回設定 (🔵 Must Have)
├── 1.2 エントリの遺言設定 (🔵 Must Have)
└── 1.3 遺言状態の確認 (🔵 Must Have)

エピック 2: コードのメンテナンス
└── 2.1 死後アクセスコード定期変更 (🔵 Must Have)

エピック 3: 遺族による継承 (死後)
├── 3.1 死後アクセス実行 (🔵 Must Have)
└── 3.2 誤実行防止 (🔵 Must Have)

エピック 4: AI 連携時の安全性
└── 4.1 Claude 誤実行防止 (🔵 Must Have)
```

## 信頼性レベルサマリー

- 🔵 青信号: 7 件 (100%)
- 🟡 黄信号: 0
- 🔴 赤信号: 0

**品質評価**: 最高品質。
