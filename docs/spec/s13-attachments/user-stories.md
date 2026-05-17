# S13 添付ファイル ユーザストーリー

**作成日**: 2026-05-18
**関連要件**: [requirements.md](requirements.md)
**ヒアリング**: [interview-record.md](interview-record.md)

**【信頼性レベル凡例】**:
- 🔵 PRD・既存実装・ユーザヒアリング由来
- 🟡 妥当な推測
- 🔴 推測のみ

---

## エピック1: 添付ファイル基本操作

### ストーリー 1.1: スクリーンショットを日記に貼り付ける 🔵

**信頼性**: 🔵 *日記アプリの基本ユースケース、ヒアリング Q1 (画像中心) で確認*

**私は** 日記利用者 **として**
**今日撮ったスクリーンショットを今日のエントリに添付したい**
**そうすることで** UI バグや業務メモを画像つきで記録できる

**関連要件**: REQ-101, REQ-102, REQ-103, REQ-401

**詳細シナリオ**:
1. `pq-diary today` で今日のエントリを開いて編集
2. 別ターミナルで `pq-diary attachment add <ENTRY_ID> ~/Pictures/bug.png`
3. `pq-diary show <ENTRY_ID>` で添付に bug.png が表示される

**前提**: vault 作成済み、画像ファイルが存在
**優先度**: Must Have

---

### ストーリー 1.2: 添付した PDF を後から取り出す 🟡

**信頼性**: 🟡 *バックアップ的な使い方、UX 推測*

**私は** 日記利用者 **として**
**過去エントリに貼った PDF レシートを取り出したい**
**そうすることで** 確定申告や経費精算に使える

**関連要件**: REQ-201, REQ-202, REQ-203

**詳細シナリオ**:
1. `pq-diary attachment list <ENTRY_ID>` で添付一覧
2. `pq-diary attachment extract <ENTRY_ID> receipt.pdf --out /tmp/r.pdf`
3. 元ファイルの SHA-256 一致を CLI が報告

**前提**: 過去に添付済み、master password 既知
**優先度**: Must Have

---

### ストーリー 1.3: 不要になった添付を物理削除する 🟡

**信頼性**: 🟡 *データ整理 UX 推測*

**私は** 日記利用者 **として**
**もう不要な大容量動画添付を削除したい**
**そうすることで** vault サイズを抑え、ディスク容量を回復できる

**関連要件**: REQ-301, REQ-302

**詳細シナリオ**:
1. `pq-diary attachment list <ENTRY_ID>` で削除対象を確認
2. `pq-diary attachment delete <ENTRY_ID> video.mp4 --force`
3. `.attachments/<uuid>.bin` が zeroize 後に削除されていることを確認

**前提**: master password 既知
**優先度**: Should Have

---

## エピック2: 新規作成時の同時添付

### ストーリー 2.1: 写真をワンコマンドで日記化 🟡

**信頼性**: 🟡 *UX 効率化、ヒアリングなしの推測*

**私は** 日記利用者 **として**
**写真を撮ってすぐ `pq-diary new --attach photo.jpg "コーヒー"` でエントリを作りたい**
**そうすることで** add の 2 ステップを 1 ステップに圧縮できる

**関連要件**: REQ-401, REQ-801

**詳細シナリオ**:
1. `pq-diary new --title "コーヒー" --attach photo.jpg --body "豆: ケニア"`
2. エントリ作成と同時に添付保存

**前提**: ファイル存在
**優先度**: Could Have (基本機能は別途 add で実現可能)

---

## エピック3: Legacy 連動 (S12 拡張)

### ストーリー 3.1: 機微な添付だけ DESTROY 指定 🔵

**信頼性**: 🔵 *ヒアリング Q3 (ファイル個別フラグ) で確定*

**私は** 終活を意識する日記利用者 **として**
**遺族に渡したい思い出の写真は INHERIT、見られたくない医療スキャン PDF は DESTROY と
個別に指定したい**
**そうすることで** legacy-access 時に思い出は継承、機微情報は確実に消去される

**関連要件**: REQ-501, REQ-502, REQ-503

**詳細シナリオ**:
1. `pq-diary attachment set <ENTRY_ID> family-photo.jpg --inherit`
2. `pq-diary attachment set <ENTRY_ID> mri-scan.pdf --destroy`
3. `pq-diary legacy-access` 後、family-photo.jpg のみ新 vault に残る

**前提**: legacy 初期化済み
**優先度**: Should Have

---

### ストーリー 3.2: エントリ DESTROY 連動 🟡

**信頼性**: 🟡 *データ整合性ルール*

**私は** 日記利用者 **として**
**エントリ自体を DESTROY 指定したら、紐付く添付も自動 DESTROY にしたい**
**そうすることで** legacy-access で「エントリは消えたが画像だけ残る」ような
中途半端な状態を避けられる

**関連要件**: REQ-504

**詳細シナリオ**:
1. エントリ AAA の添付 a.png は INHERIT、b.png は DESTROY
2. `pq-diary legacy set AAA --destroy` でエントリ全体を DESTROY
3. legacy-access 時、a.png も b.png も両方 DESTROY 処理

**前提**: S12 legacy 機能と連動
**優先度**: Must Have

---

## エピック4: Export / Import

### ストーリー 4.1: 別端末への Obsidian 互換引っ越し 🔵

**信頼性**: 🔵 *ヒアリング Q4 (双方向 Obsidian 互換) で確定*

**私は** 日記利用者 **として**
**現端末で `pq-diary export ~/migrate/` し、新端末で `pq-diary import ~/migrate/` したい**
**そうすることで** 添付込みで vault を完全再現できる

**関連要件**: REQ-601, REQ-602, REQ-603

**詳細シナリオ**:
1. 旧端末: `pq-diary export ~/migrate/` → MD + attachments/ 出力
2. USB / クラウド経由で `~/migrate/` を新端末へ移動
3. 新端末: `pq-diary init` で vault 作成
4. 新端末: `pq-diary import ~/migrate/` → MD + attachments 取り込み

**前提**: vault.pqd 内容は同じになることを SHA-256 比較で検証可能
**優先度**: Must Have

---

### ストーリー 4.2: Obsidian vault からのインポート 🔵

**信頼性**: 🔵 *ヒアリング Q4 + S6 import 既存パターン*

**私は** Obsidian ユーザー **として**
**Obsidian の MD + attachments/ をそのまま `pq-diary import` で取り込みたい**
**そうすることで** Obsidian から移行・並行運用が容易になる

**関連要件**: REQ-603, REQ-604

**詳細シナリオ**:
1. `pq-diary import ~/ObsidianVault/`
2. `![[image.png]]` リンクが自動的にバイナリ添付として取り込まれる
3. 重複添付 (SHA-256 一致) は本体書き込みスキップ

**前提**: Obsidian vault のディレクトリ構造、master password
**優先度**: Must Have

---

## エピック5: 大容量ファイル

### ストーリー 5.1: 録画動画の保管 🟡

**信頼性**: 🟡 *ユースケースの推測、ヒアリング Q1 で 1GB 上限確定*

**私は** 日記利用者 **として**
**1 時間の録画 (500MB-1GB) を日記に添付したい**
**そうすることで** 重要な会議録音や講義映像を暗号化して保管できる

**関連要件**: REQ-104, REQ-105, NFR-001, NFR-002, NFR-003

**詳細シナリオ**:
1. `pq-diary attachment add <ENTRY_ID> meeting.mp4` (size: 700MB)
2. 1MB chunk ごとに進捗表示 (`Encrypting chunk 350/700...`)
3. 60 秒〜数分以内に完了

**前提**: ディスク容量充分、メモリ 2GB 以上
**優先度**: Should Have

---

## エピック6: Show / List の拡張

### ストーリー 6.1: エントリ表示時に添付情報も見たい 🟡

**信頼性**: 🟡 *show の自然な拡張*

**私は** 日記利用者 **として**
**`pq-diary show <ID>` で添付ファイル名と数も一緒に確認したい**
**そうすることで** どのエントリに何が添付されているか把握できる

**関連要件**: REQ-402

**詳細シナリオ**:
1. `pq-diary show 3c6b`
2. エントリ本文の下に `Attachments (3): photo.jpg, receipt.pdf, voice.m4a` と表示

**前提**: master password 既知
**優先度**: Should Have

---

## 信頼性レベルサマリー

- 🔵 青信号: 3 件 (33%)
- 🟡 黄信号: 6 件 (67%)
- 🔴 赤信号: 0 件

**品質評価**: ヒアリング由来は 🔵、それ以外 (UX 改善・整合性ルール) は 🟡。
設計フェーズでの追加ヒアリングで 🟡 → 🔵 に昇格可能 (特にエピック 5/6)。
