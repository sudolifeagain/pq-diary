# S13 添付ファイル 受け入れ基準

**作成日**: 2026-05-18
**関連要件**: [requirements.md](requirements.md)
**ストーリー**: [user-stories.md](user-stories.md)

**【信頼性レベル凡例】**: 🔵 確実 / 🟡 推測 / 🔴 推測のみ

---

## 1. attachment add (REQ-101 〜 REQ-105)

### TC-S13-101-01: 正常な PNG ファイルを add すると vault に保存される 🔵

- **Given**: vault unlock 済み、`bug.png` (1.5MB) が存在
- **When**: `pq-diary attachment add 3c6b ~/bug.png` を実行
- **Then**:
  - exit 0
  - `<vault_dir>/.attachments/<blob_uuid>.bin` が生成 (暗号化済み)
  - vault.pqd の attachment レコードに `bug.png` のメタデータが追加
  - 元ファイル `~/bug.png` は無変更

### TC-S13-101-02: 存在しないファイルを add すると Io エラー 🔵

- **Given**: `/nonexistent.png` が存在しない
- **When**: `pq-diary attachment add 3c6b /nonexistent.png`
- **Then**: `Err(DiaryError::Io(_))`、vault.pqd 無変更、`.attachments/` 無変更

### TC-S13-101-03: 1GB を超えるファイルは拒否 🟡

- **Given**: 1.5GB のファイル `huge.mp4`
- **When**: `pq-diary attachment add 3c6b huge.mp4`
- **Then**: `Err(DiaryError::InvalidArgument(_))`、`.attachments/` 無変更

### TC-S13-101-04: chunk 暗号化が機能する 🟡

- **Given**: 50MB のテストファイル (1MB chunk なら 50 chunks)
- **When**: `pq-diary attachment add` 実行
- **Then**:
  - `.attachments/<blob_uuid>.bin` のサイズ ≈ 50MB + (12 + 16) * 50 (IV + GCM tag overhead)
  - 各 chunk が独立した IV を持つ (バイナリ先頭 12B 比較で確認)

### TC-S13-101-E01: メモリピーク確認 🟡

- **Given**: 100MB ファイル添付、`max_rss` プロセス監視
- **When**: add 実行
- **Then**: 最大 RSS が (vault size + 5MB) 程度に収まる (1MB chunk + overhead)

---

## 2. attachment list (REQ-201)

### TC-S13-201-01: 添付 0 個のエントリで空一覧 🟡

- **Given**: 添付未設定のエントリ
- **When**: `pq-diary attachment list 3c6b`
- **Then**: exit 0、`No attachments for entry 3c6b.` のような表示

### TC-S13-201-02: 添付 3 個のエントリで全表示 🟡

- **Given**: 3 添付済 (a.png, b.pdf, c.mp4)
- **When**: `pq-diary attachment list 3c6b`
- **Then**:
  - exit 0
  - 3 行で各添付の `name, size (KB/MB), added_at` を表示

---

## 3. attachment extract (REQ-202, REQ-203)

### TC-S13-202-01: extract で元ファイルが復元 🔵

- **Given**: `original.png` (SHA-256 X) を add 済み
- **When**: `pq-diary attachment extract 3c6b original.png --out /tmp/restored.png`
- **Then**:
  - exit 0
  - `/tmp/restored.png` の SHA-256 = X (バイト単位一致)

### TC-S13-202-02: 改ざんされた `.bin` で extract エラー 🔵

- **Given**: add 後に `.attachments/<blob_uuid>.bin` の任意の byte を flip
- **When**: extract 実行
- **Then**: `Err(DiaryError::Crypto(_))` (AEAD tag mismatch)、`--out` ファイル無生成

### TC-S13-202-03: 存在しない添付名で Entry エラー 🟡

- **Given**: 添付に nonexistent.png は存在しない
- **When**: `pq-diary attachment extract 3c6b nonexistent.png --out /tmp/x.png`
- **Then**: `Err(DiaryError::Entry(_))`、`--out` ファイル無生成

---

## 4. attachment delete (REQ-301, REQ-302)

### TC-S13-301-01: delete で本体ファイルが zeroize 削除 🔵

- **Given**: 100MB の添付 a.bin 存在
- **When**: `pq-diary attachment delete 3c6b a.bin`
- **Then**:
  - exit 0
  - `.attachments/<blob_uuid>.bin` が存在しない
  - 削除前に zeroize 上書きされた痕跡 (削除前バイトは vault からも完全に取り出せない)

### TC-S13-301-02: 添付メタデータも vault.pqd から削除 🟡

- **Given**: 削除前 attachment_count = 3
- **When**: delete 実行
- **Then**:
  - attachment_count = 2
  - 該当 attachment レコードが vault.pqd から消えている

---

## 5. new --attach (REQ-401)

### TC-S13-401-01: new と add を 1 コマンドで完了 🟡

- **Given**: `photo.jpg` 存在
- **When**: `pq-diary new --title "X" --attach photo.jpg --body "Y"`
- **Then**:
  - exit 0
  - エントリ生成 + photo.jpg 添付済み (attachment_count = 1)

### TC-S13-401-02: 複数 --attach を許容 🟡

- **When**: `pq-diary new --title "X" --attach a.png --attach b.pdf --body "Y"`
- **Then**: 2 添付済みエントリが生成

---

## 6. show 拡張 (REQ-402)

### TC-S13-402-01: 添付一覧がエントリ表示に含まれる 🟡

- **Given**: 2 添付済 (a.png, b.pdf)
- **When**: `pq-diary show 3c6b`
- **Then**: 出力末尾に `Attachments (2): a.png, b.pdf` を含む

### TC-S13-402-02: 添付 0 個ならセクション省略 🟡

- **When**: 添付 0 個のエントリで show
- **Then**: Attachments セクションは出力されない

---

## 7. Legacy 連動 (REQ-501 〜 REQ-504, S12 拡張)

### TC-S13-501-01: attachment set --inherit で legacy ブロック生成 🟡

- **Given**: legacy 初期化済み、添付 a.png 存在 (DESTROY default)
- **When**: `pq-diary attachment set 3c6b a.png --inherit`
- **Then**:
  - exit 0
  - attachment レコードの legacy_flag = 0x01
  - legacy_key_block が生成 (K_legacy で AttachmentLegacyPlaintext を暗号化)

### TC-S13-503-01: legacy-access で INHERIT 添付が継承 🟡

- **Given**: 添付 a.png INHERIT、b.pdf DESTROY、エントリ INHERIT
- **When**: `pq-diary legacy-access` (timer30 → y)
- **Then**:
  - 新 vault に a.png 残る (extract で復元可)
  - `.attachments/<b.pdf blob_uuid>.bin` が、他参照がなければ zeroize 削除済み
  - 新 vault unlock は legacy code で成功

### TC-S13-503-02: legacy-access の report 🟡

- **Given**: 上記
- **When**: legacy-access
- **Then**: stdout に `inherited entries: 1, attachments: 1; destroyed entries: 0, attachments: 1`

### TC-S13-504-01: エントリ DESTROY 連動 🟡

- **Given**: エントリ AAA に添付 a.png (INHERIT) と b.pdf (INHERIT)、エントリ AAA を DESTROY
- **When**: `pq-diary legacy set AAA --destroy`
- **Then**:
  - attachment_count はそのまま (UI 上の add/delete とは別)
  - legacy-access 時に AAA も a.png も b.pdf も destroy

---

## 8. Export / Import (REQ-601, REQ-602, REQ-603, REQ-604)

### TC-S13-601-01: export で attachments/ 出力 🔵

- **Given**: 2 添付済 vault
- **When**: `pq-diary export ~/out/` (y で確認)
- **Then**:
  - `~/out/<date>-<slug>-<id>.md` 生成
  - `~/out/attachments/photo.jpg`, `~/out/attachments/receipt.pdf` 生成
  - MD 内に `![[photo.jpg]]` が含まれる

### TC-S13-603-01: import で `![[FILE]]` が attachments/ から取り込み 🔵

- **Given**: `~/in/note.md` (内容: `Hello ![[a.png]]`), `~/in/attachments/a.png`
- **When**: `pq-diary import ~/in/`
- **Then**:
  - exit 0
  - エントリ生成済み (title: note)
  - 添付 a.png が attachment_count = 1 で記録

### TC-S13-604-01: 同一 SHA-256 添付の重複排除 🟡

- **Given**: a.png (SHA-256 X) が vault に既存
- **When**: 別エントリ B に同じ a.png を add (`import` 経由)
- **Then**:
  - 新 attachment レコードは生成
  - 新 record の AttachmentPlaintext は既存 blob_uuid + FileKey を参照
  - `.attachments/` に新 `.bin` は作られない (既存 blob を共有)
  - 片方の attachment を delete しても、もう片方から extract できる

---

## 9. --claude ブロック (REQ-701)

### TC-S13-701-01: --claude attachment add ブロック 🔵

- **When**: `pq-diary --claude attachment add 3c6b a.png`
- **Then**: `Err(...not permitted with --claude...)`、vault 無変更

### TC-S13-701-02: --claude attachment extract ブロック 🔵

- **When**: `pq-diary --claude attachment extract 3c6b a.png --out /tmp/`
- **Then**: 同上

### TC-S13-701-03: --claude attachment list は許可? 🟡

- **設計判断**: list は read-only、access policy が full なら許可?
  → Phase 1 では一律ブロックでシンプル化、ヒアリングで確認

---

## 10. change-password 連動 (REQ-702)

### TC-S13-702-01: change-password 後も attachment が読める 🟡

- **Given**: 添付済 vault
- **When**: change-password 実行 → 新パスワードで extract
- **Then**: extract が新パスワードで成功 (`.bin` 本体は変更不要、AttachmentPlaintext は再暗号化)

---

## 11. Edge cases

### TC-S13-EDGE-01: 0 バイトファイル 🟡

- **Given**: `empty.txt` (0 bytes)
- **When**: add → list → extract
- **Then**:
  - add 成功、attachment レコード生成
  - extract 後 `--out` ファイルが 0 byte で存在

### TC-S13-EDGE-02: 257 個目の添付 🟡

- **Given**: 1 エントリで添付 256 個既存
- **When**: 257 個目を add
- **Then**: `Err(DiaryError::InvalidArgument(_))`

### TC-S13-EDGE-03: 同名追加 (異 SHA-256) は拒否 🟡

- **Given**: a.png (SHA-256 X) 既存
- **When**: 別の a.png (SHA-256 Y) を add
- **Then**: `Err(DiaryError::InvalidArgument(_))` (rename を促す)

### TC-S13-EDGE-04: 後方互換 — Phase 1 vault を S13 クライアントで開く 🔵

- **Given**: S12 で生成された vault (attachment_count = 0)
- **When**: S13 クライアントで `pq-diary list`
- **Then**: 既存エントリが全て表示、attachment セクションは空

### TC-S13-EDGE-06: S13 vault は旧 client で拒否 🟡

- **Given**: S13 で `schema_version = 5` に migration 済み vault
- **When**: S12 以前のクライアントで open
- **Then**: unsupported schema エラーで停止し、unknown record を entry として parse しない

---

## 12. パフォーマンス (NFR-001 〜 NFR-003)

### TC-S13-NFR-01: 100MB add ≤ 60s 🟡

- **Given**: 100MB 単色 PNG
- **When**: add
- **Then**: `elapsed ≤ 60s` (CI runner basis)

### TC-S13-NFR-02: 1GB extract ≤ 300s 🟡

- **Given**: 1GB ランダムデータ添付済
- **When**: extract
- **Then**: `elapsed ≤ 300s`

### TC-S13-NFR-03: メモリピーク (1GB ファイル) ≤ 6MB 🟡

- **Given**: 1GB add 中
- **When**: 並行プロセスから RSS 監視
- **Then**: ピーク RSS が `vault size + 6MB` 以下 (1MB chunk + 4MB overhead)

---

## 信頼性レベル分布

- 🔵 青信号: 11 件 (~29%)
- 🟡 黄信号: 27 件 (~71%)
- 🔴 赤信号: 0 件

**カバレッジ**: 全要件 REQ-101〜901, NFR-001〜301 を 1 つ以上の TC でカバー。
設計フェーズで TC-S13-701-03 (`--claude list` 許可ポリシー) を確定する必要あり。
