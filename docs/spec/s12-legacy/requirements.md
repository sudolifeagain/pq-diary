# S12 デジタル遺言 (legacy) 要件定義書

## 概要

PRD §7 に規定される **デジタル遺言** 機能を実装する。死後アクセスコードによる INHERIT エントリの継承と DESTROY エントリの不可逆消去を可能にし、骨梧者 (deceased user's heir) が遺言として残したい日記内容のみを受け取れるようにする。

## 関連文書

- **ヒアリング記録**: [💬 interview-record.md](interview-record.md)
- **ユーザストーリー**: [📖 user-stories.md](user-stories.md)
- **受け入れ基準**: [✅ acceptance-criteria.md](acceptance-criteria.md)
- **コンテキストノート**: [📝 note.md](note.md)
- **PRD**: requirements.md v4.0 §7

## 機能要件 (EARS 記法)

**【信頼性レベル】**: 全項目🔵 (PRD §7 + 2026-05-17 ヒアリング Q1-Q7 + S3 予約フォーマットで確定)

### 1. `legacy init` (死後アクセスコード初期設定)

- **REQ-101**: システムは `pq-diary legacy init` 実行時、マスターパスワードを TTY で取得し、vault unlock を要求しなければならない 🔵 *セキュリティ前提、ヒアリング Q3*
- **REQ-102**: システムは vault unlock 成功後、死後アクセスコードを TTY で 2 回取得しなければならない (確認入力) 🔵 *ヒアリング Q3*
- **REQ-103**: 2 回の死後アクセスコードが一致しない場合、システムは `Passwords do not match` エラーで停止しなければならない 🔵 *change-password と同様*
- **REQ-104**: 死後アクセスコードが空の場合、システムは `Legacy code must not be empty` エラーで停止しなければならない 🔵 *セキュリティ規約*
- **REQ-105**: 死後アクセスコードと マスターパスワードが同一の場合、システムは `Warning: legacy code is identical to master password` 警告を表示し処理は続行する 🔵 *change-password REQ-314 と同様*
- **REQ-106**: 死後アクセスコードから `K_legacy = Argon2id(code, legacy_salt, kdf_params)` を導出しなければならない。`kdf_params` は K_master と同じ値を使う 🔵 *ヒアリング Q3*
- **REQ-107**: `legacy init` 実行時、ユーザーに確認方式 (`timer30` / `yn` / `phrase`) を選択させ、`vault.toml [legacy] destroy_confirmation` に保存しなければならない 🔵 *ヒアリング Q4*
- **REQ-108**: ユーザーが対話で確認方式を未選択 (Enter のみ) の場合、デフォルト `timer30` を採用する 🔵 *ヒアリング Q5*
- **REQ-109**: `legacy init` 完了時、メッセージ `Legacy code initialized. Confirmation mode: {mode}` を表示しなければならない 🔵 *メッセージスタイル*

#### 条件付き要件

- **REQ-111**: vault.toml の `[legacy] initialized = true` が既に true の場合、システムは `Already initialized. Use 'legacy rotate' to change the code` エラーを返さなければならない 🔵 *idempotency 保証*

### 2. `legacy set <ID_PREFIX> --inherit | --destroy` (エントリ単位の遺言設定)

- **REQ-201**: システムは `legacy set <ID> --inherit` 実行時、対象エントリの legacy フラグを `0x01` (INHERIT) に変更し、エントリ平文 JSON を K_legacy で暗号化した legacy ブロックをエントリレコードの `legacy_key_block` に追加しなければならない 🔵 *PRD §7.2 + 現行 v4 は per-entry DEK を持たないため payload copy 方式で実装*
- **REQ-202**: システムは `legacy set <ID> --destroy` 実行時、対象エントリの legacy フラグを `0x00` (DESTROY) に変更し、legacy ブロック (もしあれば) を削除しなければならない 🔵 *PRD §7.2*
- **REQ-203**: システムはこのコマンド実行時、vault.toml の `[legacy] initialized = true` を確認し、未初期化なら `legacy init を先に実行してください` エラーを返さなければならない 🔵 *依存関係*
- **REQ-204**: `legacy set` は vault.pqd 全体ではなく、対象エントリのレコードのみ書き換える (アトミック更新) 🔵 *既存 update_entry パターン踏襲*
- **REQ-205**: `--inherit` と `--destroy` が同時指定された場合、システムは `--inherit and --destroy are mutually exclusive` エラーで停止 🔵 *clap conflict_with*

### 3. `legacy list` (遺言設定一覧)

- **REQ-301**: システムは `legacy list` 実行時、全エントリの ID プレフィックス + タイトル + legacy フラグ状態 (`INHERIT` / `DESTROY`) を表示しなければならない 🔵 *PRD L249 + 既存 list パターン*
- **REQ-302**: 出力は INHERIT を先に、DESTROY を後にグループ化し、各グループ内は updated_at 降順 🔵 *UX の妥当な選択*
- **REQ-303**: 末尾に `Summary: INHERIT N entries / DESTROY M entries / Total {N+M}` を表示 🔵 *UX*

### 4. `legacy rotate` (死後アクセスコード変更)

- **REQ-401**: システムは `legacy rotate` 実行時、マスターパスワードと旧死後アクセスコードを TTY で取得し検証しなければならない 🔵 *セキュリティ二重認証*
- **REQ-402**: システムは新死後アクセスコードを TTY で 2 回取得し検証しなければならない 🔵 *change-password と同パターン*
- **REQ-403**: システムは新死後アクセスコードから K_legacy_new を導出し、全 INHERIT エントリの legacy ブロックと `[legacy]` 検証トークンを K_legacy_new で再暗号化しなければならない 🔵 *ヒアリング Q2*
- **REQ-404**: 再暗号化は vault.pqd.tmp + rename のアトミック書き換えで実施し、失敗時は旧 vault.pqd を維持しなければならない 🔵 *change-password REQ-304/313 と同パターン*
- **REQ-405**: 完了時、メッセージ `Legacy code rotated successfully ({N} INHERIT entries re-encrypted)` を表示 🔵 *メッセージスタイル*

### 5. `legacy-access` (死後アクセス実行 — 不可逆)

- **REQ-501**: システムは `pq-diary legacy-access` 実行時、`vault.toml [legacy] initialized = true` を確認しなければならない 🔵 *前提条件*
- **REQ-502**: システムは死後アクセスコードを TTY で取得し、`K_legacy = Argon2id(code, legacy_salt, kdf_params)` を導出 → `vault.toml [legacy]` の検証トークンと突合して正当性を確認しなければならない 🔵 *PRD §7.3 step 1; vault.pqd ヘッダーの既存 token は K_master 用のため流用しない*
- **REQ-503**: 死後アクセスコードが不正な場合、システムは `Invalid legacy code` エラーで停止し vault.pqd を変更してはならない 🔵 *セキュリティ規約*
- **REQ-504**: 検証成功後、システムは `vault.toml [legacy] destroy_confirmation` の値に従って確認 UI を表示しなければならない 🔵 *ヒアリング Q4/Q5*
  - `timer30`: 警告 + 30 秒タイマー + y/N
  - `yn`: 警告 + 即時 y/N
  - `phrase`: 警告 + コンフィルフレーズ手動入力 (期待値: `DESTROY ALL`)
- **REQ-505**: ユーザーが確認をキャンセル / 不正入力した場合、システムは `キャンセルしました` を表示し vault.pqd を変更してはならない 🔵 *安全側*
- **REQ-506**: 確認通過後、システムは全エントリをスキャンし以下を行わなければならない 🔵 *PRD §7.3 step 3*:
  1. INHERIT → K_legacy で legacy ブロックを復号 → エントリ平文を取得
  2. DESTROY (or 未設定) → エントリレコードを zeroize 上書き
- **REQ-507**: システムは INHERIT エントリのみを含む新 vault.pqd を K_legacy で再暗号化 (kdf_salt を元の legacy_salt に書き換え、verification token を K_legacy で再生成、新しい KEM/DSA 鍵を生成) してアトミックに書き戻さなければならない 🔵 *PRD §7.3 step 4 + ヒアリング Q1*
- **REQ-508**: 完了時、メッセージ `Legacy access complete. {INHERIT 数} entries inherited, {DESTROY 数} entries destroyed.` を表示 🔵 *UX*

### 6. `--claude` フラグでのブロック

- **REQ-601**: システムは `--claude` フラグ付きで `legacy init` / `legacy rotate` / `legacy set` / `legacy list` / `legacy-access` のいずれかを実行された場合、`Error: legacy operations are not permitted with --claude` を返さなければならない 🔵 *ヒアリング Q6*

### 7. vault.toml [legacy] セクション

- **REQ-701**: `vault.toml` に新規セクション `[legacy]` を追加しなければならない 🔵 *ヒアリング Q4*
- **REQ-702**: `[legacy] initialized: bool` (デフォルト `false`、`legacy init` 完了後 `true`) 🔵
- **REQ-703**: `[legacy] destroy_confirmation: String` (取りうる値: `"timer30"` / `"yn"` / `"phrase"`、デフォルト `"timer30"`) 🔵 *ヒアリング Q5*
- **REQ-704**: `[legacy]` セクション全体は省略可。読み込み時にデフォルト値 (`initialized = false, destroy_confirmation = "timer30"`) で補完 🔵 *後方互換性、既存 Phase 1 vault*
- **REQ-705**: `[legacy] verification_iv_b64` / `verification_ct_b64` は `legacy init` 完了時に K_legacy で生成した検証トークンを Base64 で保存しなければならない 🔵 *legacy code 検証用*
- **REQ-706**: `[legacy] initialized = true` なのに検証トークンが欠落または破損している場合、システムは `DiaryError::Config("Invalid vault.toml [legacy]: ...")` を返さなければならない 🔵 *設定破損検出*

### 8. CLI スケルトンの unhide

- **REQ-801**: `cli/src/main.rs` の `Commands::Legacy` / `Commands::LegacyAccess` から `#[command(hide = true)]` を削除しなければならない 🔵 *S10 で hide 化したものの解除*
- **REQ-802**: dispatch の `not_implemented("legacy ...", "Phase 2")` を各 `cmd_legacy_*` 呼び出しに置き換えなければならない 🔵

## 非機能要件

### パフォーマンス

- **NFR-001**: `legacy init` は Argon2id 鍵導出を含めて 5 秒以内に完了 (K_master + K_legacy の 2 回導出) 🔵 *change-password の半分相当*
- **NFR-002**: `legacy set` は 1 エントリの読み書きのみで 500 ms 以内 🔵 *既存 update_entry 同等*
- **NFR-003**: `legacy rotate` は 100 INHERIT エントリで 30 秒以内 (change-password 同規模) 🔵 *Argon2 2 回 + AES-GCM N回*
- **NFR-004**: `legacy-access` は 1000 エントリ vault で 60 秒以内 (Argon2 + 全 INHERIT 復号 + 新 vault 生成) 🔵 *change-password を参考*

### セキュリティ

- **NFR-101**: 死後アクセスコード / K_legacy / legacy ブロック復号後のエントリ平文はすべて `Zeroizing` / `SecretString` / `SecretBytes` でラップしなければならない 🔵 *CLAUDE.md 規約*
- **NFR-102**: K_legacy の導出は trait `LegacyKeyDeriver` 経由とし、Phase 3 で Shamir's Secret Sharing 実装を差し込めるよう抽象化する 🔵 *ヒアリング Q7*
- **NFR-103**: `legacy-access` 実行時、DESTROY エントリの暗号文を zeroize で 0 上書きしてから新 vault.pqd へ書き戻し → 旧 vault.pqd の rename で差し替え (DESTROY 暗号文の物理消去) 🔵 *PRD §7.3 zeroize 要件*
- **NFR-104**: `--claude` フラグ時、legacy 系コマンドは Argon2 鍵導出に入る前にブロックしなければならない (タイミングサイドチャネル回避) 🔵 *セキュリティベストプラクティス*

### ユーザビリティ

- **NFR-201**: `legacy init` の確認方式選択は対話的に行う (デフォルト選択肢を [Y] と表示、Enter のみで採用) 🔵 *UX 標準*
- **NFR-202**: `legacy-access` の警告メッセージは赤色 (ANSI escape) で表示し、視認性を確保する 🔵 *UX 標準*
- **NFR-203**: タイマー方式 (`timer30`) では残り秒数をリアルタイム表示し、ユーザーが「いつまで待てばよいか」を把握できるようにする 🔵 *UX 標準*

## Edge ケース

### エラー処理

- **EDGE-001**: `legacy init` 実行中に SIGINT (Ctrl+C) → メモリは Drop で zeroize、vault.pqd 無変更 🔵 *change-password と同パターン*
- **EDGE-002**: `legacy rotate` の再暗号化中に書き込み失敗 → vault.pqd.tmp を zeroize 削除、旧 vault.pqd 維持 🔵 *change-password と同パターン*
- **EDGE-003**: `legacy-access` の確認後、新 vault 生成中にディスクフル → vault.pqd.tmp 削除、旧 vault.pqd 維持 (= DESTROY 実行されず) 🔵 *安全側*
- **EDGE-004**: vault.toml `[legacy]` セクションが破損 (TOML エラー) → `DiaryError::Config("Invalid vault.toml [legacy]: ...")` エラー 🔵 *既存パターン*
- **EDGE-005**: `legacy set <ID>` で存在しない ID プレフィックス指定 → `Entry not found: {prefix}` エラー 🔵 *既存 show/delete と同*
- **EDGE-006**: `legacy set <ID>` で複数エントリにマッチ → `Multiple entries match prefix '{prefix}', please specify more characters` エラー 🔵 *既存 show/delete と同*

### 境界値

- **EDGE-101**: 空 vault (0 エントリ) で `legacy-access` → 確認通過後、空 vault.pqd を K_legacy で生成 (`No entries to inherit` メッセージ) 🔵 *妥当な動作*
- **EDGE-102**: 全エントリ INHERIT の vault で `legacy-access` → 全エントリを継承、削除は 0 件 🔵
- **EDGE-103**: 全エントリ DESTROY の vault で `legacy-access` → 0 件継承、全エントリ削除、空 vault 生成 🔵
- **EDGE-104**: `legacy-access` 実行後、骨梧者は同じ死後アクセスコードを通常の master password として vault を unlock できる。`[legacy] initialized = false` に戻るため、再度 `legacy-access` を実行した場合は `Legacy not initialized` で停止する 🔵 *Q1 確定 (K_legacy 残留) と新 vault 化の帰結*

### 後方互換性

- **EDGE-201**: 既存 Phase 1 vault (vault.toml に `[legacy]` セクション無し) で `legacy list` 実行 → `[legacy] initialized = false` 扱いで、全エントリは DESTROY としてリスト 🔵 *REQ-704*
- **EDGE-202**: 既存 Phase 1 vault のエントリレコード `legacyフラグ = 0x00`、`legacy鍵ブロック長 = 0` (S3 予約値) で正しく読み込める 🔵 *S3 で予約済み*

## 信頼性レベル分布

- 🔵 青信号: 全項目 (100%)
- 🟡 黄信号: 0
- 🔴 赤信号: 0

**品質評価**: 最高品質。PRD §7 が体系的に書かれており、設計判断もヒアリング 7 項目で確定。
