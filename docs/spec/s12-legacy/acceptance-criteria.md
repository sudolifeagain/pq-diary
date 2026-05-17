# S12 デジタル遺言 受け入れ基準

**作成日**: 2026-05-17
**関連要件**: [requirements.md](requirements.md)

**【信頼性レベル】**: 全項目🔵

---

## REQ-101〜111: `legacy init` 🔵

### 正常系
- [ ] **TC-101-01**: クリーンな vault (`legacy init` 未実行) で実行 → vault.toml `[legacy] initialized=true`、`destroy_confirmation="timer30"` (デフォルト) 🔵
- [ ] **TC-101-02**: `timer30` 選択時、vault.toml に `destroy_confirmation="timer30"` 保存 🔵
- [ ] **TC-101-03**: `yn` 選択時、`destroy_confirmation="yn"` 保存 🔵
- [ ] **TC-101-04**: `phrase` 選択時、`destroy_confirmation="phrase"` 保存 🔵
- [ ] **TC-101-05**: 完了メッセージ `Legacy code initialized. Confirmation mode: {mode}` 表示 🔵

### 異常系
- [ ] **TC-101-E01**: 既に `legacy init` 完了状態で再実行 → `Already initialized. Use 'legacy rotate' to change the code` (REQ-111) 🔵
- [ ] **TC-101-E02**: 死後アクセスコード 2 回不一致 → `Passwords do not match` (REQ-103) 🔵
- [ ] **TC-101-E03**: 死後アクセスコード空 → `Legacy code must not be empty` (REQ-104) 🔵
- [ ] **TC-101-E04**: マスターパスワード不正 → `Vault unlock failed` (REQ-101 の検証) 🔵
- [ ] **TC-101-E05**: --claude フラグ付きで実行 → `legacy operations are not permitted with --claude` (REQ-601) 🔵

### 境界値
- [ ] **TC-101-B01**: 死後アクセスコードがマスターパスワードと同一 → 警告表示しつつ続行 (REQ-105) 🔵
- [ ] **TC-101-B02**: NFR-001 達成 (< 5 秒、fast_params 使用) 🔵

---

## REQ-201〜205: `legacy set` 🔵

### 正常系
- [ ] **TC-201-01**: 既存 entry に `--inherit` → legacy フラグ 0x00 → 0x01、legacy 鍵ブロック追加 (K_entry を K_legacy で AES-GCM 暗号化) 🔵
- [ ] **TC-201-02**: INHERIT エントリに `--destroy` → フラグ 0x01 → 0x00、legacy 鍵ブロック削除 (長さ 0) 🔵
- [ ] **TC-201-03**: `--inherit` 後、entry を再度 show/edit/list で読める (K_master で復号できる経路は影響なし) 🔵
- [ ] **TC-201-04**: `--inherit` 後、別の死後アクセスコード (誤) で legacy 鍵ブロックを復号試行 → AEAD タグ失敗 (秘匿性) 🔵

### 異常系
- [ ] **TC-201-E01**: `--inherit` と `--destroy` 同時指定 → clap conflict エラー (REQ-205) 🔵
- [ ] **TC-201-E02**: 存在しない ID プレフィックス → `Entry not found: {prefix}` (EDGE-005) 🔵
- [ ] **TC-201-E03**: 複数 entry にマッチ → `Multiple entries match prefix ...` (EDGE-006) 🔵
- [ ] **TC-201-E04**: `legacy init` 未完了で実行 → `legacy init を先に実行してください` (REQ-203) 🔵
- [ ] **TC-201-E05**: --claude フラグ付き → ブロック (REQ-601) 🔵

### 境界値
- [ ] **TC-201-B01**: NFR-002 達成 (< 500ms、1 エントリ更新) 🔵

---

## REQ-301〜303: `legacy list` 🔵

### 正常系
- [ ] **TC-301-01**: 3 INHERIT + 5 DESTROY の vault で実行 → INHERIT グループ先、DESTROY グループ後、各 updated_at 降順 🔵
- [ ] **TC-301-02**: 末尾に `Summary: INHERIT 3 entries / DESTROY 5 entries / Total 8` 表示 🔵
- [ ] **TC-301-03**: 空 vault → `Summary: INHERIT 0 entries / DESTROY 0 entries / Total 0` のみ表示 🔵
- [ ] **TC-301-04**: 全 INHERIT vault → DESTROY グループは空、INHERIT グループのみ表示 🔵

### 異常系
- [ ] **TC-301-E01**: --claude フラグ付き → ブロック (REQ-601) 🔵
- [ ] **TC-301-E02**: master password 不正 → `Vault unlock failed` 🔵

---

## REQ-401〜405: `legacy rotate` 🔵

### 正常系
- [ ] **TC-401-01**: 5 INHERIT エントリで rotate → 5 件全ての legacy 鍵ブロックが K_legacy_new で暗号化 (旧 K_legacy では復号失敗) 🔵
- [ ] **TC-401-02**: rotate 後、master password で全 entry が読める (K_master 系は影響なし) 🔵
- [ ] **TC-401-03**: rotate 後、新 legacy code で `legacy-access` 実行成功、旧 legacy code では `Invalid legacy code` 🔵
- [ ] **TC-401-04**: 完了メッセージ `Legacy code rotated successfully (5 INHERIT entries re-encrypted)` 表示 🔵

### 異常系
- [ ] **TC-401-E01**: master password 不正 → vault.pqd 無変更 🔵
- [ ] **TC-401-E02**: 旧 legacy code 不正 → vault.pqd 無変更 🔵
- [ ] **TC-401-E03**: 新 legacy code 2 回不一致 → vault.pqd 無変更 🔵
- [ ] **TC-401-E04**: rotate 中にディスクフル → vault.pqd.tmp 削除、旧 vault.pqd 維持 (EDGE-002) 🔵
- [ ] **TC-401-E05**: --claude フラグ → ブロック (REQ-601) 🔵

### 境界値
- [ ] **TC-401-B01**: NFR-003 達成 (< 30 秒、100 INHERIT エントリ) 🔵
- [ ] **TC-401-B02**: INHERIT エントリ 0 件で rotate → K_legacy 鍵だけ更新、エントリ書き換え 0 件 🔵

---

## REQ-501〜508: `legacy-access` 🔵

### 正常系
- [ ] **TC-501-01**: INHERIT 3 + DESTROY 2 vault で実行、確認 y 入力 → 新 vault に INHERIT 3 件のみ、DESTROY 2 件は zeroize 削除 🔵
- [ ] **TC-501-02**: 新 vault は K_legacy で再暗号化、`legacy-access` 後の vault unlock は legacy code で可能 🔵
- [ ] **TC-501-03**: 新 vault.pqd ヘッダーの kdf_salt は元のまま (K_legacy 導出用)、verification_token は K_legacy で再生成 🔵
- [ ] **TC-501-04**: 完了メッセージ `Legacy access complete. 3 entries inherited, 2 entries destroyed.` 表示 🔵
- [ ] **TC-501-05**: legacy-access 後、骨梧者が同じ legacy code で再度 `legacy-access` 実行 → 元 INHERIT のみが見え、destroy は 0 件 (冪等、EDGE-104) 🔵

### 異常系
- [ ] **TC-501-E01**: legacy code 不正 → `Invalid legacy code`、vault.pqd 無変更 (REQ-503) 🔵
- [ ] **TC-501-E02**: `[legacy] initialized = false` で実行 → `Legacy not initialized. Use 'legacy init' first.` 🔵
- [ ] **TC-501-E03**: 確認プロンプトで N 入力 → `キャンセルしました`、vault.pqd 無変更 (REQ-505) 🔵
- [ ] **TC-501-E04**: phrase モードで間違ったフレーズ入力 → キャンセル扱い 🔵
- [ ] **TC-501-E05**: 新 vault 生成中にディスクフル → tmp 削除、旧 vault.pqd 維持 (= DESTROY 未実行、EDGE-003) 🔵
- [ ] **TC-501-E06**: --claude フラグ → Argon2 導出前にブロック (NFR-104) 🔵

### 境界値
- [ ] **TC-501-B01**: 空 vault → `No entries to inherit`、空 vault.pqd を K_legacy で生成 (EDGE-101) 🔵
- [ ] **TC-501-B02**: 全 INHERIT → 0 件削除、全件継承 (EDGE-102) 🔵
- [ ] **TC-501-B03**: 全 DESTROY → 0 件継承、全件削除、空 vault 生成 (EDGE-103) 🔵
- [ ] **TC-501-B04**: NFR-004 達成 (< 60 秒、1000 エントリ) 🔵

### 確認方式別テスト

- [ ] **TC-504-01**: `destroy_confirmation=timer30` → 30 秒タイマー表示 + 残り秒数リアルタイム更新 + 0 で y/N (NFR-203) 🔵
- [ ] **TC-504-02**: `destroy_confirmation=yn` → 警告即時 + y/N 🔵
- [ ] **TC-504-03**: `destroy_confirmation=phrase` → 警告 + `Type 'DESTROY ALL' to confirm:` プロンプト、完全一致のみ通過 🔵

---

## REQ-601: `--claude` ブロック 🔵
- [ ] **TC-601-01〜05**: 全 legacy* / legacy-access コマンドで --claude 時にブロック (REQ-601) 🔵
- [ ] **TC-NFR-104-01**: ブロックは Argon2 鍵導出 (= ms 単位の時間) より前に発生 (timing test 任意) 🔵

---

## REQ-701〜704: vault.toml [legacy] セクション 🔵

- [ ] **TC-701-01**: `legacy init` 後、vault.toml に `[legacy]` セクション存在 🔵
- [ ] **TC-702-01**: `initialized: true` 値設定 🔵
- [ ] **TC-703-01**: `destroy_confirmation` 値が選択値と一致 🔵
- [ ] **TC-704-01**: 既存 Phase 1 vault (`[legacy]` セクション無し) で `legacy list` 実行 → `initialized=false` 扱い (EDGE-201) 🔵

---

## REQ-801〜802: CLI スケルトン unhide 🔵
- [ ] **TC-801-01**: `pq-diary --help` 出力に `legacy` / `legacy-access` が表示される 🔵
- [ ] **TC-802-01**: `pq-diary legacy init --help` exit 0、説明文表示 🔵
- [ ] **TC-802-02**: 残存 `not_implemented("legacy ...")` がない (全 dispatch が `cmd_legacy_*` に切り替わっている) 🔵

---

## サマリー

| カテゴリ | 正常系 | 異常系 | 境界値 | 合計 |
|---|---|---|---|---|
| init (REQ-1xx) | 5 | 5 | 2 | 12 |
| set (REQ-2xx) | 4 | 5 | 1 | 10 |
| list (REQ-3xx) | 4 | 2 | 0 | 6 |
| rotate (REQ-4xx) | 4 | 5 | 2 | 11 |
| access (REQ-5xx) | 5 | 6 | 4 | 15 |
| 確認方式 (REQ-504) | 3 | 0 | 0 | 3 |
| --claude (REQ-6xx) | 5 | 1 | 0 | 6 |
| vault.toml (REQ-7xx) | 3 | 1 | 0 | 4 |
| unhide (REQ-8xx) | 3 | 0 | 0 | 3 |
| **合計** | **36** | **25** | **9** | **70** |

### 信頼性
- 🔵: 70 件 (100%)
- 🟡: 0
- 🔴: 0
