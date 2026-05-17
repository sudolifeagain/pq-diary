# S12 デジタル遺言 CLI コマンド仕様

**作成日**: 2026-05-17
**関連設計**: [architecture.md](architecture.md), [schema.md](schema.md)
**信頼性**: 全項目🔵

---

## サブコマンド一覧 (S12 で実装)

### 1. `pq-diary legacy init` 🔵

**説明**: 死後アクセスコードを初回設定し、確認方式を選択する。

**clap**:
```rust
LegacyCommands::Init
```

**動作**:
1. `--claude` チェック → ブロック
2. vault.toml `[legacy] initialized` チェック → 既に true なら `Already initialized` エラー
3. master password TTY 取得 → vault unlock
4. legacy code TTY 取得 ("Legacy code: ") → 確認 ("Confirm legacy code: ")
5. 不一致 / 空チェック / master と同一なら警告
6. 確認方式選択 prompt:
   ```
   Choose confirmation mode for legacy-access:
     [1] timer30 (default) — 30-second timer + y/N
     [2] yn               — immediate y/N
     [3] phrase           — type 'DESTROY ALL' to confirm
   Selection [1]:
   ```
7. K_legacy 導出、K_legacy 用 verification token を生成
8. vault.toml に `[legacy] initialized=true, destroy_confirmation=<mode>, verification_iv_b64, verification_ct_b64` 書き込み (アトミック)
9. `Legacy code initialized. Confirmation mode: {mode}` 表示

**出力サンプル**:
```
$ pq-diary legacy init
Master password: ***
Legacy code: ***
Confirm legacy code: ***
Choose confirmation mode for legacy-access:
  [1] timer30 (default) — 30-second timer + y/N
  [2] yn               — immediate y/N
  [3] phrase           — type 'DESTROY ALL' to confirm
Selection [1]: 1
Legacy code initialized. Confirmation mode: timer30
```

---

### 2. `pq-diary legacy set <ID> --inherit | --destroy` 🔵

**説明**: 個別エントリの遺言フラグを設定する。

**clap**:
```rust
LegacyCommands::Set {
    id: String,            // 必須、ID プレフィックス
    #[arg(long, conflicts_with = "destroy")]
    inherit: bool,
    #[arg(long, conflicts_with = "inherit")]
    destroy: bool,
}
```

**動作**:
1. `--claude` チェック → ブロック
2. vault.toml `[legacy] initialized` チェック → false なら `legacy init を先に実行してください`
3. master password 取得 + unlock
4. `--inherit` の場合は legacy code も取得
5. ID プレフィックスでエントリ検索
6. 該当エントリの legacy フラグを変更:
   - `--inherit`: legacy_flag=0x01、エントリ平文 JSON を K_legacy で AES-GCM 暗号化 → legacy_key_block 追加
   - `--destroy`: legacy_flag=0x00、legacy_key_block 削除 (長さ 0)
7. エントリレコードをアトミック書き戻し (既存 update_entry パターン)
8. メッセージ表示:
   - `Entry {prefix} set to INHERIT` / `Entry {prefix} set to DESTROY`

**異常系**:
- `--inherit` も `--destroy` も指定なし: `Error: --inherit or --destroy is required`
- 両方指定 (clap conflicts_with で防止): `Error: --inherit cannot be used with --destroy`
- ID 不一致: `Error: Entry not found: {prefix}`
- ID 複数マッチ: `Error: Multiple entries match prefix '{prefix}'`

---

### 3. `pq-diary legacy list` 🔵

**説明**: 全エントリの遺言設定一覧を表示する。

**clap**:
```rust
LegacyCommands::List
```

**動作**:
1. `--claude` チェック → ブロック
2. master password 取得 + unlock
3. 全エントリ取得 → INHERIT グループ + DESTROY グループに分類
4. 各グループ内 updated_at 降順
5. Summary 表示

**出力サンプル**:
```
$ pq-diary legacy list
Master password: ***

=== INHERIT (3 entries) ===
3c6b775f  2026-05-17  家族との思い出
08a9e139  2026-04-30  父への手紙
d65004a8  2026-04-15  遺品リスト

=== DESTROY (5 entries) ===
12345abc  2026-05-10  仕事の愚痴
fedcba98  2026-05-05  秘密のメモ
...

Summary: INHERIT 3 entries / DESTROY 5 entries / Total 8
```

---

### 4. `pq-diary legacy rotate` 🔵

**説明**: 死後アクセスコードを変更し、全 INHERIT エントリを新コードで再暗号化する。

**clap**:
```rust
LegacyCommands::Rotate
```

**動作** (change-password と同パターン):
1. `--claude` チェック
2. `[legacy] initialized` チェック
3. master + old legacy code 取得 → 両方検証 (master で unlock + old legacy で `[legacy]` verification token 突合)
4. new legacy code TTY 取得 × 2 → 確認入力
5. 不一致 / 空 / 旧と同一 (警告のみ) チェック
6. K_legacy_new 導出
7. 全 INHERIT エントリの legacy_key_block と `[legacy]` verification token を K_legacy_new で再暗号化
8. vault.pqd.tmp + rename でアトミック差し替え
9. `Legacy code rotated successfully ({N} INHERIT entries re-encrypted)` 表示

---

### 5. `pq-diary legacy-access` 🔵 (不可逆操作)

**説明**: 死後アクセスを実行する。INHERIT エントリのみを K_legacy で復号して新 vault に保存、DESTROY エントリは zeroize 削除。

**clap**:
```rust
Commands::LegacyAccess
```

**動作**:
1. `--claude` チェック → ブロック (Argon2 導出より前、NFR-104)
2. vault.toml `[legacy] initialized = true` チェック → false なら `Legacy not initialized`
3. legacy code TTY 取得 ("Legacy code: ")
4. K_legacy 導出 + 検証 (`vault.toml [legacy]` の verification token 突合)
5. 不正なら `Invalid legacy code` で停止、vault.pqd 無変更
6. vault.toml `[legacy] destroy_confirmation` の値に従って確認 UI:
   - `timer30`: 警告 + 30 秒タイマー (残り秒数リアルタイム表示) + y/N
   - `yn`: 警告 + 即時 y/N
   - `phrase`: 警告 + コンフィルフレーズ入力 (`DESTROY ALL`)
7. ユーザーキャンセル → `キャンセルしました` で停止
8. 確認通過 → 全エントリスキャン:
   - INHERIT → K_legacy で legacy_key_block を復号 → エントリ平文を新 vault バッファに保持
   - DESTROY → エントリレコードを zeroize (旧 vault.pqd 上は最終的に消える)
9. 新 vault.pqd を K_legacy で再構築:
   - ヘッダー: kdf_salt = 元の legacy_salt、verification_token = K_legacy で再生成、新規 KEM/DSA seed = K_legacy で暗号化
   - エントリ: INHERIT のみ、各エントリの legacy_flag = 0x00 にリセット (新 vault では K_legacy がマスター鍵)
   - vault.toml: `[legacy] initialized=false` に戻し、verification token を削除 (以後は通常 vault として扱う)
10. vault.pqd.tmp + rename でアトミック差し替え
11. `Legacy access complete. {N} entries inherited, {M} entries destroyed.` 表示

**出力サンプル (timer30 モード)**:
```
$ pq-diary legacy-access
Legacy code: ***

============================================================
  WARNING: THIS OPERATION IS IRREVERSIBLE
  - All INHERIT entries will be inherited.
  - All DESTROY entries (and unconfigured entries) will be
    PERMANENTLY ERASED with zeroize-overwrite.
============================================================
Waiting 30 seconds before allowing confirmation...
  29 seconds remaining...
  28 seconds remaining...
  ...
  0 seconds. Proceed? [y/N]: y
Legacy access complete. 3 entries inherited, 5 entries destroyed.
```

---

## hide 解除 (S10 の hide 化を逆転) 🔵

### Before (S10〜S11)
```rust
#[command(hide = true)]
Legacy { subcommand: LegacyCommands },
#[command(hide = true)]
LegacyAccess,
```

### After (S12)
```rust
Legacy {
    #[command(subcommand)]
    subcommand: LegacyCommands,
},
LegacyAccess,
```

`pq-diary --help` に `legacy` と `legacy-access` が表示される。

## dispatch 変更 🔵

### Before
```rust
Commands::Legacy { subcommand } => match subcommand {
    LegacyCommands::Init => not_implemented("legacy init", "Phase 2"),
    LegacyCommands::Rotate => not_implemented("legacy rotate", "Phase 2"),
    LegacyCommands::Set => not_implemented("legacy set", "Phase 2"),
    LegacyCommands::List => not_implemented("legacy list", "Phase 2"),
},
Commands::LegacyAccess => not_implemented("legacy-access", "Phase 2"),
```

### After
```rust
Commands::Legacy { subcommand } => match subcommand {
    LegacyCommands::Init => commands::cmd_legacy_init(cli),
    LegacyCommands::Rotate => commands::cmd_legacy_rotate(cli),
    LegacyCommands::Set { id, inherit, destroy } =>
        commands::cmd_legacy_set(cli, id, *inherit, *destroy),
    LegacyCommands::List => commands::cmd_legacy_list(cli),
},
Commands::LegacyAccess => commands::cmd_legacy_access(cli),
```

## smoke test スクリプト追加候補 (S12 で追加) 🔵

`ci/smoke-test.sh` / `.ps1` に以下チェック追加:
1. ヘルプ表示に `legacy` / `legacy-access` が出る (= hide 解除確認)
2. `pq-diary legacy init --help` exit 0
3. `pq-diary legacy --help` exit 0 (subcommand 一覧表示)
4. E2E: init + legacy init + new "x" + legacy set <id> --inherit + legacy list → OK
5. (legacy-access の E2E は不可逆操作のため smoke では避ける、別の単体テストで)

---

## 信頼性

🔵 100%

## 関連

- [architecture.md](architecture.md)
- [types.rs](types.rs)
- [schema.md](schema.md)
- [dataflow.md](dataflow.md)
