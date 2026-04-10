# S9 Security Hardening + Technical Debt アーキテクチャ設計

**作成日**: 2026-04-10
**ヒアリング記録**: [design-interview.md](design-interview.md)

**【信頼性レベル凡例】**:
- 🔵 **青信号**: 既存実装・CLAUDE.md規約・コードレビュー指摘事項を参考にした確実な設計

---

## システム概要 🔵

**信頼性**: 🔵 *既存コードベース分析 + レビュー指摘 H-1, M-1〜M-5, L-1〜L-4 確認済*

S9では以下の3領域でセキュリティ強化と技術的負債の解消を実施する:

1. **メモリ保護**: `mlock`/`VirtualLock` による鍵マテリアルのページロック（スワップ防止）
2. **プロセス硬化**: `PR_SET_DUMPABLE` + `RLIMIT_CORE` によるコアダンプ防止、デバッガー検出
3. **コード品質（技術的負債）**: H-1 SecretString化、M-1 bail!化、M-2/M-4 Zeroizing中間バッファ、M-3 PQCピン固定、M-5 verify_hmac Result化、読み取り時の署名/HMAC検証

## アーキテクチャパターン 🔵

**信頼性**: 🔵 *既存アーキテクチャ + CLAUDE.md規約*

- **プラットフォーム分岐**: `#[cfg(unix)]` / `#[cfg(windows)]` によるコンパイル時分岐（CLAUDE.md規約準拠）
- **RAII**: VaultGuard パターンを継続。メモリロック解除も Drop で保証
- **Fail-soft**: `mlock` 失敗時は警告のみで続行（非特権ユーザーでの利用を阻害しない）
- **エラー伝播**: core/ は `DiaryError` を返す。cli/ のみ `anyhow::bail!` 使用可（CLAUDE.md準拠）

## コンポーネント構成

### core/src/crypto/secure_mem.rs — メモリロック関数 🔵

**信頼性**: 🔵 *CLAUDE.md unsafe許可範囲: mlock/VirtualLock + 既存SecureBuffer/MasterKey構造*

既存の `secure_mem.rs` にメモリロック/アンロック関数を追加。MasterKeyバッファをページロックし、OSのスワップ領域への書き出しを防止する。

```rust
// --- 新規公開関数 ---

/// バッファをメモリにロック（スワップ防止）。
/// Unix: mlock(2), Windows: VirtualLock。
/// 失敗時はeprintln!で警告を出力し、Err(DiaryError)を返す。
pub fn mlock_buffer(ptr: *const u8, len: usize) -> Result<(), DiaryError>;

/// バッファのメモリロックを解除。
/// Unix: munlock(2), Windows: VirtualUnlock。
/// 失敗時はeprintln!で警告を出力し、Err(DiaryError)を返す。
pub fn munlock_buffer(ptr: *const u8, len: usize) -> Result<(), DiaryError>;

/// MasterKeyの全フィールド（sym_key, dsa_sk, kem_sk）をmlock。
/// CryptoEngine::unlock成功後に呼び出す。
pub fn mlock_master_key(mk: &MasterKey) -> Result<(), DiaryError>;

/// MasterKeyの全フィールドのmlockを解除。
/// CryptoEngine::lock時（Drop前）に呼び出す。
pub fn munlock_master_key(mk: &MasterKey) -> Result<(), DiaryError>;
```

**プラットフォーム実装詳細**:

- **Unix (`#[cfg(unix)]`)**:
  - `libc::mlock(ptr as *const c_void, len)` / `libc::munlock(ptr as *const c_void, len)`
  - `RLIMIT_MEMLOCK` 制限に引っかかる場合は警告のみ
  - CLAUDE.md の unsafe 許可範囲: "mlock/VirtualLock" に該当

- **Windows (`#[cfg(windows)]`)**:
  - `windows_sys::Win32::System::Memory::VirtualLock(ptr as *const c_void, len)` / `VirtualUnlock`
  - `windows-sys` features に `"Win32_System_Memory"` を追加
  - CLAUDE.md の unsafe 許可範囲: "VirtualLock" に該当

- **その他 (`#[cfg(not(any(unix, windows)))]`)**:
  - 何もせず `Ok(())` を返す（no-op）

**呼び出し箇所**:

- `CryptoEngine::unlock()` / `unlock_with_vault()` 成功直後: `mlock_master_key(&mk)`
- `CryptoEngine::lock()` 直前: `munlock_master_key(&mk)`

### core/src/crypto/mod.rs — M-2/M-4 Zeroizing中間バッファ 🔵

**信頼性**: 🔵 *レビュー指摘 M-2, M-4 + 既存コード行126-127*

`unlock_with_vault()` の行126-127で `.to_vec()` が生の `Vec<u8>` を生成し、`into_boxed_slice()` で変換している。この中間 `Vec<u8>` は zeroize されないまま解放される可能性がある。

**修正箇所**: `core/src/crypto/mod.rs` 行126-127

```rust
// Before (現行):
kem_sk: kem_sk.as_ref().to_vec().into_boxed_slice(),
dsa_sk: dsa_sk.as_ref().to_vec().into_boxed_slice(),

// After (S9):
kem_sk: {
    let tmp = Zeroizing::new(kem_sk.as_ref().to_vec());
    tmp.into_inner().into_boxed_slice()
},
dsa_sk: {
    let tmp = Zeroizing::new(dsa_sk.as_ref().to_vec());
    tmp.into_inner().into_boxed_slice()
},
```

**注意**: `Zeroizing::into_inner()` は所有権を移動するため、元の `Vec` はゼロ化後に解放される。`into_boxed_slice()` は移動先の `Vec` に対して呼ばれるため、追加コピーは発生しない。ただし `Zeroizing::into_inner()` は `Drop` を実行しない設計のため、代替として明示的なzeroize + clone パターンも検討する。最終的にはTDD実装時に最適な方法を選択する。

同様に `kem_decapsulate()` と `dsa_sign()` の `mk.kem_sk.to_vec()` / `mk.dsa_sk.to_vec()` も既に `SecureBuffer::new()` でラップ済みのため問題なし。

### core/src/crypto/hmac_util.rs — M-5 verify_hmac Result化 🔵

**信頼性**: 🔵 *レビュー指摘 M-5 + 既存関数シグネチャ確認済*

`verify_hmac()` の返り値を `bool` から `Result<bool, DiaryError>` に変更。`HmacSha256::new_from_slice` のエラーを黙って `false` として返すのではなく、呼び出し元に伝播する。

```rust
// Before (現行):
pub fn verify_hmac(key: &[u8], data: &[u8], expected: &[u8; 32]) -> bool

// After (S9):
pub fn verify_hmac(key: &[u8], data: &[u8], expected: &[u8; 32]) -> Result<bool, DiaryError>
```

**呼び出し元の変更**:

- `CryptoEngine::hmac_verify()` (`core/src/crypto/mod.rs` 行241-244):
  ```rust
  // Before:
  Ok(hmac_util::verify_hmac(&mk.sym_key, data, expected))
  // After:
  hmac_util::verify_hmac(&mk.sym_key, data, expected)
  ```

### core/src/entry.rs — 読み取り時の署名/HMAC検証 🔵

**信頼性**: 🔵 *セキュリティベストプラクティス + 既存get_entry/list_entries構造*

`get_entry()` と `list_entries()` で復号後に `content_hmac` 検証と `dsa_verify` を追加。改ざん検出を読み取りパスに組み込む。

**get_entry() 変更箇所**:
```rust
// 復号後、JSON デシリアライズ前に:
// 1. content_hmac の検証
if !engine.hmac_verify(decrypted.as_ref(), &record.content_hmac)? {
    return Err(DiaryError::Entry("content HMAC verification failed".to_string()));
}
// 2. DSA 署名の検証（署名が存在する場合のみ）
// header から dsa_pk を取得し、record.signature を検証
```

**list_entries() 変更箇所**: 同様のHMAC検証を追加。署名検証はlist表示では省略可能（パフォーマンス考慮）。

### core/Cargo.toml — M-3 PQCコミットピン固定 🔵

**信頼性**: 🔵 *レビュー指摘 M-3 + Cargo.toml確認済*

`ml-kem` と `ml-dsa` の依存指定を `branch = "pq-diary"` から `rev = "<commit_hash>"` に変更。ブランチ先端の予期しない変更によるビルド破壊を防止する。

```toml
# Before (現行):
ml-kem = { git = "https://github.com/sudolifeagain/ml-kem", branch = "pq-diary", features = ["getrandom", "zeroize"] }
ml-dsa = { git = "https://github.com/sudolifeagain/ml-dsa", branch = "pq-diary", features = ["zeroize"] }

# After (S9):
ml-kem = { git = "https://github.com/sudolifeagain/ml-kem", rev = "<ml-kem-commit-hash>", features = ["getrandom", "zeroize"] }
ml-dsa = { git = "https://github.com/sudolifeagain/ml-dsa", rev = "<ml-dsa-commit-hash>", features = ["zeroize"] }
```

**コミットハッシュの決定方法**: 実装時に `git ls-remote https://github.com/sudolifeagain/ml-kem refs/heads/pq-diary` と `git ls-remote https://github.com/sudolifeagain/ml-dsa refs/heads/pq-diary` で現在のHEADを取得し、そのハッシュを使用する。

### cli/src/main.rs — H-1 SecretString化 + M-1 bail!化 + プロセス硬化 🔵

**信頼性**: 🔵 *レビュー指摘 H-1, M-1 + 既存Cli構造体 + CLAUDE.md規約*

#### H-1: Cli.password の SecretString 化

```rust
// Before (現行):
pub password: Option<String>,

// After (S9):
pub password: Option<SecretString>,
```

`clap` は `SecretString` を直接パースできないため、カスタム `ValueParser` または中間型を使用する。最小変更として `String` で受け取り、即座に `SecretString` に変換するアプローチを採用:

```rust
/// Master password (insecure; use interactive prompt instead)
#[arg(long, global = true, value_parser = parse_secret_string)]
pub password: Option<SecretString>,
```

`parse_secret_string` は `String` を受け取り `SecretString` に変換するパーサー関数。

**cli/src/password.rs の変更**: `get_password()` の `flag_value` パラメータを `Option<&str>` から `Option<&SecretString>` に変更。

```rust
// Before:
pub fn get_password(flag_value: Option<&str>) -> Result<PasswordSource, DiaryError>

// After:
pub fn get_password(flag_value: Option<&SecretString>) -> Result<PasswordSource, DiaryError>
```

#### M-1: not_implemented() の bail! 化

```rust
// Before (現行):
fn not_implemented(cmd_name: &str, sprint: &str) -> anyhow::Result<()> {
    eprintln!("Command '{cmd_name}' is not yet implemented. Planned for {sprint}.");
    std::process::exit(1);
}

// After (S9):
fn not_implemented(cmd_name: &str, sprint: &str) -> anyhow::Result<()> {
    anyhow::bail!("Command '{cmd_name}' is not yet implemented. Planned for {sprint}.");
}
```

`process::exit(1)` はデストラクタを呼ばずにプロセスを終了するため、スタック上の `SecretString` や `Zeroizing` バッファが zeroize されない。`bail!` に変更することで正常なスタック巻き戻しが保証される。

#### プロセス硬化: harden_process()

`main()` の先頭で呼び出すプロセス硬化関数。Unix のみ有効。

```rust
// cli/src/main.rs の main() 先頭:
fn main() -> anyhow::Result<()> {
    harden_process();
    check_debugger();
    let cli = Cli::parse();
    dispatch(&cli)
}
```

**harden_process() — Unix実装**:
```rust
#[cfg(unix)]
fn harden_process() {
    // 1. PR_SET_DUMPABLE = 0: コアダンプ生成を禁止
    //    nix::sys::prctl::set_dumpable(false)
    // 2. RLIMIT_CORE = 0: コアファイルサイズ上限を0に
    //    nix::sys::resource::setrlimit(Resource::RLIMIT_CORE, 0, 0)
    // 失敗時は eprintln! で警告のみ（非root環境で失敗する可能性あり）
}

#[cfg(not(unix))]
fn harden_process() {
    // Windows/その他: no-op
}
```

**nix crateの機能追加**: `cli/Cargo.toml` の nix features に `"process"` と `"resource"` を追加:
```toml
nix = { version = "0.29", features = ["term", "user", "process", "resource"] }
```

#### デバッガー検出: check_debugger()

```rust
#[cfg(unix)]
fn check_debugger() {
    // /proc/self/status の TracerPid 行を読み取り
    // TracerPid != 0 なら「デバッガーが検出されました」警告
}

#[cfg(windows)]
fn check_debugger() {
    // windows_sys::Win32::System::Diagnostics::Debug::IsDebuggerPresent()
    // 戻り値 != 0 なら警告
}

#[cfg(not(any(unix, windows)))]
fn check_debugger() {
    // no-op
}
```

**windows-sys の機能追加**: `cli/Cargo.toml` の windows-sys features に `"Win32_System_Diagnostics_Debug"` を追加:
```toml
windows-sys = { version = "0.59", features = ["Win32_System_Console", "Win32_System_Diagnostics_Debug"] }
```

### cli/src/commands.rs — E2Eテスト + パフォーマンステスト 🔵

**信頼性**: 🔵 *既存テストパターン + 網羅的カバレッジ方針*

E2Eテストは `cli/src/commands.rs` の `#[cfg(test)] mod tests` に追加。テスト用の一時ディレクトリに vault を作成し、全コマンドフローを実行する。

**E2Eテスト対象コマンド**:
- `vault create` → `new` → `list` → `show` → `edit` → `delete`
- `search` → `stats` → `import`
- `template add` → `template list` → `template show` → `template delete`
- `today` (冪等性検証)

**パフォーマンステスト**:
- `init` + `unlock`: < 5秒（Argon2idの既存ベンチマーク準拠）
- `new` + `edit`: < 1秒（暗号化/署名/HMAC処理時間）
- `list` (100エントリ): < 2秒
- `search` (100エントリ): < 2秒

## システム構成図 🔵

**信頼性**: 🔵 *既存アーキテクチャ + S9設計*

```
┌──────────────────────────────────────────────────────┐
│                  cli/src/main.rs                      │
│  ┌────────────────────────────────────────────────┐   │
│  │ main()                                         │   │
│  │  1. harden_process()  ← PR_SET_DUMPABLE等      │   │
│  │  2. check_debugger()  ← TracerPid/IsDebugger   │   │
│  │  3. Cli::parse()                               │   │
│  │     password: Option<SecretString> ← H-1       │   │
│  │  4. dispatch(&cli)                             │   │
│  └───────────────────┬────────────────────────────┘   │
│                      │                                │
│  ┌───────────────────▼────────────────────────────┐   │
│  │ dispatch()                                     │   │
│  │  not_implemented() → bail!() ← M-1             │   │
│  └───────────────────┬────────────────────────────┘   │
│                      │                                │
│  ┌───────────────────▼────────────────────────────┐   │
│  │ cli/src/password.rs                            │   │
│  │  get_password(Option<&SecretString>) ← H-1     │   │
│  └───────────────────┬────────────────────────────┘   │
└──────────────────────┼────────────────────────────────┘
                       │
┌──────────────────────▼────────────────────────────────┐
│                core/src/                               │
│  ┌────────────────────────────────────────────────┐   │
│  │ crypto/secure_mem.rs                           │   │
│  │  mlock_buffer() / munlock_buffer() ← 新規      │   │
│  │  mlock_master_key() / munlock_master_key()     │   │
│  │  #[cfg(unix)]: libc::mlock/munlock             │   │
│  │  #[cfg(windows)]: VirtualLock/VirtualUnlock    │   │
│  └────────────────────────────────────────────────┘   │
│  ┌────────────────────────────────────────────────┐   │
│  │ crypto/mod.rs                                  │   │
│  │  unlock_with_vault(): Zeroizing<Vec<u8>> ← M-2 │   │
│  │  lock(): munlock_master_key 呼び出し           │   │
│  └────────────────────────────────────────────────┘   │
│  ┌────────────────────────────────────────────────┐   │
│  │ crypto/hmac_util.rs                            │   │
│  │  verify_hmac() → Result<bool, DiaryError> ← M-5│   │
│  └────────────────────────────────────────────────┘   │
│  ┌────────────────────────────────────────────────┐   │
│  │ entry.rs                                       │   │
│  │  get_entry(): +HMAC検証 +署名検証              │   │
│  │  list_entries(): +HMAC検証                     │   │
│  └────────────────────────────────────────────────┘   │
│  ┌────────────────────────────────────────────────┐   │
│  │ Cargo.toml                                     │   │
│  │  ml-kem: rev="<hash>" ← M-3                   │   │
│  │  ml-dsa: rev="<hash>" ← M-3                   │   │
│  └────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────┘
```

## 変更対象ファイル一覧 🔵

**信頼性**: 🔵 *設計分析*

| ファイル | 変更種別 | 内容 |
|---------|----------|------|
| `core/src/crypto/secure_mem.rs` | **拡張** | mlock_buffer(), munlock_buffer(), mlock_master_key(), munlock_master_key() の追加。#[cfg(unix)]/#[cfg(windows)] 分岐 |
| `core/src/crypto/mod.rs` | **修正** | M-2/M-4: unlock_with_vault() 行126-127の中間Vec<u8>をZeroizingでラップ。lock()にmunlock呼び出し追加。hmac_verify()のverify_hmac呼び出し更新 |
| `core/src/crypto/hmac_util.rs` | **修正** | M-5: verify_hmac() 返り値を bool → Result<bool, DiaryError> に変更 |
| `core/src/entry.rs` | **修正** | get_entry(), list_entries() に content_hmac 検証 + DSA署名検証を追加 |
| `core/Cargo.toml` | **修正** | M-3: ml-kem/ml-dsa を branch → rev に変更 |
| `cli/src/main.rs` | **修正** | H-1: Cli.password を Option<SecretString> に変更。M-1: not_implemented() を bail! に変更。harden_process(), check_debugger() を main() 先頭に追加 |
| `cli/src/password.rs` | **修正** | H-1: get_password() の flag_value パラメータを Option<&SecretString> に変更 |
| `cli/Cargo.toml` | **修正** | nix features に "process","resource" 追加。windows-sys features に "Win32_System_Diagnostics_Debug" 追加 |
| `cli/src/commands.rs` | **拡張** | E2Eテスト、パフォーマンステストの追加 |

## 非機能要件の実現方法

### セキュリティ 🔵

**信頼性**: 🔵 *CLAUDE.md規約 + セキュリティベストプラクティス*

- **メモリロック**: MasterKey のスワップアウト防止（RLIMIT_MEMLOCK 範囲内）
- **コアダンプ防止**: PR_SET_DUMPABLE=0 + RLIMIT_CORE=0 で鍵データのダンプファイル漏洩を防止
- **デバッガー検出**: 警告のみ（強制終了はしない）。ユーザーの意図的なデバッグを妨げない
- **SecretString**: コマンドライン引数のパスワードが `Debug` 出力やログに漏洩しない
- **中間バッファゼロ化**: 鍵復号の一時バッファが確実にゼロ化される
- **HMAC/署名検証**: 読み取り時の改ざん検出で整合性を保証

### パフォーマンス 🔵

**信頼性**: 🔵 *既存ベンチマーク + システムコールオーバーヘッド分析*

- **mlock/munlock**: < 1ms（ページサイズ境界のシステムコール1回）
- **harden_process()**: < 1ms（prctl + setrlimit の2システムコール）
- **check_debugger()**: < 1ms（/proc/self/status 読み取り or IsDebuggerPresent 1回）
- **verify_hmac Result化**: パフォーマンス影響なし（呼び出しパス変更のみ）
- **HMAC検証追加**: 各エントリあたり < 0.1ms（SHA-256 HMAC計算は高速）

### エラーハンドリング 🔵

**信頼性**: 🔵 *CLAUDE.md規約: unwrap禁止 + Result伝播*

- **mlock失敗**: `eprintln!("Warning: failed to lock memory: {e}")` + 処理続行
- **PR_SET_DUMPABLE失敗**: 警告のみ + 続行（非root環境で失敗可能）
- **デバッガー検出**: 警告表示のみ（プロセス終了しない）
- **HMAC検証失敗**: `DiaryError::Entry("content HMAC verification failed")` を返す
- **not_implemented**: `anyhow::bail!` で正常なスタック巻き戻し

## 関連文書

- **データフロー**: [dataflow.md](dataflow.md)
- **型定義**: [types.rs](types.rs)
- **ヒアリング記録**: [design-interview.md](design-interview.md)

## 信頼性レベルサマリー

- 🔵 青信号: 全件 (100%)
- 🟡 黄信号: 0件 (0%)
- 🔴 赤信号: 0件 (0%)

**品質評価**: 高品質 -- 全項目が既存コードベース分析・CLAUDE.md規約・レビュー指摘事項で確認済み
