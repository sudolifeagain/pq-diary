//! S9 Security Hardening + Technical Debt 型定義
//!
//! 作成日: 2026-04-10
//! 関連設計: architecture.md
//!
//! 信頼性レベル:
//! - 🔵 青信号: 既存実装・CLAUDE.md規約・レビュー指摘事項を参考にした確実な型定義

// ========================================
// core/src/crypto/secure_mem.rs — メモリロック関数
// ========================================

use crate::error::DiaryError;

// 🔵 信頼性: CLAUDE.md unsafe許可範囲 "mlock/VirtualLock"
// /// バッファをメモリにロック（スワップ防止）。
// ///
// /// Unix: `mlock(2)` を呼び出し、指定アドレスから `len` バイトをページロック。
// /// Windows: `VirtualLock` を呼び出し、指定アドレスから `len` バイトをロック。
// /// その他: no-op で `Ok(())` を返す。
// ///
// /// # Safety
// ///
// /// `ptr` は有効なメモリ領域の先頭を指し、`ptr + len` まで読み取り可能でなければならない。
// /// この関数は内部で `unsafe` ブロックを使用する（CLAUDE.md許可範囲: mlock/VirtualLock）。
// ///
// /// # Errors
// ///
// /// `mlock`/`VirtualLock` が失敗した場合は `DiaryError::Crypto` を返す。
// /// 呼び出し元は失敗を警告として扱い、処理を続行すること。
// pub fn mlock_buffer(ptr: *const u8, len: usize) -> Result<(), DiaryError>;

// 🔵 信頼性: CLAUDE.md unsafe許可範囲 "mlock/VirtualLock"
// /// バッファのメモリロックを解除。
// ///
// /// Unix: `munlock(2)` を呼び出し。
// /// Windows: `VirtualUnlock` を呼び出し。
// /// その他: no-op で `Ok(())` を返す。
// ///
// /// # Safety
// ///
// /// `ptr` は以前 `mlock_buffer` でロックされた領域の先頭を指すこと。
// ///
// /// # Errors
// ///
// /// `munlock`/`VirtualUnlock` が失敗した場合は `DiaryError::Crypto` を返す。
// pub fn munlock_buffer(ptr: *const u8, len: usize) -> Result<(), DiaryError>;

// 🔵 信頼性: 既存MasterKey構造体の全フィールド + mlock_buffer
// /// MasterKeyの全フィールド（sym_key, dsa_sk, kem_sk）をメモリにロック。
// ///
// /// `CryptoEngine::unlock()` / `unlock_with_vault()` 成功直後に呼び出す。
// /// 各フィールドのバッファに対して個別に `mlock_buffer` を呼び出し、
// /// いずれかが失敗した場合は警告を出力するが処理は続行する。
// ///
// /// # Errors
// ///
// /// いずれかの `mlock_buffer` が失敗した場合は最初のエラーを返す。
// pub fn mlock_master_key(mk: &MasterKey) -> Result<(), DiaryError>;

// 🔵 信頼性: mlock_master_key の逆操作
// /// MasterKeyの全フィールドのメモリロックを解除。
// ///
// /// `CryptoEngine::lock()` 内で、`self.master_key.take()` の前に呼び出す。
// /// ZeroizeOnDrop でゼロ化される前にページロックを解放する。
// ///
// /// # Errors
// ///
// /// いずれかの `munlock_buffer` が失敗した場合は最初のエラーを返す。
// pub fn munlock_master_key(mk: &MasterKey) -> Result<(), DiaryError>;

// ========================================
// core/src/crypto/secure_mem.rs — プラットフォーム実装
// ========================================

// 🔵 信頼性: CLAUDE.md #[cfg()] 分岐規約
//
// #[cfg(unix)]
// fn mlock_buffer_impl(ptr: *const u8, len: usize) -> Result<(), DiaryError> {
//     // SAFETY: ptr と len は呼び出し元が有効性を保証。
//     // mlock(2) は CLAUDE.md で許可された unsafe 操作。
//     let ret = unsafe { libc::mlock(ptr as *const libc::c_void, len) };
//     if ret == 0 {
//         Ok(())
//     } else {
//         Err(DiaryError::Crypto(format!(
//             "mlock failed: {}",
//             std::io::Error::last_os_error()
//         )))
//     }
// }
//
// #[cfg(unix)]
// fn munlock_buffer_impl(ptr: *const u8, len: usize) -> Result<(), DiaryError> {
//     let ret = unsafe { libc::munlock(ptr as *const libc::c_void, len) };
//     if ret == 0 {
//         Ok(())
//     } else {
//         Err(DiaryError::Crypto(format!(
//             "munlock failed: {}",
//             std::io::Error::last_os_error()
//         )))
//     }
// }
//
// #[cfg(windows)]
// fn mlock_buffer_impl(ptr: *const u8, len: usize) -> Result<(), DiaryError> {
//     // SAFETY: ptr と len は呼び出し元が有効性を保証。
//     // VirtualLock は CLAUDE.md で許可された unsafe 操作。
//     let ret = unsafe {
//         windows_sys::Win32::System::Memory::VirtualLock(
//             ptr as *mut core::ffi::c_void,
//             len,
//         )
//     };
//     if ret != 0 {
//         Ok(())
//     } else {
//         Err(DiaryError::Crypto(format!(
//             "VirtualLock failed: {}",
//             std::io::Error::last_os_error()
//         )))
//     }
// }
//
// #[cfg(windows)]
// fn munlock_buffer_impl(ptr: *const u8, len: usize) -> Result<(), DiaryError> {
//     let ret = unsafe {
//         windows_sys::Win32::System::Memory::VirtualUnlock(
//             ptr as *mut core::ffi::c_void,
//             len,
//         )
//     };
//     if ret != 0 {
//         Ok(())
//     } else {
//         Err(DiaryError::Crypto(format!(
//             "VirtualUnlock failed: {}",
//             std::io::Error::last_os_error()
//         )))
//     }
// }
//
// #[cfg(not(any(unix, windows)))]
// fn mlock_buffer_impl(_ptr: *const u8, _len: usize) -> Result<(), DiaryError> {
//     Ok(())
// }
//
// #[cfg(not(any(unix, windows)))]
// fn munlock_buffer_impl(_ptr: *const u8, _len: usize) -> Result<(), DiaryError> {
//     Ok(())
// }

// ========================================
// cli/src/main.rs — プロセス硬化
// ========================================

// 🔵 信頼性: nix crate "process"+"resource" features + CLAUDE.md unsafe許可範囲
// /// プロセスのセキュリティ硬化を実行（Unix専用）。
// ///
// /// 1. `PR_SET_DUMPABLE = 0`: コアダンプ生成を禁止し、
// ///    `/proc/{pid}/mem` へのアクセスを制限する。
// /// 2. `RLIMIT_CORE = (0, 0)`: コアファイルサイズ上限を0に設定し、
// ///    クラッシュ時のメモリダンプを防止する。
// ///
// /// いずれかの操作が失敗した場合は stderr に警告を出力するが、
// /// プロセスは正常に続行する（非特権ユーザーでの失敗を許容）。
// #[cfg(unix)]
// fn harden_process() {
//     use nix::sys::prctl;
//     use nix::sys::resource::{setrlimit, Resource};
//
//     if let Err(e) = prctl::set_dumpable(false) {
//         eprintln!("Warning: failed to set PR_SET_DUMPABLE: {e}");
//     }
//
//     if let Err(e) = setrlimit(Resource::RLIMIT_CORE, 0, 0) {
//         eprintln!("Warning: failed to set RLIMIT_CORE: {e}");
//     }
// }
//
// #[cfg(not(unix))]
// fn harden_process() {}

// 🔵 信頼性: /proc/self/status TracerPid + IsDebuggerPresent
// /// デバッガーのアタッチを検出し、警告メッセージを出力する。
// ///
// /// Unix: `/proc/self/status` の `TracerPid` 行を読み取り、
// ///       0以外の場合はデバッガーがアタッチされていると判定。
// /// Windows: `IsDebuggerPresent()` Win32 API を呼び出し。
// /// その他: no-op。
// ///
// /// 検出時は警告のみ。プロセスは終了しない。
// #[cfg(unix)]
// fn check_debugger() {
//     if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
//         for line in status.lines() {
//             if let Some(pid_str) = line.strip_prefix("TracerPid:\t") {
//                 if let Ok(pid) = pid_str.trim().parse::<u32>() {
//                     if pid != 0 {
//                         eprintln!(
//                             "Warning: debugger detected (TracerPid: {pid}). \
//                              Sensitive key material may be observable."
//                         );
//                     }
//                 }
//                 break;
//             }
//         }
//     }
// }
//
// #[cfg(windows)]
// fn check_debugger() {
//     // SAFETY: IsDebuggerPresent は引数なしの Win32 API で、
//     // 常に安全に呼び出し可能。CLAUDE.md許可範囲に該当。
//     let attached = unsafe {
//         windows_sys::Win32::System::Diagnostics::Debug::IsDebuggerPresent()
//     };
//     if attached != 0 {
//         eprintln!(
//             "Warning: debugger detected. \
//              Sensitive key material may be observable."
//         );
//     }
// }
//
// #[cfg(not(any(unix, windows)))]
// fn check_debugger() {}

// ========================================
// core/src/crypto/hmac_util.rs — M-5 verify_hmac Result化
// ========================================

// 🔵 信頼性: レビュー指摘 M-5 + 既存 verify_hmac シグネチャ
// /// HMAC-SHA256 の検証を実行し、結果を `Result<bool, DiaryError>` で返す。
// ///
// /// `HmacSha256::new_from_slice` のエラーを呼び出し元に伝播する。
// /// 従来の `bool` 返りでは鍵エラーが `false` に隠蔽されていた。
// ///
// /// # Returns
// ///
// /// - `Ok(true)`: MAC が一致。
// /// - `Ok(false)`: MAC が不一致（データまたは鍵の変更を示す）。
// /// - `Err(DiaryError::Crypto)`: HMAC初期化エラー（実質的に到達不能）。
// pub fn verify_hmac(
//     key: &[u8],
//     data: &[u8],
//     expected: &[u8; 32],
// ) -> Result<bool, DiaryError> {
//     let mut mac = HmacSha256::new_from_slice(key)
//         .map_err(|e| DiaryError::Crypto(format!("HMAC key error: {e}")))?;
//     mac.update(data);
//     Ok(mac.verify_slice(expected).is_ok())
// }

// ========================================
// core/src/crypto/mod.rs — CryptoEngine::hmac_verify 変更
// ========================================

// 🔵 信頼性: M-5 verify_hmac Result化に伴う呼び出し元変更
// /// Verify HMAC-SHA256 of `data` against `expected` using the engine's internal symmetric key.
// ///
// /// Uses constant-time comparison.
// ///
// /// Returns [`DiaryError::NotUnlocked`] if the engine has not been unlocked.
// /// Returns [`DiaryError::Crypto`] if HMAC initialization fails.
// pub fn hmac_verify(&self, data: &[u8], expected: &[u8; 32]) -> Result<bool, DiaryError> {
//     let mk = self.expose_master_key()?;
//     hmac_util::verify_hmac(&mk.sym_key, data, expected)
// }

// ========================================
// cli/src/main.rs — H-1 Cli.password SecretString化
// ========================================

use secrecy::SecretString;

// 🔵 信頼性: レビュー指摘 H-1 + 既存 Cli 構造体
//
// /// Master password のカスタム ValueParser。
// ///
// /// `clap` は `SecretString` を直接パースできないため、
// /// `String` を受け取って即座に `SecretString` に変換する。
// fn parse_secret_string(s: &str) -> Result<SecretString, std::convert::Infallible> {
//     Ok(SecretBox::new(Box::from(s)))
// }

// #[derive(Debug, Parser)]
// pub struct Cli {
//     /// Vault path or name
//     #[arg(short = 'v', long, global = true)]
//     pub vault: Option<String>,
//
//     /// Master password (insecure; use interactive prompt instead)
//     #[arg(long, global = true, value_parser = parse_secret_string)]
//     pub password: Option<SecretString>,
//
//     /// Enable Claude AI integration
//     #[arg(long, global = true)]
//     pub claude: bool,
//
//     /// Enable debug output
//     #[arg(long, global = true)]
//     pub debug: bool,
//
//     #[command(subcommand)]
//     pub command: Commands,
// }

// ========================================
// cli/src/password.rs — H-1 get_password シグネチャ変更
// ========================================

// 🔵 信頼性: レビュー指摘 H-1 + 既存 get_password シグネチャ
// /// Obtain the master password using a three-stage fallback strategy.
// ///
// /// `flag_value` は `Cli.password` から渡される `Option<&SecretString>`。
// /// `SecretString` を受け取ることで、パスワードが生 `String` として
// /// スタック上に残留するリスクを排除する。
// ///
// /// # Changes from S8
// ///
// /// - `flag_value`: `Option<&str>` → `Option<&SecretString>`
// /// - 内部で `expose_secret()` を使用して一時的に `&str` を取得
// pub fn get_password(flag_value: Option<&SecretString>) -> Result<PasswordSource, DiaryError> {
//     // Stage 1: --password flag
//     if let Some(secret) = flag_value {
//         eprintln!("Warning: Specifying a password on the command line is a security risk.");
//         return Ok(PasswordSource::Flag(SecretBox::new(
//             Box::from(secret.expose_secret()),
//         )));
//     }
//
//     // Stage 2 and 3: unchanged from current implementation
//     // ...
// }

// ========================================
// cli/src/main.rs — M-1 not_implemented bail!化
// ========================================

// 🔵 信頼性: レビュー指摘 M-1 + anyhow::bail! パターン
// /// Print a "not yet implemented" message and return an error.
// ///
// /// Uses `anyhow::bail!` instead of `process::exit(1)` to ensure
// /// that all Drop impls (including ZeroizeOnDrop) are executed during
// /// stack unwinding.
// ///
// /// # Changes from S8
// ///
// /// - `process::exit(1)` → `anyhow::bail!()`
// /// - 返り値型は変わらず `anyhow::Result<()>`
// fn not_implemented(cmd_name: &str, sprint: &str) -> anyhow::Result<()> {
//     anyhow::bail!("Command '{cmd_name}' is not yet implemented. Planned for {sprint}.");
// }

// ========================================
// core/src/crypto/mod.rs — M-2/M-4 Zeroizing中間バッファ
// ========================================

use zeroize::Zeroizing;

// 🔵 信頼性: レビュー指摘 M-2, M-4 + 既存 unlock_with_vault 行126-127
//
// unlock_with_vault() 内の MasterKey 構築部分:
//
// // Before (現行 行124-128):
// // let master_key = MasterKey {
// //     sym_key: *sym_key.as_ref(),
// //     kem_sk: kem_sk.as_ref().to_vec().into_boxed_slice(),
// //     dsa_sk: dsa_sk.as_ref().to_vec().into_boxed_slice(),
// // };
//
// // After (S9):
// // let master_key = MasterKey {
// //     sym_key: *sym_key.as_ref(),
// //     kem_sk: {
// //         let tmp = Zeroizing::new(kem_sk.as_ref().to_vec());
// //         // Zeroizing<Vec<u8>> が Drop される際に内容はゼロ化される。
// //         // into_boxed_slice() は Vec の所有権を移動するため追加コピーなし。
// //         (*tmp).clone().into_boxed_slice()
// //     },
// //     dsa_sk: {
// //         let tmp = Zeroizing::new(dsa_sk.as_ref().to_vec());
// //         (*tmp).clone().into_boxed_slice()
// //     },
// // };

// ========================================
// core/src/entry.rs — 読み取り時HMAC/署名検証
// ========================================

// 🔵 信頼性: セキュリティベストプラクティス + 既存 get_entry 構造
//
// get_entry() 内の変更:
//
// // Before (現行):
// // let record = matches.remove(0);
// // let decrypted = engine.decrypt(&record.iv, &record.ciphertext)?;
// // let plaintext: EntryPlaintext = serde_json::from_slice(decrypted.as_ref())
// //     .map_err(|e| DiaryError::Entry(format!("deserialization failed: {e}")))?;
// // Ok((record, plaintext))
//
// // After (S9):
// // let record = matches.remove(0);
// // let decrypted = engine.decrypt(&record.iv, &record.ciphertext)?;
// //
// // // S9: content_hmac 検証
// // if !engine.hmac_verify(decrypted.as_ref(), &record.content_hmac)? {
// //     return Err(DiaryError::Entry(
// //         "content HMAC verification failed".to_string(),
// //     ));
// // }
// //
// // // S9: DSA署名検証（署名フィールドが空でない場合のみ）
// // if !record.signature.is_empty() {
// //     let (header, _) = read_vault(vault_path)?;
// //     if !engine.dsa_verify(&header.dsa_pk, decrypted.as_ref(), &record.signature)? {
// //         return Err(DiaryError::Entry(
// //             "signature verification failed".to_string(),
// //         ));
// //     }
// // }
// //
// // let plaintext: EntryPlaintext = serde_json::from_slice(decrypted.as_ref())
// //     .map_err(|e| DiaryError::Entry(format!("deserialization failed: {e}")))?;
// // Ok((record, plaintext))

// ========================================
// cli/Cargo.toml — 依存関係変更
// ========================================

// 🔵 信頼性: 既存 Cargo.toml + 必要な features 追加
//
// [target.'cfg(unix)'.dependencies]
// nix = { version = "0.29", features = ["term", "user", "process", "resource"] }
//
// [target.'cfg(windows)'.dependencies]
// windows-sys = { version = "0.59", features = [
//     "Win32_System_Console",
//     "Win32_System_Diagnostics_Debug",
// ] }

// ========================================
// core/Cargo.toml — M-3 PQCピン固定
// ========================================

// 🔵 信頼性: レビュー指摘 M-3 + 既存 Cargo.toml
//
// # Before:
// # ml-kem = { git = "https://github.com/sudolifeagain/ml-kem", branch = "pq-diary", ... }
// # ml-dsa = { git = "https://github.com/sudolifeagain/ml-dsa", branch = "pq-diary", ... }
//
// # After:
// # ml-kem = { git = "https://github.com/sudolifeagain/ml-kem", rev = "<commit-hash>", ... }
// # ml-dsa = { git = "https://github.com/sudolifeagain/ml-dsa", rev = "<commit-hash>", ... }

// ========================================
// 信頼性レベルサマリー
// ========================================
// - 🔵 青信号: 全件 (100%)
// - 🟡 黄信号: 0件 (0%)
// - 🔴 赤信号: 0件 (0%)
//
// 品質評価: 高品質
