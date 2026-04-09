# ADR-0007: Win32 Console API の unsafe 使用許可
Status: 提案
Date: 2026-04-09

## Context

pq-diary はパスワード入力時にエコーバックを無効化する必要がある。

- Unix では `nix` クレート経由の safe API (`termios`) を使用できる
- Windows では同等の機能を Win32 Console API で直接実装する必要がある
- 対象 API: `GetConsoleMode`, `SetConsoleMode`, `ReadConsoleW`
- 実装箇所: `cli/src/password.rs` の `#[cfg(windows)] fn read_password_tty()`

## Decision

CLAUDE.md の `unsafe` 許可リストに Win32 Console API を追加する。

対象関数は `GetConsoleMode` / `SetConsoleMode` / `ReadConsoleW` の 3 関数のみとし、
それ以外の Win32 API は引き続き禁止とする。

## 理由

### rpassword クレート不採用理由

1. **依存関係最小化ポリシー**: プロジェクトは外部依存を最小化する方針をとっている
2. **SecretString 統合不十分**: `rpassword` は `SecretString` を直接返さないため、
   平文 `String` を経由するラッパーが必要になり、zeroize 保証に穴が生じる
3. **zeroize 保証の欠如**: 入力バッファが適切にゼロクリアされることが保証されない

### 代替クレート不採用理由

| 候補 | 不採用理由 |
|------|-----------|
| `rpassword` | SecretString 非対応、zeroize 保証なし |
| `dialoguer` | GUI コンポーネントも含む過大な依存関係 |
| 標準入力 raw mode | Windows では echo 無効化に不十分 |

### unsafe 採用理由

- `windows-sys` クレート経由の FFI 呼び出しは本質的に `unsafe`
- 呼び出しパターンが限定的 (3 関数のみ) でレビュー可能な範囲に収まる
- Unix 版の termios 実装と対称的なパターン (save → modify → use → restore)

## SAFETY コメント確認基準

`cli/src/password.rs` の Win32 Console API `unsafe` ブロックは以下を満たさなければならない:

1. **SAFETY コメント必須**: 各 `unsafe` ブロックの直前に `// SAFETY:` コメントを配置する
2. **ハンドル有効性チェック**: `GetStdHandle` の戻り値を `null` / `INVALID_HANDLE_VALUE (-1)` と
   比較し、無効なハンドルでは早期リターンする
3. **コンソールモード復元保証**: `SetConsoleMode` 失敗・`ReadConsoleW` 失敗を問わず、
   保存した `old_mode` を必ず復元してから関数を抜ける
4. **バッファサイズ境界チェック**: `ReadConsoleW` に渡す `nNumberOfCharsToRead` は
   バッファの実際のサイズ (`buf.len()`) を上限とし、`chars_read` がその範囲内に
   収まることを SAFETY コメントで明示する

現在の実装 (`cli/src/password.rs`) は上記 4 点を満たしていることを確認済み。

## Consequences

- `unsafe` 使用箇所が 1 ファイル (`cli/src/password.rs`) に限定される
- Win32 Console API を追加した場合も SAFETY コメントレビューが必須
- Unix 版と Windows 版で対称的なパターンを維持できる
- `rpassword` / `dialoguer` を導入しないため依存グラフをシンプルに保てる
