# S11 クロスプラットフォーム検証 + toolchain 固定 - Context Note

## Tech Stack

- **言語**: Rust 2021 edition
- **ワークスペース**: `core/` + `cli/`
- **CI**: GitHub Actions (`.github/workflows/ci.yml`)
- **ローカル現状 toolchain**: stable 1.95.0 (S10 hotfix で 1.94.1 → 1.95.0 アップグレード済み)
- **依存ロック**: Cargo.lock コミット済み (S10 hotfix PR #3)

## 背景: S10 hotfix で表面化した課題

| # | 課題 | 原因 | hotfix での対応 | S11 での恒久対策 |
|---|------|------|---------------|------------------|
| 1 | CI で ml-dsa/pkcs8 型不整合 | `Cargo.lock` が `.gitignore` で除外、CI で再生成され依存ドリフト | Cargo.lock コミット + `--locked` 強制 | (済) |
| 2 | nix 0.29 mlock/munlock API 変更未追従 | Linux 固有、ローカル Windows では `#[cfg(unix)]` 除外で気付かず | secure_mem.rs を NonNull<c_void> 化 | **CI check matrix 化で再発防止** |
| 3 | tc_s10_088_02 が CI で false | sandboxed runner で prctl/setrlimit 効果未反映 | `#[ignore]` 化 | (継続) |
| 4 | Rust 1.95 新 clippy lints | dtolnay/rust-toolchain@stable が auto-update | 個別 fix + ローカル 1.95 アップ | **rust-toolchain.toml で pin** |

## Phase 1 取りこぼし (S10 backlog)

```
- [ ] クロスプラットフォームビルド (Linux x86_64/aarch64, macOS aarch64, Windows x86_64)
      — Windows確認済、Linux/macOSは未確認
```

S11 はこの項目を完全に解消する。

## 既存 CI ワークフロー (`.github/workflows/ci.yml`)

```yaml
jobs:
  check:
    runs-on: ubuntu-latest  # ← matrix 化対象
    steps:
      - cargo build --workspace --locked
      - cargo test --workspace --locked
      - cargo clippy --workspace --locked --all-targets -- -D warnings
      - cargo install cargo-audit --locked  # ← 重複対象、分離検討
      - cargo audit

  smoke:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, windows-latest]  # ← macos-latest 追加対象
    runs-on: ${{ matrix.os }}
    steps:
      - cargo build --release --workspace --locked
      - ci/smoke-test.sh or ci/smoke-test.ps1
```

## GitHub Actions Runner

- ubuntu-latest = Ubuntu 24.04 LTS (x86_64)
- macos-latest = macOS 14 Sonoma (arm64/M1)
- windows-latest = Windows Server 2022 (x86_64)
- ubuntu-24.04-arm = Ubuntu 24.04 LTS (aarch64) — **public preview (2026-05 時点)**
- public リポジトリは無制限利用可

## Development Rules (CLAUDE.md)

- `unsafe` 既存許可リストのみ
- 秘密データは zeroize / SecretString / SecretBytes
- core/ にプラットフォーム依存 UI コード禁止
- platform 分岐は `#[cfg()]` で

## Key Decisions from Interview (2026-05-17)

1. **toolchain 固定**: rust-toolchain.toml で `channel = "1.95.0"` (固定バージョン)
2. **Linux aarch64**: S11 で対応 (ubuntu-24.04-arm preview を smoke matrix に追加)
3. **fail-fast: false**: 全 OS の状態を一度に把握、CI minutes は public で無料
4. **作業規模**: フル機能開発 (requirements + user-stories + acceptance-criteria)

## Related Files

- `.github/workflows/ci.yml`: 既存 CI、matrix 拡張対象
- `Cargo.lock`: S10 hotfix でコミット済み
- `rust-toolchain.toml`: 新規追加 (S11 で作成)
- `docs/backlog.md`: Phase 1 項目チェック対象
- `core/src/crypto/secure_mem.rs`: Linux 固有 nix API 依存
- `cli/src/security.rs`: harden_status (Linux で sandbox 制約)
- `cli/src/password.rs`: termios (Linux) / Console API (Windows) 分岐
- `cli/src/editor.rs`: Unix permissions / Windows ファイル作成

## Phase 2 への持ち越し候補

- Linux aarch64 が ubuntu-24.04-arm preview 終了 (EOL) になった場合の移行対応
- macOS 12 (Intel) サポート可否 (現在は arm64 のみ)
- `cargo deny` 等の高度な依存検査追加
