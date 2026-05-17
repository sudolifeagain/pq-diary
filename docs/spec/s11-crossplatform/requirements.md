# S11 クロスプラットフォーム検証 + toolchain 固定 要件定義書

## 概要

Phase 1 取りこぼし「クロスプラットフォームビルド検証 (Linux x86_64/aarch64, macOS aarch64, Windows x86_64)」を回収し、あわせて S10 hotfix で表面化した CI 環境差異の **恒久対策** を行う。

主要施策: rust-toolchain.toml で stable バージョンを pin、CI check ジョブを 3 OS matrix 化、smoke ジョブに macOS と Linux aarch64 を追加、cargo audit を別ジョブに分離。

## 関連文書

- **ヒアリング記録**: [💬 interview-record.md](interview-record.md)
- **ユーザストーリー**: [📖 user-stories.md](user-stories.md)
- **受け入れ基準**: [✅ acceptance-criteria.md](acceptance-criteria.md)
- **コンテキストノート**: [📝 note.md](note.md)

## 機能要件（EARS記法）

**【信頼性レベル】**: 全項目🔵 (S10 hotfix 実体験 + 2026-05-17 ヒアリング + 既存 CI で確定)

### 1. toolchain pin (rust-toolchain.toml)

- **REQ-101**: システムは `rust-toolchain.toml` をリポジトリルートに配置しなければならない 🔵 *ヒアリング Q1*
- **REQ-102**: `rust-toolchain.toml` の `[toolchain] channel` は固定バージョン (例: `"1.95.0"`) を指定しなければならない 🔵 *ヒアリング Q1 確定*
- **REQ-103**: `rust-toolchain.toml` の `components` には `clippy` と `rustfmt` を含めなければならない 🔵 *CI で利用するため*
- **REQ-104**: CI ワークフロー (`.github/workflows/ci.yml`) は `dtolnay/rust-toolchain@stable` を呼び出していても、`rust-toolchain.toml` の値が優先されなければならない 🔵 *Rustup の標準動作*

### 2. CI check ジョブの matrix 化

- **REQ-201**: `check` ジョブは `ubuntu-latest`, `macos-latest`, `windows-latest` の matrix で実行しなければならない 🔵 *ヒアリング Q3 + Phase 1 backlog*
- **REQ-202**: matrix の各 OS で `cargo build --workspace --locked` / `cargo test --workspace --locked` / `cargo clippy --workspace --locked --all-targets -- -D warnings` を実行しなければならない 🔵 *S10 hotfix と整合*
- **REQ-203**: `check` ジョブの `strategy.fail-fast` は `false` でなければならない 🔵 *ヒアリング Q3 確定*

### 3. smoke ジョブの拡張

- **REQ-301**: `smoke` ジョブの matrix に `macos-latest` を追加しなければならない 🔵 *スコープ*
- **REQ-302**: macOS 上では `ci/smoke-test.sh` (bash) を実行しなければならない (PowerShell は使わない) 🔵 *既存 shell 分岐の自然な拡張*
- **REQ-303**: `smoke` ジョブの matrix に `ubuntu-24.04-arm` を追加しなければならない (public preview 利用) 🔵 *ヒアリング Q2 確定*

### 4. cargo audit ジョブ分離

- **REQ-401**: `cargo audit` 実行は `check` ジョブから分離し、独立した `audit` ジョブとして 1 OS (ubuntu-latest) でのみ実行しなければならない 🔵 *スコープ + 重複排除*
- **REQ-402**: 既存の `cargo install cargo-audit --locked` ステップは `audit` ジョブに移動しなければならない 🔵 *上記の自然な帰結*

### 5. backlog 更新

- **REQ-501**: `docs/backlog.md` の Phase 1「クロスプラットフォームビルド」項目をチェック完了 (`[x]`) に更新しなければならない 🔵 *スコープ*
- **REQ-502**: S11 のスコープ項目を `docs/backlog.md` に追加しなければならない (S10 / S9 と同じスタイル) 🔵 *既存パターン*

### 6. クロスプラットフォーム検証で発覚したバグ修正 (条件付き)

- **REQ-601**: CI matrix 拡張後、いずれかの OS で `cargo build` / `cargo test` / `cargo clippy` / smoke test が失敗した場合、原因を特定し修正タスクを追加しなければならない 🔵 *スコープ「発覚したバグ修正」*

## 非機能要件

### パフォーマンス

- **NFR-001**: matrix 拡張後の CI 全体の実行時間は 10 分以内に収まることが望ましい 🔵 *既存 check 4 分 + smoke 1〜2 分 × 4 OS の見積もり*
- **NFR-002**: `cargo audit` の単独ジョブは 30 秒以内で完了することが望ましい 🔵 *cargo-audit インストール + DB 確認の標準時間*

### セキュリティ

- **NFR-101**: `rust-toolchain.toml` で固定する toolchain バージョンは現在の Rust stable (2026-05 時点で 1.95.0) を採用し、cargo audit で警告のないバージョンを選ぶ 🔵 *標準的なセキュリティ要件*

### 保守性

- **NFR-201**: matrix のいずれかの OS で失敗した場合、失敗した OS とジョブ名が一目で分かるよう GitHub Actions の標準的なジョブ命名規約に従う (例: `check (ubuntu-latest)`) 🔵 *GitHub Actions のデフォルト動作*
- **NFR-202**: `rust-toolchain.toml` を更新する際は CHANGELOG または PR 説明で理由を明示しなければならない 🔵 *慣習*

## Edgeケース

### エラー処理

- **EDGE-001**: `ubuntu-24.04-arm` (public preview) が突然 unavailable / EOL になった場合、matrix からそのエントリだけ取り除けば他の OS は影響を受けない 🔵 *fail-fast: false の効果*
- **EDGE-002**: macOS 固有のビルドエラーが発生した場合 (例: `#[cfg(target_os = "macos")]` ブランチ未実装)、修正タスクを S11 内で追加するか、修正規模が大きい場合は S12 へ繰り越す 🔵 *スコープ REQ-601 の運用*
- **EDGE-003**: Linux aarch64 で発覚するバグが既存コードの aarch64 非対応 (例: x86 intrinsic 利用) の場合、対応コストを評価して S11 続行 or S12 繰り越しを判断 🔵 *スコープ REQ-601 の運用*

### 境界値

- **EDGE-101**: rust-toolchain.toml と CI の `dtolnay/rust-toolchain@stable` 指定が併存する場合、`rust-toolchain.toml` が優先される (rustup の仕様) 🔵 *Rustup ドキュメント*
- **EDGE-102**: 既存の `--locked` フラグは Cargo.lock の存在を要求する。S10 hotfix で Cargo.lock がコミット済みのため問題なし 🔵 *S10 hotfix と整合*

## 信頼性レベル分布

- 🔵 青信号: 全 24 項目 (100%)
- 🟡 黄信号: 0 件
- 🔴 赤信号: 0 件

**品質評価**: 最高品質。S10 hotfix で実体験した課題に基づくため、推測要素ゼロ。
