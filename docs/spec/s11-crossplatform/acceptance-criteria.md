# S11 クロスプラットフォーム検証 + toolchain 固定 受け入れ基準

**作成日**: 2026-05-17
**関連要件定義**: [requirements.md](requirements.md)
**関連ユーザストーリー**: [user-stories.md](user-stories.md)
**ヒアリング記録**: [interview-record.md](interview-record.md)

**【信頼性レベル】**: 全項目🔵 (S10 hotfix 実体験 + ヒアリング + 既存 CI 動作確認)

---

## REQ-101 〜 REQ-104: rust-toolchain.toml 🔵

### Given (前提条件)
- リポジトリ root に `rust-toolchain.toml` が存在しない (S11 前)

### When (実行条件)
- `rust-toolchain.toml` を新規作成して `channel = "1.95.0"` を指定

### Then (期待結果)
- ローカル `cargo build` で rustup が 1.95.0 を自動取得
- CI でも同じバージョンが使われる

### テストケース

- [ ] **TC-101-01**: `rust-toolchain.toml` が root に存在し TOML として valid 🔵
- [ ] **TC-101-02**: `[toolchain] channel = "1.95.0"` が記述 🔵
- [ ] **TC-101-03**: `[toolchain] components = ["clippy", "rustfmt"]` が記述 🔵
- [ ] **TC-101-04**: `rustup show active-toolchain` が `1.95.0-...` を返す (ローカル) 🔵
- [ ] **TC-101-05**: CI run log で `dtolnay/rust-toolchain@stable` ステップ後、rustc バージョンが 1.95.0 と表示される 🔵

---

## REQ-201 〜 REQ-203: check ジョブ matrix 化 🔵

### Given
- 既存 `check` ジョブが ubuntu-latest 単独で実行

### When
- `.github/workflows/ci.yml` の `check` ジョブに `strategy.matrix.os` を追加 (ubuntu/macos/windows)

### Then
- 3 OS で並列実行、各 OS で全コマンド pass

### テストケース

#### 正常系

- [ ] **TC-201-01**: PR push 後、`check (ubuntu-latest)` ジョブが pass 🔵
- [ ] **TC-201-02**: `check (macos-latest)` ジョブが pass 🔵
- [ ] **TC-201-03**: `check (windows-latest)` ジョブが pass 🔵
- [ ] **TC-201-04**: `strategy.fail-fast` が `false` のため、1 OS 失敗しても他 OS が最後まで走る 🔵
- [ ] **TC-201-05**: ジョブ名が `check (<os>)` 形式で表示される 🔵

#### 異常系

- [ ] **TC-201-E01**: いずれかの OS でビルドエラー → 該当 OS のみ red、他は green or 続行 🔵
- [ ] **TC-201-E02**: clippy 警告発生 → 該当 OS のジョブが fail、ログにファイル + 行 + lint 名 🔵

---

## REQ-301 〜 REQ-303: smoke ジョブ拡張 🔵

### Given
- 既存 `smoke` ジョブが ubuntu + windows の 2 OS matrix

### When
- matrix に `macos-latest` と `ubuntu-24.04-arm` を追加

### Then
- 4 OS で smoke test pass

### テストケース

- [ ] **TC-301-01**: `CLI smoke test (macos-latest)` ジョブが pass (bash 版実行) 🔵
- [ ] **TC-301-02**: `CLI smoke test (ubuntu-24.04-arm)` ジョブが pass (bash 版実行) 🔵
- [ ] **TC-302-01**: macOS で shell 分岐 (`if: runner.os == 'Windows'`) が正しく PowerShell をスキップ 🔵
- [ ] **TC-303-01**: ubuntu-24.04-arm runner が GitHub Actions で利用可能であることを actions/setup-job ログで確認 🔵

#### Edgeケース

- [ ] **TC-EDGE-001-01**: ubuntu-24.04-arm が unavailable → matrix からそのエントリだけ手動削除で他 OS は影響なし 🔵

---

## REQ-401 〜 REQ-402: cargo audit 分離 🔵

### Given
- 既存 `check` ジョブ内に `cargo install cargo-audit --locked` と `cargo audit` ステップが含まれる

### When
- 上記 2 ステップを `check` から削除し、独立した `audit` ジョブに移動 (ubuntu-latest)

### Then
- `audit` ジョブが 1 回だけ実行、`check` matrix からは audit 関連ステップが消える

### テストケース

- [ ] **TC-401-01**: PR 上に `audit` ジョブが独立して表示される 🔵
- [ ] **TC-401-02**: `audit` ジョブが ubuntu-latest 上で実行され、3 OS 重複しない 🔵
- [ ] **TC-401-03**: RUSTSEC 警告が出た場合、`audit` ジョブが fail (既存挙動と同じ) 🔵
- [ ] **TC-402-01**: `check` matrix の各 OS で audit ステップが実行されないことをログで確認 🔵
- [ ] **TC-NFR-002-01**: `audit` ジョブ実行時間 < 30 秒 (cargo-audit インストールキャッシュヒット時) 🔵

---

## REQ-501 〜 REQ-502: backlog 更新 🔵

### Given
- 既存 `docs/backlog.md` の S9 セクションに「クロスプラットフォームビルド」項目が `[ ]` で残っている

### When
- S11 完了時に該当項目を `[x]` に変更、S11 セクションを追加

### Then
- backlog から Phase 1 取りこぼし項目が消える、S11 のスコープが S9/S10 と同じスタイルで追加

### テストケース

- [ ] **TC-501-01**: `docs/backlog.md` の S9 セクション「クロスプラットフォームビルド」が `[x]` 🔵
- [ ] **TC-502-01**: S11 セクションが追加され、6 項目以上 (toolchain pin / check matrix / smoke 拡張 / audit 分離 / Phase 1 取りこぼし完了 / 発覚バグ修正があれば) を含む 🔵
- [ ] **TC-502-02**: `docs/sprint-status.md` が S11 = `completed (s11-done)` に更新 🔵

---

## REQ-601: 発覚したバグ修正 🔵

### Given
- S11 で初めて macOS / Linux aarch64 で CI 走らせる

### When
- いずれかの OS で fail が発生

### Then
- 原因特定 → S11 内修正 or S12 繰り越し判断

### テストケース

- [ ] **TC-601-01**: macOS で発覚した unique エラーがあれば、修正コミットが含まれる 🔵
- [ ] **TC-601-02**: Linux aarch64 で発覚した unique エラーがあれば、修正 or 繰り越し判断が PR 説明に記載 🔵
- [ ] **TC-601-03**: 全 OS 一発で pass した場合、本要件は「該当なし」として S11 完了 🔵

---

## テストケースサマリー

### カテゴリ別件数

| カテゴリ | 正常系 | 異常系 | 境界値 | 合計 |
|---------|--------|--------|--------|------|
| toolchain (REQ-1xx) | 5 | 0 | 0 | 5 |
| check matrix (REQ-2xx) | 5 | 2 | 0 | 7 |
| smoke 拡張 (REQ-3xx) | 4 | 0 | 1 | 5 |
| audit 分離 (REQ-4xx) | 5 | 0 | 0 | 5 |
| backlog (REQ-5xx) | 3 | 0 | 0 | 3 |
| 発覚バグ (REQ-6xx) | 3 | 0 | 0 | 3 |
| **合計** | **25** | **2** | **1** | **28** |

### 信頼性レベル分布

- 🔵 青信号: 28 件 (100%)
- 🟡 黄信号: 0 件
- 🔴 赤信号: 0 件

**品質評価**: 最高品質。

### 優先度別

- Must Have: 22 件 (toolchain + check matrix + smoke macOS + backlog)
- Should Have: 6 件 (Linux aarch64 + audit 分離)
