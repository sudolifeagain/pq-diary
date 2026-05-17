# S11 クロスプラットフォーム検証 + toolchain 固定 ユーザストーリー

**作成日**: 2026-05-17
**関連要件定義**: [requirements.md](requirements.md)
**ヒアリング記録**: [interview-record.md](interview-record.md)

**【信頼性レベル】**: 全ストーリー🔵 (S10 hotfix 実体験 + 2026-05-17 ヒアリング)

---

## エピック 1: 開発者体験の安定化 (toolchain pin)

### ストーリー 1.1: ローカルと CI の Rust バージョン同期 🔵

**信頼性**: 🔵 *S10 hotfix で 1.94→1.95 clippy 差分が発生した実体験*

**私は** pq-diary 開発者 **として**
**ローカル `rustup show` と CI 環境の Rust バージョンが一致してほしい**
**そうすることで** ローカルで pass する clippy が CI で fail する事故を防げる

**関連要件**: REQ-101, REQ-102, REQ-104

**詳細シナリオ**:
1. 開発者がリポジトリを clone 直後 `cargo build` を実行
2. Rustup が `rust-toolchain.toml` の `channel = "1.95.0"` を読み、自動で 1.95.0 をダウンロード/有効化
3. CI も同じ `rust-toolchain.toml` を読むため、`dtolnay/rust-toolchain@stable` の指定があっても 1.95.0 が使われる
4. ローカルと CI で同じ clippy lint が走り、同じ警告/エラーが出る

**前提条件**: Rustup インストール済み (Rust 開発の標準)

**優先度**: Must Have

---

## エピック 2: クロスプラットフォーム検証 (Phase 1 取りこぼし回収)

### ストーリー 2.1: 全 OS で実機 build/test 確認 🔵

**信頼性**: 🔵 *Phase 1 backlog 項目 + ヒアリング Q3*

**私は** pq-diary プロジェクトリーダー **として**
**ubuntu / macOS / Windows / Linux aarch64 の 4 環境で build/test/clippy が pass することを CI で保証したい**
**そうすることで** S1〜S10 の Phase 1 機能がプラットフォーム横断で動くと言える

**関連要件**: REQ-201, REQ-202, REQ-203, REQ-301, REQ-302, REQ-303

**詳細シナリオ**:
1. PR を出すと CI で `check` ジョブが 3 OS matrix (ubuntu/macos/windows) で並列実行
2. 同時に `smoke` ジョブが 4 OS matrix (ubuntu/ubuntu-arm/macos/windows) で並列実行
3. いずれかの OS が失敗しても他の OS は最後まで走り、PR 上で全 OS の状態が一覧できる
4. 全 OS green になればマージ可能と判断

**前提条件**:
- `rust-toolchain.toml` で toolchain pin 済み (ストーリー 1.1)
- Cargo.lock コミット済み (S10 hotfix)

**優先度**: Must Have

---

### ストーリー 2.2: macOS 固有バグの早期検出 🔵

**信頼性**: 🔵 *S10 hotfix で Linux 固有バグ (nix API) が遅れて発覚した実体験*

**私は** pq-diary 開発者 **として**
**macOS 固有のビルドエラーや動作不良を、PR レビュー段階で検出したい**
**そうすることで** マージ後の hotfix サイクルを避けられる

**関連要件**: REQ-301, REQ-302, REQ-601

**詳細シナリオ**:
1. PR で macOS smoke ジョブが失敗 → エラーログから原因特定
2. 原因が小規模 → S11 内でタスク追加して修正
3. 原因が大規模 (例: 主要モジュール rewrite が必要) → S12 へ繰り越し判断

**前提条件**: macOS-latest runner が利用可能 (GitHub Actions 標準)

**優先度**: Must Have

---

### ストーリー 2.3: Linux aarch64 (ARM サーバー / Raspberry Pi 等) サポート確認 🔵

**信頼性**: 🔵 *ヒアリング Q2 確定 + Phase 1 backlog*

**私は** Raspberry Pi や ARM サーバーで pq-diary を使うユーザー **として**
**Linux aarch64 ビルドが CI で確認されてほしい**
**そうすることで** 自分の環境で動くと信頼できる

**関連要件**: REQ-303, EDGE-001

**詳細シナリオ**:
1. PR で `ubuntu-24.04-arm` (public preview) runner で smoke ジョブが実行
2. 全 PASS なら ARM サポートを宣言できる
3. preview EOL になったら matrix からエントリを削除して x86_64 と Apple Silicon でカバー

**前提条件**: GitHub Actions が ubuntu-24.04-arm runner を提供している (2026-05 時点で public preview)

**優先度**: Should Have (preview 依存のためベストエフォート)

---

## エピック 3: CI 効率化 (audit ジョブ分離)

### ストーリー 3.1: cargo audit の重複排除 🔵

**信頼性**: 🔵 *スコープ + GitHub Actions ベストプラクティス*

**私は** pq-diary メンテナ **として**
**`cargo audit` を 3 OS で重複実行するムダを避けたい**
**そうすることで** CI 完了時間が短くなり、依存脆弱性検出は 1 OS で十分

**関連要件**: REQ-401, REQ-402, NFR-002

**詳細シナリオ**:
1. PR で `check` matrix (3 OS 並列) と `audit` (ubuntu のみ) と `smoke` matrix (4 OS) が並列実行
2. 各ジョブは独立、`cargo audit` は ubuntu でのみ 1 回実行
3. RUSTSEC 警告は 1 ジョブで報告される (重複ノイズなし)

**前提条件**: 既存 `check` ジョブから audit ステップを移動するだけ (低リスク)

**優先度**: Should Have (UX 向上、必須ではない)

---

## エピック 4: ドキュメント整備

### ストーリー 4.1: Phase 1 完了の宣言 🔵

**信頼性**: 🔵 *スコープ + backlog 慣行*

**私は** pq-diary プロジェクトリーダー **として**
**Phase 1 の唯一の取りこぼし「クロスプラットフォームビルド」が完了したことを backlog で明示したい**
**そうすることで** Phase 1 完全完了 (`phase1-done` タグの正当性) を再確認できる

**関連要件**: REQ-501, REQ-502

**詳細シナリオ**:
1. S11 完了時に `docs/backlog.md` の該当項目を `[x]` に変更
2. S11 セクションを backlog に追記 (S10 と同じスタイル)
3. `docs/sprint-status.md` を completed (s11-done) に更新

**優先度**: Must Have

---

## ストーリーマップ

```
エピック 1: 開発者体験の安定化
└── ストーリー 1.1 (🔵 Must Have)

エピック 2: クロスプラットフォーム検証
├── ストーリー 2.1 (🔵 Must Have)
├── ストーリー 2.2 (🔵 Must Have)
└── ストーリー 2.3 (🔵 Should Have)

エピック 3: CI 効率化
└── ストーリー 3.1 (🔵 Should Have)

エピック 4: ドキュメント整備
└── ストーリー 4.1 (🔵 Must Have)
```

## 信頼性レベルサマリー

- 🔵 青信号: 6 件 (100%)
- 🟡 黄信号: 0 件
- 🔴 赤信号: 0 件

**品質評価**: 最高品質。すべて S10 hotfix 実体験 + ヒアリング根拠。
