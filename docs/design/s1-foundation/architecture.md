# s1-foundation アーキテクチャ設計

**作成日**: 2026-04-03
**関連要件定義**: [requirements.md](../../spec/s1-foundation/requirements.md)
**ヒアリング記録**: [design-interview.md](design-interview.md)

**【信頼性レベル凡例】**:
- 🔵 **青信号**: EARS要件定義書・PRD・ユーザヒアリングを参考にした確実な設計
- 🟡 **黄信号**: 妥当な推測による設計
- 🔴 **赤信号**: 推測による設計

---

## システム概要 🔵

**信頼性**: 🔵 *PRDセクション1.1・2.1より*

pq-diaryは耐量子暗号CLI日記ツール。Sprint 1ではプロジェクト基盤（ワークスペース・エラー型・セキュアメモリ型・CLIスケルトン・CI）を構築する。

## アーキテクチャパターン 🔵

**信頼性**: 🔵 *PRDセクション2.1・設計原則7より*

- **パターン**: ライブラリ+薄いCLIラッパー（Clean Architecture変形）
- **選択理由**: core/にドメインロジックを集約し、cli/は入出力のみ担当。将来のUniFFI (Swift/Kotlin) 対応に備える

```
┌─────────────────────────────────┐
│  cli/ (pq-diary binary)        │  プラットフォーム依存
│  ├── main.rs                   │  clap, termios, $EDITOR
│  └── 薄いラッパー              │  anyhow でエラー表示
├─────────────────────────────────┤
│  core/ (pq-diary-core library) │  プラットフォーム非依存
│  ├── lib.rs     公開API        │  DiaryCore 構造体
│  ├── error.rs   エラー型       │  DiaryError (thiserror)
│  ├── crypto.rs  セキュアメモリ │  SecureBuffer, MasterKey
│  ├── vault.rs   Vault操作      │  (S3で実装)
│  ├── entry.rs   エントリCRUD   │  (S4で実装)
│  ├── git.rs     Git同期        │  (S8で実装)
│  ├── legacy.rs  デジタル遺言   │  (Phase 2で実装)
│  └── policy.rs  アクセス制御   │  (S7で実装)
└─────────────────────────────────┘
```

## コンポーネント構成 🔵

**信頼性**: 🔵 *PRDセクション2.1-2.2・ヒアリングQ1より*

### core/ (pq-diary-core) 🔵

| モジュール | Sprint 1 での状態 | 責務 |
|-----------|------------------|------|
| `lib.rs` | DiaryCore スケルトン | 公開API (UniFFI互換シグネチャ) |
| `error.rs` | **全バリアント実装** | DiaryError 列挙型 |
| `crypto.rs` | **型定義実装** | SecureBuffer, ZeroizingKey, MasterKey, CryptoEngine |
| `vault.rs` | 空スケルトン | Vaultフォーマット読み書き |
| `entry.rs` | 空スケルトン | エントリCRUD |
| `git.rs` | 空スケルトン | Git同期 |
| `legacy.rs` | 空スケルトン | デジタル遺言 |
| `policy.rs` | 空スケルトン | アクセスポリシー判定 |

### cli/ (pq-diary) 🔵

| ファイル | Sprint 1 での状態 | 責務 |
|---------|------------------|------|
| `main.rs` | **全コマンド定義** | clap derive + サブコマンドディスパッチ |

## 依存関係 🔵

**信頼性**: 🔵 *PRDセクション12.3・CLAUDE.md Tech Stackより*

### core/Cargo.toml

```toml
[dependencies]
thiserror = "2"        # DiaryError
zeroize = { version = "1", features = ["derive"] }  # ZeroizeOnDrop
secrecy = "0.10"       # Secret<T>
```

### cli/Cargo.toml

```toml
[dependencies]
pq-diary-core = { path = "../core" }
clap = { version = "4", features = ["derive"] }
anyhow = "1"           # cli/のみ許可
```

## ディレクトリ構造 🔵

**信頼性**: 🔵 *PRDセクション2.1・ヒアリングQ1より*

```
pq-diary/
├── Cargo.toml                  # [workspace] members = ["core", "cli"]
├── core/
│   ├── Cargo.toml              # pq-diary-core
│   └── src/
│       ├── lib.rs              # pub mod 宣言 + DiaryCore スケルトン
│       ├── error.rs            # DiaryError (全バリアント)
│       ├── crypto.rs           # SecureBuffer, ZeroizingKey, MasterKey, CryptoEngine
│       ├── vault.rs            # (空スケルトン)
│       ├── entry.rs            # (空スケルトン)
│       ├── git.rs              # (空スケルトン)
│       ├── legacy.rs           # (空スケルトン)
│       └── policy.rs           # (空スケルトン)
├── cli/
│   ├── Cargo.toml              # pq-diary
│   └── src/
│       └── main.rs             # clap全コマンド定義
└── .github/
    └── workflows/
        └── ci.yml              # GitHub Actions CI
```

## 非機能要件の実現方法

### セキュリティ 🔵

**信頼性**: 🔵 *PRDセクション8.1・REQ-402・REQ-404より*

- **メモリ保護**: `zeroize::ZeroizeOnDrop` で全秘密型をDrop時自動ゼロ埋め
- **SecureBuffer内部型**: `Box<[u8]>` を採用。再アロケートによるデータ残存リスクを排除
- **Sprint 1 の unsafe 制限**: なし。mlock等はS9で追加
- **エラーにおける情報漏洩防止**: DiaryErrorのメッセージに秘密データを含めない

### コード品質 🔵

**信頼性**: 🔵 *REQ-101, REQ-102, NFR-101, NFR-201, NFR-202より*

- **clippy**: `-D warnings` で全警告をエラー扱い
- **doc comment**: 全公開APIに `///` 必須
- **エラーメッセージ**: 英語統一
- **テスト**: SecureBuffer/ZeroizingKeyのzeroize動作を検証

### CI パイプライン 🔵

**信頼性**: 🔵 *REQ-005・ヒアリングQ4より*

```yaml
# .github/workflows/ci.yml
trigger: push, pull_request
runner: ubuntu-latest
steps:
  1. cargo build --workspace
  2. cargo test --workspace
  3. cargo clippy --workspace -- -D warnings
  4. cargo install cargo-audit && cargo audit
```

## 技術的制約 🔵

**信頼性**: 🔵 *REQ-401〜405・CLAUDE.md規約より*

- core/ にプラットフォーム依存UIコードを含めない (REQ-401)
- 秘密データは zeroize/secrecy で保護必須 (REQ-402)
- unwrap()/expect() は本番コード禁止 (REQ-403)
- Sprint 1 で unsafe 禁止 (REQ-404)
- MSRV: Rust 1.94 (REQ-405)

## 関連文書

- **データフロー**: [dataflow.md](dataflow.md)
- **Rust型定義**: [types.rs](types.rs)
- **要件定義**: [requirements.md](../../spec/s1-foundation/requirements.md)

## 信頼性レベルサマリー

- 🔵 青信号: 10件 (100%)
- 🟡 黄信号: 0件 (0%)
- 🔴 赤信号: 0件 (0%)

**品質評価**: 最高品質 — 全設計項目がPRD・ヒアリングに裏付けられている
