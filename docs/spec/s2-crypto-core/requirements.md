# s2-crypto-core 要件定義書

## 概要

pq-diaryプロジェクトの暗号コアを実装する。PQCフォーク作成、Argon2id鍵導出、AES-256-GCM暗号化、ML-KEM-768鍵カプセル化、ML-DSA-65署名、HMAC-SHA256を整備し、後続Sprint (S3-S9) の暗号基盤とする。

## 関連文書

- **ヒアリング記録**: [interview-record.md](interview-record.md)
- **ユーザストーリー**: [user-stories.md](user-stories.md)
- **受け入れ基準**: [acceptance-criteria.md](acceptance-criteria.md)
- **PRD**: [requirements.md](../../requirements.md)
- **S1基盤**: [../s1-foundation/requirements.md](../s1-foundation/requirements.md)

## 機能要件（EARS記法）

**【信頼性レベル凡例】**:
- 🔵 **青信号**: PRD・ユーザヒアリングを参考にした確実な要件
- 🟡 **黄信号**: PRDから妥当な推測による要件
- 🔴 **赤信号**: PRDにない推測による要件

### 通常要件

- REQ-001: システムは PQCライブラリのフォークリポジトリを作成しなければならない。ml-kemフォークでは `DecapsulationKey` の zeroize 補完を行い、ml-dsaフォークでは `s1_hat` / `s2_hat` / `t0_hat` / `A_hat` フィールドの zeroize 追加および CVE-2026-22705 パッチを適用しなければならない 🔵 *PRDセクション5.3より*
- REQ-002: システムは Argon2id による鍵導出を実装しなければならない。パスワードとソルトから32バイトの対称鍵を導出する。デフォルトパラメータは `memory_cost_kb=65536`, `time_cost=3`, `parallelism=4` とする。最低保証値として `memory_cost_kb` が 19456 未満または `time_cost` が 2 未満の場合は警告を表示しなければならない 🔵 *PRDセクション5.5より*
- REQ-003: システムは AES-256-GCM による暗号化および復号を実装しなければならない。暗号化時にランダムな12バイト nonce を生成し、暗号文と16バイト GCM タグを出力する 🔵 *PRDセクション5.1より*
- REQ-004: システムは ML-KEM-768 による鍵カプセル化および脱カプセル化を実装しなければならない。鍵ペア生成、共有秘密の導出を行い、`DecapsulationKey` は Drop 時に zeroize される 🔵 *PRDセクション5.1 + FIPS 203より*
- REQ-005: システムは ML-DSA-65 による署名および検証を実装しなければならない。鍵ペア生成、メッセージ署名、署名検証を行い、秘密鍵は Drop 時に zeroize される 🔵 *PRDセクション5.1 + FIPS 204より*
- REQ-006: システムは HMAC-SHA256 を実装しなければならない。`hmac` + `sha2` クレートを使用し、32バイトの MAC を出力する 🔵 *PRDセクション5.1より*

### 制約要件

- REQ-401: 秘密鍵は全て zeroize 保護を施さなければならない 🔵 *PRDセクション8.1より*
- REQ-402: PQCフォークは GitHub 別リポジトリで管理し、Cargo.toml の git 依存として参照しなければならない 🔵 *ヒアリングQ5より*
- REQ-403: Nonce の再利用を禁止する。エントリごとに `OsRng` でランダムに生成しなければならない 🔵 *PRDセクション16.1より*
- REQ-404: S1 で定義した `SecureBuffer` / `ZeroizingKey` / `MasterKey` / `CryptoEngine` を使用しなければならない 🔵 *S1設計より*
- REQ-405: 全暗号ロジックは `core/src/crypto.rs` に集約しなければならない 🔵 *PRDセクション2.1より*

## 非機能要件

### 性能

- NFR-001: unlock 操作 (Argon2id 鍵導出) は1〜3秒以内に完了しなければならない 🔵 *PRDセクション12.1より*

### セキュリティ

- NFR-002: `cargo audit` で既知脆弱性が検出されないこと 🔵 *CLAUDE.md DoD要件より*

### テスト品質

- NFR-101: テストには NIST KAT ベクター（既知応答テスト）を含めなければならない 🔵 *PRDセクション5.3より*

## エッジケース

### エラー処理

- EDGE-001: 不正パスワードでの Argon2id 鍵導出は成功するが、検証トークンとの照合で不一致を検出すること 🔵 *PRDセクション6.1より*
- EDGE-002: 空パスワードが入力された場合、`DiaryError::Password` を返すこと 🔵 *セキュリティ慣例より*
- EDGE-003: AES-GCM の暗号文を1バイトでも改竄した場合、復号時にエラー（GCMタグ不一致）を返すこと 🔵 *GCM仕様より*
- EDGE-004: ML-KEM に不正な暗号文を渡した場合、脱カプセル化エラーを返すこと 🔵 *FIPS 203より*
- EDGE-005: ML-DSA の署名を改竄した場合、検証が失敗すること 🔵 *FIPS 204より*
