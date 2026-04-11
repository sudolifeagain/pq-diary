# S9 Security Hardening + Technical Debt 設計ヒアリング記録

**作成日**: 2026-04-10
**ヒアリング実施**: step4 既存実装ベースの分析確認

## ヒアリング目的

S9はセキュリティ強化と技術的負債の解消を目的とするスプリントである。設計判断の大半は既存コードベースのレビュー指摘事項（H-1, M-1〜M-5, L-1〜L-4）に基づくため、新規のアーキテクチャ判断は限定的である。既存実装の分析結果を確認し、設計の正当性を検証するヒアリングを実施した。

## 質問と回答

### Q1: 既存実装の分析 — 中間バッファゼロ化の必要性と影響範囲

**質問日時**: 2026-04-10
**カテゴリ**: セキュリティ / コード品質
**背景**: レビュー指摘 M-2/M-4 は `core/src/crypto/mod.rs` の `unlock_with_vault()` 行126-127 で `.to_vec().into_boxed_slice()` が生の `Vec<u8>` を中間バッファとして生成している問題を指摘している。同様のパターンが他の箇所にも存在するか、また修正の影響範囲を確認する必要がある。

**分析結果**:

既存コードベースを調査した結果、以下の知見を得た:

1. **行126-127（M-2/M-4対象）**: `unlock_with_vault()` 内の MasterKey 構築部分。
   ```rust
   kem_sk: kem_sk.as_ref().to_vec().into_boxed_slice(),
   dsa_sk: dsa_sk.as_ref().to_vec().into_boxed_slice(),
   ```
   `kem_sk` と `dsa_sk` は `SecureBuffer` 型で既にゼロ化保護されているが、`.to_vec()` が生成する中間 `Vec<u8>` はゼロ化されない。`Zeroizing<Vec<u8>>` でラップすることで中間バッファも確実にゼロ化される。

2. **kem_decapsulate() / dsa_sign()**: `mk.kem_sk.to_vec()` / `mk.dsa_sk.to_vec()` が存在するが、これらは即座に `SecureBuffer::new()` に渡されており、`SecureBuffer` が `ZeroizeOnDrop` を実装しているため追加対応不要。

3. **影響範囲**: `verify_hmac()` の Result 化（M-5）は `CryptoEngine::hmac_verify()` の1箇所のみ。呼び出しチェーンの変更は最小限。

4. **H-1 SecretString化**: `Cli.password` のみが対象。`get_password()` の `flag_value` パラメータ変更は `dispatch()` → `get_password()` の呼び出しチェーンに限定される。`password.rs` 内部のロジックは `expose_secret()` で `&str` を取得する1行の変更のみ。

**信頼性への影響**:
- 中間バッファゼロ化の必要箇所が `unlock_with_vault()` 行126-127 の2箇所に限定されることを確認（🔵）
- 類似パターンの `kem_decapsulate()` / `dsa_sign()` は既に `SecureBuffer` で保護済みであることを確認（🔵）
- M-5 verify_hmac の呼び出し元が1箇所のみであることを確認（🔵）
- H-1 の影響範囲が `main.rs` + `password.rs` の2ファイルに限定されることを確認（🔵）
- 全レビュー指摘事項の修正箇所と影響範囲が明確化された（🔵）

---

## ヒアリング結果サマリー

### 確認できた事項
- M-2/M-4: 中間バッファゼロ化は `unlock_with_vault()` 行126-127の2箇所のみ
- M-5: verify_hmac の呼び出し元は `CryptoEngine::hmac_verify()` の1箇所のみ
- H-1: SecretString化の影響は `main.rs` の Cli構造体 + `password.rs` の get_password() に限定
- M-1: `not_implemented()` は `main.rs` の dispatch() 内で10箇所以上呼ばれるが、シグネチャは変わらない（内部実装のみ変更）
- M-3: PQCピン固定は `core/Cargo.toml` の2行のみ変更
- メモリロック: `mlock_buffer`/`munlock_buffer` は `secure_mem.rs` に追加、呼び出しは `crypto/mod.rs` の unlock/lock
- プロセス硬化: `main.rs` の `main()` 先頭に2関数追加（既存ロジックへの影響なし）

### 設計方針の決定事項
- `mlock` 失敗時は警告 + 続行（fail-soft）。非特権ユーザーを排除しない
- デバッガー検出は警告のみ。強制終了はしない（正当なデバッグ用途を妨げない）
- `not_implemented()` は `bail!` に変更し、ZeroizeOnDrop を確実に実行
- HMAC/署名検証は読み取りパス（get_entry, list_entries）に追加
- PQCコミットハッシュは実装時に `git ls-remote` で取得
- E2Eテストは既存コマンドフローの全網羅を目指す

### 残課題
- なし（全項目確認済み）

### 信頼性レベル分布

**ヒアリング前**:
- 🔵 青信号: 全件（レビュー指摘事項の修正方針は明確）

**ヒアリング後**:
- 🔵 青信号: 全件（影響範囲の限定性を確認。全設計判断が確定）

## 関連文書

- **アーキテクチャ設計**: [architecture.md](architecture.md)
- **データフロー**: [dataflow.md](dataflow.md)
- **型定義**: [types.rs](types.rs)
