# s3-vault-storage 要件定義書

## 概要

pq-diaryプロジェクトのVaultフォーマットとストレージ層を実装する。vault.pqd v4バイナリフォーマットの読み書き、vault.toml / config.toml の serde パース、マルチVaultディレクトリ構造、テンプレート格納領域を整備し、後続Sprint (S4-S9) のデータ永続化基盤とする。

## 関連文書

- **ヒアリング記録**: [interview-record.md](interview-record.md)
- **ユーザストーリー**: [user-stories.md](user-stories.md)
- **受け入れ基準**: [acceptance-criteria.md](acceptance-criteria.md)
- **PRD**: [requirements.md](../../requirements.md)
- **S1基盤**: [../s1-foundation/requirements.md](../s1-foundation/requirements.md)
- **S2暗号コア**: [../s2-crypto-core/requirements.md](../s2-crypto-core/requirements.md)

## 機能要件（EARS記法）

**【信頼性レベル凡例】**:
- 🔵 **青信号**: PRD・ユーザヒアリングを参考にした確実な要件
- 🟡 **黄信号**: PRDから妥当な推測による要件
- 🔴 **赤信号**: PRDにない推測による要件

### 通常要件

- REQ-001: システムは vault.pqd v4 バイナリフォーマットのヘッダを読み書きしなければならない。マジックバイト `"PQDIARY\0"` (8B) の検証、スキーマバージョン `0x04` のチェック、フラグ (1B)、予約 (2B)、ペイロードサイズ (LE u32)、KDFソルト (32B)、Legacyソルト (32B)、検証トークンIV (12B)、検証トークン暗号文 (48B)、ML-KEM公開鍵オフセット予約 (32B)、ML-DSA公開鍵ハッシュ (32B)、可変長秘密鍵ブロック、エントリセクション、ランダムパディングを含む完全なファイル構造を処理しなければならない 🔵 *PRDセクション6.1より*

- REQ-002: システムは エントリレコードを読み書きしなければならない。各レコードは レコード長 (4B, 0で終端)、UUID (16B)、作成日時 (u64 LE 8B)、更新日時 (u64 LE 8B)、IV (12B)、暗号文長 (4B)、暗号文+GCMタグ、ML-DSA署名長 (4B)、ML-DSA署名、content_hmac (32B)、legacyフラグ (1B: 0x00=DESTROY / 0x01=INHERIT)、legacy鍵ブロック長 (4B)、legacy鍵ブロック、パディング長 (1B)、ランダムパディングで構成される。添付ファイル予約フィールドとして添付ファイルカウント (u16) + 添付ブロックオフセット (u64) をレコードに含め、Phase 1では0初期化しなければならない 🔵 *PRDセクション6.2 + ADR-0002より*

- REQ-003: システムは テンプレートレコードタイプを実装しなければならない。エントリレコードと同じ構造を持ちつつ、レコードタイプフラグで通常エントリとテンプレートを区別する。テンプレートはvault.pqd内に暗号化格納される 🔵 *ADR-0005より*

- REQ-004: システムは vault.toml を serde + toml クレートでデシリアライズ/シリアライズしなければならない。VaultConfig構造体は `[vault]` (name, schema_version)、`[access]` (policy)、`[git]` (author_name, author_email, commit_message)、`[git.privacy]` (timestamp_fuzz_hours, extra_padding_bytes_max)、`[argon2]` (memory_cost_kb, time_cost, parallelism) セクションを含む。vault.tomlにタイムスタンプフィールドを含めてはならない 🔵 *PRDセクション3.2 + ヒアリングQ2より*

- REQ-005: システムは config.toml を serde + toml クレートでデシリアライズ/シリアライズしなければならない。AppConfig構造体は `[defaults]` (vault)、`[daemon]` (socket_dir, timeout_secs) セクションを含む 🔵 *PRDセクション3.3 + ヒアリングQ2より*

- REQ-006: システムは マルチVaultディレクトリ構造を管理しなければならない。`~/.pq-diary/vaults/{name}/` の作成・探索・一覧を行い、vault init では鍵生成 + vault.pqd作成 + vault.toml作成 + entries/ ディレクトリ作成を一括で実行しなければならない 🔵 *PRDセクション3.1より*

- REQ-007: システムは 検証トークンを生成・検証しなければならない。32Bのランダム平文をAES-GCMで暗号化してvault.pqdヘッダに格納し、unlock時に復号して一致を確認することでパスワード正当性を検証する。S2のCryptoEngineと連携しなければならない 🔵 *PRDセクション6.1より*

- REQ-008: システムは ランダムパディングを付与しなければならない。vault.pqdファイル末尾に512〜4096Bのランダムパディング、各エントリレコードに0〜255Bのランダムパディングを付与し、ファイルサイズからエントリ数や内容量を推測困難にしなければならない 🔵 *PRDセクション6.1, 9.1より*

### 制約要件

- REQ-401: バイナリシリアライズは自前実装としなければならない。bincode等の外部クレートを使用してはならない 🔵 *PRDセクション12.3より*
- REQ-402: `strings vault.pqd` コマンドでフィールド名・アルゴリズム名が露出してはならない 🔵 *PRDセクション6.1より*
- REQ-403: vault.tomlにタイムスタンプフィールドを含めてはならない 🔵 *PRDセクション3.2 v4.0変更より*
- REQ-404: S2で定義した `CryptoEngine` / `SecureBuffer` / `ZeroizingKey` を使用しなければならない 🔵 *S2設計より*

## 非機能要件

### 性能

- NFR-001: vault init 操作（鍵生成含む）は3秒以内に完了しなければならない 🔵 *PRDセクション12.1より*
- NFR-002: vault.toml / config.toml のパースは100ms以内に完了しなければならない 🔵

## エッジケース

### エラー処理

- EDGE-001: 不正マジックバイト（`"PQDIARY\0"` でないファイル）の場合、`DiaryError::Vault` を返すこと 🔵
- EDGE-002: 不正スキーマバージョン（`0x04` でないバージョン）の場合、`DiaryError::Vault` を返すこと 🔵
- EDGE-003: vault.tomlが存在しない場合、デフォルト値で自動生成すること 🔵
- EDGE-004: config.tomlが存在しない場合、デフォルト値で自動生成すること 🔵
- EDGE-005: 空のvault.pqd（エントリなし）の場合、正常に読み込めること 🔵
- EDGE-006: 破損したエントリレコードの場合、`DiaryError::Vault` を返し、当該レコードをスキップして後続レコードの読み込みを試行すること 🔵
