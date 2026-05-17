# S13 添付ファイル 要件定義書

**作成日**: 2026-05-18
**スプリント**: S13

## 概要

エントリに任意のバイナリファイル (画像・PDF・音声等) を紐付けて
暗号化保存・取り出し・エクスポート/インポートできる機能を追加する。
vault.pqd v4 で予約済みフィールド (`attachment_count` / `attachment_offset`)
を本実装する。

## 関連文書

- **ヒアリング記録**: [💬 interview-record.md](interview-record.md)
- **ユーザストーリー**: [📖 user-stories.md](user-stories.md)
- **受け入れ基準**: [✅ acceptance-criteria.md](acceptance-criteria.md)
- **コンテキストノート**: [📝 note.md](note.md)
- **PRD**: [requirements.md](../../../requirements.md) §10 / Phase 2
- **設計**: [📐 architecture.md](../../design/s13-attachments/architecture.md)

## 機能要件 (EARS記法)

**【信頼性レベル凡例】**:
- 🔵 PRD・既存実装・ユーザヒアリングを参考にした確実な要件
- 🟡 PRD・既存実装・ユーザヒアリングから妥当な推測による要件
- 🔴 推測のみ

### 通常要件 — ファイル追加 (add)

- REQ-101: システムは `pq-diary attachment add <ENTRY_ID> <FILE>` で
  指定エントリに任意のバイナリファイルを添付しなければならない 🟡 *backlog 由来・vault.pqd 予約フィールド設計*
- REQ-102: システムは添付ファイルを AES-256-GCM で暗号化し、
  `<vault_dir>/.attachments/<file_uuid>.bin` として保存しなければならない 🟡 *ヒアリング Q2 (vault.pqd + .attachments/) 確定*
- REQ-103: システムは添付ファイルのメタデータ (ファイル名、MIME type、
  サイズ、SHA-256、追加時刻) を vault.pqd 内の attachment レコードとして保存しなければならない 🟡 *vault.pqd v4 予約フィールド活用、既存パターン踏襲*
- REQ-104: システムは 1 ファイルあたり最大 1GB までの添付を許可しなければならない 🔵 *ヒアリング Q1 確定*
- REQ-105: システムは添付ファイル本体を 1MB chunk 単位で
  AES-256-GCM ストリーミング暗号化しなければならない 🟡 *NFR-001 (メモリ使用量) からの推測*

### 通常要件 — ファイル一覧 / 取得 (list / extract)

- REQ-201: システムは `pq-diary attachment list <ENTRY_ID>` で
  指定エントリに紐付く全添付のファイル名・サイズ・追加時刻を表示しなければならない 🟡 *list コマンドの自然な拡張*
- REQ-202: システムは `pq-diary attachment extract <ENTRY_ID> <FILE_NAME> --out <PATH>` で
  指定添付を復号して `<PATH>` に書き出さなければならない 🟡 *show ではバイナリ不可なので extract 必須*
- REQ-203: システムは復号時にエントリの ML-DSA-65 署名と添付の SHA-256 を検証し、
  改ざんを検出した場合エラーを返さなければならない 🔵 *既存 entry CRUD の検証パターン踏襲*

### 通常要件 — ファイル削除 (delete)

- REQ-301: システムは `pq-diary attachment delete <ENTRY_ID> <FILE_NAME>` で
  添付メタデータと本体ファイル両方を削除しなければならない 🟡 *delete 系の自然な拡張*
- REQ-302: システムは削除時に `.attachments/<file_uuid>.bin` を zeroize 上書きしてから削除しなければならない 🔵 *既存 vault::delete_vault の zeroize パターン*

### 通常要件 — 既存コマンド統合

- REQ-401: システムは `pq-diary new --attach <FILE>` で
  新規エントリ作成と同時に添付追加を行えなければならない 🟡 *コマンドライン UX 効率化*
- REQ-402: システムは `pq-diary show <ENTRY_ID>` で
  紐付く添付ファイル数とファイル名一覧をエントリ本文と共に表示しなければならない 🟡 *show の自然な拡張*

### 条件付き要件 — Legacy 連動 (S12)

- REQ-501: `pq-diary attachment set <ENTRY_ID> <FILE_NAME> --inherit | --destroy` で
  添付ファイル個別に legacy フラグを設定できなければならない 🟡 *ヒアリング Q3 (ファイル個別フラグ) 確定*
- REQ-502: INHERIT フラグが立っている添付について、システムは
  K_legacy で暗号化したアクセスブロックを attachment レコードに保存しなければならない 🟡 *S12 と同じパターン*
- REQ-503: `legacy-access` 実行時、INHERIT 添付のみを新 vault に継承し、
  DESTROY 添付の `.attachments/<uuid>.bin` を zeroize 上書きして削除しなければならない 🟡 *S12 セマンティクスの拡張*
- REQ-504: エントリが DESTROY のとき、紐付く全添付も自動的に DESTROY 扱いとしなければならない 🟡 *データ整合性*

### 通常要件 — Export / Import

- REQ-601: システムは `pq-diary export <DIR>` で
  添付ファイルを `<DIR>/attachments/<file_name>` に復号して書き出さなければならない 🟡 *ヒアリング Q4 (export 別ディレクトリ) 確定*
- REQ-602: システムは export 時、Markdown 内の添付参照を
  Obsidian 互換の `![[file_name]]` 形式で出力しなければならない 🟡 *ヒアリング Q4 (Obsidian 互換) 確定*
- REQ-603: システムは `pq-diary import <DIR>` で
  `<DIR>/attachments/` フォルダをスキャンし、Markdown 内の `![[...]]` リンクを
  対応する添付ファイルにリンクして取り込まなければならない 🟡 *ヒアリング Q4 (双方向) 確定*
- REQ-604: import 時、同一 SHA-256 を持つ添付が既に存在する場合は
  本体ファイル書き込みをスキップし、メタデータレコードのみ追加しなければならない 🟡 *重複排除*

### 状態要件

- REQ-701: vault が `--claude` 起動の場合、システムは
  attachment add / extract / delete / set コマンドを全て拒否しなければならない 🔵 *S10 / S12 と同じセキュリティ規則*
- REQ-702: `change-password` 実行時、システムは
  vault.pqd の attachment メタデータレコードを新 K_master で再暗号化しなければならない 🟡 *S10 既存パターン拡張*

### オプション要件

- REQ-801: システムは `pq-diary new --attach <FILE1> --attach <FILE2>` のように
  複数添付を一度に行えてもよい 🟡 *UX 改善*

### 制約要件

- REQ-901: 添付ファイル本体は `.attachments/<file_uuid>.bin` の単一階層で保管しなければならない 🟡 *シンプルさ優先*
- REQ-902: 添付メタデータは entry record の `attachment_offset` フィールドで指される
  vault.pqd 内の attachment レコード群 (`RECORD_TYPE_ATTACHMENT=0x03`) として保存しなければならない 🟡 *v4 予約フィールド活用、既存パターン拡張*

## 非機能要件

### パフォーマンス

- NFR-001: 100MB ファイルの add は 60 秒以内に完了しなければならない 🟡 *Argon2 や ML-DSA は使わず AES-GCM のみなので妥当*
- NFR-002: メモリピーク使用量は (chunk size + 既存 vault サイズ) を超えてはならない 🟡 *streaming 設計*
- NFR-003: 1GB ファイルの extract は 5 分以内に完了しなければならない 🟡 *AES-GCM 復号速度ベースの推測*

### セキュリティ

- NFR-101: 添付ファイル本体の暗号化に使う chunk IV は OsRng で生成し、
  chunk index を AAD に含めて再利用検出を可能にしなければならない 🟡 *AES-GCM IV 再利用回避*
- NFR-102: 添付の chunk plaintext は全て Zeroizing<Vec<u8>> または
  ZeroizeOnDrop 構造体で保持しなければならない 🔵 *CLAUDE.md ルール*
- NFR-103: 添付ファイル全体の SHA-256 を計算し、attachment レコードに保存して
  改ざん検出に使わなければならない 🟡 *データ整合性*
- NFR-104: 添付ファイル全体の ML-DSA-65 署名は entry record の signature と同等の検証対象としなければならない 🟡 *署名対象拡大、S2 暗号設計と整合*

### ユーザビリティ

- NFR-201: 添付ファイル一覧表示は人間が読みやすい形式 (サイズを KB/MB 表示、追加日 YYYY-MM-DD) でなければならない 🟡 *list 同様の UX*

### スケーラビリティ

- NFR-301: 1 エントリあたり 256 個までの添付を許容しなければならない (u16 範囲だが現実的上限を設ける) 🟡 *attachment_count: u16 制約 + 現実的サイズ*

## Edgeケース

### エラー処理

- EDGE-001: 添付対象ファイルが存在しない: `DiaryError::Io` を返し vault は無変更 🔵 *既存パターン*
- EDGE-002: 添付ファイルサイズが 1GB を超える: `DiaryError::InvalidArgument` を返し処理を中止 🟡 *NFR-104 補完*
- EDGE-003: `.attachments/` の書き込み権限不足: `DiaryError::Io` を返し vault は無変更 🟡 *ファイルシステム制約*
- EDGE-004: extract 先パスへの書き込み失敗: tmp ファイル削除して `DiaryError::Io` 🟡 *書き込み失敗時のリカバリ*
- EDGE-005: import 時の `![[FILE]]` リンクで `attachments/FILE` が見つからない:
  警告を出して当該リンクをそのまま残す (entry の取り込みは継続) 🟡 *部分失敗の許容*

### 境界値

- EDGE-101: 0 バイトの空ファイル添付: 許可、attachment レコードは生成、本体は 0 バイトのまま 🟡 *エッジ可用性*
- EDGE-102: 添付ファイル名が長すぎる (>255 chars): 切り詰めるか `DiaryError::InvalidArgument` 🟡 *ファイル名制約*
- EDGE-103: 1 エントリで 256 個目の添付追加: REQ-NFR-301 違反、`DiaryError::InvalidArgument` 🟡 *上限制約*
- EDGE-104: 同名添付の重複追加: SHA-256 一致なら無視、不一致なら `DiaryError::InvalidArgument` 🟡 *データ整合性*

### 並行性 (Phase 1 で 1 プロセス前提)

- EDGE-201: 1 プロセス内のみ動作を保証する (V-1〜V-8 はデーモン化でカバー) 🔵 *PRD 既存制約*

### 後方互換性

- EDGE-301: 既存の Phase 1 vault (attachment_count=0 で書き込まれた entry) は
  読み込み時に `attachment_count=0, attachment_offset=0` のままで動作しなければならない 🔵 *既存 reader 実装*
- EDGE-302: S13 後の vault は古い (S13 以前の) クライアントで `attachment_count != 0` を読んでもエラーにならないが、添付は無視される 🟡 *スキーマ互換性*

## 関連

- [interview-record.md](interview-record.md): ヒアリング詳細
- [user-stories.md](user-stories.md): ユーザストーリー
- [acceptance-criteria.md](acceptance-criteria.md): TC 一覧
- [architecture.md](../../design/s13-attachments/architecture.md)

## 信頼性レベルサマリー

- 🔵 青信号: 8 件 (~17%)
- 🟡 黄信号: 39 件 (~83%)
- 🔴 赤信号: 0 件

**品質評価**: PRD §10 に明示無し (backlog 由来) のため 🟡 が多めになるのは自然。
設計で🔵に向上できる項目: NFR-001/002/003 (実測ベース)、REQ-104 (確定済み)、
REQ-501〜504 (S12 拡張パターン明確化)。
