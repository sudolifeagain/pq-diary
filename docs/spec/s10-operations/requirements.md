# S10 運用機能 + CLI整合性 要件定義書

## 概要

Phase 1 で CLI スケルトンとしてのみ存在し未実装だった運用系コマンド (`init`, `sync`, `change-password`, `info`, `export`) を実装する。あわせて、CLI ヘルプと実装の乖離を防ぐため DoD を強化し、未実装スケルトン (`legacy*`, `daemon*`) をヘルプから隠す。

## 関連文書

- **ヒアリング記録**: [💬 interview-record.md](interview-record.md)
- **ユーザストーリー**: [📖 user-stories.md](user-stories.md)
- **受け入れ基準**: [✅ acceptance-criteria.md](acceptance-criteria.md)
- **コンテキストノート**: [📝 note.md](note.md)
- **PRD**: [requirements.md (v4.0)](../../../requirements.md)

## 機能要件（EARS記法）

**【信頼性レベル】**: 全項目🔵 (PRD + ヒアリング 2026-05-17 確定提案 A〜J + 既存実装パターンで確定済み)

---

### 1. init コマンド

#### 通常要件

- **REQ-101**: システムは `pq-diary init` 実行時、`~/.pq-diary/config.toml` (AppConfig) と `~/.pq-diary/vaults/default/` (デフォルト vault) を作成しなければならない 🔵 *PRD L218 + 2026-05-17 ヒアリング*
- **REQ-102**: システムは `init` 実行前に新パスワードを TTY で取得しなければならない (PQ_DIARY_PASSWORD 環境変数または --password フラグも許容) 🔵 *PRD §4.2 パスワード入力*
- **REQ-103**: システムは `init` で作成する default vault のポリシーを `none` に設定しなければならない 🔵 *2026-05-17 ヒアリング*
- **REQ-104**: システムは `init` 実行成功時、`Initialized pq-diary at {path}` 形式のメッセージを表示しなければならない 🔵 *ヒアリング2026-05-17 確定提案A (既存 `Created vault 'X' at ...` スタイル踏襲)*

#### 条件付き要件

- **REQ-111**: `~/.pq-diary/config.toml` がすでに存在する場合、システムは `init` を `Already initialized at {path}` エラーで拒否しなければならない 🔵 *2026-05-17 ヒアリング*
- **REQ-112**: AppConfig 作成途中で vault 作成に失敗した場合、システムは作成済みの config.toml と部分ディレクトリを zeroize 削除しなければならない 🔵 *ヒアリング2026-05-17 確定提案C + 既存 core/src/vault/writer.rs .tmp+rename パターン*

---

### 2. sync コマンド

#### 通常要件

- **REQ-201**: システムは `pq-diary sync` 実行時、AppConfig の `sync_backend` 値を読み込まなければならない 🔵 *2026-05-17 ヒアリング*
- **REQ-202**: `sync_backend = "git"` の場合、システムは `cmd_git_sync` (既存) を呼び出さなければならない 🔵 *2026-05-17 ヒアリング*
- **REQ-203**: `sync_backend` 値が `git` 以外の場合、システムは `Unknown sync backend: {value}` エラーで停止しなければならない 🔵 *2026-05-17 ヒアリング*

#### 条件付き要件

- **REQ-211**: AppConfig が未作成 (init 未実施) の場合、システムは `Error: pq-diary init を先に実行してください (~/.pq-diary/config.toml が見つかりません)` エラーを返さなければならない 🔵 *ヒアリング2026-05-17 確定提案H*
- **REQ-212**: `sync_backend` フィールドが省略されている場合、システムはデフォルト `"git"` として扱わなければならない 🔵 *2026-05-17 ヒアリング (デフォルト git)*

---

### 3. change-password コマンド

#### 通常要件

- **REQ-301**: システムは `change-password` 実行時、旧パスワードと新パスワードを 2 回 TTY で取得しなければならない (新パスワードは確認入力で 2 回) 🔵 *ヒアリング2026-05-17 確定提案E + PRD L234*
- **REQ-302**: システムは旧パスワードで vault.pqd を復号し、全エントリを `SecretBytes` でメモリ上に保持しなければならない 🔵 *2026-05-17 ヒアリング (vault.pqd 全体アトミック方針)*
- **REQ-303**: システムは新パスワードで Argon2id 鍵を導出し、全エントリと vault ヘッダー (KEM/DSA seed 含む) を再暗号化して `vault.pqd.tmp` に書き出さなければならない 🔵 *2026-05-17 ヒアリング*
- **REQ-304**: システムは `vault.pqd.tmp` 書き出し成功後、`rename(vault.pqd.tmp, vault.pqd)` で原子的に差し替えなければならない 🔵 *2026-05-17 ヒアリング + 既存 writer.rs パターン*
- **REQ-305**: システムは `change-password` 成功時、`Password changed successfully` メッセージを表示しなければならない 🔵 *ヒアリング2026-05-17 確定提案A*

#### 条件付き要件

- **REQ-311**: 旧パスワードが不正な場合、システムは vault.pqd を変更せず `Old password is incorrect` エラーを返さなければならない 🔵 *unlock 失敗時の標準動作*
- **REQ-312**: 新パスワードが空の場合、システムは vault.pqd を変更せず `New password must not be empty` エラーを返さなければならない 🔵 *既存 init_vault のガード参照*
- **REQ-313**: 再暗号化または書き込み失敗時、システムは `vault.pqd.tmp` を zeroize 削除し旧 vault.pqd を維持しなければならない 🔵 *2026-05-17 ヒアリング*
- **REQ-314**: 新旧パスワードが同一の場合、システムは `Warning: New password is identical to old password.` 警告を表示し処理は続行する (ユーザー意図の可能性のため) 🔵 *ヒアリング2026-05-17 確定提案E*

---

### 4. info コマンド

#### 通常要件

- **REQ-401**: システムは `pq-diary info` 実行時、vault 名・ポリシー・エントリ数・作成日時・最終更新日時を表示しなければならない 🔵 *PRD L235*
- **REQ-402**: vault の作成日時は `fs::metadata(vault.pqd).created()` (フォールバック: ctime) から取得しなければならない 🔵 *ヒアリング2026-05-17 確定提案D*
- **REQ-403**: vault の最終更新日時は `fs::metadata(vault.pqd).modified()` (mtime) から取得しなければならない 🔵 *ヒアリング2026-05-17 確定提案D*
- **REQ-404**: システムは `info` 実行時、vault のアンロックを要求しなければならない (エントリ数は vault.pqd ペイロード解析で取得) 🔵 *ヒアリング2026-05-17 確定提案D*

#### 条件付き要件

- **REQ-411**: `--security` フラグ指定時、システムは追加で Argon2 パラメータ (memory_cost_kb, time_cost, parallelism)、KEM アルゴリズム (`ML-KEM-768` 固定)、署名アルゴリズム (`ML-DSA-65` 固定) を表示しなければならない 🔵 *PRD L235 + vault.toml セクション*
- **REQ-412**: `--security` フラグ指定時、システムは追加でメモリ保護状態 (`mlock active: yes/no`)、コアダンプ無効化状態 (`coredump disabled: yes/no`)、デバッガ検知状態 (`debugger detected: yes/no`) を表示しなければならない 🔵 *S9 で実装した security.rs を活用*

---

### 5. export コマンド

#### 通常要件

- **REQ-501**: システムは `pq-diary export <DIR>` 実行時、指定ディレクトリ配下に全エントリを Markdown ファイルで書き出さなければならない 🔵 *PRD L231*
- **REQ-502**: 出力ファイル名は `{YYYY-MM-DD}-{slug}-{id8}.md` 形式とする (YYYY-MM-DD = エントリ作成日、slug = タイトルから生成、id8 = UUID 先頭 8 桁) 🔵 *2026-05-17 ヒアリング*
- **REQ-503**: 出力ファイルの先頭に YAML フロントマターでメタデータを含めなければならない。キー: `id`, `title`, `tags` (配列), `created`, `updated` (ISO 8601) 🔵 *ヒアリング2026-05-17 確定提案F + 既存 core/src/importer.rs の Obsidian YAML フロントマターと対称*
- **REQ-504**: システムは export 実行前に `平文を {DIR} に書き出します。続行しますか? [y/N]` 警告プロンプトを表示しなければならない 🔵 *2026-05-17 ヒアリング*
- **REQ-505**: システムは export 完了時、`Exported {N} entries to {DIR}` メッセージを表示しなければならない 🔵 *ヒアリング2026-05-17 確定提案A*

#### 条件付き要件

- **REQ-511**: `--claude` フラグ指定時、システムは export を完全に拒否し `export is not permitted with --claude` エラーを返さなければならない 🔵 *2026-05-17 ヒアリング*
- **REQ-512**: 出力ディレクトリが存在しない場合、システムは `Error: Directory does not exist: {DIR}` エラーを返さなければならない (`--mkdir` フラグは S10 スコープ外) 🔵 *ヒアリング2026-05-17 確定提案F*
- **REQ-513**: ユーザーが警告プロンプトで `y` 以外を入力した場合、システムは何もせず `キャンセルしました` で終了しなければならない 🔵 *既存 confirm_full_policy パターン参考*

#### 制約要件

- **REQ-521**: 平文書き出しは指定ディレクトリのみで、`/tmp` などの予期しない場所には書かない 🔵 *セキュリティ常識*

---

### 6. AppConfig (~/.pq-diary/config.toml)

#### 通常要件

- **REQ-601**: AppConfig は TOML 形式で、`[app]` セクションに `default_vault: String` と `sync_backend: String` を持つ 🔵 *2026-05-17 ヒアリング*
- **REQ-602**: `default_vault` のデフォルト値は `"default"` とする 🔵 *2026-05-17 ヒアリング*
- **REQ-603**: `sync_backend` のデフォルト値は `"git"` とする 🔵 *2026-05-17 ヒアリング*
- **REQ-604**: AppConfig は `core/src/vault/config.rs` に `AppConfig` 構造体として実装し、`from_file`/`to_file`/`Default` API を提供する 🔵 *ヒアリング2026-05-17 確定提案I + 既存 VaultConfig パターン踏襲*

#### 制約要件

- **REQ-611**: AppConfig ファイルのパーミッションは Unix 系では `set_permissions(0o600)` で設定する 🔵 *ヒアリング2026-05-17 確定提案G + vault.toml と同等のセキュリティ要件*

---

### 7. DoD 強化 + 未実装スケルトン整理

#### 通常要件

- **REQ-701**: `docs/definition-of-done.md` に「CLI 整合性」セクションを追加し、全トップレベルコマンドが `not_implemented` を返さず正常終了することをチェック項目に含める 🔵 *2026-05-17 ヒアリング*
- **REQ-702**: 未実装スケルトン (`legacy*`, `legacy-access`, `daemon*`) に `#[command(hide = true)]` を付与してヘルプから除外する 🔵 *2026-05-17 ヒアリング*
- **REQ-703**: 残った `not_implemented()` 呼び出しのメッセージを `Planned for Phase 2` に統一する 🔵 *2026-05-17 ヒアリング*
- **REQ-704**: CI に CLI smoke test スクリプトを追加し、ヘルプ掲載コマンドが exit 0 で完了することを検証する 🔵 *2026-05-17 ヒアリング*

---

## 非機能要件

### パフォーマンス

- **NFR-001**: `init` コマンドは Argon2id 鍵導出を含めて 3 秒以内に完了しなければならない 🔵 *PRD L712*
- **NFR-002**: `info` コマンド (`--security` なし) は vault アンロック後 100ms 以内に応答しなければならない 🔵 *ヒアリング2026-05-17 確定提案B (list/show 等読み取り系と同等水準)*
- **NFR-003**: `change-password` コマンドはエントリ数 100 件・1KB/件 の vault で 30 秒以内に完了しなければならない 🔵 *ヒアリング2026-05-17 確定提案B (Argon2id 1〜3秒 + AES-GCM 100MB/秒 想定)*
- **NFR-004**: `export` コマンドはエントリ数 1000 件・1KB/件 の vault で 10 秒以内に完了しなければならない 🔵 *ヒアリング2026-05-17 確定提案B (I/O 律速 + AES-GCM 100MB/秒 想定)*

### セキュリティ

- **NFR-101**: `change-password` でメモリ上に保持する旧鍵・新鍵・全エントリは `ZeroizingKey` / `SecretBytes` でラップしなければならない 🔵 *CLAUDE.md Rust 規約*
- **NFR-102**: `export` 出力ファイルは zeroize 削除されないため、ユーザーに警告で明示しなければならない 🔵 *2026-05-17 ヒアリング*
- **NFR-103**: `--claude` フラグ時、`export` / `change-password` は実行されてはならない 🔵 *PRD §4 + 2026-05-17 ヒアリング*
- **NFR-104**: `info --security` で表示する状態は実プロセスの状態を反映しなければならない (ハードコードされた "yes" を返してはならない) 🔵 *セキュリティ機能の正確性*
- **NFR-105**: `change-password` の `vault.pqd.tmp` は失敗時 zeroize 削除しなければならない 🔵 *2026-05-17 ヒアリング*

### ユーザビリティ

- **NFR-201**: 初回ユーザーは `pq-diary init` 一発で使用開始できなければならない (引数なし、対話のみ) 🔵 *2026-05-17 ヒアリング*
- **NFR-202**: `info` 出力は `pq-diary stats` の `=== Vault Statistics ===` ヘッダー + `Label:    value` 左寄せスタイルと統一しなければならない 🔵 *ヒアリング2026-05-17 確定提案J*
- **NFR-203**: `change-password` の新パスワード入力は確認のため 2 回求めなければならない 🔵 *ヒアリング2026-05-17 確定提案E*

---

## Edgeケース

### エラー処理

- **EDGE-001**: `init` で `~/.pq-diary/` の親ディレクトリ (`~`) に書き込み権限がない場合、`Cannot create config directory: {error}` エラーで停止 (std::io::Error を anyhow で包む) 🔵 *ヒアリング2026-05-17 確定提案G*
- **EDGE-002**: `init` で部分ファイルが残った場合、次回 `init` は `Already initialized` で停止。ユーザーが `~/.pq-diary/` を手動削除して再試行する (S9 vault 破損リカバリと同方針) 🔵 *ヒアリング2026-05-17 確定提案C*
- **EDGE-003**: `change-password` 実行中に SIGINT (Ctrl+C) を受けた場合、メモリは Drop で zeroize、`vault.pqd.tmp` は残るが旧 `vault.pqd` 無傷 (S3 のアトミック書き込み設計と整合) 🔵 *ヒアリング2026-05-17 確定提案C*
- **EDGE-004**: `export` 出力ディレクトリの一部ファイルが既存の場合、システムは上書きせず `File exists: {path}` エラーで停止 🔵 *ヒアリング2026-05-17 確定提案F (安全側設計)*
- **EDGE-005**: `sync` で AppConfig が破損 (TOML パースエラー) している場合、`DiaryError::Config(Invalid config.toml: {error})` エラー (既存 core/src/vault/config.rs `from_file` パターン踏襲) 🔵 *ヒアリング2026-05-17 確定提案G*
- **EDGE-006**: `info` で vault.toml が破損している場合、`DiaryError::Config(Invalid vault.toml: {error})` エラー (同上) 🔵 *ヒアリング2026-05-17 確定提案G*

### 境界値

- **EDGE-101**: `change-password` で旧パスワードと新パスワードが完全に同一の場合、`Warning: New password is identical to old password.` を表示するが処理は続行 🔵 *ヒアリング2026-05-17 確定提案E*
- **EDGE-102**: `export` で空 vault (エントリ 0 件) の場合、ディレクトリは作成せず `No entries to export` メッセージのみ表示 🔵 *ヒアリング2026-05-17 確定提案F*
- **EDGE-103**: `export` でタイトルが空 / 制御文字のみの場合、slug は `untitled` とする 🔵 *ヒアリング2026-05-17 確定提案F + 既存 new コマンドの "Untitled" デフォルトと対称*
- **EDGE-104**: `init` で既存の `~/.pq-diary/` ディレクトリがあるが `config.toml` が無い場合、`Already initialized` で停止 (一貫性優先、補正は手動) 🔵 *ヒアリング2026-05-17 確定提案C*

---

## 信頼性レベル分布

- 🔵 青信号: 46 件 (100%)
- 🟡 黄信号: 0 件
- 🔴 赤信号: 0 件

**品質評価**: 最高品質。全項目が PRD・ヒアリング 2026-05-17 (確定提案 A〜J を含む) ・既存実装パターンを参照し確定済み。kairo-design では設計詳細 (アーキテクチャ図・データフロー・擬似コード) に集中可能。
