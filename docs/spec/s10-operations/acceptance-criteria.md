# S10 運用機能 + CLI整合性 受け入れ基準

**作成日**: 2026-05-17
**関連要件定義**: [requirements.md](requirements.md)
**関連ユーザストーリー**: [user-stories.md](user-stories.md)
**ヒアリング記録**: [interview-record.md](interview-record.md)

**【信頼性レベル】**: 全項目🔵 (PRD + ヒアリング 2026-05-17 確定提案 A〜J + 既存実装パターンで確定済み)

---

## REQ-101 〜 REQ-112: init コマンド 🔵

### Given（前提条件）
- `~/.pq-diary/` が存在しない (or `config.toml` が無い)
- TTY または `PQ_DIARY_PASSWORD` 環境変数 / `--password` フラグでパスワードが提供される

### When（実行条件）
- `pq-diary init` を実行

### Then（期待結果）
- `~/.pq-diary/config.toml` (AppConfig) が作成される
- `~/.pq-diary/vaults/default/vault.pqd` `vault.toml` `entries/` が作成される
- default vault のポリシーが `none` に設定される
- 成功メッセージが表示され exit 0

### テストケース

#### 正常系

- [ ] **TC-101-01**: クリーンな環境で `pq-diary init` 実行 → config.toml と default vault が作成される 🔵
  - 入力: TTY で新パスワード "Test123!"
  - 期待結果: `~/.pq-diary/config.toml` 作成、`~/.pq-diary/vaults/default/vault.pqd` 作成、ポリシー `none`、exit 0
- [ ] **TC-101-02**: `PQ_DIARY_PASSWORD=Test123! pq-diary init` で TTY なし初期化 🔵
  - 期待結果: 同上
- [ ] **TC-101-03**: init 完了後 `pq-diary new "test"` が default vault に書き込める 🔵
  - 期待結果: AppConfig の default_vault が読まれ、`vaults/default/entries/` にエントリ追加

#### 異常系

- [ ] **TC-101-E01**: 既に `~/.pq-diary/config.toml` が存在する状態で `init` 実行 🔵
  - 期待結果: `Error: Already initialized at ~/.pq-diary/`、exit ≠ 0、既存データ無変更
- [ ] **TC-101-E02**: 新パスワード空文字で `init` 実行 🔵
  - 期待結果: `Error: Password must not be empty`、何もファイルが作成されない
- [ ] **TC-101-E03**: `~/.pq-diary/` の親に書き込み権限が無い場合 🔵
  - 期待結果: `Cannot create config directory: Permission denied`、exit ≠ 0
- [ ] **TC-101-E04**: vault 作成途中で書き込みエラーが発生 🔵
  - 期待結果: 作成済みの config.toml と部分ディレクトリが zeroize 削除される

#### 境界値

- [ ] **TC-101-B01**: init 完了時間が 3 秒以内 (NFR-001) 🔵
  - 測定: Argon2id memory_cost_kb=65536, time_cost=3 設定で計測
  - 期待結果: < 3000ms

---

## REQ-201 〜 REQ-212: sync コマンド 🔵

### Given（前提条件）
- `pq-diary init` 済み
- AppConfig に `sync_backend` 設定がある (または省略)
- 対象 vault が git-init 済み (sync 実行のため)

### When（実行条件）
- `pq-diary sync` を実行

### Then（期待結果）
- `sync_backend` の値に応じて適切なバックエンドが呼ばれる

### テストケース

#### 正常系

- [ ] **TC-201-01**: `sync_backend = "git"` で `cmd_git_sync` が呼ばれる 🔵
- [ ] **TC-201-02**: `sync_backend` 省略時もデフォルト `"git"` で動作 (REQ-212) 🔵
- [ ] **TC-201-03**: `pq-diary sync` が `git-sync` と同じ pull→push 動作をする 🔵

#### 異常系

- [ ] **TC-201-E01**: `sync_backend = "github"` (未知の値) でエラー停止 🔵
  - 期待結果: `Error: Unknown sync backend: github`、exit ≠ 0
- [ ] **TC-201-E02**: AppConfig 未作成状態で `sync` 実行 🔵
  - 期待結果: `Error: pq-diary init を先に実行してください`、exit ≠ 0
- [ ] **TC-201-E03**: AppConfig が破損 (TOML パースエラー) 🔵
  - 期待結果: `Error: Invalid config.toml: {detail}`、exit ≠ 0

---

## REQ-301 〜 REQ-314: change-password コマンド 🔵

### Given（前提条件）
- 既存 vault が旧パスワード "Old123!" で作成済み
- vault にエントリが 0 件以上ある
- ディスクに十分な空き容量

### When（実行条件）
- `pq-diary change-password` を実行

### Then（期待結果）
- 全エントリと vault ヘッダーが新パスワードで再暗号化される
- vault.pqd がアトミックに差し替わる
- 新パスワードでの unlock が成功する
- 旧パスワードでの unlock が失敗する

### テストケース

#### 正常系

- [ ] **TC-301-01**: 空 vault (エントリ 0 件) で change-password 成功 🔵
  - 入力: 旧 "Old123!" 新 "New456!"
  - 期待結果: 旧で unlock 失敗、新で unlock 成功
- [ ] **TC-301-02**: 3 エントリ vault で change-password 成功、全エントリが新パスワードで読める 🔵
- [ ] **TC-301-03**: change-password 後、`pq-diary list` でエントリタイトル・タグが旧と完全一致 🔵
- [ ] **TC-301-04**: change-password 後、`pq-diary show <id>` で本文が完全一致 🔵
- [ ] **TC-301-05**: 100 エントリ vault で 30 秒以内に完了 (NFR-003) 🔵

#### 異常系

- [ ] **TC-301-E01**: 旧パスワード不正 → vault.pqd 無変更で停止 🔵
  - 期待結果: `Error: Old password is incorrect`、`vault.pqd` の mtime 不変
- [ ] **TC-301-E02**: 新パスワード空 → vault.pqd 無変更で停止 🔵
- [ ] **TC-301-E03**: 新パスワード 2 回入力が一致しない → vault.pqd 無変更で停止 🔵
  - 期待結果: `Error: Passwords do not match`
- [ ] **TC-301-E04**: 再暗号化中にディスクフルで失敗 🔵
  - 期待結果: `vault.pqd.tmp` が zeroize 削除される、旧 `vault.pqd` 維持
- [ ] **TC-301-E05**: change-password 実行中に SIGINT (Ctrl+C) 受信 🔵
  - 期待結果: メモリの新旧鍵が zeroize される (Drop)、旧 `vault.pqd` が無傷

#### 境界値

- [ ] **TC-301-B01**: 新旧パスワード同一 → 警告表示するが処理続行 (REQ-314) 🔵
  - 期待結果: `Warning: New password is identical to old password.` 表示、change-password 成功
- [ ] **TC-301-B02**: 1MB の大きな本文を持つエントリでも再暗号化成功 🔵

---

## REQ-401 〜 REQ-412: info コマンド 🔵

### Given（前提条件）
- vault が存在し、エントリが N 件ある
- 正しいパスワードが提供される

### When（実行条件）
- `pq-diary info` または `pq-diary info --security` を実行

### Then（期待結果）
- vault の基本情報 (or セキュリティ詳細を含む) が表示される
- exit 0

### テストケース

#### 正常系

- [ ] **TC-401-01**: `info` で vault 名・ポリシー・エントリ数・作成日時・最終更新日時が表示 🔵
- [ ] **TC-401-02**: `info` 出力に "Entries: 3" が含まれる (3 エントリ vault の場合) 🔵
- [ ] **TC-401-03**: `info` 応答時間が 100ms 以内 (NFR-002) 🔵
- [ ] **TC-411-01**: `info --security` で REQ-401 の項目に加えて Argon2 パラメータが表示 🔵
- [ ] **TC-411-02**: `info --security` で KEM "ML-KEM-768" / 署名 "ML-DSA-65" が表示 🔵
- [ ] **TC-412-01**: `info --security` で `mlock active: yes/no` が実際の状態を反映 🔵
- [ ] **TC-412-02**: `info --security` で `coredump disabled: yes/no` が実際の状態を反映 🔵
- [ ] **TC-412-03**: `info --security` で `debugger detected: yes/no` が実際の状態を反映 🔵

#### 異常系

- [ ] **TC-401-E01**: パスワード不正 → `Error: Vault unlock failed` 🔵
- [ ] **TC-401-E02**: vault.toml 破損 → `Invalid vault.toml: {error}` (EDGE-006) 🔵

---

## REQ-501 〜 REQ-521: export コマンド 🔵

### Given（前提条件）
- vault が存在し、エントリが N 件ある
- 出力ディレクトリが存在し書き込み可能

### When（実行条件）
- `pq-diary export <DIR>` を実行
- 警告プロンプトに `y` を入力

### Then（期待結果）
- 全エントリが `{DIR}/{YYYY-MM-DD}-{slug}-{id8}.md` 形式で書き出される
- YAML フロントマターでメタデータが保持される

### テストケース

#### 正常系

- [ ] **TC-501-01**: 3 エントリ vault で export → 3 ファイルが指定ディレクトリに作成 🔵
- [ ] **TC-501-02**: 出力ファイル名が `YYYY-MM-DD-slug-id8.md` 形式 🔵
- [ ] **TC-503-01**: 出力 MD の先頭に YAML フロントマター (title, tags, created, updated, id) がある 🔵
- [ ] **TC-505-01**: 完了時に `Exported 3 entries to {DIR}` メッセージ表示 🔵
- [ ] **TC-504-01**: 警告プロンプトが `平文を {DIR} に書き出します。続行しますか? [y/N]` 形式で表示 🔵
- [ ] **TC-501-03**: 1000 エントリ vault で 10 秒以内に完了 (NFR-004) 🔵

#### 異常系

- [ ] **TC-511-01**: `--claude` フラグ付きで export 実行 → 完全ブロック 🔵
  - 期待結果: `Error: export is not permitted with --claude`、何もファイルが作成されない
- [ ] **TC-512-01**: 存在しないディレクトリを指定 → エラー停止 🔵
  - 期待結果: `Error: Directory does not exist: {DIR}`
- [ ] **TC-513-01**: 警告で空入力 (Enter のみ) → キャンセル 🔵
  - 期待結果: `キャンセルしました`、何もファイル作成なし
- [ ] **TC-513-02**: 警告で `n` 入力 → キャンセル 🔵
- [ ] **TC-501-E01**: 出力先に同名ファイル既存 → 上書きせずエラー停止 (EDGE-004) 🔵

#### 境界値

- [ ] **TC-501-B01**: 空 vault (エントリ 0 件) で export → `No entries to export` (EDGE-102) 🔵
- [ ] **TC-501-B02**: タイトル空 / 制御文字のみのエントリ → slug = "untitled" (EDGE-103) 🔵
- [ ] **TC-502-B01**: 同一日付・同一タイトルの 2 エントリ → UUID 8 桁プレフィックスで衰突回避 🔵

---

## REQ-601 〜 REQ-611: AppConfig 🔵

### Given（前提条件）
- `pq-diary init` 実行直後

### When（実行条件）
- `~/.pq-diary/config.toml` を確認

### Then（期待結果）
- TOML として正しくパースできる
- `default_vault = "default"`、`sync_backend = "git"` がデフォルト値

### テストケース

#### 正常系

- [ ] **TC-601-01**: init 直後の config.toml が TOML として valid 🔵
- [ ] **TC-602-01**: init 直後の `default_vault` が `"default"` 🔵
- [ ] **TC-603-01**: init 直後の `sync_backend` が `"git"` 🔵
- [ ] **TC-604-01**: `AppConfig::from_file` で読み書きが round-trip する 🔵
- [ ] **TC-611-01**: Unix で config.toml のパーミッションが `0600` 🔵

#### 異常系

- [ ] **TC-601-E01**: 不正な TOML で `from_file` → `DiaryError::Config` 🔵

---

## REQ-701 〜 REQ-704: DoD 強化 + 未実装スケルトン整理 🔵

### Given（前提条件）
- S10 実装後の CLI

### When（実行条件）
- `pq-diary --help` 表示
- CI smoke test 実行

### Then（期待結果）
- legacy/daemon がヘルプに出ない
- ヘルプに出るすべてのコマンドが正常終了する

### テストケース

#### 正常系

- [ ] **TC-701-01**: `docs/definition-of-done.md` に「CLI 整合性」セクションが存在 🔵
- [ ] **TC-702-01**: `pq-diary --help` 出力に "legacy" "daemon" が含まれない 🔵
- [ ] **TC-702-02**: `pq-diary legacy --help` は (hide でも) 動作する 🔵
- [ ] **TC-703-01**: 残存する `not_implemented()` 呼び出しのメッセージが "Planned for Phase 2" に統一 🔵
- [ ] **TC-704-01**: CI smoke test スクリプトが存在し、`init/new/list/show/search/stats/info/today/sync/change-password/export` の `--help` が exit 0 🔵
- [ ] **TC-704-02**: CI smoke test が `pq-diary init && pq-diary new --body "x" && pq-diary list` の最小フローを通す 🔵

---

## 非機能要件テスト

### NFR-001: init 性能 🔵

- [ ] **TC-NFR-001-01**: init 実行時間が 3 秒以内
  - 測定: Argon2id memory_cost_kb=65536, time_cost=3
  - 目標値: < 3000ms

### NFR-101: change-password メモリ保護 🔵

- [ ] **TC-NFR-101-01**: change-password 後にプロセスメモリダンプを取り、新旧パスワードや平文エントリが残存しないこと
  - 検証手段: ヒープインスペクション or zeroize 呼び出しの単体テスト

### NFR-103: --claude ブロック 🔵

- [ ] **TC-NFR-103-01**: `pq-diary --claude export ./out` が `Error: export is not permitted with --claude` で停止
- [ ] **TC-NFR-103-02**: `pq-diary --claude change-password` が同様にブロック

### NFR-104: info --security 正確性 🔵

- [ ] **TC-NFR-104-01**: mlock が失敗している環境では `mlock active: no` を表示

---

## Edgeケーステスト

- [ ] **TC-EDGE-001-01**: `~/` に書き込み権限なし → init が `Cannot create config directory` 🔵
- [ ] **TC-EDGE-003-01**: change-password 実行中に SIGINT → vault.pqd 維持、tmp 残存可能性あり 🔵
- [ ] **TC-EDGE-005-01**: AppConfig 破損 (TOML エラー) → sync が `Invalid config.toml` 🔵
- [ ] **TC-EDGE-101-01**: 新旧パスワード同一 → 警告表示するが処理続行 🔵
- [ ] **TC-EDGE-102-01**: 空 vault で export → `No entries to export` 🔵
- [ ] **TC-EDGE-103-01**: タイトル空のエントリ export → slug "untitled" 🔵

---

## テストケースサマリー

### カテゴリ別件数

| カテゴリ | 正常系 | 異常系 | 境界値 | 合計 |
|---------|--------|--------|--------|------|
| init (REQ-1xx) | 3 | 4 | 1 | 8 |
| sync (REQ-2xx) | 3 | 3 | 0 | 6 |
| change-password (REQ-3xx) | 5 | 5 | 2 | 12 |
| info (REQ-4xx) | 8 | 2 | 0 | 10 |
| export (REQ-5xx) | 6 | 5 | 3 | 14 |
| AppConfig (REQ-6xx) | 5 | 1 | 0 | 6 |
| DoD (REQ-7xx) | 6 | 0 | 0 | 6 |
| NFR | 4 | 0 | 0 | 4 |
| Edge | 0 | 4 | 2 | 6 |
| **合計** | 40 | 24 | 8 | **72** |

### 信頼性レベル分布

- 🔵 青信号: 72 件 (100%)
- 🟡 黄信号: 0 件
- 🔴 赤信号: 0 件

**品質評価**: 最高品質。全 72 テストケースが PRD・ヒアリング 2026-05-17 (確定提案 A〜J)・既存実装パターンで確定済み。

### 優先度別テストケース

- **Must Have**: 60 件 (init, sync, change-password, info, export, DoD)
- **Should Have**: 12 件 (Edge cases, NFR)

---

## テスト実施計画

### Phase 1: AppConfig + init (Week 10前半)
- REQ-101 ~ REQ-112, REQ-601 ~ REQ-611
- TC-101-* + TC-601-*

### Phase 2: sync + info (Week 10前半)
- REQ-201 ~ REQ-212, REQ-401 ~ REQ-412
- TC-201-* + TC-401-* + TC-411-* + TC-412-*

### Phase 3: change-password (Week 10中盤)
- REQ-301 ~ REQ-314
- TC-301-* (NFR-101, NFR-105 含む)

### Phase 4: export (Week 10中盤)
- REQ-501 ~ REQ-521
- TC-501-* + TC-511-* (NFR-103, NFR-104 含む)

### Phase 5: DoD 強化 + スケルトン整理 (Week 10後半)
- REQ-701 ~ REQ-704
- TC-701-* + smoke test
