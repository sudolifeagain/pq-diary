# S10 運用機能 + CLI整合性 ヒアリング記録

**作成日**: 2026-05-17
**ヒアリング実施**: step4 既存情報ベースの差分ヒアリング

## ヒアリング目的

Phase 1 完了後の動作確認で判明した「ヘルプに出るが未実装のコマンド」を整理し、S10 のスコープを確定するためのヒアリングを実施した。

## 質問と回答

### Q1: 動作確認の後、次に進める方向は?

**質問日時**: 2026-05-17
**カテゴリ**: 優先順位
**背景**: Phase 1 (S1-S9) は phase1-done タグ付与済みで完了状態。動作確認で4つの未実装コマンド (init/info/export/change-password) を発見。次に何を進めるか方向性を確認する必要があった。

**回答**: 「S10: Phase 2 着手 (要テーマ選定)」を選択。クロスプラットフォーム検証 (Phase 1 唯一の未完了) は後回しで Phase 2 のテーマを選ぶ。

**信頼性への影響**:
- S10 着手が確定 (信頼性: 🔵)

---

### Q2: S10 のテーマは?

**質問日時**: 2026-05-17
**カテゴリ**: スコープ決定
**背景**: Phase 2 バックログから 4 つの候補テーマを提示。

**回答**: 「運用機能: change-password + info --security + export」を選択。

**信頼性への影響**:
- S10 のコアスコープ確定 (信頼性: 🔵)

---

### Q3: 未実装のコマンドが他にもないか?

**質問日時**: 2026-05-17
**カテゴリ**: スコープ確認
**背景**: 動作確認で 3 つ (info/export/change-password) 以外にも未実装が無いか念のため確認。

**回答**: `init` (Sprint 2 と表示) と `sync` (Sprint 8 と表示) も未実装で残っていた。

**追加された要件**:
- `init` を S10 で新規実装する (PRD L218, L712 で規定された必須機能)
- `sync` を S10 で新規実装する (PRD L230, L262 で `git-sync` と別物として規定)

**信頼性への影響**:
- スコープが 5 機能に拡大 (信頼性: 🔵)

---

### Q4: tsumiki のドキュメントに「未実装コマンドの監視」の規定はあるか?

**質問日時**: 2026-05-17
**カテゴリ**: 開発プロセス改善
**背景**: ヘルプに出るのに動かないコマンドが残ったのはなぜか、再発防止策があるかの確認。

**回答**: workflow.md / definition-of-done.md には規定なし。tsumiki コマンドにも「ヘルプと実装の整合性チェック」は無い。DoD 強化が必要。

**追加された要件**:
- `docs/definition-of-done.md` に「CLI 整合性」セクションを追加 (REQ-701)
- 未実装スケルトンは `#[command(hide = true)]` でヘルプから隠す (REQ-702)
- CI に smoke test スクリプトを追加 (REQ-704)

**信頼性への影響**:
- DoD 強化が S10 スコープに追加 (信頼性: 🔵)

---

### Q5: `init` と `vault create` の責務分担は?

**質問日時**: 2026-05-17
**カテゴリ**: 設計判断
**背景**: PRD には両方記載されているが役割の説明がない。統合すべきか切り分けるべきかの判断が必要。

**回答**: 「切り分け」を選択。`init` = 初回セットアップ (config.toml + default vault)、`vault create` = 追加 vault 作成として責務を分離。

**信頼性への影響**:
- `init` の仕様確定 (REQ-101 〜 REQ-112、信頼性: 🔵)
- `vault create` は変更なし

---

### Q6: 要件定義の作業規模は?

**質問日時**: 2026-05-17
**カテゴリ**: スコープ調整
**背景**: kairo-requirements の作業規模を選択。

**回答**: 「フル機能開発」を選択。詳細 EARS / 包括的ユーザーストーリー / 完全な受け入れ基準 / 非機能要件 / エッジケース含む。

**信頼性への影響**:
- 要件定義の網羅性が向上 (信頼性: 🔵)

---

### Q7: 既存コードベースの詳細分析を実施するか?

**質問日時**: 2026-05-17
**カテゴリ**: 調査方針
**背景**: kairo-requirements step3 で既存コードベース分析の要否を確認。

**回答**: 「必要」を選択。Explore agent または直接 Grep/Read で関連 API の現状を調査。

**信頼性への影響**:
- `init_vault` メソッドが既に core 側に存在することを発見 (S10 で再利用可能)
- AppConfig (config.toml) は未実装と判明 (S10 で新規実装が必要)

---

### Q8: AppConfig (~/.pq-diary/config.toml) は S10 で新規実装するか?

**質問日時**: 2026-05-17
**カテゴリ**: 設計判断
**背景**: コードベース調査で AppConfig が未実装と判明。`init` と `sync` の両方が AppConfig に依存するため、設計判断が必要。

**回答**: 「S10 で新規実装」を選択。`~/.pq-diary/config.toml` に `default_vault` と `sync_backend` を持つ AppConfig 構造体を追加。

**追加された要件**:
- REQ-601 〜 REQ-611 (AppConfig 仕様)

**信頼性への影響**:
- AppConfig の仕様確定 (信頼性: 🔵)

---

### Q9: change-password のアトミック性はどの粒度?

**質問日時**: 2026-05-17
**カテゴリ**: 設計判断
**背景**: 中断時の vault 破損を防ぐ実装方式の判断。

**回答**: 「vault.pqd 全体」を選択。新パスワードで全エントリを再暗号化した vault.pqd.tmp を作成 → rename でアトミック差し替え。中断時は旧 vault.pqd が無傷。

**信頼性への影響**:
- change-password のアトミック性仕様確定 (REQ-302 〜 REQ-304, REQ-313, 信頼性: 🔵)

---

### Q10: export のファイル名規約と衰突対策は?

**質問日時**: 2026-05-17
**カテゴリ**: 設計判断
**背景**: 同一日付・同一タイトルのエントリが複数ある場合のファイル名衰突回避。

**回答**: 「`YYYY-MM-DD-{slug}-{id8}.md` デフォルトで UUID プレフィックス」を選択。安全側設計。

**信頼性への影響**:
- export のファイル名仕様確定 (REQ-502, 信頼性: 🔵)

---

### Q11: 黄信号項目を全て🔵 に格上げするための確定提案 (A〜J) の一括承認

**質問日時**: 2026-05-17
**カテゴリ**: 信頼性向上 / 確定提案承認
**背景**: requirements.md / user-stories.md / acceptance-criteria.md に残った黄信号 (推測扱い) 項目を全て🔵 に格上げするため、10 カテゴリの確定提案を一括提示し承認を得た。

**確定提案カテゴリ**:
- **A. メッセージ文言**: `Initialized pq-diary at {path}`, `Password changed successfully`, `Exported {N} entries to {DIR}`, `Warning: New password is identical to old password.` (既存スタイル踏襲)
- **B. 性能目標値**: info < 100ms / change-password < 30秒 (100エントリ・1KB/件) / export < 10秒 (1000エントリ・1KB/件)
- **C. アトミック性・リカバリ**: init 失敗時の zeroize 削除 / 部分残りは `Already initialized` で停止 / change-password SIGINT 中断時の旧 vault.pqd 維持 / 既存ディレクトリ補正は手動
- **D. メタデータ取得**: `fs::metadata(vault.pqd).created()/modified()` / info でアンロック要求
- **E. change-password UX**: 新パスワード 2 回入力 / 新旧同一は警告して続行
- **F. export 形式**: YAML フロントマター (id, title, tags, created, updated) / ディレクトリ未存在エラー / 空 vault は `No entries to export` / タイトル空は slug="untitled"
- **G. エラー処理**: 既存 `DiaryError::Config` / `set_permissions(0o600)` パターン踏襲
- **H. sync 細部**: 未 init 時の具体的エラーメッセージ
- **I. AppConfig 設計**: 既存 VaultConfig パターン踏襲
- **J. UX 統一**: stats の `=== Vault Statistics ===` ヘッダー + 左寄せスタイル統一

**回答**: 「全部これで OK」一括承認。

**信頼性への影響**:
- requirements.md: 18 件の🟡 → 🔵 (28 件 → 46 件)
- user-stories.md: 1 件の🟡 → 🔵 (12 件 → 13 件)
- acceptance-criteria.md: 25 件の🟡 → 🔵 (47 件 → 72 件)
- **全項目🔵 100% 達成**

---

## ヒアリング結果サマリー

### 確認できた事項

1. S10 着手と Phase 2 への移行 (Phase 1 の取りこぼし「クロスプラットフォーム検証」は後続スプリントへ)
2. S10 のコアスコープは運用機能 (change-password + info + export)
3. `init` と `sync` も S10 スコープに追加 (Phase 1 取り残し)
4. `init` と `vault create` は責務切り分け方針
5. AppConfig (~/.pq-diary/config.toml) を S10 で新規実装
6. change-password は vault.pqd 全体のアトミック差し替え
7. export ファイル名は UUID プレフィックス付与
8. DoD に「CLI 整合性」セクションを追加し、CI smoke test を追加
9. legacy*/daemon* は `#[command(hide = true)]` でヘルプから隠す
10. 残存 `not_implemented()` メッセージは "Planned for Phase 2" に統一

### 追加/変更要件

- **追加**: `init` 仕様 (REQ-101 〜 REQ-112)
- **追加**: `sync` 仕様 (REQ-201 〜 REQ-212)
- **追加**: AppConfig 仕様 (REQ-601 〜 REQ-611)
- **追加**: DoD 強化 (REQ-701 〜 REQ-704)
- **変更**: 当初想定の S10 (change-password + info + export 3 機能) から、init + sync + AppConfig + DoD 強化を加えた 7 項目に拡大

### 残課題

- `change-password` の新パスワード入力プロンプトのメッセージ文言 → 実装時に確定
- `info` 出力の具体的フォーマット (整列幅、色付け有無) → 実装時に確定
- export の YAML フロントマター形式の具体的キー名 → 設計フェーズ (kairo-design) で確定
- `info --security` の出力で「KEM アルゴリズム」が "ML-KEM-768" 固定で良いか (将来 HQC 対応で変化する可能性) → Phase 4 で再考

### 信頼性レベル分布

**ヒアリング前 (会話開始時点)**:
- 🔵 青信号: 0 件 (要件定義書未作成)
- 🟡 黄信号: 0 件
- 🔴 赤信号: 0 件

**ヒアリング Q1-Q10 完了時点**:
- 🔵 青信号: 28 件 (60%)
- 🟡 黄信号: 18 件 (38%)
- 🔴 赤信号: 0 件

**Q11 (確定提案 A〜J 一括承認) 後の最終状態**:
- 🔵 青信号: 46 件 + 13 件 (ストーリー) + 72 件 (テストケース) = **全 131 項目 100%**
- 🟡 黄信号: 0 件
- 🔴 赤信号: 0 件

## 関連文書

- **要件定義書**: [requirements.md](requirements.md)
- **ユーザストーリー**: [user-stories.md](user-stories.md)
- **受け入れ基準**: [acceptance-criteria.md](acceptance-criteria.md)
- **コンテキストノート**: [note.md](note.md)
