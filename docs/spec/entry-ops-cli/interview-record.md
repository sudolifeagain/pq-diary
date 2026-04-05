# entry-ops-cli ヒアリング記録

**作成日**: 2026-04-03
**ヒアリング実施**: step4 既存情報ベースの差分ヒアリング

## ヒアリング目的

requirements.md v4.0、ADR-0003/0004、S1-S3実装を確認し、S4「エントリ操作 + CLI」の不明点・曖昧な部分を明確化するためのヒアリングを実施しました。

## 質問と回答

### Q1: エントリの平文フォーマット

**カテゴリ**: 未定義部分詳細化
**背景**: requirements.md §2.3 の公開API `new_entry(title, body, tags)` はメタデータを別引数で受け取る設計だが、$EDITORでの表示形式やObsidianインポート時の互換性方針が未定義。YAML Front Matter / メタデータ分離 / シンプルMarkdownの3案を提示。

**回答**: **メタデータ分離型**を採用。タイトル・タグはEntryRecordのフィールドとして暗号化格納。本文のみMarkdown。

**信頼性への影響**:
- REQ-001〜REQ-005 (Entry CRUD) の信頼性が 🟡 → 🔵 に向上
- $EDITORでの表示形式が確定し、一時ファイル仕様も明確化

---

### Q2: deleteコマンドの確認方式

**カテゴリ**: 未定義部分詳細化
**背景**: requirements.md §4.1 に `delete <ID_PREFIX>` が定義されているが、確認プロンプトの有無・スキップ方法が未記載。Obsidian CLI、nb、jrnlの削除方式を調査して選択肢を提示。

**回答**: **確認プロンプト + `--force`/`-f` でスキップ**。Obsidian CLIのsoft delete（ゴミ箱）は暗号化ジャーナルのセキュリティ要件と矛盾するため不採用。`--claude` フラグ使用時は `--force` 相当とする。

**信頼性への影響**:
- REQ-005 (delete) の信頼性が 🔴 → 🔵 に向上

---

### Q3: ID_PREFIXの最小文字数

**カテゴリ**: 未定義部分詳細化
**背景**: requirements.md §4.1 に `show <ID_PREFIX>` とあるが最小長が未定義。Obsidianはファイル名でノートを識別するためプレフィックスの概念がない（pq-diary固有の設計判断）。

**回答**: **最小4文字**。複数マッチ時はエラーで候補を表示。listコマンドの出力にも4〜8文字のプレフィックスを表示。

**信頼性への影響**:
- REQ-003 (show), REQ-004 (edit), REQ-005 (delete) の信頼性が 🟡 → 🔵 に向上

---

### Q4: listコマンドのデフォルト表示件数

**カテゴリ**: 未定義部分詳細化
**背景**: requirements.md §4.1 に `-n N` オプションがあるがデフォルト値が未記載。

**回答**: **デフォルト20件**。新しい順に表示。`-n` で変更可能。

**信頼性への影響**:
- REQ-002 (list) の信頼性が 🟡 → 🔵 に向上

---

### Q5: Windows環境での$EDITOR一時ファイル制御

**カテゴリ**: 技術制約確認
**背景**: requirements.md §4.3 は `/dev/shm` / `/run/user/$UID/` 等Unix前提の記述。現在の開発環境がWindowsであり、クロスプラットフォーム対応方針が必要。

**回答**: **S4でWindows対応も実装**。`%LOCALAPPDATA%\pq-diary\tmp\` に専用ディレクトリを作成。ACLでオーナーのみRW。zeroize削除も同様。

**信頼性への影響**:
- REQ-007 ($EDITOR制御) のWindows対応が 🔴 → 🔵 に向上

---

### Q6: パスワード入力TTY実装のWindows対応

**カテゴリ**: 技術制約確認
**背景**: ADR-0003はtermios自前実装を決定しているがUnix前提。Bitwarden CLIの実装（inquirer + crossterm）を調査して選択肢を提示。

**回答**: **自前実装 + `#[cfg]` 分岐**。Unix: termios (ECHO無効化)、Windows: SetConsoleMode (ENABLE_ECHO_INPUT無効化)。入力を直接SecretStringに格納。ADR-0003の方針を維持。

**信頼性への影響**:
- REQ-006 (パスワード入力) のWindows対応が 🔴 → 🔵 に向上

---

### Q7: newコマンドの本文入力優先順位

**カテゴリ**: 未定義部分詳細化
**背景**: requirements.md §4.1 に `-b BODY` オプションがあるが、stdin（パイプ入力）や$EDITOR起動との優先順位が未定義。

**回答**: **`-b` > stdin > `$EDITOR`** の優先順位。`-b` フラグ指定時は即座にエントリ作成。パイプ入力があれば本文として取り込み。どちらもなければ$EDITORを起動。

**信頼性への影響**:
- REQ-001 (new) の信頼性が 🟡 → 🔵 に向上

---

### Q8: editコマンドの$EDITOR表示内容

**カテゴリ**: 未定義部分詳細化
**背景**: メタデータ分離型を採用したが、$EDITORでの編集時にタイトル・タグをどう表示・編集するかが未定義。git commit / crontab -e / kubectl edit 等の既存パターンを分析。

**回答**: **ヘッダーコメント形式 + CLIフラグ併用**。$EDITORでは `# Title:` / `# Tags:` / `# ---` ヘッダー付きで全編集可能。CLIフラグ（`--title`, `--add-tag`）でもエディタなしで個別変更可能。

**信頼性への影響**:
- REQ-004 (edit) の信頼性が 🔴 → 🔵 に向上

---

## ヒアリング結果サマリー

### 確認できた事項
- エントリのデータモデル（メタデータ分離型、暗号化フィールドとしてtitle/tags/body格納）
- 全CRUDコマンドの具体的な動作仕様
- パスワード入力のクロスプラットフォーム実装方式
- $EDITOR連携の一時ファイル仕様（Unix + Windows）
- IDプレフィックスの最小長と表示方式

### 追加/変更要件
- `--force`/`-f` フラグをdeleteコマンドに追加
- edit コマンドに `--title`, `--add-tag`, `--remove-tag` フラグを追加
- Windows用セキュア一時ディレクトリ（`%LOCALAPPDATA%\pq-diary\tmp\`）
- Windows用TTY実装（SetConsoleMode）

### 残課題
- list表示の具体的なカラムレイアウト（ID_PREFIX / 日付 / タイトル / タグ の幅配分）— 実装時に決定可能

### 信頼性レベル分布

**ヒアリング前**:
- 🔵 青信号: 3件
- 🟡 黄信号: 8件
- 🔴 赤信号: 7件

**ヒアリング後（最終）**:
- 🔵 青信号: 18件 (+15)
- 🟡 黄信号: 0件 (-8)
- 🔴 赤信号: 0件 (-7)

## 関連文書

- **要件定義書**: [requirements.md](requirements.md)
- **ユーザストーリー**: [user-stories.md](user-stories.md)
- **受け入れ基準**: [acceptance-criteria.md](acceptance-criteria.md)
