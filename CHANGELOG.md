# Changelog

All notable changes to pq-diary are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
pq-diary is pre-1.0 and has not yet cut a binary release — versioned entries
will appear once the first release tag (`v0.x.0`) is created. Until then,
sprint-level milestones are tracked here as **Unreleased** subsections, plus
the **History** table at the bottom for git-tag pointers.

## [Unreleased]

### Installation and first use

- Require matching confirmation for interactive new passwords in `init` and `vault create` before creating state; retain flag/environment automation and existing policy/weak-password confirmation order.
- Add isolated Linux Cargo lifecycle and real-terminal setup checks to the default CI, reusing debug build artifacts.

### Current implementation status (2026-10-16)

- Current writer schema is **0x06**; readers accept v0x04–v0x06. S16 v0x07 integration/migration is unfinished. MDK/keyslot primitives are present but are not yet the normal vault create/unlock/data path.
- Git sync has snapshot validation and fail-closed guards. Common-base deletion/metadata reconciliation, remote ancestry, attachment sync and cross-device key/config migration remain open. The historical “3-way merge” milestone below is not a claim that these cases are complete.
- Default CI uses Linux check/debug smoke plus audit/deny. Cross-platform check/release smoke remains available through manual `full_matrix=true`.
- The S13 v5 format notes below describe that historical release stage, not the current writer. See [development inventory](docs/development-inventory.md) for pinned source evidence and verification limits.

### Markdown import fixes
- Preserve code, escaped markers, wiki-link targets and URL fragments during inline tag and alias conversion.
- Import complete hyphenated, nested and Unicode symbol/emoji tags; preserve numeric-only hashes as text, matching Obsidian's tag format.

### Security (review follow-up)
- Generate attachment file keys directly in protected storage, propagate OS randomness failures, and verify attachment HMACs with constant-time comparison.
- Reject edits to INHERIT entries when the legacy key is unavailable, preserving the owner's content and the separate heir-recovery payload. Create a separate entry for revisions instead.
- Direct attachment and master-password legacy APIs verify vault integrity before using records or changing files; these APIs and password rotation authenticate the same byte snapshot they parse.
- Keep attachment API master-key copies in zeroize-on-drop storage through success and error paths.
- Update locked anyhow to 1.0.103 and rand to 0.8.6 for RUSTSEC-2026-0190 / RUSTSEC-2026-0097; replace yanked der 0.8.0 with 0.8.2.
- Fail dependency audits on unsound advisories and yanked crates as well as vulnerabilities.

### Fixed (S17)
- Legacy access preserves the original vault and configuration when either backup rename fails; old backups are wiped only after both replacements succeed.
- Password changes accept template payloads as templates, preserving mixed diary/template vaults.
- Password changes verify the existing vault integrity MAC before rewriting any data, rejecting authenticated metadata tampering.

### Phase 2 (in progress)

Phase 2 中核 (legacy / attachments) を完了。残候補は Bases like ビュー / 固定ブロックサイズ化 (OQ-20) / Web Clipper / 鍵素材 XOR 分散 / Unix ソケット + ロックデーモン。

#### Added
- **デジタル遺言 (S12)**: `pq-diary legacy init/set/list/rotate` + `pq-diary legacy-access`。死後アクセスコード (K_legacy) で INHERIT エントリを継承、DESTROY エントリは zeroize 削除。確認 UI 3 モード (timer30 / yn / phrase)。`core/src/legacy.rs` 新規。
- **添付ファイル (S13)**: `pq-diary attachment add/list/extract/delete/set` + `new --attach` + `show` 拡張。1MB chunk + AES-256-GCM ストリーミング暗号化、最大 1GB/ファイル。`core/src/attachment.rs` + `core/src/crypto/streaming.rs` 新規。
- **export/import の双方向 Obsidian 互換 (S13 + S13.1)**: `export` で `attachments/` 別ディレクトリ + `![[FILE]]` 埋め込み、`import` で `![[FILE]]` の自動解決。
- **運用コマンド (S10)**: `init` / `sync` / `change-password` / `info [--security]` / `export <DIR>`。`~/.pq-diary/config.toml` 導入、smoke-test スクリプト (`ci/smoke-test.{sh,ps1}`) 追加。
- **S16 keyslot / MDK 基盤**: RFC 5869 HKDF-SHA256、ランダム MDK の用途別サブ鍵、password / password+keyfile / recipient / recovery keyslot の MDK wrap/unwrap、keyslot section と keyfile payload の parser/serializer を追加。

#### Changed
- vault.pqd `schema_version` を `0x04` → `0x05` に bump (S13)。reader は v4/v5 両方を受理 (`SCHEMA_VERSION_MIN = 0x04`)、writer は常に v5 を書き込み (v4 vault は次回 write で自動 v5 化)。
- `RECORD_TYPE_ATTACHMENT = 0x03` を新設、`AttachmentPlaintext` (K_master 暗号化) と `AttachmentLegacyPlaintext` (K_legacy 暗号化) を分離。
- `change-password` で attachment メタデータも再暗号化 (`.bin` 本体は不変 — ランダム per-blob FileKey 設計)。
- legacy / legacy-access / attachment の各 hide 解除、`pq-diary --help` に表示。

#### Security
- 添付本体は per-blob FileKey で暗号化 (K_master からの独立)。
- chunk AAD = `chunk_index || total || blob_uuid` で reorder / truncation / file substitution を検出。
- 添付・エントリで SHA-256 重複排除 + 参照カウント方式 delete。
- legacy-access は `--claude` を Argon2 サイクル消費前にブロック (NFR-104)。
- S16 keyslot 基盤では `wrapped_mdk = AES-256-GCM(slot_key, MDK)` の AEAD タグを資格情報確認として使い、ML-KEM-768 共有秘密は HKDF-SHA256 で slot_id に束縛してから MDK ラップ鍵にする。

#### Documentation
- `CHANGELOG.md` 新規 (S14 棚卸し)。
- `docs/backlog.md` 古い `[ ]` 表現を実装状態に補正 (S4 / S5 全項目、M-5 / H-3、S13 v4 → v5 と Phase 4 v5 → v6 の整理)。
- `requirements.md` を v5 対応に更新 (§6 / §5.4 / §Phase 4)。

### Git sync safety

- Pull validates fetched vault bytes without checking them out into the local
  vault/index. Incompatible headers/keys or `vault.toml` changes are rejected
  before local data is changed
- Git reads authenticate and parse the same snapshot; writes use its validated
  records without reopening the destination for attachment metadata
- Push and pull reject attachment-bearing vaults until attachment metadata and
  encrypted blob sync are supported together
- Push and pull commit only their allowlisted vault paths, keeping unrelated
  staged files out of published history
- Pull preserves existing recovery backups; a failed commit restores the local
  vault without changing its original index
- Remote ancestry and deletion reconciliation remain open work; an ordinary
  push after a remote advance can still fail with a non-fast-forward rejection

### Phase 1 (完了済み)

PRD §15 で定義された Phase 1 を 2026-04-11 (s9) → 2026-05-17 (s11) で完走。

#### Highlights
- Cargo ワークスペース (`core/` + `cli/`) と CI 基盤 (test / clippy / audit + cross-platform matrix)。
- 暗号コア: Argon2id / AES-256-GCM / ML-KEM-768 / ML-DSA-65 / HMAC-SHA256 (RustCrypto + zeroize / Drop 漏れ修正 fork)。
- vault.pqd v4 バイナリフォーマット + `vault.toml` / `config.toml`。
- Entry CRUD (`new` / `list` / `show` / `edit` / `delete`) + ネストタグ + パスワード入力 3 段階 (flag / env / TTY echo-OFF)。
- デイリーノート (`today`) + テンプレート + `[[link]]` + バックリンクインデックス。
- 検索 (regex inmemory) + 統計 (heatmap) + Obsidian import。
- アクセス制御 (`access.policy`) + `--claude` 4 層チェック。
- Git 連携 (sync / push / pull / status) + privacy padding + timestamp fuzzing + 3-way merge。
- セキュリティ硬化: mlock / VirtualLock / PR_SET_DUMPABLE / `IsDebuggerPresent` + 統合テスト。
- `rust-toolchain.toml` で 1.95.0 pin + CI matrix を ubuntu / macos / windows + ubuntu-24.04-arm に拡張。

## Migration Notes

### vault.pqd v4 → v5 (S13 で導入)

物理レイアウトは v4 と同一。`schema_version` が `0x05` に bump され、payload に
`RECORD_TYPE_ATTACHMENT (0x03)` レコードが含まれる場合がある。

- **読み込み**: S13+ クライアントは v4 / v5 両方を受け入れる (`SCHEMA_VERSION_MIN = 0x04`)
- **S13当時の書き込み**: v5を書き、v4 vaultは次回writeでv5化。現行writerはS15で導入したv0x06を使う
- **古いクライアント (S12 以前) ↔ v5 vault**: `schema_version` チェックで拒絶 — S13+ クライアントのみで開く運用を推奨

現在はS15のv0x06が導入済み。次のv0x07移行は未完了のS16で扱う。HQCはS16設計上、schema bumpではなくスロットアルゴリズムの追加を予定する。

## History

スプリント単位の詳細は `docs/sprint-status.md` を、メタ情報は git の
PR マージコミット (`git log --merges`) を参照。S14 以降は個別の
スプリントタグを打たず、Phase 完了でのみ `phaseN-done` を切る運用 (`docs/workflow.md` 参照)。

### Phase 1 タグ (履歴として残置)

| Tag | Date | Theme |
|-----|------|-------|
| `s1-done` | 2026-04-03 | 基盤構築 (workspace, CI, clap skeleton) |
| `s2-done` | 2026-04-03 | 暗号コア (Argon2 / AES-GCM / ML-KEM / ML-DSA / HMAC) |
| `s3-done` | 2026-04-03 | vault.pqd v4 + vault.toml + config.toml |
| `s4-done` | 2026-04-05 | Entry CRUD + CLI + パスワード 3 段階 + ネストタグ |
| `s5-done` | 2026-04-08 | today + テンプレート + `[[link]]` + バックリンク |
| `s6-done` | 2026-04-09 | search + stats + Obsidian import + 技術的負債 |
| `s7-done` | 2026-04-10 | アクセス制御 + `--claude` 4 層チェック |
| `s8-done` | 2026-04-11 | Git 連携 + privacy + 3-way merge |
| `s9-done` | 2026-04-11 | セキュリティ硬化 (mlock / coredump / debugger) |
| `s10-done` | 2026-05-17 | 運用機能 (init / sync / change-password / info / export) |
| `s11-done` | 2026-05-17 | クロスプラットフォーム検証 + toolchain pin |
| **`phase1-done`** | 2026-04-11 | **S9時点のPhase 1タグ (S10/S11 follow-up前; 真の完了は `s11-done` で追跡)** |

### Phase 2 タグ (一部のみ、運用変更後)

| Tag | Date | Theme |
|-----|------|-------|
| `s12-done` | 2026-05-18 | デジタル遺言 (legacy) — S14 運用変更前に既に切られていたため残置 |
| `s13-done` | 2026-05-18 | 添付ファイル + cmd_import follow-up (S13.1) — 同上 |
| `phase2-done` | (未着手) | Phase 2 全機能完了時に切る予定 |

### Phase 2 以降は PR ベース

S14 以降の作業は git tag を打たず、PR マージコミットで追跡:

- S14 (本 PR): Phase 2 棚卸し + CHANGELOG.md 新規作成 — タグなし
- S15: v0x06整合性MACなどの硬化。S16: MDK/keyslot基盤まで導入、vault/CLI統合未完了。S17: データ保全・I/O回帰対応を継続。詳細は `docs/sprint-status.md` を参照
- Phase 2残候補: Bases like ビュー / 固定ブロック OQ-20 / Web Clipper / 鍵素材 XOR 分散 / Unix ソケット + デーモン
