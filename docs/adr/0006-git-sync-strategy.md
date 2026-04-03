# ADR-0006: Git同期方式
Status: accepted
Date: 2026-04-03

## Context
Git操作の実装方式として git CLI直接呼び出し / git2クレート / 自前実装 の選択肢がある。

## Decision
**デスクトップはgit CLI直接呼び出し、モバイル(Phase 3)はgit2クレート。**

プライバシー強化3点セット:
1. author匿名化: `pq-diary <ランダムID@localhost>` (Vault初期化時に生成・固定)
2. コミットメッセージ定型化: `"update"` のみ
3. コミット毎パディング: vault.pqd末尾に0-4096Bランダム追記

タイムスタンプファジング: GIT_AUTHOR_DATE/GIT_COMMITTER_DATE を設定可能幅(デフォルト6h)でランダム化。単調増加保証。

## Consequences
- git CLIが未インストールの環境では同期不可（起動時に `git --version` で確認）
- git2不使用でバイナリサイズを抑制（デスクトップ）
- タイムスタンプファジングにより `git log` の日時が実際と異なる（意図的）
