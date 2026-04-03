# ADR-0003: パスワード入力方式
Status: accepted
Date: 2026-04-03

## Context
パスワードを安全に受け取る方法が複数あり、利便性とセキュリティのトレードオフがある。

## Decision
**3段階の優先順位方式を採用。**

1. `--password` フラグ (最優先・非推奨): シェル履歴・/proc漏洩リスクあり。使用時に警告表示
2. `PQ_DIARY_PASSWORD` 環境変数 (推奨): /proc/environ はオーナー+rootのみ読み取り可
3. TTYプロンプト (デフォルト・最安全): termios自前実装。`rpassword`クレート不採用(SecretString非対応のため)

## Consequences
- termios自前実装のメンテコスト
- 入力を直接SecretStringに格納でき、平文Stringを経由しない
- Claude Code連携では環境変数方式を推奨
