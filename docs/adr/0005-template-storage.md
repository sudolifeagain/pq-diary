# ADR-0005: テンプレート保存方式
Status: accepted
Date: 2026-04-03

## Context
テンプレートの保存先として vault.pqd内(暗号化) / vault.toml内(平文) / 別ファイル(平文) の3案。

## Decision
**vault.pqd内に暗号化して格納。**

退けた選択肢:
- vault.toml内: テンプレート内容がGit経由で平文漏洩
- templates.toml: 同上。さらにファイル管理が増える

## Consequences
- テンプレート内容も秘匿される（テンプレート名にプライベートな情報を含められる）
- テンプレートの追加・編集にはVault解錠が必要
- vault.pqdのエントリセクションにテンプレート用レコードタイプを追加する設計が必要
