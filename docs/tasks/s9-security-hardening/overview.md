# S9 Security Hardening タスク概要

**作成日**: 2026-04-11
**推定工数**: 29時間
**総タスク数**: 6件

## 関連文書

- **要件定義書**: [requirements.md](../spec/s9-security-hardening/requirements.md)
- **設計文書**: [architecture.md](../design/s9-security-hardening/architecture.md)
- **データフロー図**: [dataflow.md](../design/s9-security-hardening/dataflow.md)
- **型定義**: [types.rs](../design/s9-security-hardening/types.rs)
- **コンテキストノート**: [note.md](../spec/s9-security-hardening/note.md)

## フェーズ構成

| フェーズ | 成果物 | タスク数 | 工数 | ファイル |
|---------|--------|----------|------|----------|
| Phase 1 | 技術的負債回収 | 2 | 9h | [TASK-0080~0081](#phase-1-技術的負債回収) |
| Phase 2 | セキュリティコア | 2 | 11h | [TASK-0082~0083](#phase-2-セキュリティコア) |
| Phase 3 | プロセス硬化 + E2E | 2 | 9h | [TASK-0084~0085](#phase-3-プロセス硬化--e2e) |

## タスク番号管理

**使用済みタスク番号**: TASK-0080 ~ TASK-0085
**次回開始番号**: TASK-0086

## 全体進捗

- [ ] Phase 1: 技術的負債回収
- [ ] Phase 2: セキュリティコア
- [ ] Phase 3: プロセス硬化 + E2E

---

## Phase 1: 技術的負債回収

**目標**: S1-S6起源の技術的負債を回収
**成果物**: bail!化、PQC pin、verify_hmac Result化、SecretString化、Zeroizing

### タスク一覧

- [ ] [TASK-0080: M-1 bail! + M-3 PQC pin + M-5 verify_hmac](TASK-0080.md) - 4h (TDD) 🔵
- [ ] [TASK-0081: H-1 SecretString + M-2/M-4 Zeroizing](TASK-0081.md) - 5h (TDD) 🔵

### 依存関係

```
TASK-0080 と TASK-0081 は並行実行可能
```

---

## Phase 2: セキュリティコア

**目標**: エントリ整合性検証とメモリロック
**成果物**: HMAC/署名検証、mlock/VirtualLock

### タスク一覧

- [ ] [TASK-0082: 読み取り時署名/HMAC検証](TASK-0082.md) - 6h (TDD) 🔵
- [ ] [TASK-0083: メモリロック mlock/VirtualLock](TASK-0083.md) - 5h (TDD) 🔵

### 依存関係

```
TASK-0080 → TASK-0082
TASK-0081 → TASK-0082
TASK-0081 → TASK-0083
```

---

## Phase 3: プロセス硬化 + E2E

**目標**: プロセスレベルの防御とフル統合テスト
**成果物**: PR_SET_DUMPABLE、コアダンプ無効化、デバッガ検知、E2Eテスト

### タスク一覧

- [ ] [TASK-0084: プロセス硬化 PR_SET_DUMPABLE + RLIMIT_CORE + デバッガ検知](TASK-0084.md) - 4h (TDD) 🔵
- [ ] [TASK-0085: E2Eテスト + パフォーマンス検証 + run-sprint.sh更新](TASK-0085.md) - 5h (TDD) 🔵

### 依存関係

```
TASK-0083 → TASK-0084
TASK-0082 → TASK-0085
TASK-0084 → TASK-0085
```

---

## 信頼性レベルサマリー

- **総タスク数**: 6件
- 🔵 **青信号**: 6件 (100%)

**品質評価**: 高品質

## クリティカルパス

```
TASK-0081 → TASK-0083 → TASK-0084 → TASK-0085
TASK-0080 → TASK-0082 ───────────↗
```

**クリティカルパス工数**: 19h (0081→0083→0084→0085)

## 次のステップ

- 自動実行: `bash scripts/run-sprint.sh`
