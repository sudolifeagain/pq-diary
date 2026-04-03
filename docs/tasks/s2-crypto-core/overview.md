# s2-crypto-core タスク概要

**作成日**: 2026-04-03
**推定工数**: 40時間（10タスク × 4h）
**総タスク数**: 10件
**タスク粒度**: 半日（4時間）単位

## 関連文書

- **要件定義書**: [📋 requirements.md](../../spec/s2-crypto-core/requirements.md)
- **設計文書**: [📐 architecture.md](../../design/s2-crypto-core/architecture.md)
- **データフロー図**: [🔄 dataflow.md](../../design/s2-crypto-core/dataflow.md)
- **型定義**: [📝 types.rs](../../design/s2-crypto-core/types.rs)

## フェーズ構成

| フェーズ | 成果物 | タスク数 | 工数 |
|---------|--------|----------|------|
| Phase 1 - 基盤+暗号実装 | PQCフォーク、サブモジュール、各アルゴリズム | 7件 | 28h |
| Phase 2 - エンジン統合 | CryptoEngine unlock/lock、メソッド統合、E2E | 3件 | 12h |

## タスク番号管理

**使用済みタスク番号**: TASK-0008 ~ TASK-0017
**次回開始番号**: TASK-0018

## 全体進捗

- [ ] Phase 1: 基盤+暗号実装
- [ ] Phase 2: エンジン統合

## タスク一覧

### Phase 1: 基盤+暗号実装

- [ ] [TASK-0008: PQCフォークリポジトリ作成](TASK-0008.md) - 4h (DIRECT) 🔵
- [ ] [TASK-0009: crypto/サブモジュール分割 + 依存クレート追加](TASK-0009.md) - 4h (DIRECT) 🔵
- [ ] [TASK-0010: Argon2id鍵導出 (kdf.rs)](TASK-0010.md) - 4h (TDD) 🔵
- [ ] [TASK-0011: AES-256-GCM暗号化/復号 (aead.rs)](TASK-0011.md) - 4h (TDD) 🔵
- [ ] [TASK-0012: ML-KEM-768鍵カプセル化 (kem.rs)](TASK-0012.md) - 4h (TDD) 🔵
- [ ] [TASK-0013: ML-DSA-65署名/検証 (dsa.rs)](TASK-0013.md) - 4h (TDD) 🔵
- [ ] [TASK-0014: HMAC-SHA256 (hmac_util.rs)](TASK-0014.md) - 4h (TDD) 🔵

### Phase 2: エンジン統合

- [ ] [TASK-0015: CryptoEngine unlock/lock実装](TASK-0015.md) - 4h (TDD) 🔵
- [ ] [TASK-0016: CryptoEngine暗号操作メソッド統合](TASK-0016.md) - 4h (TDD) 🔵
- [ ] [TASK-0017: 統合テスト + doc comment整備](TASK-0017.md) - 4h (TDD) 🔵

## 依存関係

```
TASK-0008 (PQCフォーク)
└── TASK-0009 (サブモジュール分割)
    ├── TASK-0010 (Argon2id) ──────┐
    ├── TASK-0011 (AES-GCM) ──────┼── TASK-0015 (unlock/lock)
    ├── TASK-0012 (ML-KEM) ───┐   │
    ├── TASK-0013 (ML-DSA) ───┼───┼── TASK-0016 (メソッド統合)
    └── TASK-0014 (HMAC) ─────┘   │
                                   └── TASK-0017 (統合テスト)
```

## クリティカルパス

```
TASK-0008 → 0009 → 0010 → 0015 → 0017
```

**クリティカルパス工数**: 20時間
**並行作業**: TASK-0010〜0014 は TASK-0009 完了後に並行実行可能

## 信頼性レベルサマリー

- **総タスク数**: 10件
- 🔵 **青信号**: 10件 (100%)
- 🟡 **黄信号**: 0件 (0%)
- 🔴 **赤信号**: 0件 (0%)

**品質評価**: 最高品質

## 次のステップ

タスクを実装するには:
- 全タスク順番に実装: `/tsumiki:kairo-implement s2-crypto-core`
- 特定タスクを実装: `/tsumiki:kairo-implement s2-crypto-core TASK-0008`
