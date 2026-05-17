# S11 クロスプラットフォーム検証 + toolchain 固定 タスク概要

**作成日**: 2026-05-17
**スプリント期間**: 半日 (4-6 時間想定)
**推定工数**: 約 2.5 時間 (発覚バグ修正除く)
**総タスク数**: 6 件

## 関連文書

- [📋 requirements.md](../../spec/s11-crossplatform/requirements.md)
- [📐 architecture.md](../../design/s11-crossplatform/architecture.md)
- [📖 user-stories.md](../../spec/s11-crossplatform/user-stories.md)
- [✅ acceptance-criteria.md](../../spec/s11-crossplatform/acceptance-criteria.md)

## フェーズ構成

| Phase | 内容 | タスク | 工数 |
|---|---|---|---|
| 1 | toolchain pin + CI 再構成 | TASK-0098 〜 0101 | 約 100 分 |
| 2 | 検証 + バグ修正 + ドキュメント | TASK-0102 〜 0103 | 約 60 分 + α |

## タスク一覧

- [ ] [TASK-0098: rust-toolchain.toml 新規作成](TASK-0098.md) - 30m (DIRECT) 🔵
- [ ] [TASK-0099: CI check ジョブを 3 OS matrix 化](TASK-0099.md) - 30m (DIRECT) 🔵
- [ ] [TASK-0100: CI smoke ジョブに macos + ubuntu-24.04-arm 追加](TASK-0100.md) - 30m (DIRECT) 🔵
- [ ] [TASK-0101: cargo audit を独立ジョブに分離](TASK-0101.md) - 15m (DIRECT) 🔵
- [ ] [TASK-0102: backlog + sprint-status 更新](TASK-0102.md) - 10m (DIRECT) 🔵
- [ ] [TASK-0103: クロスプラットフォーム検証で発覚したバグ修正 (条件付き)](TASK-0103.md) - α (TBD) 🔵

## 依存関係

```
TASK-0098 (rust-toolchain.toml) ─┐
TASK-0099 (check matrix)         ├─→ CI run → TASK-0103 (発覚バグ fix, 条件付き)
TASK-0100 (smoke 拡張)           ├─→
TASK-0101 (audit 分離)           ┘
TASK-0102 (docs) は最後 (検証完了後)
```

並列実行可能: TASK-0098, 0099, 0100, 0101 (CI yaml と新規ファイルなので順次)
順次: 全 CI ジョブ green 確認 → TASK-0102 → main マージ → s11-done

## クリティカルパス

```
TASK-0098 → TASK-0099 → TASK-0100 → TASK-0101 → CI run → TASK-0102 → merge
```

約 2.5 時間 + CI 待ち + 発覚バグ修正 (TASK-0103, 不明)。

## 信頼性レベルサマリー

全 6 タスク🔵 (S10 hotfix 実体験ベース + 詳細設計済み)。

## 次のステップ

`/tsumiki:kairo-implement s11-crossplatform` で順次実装。
