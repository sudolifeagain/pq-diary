# ADR-0001: PQCライブラリ選定
Status: accepted
Date: 2026-04-03

## Context
ML-KEM-768 / ML-DSA-65の実装クレートが複数存在する。秘密鍵のzeroize漏れはメモリフォレンジックに直結する。

## Decision
**RustCrypto (`ml-kem`/`ml-dsa`) のフォークを採用。**

退けた選択肢:
- `pqcrypto-mlkem/mldsa`: AArch64サイドチャネル残存、NIST KATなし
- `oqs` (liboqs): 本番非推奨明記、SecretKeyにZeroize未実装

フォーク修正内容:
- `ml-dsa`: `s1_hat`/`s2_hat`/`t0_hat`/`A_hat` の4フィールドにzeroize追加 + CVE-2026-22705パッチ
- `ml-kem`: DecapsulationKeyのzeroize補完
- CIに `cargo audit` 組み込み

## Consequences
- フォーク維持コストが発生（上流のセキュリティパッチ追従が必要）
- FIPS 203/204準拠 + NIST KAT通過の品質を確保
- Phase 4でHQC追加時も同じフォーク戦略を適用予定
