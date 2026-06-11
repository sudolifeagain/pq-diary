# ADR-0010: フォーク暗号クレートのサプライチェーン方針

Status: accepted
Date: 2026-06-11

## Context

ML-KEM-768 / ML-DSA-65 は RustCrypto の**フォーク** (`sudolifeagain/ml-kem`,
`sudolifeagain/ml-dsa`) を特定リビジョンに固定して利用している (ADR-0001)。
S15 セキュリティ監査 (Medium-1) で次の点が指摘された:

- これらは**未監査・pre-1.0** の暗号実装であり、アップストリームから分岐した
  個人フォークである。
- `cargo audit` (RustSec) は crates.io 版にひも付く advisory が中心で、**git 依存
  そのものの出所**は検査しない。フォーク origin が差し替わっても気づけない。
- S16 (キースロット/MDK, ADR-0009) で **ML-KEM が機密性の load-bearing になる**ため、
  これらの依存の重大度が上がる。

## Decision

**`cargo-deny` を CI 必須化し、`[sources]` 許可リストで git 依存の出所を固定する。**

- `deny.toml` の `[sources]` で `unknown-git = "deny"` とし、許可する git origin を
  `sudolifeagain/ml-kem` / `sudolifeagain/ml-dsa` の 2 つだけに限定する。これにより
  **フォーク origin の差し替え・予期しない git 依存の混入は CI で失敗**する。
- リビジョン (rev) は `core/Cargo.toml` / `Cargo.lock` で固定済み。`deny.toml` は
  origin のみを認可し、rev の固定は lock に委ねる。
- `[licenses]` で許可ライセンスを明示 (許可外は CI 失敗)。`[bans]` で重複バージョン・
  wildcard を警告。
- advisory (脆弱性) は既存の `cargo audit` ジョブが担う。`cargo-deny` は
  `check bans licenses sources` を実行し役割を分離する。

### フォーク維持義務

- フォークの差分 (ADR-0001: `ml-dsa` の zeroize 補完 + CVE-2026-22705 パッチ、
  `ml-kem` の DecapsulationKey zeroize 補完) は**最小限に保ち、upstream へ PR で
  還元**する。upstream に取り込まれ次第フォークを解消し crates.io 版へ戻す。
- フォーク rev を更新する際は、差分が想定どおりであることをレビューし、`deny.toml`
  許可リストと整合させる。
- upstream のセキュリティパッチを定期的に追従する。

## Consequences

- フォーク origin の差し替え・サプライチェーン経由の不正依存混入を CI で検知できる。
- ライセンス違反・未許可ライセンスの混入を CI で検知できる。
- `cargo-deny` の license/bans 許可リストは初回 CI 実行で検証される。許可外ライセンスが
  出た場合は `deny.toml` の `allow`/`exceptions` をレビューの上で更新する。
- フォーク解消 (upstream 還元完了) 時は本 ADR と `deny.toml` 許可リストを更新する。
