+++
id = "M0-T01"
title = "Establish the locked workspace and core contracts"
milestone = "M0"
status = "ready"
priority = "P0"
blocked_by = []
owns = [
  "Cargo.toml",
  "Cargo.lock",
  "rust-toolchain.toml",
  ".cargo/config.toml",
  "LICENSE",
  "bins/ferrum2-client/Cargo.toml",
  "bins/ferrum2-server/Cargo.toml",
  "crates/ferrum2-core/**",
  "crates/ferrum2-crypto/Cargo.toml",
  "crates/ferrum2-shadowsocks/Cargo.toml",
  "crates/ferrum2-socks5/Cargo.toml",
  "crates/ferrum2-runtime/Cargo.toml",
  "crates/ferrum2-config/Cargo.toml",
  "crates/ferrum2-observability/Cargo.toml",
  "tests/m0-harness/Cargo.toml",
  "tests/m0-harness/tests/architecture.rs",
  "tests/m0-harness/tests/workspace_policy.rs",
]
spec = "docs/specs/SPEC-0001-m0-aes128-tcp-vertical-slice.md"
test_plan = "docs/test-plans/TEST-0001-m0-aes128-tcp-vertical-slice.md"
acceptance = [
  "M0-WS-001 passes: cargo metadata reports exactly the ten approved members and the tested dependency DAG has no reverse edge into ferrum2-core",
  "M0-WS-002 passes: exact direct versions and features, Cargo.lock, GPL-3.0-only metadata, publish=false, and workspace unsafe_code=forbid match ADR-0001 as partially superseded by ADR-0009",
  "The ADR-0009 repair adds only exact aes 0.9.1 and ghash 0.6.0 no-default zeroize feature anchors, proves the exact ADR-0009 resolved feature sets and unique package IDs, and exactly preserves the 110-tuple locked package name/version/source/checksum baseline",
  "Rust 1.97.1 can build and test ferrum2-core plus the architecture and workspace-policy tests with --locked",
  "Core LocalEndpoint requires an infallible stored SocketAddrV4 on Connector and Outbound streams, and consuming SessionReply::succeeded requires that endpoint",
  "All later member target paths are predeclared in manifests, and no later ticket needs to edit a manifest or Cargo.lock",
  "ferrum2-m0-harness has no Cargo dependency on a concrete ferrum2 crate, so both T01 static tests compile while future target sources are absent",
]
+++

# M0-T01: Establish the locked workspace and core contracts

## Outcome

建立可被后续 ownership-disjoint tickets 使用的 Cargo workspace、locked dependency
graph、toolchain/license policy和 runtime-neutral core contracts；本票不实现任何
SOCKS5、SIP022、runtime 或 binary product behavior。

## Context

这是 M0 的唯一初始 frontier。全部 manifests/lockfile 必须在并行 wave 之前由一个
Engineer独占，否则后续 T02/T04/T05/T06 会竞争 shared files。模块、版本和 traits
已在 ADR-0001/SPEC-0001 冻结，不由本票重新设计。

## In scope

- root workspace、十个 members、explicit future target paths与exact dependency
  pins。
- Rust 1.97.1 toolchain、MSRV metadata 1.85.0、三个 target declarations。
- GPL-3.0-only `LICENSE`/metadata、`publish=false`、workspace lint。
- committed `Cargo.lock` 与完整 initial transitive graph。
- ADR-0009 唯一授权的 `aes 0.9.1`/`ghash 0.6.0` direct feature anchors、
  regenerated lock representation 与 deterministic resolved-feature policy evidence。
- `ferrum2-core` 的 address/session/connect error及
  `Inbound`/`Outbound`/`Connector`/`LocalEndpoint`/`SessionReply` contracts。
- architecture/workspace-policy harness tests。
- metadata/process-only harness manifest；不得声明concrete ferrum2 path dependency。

## Out of scope

- concrete crypto/protocol/SOCKS/runtime/config/observability behavior。
- binary `main`/run composition。
- 增加 ADR-0001 经 ADR-0009 部分取代后仍未批准的 dependency/feature/member。
- CI provider、interop download或平台 qualification。

## Implementation notes and constraints

- 所有非 core members用explicit target paths预声明；target source不存在是T01的
  受控transient state，文件完全由其owning ticket创建。T01不得对它们运行workspace
  build/format并把预期missing source误报为产品failure。
- `ferrum2-core` 不依赖 Tokio、Serde/TOML、cipher或concrete protocol。
- traits使用 RPITIT/static dispatch，不引入 `async-trait`。
- `TargetAddr` 不实现泄露原值的 `Display`；domain storage有 255-byte bound。
- 若 exact dependency 无法形成 locked graph，停止并请求 ADR/spec revision；不得
  自行换版本。
- 本次 reopen 只有一个 manifest writer；只可修改 root/crypto manifests、
  `Cargo.lock` 与 `workspace_policy.rs`。不得修改 product source、依赖版本、
  AES/SIP022 behavior 或其他 member manifest。
- 必须从现有 lock 做受控 in-place edge update；不得删除 `Cargo.lock`、执行 broad
  `cargo update` 或从空 lock re-resolve。任一 identity/feature/regression gate
  失败时不提交、不集成，T01/T02 继续 blocked。
- policy evidence 必须内嵌并 exact 比较 ADR-0009 的 110-tuple lock identity
  baseline，断言五个 resolved-node exact feature sets/unique IDs，并用相同
  LF/CRLF 正负 fixtures 覆盖 root/member manifest 与 lock parsing。

## Validation commands

```bash
cargo +1.97.1 metadata --locked --format-version 1
cargo +1.97.1 test -p ferrum2-core --locked
cargo +1.97.1 test -p ferrum2-m0-harness --test architecture --locked
cargo +1.97.1 test -p ferrum2-m0-harness --test workspace_policy --locked
cargo +1.97.1 tree --workspace --locked
cargo +1.97.1 tree -p ferrum2-crypto --locked -e features -i aes
cargo +1.97.1 tree -p ferrum2-crypto --locked -e features -i ghash
cargo +1.97.1 tree -p ferrum2-crypto --locked -e features -i polyval
cargo +1.97.1 tree -p ferrum2-crypto --locked -e features -i zeroize
cargo fmt -p ferrum2-core -- --check
git diff --check
```

## Risks

- 某个 pinned transitive dependency可能无法在 MSRV 1.85.0解析；最终 blocking MSRV
  gate仍由 T08执行，但本票应尽早验证 metadata。
- predeclared target漏项会迫使后续修改 manifest；这是 blocker，不允许 ownership
  例外。
- license review遗漏会阻塞 M0，而不是通过编译自动豁免。

## Completion evidence

- Branch: `codex/ticket/m0-t01`
- Commit(s): `ed2fc9243ceed8e2822319b22182f47936f4c22f`,
  `a13949998535a591f0f0a28542ac2b9bf5a25d15`,
  `cd51226cd1875f80115ac657526e3f9dfb267c14`,
  `4948185c0db282261e045ad1276f5e286f6d7d1d`
- Architect verdict: **PASS** for ticket HEAD and integration
  `d9a641fecb2088fc1813ef4ebc58df392be48d64`.
- QA verdict: **PASS**; all seven ticket commands and both focused CRLF
  regressions exited 0 in the integration worktree.
- Integrated commit:
  `d9a641fecb2088fc1813ef4ebc58df392be48d64`
- Resume authorization: on 2026-07-27 the user authorized exactly one additional
  bounded repair beyond the configured 2/2 limit, confined to CRLF-independent
  matching in `tests/m0-harness/tests/workspace_policy.rs`. No other code,
  manifest, contract, or workflow-policy change was authorized by that exception;
  it was consumed by `4948185c0db282261e045ad1276f5e286f6d7d1d`.
- ADR-0009 authorization: on 2026-07-27 the user separately reopened T01 for exactly
  one exclusive post-2/2 manifest repair confined to exact
  `aes 0.9.1`/`ghash 0.6.0` `zeroize` feature unification, `Cargo.lock`, and
  workspace-policy evidence. It is a distinct one-off authorization, does not
  reset or obscure the exhausted configured 2/2 repair accounting, and does not
  change versions, cipher/protocol behavior, API, or product scope. ADR-0009
  document gates passed; this ticket is the sole ready frontier.
