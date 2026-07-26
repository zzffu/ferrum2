+++
id = "M0-T07"
title = "Compose the client and server binaries and prove the local vertical slice"
milestone = "M0"
status = "ready"
priority = "P0"
blocked_by = ["M0-T03", "M0-T04", "M0-T05", "M0-T06"]
owns = [
  "bins/ferrum2-client/src/cli.rs",
  "bins/ferrum2-client/src/main.rs",
  "bins/ferrum2-client/src/run.rs",
  "bins/ferrum2-server/src/cli.rs",
  "bins/ferrum2-server/src/main.rs",
  "bins/ferrum2-server/src/run.rs",
  "tests/m0-harness/src/local_support/**",
  "tests/m0-harness/tests/config_cli.rs",
  "tests/m0-harness/tests/cli_contract.rs",
  "tests/m0-harness/tests/local_e2e.rs",
  "tests/m0-harness/tests/lifecycle_cycles.rs",
  "tests/m0-harness/tests/detection_probe.rs",
]
spec = "docs/specs/SPEC-0001-m0-aes128-tcp-vertical-slice.md"
test_plan = "docs/test-plans/TEST-0001-m0-aes128-tcp-vertical-slice.md"
acceptance = [
  "M0-CFG-001 through M0-CLI-001 pass against both real binaries, including exact offline output and zero listener, connector, metrics, tracing, or task side effects",
  "M0-E2E-001 and both M0-SOCKS criteria pass through two independent processes, a SOCKS5 peer, and an IPv4 echo target with byte equality and half-close",
  "Composition passes the opened Shadowsocks stream stored LocalEndpoint into the consuming SOCKS success reply; it does not substitute the SOCKS listener or remote endpoint",
  "M0-ENDPOINT-001 client composition maps a LocalEndpoint or connect general error to one exact 05 01 00 01 00000000 0000 reply and performs no protocol first-write",
  "M0-E2E-002 fixes pre-success protocol failure versus post-success target-refusal EOF or reset semantics and proves target accept count remains zero on unauthenticated requests",
  "M0-LIFE-005 completes at least 100 mixed lifecycle cycles with owner, buffer, permit, listener, and child-process counts at baseline",
  "M0-DETECT-002 passes on the host native socket probe or the ticket is blocked pending an ADR-0004 revision",
  "Real-binary probes prove each ShadowsocksError::Detection path invokes the runtime AbortiveClose capability while every ordinary EOF, target failure, and shutdown path remains a normal close",
]
+++

# M0-T07: Compose the client and server binaries and prove the local vertical slice

## Outcome

将已审核的deep modules组合为独立`ferrum2-client`/`ferrum2-server`，以真实process
证明offline config、SOCKS5→SIP022→direct echo、failure ordering、half-close和
repeated cleanup。

## Context

这是T03/T04/T05/T06的汇合票。composition root不得重新实现protocol/runtime
规则；发现contract不匹配时停止并回到对应上游ticket/ADR，而不是在binary中shim。

## In scope

- 两binary `main`/run composition、Tokio multi-thread runtime和signal wiring。
- validated config到providers/listeners/metrics/supervisor的construction order。
- process harness local support、ephemeral echo/recording target和child cleanup。
- real-binary config CLI、local E2E、failure、lifecycle cycles与native detection probe。

## Out of scope

- external reference download/interop、target platform matrix（T08）。
- method/transport/address范围扩展。
- manifest/lock或shared module修改。
- push/publish/release。

## Implementation notes and constraints

- `--check-config`必须在任何subscriber/runtime/listener/provider side effect前return。
- client SOCKS success时机与SPEC-0001一致，并传入opened SS stream存储的
  `LocalEndpoint`；server target failure不产生第二reply。
- listener/supervisor拥有所有child；harness必须kill-on-drop并避免固定ports。
- instrumentation只调用typedobservability API，不加入free-formtarget/error labels。
- native detection probe失败是contract evidence blocker，不能标记flaky/skip。

## Validation commands

```bash
cargo build --workspace --bins --locked
cargo test -p ferrum2-m0-harness --test config_cli --locked
cargo test -p ferrum2-m0-harness --test cli_contract --locked
cargo test -p ferrum2-m0-harness --test local_e2e --locked
cargo test -p ferrum2-m0-harness --test lifecycle_cycles --locked
cargo test -p ferrum2-m0-harness --test detection_probe --locked
cargo test -p ferrum2-client --locked local_endpoint_failure
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --locked
```

## Risks

- composition初始化顺序可能破坏offline/no-listener guarantee。
- optimistic SOCKS success容易与server target refusal错误映射。
- process tests若未严格分配/清理ports和children会产生flake或leak假阴性。

## Completion evidence

To be filled by the Team Lead after integration:

- Branch:
- Commit(s):
- Architect verdict:
- QA verdict:
- Integrated commit:
