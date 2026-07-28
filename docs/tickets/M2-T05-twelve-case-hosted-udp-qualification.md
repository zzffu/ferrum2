+++
id = "M2-T05"
title = "Add the twelve-case fail-closed hosted UDP qualification"
milestone = "M2"
status = "ready"
priority = "P0"
risk = "high"
implementation_blocked_by = ["M2-T02"]
review_blocked_by = []
integration_blocked_by = ["M2-T01", "M2-T02", "M2-T03", "M2-T04"]
release_blocked_by = ["M2-T04"]
required_reviews = ["architect", "qa"]
owns = [
  "crates/ferrum2-shadowsocks/examples/udp_protocol_client.rs",
  "tests/m0-harness/Cargo.toml",
  "tests/m0-harness/src/bin/m0_qualification.rs",
  "tests/m0-harness/src/external_support/**",
  "tests/m0-harness/src/qualification/**",
  "tests/m0-harness/tests/qualification_contract.rs",
  "tests/interop/**",
  ".github/workflows/**",
]
spec = "docs/specs/SPEC-0003-m2-sip022-udp-protocol-and-direct-server.md"
test_plan = "docs/test-plans/TEST-0003-m2-sip022-udp-protocol-and-direct-server.md"
acceptance = [
  "M2-UDP-INT-001 through M2-UDP-INT-012 cover each supported method, pinned reference, and direction tuple exactly once in the approved method-major order with no discovery, skipped, waived, or duplicate row",
  "Ferrum-client rows spawn the Cargo-managed Shadowsocks UDP protocol example as a black-box process and reference-client rows target the composed ferrum2 server, while the qualification harness adds no ferrum library dependency and no public client UDP inbound",
  "Every case reuses one session for three distinct request and reply datagrams, validates payload and observed source address, and owns independent temp paths, ports, child processes, absolute deadlines, bounded redacted capture, sockets, and cleanup",
  "Pinned sing-box 1.13.14 and shadowsocks-rust 1.24.0 provenance, asset size and SHA-256, safe extraction, version output, license and UDP configuration are verified before their rows execute",
  "Reference setup failure marks its six rows failed under one canonical root while the other reference remains runnable; panic, timeout, missing, skipped, mismatch, nonzero or cleanup failure cannot produce a success result",
  "Local quick and full only compile and lint the example and Cargo-managed qualification entry and run the pure aggregation contract; they never execute qualification, download references, open external sockets, or spawn reference processes",
  "After separate authorization, exit zero requires one clean GitHub Actions Linux checkout at exact GITHUB_SHA and an explicit twelve-line 12-of-12 plus cleanup report on one run and attempt; missing or unavailable evidence remains BLOCKED",
]
+++

# M2-T05: Add the twelve-case fail-closed hosted UDP qualification

## Outcome

扩展既有thin hosted qualification为固定12项UDP compatibility gate，同时以
black-box Cargo example使用public protocol API，保持harness independence。

## In scope

- `M2-UDP-INT-001..012` fixed plan和three-datagram/source checks。
- Protocol example process adapter；reference UDP configs/provisioning。
- Canonical setup roots、failure continuation、exact-SHA/summary/cleanup guards。
- Existing quality/MSRV/platform/interop hosted profile的最小扩展。

## Out of scope

- Product crypto/protocol/runtime/server fixes。
- Public client inbound、SOCKS5 UDP ASSOCIATE或new CI job matrix。
- 本票自动push/run/rerun/publish；remote action另需授权。

## Contract references

- `docs/research/M2-udp-baseline.md`：pins和case order。
- `SPEC-0003` M2-AC-07/08。
- `TEST-0003` hosted table、false-PASS和local/external boundary。
- ADR-0006/0017的provenance、exact-SHA和thin CI rules。

## Primary evidence

| Acceptance | Primary evidence |
|---|---|
| 1 | pure fixed case-plan uniqueness table |
| 2 | Cargo metadata/dependency inspection + process launch contract |
| 3 | per-case result/cleanup contract |
| 4 | existing pinned provisioning checks extended for UDP |
| 5 | pure aggregation failure-continuation table |
| 6 | local build/lint/pure commands and no-execution guard |
| 7 | one authorized raw hosted 12/12+cleanup report |

Hosted compatibility不能替代ferrum-ownedcrypto/state/resource evidence。

## Validation commands

```powershell
cargo build -p ferrum2-shadowsocks --example udp_protocol_client --locked
cargo build -p ferrum2-m0-harness --bin m0-qualification --locked
cargo test -p ferrum2-m0-harness --test qualification_contract --locked
cargo metadata --no-deps --format-version 1 --locked
cargo fmt --all -- --check
$env:PYTHONUTF8='1'
python .agents/skills/milestone-workflow/scripts/workflow.py test-budget --gate ticket --base <ticket-base-sha>
git diff --check
```

不得在local执行`m0-qualification`。

## Ownership and risks

- T05 example是唯一允许链接ferrum protocol crate的client adapter；
  `ferrum2-m0-harness` manifest不得增加任何ferrum dependency。
- T05可在T02后implement/review，但只有T04 integrated后才可integration/release。
- Provider/setup unavailable是release blocker，不修改product票或拼接旧run。
- 既有binary名称可保留；不为命名cleanup制造额外测试。

## Completion evidence

由Team Lead integration/release evidence后填写：

- Branch/worktree/candidate and integrated commit:
- Architect/QA full/targeted review and stable finding IDs:
- Exact local and hosted validation exits/run/attempt:
- Test-budget counts/baseline and accepted debt:
- Push/publish state:
