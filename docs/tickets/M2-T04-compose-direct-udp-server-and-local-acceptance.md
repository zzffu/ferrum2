+++
id = "M2-T04"
title = "Compose the bounded direct UDP server and prove local acceptance"
milestone = "M2"
status = "done"
priority = "P0"
risk = "critical"
implementation_blocked_by = ["M2-T02", "M2-T03"]
review_blocked_by = []
integration_blocked_by = ["M2-T01", "M2-T02", "M2-T03"]
release_blocked_by = []
required_reviews = ["architect", "qa"]
owns = [
  "crates/ferrum2-config/**",
  "crates/ferrum2-observability/**",
  "bins/ferrum2-server/**",
  "tests/fixtures/config/**",
  "tests/platform/**",
  "tests/m0-harness/src/local_support/**",
  "tests/m0-harness/tests/cli_contract.rs",
  "tests/m0-harness/tests/config_cli.rs",
  "tests/m0-harness/tests/detection_probe.rs",
  "tests/m0-harness/tests/lifecycle_cycles.rs",
  "tests/m0-harness/tests/local_e2e.rs",
  "tests/m0-harness/tests/udp_local_e2e.rs",
]
spec = "docs/specs/SPEC-0003-m2-sip022-udp-protocol-and-direct-server.md"
test_plan = "docs/test-plans/TEST-0003-m2-sip022-udp-protocol-and-direct-server.md"
acceptance = [
  "Server schema v1 validates udp enabled, max_sessions, max_buffered_bytes, and idle_timeout defaults and ranges offline; unknown or invalid values exit with stable redacted semantics before any TCP, UDP, metrics, table, worker, resolver, or task resource exists",
  "Omitted UDP configuration enables UDP by default on the existing server.listen address and port, enabled false creates no UDP resources, and both TCP and UDP binds succeed before either loop starts while either-bind failure rolls back the other",
  "The composed server authenticates and semantically validates all three SIP022 UDP methods before session reservation commit, source update, resolution, direct socket creation, queueing, target send, or response and isolates every affected-datagram or session failure",
  "A bounded local process matrix sends three distinct request and response datagrams through the protocol API and direct UDP echo for every method, with focused IPv6, domain, source-address, invalid, stalled-consumer, and saturation rows rather than a full cross product",
  "Idle expiry, target failure, listener failure, cancellation, shutdown grace, forced shutdown, restart and rebind return all UDP and shared owners to baseline without regressing existing TCP configuration, relay, detection, lifecycle, or disabled-UDP behavior",
  "The seven stable UDP metric families and closed trace categories account for sessions, allocated buffered bytes, datagrams, bytes, replay, failure and forced shutdown without PSK, key, nonce, wire ID, target, source or peer cardinality and without changing existing TCP families",
  "Ticket-specific product and process suites, authoritative quick-compatible behavior, formatting, test-budget and diff checks pass; any environment-limited IPv6 or port row is recorded as unexecuted rather than PASS",
]
+++

# M2-T04: Compose the bounded direct UDP server and prove local acceptance

## Outcome

把T02 protocol和T03 runtime组合进server，在一个same-port、offline-validatable、
bounded且可观测的local UDP产品路径中证明三方法。

## In scope

- `[udp]` server config和offline validation。
- Atomic TCP+UDP same-address startup、direct UDP composition和failure ordering。
- Stable UDP metrics/tracing/redaction。
- Small real-process method/address/backpressure/lifecycle matrix。

## Out of scope

- Client binary UDP listener/schema和SOCKS5 UDP ASSOCIATE。
- Protocol/crypto/runtime internals和external reference orchestration。
- Hosted execution、platform qualification或publication。

## Contract references

- `ADR-0021`：atomic replay/peer/generation ordering。
- `ADR-0022`：config、dual bind、numeric limits、lifecycle、metrics。
- `SPEC-0003` M2-AC-05/06；`TEST-0003` T04 integration evidence。

## Primary evidence

| Acceptance | Primary evidence |
|---|---|
| 1 | config defaults/ranges + CLI zero-resource table |
| 2 | dual-bind transaction/UDP-disabled process table |
| 3 | recording composition ordering/failure table |
| 4 | bounded local three-method echo matrix |
| 5 | owner snapshot expiry/shutdown/rebind + TCP regression |
| 6 | metric series identity + tracing sentinel tables |
| 7 | exact ticket gates and unexecuted-platform record |

Product tables证明deterministic semantics；real process只证明adapter/OS interaction。

## Validation commands

```powershell
cargo test -p ferrum2-config -p ferrum2-observability -p ferrum2-server --locked
cargo test -p ferrum2-m0-harness --test config_cli --test detection_probe --test udp_local_e2e --locked
cargo fmt --all -- --check
$env:PYTHONUTF8='1'
python .agents/skills/milestone-workflow/scripts/workflow.py test-budget --gate ticket --base <ticket-base-sha>
git diff --check
```

## Ownership and risks

- T04不编辑client/SOCKS5、protocol/runtime或qualification paths。
- Default UDP enablement是documented startup compatibility change；disabled row
  必须真实证明zero UDP resources。
- Dual bind/start和shutdown是single transaction；partial owner不能被background
  task隐藏。
- Local matrix不膨胀为method×address×failure全组合。

## Completion evidence

- Branch/worktree/candidates: `codex/ticket/m2-t04`,
  `C:\project\ferrum2\.worktrees\m2-t04`; initial
  `aac21f48b6bd3cb3aa940a60628e5b94eaac89d6`, lifecycle repair
  `6896c6e026797cd62fd9787a66abcca6ec6c7b58`, and mechanical
  integration-evidence repair `c6ade6d34ee95767852cfa25327a4fb6da520a46`.
  Exact product integration is
  `980540bd439c438eb196cbc3096cbea0cda3fb4d`.
- Reviews: Architect/QA full reviews both `BLOCK` on
  `ARCH-M2-T04-001` and `QA-M2-T04-001`. One substantive repair resolved
  canonical root `M2-T04-REVIEW-001`; both targeted reviews returned
  `PASS_WITH_NOTES`. Integration root `M2-T04-INTEGRATION-001` exposed
  TCP-only fixtures that omitted the now-default UDP configuration; the
  mechanical repair added explicit TCP-only helpers without changing
  default-enabled evidence. Exact-SHA Architect/QA integration reviews both
  returned `PASS_WITH_NOTES`.
- Validation at `980540bd`: exact binary build, authoritative quick `3/3`,
  full `4/4`, focused and workspace all-features 100-cycle lifecycle,
  config/detection/TCP/UDP process suites, workflow validation,
  review/integration gate, and `git diff --check` all exited `0`.
- Ticket budget `PASS`: code `11582`, tests `18721`, ratio `1.616`,
  baseline `2.041`; delta `954/774`, allowance `1074`. Mechanical repair
  delta was code `0`, tests `35`, allowance `120`.
- Accepted review debt: `QA-M2-T02-N01` is satisfied at all T04-owned
  request/response commit call sites. `ARCH-M2-T04-N01` and
  `QA-M2-T04-N01` retain IPv6 as **NOT EXECUTED** pending an exact-SHA
  IPv6-capable platform run. Hosted/external qualification was not run.
- Push/publish state: nothing pushed or published.
