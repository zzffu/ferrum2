+++
id = "M3-T03"
title = "Build the topology-neutral transactional process supervisor"
milestone = "M3"
status = "done"
priority = "P0"
risk = "critical"
implementation_blocked_by = []
review_blocked_by = []
integration_blocked_by = []
release_blocked_by = []
required_reviews = ["architect", "qa"]
owns = [
  "crates/ferrum2-runtime/**",
]
spec = "docs/specs/SPEC-0004-m3-operational-lifecycle-platform-contract.md"
test_plan = "docs/test-plans/TEST-0004-m3-operational-lifecycle-platform-contract.md"
acceptance = [
  "A protocol and topology neutral runtime seam represents the observable Validated, Preparing, Prepared, Active, Quiescing, Draining, Forced or Fatal, and Stopped outcomes without owning configuration parsing, observability policy, routing, DNS, transparent proxy, TUN, or CLI concerns",
  "All required root resources complete fallible preparation before any public service root is polled; failure at every preparation or synchronous activation position rolls back already prepared owners in deterministic order and returns snapshots to baseline",
  "Process, root, and child resources each have one transitive owner and exactly-once completion and reap accounting; cancellation, late completion, generation mismatch, task panic or join error cannot leak or resurrect sockets, tasks, channels, buffers, sessions, or owner counts",
  "External shutdown, startup rollback, and fatal required-root completion use one monotonic cancellation lineage and deterministic first-cause arbitration while ordinary authentication, semantic, target, queue, idle, relay, or datagram failure remains isolated to the affected flow or session",
  "Handshake, connect or resolve, idle, and shutdown budgets use monotonic absolute deadlines that do not reset within retries, candidates, child phases, or bidirectional relay progress",
  "Graceful shutdown quiesces admission, drains accepted work to the configured absolute grace deadline, force-cancels the remainder, joins and reaps all roots and children, and reports cleanup failure rather than returning false success",
  "Focused lifecycle, shutdown, half-close, backpressure and UDP runtime tests, strict Clippy, formatting, ticket test-budget, and diff checks pass without edits outside this ticket's ownership",
]
+++

# M3-T03: Build the topology-neutral transactional process supervisor

## Outcome

提供可被当前 TCP/UDP/metrics roots 与未来 inbound/outbound adapters 复用的 process
supervisor outcome，统一 prepare/activate/rollback/fatal/shutdown ownership。

## In scope

- Prepared-root/process supervisor seam and deterministic outcome arbitration。
- Root/child ownership、cancellation lineage、late completion/reap accounting。
- Absolute phase/shutdown deadlines和graceful/forced cleanup。
- Paused-time fake-root state table，复用既有 owner registry/lifecycle suites。

## Out of scope

- Binary composition、OS signal adapter、config/observability mappings。
- Routing graph、DNS policy、transparent socket/device、TUN 或 topology registry。
- Protocol/wire behavior、performance tuning和long soak。

## Contract references

- `ADR-0024` complete lifecycle decision。
- `ADR-0023` only for binary-level run-code mapping, not a runtime dependency。
- `SPEC-0004` M3-MUST-06/07。
- `TEST-0004` T03 product commands。

## Primary evidence

| Acceptance | Primary evidence |
|---|---|
| 1 | direct runtime API/dependency inspection + fake-root state model |
| 2 | one preparation/activation failure-position rollback table |
| 3 | owner snapshot/late-completion/panic table |
| 4 | cancellation and simultaneous-root arbitration table |
| 5 | existing paused-time deadline/candidate/relay rows |
| 6 | graceful/forced shutdown owner snapshot table |
| 7 | exact ticket gates and budget report |

Fake roots证明generic policy；真实 OS bind/signal failure由T04在production-used adapter
seam证明，不在本票重复。

## Validation commands

```powershell
cargo test -p ferrum2-runtime --test lifecycle --test shutdown --test half_close --test backpressure --test udp_runtime --locked
cargo clippy -p ferrum2-runtime --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
python -X utf8 .agents/skills/milestone-workflow/scripts/workflow.py test-budget --gate ticket --base <ticket-base-sha>
git diff --check
```

## Ownership and risks

- T03 与 T01/T02 是 initial frontier；不编辑 binary、config、observability或
  harness。
- Runtime 不能新增对 concrete protocol/config/observability 的依赖；closed
  outcome由 binary adapter 映射。
- “Prepared”不得暗中 spawn/poll public root；owner drop不得替代可证明的 reap。
- 不为每种 root/failure 建独立 supervisor；使用一个 parameter table。

## Completion evidence

- Initial candidate `c1cf718bcf94777aa8aa05ea5975d3822dd2573d`;
  repaired candidate `1d7111d2d20df805740c21e98da8fb161141b161`;
  integrated as `c521150265d5c49fe5cb0eb8fcd8159b93489995` plus
  `da8fa58e0f50dda1637e3a2b205e6f34332a5bec`.
- Architect full review: BLOCK on canonical
  `ARC-M3-T03-001` (major). QA full review: BLOCK on derivatives
  `QA-M3-T03-001` and `QA-M3-T03-002` (major). One substantive repair
  consumed the `1/1` budget; both targeted reviews PASS and the canonical
  root plus both derivatives were resolved.
- Repaired ticket test budget: PASS, code `12519`, tests `19839`, ratio
  `1.585` against baseline `1.642`.
- Accepted review debt: none.
