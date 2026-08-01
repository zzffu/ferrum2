+++
id = "M1-T03"
title = "Compose method-aware binaries and prove the local product matrix"
milestone = "M1"
status = "done"
priority = "P0"
risk = "high"
implementation_blocked_by = ["M1-T02"]
review_blocked_by = []
integration_blocked_by = ["M1-T01", "M1-T02"]
release_blocked_by = []
required_reviews = ["architect", "qa"]
owns = [
  "crates/ferrum2-config/**",
  "bins/ferrum2-client/**",
  "bins/ferrum2-server/**",
  "tests/fixtures/config/**",
  "tests/platform/**",
  "tests/m0-harness/src/local_support/**",
  "tests/m0-harness/tests/cli_contract.rs",
  "tests/m0-harness/tests/config_cli.rs",
  "tests/m0-harness/tests/detection_probe.rs",
  "tests/m0-harness/tests/local_e2e.rs",
  "tests/m0-harness/tests/lifecycle_cycles.rs",
]
spec = "docs/specs/SPEC-0002-m1-complete-tcp-methods-and-interop.md"
test_plan = "docs/test-plans/TEST-0002-m1-complete-tcp-methods-and-interop.md"
acceptance = [
  "Both binaries preserve the validated method with its PSK through composition and offline validation accepts exactly the three method-correct configurations",
  "Unknown, reduced-round, wrong-width, malformed, and noncanonical method/PSK configurations exit 2 with redacted stable errors before listener, runtime, connector, tracing, metrics, or task creation",
  "One bounded real-process matrix proves SOCKS5-to-direct echo for every method plus focused IPv4, IPv6, and domain cross-module rows without multiplying every combination",
  "Target refusal, resolution failure, no candidate, timeout, IPv4/IPv6 reply family, and post-SOCKS-success server failure remain observable at the SOCKS client seam with stable mapping",
  "Half-close, cancellation, partial-byte accounting, listener shutdown/rebind, and owner cleanup preserve bytes and terminate tasks and sockets for all methods through the existing lifecycle seams",
  "Existing tracing and Prometheus names, fixed label cardinality, secret and destination redaction, M0 native detection, and three-platform config-smoke contracts do not regress",
]
+++

# M1-T03: Compose method-aware binaries and prove the local product matrix

## Outcome

让 parsed method 不再在 composition roots 丢失，并以最小 real-process matrix
证明三个 methods 与三个 target classes 的实际产品交互、失败和生命周期。

## In scope

- schema v1 method/key validation 和 synthetic config fixtures。
- client/server method-bound crypto/protocol composition。
- existing local process support、CLI/config、detection、E2E、lifecycle tests。
- focused IPv6/domain/refusal/reply/error rows。
- existing platform config-smoke fixture updates。

## Out of scope

- protocol/crypto internals、root dependencies/lock。
- external reference driver、interop pins/workflow、hosted execution。
- observability production source changes；既有 source 只作 regression evidence。
  若确需修改，必须先由 Team Lead 显式 amendment ownership。
- UDP、M3 final platform qualification、M4 performance。

## Contract references

- `ADR-0018` method-bound composition。
- `ADR-0019` address/deadline/reply behavior。
- `SPEC-0002` M1-AC-01/04/05/06/08。
- `TEST-0002` product/integration commands 与 process evidence economy。

## Primary evidence

| Acceptance | Primary evidence |
|---|---|
| 1–2 | config crate table + existing offline binary process seam |
| 3–4 | one bounded local real-process method/address/outcome matrix |
| 5 | existing lifecycle suite parameterized only for changed method owner |
| 6 | existing detection/platform/redaction/cardinality sentinel targets |

真实 OS rows 证明 adapters/composition，不重复 T02 的完整 address codec/ordering
negative table。

## Validation commands

```powershell
cargo test -p ferrum2-config -p ferrum2-client -p ferrum2-server --locked
cargo test -p ferrum2-m0-harness --test cli_contract --test config_cli --test local_e2e --test lifecycle_cycles --test detection_probe --locked
cargo fmt --all -- --check
$env:PYTHONUTF8='1'
python .agents/skills/milestone-workflow/scripts/workflow.py test-budget --gate ticket --base <ticket-base-sha>
git diff --check
```

## Ownership and risks

- T03 只编辑列出的 local harness files；不得用
  `tests/m0-harness/**` broad glob 与 T04 重叠。
- method × address 只选能杀死跨 module wiring/family defect 的 rows，不建立
  9×每层 duplicate。
- external qualification 不在本机运行；M0/hosted 旧结果不是 T03 pass。
- process/temp/port/child owner、readiness/operation deadline 和 bounded capture
  沿用 M0 proven seam。

## Completion evidence

- Branch/worktree/candidate: `codex/ticket/m1-t03`,
  `C:\project\ferrum2\.worktrees\m1-t03`,
  `4c9ad421e0ef5d193e29e70ed5a674cb30a4aa88`; product integration commit
  `2d4cb763ed632fb6d160679386eaf498ed5044f6`.
- Reviews: Architect and QA full reviews on the exact candidate both
  `PASS_WITH_NOTES`; there was no blocker, major finding, or repair round.
  Stable notes are `ARCH-M1-T03-001`, `QA-M1-T03-001`, and
  `QA-M1-T03-002`.
- Candidate validation: config/client/server package tests passed 31/31;
  the exact five-target harness command passed 17/17, including the fixed
  5×20 lifecycle matrix; focused strict Clippy, fmt, ticket budget, and
  `git diff --check` all exited 0. Engineer workspace quick also exited 0.
- Integration validation on `2d4cb76`: binary build; authoritative quick
  fmt/check/tests; authoritative full fmt/Clippy/all-feature tests/docs;
  workflow validation and `git diff --check` all exited 0.
- Test budget: ticket gate `PASS`, code `7720`, tests `15639`, ratio `2.026`;
  baseline `7031/14707/2.092`; delta `+10/+128`, allowance `130`.
- Accepted review debt: this Windows host binds `[::1]` but raw loopback
  connect fails `WSAEACCES`, so the real-process IPv6 target row was
  **NOT EXECUTED** and its IPv4 fallback counts only for third-method
  echo/half-close. The local platform artifact run was setup-blocked by an
  occupied fixed port 1080. Exact-SHA IPv6-capable and frozen three-platform
  evidence remain release-qualification requirements and are not local PASS.
- Push/publish/external qualification: none.
