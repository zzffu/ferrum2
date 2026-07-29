+++
id = "M3-T07"
title = "Isolate portable UDP lifecycle evidence under parallel execution"
milestone = "M3"
status = "ready"
priority = "P0"
risk = "high"
implementation_blocked_by = ["M3-T06"]
review_blocked_by = []
integration_blocked_by = ["M3-T06"]
release_blocked_by = ["M3-T01", "M3-T02", "M3-T03", "M3-T06"]
required_reviews = ["architect", "qa"]
owns = ["tests/m0-harness/tests/udp_local_e2e.rs"]
spec = "docs/specs/SPEC-0004-m3-operational-lifecycle-platform-contract.md"
test_plan = "docs/test-plans/TEST-0004-m3-operational-lifecycle-platform-contract.md"
acceptance = [
  "The portable IPv4 live-UDP signal row no longer reads or compares the process-global active-child baseline and does not serialize, ignore, retry, or otherwise weaken the parallel test binary",
  "The row still observes the authenticated UDP payload and proves that its UDP example remains live before a genuine OS shutdown signal is delivered to the real server",
  "The row performs bounded wait and reap for its own server and bounded termination and reap for its own UDP example, and the server exits with code zero",
  "After its owned processes are reaped, one immediate exact-address TCP bind-and-listen and one exact-address UDP bind both succeed without a sleep, deadline, or retry",
  "The complete non-ignored udp_local_e2e test binary passes 100 consecutive executions with four libtest threads, without filtering or serializing the portable row",
  "The exact candidate passes focused harness, authoritative quick and full, formatting, Clippy, ticket and milestone budget, control-plane, ownership, diff, and fresh Architect and QA full-review gates",
  "A new exact-descendant hosted run, not a rerun or evidence splice of run 30472227257, passes quality, MSRV, Windows MSVC, Linux GNU, Linux musl, interop, and final qualification on one SHA, run, and attempt",
]
+++

# M3-T07: Isolate portable UDP lifecycle evidence under parallel execution

## Outcome

Repair the late M3 hosted qualification evidence defect without reopening the bounded
M3-T05 or M3-T06 review histories. The portable admitted-UDP signal row proves cleanup
only for the processes it owns, so unrelated parallel `ChildGuard` activity cannot
change its verdict.

## Context

- Exact affected candidate:
  `bba40d127dee29a719d6ea1d80fb10427149d890`.
- GitHub Actions run `30472227257`, attempt `1`, passed all three native platform
  rows and interop, but quality and MSRV both failed
  `portable_ipv4_live_udp_signal_exits_cleanly_and_rebinds` at
  `tests/m0-harness/tests/udp_local_e2e.rs:95`.
- Quality observed current/baseline child counts `1/2`; MSRV observed `1/0`.
  Opposite process-global drift directions identify unrelated sibling-test activity,
  not an owned server that deterministically failed to reap.
- The exact portable row passed `30/30` when selected alone with one test thread.
  Run `30472227257` remains immutable failed evidence and contributes no PASS rows.
- Canonical release root `HOSTED-M3-T05-001` is repaired by this fresh ticket. T05's
  and T06's completed full/targeted review records and repair budgets are not changed.

## In scope

- Change only the existing portable IPv4 row in
  `tests/m0-harness/tests/udp_local_e2e.rs`.
- Remove its process-global child-count baseline observation.
- Preserve authenticated live UDP, genuine signal, bounded server wait/reap, bounded
  UDP-example termination/reap, exit code zero, and immediate exact TCP+UDP rebind.
- Prove the default parallel test-binary execution repeatedly and run the frozen M3
  local and release gates.

## Out of scope

- `tests/m0-harness/src/local_support/mod.rs`, product/runtime/config/wire/crypto,
  dependencies, manifests, unsafe code, CLI, logs, metrics, and public APIs.
- A global mutex, test serialization, `--test-threads=1`, ignore, delayed retry, or a
  second lifecycle harness.
- `.github/workflows/**`, `tests/platform/**`, and any new target or provider behavior.
- Reopening M3-T05 or M3-T06 reviews, rerunning run `30472227257`, or splicing its
  passing rows into a later qualification result.
- Remote push/dispatch/rerun, archive, installer, signing, upload, publication,
  release, performance, soak, or future-topology work under the local authorization.

## Contract references

- `ADR-0016` assigns outcome-first OS/process claims to black-box evidence.
- `ADR-0024` requires bounded cleanup and resource reacquisition.
- `SPEC-0004` M3-MUST-08/09/10 require lifecycle/rebind evidence and one exact-SHA
  hosted convergence result.
- `TEST-0004` assigns admitted UDP, signal, exit, and exact rebind to the existing
  process seam and forbids evidence splicing.
- A routine evidence-isolation repair does not require a new ADR or SPEC amendment.

## Primary evidence

| Acceptance | Primary evidence |
|---|---|
| 1–4 | existing portable IPv4 `udp_local_e2e` row and exact scoped diff |
| 5 | 100 consecutive complete test-binary runs with `--test-threads=4` |
| 6 | exact-SHA local gates and fresh Architect/QA full reviews |
| 7 | one new same-SHA/run/attempt GitHub Actions qualification result |

The row's server `wait_for_exit` performs its own reap before returning, the UDP
example is explicitly waited, and immediate exact TCP+UDP rebind proves listener
release. A process-global registry snapshot is duplicate, non-isolated evidence in a
parallel test binary.

## Validation commands

```powershell
cargo test -p ferrum2-m0-harness --test udp_local_e2e --locked -- --test-threads=4
1..100 | ForEach-Object {
  cargo test -p ferrum2-m0-harness --test udp_local_e2e --locked -- --test-threads=4
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
cargo fmt --all -- --check
python -X utf8 .agents/skills/milestone-workflow/scripts/workflow.py control-plane-check --base <ticket-base-sha> --candidate-sha <candidate-sha> --json
python -X utf8 .agents/skills/milestone-workflow/scripts/workflow.py test-budget --gate ticket --base <ticket-base-sha>
git diff --check <ticket-base-sha>..<candidate-sha>
```

The Team Lead runs the authoritative quick/full and milestone-budget gates serially
before integration and the new hosted qualification.

## Ownership and risks

- Engineer ownership is exactly
  `tests/m0-harness/tests/udp_local_e2e.rs`; the completed T06 historical ownership
  does not create an active writer conflict.
- T07 depends only on already-done T06 in scheduler metadata. T05 is the affected
  locally integrated qualification ticket, but making it a `done` dependency would
  create a release-repair deadlock while `HOSTED-M3-T05-001` remains open.
- A post-repair parallel failure with a different exact cause is a new root. It must
  not be hidden by serialization or retry and cannot expand ownership without
  separate authorization.
- Local scope `AUTH-M3-T07-LOCAL-001` excludes every remote effect. A later push must
  bind one exact full SHA and ref before it is consumed.

## Completion evidence

Filled by the Team Lead after integration and hosted qualification:

- Contract/base and candidate commits:
- Branch/worktree and changed paths:
- Full/targeted review records and stable finding IDs:
- Focused/repeated/quick/full commands and exit statuses:
- Test-budget/control/diff results:
- Hosted run/SHA/attempt/job results:
- Authorization and publication state:
