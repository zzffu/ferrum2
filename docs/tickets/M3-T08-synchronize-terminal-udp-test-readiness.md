+++
id = "M3-T08"
title = "Synchronize terminal UDP test readiness on its causal event"
milestone = "M3"
status = "done"
priority = "P0"
risk = "high"
implementation_blocked_by = ["M3-T06"]
review_blocked_by = []
integration_blocked_by = ["M3-T06"]
release_blocked_by = ["M3-T01", "M3-T02", "M3-T03", "M3-T06"]
required_reviews = ["architect", "qa"]
owns = ["bins/ferrum2-server/src/run.rs"]
spec = "docs/specs/SPEC-0004-m3-operational-lifecycle-platform-contract.md"
test_plan = "docs/test-plans/TEST-0004-m3-operational-lifecycle-platform-contract.md"
acceptance = [
  "The terminal-UDP server-private test contains no fixed-count yield_now readiness loop or equivalent scheduler-count assumption",
  "The existing one-second target-side datagram receive completes and verifies listener-failure before live owner counts are asserted",
  "After that causal event the test observes exactly one active process root, UDP session, and UDP task before releasing the target response",
  "The response still drives the scripted listener terminal error and the process completes within the existing 500 ms bound with the original RuntimeListener root cause, no cleanup failure, and zero forced roots",
  "Final evidence still proves root and session cleanup, one process-root reap, one forced UDP shutdown, and the existing forced-shutdown metric value",
  "The focused test and complete affected UDP server-private subset pass 100 consecutive two-thread executions without serialization, retry, filtering away the subject, or enlarged deadlines",
  "The exact candidate passes the server suite, authoritative quick and full gates, formatting, ticket and milestone budgets, control-plane, ownership, diff, and fresh full Architect and QA review gates before local integration",
]
+++

# M3-T08: Synchronize terminal UDP test readiness on its causal event

## Outcome

Repair the second late M3 hosted qualification evidence defect without reopening the
bounded M3-T06 or M3-T07 review histories. The server-private terminal-UDP test uses
the target-side datagram already present in the scenario as its causal admission
event instead of guessing readiness from a fixed number of scheduler yields.

## Context

- Exact affected candidate:
  `bc14971c51982b6ad9a970593fb3848b2763b112`.
- GitHub Actions run `30476271774`, attempt `1`, passed Windows MSVC, Linux GNU,
  Linux musl, and interop. Quality job `90658650037` and MSRV job `90658649997`
  both failed
  `run::tests::udp_terminal_error_with_live_session_notifies_process_and_reaps`
  at `bins/ferrum2-server/src/run.rs:2715`, observing `udp_sessions` as `0`
  instead of `1`; qualification job `90659341369` was a derivative failure.
- Both failed jobs report the M3-T07 portable row
  `portable_ipv4_live_udp_signal_exits_cleanly_and_rebinds ... ok`, resolving
  canonical root `HOSTED-M3-T05-001`.
- The affected server-private test first polls at most 100 `yield_now` calls and
  only afterwards performs an already-bounded target `recv_from`. A scheduler-count
  loop is not an event or deadline guarantee. The target datagram cannot arrive
  until the direct UDP session and task owners have been committed.
- Local exact execution passed once and the complete two-thread UDP subset passed
  `150/150`; no stable product failure was established. Run `30476271774` remains
  immutable failed evidence and contributes no PASS rows.
- Canonical release root `HOSTED-M3-T07-002` is repaired by this fresh ticket.
  T06 and T07 completed review records and repair budgets remain immutable.

## In scope

- Change only the body of
  `udp_terminal_error_with_live_session_notifies_process_and_reaps` in
  `bins/ferrum2-server/src/run.rs`.
- Await and validate the existing target-side datagram before taking the live owner
  snapshot.
- Remove the fixed 100-yield readiness loop.
- Preserve the existing one-second target receive bound, 500 ms process bound,
  terminal listener cause, cleanup/reap/forced-session assertions, and metric
  assertion.
- Prove the affected UDP subset repeatedly in parallel and run the frozen M3 local
  gates.

## Out of scope

- Any production portion of `bins/ferrum2-server/src/run.rs`.
- Runtime, UDP, supervisor, config, wire, crypto, CLI, metrics, dependencies,
  manifests, unsafe code, or public APIs.
- A new readiness primitive or product test hook, timeout increase, retry, sleep,
  serialization, ignore, or new harness.
- Other source/test files, `.github/workflows/**`, `tests/platform/**`, or
  `tests/m0-harness/**`.
- Reopening M3-T06 or M3-T07 reviews, rerunning an old hosted attempt, or splicing
  passing rows from a failed run.
- Remote push/dispatch/rerun, PR, archive, installer, signing, upload, publication,
  release, force, deletion, performance, soak, or future-topology work under the
  local authorization.

## Contract references

- `ADR-0016` assigns internal owner claims to direct composition evidence and allows
  equivalent evidence substitution without weakening normative outcomes.
- `ADR-0024` requires terminal required-root failure, bounded cleanup, and owner
  baseline.
- `SPEC-0004` M3-MUST-08/09/10 require root-fatal, cleanup, and one exact-SHA hosted
  convergence result rather than a particular readiness mechanism.
- `TEST-0004` already assigns this claim to the production-used server-private
  composition seam.
- This routine evidence synchronization repair needs no ADR or SPEC amendment.

## Primary evidence

| Acceptance | Primary evidence |
|---|---|
| 1–5 | existing terminal-UDP server-private test and exact scoped diff |
| 6 | 100 consecutive affected UDP-subset runs with `--test-threads=2` |
| 7 | exact-SHA local gates and fresh Architect/QA full reviews |

`DirectUdpRuntime::commit_session_with` creates the UDP session/task owners before
spawning the task that sends the first target datagram. Therefore receipt at the
stalled target is a causal, test-owned readiness event; adding a larger poll count or
timeout would remain a weaker scheduler guess.

## Validation commands

```powershell
cargo test -p ferrum2-server --bin ferrum2-server run::tests::udp_terminal_error_with_live_session_notifies_process_and_reaps --locked -- --exact
1..100 | ForEach-Object {
  cargo test -p ferrum2-server --bin ferrum2-server 'run::tests::udp_' --locked -- --test-threads=2
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
cargo test -p ferrum2-server --bin ferrum2-server --locked
cargo fmt --all -- --check
python -X utf8 .agents/skills/milestone-workflow/scripts/workflow.py control-plane-check --base <ticket-base-sha> --candidate-sha <candidate-sha> --json
python -X utf8 .agents/skills/milestone-workflow/scripts/workflow.py test-budget --gate ticket --base <ticket-base-sha>
git diff --check <ticket-base-sha>..<candidate-sha>
```

The Team Lead runs authoritative quick/full and milestone-budget gates serially
before local integration. A later exact-SHA push and fresh hosted run require a
separate remote authorization.

## Ownership and risks

- Engineer ownership is the path `bins/ferrum2-server/src/run.rs`, but the approved
  delta is narrower: only the named private test body may change. Review and
  integration must reject any production hunk.
- T08 depends only on already-done T06 in scheduler metadata. T07 is the exact
  integrated lineage but remains release-pending, so making it a `done` scheduler
  dependency would create a late-repair deadlock.
- The historical T06 ownership of `run.rs` is not an active writer conflict.
- The unrelated one-off local Windows UDP `ConnectionReset` is diagnostic noise
  unless independently reproduced. A distinct repeated failure becomes a new root
  rather than expanding this ticket.
- Local scope `AUTH-M3-T08-LOCAL-001` excludes every remote effect. A later push must
  bind one exact full SHA and ref before use.

## Completion evidence

- **Contract/base and candidate:** contract commit
  `04aaba1dc1010c65f2be1bb40ef9c027b78dcbc5`; final ticket and cumulative
  qualified product SHA
  `d9e59d787c3fe78dfca778ee8a36668a45387368`.
- **Branch/worktree and scope:** `codex/ticket/m3-t08` in
  `C:\project\ferrum2\.worktrees\m3-t08`; integrated through
  `codex/integration/m3`. The only implementation delta is inside the named
  private test in `bins/ferrum2-server/src/run.rs`: four insertions and eleven
  deletions replace the fixed-yield readiness guess with the existing bounded
  target-datagram event. Production behavior is unchanged.
- **Reviews:** fresh Architect and QA full reviews at exact `d9e59d78...` both
  returned `PASS` with no findings. No targeted round, repair budget, or
  accepted review debt was required.
- **Local evidence:** the exact test passed; the complete affected two-thread
  UDP subset passed `100/100`; the server suite passed `16/16`. Formatting,
  scoped strict Clippy, ownership, diff, control-plane, review, integration,
  authoritative quick `5/5`, and authoritative full `6/6` gates exited `0`.
  Ticket budget passed at code `12956`, tests `19861`, ratio `1.533`, delta
  `0/0`, allowance `120`; milestone budget passed at delta code/tests
  `1242/627`, allowance `1362`.
- **Hosted evidence:** GitHub Actions run `30494736004`, attempt `1`, event
  `push`, at exact `d9e59d78...` completed `success`. Job IDs
  `90720794923` (quality), `90720794873` (MSRV), `90720794992` (Windows
  MSVC), `90720795107` (Linux GNU), `90720794921` (Linux musl),
  `90720794966` (interop), and `90721365575` (final qualification) all
  succeeded on the same SHA/run/attempt, resolving `HOSTED-M3-T07-002`.
- **Authorization/publication:** local scope `AUTH-M3-T08-LOCAL-001` and exact
  remote scope `AUTH-M3-T08-REMOTE-001` were each consumed and revoked `1/1`.
  The remote grant covered exactly one non-force fast-forward push to
  `refs/heads/codex/integration/m3` plus read-only monitoring. No additional
  push, rerun, dispatch, remote `master` update, force, PR, tag, release,
  upload, signing, publication, ref deletion, or control-plane mutation
  occurred.
