---
id: M4-T02
milestone: M4
status: active
depends_on: [M4-T01]
owns:
  - tools/ferrum2-m4-qualification/src/m4_support/mod.rs
  - docs/ci-status.md
  - docs/tickets/M4-T02-qualify-preview-on-one-exact-commit.md
---

# M4-T02 — Qualify the preview on one exact commit

## Outcome

Use local gates only as pre-push diagnostics, then run the authoritative M4 driver and
all existing gates in one GitHub Actions run for one exact integrated commit. Record
the bounded summary needed for M4 close.

## Acceptance

- [ ] The hosted `performance` job passes `M4-GHA-01` preflight and reference SHA-256
      verification before measurement; no WSL2 result is accepted as qualification.
- [ ] Throughput records five trials per topology, both medians, ratio, and difference;
      the measured ratio is reported and never used as a pass threshold.
- [ ] The bounded 10k-idle run passes all 180 owner/task/RSS samples, six per-binary RSS
      window comparisons, and exact two-minute drain with both binaries alive.
- [ ] Local Full validation and milestone test-budget checks pass as diagnostic
      integration gates on the candidate SHA.
- [ ] After separate explicit authorization, one `push` run/attempt for that SHA passes
      performance, quality, MSRV, TCP/UDP `24/24`, all three native targets, and final
      qualification.
- [ ] P0/P1 blockers and blocking review findings are zero; runner-temp evidence is
      summarized then deleted, nothing raw is committed or uploaded, and no release or
      publication action occurs.
- [ ] Every bounded subprocess probe reports a static, redacted identity and distinct
      timeout, nonzero-exit, output-bound, secret-output, or UTF-8 failure class; the
      probe remains fail-closed and emits no command arguments, paths, or captured text.
- [ ] The five-second probe boundary is diagnosed under WSL2 before the final bounded
      timeout is selected; WSL2 remains diagnostic and cannot satisfy hosted acceptance.
- [ ] A valid initial ferrum2 metrics exposition with no lazily-created active-flow
      series is admitted as the zero pre-load baseline; malformed/unidentified metrics
      remain fail-closed, and post-load samples still require exact `10000` gauges.

## Validation

Run the exact T02 commands in TEST-0005, followed by:

```sh
sh scripts/test-budget.sh milestone --candidate <accepted-integration-sha>
git status --short
```

## Result

- Local repair candidate: `57d317ddb554bbbbc5cc324046277a514ce54324`
- Review: Architect `PASS`; QA `PASS`; no findings
- Notes: the repair keeps every external probe bounded, assigns a static redacted
  identity and distinct failure class, and raises only the identity/reference/hash
  probe limit from five to thirty seconds. `IO_TIMEOUT` and `REAP_TIMEOUT` remain five
  seconds. Release self-check passed with `mutations=10`; authoritative Full passed
  `6/6`; ticket and milestone budgets passed at code `13812`, tests `20740`, ratio
  `1.501593`.
- WSL2 diagnosis: the original five-second candidate completed the full hosted identity
  path `50/50` on a native Linux checkout. Mounted-worktree `git status` samples ranged
  from `0.775` to `3.297` seconds; a controlled six-second `git status` delay produced
  exactly `checkout status probe timed out`. The old hosted command cannot be recovered
  from its collapsed immutable log; thirty seconds is bounded diagnostic headroom, not
  a waiver or a throughput measurement change.
- Historical hosted result: single-use scope `M4-REMOTE-4cee0a1-A1` was consumed and
  auto-revoked before one non-force push of
  `4cee0a1e18450eb0a95c3e16a0903a735969591c`. GitHub Actions run
  [`30697247986`, attempt `1`](https://github.com/zzffu/ferrum2/actions/runs/30697247986)
  completed `failure`: quality, MSRV, interop, and all three native-platform rows
  succeeded; performance job `91362102185` failed after hosted preflight and the
  release build, and final qualification `91362498191` consequently failed. The
  performance log ended with `M4 qualification rejected: bounded identity probe
  failed`; cleanup succeeded, but no throughput or resource evidence was produced.
- Fresh hosted result: scope `M4-REMOTE-57d317d-A1` was consumed and auto-revoked
  before one non-force push of exact `57d317d`. GitHub Actions
  [`30698815475`, attempt `1`](https://github.com/zzffu/ferrum2/actions/runs/30698815475)
  completed `failure`: quality, MSRV, TCP/UDP `12/12` interop, and all three native
  platforms succeeded. Throughput completed five trials per topology with ferrum2
  median `7977915`, reference median `478773248`, and ratio `0.016663243`; resource
  then failed before load with `metrics readiness timed out`. Cleanup succeeded and
  final qualification failed. No resource sample, RSS window, or drain is credited.

## Blocker

- `HOSTED-M4-T02-001` is resolved: run `30698815475/1` passed every bounded identity,
  reference, and hash probe and completed throughput.
- `HOSTED-M4-T02-002`: the resource driver waits for an active-flow sample before it
  creates any flow, while the Prometheus `Family` creates that labelled series only on
  the first flow. Exact `57d317d` reproduces the circular wait `2/2` in WSL2 within
  `15.5` seconds; an independent server scrape returns valid HTTP/OpenMetrics with the
  active sample absent. Repair only this pre-load evidence seam, preserve exact post-load
  `10000` checks, then repeat local review/gates. No rerun, second push, dispatch, PR,
  release, publication, or other remote mutation is authorized.
