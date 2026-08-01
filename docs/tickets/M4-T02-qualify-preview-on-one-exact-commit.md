---
id: M4-T02
milestone: M4
status: active
depends_on: [M4-T01]
owns:
  - Cargo.lock
  - tools/ferrum2-m4-qualification/Cargo.toml
  - tools/ferrum2-m4-qualification/src/m4_support/mod.rs
  - tests/m0-harness/tests/workspace_policy.rs
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

- Probe repair candidate: `57d317ddb554bbbbc5cc324046277a514ce54324`
- Resource-readiness repair: `56aadd4b25baacb6972ed9bf65ae5052a0d4c6a8`
- RSS diagnostic repair: `7b63bd588e1be600beb417636ed0d37ac3b0fb44`
- WSL target-backlog repair: `7c19e80f7c7fcb68e3c6b3e562c6d01a379ebf47`
- Hosted diagnostic source: `4468f75ecc055531f554d218fb89b6b079dc432d`
- Review: Architect `PASS`; QA `PASS`; no findings on the local resource repairs
- Notes: the probe repair keeps every external probe bounded, assigns a static redacted
  identity and distinct failure class, and raises only the identity/reference/hash
  probe limit from five to thirty seconds. `IO_TIMEOUT` and `REAP_TIMEOUT` remain five
  seconds. The resource repair treats lazy active-series absence as zero only for a
  complete HTTP 200 exposition anchored by the stable eager replay gauge; malformed,
  duplicate, or unidentified input remains rejected, and post-load exact `10000` is
  unchanged. Release self-check passed with `mutations=11`; authoritative Full passed
  `6/6`; ticket and milestone budgets passed at code `13879`, tests `20740`, ratio
  `1.494344`.
- RSS diagnostic TDD used the same release self-check command: RED exit `1` reported
  the old generic window-only error, then GREEN exit `0` reported `mutations=11`.
  The repair adds only the already-computed client/server first/current median-twice
  integers to the bounded error; the 105% comparison and complete resource profile are
  unchanged. Architect and QA returned `PASS` with no findings. Focused checks and both
  budgets passed at code `13897`, tests `20740`, ratio `1.492408`; final Full evidence
  is recorded on the integration docs descendant.
- WSL2 diagnosis: the original five-second candidate completed the full hosted identity
  path `50/50` on a native Linux checkout. Mounted-worktree `git status` samples ranged
  from `0.775` to `3.297` seconds; a controlled six-second `git status` delay produced
  exactly `checkout status probe timed out`. The old hosted command cannot be recovered
  from its collapsed immutable log; thirty seconds is bounded diagnostic headroom, not
  a waiver or a throughput measurement change.
- WSL2 resource validation: exact `7c19e80` requested backlog `10000` only for the
  synthetic resource target. Architect and QA independently returned `PASS` with no
  findings. Full passed `6/6`; ticket and milestone budgets passed at code `13906`,
  tests `20756`, ratio `1.492593`. The native ext4 run reached exact `10000` target
  accepts, completed `180/180` samples and `6/6` RSS windows, passed exact drain, and
  exited `0` after `2131` seconds. All six client/server median-twice values remained
  `1909544/1966728` KiB; Linux reported zero listen overflow/drop and cleanup left no
  driver/client/server process. This is diagnostic evidence, not hosted qualification.
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
- Latest hosted result: scope `M4-REMOTE-2f4190c-A1` was consumed and auto-revoked
  before one non-force push of exact `2f4190c`. GitHub Actions
  [`30700273019`, attempt `1`](https://github.com/zzffu/ferrum2/actions/runs/30700273019)
  completed `failure`: quality, MSRV, TCP/UDP `12/12` interop, and all three native
  platforms succeeded. Throughput completed with ferrum2 median `9013384`, reference
  median `480717482`, and ratio `0.018749857`. Resource passed readiness, established
  exact `10000`, collected all 180 samples with stable active/fd/task tuples, then
  rejected RSS window 2 above 105%. Cleanup succeeded; drain was not reached.
- Current hosted result: scope `M4-REMOTE-4468f75-A1` was consumed and auto-revoked
  before one non-force push of exact `4468f75`. GitHub Actions
  [`30704646072`, attempt `1`](https://github.com/zzffu/ferrum2/actions/runs/30704646072)
  completed `failure`: quality, MSRV, TCP/UDP `12/12` interop, and all three native
  platforms succeeded. Throughput passed with ferrum2 median `9035229`, reference
  median `547376332`, signed difference `-98.349357020%`, and ratio `0.016506430`.
  Resource established exact `10000`, collected all 180 stable active/fd/task samples,
  then failed window 2. Client median-twice stayed `1907336/1907336` KiB; server moved
  `2182832` to `2389976` KiB (`+103572` KiB actual, `+9.4897%`). Cleanup succeeded;
  drain was not reached and final qualification failed closed.
- Paired-RSS diagnostic authorization: local scope `M4-LOCAL-RSS-PAIR-001` permits one
  writer to modify only the non-shipping qualification driver, using its existing
  `self-check` seam for RED→GREEN coverage of strict `smaps_rollup` parsing and bounded
  all-six-window paired trajectories. The current `VmRSS` 105% gate, 10k load, timing,
  drain, product binaries, workflow, SPEC, and TEST profile remain unchanged. The scope
  includes Architect/QA review, local Full/budgets, and a complete native ext4 WSL2
  resource diagnostic. It authorizes no push, workflow run/dispatch, PR, release, or
  publication.

## Blocker

- `HOSTED-M4-T02-001` is resolved: run `30698815475/1` passed every bounded identity,
  reference, and hash probe and completed throughput.
- `HOSTED-M4-T02-002` is resolved: the resource driver previously waited for an
  active-flow sample before it created any flow, while the Prometheus `Family` creates
  that labelled series only on the first flow. Exact `57d317d` reproduces the circular
  wait `2/2` in WSL2 within
  `15.5` seconds; an independent server scrape returns valid HTTP/OpenMetrics with the
  active sample absent. Repair only this pre-load evidence seam, preserve exact post-load
  `10000` checks. Exact `56aadd4` implements that repair; both reviews and all local
  gates passed, and run `30700273019/1` proceeded through exact 10k load and all 180
  samples.
- `HOSTED-M4-T02-003`: exact `4468f75` confirms a server-only window-2 RSS rise after
  all active/fd/task tuples remained stable; client RSS did not move. This rules out
  growing task/socket/session ownership but does not distinguish a product leak,
  delayed page residency, a step then plateau, or Linux RSS-accounting behavior. The
  driver reads `/proc/<pid>/status` `VmRSS`, which Linux documents as asynchronous and
  potentially imprecise; accurate `smaps_rollup` is available in WSL2, but the exact WSL
  profile passed and is not a hosted reproduction. Preserve the existing gate and first
  add one fast red-capable parser check plus bounded all-six median trajectories for the
  existing and accurate signals. Local scope `M4-LOCAL-RSS-PAIR-001` is active for that
  work; no push, rerun, dispatch, PR, release, publication, or other remote mutation is
  authorized.
- `LOCAL-M4-T02-004`: exact `d28ed0a` reproduced `target did not accept 10000
  streams` in two native WSL2 runs. Both product active gauges reached exact `10000`,
  while the qualification driver retained fewer target-side streams and Linux
  reported listener overflows/drops. The resource-only synthetic target uses the
  platform-default `TcpListener::bind` backlog against fixed setup concurrency `256`.
  Local scope `M4-LOCAL-WSL-TARGET-BACKLOG-001` authorizes one writer to reuse the
  already pinned workspace `socket2` dependency, set an explicit synthetic-target
  backlog without weakening the profile, update the exact dependency policy/lock edge,
  run local reviews and WSL2 validation, and integrate the reviewed repair locally.
  Exact `7c19e80` implements the repair and passed both reviews, Full, both budgets,
  and the complete WSL2 resource mode above. The scope is consumed and revoked. It
  authorized no push, workflow run/dispatch, PR, release, or publication.
