# M4 — Performance, resource, and v0 preview qualification

- Status: executing
- Baseline: `701925681df78ad83076ed67863bf4fecf46f77c`
- Owner: primary thread

## Outcome

Record a reproducible same-runner ferrum2/shadowsocks-rust TCP throughput baseline,
pass the single bounded 10,000-idle-session resource qualification, and converge the
existing full, interoperability, and native-platform gates in one GitHub Actions run
for one exact commit. M4 qualifies a v0 preview; it does not publish one.

## Non-goals

- A minimum throughput ratio, optimization work, or a production-performance claim.
- A long, multi-host, or all-platform soak.
- Packaging, signing, upload, tag, release, publication, or deferred product features.

## Exit criteria

- [ ] Five fixed-profile trials per implementation record both medians, the ferrum2 /
      shadowsocks-rust ratio, and the signed difference without a minimum ratio gate.
- [ ] 10,000 release-binary end-to-end TCP sessions pass the 5-minute stabilization,
      30-minute sampling, RSS-window, and 2-minute exact-drain contract in the same
      `M4-GHA-01` GitHub-hosted runner job as the throughput trials.
- [ ] Full validation, the test-budget milestone gate, TCP/UDP interop `24/24`, and all
      three native-platform rows pass in that workflow run/attempt for the same exact
      accepted commit.
- [ ] Blocking P0/P1 issues and blocking review findings are zero.

## Tickets

| Ticket | Outcome | Depends on | Status |
|---|---|---|---|
| M4-T01 | Add the Cargo driver and existing-workflow M4 qualification job | — | done |
| M4-T02 | Run and record all M4 gates on one exact commit | M4-T01 | active |

## Next action

Preserve failed run `30704646072/1` on exact `4468f75`: all six independent
quality/MSRV/interop/platform jobs succeeded, TCP/UDP recorded `12/12` with cleanup,
and throughput recorded `9035229 / 547376332`, difference `-98.349357020%`, ratio
`0.016506430`. Resource completed exact 10k plus 180 stable active/fd/task samples, but
server RSS median-twice rose from `2182832` to `2389976` KiB in window 2 (`+9.4897%`)
while client RSS remained `1907336`; drain was not reached. The driver currently gates
on Linux's potentially imprecise `/proc/<pid>/status` `VmRSS`. Under local scope
`M4-LOCAL-RSS-PAIR-001`, retain that gate, establish a fast parser regression, and add
bounded all-six `VmRSS` plus parallel `smaps_rollup` trajectories. Then complete review,
Full, budgets, and the native ext4 WSL2 resource profile. WSL2 remains diagnostic and
cannot close the hosted blocker. No rerun or new push is currently authorized.
