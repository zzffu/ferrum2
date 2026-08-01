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
| M4-T01 | Add the Cargo driver and existing-workflow M4 qualification job | — | blocked |
| M4-T02 | Run and record all M4 gates on one exact commit | M4-T01 | todo |

## Blocker / next action

`M4-BUDGET-001` blocks M4-T01 before a candidate commit: pinned `rustloc 0.19.1`
classifies the required non-test Cargo driver's 1,802 new Rust lines below
`tests/m0-harness` as test growth, while `scripts/test-budget.sh` permits 120. The
alternate-index ticket gate returned `BLOCKED reason=ticket_allowance_exceeded`.
The validated working tree is parked at `.worktrees/m4-t01`; no hook bypass,
classifier gaming, baseline advance, or deletion of independent evidence is allowed.
Resume requires explicit authorization for a separately planned control-policy
amendment. T02's push/run remains separately unauthorized.
