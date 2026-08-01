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

Preserve failed run `30700273019/1` on exact `2f4190c`: all six independent
quality/MSRV/interop/platform jobs succeeded, TCP/UDP recorded `12/12` with cleanup,
and throughput recorded `9013384 / 480717482`, ratio `0.018749857`. Resource passed
readiness, exact 10k load, and 180 stable active/fd/task samples, then failed because
RSS window 2 exceeded 105%; cleanup succeeded and drain was not reached. Raw samples
were correctly deleted, but the bounded error omits the binary and first/current
medians. Local scope `M4-LOCAL-RSS-DIAG-001` is consumed and revoked to add only that
bounded redacted diagnostic, preserving the 105% threshold, sample profile, and drain
contract, then run self-check, reviews, Full, and budget. Diagnose before requesting
any new remote scope; no rerun or new push is authorized.
