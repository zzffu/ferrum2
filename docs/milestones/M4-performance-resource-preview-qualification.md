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
| M4-THP-PROFILE-001 | Bind and restore the hosted `max_ptes_none=0` profile | M4-T01 | active |
| M4-T02 | Run and record all M4 gates on one exact commit | M4-THP-PROFILE-001 | blocked |

## Next action

Preserve failed run `30710439015/1` on exact `a53a5d7`. Quality, MSRV,
interoperability, all three native-platform jobs, and diagnostic throughput passed;
performance failed the unchanged 105% resource gate at window 2 and final
qualification failed closed. The paired trajectories show exact `VmRSS == Rss`,
anonymous-only growth, large `AnonHugePages` growth, and a final plateau while all
active/fd/task tuples remain stable. This rules out the former RSS-accounting-only
hypothesis and contradicts an owner-count leak, while remaining only consistent with
delayed THP backing rather than proving the hosted allocator/kernel causal path. Execute
the authorized local `M4-THP-PROFILE-001` repair from exact `d9aa968`; it binds only the
selected hosted conformance profile and leaves product behavior and all resource
quantities, thresholds, and timing unchanged. Remote scope `M4-REMOTE-a53a5d7-A1` is
consumed and revoked; no rerun or new push is currently authorized.
