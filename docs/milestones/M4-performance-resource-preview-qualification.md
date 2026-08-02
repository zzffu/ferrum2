# M4 — Performance, resource, and v0 preview qualification

- Status: closed
- Baseline: `701925681df78ad83076ed67863bf4fecf46f77c`
- Owner: primary thread

## Outcome

Record a reproducible same-runner ferrum2/shadowsocks-rust TCP throughput baseline,
pass the single bounded 10,000-idle-session resource qualification, and converge the
existing full, interoperability, and native-platform gates in one GitHub Actions run
for one exact commit. M4 qualifies a v0 preview; it does not publish one.

## Non-goals

- A minimum throughput ratio, broad optimization work, or a production-performance
  claim. The separately user-authorized default TCP_NODELAY ticket is the only narrow
  optimization in M4.
- A long, multi-host, or all-platform soak.
- Packaging, signing, upload, tag, release, publication, or deferred product features.

## Exit criteria

- [x] Five fixed-profile trials per implementation record both medians, the ferrum2 /
      shadowsocks-rust ratio, and the signed difference without a minimum ratio gate.
- [x] 10,000 release-binary end-to-end TCP sessions pass the 5-minute stabilization,
      30-minute sampling, RSS-window, and 2-minute exact-drain contract in the same
      `M4-GHA-01` GitHub-hosted runner job as the throughput trials.
- [x] Full validation, the test-budget milestone gate, TCP/UDP interop `24/24`, and all
      three native-platform rows pass in that workflow run/attempt for the same exact
      accepted commit.
- [x] Blocking P0/P1 issues and blocking review findings are zero.

## Tickets

| Ticket | Outcome | Depends on | Status |
|---|---|---|---|
| M4-T01 | Add the Cargo driver and existing-workflow M4 qualification job | — | done |
| M4-THP-PROFILE-001 | Bind and restore the hosted `max_ptes_none=0` profile | M4-T01 | done |
| M4-QUALITY-PORT-LOCK-001 | Serialize UDP local E2E port ownership | M4-THP-PROFILE-001 | done |
| M4-TCP-NODELAY-001 | Default product TCP sockets to TCP_NODELAY | M4-QUALITY-PORT-LOCK-001 | done |
| M4-T02 | Run and record all M4 gates on one exact commit | M4-TCP-NODELAY-001 | done |

## Close evidence

Exact `9b379a426853d86a184464f6fd8c73081b464535` automatic push run
[`30730883667/1`](https://github.com/zzffu/ferrum2/actions/runs/30730883667)
passed all M4 jobs and final qualification. Ferrum2/reference medians were
`50860305/476470749` bytes/s, ratio `0.106743814`, and signed difference
`-89.325618602%`; the ratio remained diagnostic. The selected THP profile applied and
restored, and resource passed exact 10k, `180/180`, `6/6`, drain, and cleanup. Full,
security, process, MSRV, TCP/UDP `24/24`, three platforms, and test budget passed for
the same SHA. Blocking P0/P1 issues and review findings are zero. M4 qualified but did
not package, publish, or release the v0 preview.
