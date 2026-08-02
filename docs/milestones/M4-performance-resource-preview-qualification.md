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

- A minimum throughput ratio, broad optimization work, or a production-performance
  claim. The separately user-authorized default TCP_NODELAY ticket is the only narrow
  optimization in M4.
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
| M4-THP-PROFILE-001 | Bind and restore the hosted `max_ptes_none=0` profile | M4-T01 | done |
| M4-QUALITY-PORT-LOCK-001 | Serialize UDP local E2E port ownership | M4-THP-PROFILE-001 | done |
| M4-TCP-NODELAY-001 | Default product TCP sockets to TCP_NODELAY | M4-QUALITY-PORT-LOCK-001 | active |
| M4-T02 | Run and record all M4 gates on one exact commit | M4-TCP-NODELAY-001 | blocked |

## Next action

Preserve failed run `30725843401/1` on exact `35fb3f8`. Performance passed throughput,
the selected THP profile, exact 10k, all 180 samples, all six RSS windows, exact drain,
restoration, and cleanup. MSRV, interoperability, and all three native-platform jobs
also passed. Quality alone failed before product startup when parallel
`udp_local_e2e` tests raced during a released-port handoff; final qualification then
failed closed. Scope `M4-REMOTE-FINAL-A1` was consumed and revoked by that one push and
automatic run. Local `M4-QUALITY-PORT-LOCK-001` is complete at exact `5f4fed7`: both
WSL 200-run loops, the native-ext4 harness, Full `6/6`, and both budgets passed. Execute
the user-authorized `M4-TCP-NODELAY-001`, then validate the final exact integration SHA.
Scope `M4-REMOTE-TCP-NODELAY-A1` permits exactly one next non-force push to
`codex/integration/m4` and its automatic push run. It permits no rerun, dispatch, PR,
release, publication, or second push.
