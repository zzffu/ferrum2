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
| M4-T02 | Run and record all M4 gates on one exact commit | M4-T01 | blocked |

## Next action

Local repair candidate `57d317ddb554bbbbc5cc324046277a514ce54324` has Architect
and QA `PASS`, WSL2 diagnosis, release self-check `mutations=10`, Full `6/6`, and
milestone budget `PASS_ADVANCE`. It replaces the collapsed probe error with static
redacted identity/failure classes and uses one thirty-second external-probe bound;
five-second I/O and reap bounds are unchanged. Preserve failed run `30697247986/1` on
`4cee0a1` as immutable evidence. Stop for a new exact, single-use authorization to push
`57d317d` and observe one fresh run; no remote action is currently allowed.
