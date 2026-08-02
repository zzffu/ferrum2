---
id: M4-TCP-NODELAY-001
milestone: M4
status: done
depends_on: [M4-QUALITY-PORT-LOCK-001]
owns:
  - crates/ferrum2-runtime/src/connector.rs
  - crates/ferrum2-runtime/src/supervisor.rs
  - crates/ferrum2-runtime/tests/local_endpoint.rs
---

# M4-TCP-NODELAY-001 — Default product TCP sockets to TCP_NODELAY

## Outcome

Enable TCP_NODELAY before product TCP streams enter protocol or relay work. Reuse the
shared accepted-stream and post-connect runtime seams so both client and server inbound
and outbound data paths receive the same default.

## Acceptance

- [x] Client SOCKS and server Shadowsocks accepted TCP streams have TCP_NODELAY enabled.
- [x] Client-to-server and server-to-target streams returned by `TcpConnector` have
      TCP_NODELAY enabled.
- [x] Existing socket-option errors remain closed errors; no config, dependency, wire,
      diagnostic identity, metric identity, or workflow change is introduced.
- [x] Public-seam loopback tests record RED before implementation and GREEN afterward.
- [x] Focused, Quick, Full, ticket-budget, milestone-budget, diff, and cleanliness
      checks pass.

## Validation

```sh
cargo test -p ferrum2-runtime --test local_endpoint --locked
sh scripts/test-budget.sh ticket --base 6822945a0488591a30ab12c42ecffd02d82d220a --candidate <candidate-sha>
```

Run Quick, serial Full, and milestone-budget commands from
`docs/agents/milestone-workflow.md`. Scope `M4-REMOTE-TCP-NODELAY-A1` permits exactly
one next non-force push of the final validated integration SHA to
`codex/integration/m4` and its automatic push run. It permits no rerun, dispatch, PR,
release, publication, or second push.

## Result

- Commit: `c0de9bd87821b0de1c864f06acbe78a86accd60b`.
- TDD: the existing public loopback seam first failed on the connector socket's false
  TCP_NODELAY state, then passed after the post-connect change; its accepted socket
  assertion independently failed before the accept-seam change. Final focused result
  was `9/9`.
- Validation: Windows Quick and serial Full `6/6` passed. Native-ext4 WSL ran the same
  exact commit and passed focused `9/9` plus all `ferrum2-runtime` tests. Ticket and
  milestone budgets returned `PASS_ADVANCE` at code `14173`, tests `20878`, examples
  `132`, ratio `1.473083`, with ticket debt `4` and milestone debt `-2052`.
- Review: primary exact-diff review `PASS`; no blocker, major, minor, or note finding.
  Scope `M4-REMOTE-TCP-NODELAY-A1` is consumed and revoked for one non-force push of
  the final exact integration tree and its automatic push run.
