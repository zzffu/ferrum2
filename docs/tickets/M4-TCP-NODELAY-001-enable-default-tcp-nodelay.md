---
id: M4-TCP-NODELAY-001
milestone: M4
status: active
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

- [ ] Client SOCKS and server Shadowsocks accepted TCP streams have TCP_NODELAY enabled.
- [ ] Client-to-server and server-to-target streams returned by `TcpConnector` have
      TCP_NODELAY enabled.
- [ ] Existing socket-option errors remain closed errors; no config, dependency, wire,
      diagnostic identity, metric identity, or workflow change is introduced.
- [ ] Public-seam loopback tests record RED before implementation and GREEN afterward.
- [ ] Focused, Quick, Full, ticket-budget, milestone-budget, diff, and cleanliness
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

- Pending.
