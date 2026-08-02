---
id: M6-T02
milestone: M6
status: todo
depends_on: [M6-T01]
owns:
  - crates/ferrum2-config/src/lib.rs
  - crates/ferrum2-config/tests/config_contract.rs
  - crates/ferrum2-shadowsocks/src/udp.rs
  - crates/ferrum2-shadowsocks/tests/**
  - crates/ferrum2-runtime/src/udp.rs
  - crates/ferrum2-runtime/tests/udp_runtime.rs
  - bins/ferrum2-client/**
  - tests/fixtures/config/client-*.toml
  - tests/m0-harness/src/local_support/mod.rs
  - tests/m0-harness/tests/config_cli.rs
  - tests/m0-harness/tests/socks_udp_local_e2e.rs
---

# M6-T02 — Compose the bounded client UDP association

## Outcome

Add explicit client `[udp]` opt-in and compose the T01 interface with one collision-safe
SIP022 client session, the existing runtime manager/budget/queues and supervised control
connection into a complete local public UDP path。

## Acceptance

- [ ] Absent client `[udp]` preserves the M3 cohort and old command rejection；explicit
      section reuses validated numeric limits, and disabled/check mode owns zero UDP resource。
- [ ] Setup reserves association/buffer capacity and both sockets before success reply；TCP
      peer IP authority plus fixed/learned port prevents an open relay, and invalid/wrong-source
      datagrams mutate nothing。
- [ ] Three methods and IPv4/IPv6/domain targets reuse existing SIP022 packet/replay/binding
      state with live-ID collision prevention。Authenticated response preparation borrows
      validated target/payload from precharged scratch；exact reservation precedes its sole
      owned materialization and commit。
- [ ] T02 promotes only the manager's existing per-handle cancellation/deadline operations；
      it adds no runtime loop/trait。Session/byte/queue/idle limits and generation cancellation
      remain owned by `UdpSessionManager`。
- [ ] One association alternates at least two targets；all three methods × IPv4/IPv6/domain
      pass exact composed maximum and silently drop one byte over before allocation/mutation。
- [ ] Control EOF/reset/write-half-close、idle、both socket I/O directions、child cancel、
      graceful/forced shutdown、sibling-root failure and restart/rebind return every session-ID/
      process/runtime/socket owner to baseline within the configured bound。
- [ ] Existing UDP families record only closed client-role values and no secret、endpoint、
      server or target cardinality；TCP CONNECT/server UDP behavior remains unchanged。
- [ ] Exact T02 commands, Full, MSRV, ticket budget and blocking Architect/QA review pass。

## Validation

Run `TEST-0007` T02 commands, then repository Full commands before integration。

## Result

- Commit: —
- Review: —
- Notes: —

## Rollback / risk

Rollback removes the optional section and client adapter as one vertical slice；server UDP and
protocol APIs remain。Do not add a shared listener、routing abstraction or new dependency to
solve the single configured-upstream path。
