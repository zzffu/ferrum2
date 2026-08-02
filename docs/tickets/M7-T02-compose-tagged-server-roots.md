---
id: M7-T02
milestone: M7
status: todo
depends_on: [M7-T01]
owns:
  - crates/ferrum2-runtime/src/supervisor.rs
  - crates/ferrum2-runtime/src/udp.rs
  - crates/ferrum2-runtime/tests/lifecycle.rs
  - crates/ferrum2-runtime/tests/shutdown.rs
  - crates/ferrum2-runtime/tests/udp_runtime.rs
  - bins/ferrum2-server/src/run.rs
---

# M7-T02 — Compose tagged server roots

## Outcome

Build every validated Shadowsocks TCP/UDP inbound and referenced direct outbound as concrete server
adapters under one existing process transaction，sharing replay/admission/UDP capacity and rolling
back all listeners atomically。

## Acceptance

- [ ] Multiple ordered TCP listeners、enabled same-address UDP listeners and optional metrics join
      one `ProcessSupervisor` transaction；no root polls before all roots prepare。
- [ ] The server removes T01's fail-closed multi-inbound run guard only when every validated
      inbound/outbound is consumed by this transaction。
- [ ] `runtime.max_connections`、TCP replay、UDP sessions and allocated bytes are aggregate process
      owners rather than per-listener multipliers；backlog remains per listener。
- [ ] Static inbound→direct mapping has no selector/fallback。TCP replays across listeners fail
      before direct side effects while fresh flows and shared-outbound mappings succeed。
- [ ] Server UDP binds each accepted session to one local inbound，rejects cross-inbound packets
      before mutation and sends responses through the bound listener without weakening same-inbound
      roaming、replay or generation rules。
- [ ] First/middle/last TCP/UDP/metrics preparation、root fatal、signal and forced paths preserve
      first cause，reap shared owners and permit exact immediate rebind。
- [ ] Shared capacity, if needed, is one concrete runtime value；no new trait、Endpoint、factory、
      registry、core/protocol dependency or external crate is added。
- [ ] `TEST-0008` T02 commands、repository Full、MSRV、ticket budget and blocking Architect/QA
      review pass on one exact candidate。

## Validation

Run `TEST-0008` T02 commands, then repository Full commands before integration。

## Result

- Commit: —
- Review: —
- Notes: —

## Rollback / risk

Rollback removes multi-root server composition and any concrete shared-capacity constructor as one
slice。Cross-listener replay/response egress and partial bind are P0 review paths；per-listener
independent budgets are not an acceptable shortcut。
