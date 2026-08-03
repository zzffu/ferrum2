---
id: M7-T02
milestone: M7
status: done
depends_on: [M7-T01]
owns:
  - crates/ferrum2-runtime/src/supervisor.rs
  - crates/ferrum2-runtime/src/udp.rs
  - crates/ferrum2-runtime/tests/lifecycle.rs
  - crates/ferrum2-runtime/tests/shutdown.rs
  - crates/ferrum2-runtime/tests/udp_runtime.rs
  - bins/ferrum2-server/src/run.rs
  - tests/m0-harness/tests/config_cli.rs
---

# M7-T02 — Compose tagged server roots

## Outcome

Build every validated Shadowsocks TCP/UDP inbound and referenced direct outbound as concrete server
adapters under one existing process transaction，sharing replay/admission/UDP capacity and rolling
back all listeners atomically。

## Acceptance

- [x] Multiple ordered TCP listeners、enabled same-address UDP listeners and optional metrics join
      one `ProcessSupervisor` transaction；no root polls before all roots prepare。
- [x] The server removes T01's fail-closed multi-inbound run guard only when every validated
      inbound/outbound is consumed by this transaction。
- [x] The shared CLI transition row expects the composed server to reach its occupied endpoint and
      fail closed as `startup.bind`，while the uncomposed client still fails as `startup.protocol`；
      `--check-config` and pre-existing endpoint ownership remain unchanged。
- [x] `runtime.max_connections`、TCP replay、UDP sessions and allocated bytes are aggregate process
      owners rather than per-listener multipliers；backlog remains per listener。
- [x] Static inbound→direct mapping has no selector/fallback。TCP replays across listeners fail
      before direct side effects while fresh flows and shared-outbound mappings succeed。
- [x] Server UDP binds each accepted session to one local inbound，rejects cross-inbound packets
      before mutation and sends responses through the bound listener without weakening same-inbound
      roaming、replay or generation rules。
- [x] First/middle/last TCP/UDP/metrics preparation、root fatal、signal and forced paths preserve
      first cause，reap shared owners and permit exact immediate rebind。
- [x] Shared capacity, if needed, is one concrete runtime value；no new trait、Endpoint、factory、
      registry、core/protocol dependency or external crate is added。
- [x] `TEST-0008` T02 commands、repository Full、MSRV、ticket budget and blocking Architect/QA
      review pass on one exact candidate。

## Validation

Run `TEST-0008` T02 commands, then repository Full commands before integration。

## Result

- Commit: candidate `d1b3dbe45e20d4d2476ccfde809ded945741c472`；integrated
  `b864a40a5ada975c09c5b95a1373bd3c15373bdf`。
- Review: Architect/QA initial BLOCK on per-root shared UDP shutdown；the same bounded repair also
  closed missing middle bind positions、independent byte saturation and complete owner-baseline
  evidence。Targeted Architect/QA reviews PASS with every finding resolved and no new blocker/major。
- Notes: exact candidate focused、Quick、Full、Rust 1.85 and ignored lifecycle qualification PASS；
  integration runtime `17/5/13`、server `19/19`、CLI `5/5`、binary build、Clippy/fmt/diff PASS。
  Budget is `PASS_HOLD` at code/tests `15506/23534` and ticket debt `99/120`。The first integration
  CLI invocation found a stale pre-T02 binary；the required workspace bin build alone made the
  exact repro and full suite pass，with no source change。

## Rollback / risk

Rollback removes multi-root server composition and any concrete shared-capacity constructor as one
slice。Cross-listener replay/response egress and partial bind are P0 review paths；per-listener
independent budgets are not an acceptable shortcut。
