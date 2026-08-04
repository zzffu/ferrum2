---
id: M11-T02
milestone: M11
status: active
depends_on: [M11-T01]
owns:
  - crates/ferrum2-shadowsocks/src/lib.rs
  - crates/ferrum2-shadowsocks/tests/tcp_flow_contract.rs
  - bins/ferrum2-client/src/run.rs
---

# M11-T02 — Compose fixed TCP chains

## Outcome

Open one selected immutable TCP plan in hop order with each concrete outbound's effective credential，
reusing the existing SIP022 client state machine under one connection owner。

## Acceptance

- [ ] A mixed-method/distinct-PSK table proves raw dial A、request B through A and final target through
      B；swapped/skipped hop or credential fails。
- [ ] The minimum transport composition seam nests existing `ClientFlow` owners without another cipher/
      protocol implementation、dependency or detached per-hop relay task。
- [ ] Outer/inner tamper、wrong credential、unavailable/later-hop failure and cancellation terminate the
      full stack with zero retry/fallback/application forwarding and preserved selector state。
- [ ] Per-layer buffers、half-close、abortive terminal、deadline and zeroization behavior remain bounded；
      an open flow keeps its selected plan while a later flow may observe a selector switch。
- [ ] `TEST-0012` T02、repository Full、ticket footprint and blocking Architect/QA review pass on one
      exact candidate。

## Validation

Run `TEST-0012` T02 commands，then repository Full commands before integration。

## Result

- Commit: —
- Review: —
- Notes: —

## Rollback / risk

Rollback restores one-hop TCP composition while retaining T01 only if chain configs fail closed at run。
The main risk is inner failure being flattened into apparent success or leaving an outer owner live。
