---
id: M11-T03
milestone: M11
status: active
depends_on: [M11-T02]
owns:
  - crates/ferrum2-shadowsocks/src/udp.rs
  - crates/ferrum2-shadowsocks/tests/udp_packets.rs
  - bins/ferrum2-client/src/run.rs
---

# M11-T03 — Compose bounded UDP chains

## Outcome

Layer one selected UDP plan inner-to-outer and authenticate/open responses outer-to-inner with exact
per-hop credentials、intermediate target binding、nested length bounds and association-owned cleanup。

## Acceptance

- [ ] Mixed-method/distinct-PSK tables prove request/response hop order、only-first-hop network send and
      final SOCKS target/payload across static and routed plan snapshots。
- [ ] Outer/inner tamper、wrong credential、replay、wrong intermediate target and cross-plan response fail
      without alternate send、application output or partial accepted replay/association mutation。
- [ ] Exact nested maximum succeeds；maximum+1 and eight-hop overhead reject before reservation/session/
      counter mutation using bounded reusable buffers rather than one maximum buffer per hop。
- [ ] Lazy per-plan/per-hop state has a fixed ceiling，shares existing aggregate admission/byte/live-ID
      owners and is fully removed on idle、I/O failure、control close、graceful or forced cancellation。
- [ ] `TEST-0012` T03、repository Full、ticket footprint and blocking Architect/QA review pass on one
      exact candidate。

## Validation

Run `TEST-0012` T03 commands，then repository Full commands before integration。

## Result

- Commit: —
- Review: —
- Notes: —

## Rollback / risk

Rollback restores one-layer UDP and rejects chains at run。Primary risks are cross-plan response
confusion、inner-invalid outer-state poisoning and unaccounted per-plan socket/session growth。
