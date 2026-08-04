---
id: M11-T03
milestone: M11
status: done
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

- [x] Mixed-method/distinct-PSK tables prove request/response hop order、only-first-hop network send and
      final SOCKS target/payload across static and routed plan snapshots。
- [x] Outer/inner tamper、wrong credential、replay、wrong intermediate target and cross-plan response fail
      without alternate send、application output or partial accepted replay/association mutation。
- [x] Exact nested maximum succeeds；maximum+1 and eight-hop overhead reject before reservation/session/
      counter mutation using bounded reusable buffers rather than one maximum buffer per hop。
- [x] Lazy per-plan/per-hop state has a fixed ceiling，shares existing aggregate admission/byte/live-ID
      owners and is fully removed on idle、I/O failure、control close、graceful or forced cancellation。
- [x] `TEST-0012` T03、repository Full、ticket footprint and blocking Architect/QA review pass on one
      exact candidate。

## Validation

Run `TEST-0012` T03 commands，then repository Full commands before integration。

## Result

- Commit: ticket `0bb938a8d0bedc9d6f3a384b3d55a56aaa6078b8`；integrated product
  `4a82f59bec3b0e957530bef05e763b1ab2d6ffd6`。
- Review: Architect `PASS`；QA `PASS`；all stable findings resolved。
- Notes: ticket and integration focused gates、repository Full、100+ lifecycle and docs pass。Ticket
  footprint integrity and ratio `1.982775` pass；numeric test growth/large-file signal is reviewed and
  accepted。The first integration lifecycle invocation was tool-killed by an undersized 60-second command
  timeout；the unchanged exact command passed `1/1` in `130.29s` with a sufficient timeout。

## Rollback / risk

Rollback restores one-layer UDP and rejects chains at run。Primary risks are cross-plan response
confusion、inner-invalid outer-state poisoning and unaccounted per-plan socket/session growth。
