---
id: M11-T04
milestone: M11
status: todo
depends_on: [M11-T03]
owns:
  - tests/m0-harness/src/local_support/mod.rs
  - tests/m0-harness/tests/local_e2e.rs
  - tests/m0-harness/tests/socks_udp_local_e2e.rs
---

# M11-T04 — Prove two-hop real-process paths

## Outcome

Use the existing local process harness to prove actual client→server A→server B→target TCP/UDP paths
with different methods/PSKs，terminal later-hop failures、secret redaction and exact resource rebind。

## Acceptance

- [ ] One table-driven config/helper extension covers three method rotations、distinct PSKs、inheritance/
      override and static/route/selector chain roots without a second process or SIP022 harness。
- [ ] Real TCP multi-frame/half-close and UDP multi-datagram response-source paths pass through two actual
      server binaries in configured order。
- [ ] Hop-1/later-hop unavailable or wrong credentials never reach target、never reroute and expose no
      global/outbound secret in child stderr、trace or metrics。
- [ ] Bounded success/failure cycles terminate/reap client、both servers and target workers，observe zero
      owners and permit exact TCP/UDP listener rebind。
- [ ] `TEST-0012` T04、Rust 1.85、architecture、ticket footprint and blocking Architect/QA review pass on
      one exact candidate。

## Validation

Run `TEST-0012` T04 commands，then repository Quick commands。

## Result

- Commit: —
- Review: —
- Notes: —

## Rollback / risk

This ticket is evidence/support only。Rollback removes chain-specific rows without changing product；
M11 cannot close if the product requires a copied helper or cannot reap/rebind after later-hop failure。
