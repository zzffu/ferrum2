---
id: M11-T04
milestone: M11
status: done
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

- [x] One table-driven config/helper extension covers three method rotations、distinct PSKs、inheritance/
      override and static/route/selector chain roots without a second process or SIP022 harness。
- [x] Real TCP multi-frame/half-close and UDP multi-datagram response-source paths pass through two actual
      server binaries in configured order。
- [x] Hop-1/later-hop unavailable or wrong credentials never reach target、never reroute and expose no
      global/outbound secret in child stderr、trace or metrics。
- [x] Bounded success/failure cycles terminate/reap client、both servers and target workers，observe zero
      owners and permit exact TCP/UDP listener rebind。
- [x] `TEST-0012` T04、Rust 1.85、architecture、ticket footprint and blocking Architect/QA review pass on
      one exact candidate。

## Validation

Run `TEST-0012` T04 commands，then repository Quick commands。

## Result

- Commit: ticket `bf4f032bbe27f1a24bd75a935360e5a28e52dc15`；integrated product
  `6d975c1e45eb0e614c54961e35fdc19fa2478d98`。
- Review: Architect `PASS`；QA `PASS`；`ARCH-M11-T04-006/007` resolved by one direct repair and
  targeted re-review。
- Notes: both real-process exact rows、full local process suites、architecture、Rust 1.85 and repository
  Quick pass。Ticket/integration footprint integrity passes；case/support/fixture `+565/+121/0`、growth
  `686` and ratio `2.025588` numeric signals are reviewed and accepted。

## Rollback / risk

This ticket is evidence/support only。Rollback removes chain-specific rows without changing product；
M11 cannot close if the product requires a copied helper or cannot reap/rebind after later-hop failure。
