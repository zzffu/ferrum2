---
id: M8-T04
milestone: M8
status: todo
depends_on: [M8-T03]
owns:
  - tests/m0-harness/src/local_support/mod.rs
  - tests/m0-harness/src/bin/m0_qualification.rs
  - tests/m0-harness/tests/architecture.rs
  - tests/m0-harness/tests/lifecycle_cycles.rs
  - tests/m0-harness/tests/local_e2e.rs
  - tests/m0-harness/tests/udp_local_e2e.rs
  - tests/m0-harness/tests/socks_udp_local_e2e.rs
  - tests/m0-harness/tests/qualification_contract.rs
  - tests/platform/qualify_native.py
---

# M8-T04 — Qualify shared first-match routing

## Outcome

Reuse existing process/platform/interop harnesses to prove bounded routed TCP/UDP behavior and
qualify one exact integration SHA without a new provider、workflow job or performance claim。

## Acceptance

- [ ] A bounded real-process matrix proves ordered rule、AND/wildcard、final、two inbounds/
      outbounds and one UDP association routing two targets to two servers without a cross product。
- [ ] Focused rows prove no failure fallback、response source binding、aggregate bounds、partial
      bind、root fatal、signal、100+ cycles and exact restart/rebind。
- [ ] Existing legacy/M7 static config/CLI、TCP、server UDP、SOCKS UDP and architecture gates
      remain；one core route module exists and protocol/runtime crates own no routing policy。
- [ ] Existing external TCP/UDP IDs/methods/references/deadlines/cleanup remain unchanged and pass
      `12/12` each on the accepted SHA。
- [ ] Windows/GNU/musl native rows run routed offline validation and bounded route smoke；
      missing/setup/skipped is BLOCKED。
- [ ] Exact integration passes Full、Rust 1.85、M8 Budget and final blocking review。After separate
      explicit authorization only，one same-SHA run/attempt may supply hosted evidence；no result
      splicing、rerun、second push、PR、tag、release or publication。

## Validation

Run `TEST-0009` T04、integration and hosted commands exactly as recorded。

## Result

- Commit/run: —
- Review: —
- Notes: —

## Rollback / risk

Evidence changes may revert independently before close，but cannot waive T01～T03 product evidence
or reuse M7 results as M8 qualification。Performance remains regression-only。
