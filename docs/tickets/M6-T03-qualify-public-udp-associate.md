---
id: M6-T03
milestone: M6
status: ready
depends_on: [M6-T02]
owns:
  - tests/m0-harness/src/external_support/mod.rs
  - tests/m0-harness/src/qualification/mod.rs
  - tests/m0-harness/tests/qualification_contract.rs
---

# M6-T03 — Qualify the public UDP association

## Outcome

Use the composed client binary for the existing six FerrumClient UDP external rows, retain the
six reference-client rows, and qualify one exact M6 integration SHA without a new provider、
matrix or workflow job。

## Acceptance

- [ ] Fixed `M2-UDP-INT-001..012` identities/methods/references/deadlines/continuation remain；
      FerrumClient rows spawn explicit bounded client `[udp]` and use the existing SOCKS exerciser。
- [ ] The protocol example remains independent local API evidence；qualification no longer uses
      it as the FerrumClient external process adapter and does not weaken reference-client rows。
- [ ] Exact integration passes Full、MSRV、three native targets、budget and final blocking review。
- [ ] After separate explicit authorization, one same-SHA run/attempt passes external UDP
      `12/12`+cleanup and repository final qualification；no result splicing。
- [ ] Missing/failed/unavailable/unauthorized evidence records M6 blocked；no push/rerun/
      dispatch/PR/tag/release/publication occurs without its own authorization。

## Validation

Run `TEST-0007` T03, integration and hosted commands exactly as recorded。

## Result

- Commit/run: —
- Review: —
- Notes: —

## Rollback / risk

The evidence adapter may revert independently before close；it cannot waive T02 public-path
evidence or reuse an old M2 result as M6 qualification。
