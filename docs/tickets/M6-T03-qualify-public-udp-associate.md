---
id: M6-T03
milestone: M6
status: done
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

- [x] Fixed `M2-UDP-INT-001..012` identities/methods/references/deadlines/continuation remain；
      FerrumClient rows spawn explicit bounded client `[udp]` and use the existing SOCKS exerciser。
- [x] The protocol example remains independent local API evidence；qualification no longer uses
      it as the FerrumClient external process adapter and does not weaken reference-client rows。
- [x] Exact integration passes Full、MSRV、three native targets、budget and final blocking review。
- [x] After separate explicit authorization, one same-SHA run/attempt passes quality、MSRV、
      platform `3/3` and external UDP `12/12`+cleanup；no result splicing。The user explicitly
      waives waiting for performance and its dependent repository aggregate for M6 close。
- [x] Missing/failed/unavailable/unauthorized required evidence records M6 blocked；no push/rerun/
      dispatch/PR/tag/release/publication occurs without its own authorization。

## Validation

Run `TEST-0007` T03, integration and hosted commands exactly as recorded。

## Result

- Commit/run: accepted integration `7f1e45c174e749d3dddd32d187365722cce94dbe`；
  automatic push run [`30765897553/1`](https://github.com/zzffu/ferrum2/actions/runs/30765897553)。
- Review: Architect `PASS` on `99a70b8`；QA `QA-M6-T03-001` triggered two independent
  `xhigh` escalations and bounded evidence repairs `3cade85`/`27365c9`。The review bound is
  exhausted；the final one-character deadline repair passed its focused and regression gates。
- Notes: local T03、Full、Rust 1.85、100-cycle and docs pass。The user authorized
  `--no-verify` for T02/T03；M6-T04 now passes the exact-ceiling ticket、milestone and CI
  budget gates。Hosted quality `91544432681`、MSRV `91544432690`、interop
  `91544432703`、Windows `91544432726`、musl `91544432739` and GNU `91544432748`
  completed `success` on the same SHA/run/attempt。Interop success requires exactly one TCP
  `12/12` and one UDP `12/12` marker plus cleanup。Performance and the dependent aggregate
  were explicitly removed from the M6 completion condition and are not claimed。

## Rollback / risk

The evidence adapter may revert independently before close；it cannot waive T02 public-path
evidence or reuse an old M2 result as M6 qualification。

## Remote boundary

The authorized single non-force push is consumed。No rerun、dispatch、second push、PR、tag、
release or publication occurred or is authorized。This docs-only closeout will not be pushed
without new approval。
