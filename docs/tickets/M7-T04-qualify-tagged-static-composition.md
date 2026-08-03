---
id: M7-T04
milestone: M7
status: active
depends_on: [M7-T03]
owns:
  - tests/m0-harness/src/local_support/mod.rs
  - tests/m0-harness/src/bin/m0_qualification.rs
  - tests/m0-harness/tests/architecture.rs
  - tests/m0-harness/tests/lifecycle_cycles.rs
  - tests/m0-harness/tests/local_e2e.rs
  - tests/m0-harness/tests/udp_local_e2e.rs
  - tests/m0-harness/tests/socks_udp_local_e2e.rs
  - tests/m0-harness/tests/qualification_contract.rs
---

# M7-T04 — Qualify tagged static composition

## Outcome

Reuse the existing process/platform/interop harnesses to prove bounded multi-instance behavior and
qualify one exact integration SHA without a new provider、workflow job or performance claim。

## Acceptance

- [ ] A bounded real-process table exercises at least two client and server inbounds/outbounds、
      both static TCP/UDP mappings、shared outbound and no-fallback；all three methods are covered
      without a tag cross product。
- [ ] Focused process rows prove aggregate admission、cross-listener replay/UDP binding、partial
      bind rollback、root fatal、signal shutdown、at least 100 completed cycles and exact rebind。
- [ ] Existing legacy config/CLI、local TCP、server UDP、SOCKS UDP and architecture gates remain；
      core/protocol modules contain no Endpoint/config/runtime dependency or generic registry。
- [ ] Existing external TCP and UDP case IDs/methods/references/deadlines/cleanup remain unchanged
      and pass `12/12` each on the accepted SHA。
- [ ] Windows MSVC、Linux GNU/musl native rows run tagged offline validation and bounded
      multi-listener rollback/rebind；missing/setup/skipped is BLOCKED。
- [ ] Exact integration passes Full、Rust 1.85、budget and final blocking review。After separate
      explicit authorization only，one same-SHA run/attempt may supply hosted evidence；no result
      splicing、rerun、second push、PR、tag、release or publication。

## Validation

Run `TEST-0008` T04、integration and hosted commands exactly as recorded。

## Result

- Commit/run: —
- Review: —
- Notes: —

## Rollback / risk

Evidence-only changes may revert independently before close，but they cannot waive T01～T03
product evidence or reuse M6 results as M7 qualification。Performance remains a repository
regression only，not an M7 acceptance threshold。
