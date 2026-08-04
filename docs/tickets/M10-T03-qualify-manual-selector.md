---
id: M10-T03
milestone: M10
status: todo
depends_on: [M10-T02]
owns:
  - tests/m0-harness/tests/architecture.rs
  - docs/ci-status.md
  - docs/handoffs/HANDOFF-M10-*.md
  - docs/milestones/M10-manual-outbound-selector.md
  - docs/roadmap.md
  - docs/tickets/M10-T03-qualify-manual-selector.md
---

# M10-T03 — Qualify manual selector

## Outcome

Reuse existing process、platform and interoperability evidence to qualify one exact M10 integration SHA，
without inventing a child-process switch channel、new provider/job or performance claim。

## Acceptance

- [ ] Public-interface and four data-plane focused tests pass on the accepted exact SHA；query/switch/
      concurrency/error claims do not rely on private state or a process control backdoor。
- [ ] Existing real-process tagged/routed TCP and UDP rows prove configured default startup、no-fallback、
      response binding、100+ lifecycle and exact restart/rebind without a new harness/helper。
- [ ] Architecture evidence proves one core selector module、no protocol/runtime policy duplicate、no new
      trait/dependency/control transport and no tag/selection telemetry。
- [ ] Exact integration passes Full、Rust 1.85、three native targets、existing TCP/UDP `12/12` each、
      schema 3 footprint and final blocking review。
- [ ] Any hosted evidence uses one exact SHA/run/attempt only after separate explicit authorization；no
      splicing、rerun、second push、PR、tag、release or publication。

## Validation

Run `TEST-0011` T03 and integration commands exactly as recorded。Remote commands remain unrun until
separately authorized。

## Result

- Commit/run: —
- Review: —
- Footprint: forecast `0/0/0` new case/support/fixture LOC；reuse only。

## Rollback / risk

Evidence changes may revert independently before close but cannot waive T01/T02 product evidence or use
an old hosted run as M10 qualification。Performance remains regression-only。
