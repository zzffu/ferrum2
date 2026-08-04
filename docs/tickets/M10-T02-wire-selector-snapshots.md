---
id: M10-T02
milestone: M10
status: done
depends_on: [M10-T01]
owns:
  - bins/ferrum2-client/src/run.rs
  - bins/ferrum2-server/src/run.rs
---

# M10-T02 — Wire selector snapshots through TCP/UDP

## Outcome

Prove and，only where required，minimally adapt the four existing client/server TCP/UDP selection seams
so later calls observe public selector switches and work that already captured a concrete identity does not。

## Acceptance

- [x] Client/server TCP resolve after existing target authentication/validation and before outbound
      connect/write；an open flow stays on its concrete member and a later flow observes the switch。
- [x] Client static UDP keeps its association-setup snapshot；client routed UDP and server UDP preserve
      their per-validated-datagram selection and already-selected leg/response identity。
- [x] Switches in tests use only the public control handle；no direct atomic/private-index mutation or
      test-only route implementation is added。
- [x] Selected member failure is no-fallback and does not change current state；nested/shared selectors
      have one process-local state across all inbound/rule references。
- [x] Existing auth/replay/source/inbound binding、reserve/commit ordering、aggregate owners/bytes/IDs、
      idle/cancel/fatal/forced/rebind and observability contracts remain exact。
- [x] `TEST-0011` T02、repository Full、ticket footprint and blocking Architect/QA review
      pass on one exact candidate。

## Validation

Run `TEST-0011` T02 commands，then repository Full commands before integration。

## Result

- Candidate: `9cc74b1b2ca52e7df1f7f67863726233fa0ea69c`；integrated product exact
  `93ed9d91929200a1786694ffd59e491b7188a5d1`。All changes are test-only in the two owned files；the
  existing production selection seams already had the required timing and snapshot granularity。
- Review: Architect and QA both `PASS_WITH_NOTES` with no blocker/major/minor。`ARCH-M10T02-001` and
  `M10-T02-QA-N01` accept the footprint growth because the distinct real TCP/static-UDP/routed-UDP/
  server composition seams reuse existing helpers and no new harness or third equivalent helper exists。
- Validation: five temporary wrong-snapshot mutations were RED and fully reverted；four exact focused
  tests passed `1/1`，packages passed `29/29 + 18/18`，Clippy/fmt/diff passed。Integration Full passed，
  including all-feature workspace tests，lifecycle `1/1` in `126.02s` and docs。The Engineer's first
  lifecycle attempt used an insufficient `120s` tool deadline；the exact rerun passed in `125.72s`。
- Footprint: ticket case/support/fixture `169/0/0` and integrity/change level `PASS`；milestone cumulative
  `403/0/0` versus forecast `230/0/0`。Code/tests `16646/27319`，ratio `1.641175`。Client/server
  `run.rs` are explicitly accepted `REVIEW_REQUIRED` at `3527 (+137)` / `1809 (+32)` semantic test LOC。

## Rollback / risk

Rollback restores concrete-only composition while retaining T01's validated selector graph only if both
binaries fail closed before side effects。Post-snapshot re-resolution or owner-wide interruption is blocking。
