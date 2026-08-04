---
id: M10-T02
milestone: M10
status: active
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

- [ ] Client/server TCP resolve after existing target authentication/validation and before outbound
      connect/write；an open flow stays on its concrete member and a later flow observes the switch。
- [ ] Client static UDP keeps its association-setup snapshot；client routed UDP and server UDP preserve
      their per-validated-datagram selection and already-selected leg/response identity。
- [ ] Switches in tests use only the public control handle；no direct atomic/private-index mutation or
      test-only route implementation is added。
- [ ] Selected member failure is no-fallback and does not change current state；nested/shared selectors
      have one process-local state across all inbound/rule references。
- [ ] Existing auth/replay/source/inbound binding、reserve/commit ordering、aggregate owners/bytes/IDs、
      idle/cancel/fatal/forced/rebind and observability contracts remain exact。
- [ ] `TEST-0011` T02、repository Full、ticket footprint and blocking Architect/QA review
      pass on one exact candidate。

## Validation

Run `TEST-0011` T02 commands，then repository Full commands before integration。

## Result

- Commit: —
- Review: —
- Footprint: forecast `75/0/0` case/support/fixture LOC；both growing `run.rs` files require explicit
  file `REVIEW_REQUIRED` disposition。

## Rollback / risk

Rollback restores concrete-only composition while retaining T01's validated selector graph only if both
binaries fail closed before side effects。Post-snapshot re-resolution or owner-wide interruption is blocking。
