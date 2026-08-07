---
id: M13-T02
milestone: M13
status: done
depends_on: [M13-T01]
owns:
  - crates/ferrum2-core/src/lib.rs
  - crates/ferrum2-core/tests/selector_contract.rs
---

# M13-T02 — Add the owned egress-plan snapshot

## Outcome

Make core's graph allocation the only owned concrete-plan identity while preserving every borrowed
route/selector interface and result。

## Acceptance

- [ ] `EgressPlanSnapshot` is owned、immutable、clone/equality/hash capable and redacted；validated direct/
      chain plans are never empty and retain order/bounds。
- [ ] `snapshot_owned`、`select_plan_snapshot` and `final_plan_snapshot` share the graph's hop allocation；
      selection/clone does not copy hops。
- [ ] Existing borrowed methods and public module paths remain source/result compatible。
- [ ] Static、routed、final、chain and nested-selector rows prove old snapshots remain fixed after switch
      while later snapshots observe the switch。
- [ ] `TEST-0014` T02、repository Quick、ticket footprint and blocking Architect/QA review pass on one
      exact candidate。

## Validation

Run `TEST-0014` T02 commands，then repository Quick。Begin with one red owned-snapshot assertion and
close each vertical slice green before adding the next。

## Result

- Commit: initial `232d52646acd19b35f48ee4497cb2413a080d90c`；accepted/integrated repair
  `3228c469b3a9a0613d39bb193f18145e1ae8a2fc`。
- Review: initial Architect/QA `BLOCK` on `ARCH-M13T02-001`、`M13-T02-QA-001` and note
  `M13-T02-QA-002`；one bounded test-only repair；targeted Architect/QA `PASS`，all IDs closed。
- Notes: RED was exact missing-method `E0599` for `snapshot_owned`。Focused/core/clippy/Quick passed on
  integration；footprint integrity `PASS`，numeric ratio-only `WARN`，code/case/support/fixture delta
  `+31/+108/0/0`，no file signal。No remote action。

## Rollback / risk

Rollback removes only the additive owned interface/storage change；borrowed behavior remains the safety
path。Primary risks are hidden hop allocation、selector re-read and accidental outbound identity leakage。
