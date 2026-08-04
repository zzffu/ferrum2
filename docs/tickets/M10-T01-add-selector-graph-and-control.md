---
id: M10-T01
milestone: M10
status: ready
depends_on: []
owns:
  - crates/ferrum2-core/src/lib.rs
  - crates/ferrum2-core/tests/selector_contract.rs
  - crates/ferrum2-config/src/lib.rs
  - crates/ferrum2-config/tests/config_contract.rs
  - tests/m0-harness/tests/config_cli.rs
---

# M10-T01 — Add selector graph and public control

## Outcome

Add one bounded runtime-neutral selector module，compile additive tagged selector graphs for both roles，
and expose a public atomic query/switch handle shared by the existing route table before any side effect。

## Acceptance

- [ ] Legacy/static/routed configs stay exact；tagged-only `[[selectors]]` validates count、global tags、
      explicit defaults、members、transitive reachability and all-edge cycles with closed redacted fields。
- [ ] Static bindings、route rules and final resolve concrete/selector tags；one route query still returns
      one concrete outbound index and no-selector numeric results remain exact。
- [ ] The public handle proves immediate-member query、valid/no-op switch、nested resolution、exact
      unknown-selector/member no-mutation and bounded linearizable concurrency using only public types。
- [ ] Core uses immutable bounded graph plus atomics，without trait、async lock、new crate/dependency、
      I/O、retry、persistence or test-only mutation surface。
- [ ] Both public loaders and `--check-config` accept valid selector graphs and reject invalid/inert graphs
      before subscriber/runtime/listener creation。
- [ ] `TEST-0011` T01、repository Quick、ticket footprint and blocking Architect/QA review pass on one
      exact candidate。

## Validation

Run `TEST-0011` T01 commands，then repository Quick commands from
`docs/agents/milestone-workflow.md`。

## Result

- Commit: —
- Review: —
- Footprint: forecast `155/0/0` case/support/fixture LOC；`config_contract.rs` file WARN expected。

## Rollback / risk

Rollback removes selector parsing/state while preserving concrete route behavior。Do not expose a
selector config that either binary can index as a concrete outbound or retain tag values in errors。
