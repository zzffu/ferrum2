---
id: M10-T01
milestone: M10
status: done
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

- [x] Legacy/static/routed configs stay exact；tagged-only `[[selectors]]` validates count、global tags、
      explicit defaults、members、transitive reachability and all-edge cycles with closed redacted fields。
- [x] Static bindings、route rules and final resolve concrete/selector tags；one route query still returns
      one concrete outbound index and no-selector numeric results remain exact。The new public compile
      entry validates tagged identity domains and returns shared route/control state atomically；existing
      concrete-only constructors cannot accept or return logical selector IDs。
- [x] `final_outbound()` and `ValidatedClientConfig.server` remain immutable concrete configured-default
      compatibility snapshots；live runtime choices use `select()` and observe current members。
- [x] The public handle proves immediate-member query、valid/no-op switch、nested resolution、exact
      unknown/concrete-as-selector and unknown/case/non-member/descendant-only member no-mutation、
      Display/Debug redaction and bounded linearizable concurrency using only public types。
- [x] Core uses immutable bounded graph plus atomics，without trait、async lock、new crate/dependency、
      I/O、retry、persistence or test-only mutation surface。
- [x] Both public loaders and `--check-config` accept valid selector graphs and reject invalid/inert graphs
      before subscriber/runtime/listener creation。
- [x] `TEST-0011` T01、repository Quick、ticket footprint and blocking Architect/QA review pass on one
      exact candidate。

## Validation

Run `TEST-0011` T01 commands，then repository Quick commands from
`docs/agents/milestone-workflow.md`。

## Result

- Candidate: `1a61427fc8b1622333b052a204625864dc04c16d`；integrated product exact
  `e6ede87ae314fe201bc6412bacd360bc0505cf4c`。
- Review: Architect `PASS_WITH_NOTES`；QA initially blocked as `QA-M10T01-001` because every positive
  selector default was member zero。Two independent read-only xhigh analyses selected the same test-only
  repair；targeted Architect `PASS_WITH_NOTES` and QA `PASS` resolved the finding with no new blocker。
- Validation: core selector `2/2`、config contract `10/10`、config CLI `5/5`、focused Clippy/fmt、
  repository Quick and `git diff --check` passed；workspace tests `308` passed、`5` ignored、`0` failed。
- Footprint: code/tests `16646/27150`，ratio `1.631022`；ticket case/support/fixture
  `234/0/0`，integrity/category `PASS`。Only expected numeric file `WARN` remains for
  `config_contract.rs` (`979` semantic test LOC，`+108`)；no `REVIEW_REQUIRED` file。

## Rollback / risk

Rollback removes selector parsing/state while preserving concrete route behavior。Do not expose a
selector config that either binary can index as a concrete outbound or retain tag values in errors。
