---
id: M11-T01
milestone: M11
status: done
depends_on: []
owns:
  - crates/ferrum2-core/src/lib.rs
  - crates/ferrum2-core/tests/selector_contract.rs
  - crates/ferrum2-config/src/lib.rs
  - crates/ferrum2-config/tests/config_contract.rs
  - tests/m0-harness/tests/config_cli.rs
---

# M11-T01 — Compile credentials and fixed chain plans

## Outcome

Validate additive client outbound credential pairs and fixed chain tags into one bounded immutable
direct/chain plan domain consumed by the existing route/selector graph，before any runtime side effect。

## Acceptance

- [x] Legacy/global and tagged-inheritance values remain exact；complete per-outbound method/PSK uses the
      existing method-bound secret owner，while either partial field fails at the closed redacted field。
- [x] Client-only `[[chains]]` enforces collection/tag/global-collision、`2..=8` unique concrete hops、
      reachability and server/legacy rejection；errors expose no tag、endpoint、method value or PSK。
- [x] Static/rule/final and selectors choose one immutable one-or-many-hop plan；direct-only results stay
      exact，public selector switch chooses a whole plan and old returned plans stay unchanged。
- [x] Every outbound is reachable directly or through a reachable chain；no inert credential/chain is
      accepted and no stock-client path can silently truncate a chain。
- [x] `TEST-0012` T01、repository Quick、ticket footprint and blocking Architect/QA review pass on one
      exact candidate。

## Validation

Run `TEST-0012` T01 commands，then repository Quick commands from
`docs/agents/milestone-workflow.md`。

## Result

- Candidate: `e322b6361d973c3fc572a165a920efdaee9e7cf1`；integrated product exact
  `173d1642a1d992b9fefa1bb381c15b826c64ac2d`。
- Review: Architect `PASS_WITH_NOTES`；QA initially blocked as `M11-T01-QA-001` because the nine-hop
  negative also contained duplicate hops。Two mandated independent read-only xhigh analyses selected
  the same one-row test-only repair；targeted Architect `PASS_WITH_NOTES` and QA `PASS` resolved it。
- Validation: core selector `3/3`、config contract `14/14`、config CLI `5/5`、focused Clippy/fmt、
  repository Quick and `git diff --check` passed；workspace tests `311` passed、`5` ignored、`0` failed。
  The fresh integration worktree's first CLI run lacked built binaries；the required workspace bins build
  passed and the unchanged rerun passed `5/5`。
- Footprint: code/tests `16909/27581`，ratio `1.631143`；ticket case/support/fixture `239/0/0`，
  integrity/category `PASS`。Only the expected numeric file `WARN` remains for `config_contract.rs`
  (`1145` semantic test LOC，`+166`)；no `REVIEW_REQUIRED` file。

## Rollback / risk

Rollback removes additive fields/plan compilation and rejects new documents。The main risk is an index
domain that lets a chain be mistaken for one concrete outbound；public tests must kill that mutation。
