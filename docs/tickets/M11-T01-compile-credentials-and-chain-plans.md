---
id: M11-T01
milestone: M11
status: active
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

- [ ] Legacy/global and tagged-inheritance values remain exact；complete per-outbound method/PSK uses the
      existing method-bound secret owner，while either partial field fails at the closed redacted field。
- [ ] Client-only `[[chains]]` enforces collection/tag/global-collision、`2..=8` unique concrete hops、
      reachability and server/legacy rejection；errors expose no tag、endpoint、method value or PSK。
- [ ] Static/rule/final and selectors choose one immutable one-or-many-hop plan；direct-only results stay
      exact，public selector switch chooses a whole plan and old returned plans stay unchanged。
- [ ] Every outbound is reachable directly or through a reachable chain；no inert credential/chain is
      accepted and no stock-client path can silently truncate a chain。
- [ ] `TEST-0012` T01、repository Quick、ticket footprint and blocking Architect/QA review pass on one
      exact candidate。

## Validation

Run `TEST-0012` T01 commands，then repository Quick commands from
`docs/agents/milestone-workflow.md`。

## Result

- Commit: —
- Review: —
- Notes: —

## Rollback / risk

Rollback removes additive fields/plan compilation and rejects new documents。The main risk is an index
domain that lets a chain be mistaken for one concrete outbound；public tests must kill that mutation。
