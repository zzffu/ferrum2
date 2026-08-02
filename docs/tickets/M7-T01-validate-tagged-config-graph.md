---
id: M7-T01
milestone: M7
status: active
depends_on: []
owns:
  - crates/ferrum2-config/src/lib.rs
  - crates/ferrum2-config/tests/config_contract.rs
  - tests/fixtures/config/*tagged*.toml
  - tests/m0-harness/tests/config_cli.rs
  - bins/ferrum2-client/src/run.rs
  - bins/ferrum2-server/src/run.rs
---

# M7-T01 — Validate and normalize the tagged config graph

## Outcome

Extend both schema v1 loaders with one bounded tagged shape，normalize legacy documents to one
inbound/outbound，and return only complete static references before any runtime side effect。

## Acceptance

- [ ] Every baseline legacy fixture retains exact normalized values/defaults and one effective
      inbound/outbound；tagged/legacy mixing and heuristic fallback are rejected。
- [ ] Tagged mode enforces `1..=64` entries per side、global exact unique tags、the approved
      ASCII/length grammar、complete inbound→outbound resolution and no unreferenced outbound。
- [ ] All inbound/metrics/client-server endpoint collisions are validated globally；invalid graph
      errors remain closed `config.semantic` and expose no tag、endpoint、PSK or raw source。
- [ ] Validated config owns concrete role-specific collections/resolved references；callers do not
      parse strings or perform fallible reference lookup after `load_*` succeeds。
- [ ] `--check-config` covers legacy/tagged positives and graph negatives with zero runtime
      resource；no new dependency、protocol kind field or `Endpoint` interface is added。
- [ ] Until T02/T03 consume the full graph，each binary rejects a multi-inbound run with the
      existing `startup.protocol` error before observability、runtime or listener side effects；
      one-entry legacy/tagged execution remains unchanged。
- [ ] `TEST-0008` T01 commands、repository Quick、ticket budget and blocking Architect/QA review
      pass on one exact candidate。

## Validation

Run `TEST-0008` T01 commands, then repository Quick commands from
`docs/agents/milestone-workflow.md`。

## Result

- Commit: —
- Review: —
- Notes: —

## Rollback / risk

One config/guard revert restores legacy-only parsing。T02/T03 remove only their corresponding
fail-closed guard when they consume the full graph。Do not include tag/endpoint values in
diagnostics to improve operator specificity。
