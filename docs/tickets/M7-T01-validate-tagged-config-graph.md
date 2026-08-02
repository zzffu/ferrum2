---
id: M7-T01
milestone: M7
status: done
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

- [x] Every baseline legacy fixture retains exact normalized values/defaults and one effective
      inbound/outbound；tagged/legacy mixing and heuristic fallback are rejected。
- [x] Tagged mode enforces `1..=64` entries per side、global exact unique tags、the approved
      ASCII/length grammar、complete inbound→outbound resolution and no unreferenced outbound。
- [x] All inbound/metrics/client-server endpoint collisions are validated globally；invalid graph
      errors remain closed `config.semantic` and expose no tag、endpoint、PSK or raw source。
- [x] Validated config owns concrete role-specific collections/resolved references；callers do not
      parse strings or perform fallible reference lookup after `load_*` succeeds。
- [x] `--check-config` covers legacy/tagged positives and graph negatives with zero runtime
      resource；no new dependency、protocol kind field or `Endpoint` interface is added。
- [x] Until T02/T03 consume the full graph，each binary rejects a multi-inbound run with the
      existing `startup.protocol` error before observability、runtime or listener side effects；
      one-entry legacy/tagged execution remains unchanged。
- [x] `TEST-0008` T01 commands、repository Quick、ticket budget and blocking Architect/QA review
      pass on one exact candidate。

## Validation

Run `TEST-0008` T01 commands, then repository Quick commands from
`docs/agents/milestone-workflow.md`。

## Result

- Commit: candidate `0b7253e6a02bd463e5f4a37609e145ea7b406067`；integrated
  `f6ee43fa766dd326d33ba140a273b7df201749c1`。
- Review: Architect initial PASS；QA full `QA-M7-T01-001` major；bounded test-only repair；
  QA targeted PASS；Architect targeted `ARCH-M7-T01-001` major。Two independent read-only
  `gpt-5.6-sol/xhigh` analyses converged on the final helper-only repair；final Architect/QA
  targeted reviews PASS with both findings resolved and no new blocker/major。
- Notes: exact candidate/integration config `6/6`、CLI `5/5`、focused Clippy/fmt and repository
  Quick PASS；integration budget `PASS_HOLD` at code/tests `15303/23232`、ticket debt `108/120`、
  permanent ceiling PASS。The first clean-worktree CLI attempt lacked the existing binary artifact
  prerequisite and failed；after the recorded workspace binary build，all exact reruns passed。

## Rollback / risk

One config/guard revert restores legacy-only parsing。T02/T03 remove only their corresponding
fail-closed guard when they consume the full graph。Do not include tag/endpoint values in
diagnostics to improve operator specificity。
