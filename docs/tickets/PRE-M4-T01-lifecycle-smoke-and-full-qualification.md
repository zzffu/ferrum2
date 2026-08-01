---
id: PRE-M4-T01
milestone: pre-M4
status: blocked
depends_on: []
owns:
  - tests/m0-harness/src/local_support/mod.rs
  - tests/m0-harness/tests/lifecycle_cycles.rs
  - docs/agents/milestone-workflow.md
  - docs/test-plans/TEST-0001-m0-aes128-tcp-vertical-slice.md
  - docs/test-plans/TEST-0004-m3-operational-lifecycle-platform-contract.md
  - .github/workflows/m0.yml
---

# PRE-M4-T01 — Split lifecycle smoke from full qualification

## Outcome

Keep the existing real-process lifecycle matrix and M3 evidence strength while making
default workspace tests run one smoke iteration per category. The authoritative full
gate and CI explicitly run the ignored 20-iteration qualification by exact test name,
and Windows signal children use a non-popup process group targeted by Ctrl-Break.

ADR-0016 already protects the per-category counts and cleanup/rebind outcomes while
allowing test-file/process organization to change, so this ticket does not supersede
or edit an Accepted ADR.

## Acceptance

- [x] Windows signallable children use `CREATE_NEW_PROCESS_GROUP`, never
  `CREATE_NEW_CONSOLE`, and Ctrl-Break targets only the child PID's process group.
- [x] One shared lifecycle matrix runs one iteration per category by default and an
  ignored exact-name full qualification runs 20 per category.
- [x] Full qualification guarantees at least 100 real client and 100 real server
  starts while preserving signal, exit, reap, cleanup, and immediate-rebind assertions.
- [ ] Authoritative full validation and CI explicitly execute the full test on the same
  SHA; quick/default workspace tests execute only smoke.
- [x] No dependency, production code, new harness, or hidden environment-variable
  control is added.
- [x] Focused and repository validation pass.

## Validation

```sh
cargo fmt --all -- --check
cargo test -p ferrum2-m0-harness --test lifecycle_cycles --locked
cargo test -p ferrum2-m0-harness --test lifecycle_cycles full_qualification_runs_twenty_cycles_per_category_and_at_least_100_per_binary --locked -- --ignored --exact --nocapture
cargo test -p ferrum2-m0-harness --test udp_local_e2e portable_ipv4_live_udp_signal_exits_cleanly_and_rebinds --locked -- --exact
cargo test --workspace --locked
```

## Result

- Commit: `68f94c3` (test implementation, test plans, and authoritative local gate)
- Review: `PRE-M4-T01-REVIEW-001` PASS with no findings
- Notes: The exact CI command is present as an uncommitted one-line change. The normal
  commit hook rejects `.github/workflows/m0.yml` with `control_plane_changed`; the
  current workflow defines no sanctioned control-maintenance commit path, so the hook
  was not bypassed.
