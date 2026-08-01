---
id: M4-T01
milestone: M4
status: blocked
depends_on: []
owns:
  - .github/workflows/m0.yml
  - tests/m0-harness/Cargo.toml
  - tests/m0-harness/src/bin/m4_qualification.rs
  - tests/m0-harness/src/m4_support/**
---

# M4-T01 — Build the reproducible qualification driver

## Outcome

Add one Cargo-managed, non-default driver that reuses the shipped release binaries to
run the fixed throughput and 10k-idle profiles, then wire it into one `performance` job
in the existing hosted workflow. It emits bounded generated JSONL evidence and fails
closed on identity, sample, resource, or cleanup defects.

## Acceptance

- [ ] `throughput`, `resource`, and short `self-check` modes implement the exact
      SPEC-0005 profiles without a new dependency, product API, metric, or workflow.
- [ ] The driver verifies SHA/hosted-profile/reference identity, owns and reaps every
      child and worker, bounds logs/deadlines/setup concurrency, and writes only below
      the requested ignored output path.
- [ ] Throughput produces all ten trials and exact medians/ratio/difference; resource
      produces 10,000 established flows, 180 samples, six RSS verdicts, and exact drain.
- [ ] Negative self-checks reject wrong identity, incomplete/changing samples, RSS
      regression, incomplete drain, leaked owners, and secret-bearing output.
- [ ] `.github/workflows/m0.yml` adds one `performance` job on `ubuntu-24.04`, runs it
      only outside pull requests, uses one 90-minute bound, runs throughput before
      resource, emits one bounded same-SHA/run summary, and deletes `$RUNNER_TEMP/m4`.
- [ ] The protected workflow edit is a separate single-parent control commit containing
      no Rust or other implementation/configuration change.
- [ ] Focused and repository validation pass.

## Validation

```sh
cargo fmt --all -- --check
cargo check -p ferrum2-m0-harness --all-targets --locked
cargo run --release -p ferrum2-m0-harness --bin m4-qualification --locked -- self-check
cargo test -p ferrum2-m0-harness --locked
sh scripts/test-budget.sh ticket --base 701925681df78ad83076ed67863bf4fecf46f77c --candidate <candidate-sha>
git diff --check 701925681df78ad83076ed67863bf4fecf46f77c..<candidate-sha>
```

## Result

- Commit: —
- Review: Architect `ESCALATE` (`M4-BUDGET-001`); no candidate correctness review.
- Notes: The isolated worktree contains only the manifest entry and driver/support
  paths, unstaged and uncommitted. `fmt`, harness `check`, release `self-check`
  (`mutations=9`), workspace binary build, UDP example build, harness tests (57 passed,
  2 ignored), and diff-check passed. Hosted modes were not run. An alternate temporary
  index left the real index untouched and produced
  `BLOCKED reason=ticket_allowance_exceeded`: exact-base code growth is zero and the
  new driver contributes 1,802 test-classified lines against the 120-line allowance.
  Resume requires an explicitly authorized plan/control-policy amendment; no
  performance threshold, hook bypass, baseline advance, or remote action occurred.
