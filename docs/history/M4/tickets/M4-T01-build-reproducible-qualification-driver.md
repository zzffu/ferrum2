---
id: M4-T01
milestone: M4
status: done
depends_on: []
owns:
  - .github/workflows/m0.yml
  - Cargo.toml
  - Cargo.lock
  - tools/ferrum2-m4-qualification/**
  - tests/m0-harness/Cargo.toml
  - tests/m0-harness/src/bin/m4_qualification.rs
  - tests/m0-harness/src/m4_support/**
  - tests/m0-harness/tests/workspace_policy.rs
---

# M4-T01 — Build the reproducible qualification driver

## Outcome

Add one Cargo-managed, non-default driver in the dedicated non-shipping
`tools/ferrum2-m4-qualification` package. It reuses the shipped release binaries to run
the fixed throughput and 10k-idle profiles, then wires them into one `performance` job
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
cargo check -p ferrum2-m4-qualification --all-targets --locked
cargo run --release -p ferrum2-m4-qualification --bin m4-qualification --locked -- self-check
cargo test -p ferrum2-m0-harness --locked
sh scripts/test-budget.sh ticket --base 701925681df78ad83076ed67863bf4fecf46f77c --candidate <candidate-sha>
git diff --check 701925681df78ad83076ed67863bf4fecf46f77c..<candidate-sha>
```

## Result

- Commit: `7730ec730258971652270cc6ef41be9457abc2a7` (implementation `fc3efba`,
  protected control commit `94671d4`, boundary repairs `8205944` and `7730ec7`).
- Review: Architect `PASS`; QA `PASS`; zero blocker/major/minor findings on the exact
  final candidate.
- Notes: The recovered driver now lives in the dedicated non-shipping tools package;
  the old harness draft is absent. Format, focused check, strict Clippy, Rust 1.85
  check, release self-check (`mutations=9`), workspace quick gate, harness tests
  (`57 passed`, `2 ignored`), diff-check, and control-commit structure passed. The
  exact ticket budget returned `PASS_ADVANCE`: code `+1854`, tests `+48`, ticket debt
  `-1806`, ratio `1.509022`. Formal throughput/resource modes remain unrun; they belong
  to separately authorized T02 hosted execution.
