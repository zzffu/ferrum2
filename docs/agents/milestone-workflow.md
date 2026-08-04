# Milestone workflow settings

- Base branch: `master`
- Worktree root: `.worktrees`
- Max parallel engineers: 3

## Paths

- Milestones: `docs/milestones`
- Tickets: `docs/tickets`
- ADRs: `docs/adr`
- Specs: `docs/specs`
- Test plans: `docs/test-plans`
- Handoffs: `docs/handoffs`
- History: `docs/history`

## Quick validation

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo build --workspace --bins --locked
cargo test --workspace --locked
```

## Full validation

Run serially.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo build --workspace --bins --locked
cargo test --workspace --all-features --locked
cargo test -p ferrum2-m0-harness --test lifecycle_cycles full_qualification_runs_twenty_cycles_per_category_and_at_least_100_per_binary --locked -- --ignored --exact --nocapture
cargo doc --workspace --all-features --no-deps --locked
```

## Test footprint

The tracked control remains `scripts/test-budget.sh`, but schema 3 treats Rust test LOC as a
maintenance signal rather than correctness evidence. It uses pinned `rustloc 0.19.1`, an exact
ancestor SHA, and recomputed `code`/`tests` totals from `ci/test-budget-baseline.txt`.

The gate has two different semantics:

- **Integrity gate:** invalid tool version, malformed or stale policy, wrong base counts, mixed
  control/product changes, and non-inherited merge resolutions return `BLOCKED` or `ERROR`.
- **Numeric signal:** size thresholds return `PASS`, `WARN`, or `REVIEW_REQUIRED`; all three exit
  zero so necessary implementation and evidence can continue.

Schema 3 reports the Rustloc `Tests` total as three mutually exclusive categories. Their sum must
always equal `tests`:

| Metric | `path-v2` classification |
|---|---|
| `test_fixture_loc` | Rust test lines below `tests/fixtures/`, `test-fixtures`/`test_fixtures`, `snapshots`, or `testdata`; evaluated first |
| `test_support_loc` | Rust test lines in `tests/<harness>/src/**`, `*/tests/{common,support,helpers,fakes}/**`, or matching support/helper/fake test modules |
| `test_case_loc` | all remaining Rustloc test lines, including inline `#[cfg(test)]` evidence and normal integration-test files |

`path-v2` composes the Cargo-workspace scan with a second Rustloc scan of
`tests/fixtures/`. Supplemental rows receive a `tests/fixtures/` prefix before
classification and duplicate paths fail closed, so standalone Rust fixture generators are
included without changing the Cargo workspace graph.

Static non-Rust fixtures are outside the Rustloc `Tests` total and therefore outside this
three-way sum. They still require provenance, license, size, and diff review.

The default review triggers are strict greater-than comparisons:

| Signal | `PASS` | `WARN` | `REVIEW_REQUIRED` |
|---|---:|---:|---:|
| repository `tests / code` | `<= 2.0` | `> 2.0` | `> 2.5` |
| one ticket/change-set positive test growth | `<= 240` | `> 240` | `> 600` |
| a new or expanded test file's semantic test LOC | `<= 800` | `> 800` | `> 1200` |

File thresholds apply only when that file grows relative to the comparison base. Existing large
files are reported but do not make every unrelated commit noisy; growing an already-large file
triggers review. Ratios and absolute largest-file metrics remain visible on every report.

Before adding test code, the Engineer records or can explain:

1. the unique contract, threat, regression, or failure mode proved;
2. why current evidence does not already prove it;
3. the cheapest sufficient layer: unit, integration, process, or E2E;
4. whether a matrix can be table-driven instead of copied;
5. whether setup duplicates an existing helper.

Introducing a third semantically equivalent helper implementation is an Architect/QA
`REVIEW_REQUIRED` finding. The LOC script cannot determine semantic equivalence reliably, so this
rule remains a human review responsibility.

Install once and enable the tracked hook:

```sh
cargo install --locked rustloc --version '=0.19.1'
sh scripts/test-budget.sh install-hook
sh scripts/test-budget.sh verify
```

For each ticket worktree:

```sh
sh scripts/test-budget.sh bind --base <exact-ticket-base-sha>
git add <explicit-paths>
git commit
```

The hook counts the staged Git tree. `WARN` and `REVIEW_REQUIRED` are recorded and do not reject the
commit. A non-zero result means the policy/control result itself is unreliable or invalid and is
`BLOCKED`; do not use `--no-verify` to bypass that integrity check. For an isolated staged control
upgrade, the script evaluates against `HEAD` instead of a stale ticket binding. After activation,
`bind --base <new-base>` may migrate a legacy branch binding only when that old binding is already
an ancestor of the new policy base.

The primary thread independently checks exact commits:

```sh
sh scripts/test-budget.sh ticket --base <ticket-base-sha> --candidate <candidate-sha>
sh scripts/test-budget.sh ticket --base <ticket-base-sha> --candidate <integration-sha>
sh scripts/test-budget.sh milestone --candidate <accepted-integration-sha>
```

A policy is activated in a single-parent control-only commit before product work. The commit may
contain protected control paths and Markdown evidence only. The exact milestone base and base
counts stay fixed. Thresholds may be reforecast in the same milestone only through another isolated
control commit that increments `policy_revision` by exactly one and changes `reforecast_ref` to the
approved plan/test-plan/review decision. Increasing a threshold is therefore visible and reviewed,
not forbidden or hidden.

The initial M9 `path-v1` measurement omitted standalone Rust files below `tests/fixtures/`.
Policy revision 2 performs one isolated `v1/path-v1` to `v2/path-v2` measurement correction:
the exact base, code count, milestone, and thresholds stay fixed while the reproducibly recomputed
test total includes those fixture generators. Later revisions use the normal threshold reforecast
rules.

Malformed, stale, wrong-count, mixed-control, and merge-only policy changes fail closed. Numeric
`REVIEW_REQUIRED` items must be dispositioned before milestone close as one of: accepted with a
recorded rationale, reduced by a focused refactor, or covered by an approved policy reforecast.
Independent evidence must never be deleted merely to improve a number.

The CI `quality` and `test-footprint` jobs remain independent, so a control-policy failure cannot
suppress Full/focused evidence. The final aggregate requires both jobs to execute successfully;
numeric footprint findings remain visible in the job log without turning size estimates into
correctness failures.
