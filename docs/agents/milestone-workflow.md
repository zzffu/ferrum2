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

## Test budget

The machine gate is `scripts/test-budget.sh`. Prompts are reminders only. `examples`
are reported for review but are not part of this first `tests / code` series.

- Tool: `rustloc 0.19.1`, Rust backend, CSV total row.
- Metric: `tests / code`.
- Accepted anchor: `ci/test-budget-baseline.txt`, bound to one exact commit.
- Permanent exact ceiling: `22853 / 15032`, measured at M6 integration commit
  `0ab207c365574ebb17b8d7c755039e70ea9d1ab4`.
- Ticket surplus allowance: `ticket_debt <= 120` for staged/committed ticket checks and
  ordinary CI event ranges；the exact ticket base, not Git author identity, owns the delta.
- Anchor ratchet: a candidate worse than the accepted anchor returns `PASS_HOLD`；an
  equal or better candidate returns `PASS_ADVANCE` and may advance the anchor.
- Anchor debt and material growth are diagnostics；no allowance overrides the exact ceiling.

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

The hook counts the staged Git tree. A non-zero result is `BLOCKED`; do not use
`--no-verify`. `PASS_HOLD` permits a bounded test-only fix, code deletion, or small
refactor but does not permit a baseline advance.

A control-plane repair must be a single-parent commit containing only the protected
control paths named by `scripts/test-budget.sh` and Markdown evidence. Rust or another
implementation/configuration file cannot share that commit. CI validates every control
commit in the complete event range and rejects merge-only control resolutions. During
initial adoption the baseline commit may appear inside a multi-commit range: its exact
source and non-Rust migration prefix are verified first, then the final candidate runs
the applicable ticket-debt、ceiling and anchor comparisons. None of these rules is a
budget waiver.

The primary thread independently checks exact commits:

```sh
sh scripts/test-budget.sh ticket --base <ticket-base-sha> --candidate <candidate-sha>
sh scripts/test-budget.sh ticket --base <ticket-base-sha> --candidate <integration-sha>
sh scripts/test-budget.sh milestone --candidate <accepted-integration-sha>
```

After milestone acceptance, only `PASS_ADVANCE` may update the anchor:

```sh
sh scripts/test-budget.sh ratchet --candidate HEAD --write
git add ci/test-budget-baseline.txt
git commit -m "chore: ratchet test budget baseline"
```

The closeout commit changes only the baseline file, whose `commit` field points to its
parent. CI recomputes the old anchor, candidate, and new anchor from Git objects.

Definitions for anchor `A`, ticket base `B`, and candidate `Q`:

```text
growth(x, y) = max(0, x - y)
ticket_debt = growth(tests_Q, tests_B) - growth(code_Q, code_B)
anchor_debt = growth(tests_Q, tests_A) - growth(code_Q, code_A)
admitted(Q) = tests_Q * 15032 <= 22853 * code_Q
```

The gate requires positive `code_Q` and evaluates `admitted(Q)` with exact integer
cross-products；rounded display values never decide acceptance。`ticket-staged`、
`ticket-commit` and ordinary `ci` additionally require `ticket_debt <= 120`。Milestone、
ratchet、baseline-adoption and baseline-closeout modes do not reapply that per-ticket
allowance；`anchor_debt` and material growth remain review diagnostics。An admitted candidate
worse than anchor `A` returns `PASS_HOLD` with `baseline_eligible=no`；an equal or better
candidate returns `PASS_ADVANCE` with `baseline_eligible=yes`. Therefore the accepted
baseline never moves upward, and no mode can admit a ratio above the permanent ceiling.

Do not add inert product code or remove tests that cover an independent risk. Prefer
merging duplicate cases, table-driven coverage, shared fixtures, public-seam tests, and
removing implementation-coupled tests or redundant harnesses. Architecture and QA own
this semantic check; LOC cannot prove test value.

The former builtin baseline is historical and is not numerically converted. This series
starts at `4f2c98d8d485117a6c0ab058a410bfe8b7388c86` using the pinned rustloc classifier.
