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
- Ticket and cumulative allowance: `120` test lines after positive code growth.
- Milestone threshold: positive code growth plus positive test growth of `200` lines.
- Ratchet: `required = max(1.0, baseline_ratio - 0.05)`.

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
```

Both debts must be `<= 120`. For positive anchor growth
`growth(code_Q, code_A) + growth(tests_Q, tests_A) >= 200`, the exact integer ratio
comparison must satisfy the ratchet target. Smaller ratio regressions may return
`PASS_HOLD`, but the accepted baseline never moves upward.

Do not add inert product code or remove tests that cover an independent risk. Prefer
merging duplicate cases, table-driven coverage, shared fixtures, public-seam tests, and
removing implementation-coupled tests or redundant harnesses. Architecture and QA own
this semantic check; LOC cannot prove test value.

The former builtin baseline is historical and is not numerically converted. This series
starts at `4f2c98d8d485117a6c0ab058a410bfe8b7388c86` using the pinned rustloc classifier.
