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

The machine gate is `scripts/test-budget.sh`. It uses pinned `rustloc 0.19.1` counts and the
schema 2 milestone policy in `ci/test-budget-baseline.txt`:

```text
test_growth = max(0, candidate_tests - base_tests)
admitted(candidate) = test_growth <= max_test_growth
```

The policy binds one milestone to an exact ancestor SHA and recomputed base counts. `code`、ratio、
examples and per-ticket debt remain diagnostics；adding code cannot buy test capacity。A ticket
whose positive test growth exceeds `ticket_warning` returns PASS with an explicit warning that
requires Architect/QA explanation。Only envelope overflow returns `BLOCKED`。

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
`--no-verify`。

A policy is created in a single-parent control-only commit before its first product ticket。The
commit may contain only protected control paths and Markdown evidence；Rust or another
implementation/configuration file cannot share it。Within one milestone the exact base and warning
stay fixed and `max_test_growth` may only shrink。A successor milestone may replace the policy only
when no Rust change exists between its declared exact base and the policy commit。Malformed、stale、
wrong-count、mixed-control and merge-only policy changes fail closed。

The primary thread independently checks exact commits:

```sh
sh scripts/test-budget.sh ticket --base <ticket-base-sha> --candidate <candidate-sha>
sh scripts/test-budget.sh ticket --base <ticket-base-sha> --candidate <integration-sha>
sh scripts/test-budget.sh milestone --candidate <accepted-integration-sha>
```

At milestone planning，derive `max_test_growth` from the accepted evidence map plus one explicit
contingency；do not increase it during execution。Deleting independent evidence to create headroom
remains a blocking semantic review finding。The CI `quality` and `test-budget` jobs are independent，
so a policy failure cannot suppress Full/focused evidence；the final aggregate normally requires
both。
