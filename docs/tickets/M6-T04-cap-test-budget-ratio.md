---
id: M6-T04
milestone: M6
status: validating
depends_on: [M6-T03]
owns:
  - scripts/test-budget.sh
  - docs/agents/milestone-workflow.md
  - docs/milestones/M6-socks5-udp-associate.md
  - docs/tickets/M6-T04-cap-test-budget-ratio.md
---

# M6-T04 — Cap the test-budget ratio

## Outcome

Replace the obsolete allowance/material-growth ratchet with one exact permanent ceiling at
the current `22853 / 15032` tests/code ratio while retaining the accepted anchor as a
non-upward baseline ratchet。Do not reformat、reclassify、delete independent tests or add inert
product code to change the count。

## Acceptance

- [ ] Every ticket、milestone、ratchet and CI admission path rejects an exact ratio above
      `22853 / 15032`, including a rounded-equal counterexample。
- [ ] The current M6 Rust tree passes at ceiling equality as `PASS_HOLD`；a candidate equal to
      or better than the accepted anchor remains `PASS_ADVANCE` and baseline-eligible。
- [ ] A `PASS_HOLD` candidate cannot advance the baseline；baseline provenance、control-only
      commits、merge handling and exact-count verification remain unchanged。
- [ ] The change is one single-parent control commit containing only the protected script and
      Markdown evidence；Rust counts remain exactly `code=15032`、`tests=22853`、`examples=132`。
- [ ] Focused and repository validation pass。

## Validation

```powershell
& 'C:\Program Files\Git\bin\bash.exe' -n scripts/test-budget.sh
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base 0ab207c365574ebb17b8d7c755039e70ea9d1ab4 --candidate <candidate-sha>
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh milestone --candidate <candidate-sha>
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ci --base 0ab207c365574ebb17b8d7c755039e70ea9d1ab4 --candidate <candidate-sha>
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo build --workspace --bins --locked
cargo test --workspace --all-features --locked
cargo test -p ferrum2-m0-harness --test lifecycle_cycles full_qualification_runs_twenty_cycles_per_category_and_at_least_100_per_binary --locked -- --ignored --exact --nocapture
cargo +1.85.0 check --workspace --all-targets --locked
cargo doc --workspace --all-features --no-deps --locked
git diff --check
```

## Result

- Commit: —
- Review: three independent T04 design explorations completed；final exact-diff review —
- Notes: hosted UDP `12/12`、three native targets and final qualification remain separately
  authorized M6 close evidence and are not part of this control repair。
