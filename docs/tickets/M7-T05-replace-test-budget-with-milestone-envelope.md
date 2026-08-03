---
id: M7-T05
milestone: M7
status: done
depends_on: [M7-T04]
owns:
  - scripts/test-budget.sh
  - ci/test-budget-baseline.txt
  - .github/workflows/m0.yml
  - docs/agents/milestone-workflow.md
  - docs/research/M7-test-budget-gate-analysis.md
  - docs/test-plans/TEST-0008-m7-tagged-static-composition.md
  - docs/milestones/M7-tagged-static-composition.md
  - docs/roadmap.md
  - docs/ci-status.md
  - docs/tickets/M7-T05-replace-test-budget-with-milestone-envelope.md
  - docs/tickets/M7-T06-remove-m6-m7-rustfmt-skips.md
---

# M7-T05 — Replace test-budget ratio with a milestone envelope

## Outcome

Replace the M6 permanent ratio、anchor ratchet and ticket hard allowance with one schema 2 exact-base
absolute test-growth envelope，and isolate Budget from quality evidence without adding a dependency or
second policy file。

## Acceptance

- [x] The policy binds M7 to exact base `953689ad2c9984a317f617e26444db7aa173513a` at
      code/tests `15529/24619` and admits exactly `864` planned test lines for T06。
- [x] Equality passes、`+1` blocks、code padding cannot change admission，and ticket growth over
      `120` produces a nonblocking warning。
- [x] Wrong base counts、stale base、malformed schema、mixed control commits and same-milestone
      envelope increases fail closed；a new milestone policy requires a Rust-clean prefix from base。
- [x] Quality always reaches Full/focused markers independently；the separate Budget job emits its
      own marker and remains required by final qualification。
- [x] The obsolete ratio、ratchet and `PASS_HOLD/PASS_ADVANCE` machinery is removed；focused and
      repository validation pass。

## Validation

```powershell
& 'C:\Program Files\Git\bin\bash.exe' -n scripts/test-budget.sh
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh self-test
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base 869d54883a72d1c226e2211ff144bca175f90b47 --candidate <candidate-sha>
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh milestone --candidate <candidate-sha>
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ci --base 869d54883a72d1c226e2211ff144bca175f90b47 --candidate <candidate-sha>
cargo fmt --all -- --check
git diff --check
```

Temporary commit/tree controls cover malformed、stale、wrong-count、mixed-control and envelope
increase negatives；they are not retained。

## Result

- Commit: initial control `839fb92380c44be1f8ff0f0d3bb99eae4a07249c`；bounded rename
  repair/final exact `9baba260dde2adefb33a927787ba556299b81bcd`。
- Review: initial QA `PASS_WITH_NOTES`；Architect blocked `ARCH-M7T05-001` because rename folding
  could hide a removed Rust path。Targeted Architect and QA both returned PASS after the repair。
- Notes: exact verify、ticket、milestone、CI、self-test、YAML isolation、format and diff gates PASS。
  Six policy negatives passed；the rename RED incorrectly admitted R100 `rs→md` at `24543` tests，
  while final staged/ticket/CI probes blocked `3/3` with `control_plane_changed`。
