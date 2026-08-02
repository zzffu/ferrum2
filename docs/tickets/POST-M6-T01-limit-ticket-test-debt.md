---
id: POST-M6-T01
milestone: post-M6
status: done
depends_on: []
owns:
  - scripts/test-budget.sh
  - docs/agents/milestone-workflow.md
  - docs/tickets/POST-M6-T01-limit-ticket-test-debt.md
---

# POST-M6-T01 — Limit per-ticket test debt

## Outcome

Bound one ticket's positive test growth to positive code growth plus `120` lines while
retaining the permanent project ratio ceiling and non-upward accepted baseline。Bind the
machine rule to exact base/candidate trees rather than mutable author identity。

## Acceptance

- [x] `ticket-staged`、`ticket-commit` and ordinary `ci` block `ticket_debt > 120` with
      `ticket_allowance_exceeded` and admit equality at `120` when the hard ceiling also holds。
- [x] Milestone、ratchet、baseline-adoption and baseline-closeout modes do not reapply
      per-ticket debt；the old cumulative `anchor_debt` and forced `-0.05` ratchet stay absent。
- [x] Every mode still blocks an exact ratio above `22853 / 15032`, including rounded-equal
      overflow；`PASS_HOLD` remains baseline-ineligible。
- [x] The repair is one single-parent control commit containing only the protected script and
      Markdown evidence；no Rust、classifier、dependency or baseline change is included。
- [x] Focused validation and repository formatting pass。

## Validation

```powershell
& 'C:\Program Files\Git\bin\bash.exe' -n scripts/test-budget.sh
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --staged
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base e2767d0a486650b8b735a85de1d1825a1481c69c --candidate <candidate-sha>
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh milestone --candidate <candidate-sha>
cargo fmt --all -- --check
git diff --check
```

## Result

- Commit: `e20133c65a8f56418ed874b3bbaba2641180bd66`
- Review: primary exact-mode and invariant review — PASS。
- Notes: debt `120` passed and debt `121` blocked in all three ordinary modes；the same
  debt `121` passed milestone mode；a one-line hard-ceiling overflow blocked；anchor equality
  remained `PASS_ADVANCE`；an ineligible ratchet left the baseline blob unchanged。Temporary
  numeric controls were validation-only and were not committed。
