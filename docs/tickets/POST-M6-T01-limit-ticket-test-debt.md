---
id: POST-M6-T01
milestone: post-M6
status: validating
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

- [ ] `ticket-staged`、`ticket-commit` and ordinary `ci` block `ticket_debt > 120` with
      `ticket_allowance_exceeded` and admit equality at `120` when the hard ceiling also holds。
- [ ] Milestone、ratchet、baseline-adoption and baseline-closeout modes do not reapply
      per-ticket debt；the old cumulative `anchor_debt` and forced `-0.05` ratchet stay absent。
- [ ] Every mode still blocks an exact ratio above `22853 / 15032`, including rounded-equal
      overflow；`PASS_HOLD` remains baseline-ineligible。
- [ ] The repair is one single-parent control commit containing only the protected script and
      Markdown evidence；no Rust、classifier、dependency or baseline change is included。
- [ ] Focused validation and repository formatting pass。

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

- Commit: —
- Review: primary exact-mode and invariant review —
- Notes: temporary numeric controls are validation-only and are not committed。
