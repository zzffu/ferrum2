---
id: M9-T02
milestone: M9
status: done
depends_on: [M9-T01]
owns:
  - scripts/test-budget.sh
  - docs/agents/milestone-workflow.md
  - docs/ci-status.md
  - docs/milestones/M9-multi-upstream-closure.md
  - docs/tickets/M9-T02-repair-test-footprint-wide-push.md
---

# M9-T02 — Repair test-footprint validation for a wide push

## Outcome

Keep the active schema 3 revision fail-closed while allowing one push to span superseded schema 2
and schema 3 revision 1 history. The full range retains per-commit isolation and transition
checks by using the exact predecessor grammars and measurement modes already present in repository
history; normal candidate loading remains revision 2 only.

## Acceptance

- [x] The failed hosted range `b3b99a1..5392ad6` no longer stops on legacy
      `baseline_unknown_key` or `baseline_series_mismatch` errors.
- [x] Every commit in the original range retains its control-isolation and policy-transition
      checks across schema 2, schema 3 revision 1, and revision 2.
- [x] A normal push whose base is newer than the current policy revision keeps the same behavior.
- [x] No product code, test evidence, dependency, threshold, or baseline count changes.

## Validation

```powershell
& 'C:\Program Files\Git\bin\bash.exe' -n scripts/test-budget.sh
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh self-test
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ci --base b3b99a15aa99f8393f99f4c72c85f451a48c6749 --candidate 7f6218426bedd23c324bbfe3091bc2be8b0dbdec
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ci --base 5392ad674036b0c7e85dcb8aa0ed5a52746f6ac0 --candidate 7f6218426bedd23c324bbfe3091bc2be8b0dbdec
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base 5392ad674036b0c7e85dcb8aa0ed5a52746f6ac0 --candidate 7f6218426bedd23c324bbfe3091bc2be8b0dbdec
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh milestone --candidate 7f6218426bedd23c324bbfe3091bc2be8b0dbdec
git diff --check
```

## Result

- Root cause: run `30888202051/1` used push base `b3b99a1`, so revision 2 tried to replay
  superseded schema 2 and revision 1 baselines with its current-only parser.
- Implementation commit: `7f6218426bedd23c324bbfe3091bc2be8b0dbdec` (isolated
  control-only change).
- The original wide CI range, a current short range, self-test, syntax, milestone footprint, and
  diff checks pass locally; the current measurement transition remains visible in the wide-range
  output.
- Remote requalification: not run without explicit push/rerun approval.
