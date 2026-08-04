---
id: POST-M10-T01
milestone: post-M10
status: done
depends_on: []
owns:
  - .github/workflows/m0.yml
  - .agents/skills/milestone-workflow/references/plan.md
  - docs/agents/milestone-workflow.md
  - tests/m0-harness/tests/workspace_policy.rs
  - docs/tickets/POST-M10-T01-decouple-performance-qualification.md
---

# POST-M10-T01 — Decouple performance qualification

## Outcome

Keep correctness and security qualification automatic while making the 40-minute hosted
performance profile an explicit exact-SHA milestone decision.

## Acceptance

- [x] `performance` runs only for `workflow_dispatch` and retains its own fail-closed evidence.
- [x] `qualification` requires quality、test footprint、MSRV、all platforms and interop, but does
      not wait for or claim performance.
- [x] Milestone plans default performance to excluded with a rationale and name the bounded cases
      that require it; no correctness or security gate becomes optional.
- [x] Existing M4 THP apply/restore/cleanup checks remain covered, and one focused workflow-policy
      test prevents reconnecting automatic qualification to performance.
- [x] The protected workflow and planning controls are isolated from Rust changes.
- [x] Focused validation and repository formatting pass.

## Validation

```powershell
cargo test -p ferrum2-m0-harness --test workspace_policy performance_is_manual_and_decoupled_from_qualification --locked -- --exact
cargo test -p ferrum2-m0-harness --test workspace_policy m4_thp_profile_is_applied_and_restored_around_resource_qualification --locked -- --exact
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base 046c211b3967695054f372246413b18aa2fcc72d --candidate <candidate-sha>
cargo fmt --all -- --check
git diff --check
```

## Result

- Commits: control `62949c3a94d86ffddd3e28656dd48e9b2b549a00`; regression evidence in
  this closeout commit.
- Review: primary exact-diff review — PASS.
- Notes: YAML parse、both focused workflow-policy tests、Rustfmt and diff check passed. The
  footprint integrity gate passed；numeric `REVIEW_REQUIRED` is accepted because the existing
  `workspace_policy.rs` control seam grew by only 23 case lines and no helper/harness was added.
  No push、dispatch or other remote action occurred.
