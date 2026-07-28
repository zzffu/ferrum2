# Test Economy

Quality is evidence strength, not test volume. A large test suite is justified only
when it covers distinct product risks at the cheapest reliable seam.

## Default evidence rule

For each MUST requirement, name one primary evidence item. Add another layer only
when it exercises a distinct failure mode that the primary evidence cannot observe.
Examples:

- parser behavior: table-driven unit test
- cross-crate contract: one integration test
- process lifecycle: one process-level test
- external implementation compatibility: hosted qualification or a pinned local
  interoperability test, not both unless each proves a different risk

Do not duplicate the same outcome across unit, integration, E2E, hosted CI, and soak
layers merely because every layer is available.

## Selective TDD

Use red-green-refactor when changing behavior, fixing a regression, or clarifying a
hard invariant. First search for an existing test seam. Prefer extending a table or
fixture over creating a new file or harness.

TDD is normally unnecessary for:

- formatting, comments, and documentation
- dependency metadata with deterministic validation
- mechanical refactoring already covered by behavior tests
- generated files
- a reviewer preference that is not a requirement or demonstrated defect

## Test infrastructure

A test harness is code and carries maintenance risk. Test the harness itself only
when it is shipped, reused as a supported tool, or has a demonstrated failure mode.
Do not create process wrappers, evidence parsers, environment probes, or policy tests
solely to satisfy an abstract completeness goal.

## Product, integration, release

- Product gate: ticket behavior and invariants.
- Integration gate: interactions among accepted tickets.
- Release gate: hosted runners, platform matrices, real external services, soak,
  packaging, and publication.

A release-environment failure does not reopen an accepted product ticket unless the
failure proves a concrete product defect.

## Test-budget gates

```bash
# Informational; always suitable during bootstrap/plan.
python .agents/skills/milestone-workflow/scripts/workflow.py \
  test-budget --gate report

# Candidate must not worsen the baseline and must respect delta allowance.
python .agents/skills/milestone-workflow/scripts/workflow.py \
  test-budget --gate ticket --base <base_branch>

# Material milestones must also improve the ratchet toward target_ratio.
python .agents/skills/milestone-workflow/scripts/workflow.py \
  test-budget --gate milestone --base <base_branch>
```

For an existing high-ratio repository, create a dependency-free built-in baseline once:

```bash
python .agents/skills/milestone-workflow/scripts/workflow.py \
  test-budget --gate report --tool builtin --write-baseline
```

Do not reduce the ratio by adding meaningless production code. Consolidate duplicate
tests, reuse fixtures, remove implementation-coupled checks, and move release-only
qualification out of product gates.


The built-in classifier and `rustloc` may report different totals because they use
different test-region rules. Keep one tool for a baseline. To migrate deliberately,
set `quality.test_budget.tool` and rewrite the baseline with the same explicit tool.
