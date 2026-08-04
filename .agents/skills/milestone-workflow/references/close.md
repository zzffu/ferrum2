# Status and close

## Status

Report facts, not a narrative log:

- baseline, branch, and clean/dirty state;
- milestone outcome and state;
- done, ready, active, blocked, and deferred tickets;
- worktrees and candidate/integration commits;
- latest review verdicts and validation results;
- first concrete next action.

Do not call a milestone complete because tickets are merely merged.

## Close

1. Verify every exit criterion against the exact integrated commit.
2. Run the configured full gate serially plus any milestone-specific qualification.
3. Run `sh scripts/test-budget.sh milestone --candidate <accepted-integration-sha>` and
   record total ratio plus test-case, test-support, and test-fixture deltas.
4. Confirm blocking findings are zero and deferred work is explicitly out of scope.
5. Disposition every numeric `REVIEW_REQUIRED` item as accepted with rationale, reduced by a
   focused refactor, or covered by an approved policy reforecast. Do not delete independent
   evidence merely to improve a metric.
6. Update the milestone, roadmap, active project context, and debt lists.
7. Write one short handoff that links durable contracts and evidence instead of
   repeating them.
8. Remove only workflow-owned worktrees after verifying their branches and commits are
   preserved. Do not delete unknown work.
9. Mark the milestone closed in a dedicated commit.

If any required gate is missing, skipped, stale, tied to another commit, or a footprint review
item lacks a recorded decision, report the milestone as not closed. A numeric footprint status
is not itself a correctness failure.
