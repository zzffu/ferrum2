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
3. Confirm blocking findings are zero and deferred work is explicitly out of scope.
4. Update the milestone, roadmap, active project context, and debt lists.
5. Write one short handoff that links durable contracts and evidence instead of
   repeating them.
6. Remove only workflow-owned worktrees after verifying their branches and commits are
   preserved. Do not delete unknown work.
7. Mark the milestone closed in a dedicated commit.

If any required gate is missing, skipped, stale, or tied to another commit, report the
milestone as not closed.
