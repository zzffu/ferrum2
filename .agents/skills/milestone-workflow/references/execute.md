# Execute and resume

## Reconcile

1. Read Git status, branches, worktrees, commits, active milestone, and ticket states.
2. Treat Git and tracked contracts as authoritative. Ignore stale local notes.
3. Verify the base is clean and unchanged before scheduling or integration.
4. Resume valid worktrees; do not create duplicates for an existing ticket.

## Schedule

Select dependency-ready tickets. Run independent tickets in separate worktrees only
when owned paths do not overlap and capacity remains. Give each Engineer:

- exact ticket and contract paths;
- base commit, branch, and absolute worktree;
- owned paths and forbidden paths;
- focused and repository validation commands;
- required return fields.

## Implement

The Engineer makes the smallest coherent change, extends existing evidence where
possible, runs the stated gates, inspects the diff, commits explicit files, and leaves
the worktree clean. It does not merge, rebase, push, or edit workflow control files.

## Review

Review the exact candidate commit against the ticket/spec and repository standards.
Use stable IDs and `blocker`, `major`, `minor`, or `note` severity.

- `PASS` and `PASS_WITH_NOTES` may integrate.
- `BLOCK` permits one bounded repair for blocking IDs.
- Targeted re-review checks those IDs, the repair delta, and invalidated tests only.
- A remaining blocker is `ESCALATE`; do not restart an unbounded loop.

## Integrate

1. Reconfirm clean, unmoved integration/base branches.
2. Integrate passing candidates in dependency order into an integration worktree.
3. Resolve only genuine integration conflicts; do not silently redesign a ticket.
4. Run affected focused tests, then configured quick/full gates as required.
5. Fast-forward the base only when explicitly allowed and still unchanged.
6. Update ticket and milestone status with concise evidence and commit IDs.

With `strategy: drain`, repeat until ready to close or a stop condition occurs. With
`wave`, return after one frontier.
