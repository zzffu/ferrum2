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

## Test footprint

Bind the exact ticket base before implementation:

```sh
sh scripts/test-budget.sh bind --base <ticket-base-sha>
```

A normal `git commit` evaluates the staged Git tree. `PASS`, `WARN`, and
`REVIEW_REQUIRED` are valid zero-exit results; report the numeric status and continue bounded
implementation. A non-zero result means the tool, exact baseline, or protected control plane could
not be trusted and is `BLOCKED`; never use `--no-verify`.

Before adding test code, identify the unique contract/threat/regression proved, why existing
evidence is insufficient, the cheapest sufficient test layer, and whether a table or existing
helper can express the case. A third semantically equivalent helper is a human
`REVIEW_REQUIRED` finding even when the LOC script cannot detect it.

The primary thread independently checks the exact candidate and integration commits and records:

- total `tests / code` status;
- positive change-set test growth;
- `test_case_loc`, `test_support_loc`, and `test_fixture_loc` deltas;
- any new or expanded file over the file thresholds;
- the disposition of every `REVIEW_REQUIRED` item.

Engineers do not edit the policy. The primary thread may reforecast thresholds only in an isolated
control-only commit with an incremented `policy_revision` and a new approved `reforecast_ref`; the
exact milestone base and base counts do not move.
