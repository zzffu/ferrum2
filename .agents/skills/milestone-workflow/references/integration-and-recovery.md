# Integration and recovery

## Why integration uses a separate worktree

Parallel ticket branches are never merged directly into the base one by one. The
Team Lead creates a milestone integration branch/worktree, combines passing branches
there, and runs deterministic validation. Only a proven integration commit may
fast-forward the base branch.

This gives four useful properties:

1. A failing cross-ticket interaction does not leave the base branch broken.
2. The base worktree remains available and clean.
3. Integration conflicts are isolated and inspectable.
4. A context reset can recover from Git state and documents.

## Multi-wave drain sequence

`execute` defaults to draining all available dependency waves in one primary-thread
invocation:

```text
base B0
  |\
  | ticket/A -- Engineer commit
  | ticket/B -- Engineer commit
  |
  +-- integration/M1
        merge A --no-ff
        quick validation
        merge B --no-ff
        quick validation
        full validation
        Architect + QA final gates

base --ff-only--> integration/M1
base: mark A/B done and checkpoint docs

scheduler recomputes frontier
  |
  +-- dependent ticket/C now becomes ready
  +-- independent ticket/D may also become ready

integration/M1 --ff-only--> latest base coordination commit
  |\
  | ticket/C -- Engineer commit
  | ticket/D -- Engineer commit
  |
  +-- merge C/D, validate, gate, base ff-only

repeat until ready_to_close or blocked
```

The primary thread, not the user, performs the transition from one wave to the next.
`strategy = "wave"` is an explicit debugging/manual-control option.

## Synchronizing a reused integration branch

A previous wave can leave the base ahead of the integration branch because ticket
status and roadmap evidence are committed after the code fast-forward. Before merging
a new wave:

1. require both base and integration worktrees to be clean
2. verify no unexpected commits exist on the integration branch
3. fast-forward the integration branch to the current base coordination commit
4. only then merge the new ticket branches

Never reset the integration branch to achieve synchronization.

## Verification before integrating a ticket branch

- branch/worktree matches the assigned ticket
- branch fork point is the expected coordination commit
- no unexpected merge/rebase occurred
- worktree is clean
- commit(s) exist and mention the ticket
- diff paths conform to `owns`
- no secret, build artifact, debug output, or unrelated cleanup is included
- Architect and QA ticket verdicts are PASS

## Review repair loop

When Architect or QA returns required findings:

1. send the concrete findings back to an Engineer assigned to the same worktree
2. require a new explicit repair commit
3. rerun ticket tests and quick validation
4. rerun Architect and QA gates
5. stop after `execution.max_repair_attempts_per_ticket`

A repair must not silently modify the approved contract or expand ownership. A
contract defect returns to planning and blocks the ticket.

## Conflict policy

Resolve conflicts by tracing intent to, in order:

1. user request and milestone exit criteria
2. accepted ADR
3. approved spec
4. approved test plan and ticket acceptance criteria
5. existing public behavior and tests
6. current implementation details

A conflict that reveals contradictory contracts is a planning failure. Stop and revise
the contract explicitly rather than choosing the easiest code shape.

## Fast-forward policy

After full validation, update the base only with a fast-forward when the integration
branch still descends from the current base. If the base moved:

1. keep the validated integration branch
2. identify intervening commits
3. rebuild or merge them into the integration branch
4. rerun affected ticket reviews and full validation
5. then fast-forward

Never force-update the base.

## Recovery checklist

After interruption:

```bash
python3 .agents/skills/milestone-workflow/scripts/workflow.py status
python3 .agents/skills/milestone-workflow/scripts/workflow.py worktree-list
python3 .agents/skills/milestone-workflow/scripts/workflow.py next \
  --milestone <ID> --json
git status --short --branch
git branch --list 'codex/*'
git worktree list --porcelain
```

Then inspect:

- tickets in `in_progress`, `review`, or `failed`
- dirty worktrees
- branch HEAD commits
- integration branch merge state
- most recent handoff
- roadmap/CI status commit references

Resume the earliest incomplete gate and, when strategy is `drain`, continue subsequent
waves automatically. Do not remove or recreate a worktree until its changes and
branch are understood.

## Cleanup policy

Removing a clean worktree is not the same as deleting its branch. Default behavior:

- keep failed/blocked worktrees
- optionally remove clean, integrated ticket worktrees after closeout
- keep branches until the user explicitly requests branch cleanup
- never use `git worktree remove --force` unless the user explicitly authorizes loss
