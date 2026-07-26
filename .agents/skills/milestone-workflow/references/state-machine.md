# Workflow state machine

## Control-plane states

```text
UNINITIALIZED
    |
    v
BOOTSTRAPPED  -- vision, gap analysis, roadmap, CI baseline exist
    |
    v
PLANNED       -- ADR/spec/test plan/tickets are approved and validated
    |
    v
EXECUTING     -- scheduler drains one or more dependency waves
    |               |
    |               +-- Engineer worktrees in parallel within a wave
    |               +-- Architect/QA gates
    |               +-- integration checkpoint
    |               +-- recompute next wave without a new user invocation
    v
READY_TO_CLOSE -- all in-scope tickets are done/deferred and final validation passed
    |
    v
CLOSED        -- exit criteria proved, documents updated, handoff committed
```

A repository can have more than one milestone, but only one integration branch may
actively target a given base branch unless the user explicitly coordinates multiple
release trains.

## Execute scheduler actions

`workflow.py next --milestone <ID> --json` reports one of these actions:

| Action | Meaning | Primary-thread behavior |
|---|---|---|
| `execute_frontier` | Dependency-ready tickets are available | Spawn one Engineer per selected, disjoint ticket and run the wave |
| `resume_active` | A ticket is `in_progress`, `review`, or `failed` | Recover the earliest incomplete implementation/review/repair gate before selecting new work |
| `ready_to_close` | Every in-scope ticket is `done` or `deferred` | Run final full validation, then return ready-to-close or enter closeout |
| `blocked` | Work remains but no ticket can progress | Stop with exact contract, dependency, failure, or decision blockers |
| `no_tickets` | The milestone has no tickets | Return to planning or correct the milestone ID |

With `execution.strategy = "drain"`, the primary thread loops over these actions until
`ready_to_close` or a material stop condition. With `strategy = "wave"`, it returns
after one durable frontier checkpoint.

## Ticket states

| State | Meaning | Allowed next states |
|---|---|---|
| `draft` | Contract incomplete or not approved | `blocked`, `ready`, `deferred` |
| `blocked` | A named dependency, decision, or external condition prevents work | `draft`, `ready`, `deferred` |
| `ready` | Spec/test plan approved, blockers done, ownership declared | `in_progress` |
| `in_progress` | Assigned Engineer/worktree exists or repair is underway | `review`, `blocked`, `failed` |
| `review` | Commit exists and Architect/QA gates are running | `in_progress`, `blocked`, `done`, `failed` |
| `failed` | Execution failed and needs explicit recovery | `in_progress`, `blocked`, `deferred` |
| `done` | Integrated into the base branch and validated | terminal unless reopened explicitly |
| `deferred` | Removed from current milestone with rationale | `draft` in a later milestone |

`done` means integrated and validated, not merely committed on a ticket branch.

## Wave lifecycle

```text
READY FRONTIER
    |
    v
COORDINATION COMMIT       tickets -> in_progress
    |
    v
ENGINEER FAN-OUT          one ticket / branch / worktree per Engineer
    |
    v
WAIT + VERIFY             commits exist, scope is clean, worktrees are clean
    |
    v
ARCHITECT + QA GATES      parallel read/test review
    |          |
    |          +-- required findings -> bounded Engineer repair -> rerun gates
    v
INTEGRATION WORKTREE      sequential --no-ff merges
    |
    v
QUICK PER MERGE + FULL PER WAVE
    |
    v
FINAL ARCHITECT + QA GATE
    |
    v
BASE FF-ONLY + DONE CHECKPOINT
    |
    v
RECOMPUTE NEXT ACTION     drain continues automatically
```

The user is not the scheduler between waves. The primary Codex thread waits for
subagents, consumes their summaries, closes completed threads, and starts the next
eligible wave.

## Gate invariants

### Planning gate

A ticket may become `ready` only when:

- its milestone and product outcome are documented
- its spec and test plan exist
- every acceptance criterion is measurable
- blockers are valid ticket IDs and form no dependency cycle
- ownership paths are explicit
- cross-module or irreversible decisions have approved ADRs
- the ticket is small enough for one focused Engineer context

### Execution gate

A ticket may become `in_progress` only when:

- all blockers are `done`
- it belongs to the requested milestone
- its ownership does not overlap another selected ticket
- the base tree is clean
- its branch and worktree are created from the expected coordination commit

### Review gate

A ticket may pass review only when:

- the assigned branch has a real commit
- the worktree is clean
- changed tracked files stay within declared scope or an approved scope expansion
- Architect verdict is PASS
- QA verdict is PASS
- ticket tests and quick validation pass
- required review findings have been repaired and rechecked within the configured
  repair budget

### Integration gate

A wave may enter the base branch only when:

- all passing ticket branches are merged into the integration branch
- merge conflicts were resolved from contract evidence
- quick validation passed after each merge
- full validation passed for the assembled wave
- final Architect verdict is PASS
- final QA verdict is PASS
- the base branch has not moved since the integration branch was synchronized

A failed ticket does not automatically invalidate independent passing tickets. It may
be excluded from the wave when configuration allows continuation and no dependency,
ownership, or contract relationship connects it to the passing work.

### Drain-loop gate

The scheduler may begin another wave only when:

- the previous wave has a durable Git/document checkpoint
- the base worktree is clean
- completed subagent results were collected
- selected worktree states are known
- `workflow.py next` reports `execute_frontier`
- the no-progress and wave limits have not been reached

### Close gate

A milestone may close only when:

- exit criteria have direct evidence
- all in-scope tickets are done or explicitly deferred
- final full validation passed on the milestone head
- roadmap and CI status identify the integrated commit
- open risks and debt are documented
- a handoff exists

## Stop and failure behavior

- **Dirty base tree:** stop; name the dirty paths. Do not stash or reset.
- **Missing contract:** move ticket to draft/blocked; do not improvise a hidden design.
- **Engineer failure:** preserve worktree and branch; retry only within the repair
  budget, otherwise mark failed or blocked.
- **Review blocker:** do not integrate; return ticket to in-progress/blocked.
- **Merge conflict:** preserve conflict state when intent is unclear.
- **Validation failure:** keep integration branch; do not fast-forward base.
- **Base moved:** stop and rebuild/review integration against the new base.
- **No progress:** stop when the same scheduler state repeats up to the configured
  limit; report the exact loop state.
- **Interrupted session:** use `resume`; never recreate state blindly.
