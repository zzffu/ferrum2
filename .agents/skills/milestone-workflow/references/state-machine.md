# Workflow state machine

## Durable and transient state

Product history stores only durable outcomes:

```text
DRAFT <-> BLOCKED
  |
  +----> READY ----> DONE
           |
           +-------> DEFERRED
```

`implementation`, `review`, `repair`, `integration`, and `release` are transient
execution phases stored in the Git-common-dir runtime ledger. Do not create a product
commit merely to enter or leave a transient phase.

`in_progress`, `review`, and `failed` tracked statuses are read-only compatibility
adapters for existing tickets. New transitions use `set-phase`/`clear-phase`; the
helper migrates a legacy active status back to durable `ready`.

`done` means integrated and validated, not merely committed on a ticket branch.

## Four dependency gates

Dependencies are cumulative through their named gate:

| Field | First gate enforced | Effect |
|---|---|---|
| `implementation_blocked_by` | Engineer startup | Prevents implementation |
| `review_blocked_by` | Candidate review | Implementation may proceed |
| `integration_blocked_by` | Integration/done | Implementation and review may proceed |
| `release_blocked_by` | Milestone close | Integration may proceed |

Legacy `blocked_by` is an alias for `implementation_blocked_by`. A dependency must be
`done` when its gate is evaluated. All dependency IDs must exist and must not
self-block. The cumulative implementation/review/integration completion graph must
be acyclic. Release-only edges are checked at closeout but do not create a false
implementation cycle.

## Scheduler actions

`workflow.py next --milestone <ID> --json` reports:

| Action | Meaning | Primary-thread behavior |
|---|---|---|
| `execute_frontier` | Independent implementation-ready tickets exist | Start them up to capacity |
| `resume_active` | Only active implementation/review/repair work can progress | Resume it |
| `resume_and_execute_frontier` | Active work and a disjoint frontier both exist | Run both; active work is not a global barrier |
| `ready_to_close` | Durable tickets and release dependencies are complete | Run exact-SHA final validation/closeout |
| `blocked` | No active or independent work can progress | Report canonical root blockers |
| `run_limit_reached` | Wave or no-progress limit stopped this invocation | Persist state and return the exact resume command |
| `no_tickets` | Milestone has no tickets | Return to planning |

With `strategy = "drain"`, the primary thread repeatedly consumes these actions
without another user invocation. `next` is a deterministic decision helper, not an
agent spawner. `checkpoint` persists the loop fingerprint, no-progress count,
authorizations, blockers, and repair usage across worktrees and contexts.

## Pipelined execution

```text
IMPLEMENTATION-READY FRONTIER
    |
    +-- Engineer A -> verify SHA -> required ticket reviews --+
    |                                                        |
    +-- Engineer B still working                             +--> integration batch
    |                                                        |      |
    +-- active repair C -> affected review only -------------+      v
                                                               affected quick gates
                                                                    |
                                                               one full exact-SHA gate
                                                                    |
                                                               required integration reviews
                                                                    |
                                                               one material checkpoint
                                                                    |
                                                               recompute immediately
```

There is no wait-for-all barrier and no mandatory coordination commit for an
implementation or review phase. File ownership and worktree isolation remain
mandatory.

## Gate invariants

### Planning

A ticket may become ready only when:

- product outcome, scope, non-goals, risk, and measurable acceptance are documented
- spec and test plan exist
- four dependency lists are valid
- ownership paths are explicit
- `required_reviews` matches risk and change surface
- architectural decisions have an ADR; routine CRLF/format/filter/evidence repairs do
  not

### Implementation

An Engineer may start only when:

- implementation dependencies are done
- ownership does not overlap another write-active ticket
- the assigned branch/worktree and base SHA are exact
- configured `agent_type`, model, and reasoning effort were verified when observable

### Review and repair

A candidate may pass only when:

- its exact SHA and scoped diff are known
- all required reviewer roles ran with the configured profile
- required tests passed
- review dependencies are done
- canonical root findings are resolved

Open roots are gate-aware: a review root does not prevent implementation, but it
blocks review and every later gate. Integration roots prevent `done`; any open
canonical root prevents `ready_to_close`.

Risk-aware repair rules:

- security/protocol/concurrency/public API/hard-to-reverse changes require Architect
  and QA
- mechanical repairs do not consume substantive repair budget
- derived failures do not create repair attempts
- only invalidated gates rerun
- a local unintegrated candidate may be amended with explicit provenance

### Integration

A ticket may become done only when:

- integration dependencies are done
- passing candidate commits are present with traceable provenance
- affected quick gates and the assembled full gate passed
- required cross-ticket/integration reviews passed on the exact SHA
- the base branch did not move unexpectedly

### Release

A milestone may close only when:

- all in-scope tickets are done or explicitly deferred
- release dependencies are done
- required platform and hosted evidence is from the exact candidate SHA
- roadmap, CI status, risks, and handoff are current
- no canonical root blocker remains open

Intermediate evidence may be impact-scoped; the final release gate is never weakened.

## Progress and stop behavior

Material progress is one of:

- product or test behavior changed
- a canonical root blocker was resolved
- new evidence was produced for a new candidate SHA
- an integration or release result completed

Status edits, coordination commits, repeated derived failures, and unchanged reruns
are not progress. `workflow.py checkpoint --progress none` always increments the
no-progress count; a changed scheduler fingerprint is diagnostic and cannot reset
the guard. Only `--progress material` resets it.

Before stopping:

1. continue all independent work
2. check the exact authorization ledger
3. classify the root blocker
4. retain dirty/failed worktrees
5. report blocker ID, class, gate, root cause, derived failures, owner, evidence, and
   unblock condition

Local repair authorization never implies push, publish, force, deletion, remote
mutation, contract expansion, or ownership expansion.
