# Integration and recovery

## Isolation and provenance

Engineers work in isolated ticket worktrees. The Team Lead alone integrates candidate
commits in the milestone integration worktree. Preserve:

- ticket branch, worktree, fork SHA, and candidate SHA
- exact changed paths against `owns`
- required reviewer role/profile and verdict
- commands, exit codes, and evidence scope

Do not add a merge or status commit solely to express a transient workflow phase.
Candidate provenance must remain traceable, but integration history need not contain
one coordination commit per transition.

## Pipelined drain

`drain` resumes active work and starts every independent implementation-ready ticket:

```text
active T07 implementation/repair -----------------------+
                                                        +--> integration gate
independent T08 implementation -> ticket review --------+

other disjoint work may start as soon as capacity is available
```

Each candidate enters review when it finishes; it does not wait for the rest of a
wave. Compatible passing candidates are assembled into an integration batch. Run
affected quick validation while assembling, then one configured full gate and
required exact-SHA integration reviews.

Create at most one consolidated Git evidence/status checkpoint per accepted
integration batch. Contract changes remain separate material commits.

## Four dependency checks

- Engineer startup checks `implementation_blocked_by`.
- Ticket review checks cumulative implementation + review dependencies.
- Integration/done checks cumulative implementation + review + integration
  dependencies.
- Closeout checks all four phases, including release dependencies.

An integration or release dependency does not prevent disjoint implementation.

## Review and repair

Bind every gate to an exact candidate SHA and configured role profile. If launch
metadata is not observable, record it as unverified.

When a required finding appears:

1. record one canonical root blocker and link derivative failures
2. check exact authorization scope independently from repair budget
3. classify the repair as `mechanical`, `evidence`, or `substantive`
4. send only the root finding to the assigned Engineer
5. rerun affected tests and invalidated reviewer gates

Mechanical line-ending, formatting, test-filter spelling, and equivalent
representation repairs do not consume substantive budget. Environment retries and
derived failures are evidence, not product repair attempts. Security/protocol/public
API/concurrency/root architecture repairs consume the risk-aware budget.

Repair budgets are per canonical root cause. When a root is exhausted, first consume
one exact `repair_budget_override` authorization with `--root-blocker`; that creates
one persisted allowance. It cannot unblock another root on the same ticket.

An unintegrated local candidate may be amended when the prior SHA and finding remain
recorded. Never rewrite pushed/published history.

## Runtime ledger

The helper stores recoverable state below `git rev-parse --git-common-dir`, shared by
all worktrees but outside product history. It contains:

- revision-protected scheduler checkpoint and no-progress fingerprint
- structured root blockers and derivative evidence
- risk-aware repair events
- explicit authorization scopes

Ledger writes use a persistent lock file with a process-owned OS lock. Process exit,
kill, or host interruption releases the lock automatically; stale owner metadata is
not itself a lock. Revision checks and atomic replace prevent concurrent writers from
silently overwriting each other.

Useful commands:

```bash
python .agents/skills/milestone-workflow/scripts/workflow.py state --milestone M0
python .agents/skills/milestone-workflow/scripts/workflow.py next \
  --milestone M0 --json
python .agents/skills/milestone-workflow/scripts/workflow.py set-phase \
  M0-T07 implementation --branch <branch> --worktree <absolute-path>
python .agents/skills/milestone-workflow/scripts/workflow.py checkpoint \
  --milestone M0 --progress material
```

Only record authorization after explicit user language. Store a concise evidence
summary, never credentials or full secret-bearing messages. A local authorization
must specify actions, tickets, blocker classes, maximum risk, and
`remote_effects=false`. Remote authorization must be independently explicit and
bind its exact remote ref, full commit SHA, and use count. Atomically run
`consume-authorization` immediately before the authorized remote mutation.

## Interruption recovery

After interruption:

1. run `doctor`, `validate`, `status`, `worktree-list`, `state`, and `next`
2. compare ledger revision with tickets, branches, worktrees, candidate SHAs, and the
   integration branch
3. identify write-active ownership leases
4. adopt the exact existing ticket/repair worktree, branch, and HEAD into the runtime
   phase; do not call default `worktree-create` when a non-default repair worktree
   already carries the ticket
5. resume active work and independent frontier together
6. preserve ambiguous or dirty worktrees; never recreate or reset them

Durable ticket status replacement preserves existing line endings and uses an atomic
same-directory replace. If interruption occurs after the ticket changes but before
the ledger phase is cleared, rerun the same `set-status`; the idempotent retry clears
the stale phase.

A context reset does not invalidate a precise authorization that the new user prompt
explicitly re-grants or instructs the agent to recover from the ledger. Never infer
remote/destructive authority from a local repair record.

## Base movement and conflicts

Resolve conflicts from, in order:

1. current user request and milestone outcome
2. accepted ADR
3. approved spec
4. test plan and ticket acceptance
5. existing public behavior

If the base moves, retain the validated integration commit, inspect intervening
changes, rebuild only affected candidate/integration evidence, and still run the
required final exact-SHA release gate. Never force-update the base.

## Cleanup

- keep failed/blocked/dirty worktrees
- optionally remove clean integrated worktrees after closeout
- preserve branches unless deletion is explicitly authorized
- never use forced worktree removal to hide partial work
