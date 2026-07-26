---
name: milestone-workflow
description: Orchestrate a repository milestone with Product Manager, Architect, Engineer, and QA subagents. Use explicitly for bootstrap, plan, execute, status, resume, or close modes; creates ADR/spec/test-plan/ticket contracts, drains dependency-ready tickets through isolated Git worktrees, reviews and integrates them, and records milestone evidence. Never pushes or publishes by default.
---

# Milestone Workflow

The primary thread is the **Team Lead** and sole scheduler/integrator. Subagents do
bounded specialist work and return evidence to the primary thread. Subagents must not
schedule other subagents. Engineers are the only subagents that normally edit product
code, and every Engineer works in a separate Git worktree.

## Invocation

Accept natural language or these explicit fields:

```text
mode: bootstrap | plan | execute | status | resume | close
milestone: M0               # required for plan/execute/close when not inferable
goal: ...                   # required for bootstrap/plan when not already documented
strategy: drain | wave      # execute only; default comes from workflow.toml
max_parallel: 3             # never exceed workflow.toml or Codex capacity
max_waves: 0                # execute only; 0 means no artificial cap
auto_close: false           # execute only; true performs closeout after completion
scope: ...                  # optional path/module restriction
```

Infer omitted non-critical values from `workflow.toml`, `docs/roadmap.md`, ticket
metadata, and the current branch. State assumptions. Do not turn an execution request
into an extended interview.

### Execute default

`strategy: drain` is the default. One user invocation of `mode: execute` owns the
entire scheduling loop:

```text
reconcile existing state
  -> select one dependency-ready wave
  -> spawn isolated Engineers
  -> wait for all Engineers
  -> run Architect and QA gates
  -> repair bounded failures when possible
  -> integrate passing branches
  -> validate and checkpoint
  -> recompute the next wave
  -> repeat without asking the user to invoke execute again
```

Do **not** return after the first frontier when strategy is `drain`. Return after one
frontier only when the user explicitly selects `strategy: wave`, the configured wave
cap is reached, or a stop condition below applies.

## Mandatory preflight

For every mode:

1. Read the applicable `AGENTS.md` chain and `workflow.toml`.
2. Run:

   ```bash
   python3 .agents/skills/milestone-workflow/scripts/workflow.py doctor
   python3 .agents/skills/milestone-workflow/scripts/workflow.py validate
   ```

3. Read `references/state-machine.md` and the mode-specific section below.
4. Treat approved ADRs, specs, test plans, and ticket frontmatter as contracts.
5. Never claim a gate passed without direct evidence.

For `execute`, `resume`, and `close`, also read
`references/integration-and-recovery.md`. For document creation or ticket changes,
read `references/document-contracts.md`. For optional third-party skills, read
`references/mattpocock-integration.md`.

## Global safety and ownership rules

- Never push, open or merge a remote PR, publish a release, mutate remote issues, or
  delete remote/local branches unless the user separately and explicitly requests it.
- Never force-push, use destructive reset/clean commands, discard unknown changes,
  or abort another agent's Git operation.
- The base worktree must remain clean during execution. Do not stash user changes.
- The Team Lead is the only actor allowed to integrate branches or mutate workflow
  coordination state.
- Do not run multiple write-heavy agents in one worktree.
- Parallel tickets must be dependency-ready and have disjoint `owns` paths. Unknown
  ownership is treated as overlapping.
- Keep failed or blocked worktrees intact for diagnosis. Do not conceal partial work.
- A spec or ADR conflict blocks implementation; it is not resolved by silently
  editing the contract after the code.
- Close completed subagent threads after collecting their results so later waves can
  reuse the configured thread capacity.

## Mode: `bootstrap`

Purpose: establish the repository control plane without implementing product code.

1. Run `workflow.py bootstrap` to create missing directories/templates safely.
2. Inspect the repository, current docs, build files, CI, tests, and recent history.
3. Spawn `product_manager` and `architect` in parallel as read-only investigations.
   Give both the same goal and ask them to cite concrete repository evidence. Wait for
   both reports.
4. Spawn `qa` after the initial reports to identify baseline test/CI gaps. QA must not
   edit tracked files.
5. Synthesize and write/update:
   - `docs/vision.md`
   - `docs/gap-analysis.md`
   - `docs/roadmap.md`
   - `docs/ci-status.md`
6. Record assumptions, non-goals, milestone exit criteria, and unresolved decisions.
7. Run validation again. Stop before product-code implementation.

Output: created/updated documents, proposed first milestone, unresolved decisions,
and the exact next `plan` invocation.

## Mode: `plan`

Purpose: turn one milestone goal into approved, executable contracts.

1. Resolve the milestone and objective from the request and roadmap.
2. Spawn `product_manager` for scope, vertical slices, blockers, and exit criteria.
3. Spawn `architect` for execution-path tracing, options, ADR requirements, interfaces,
   errors, compatibility, migration, and rollback.
4. After those reports, spawn `qa` for an acceptance-to-test matrix and CI strategy.
5. The Team Lead writes or updates the required ADR, spec, test plan, roadmap entry,
   and tickets. Do not let subagents write these concurrently.
6. Every ticket must:
   - be a verifiable vertical slice
   - reference an approved spec and test plan
   - declare all blockers
   - declare explicit ownership paths
   - have measurable acceptance criteria
   - fit one focused Engineer context
7. Mark a ticket `ready` only when all document gates pass. Otherwise mark it `draft`
   or `blocked` with the reason in the body.
8. Run `workflow.py validate`, `workflow.py frontier --milestone <ID>`, and
   `workflow.py next --milestone <ID> --json`.
9. Stop before implementation. Planning is an intentional human-visible gate; do not
   silently start coding from `plan` mode.

Output: decisions, documents, ticket dependency graph, ready frontier, and blocked
items.

## Mode: `status`

Purpose: report authoritative workflow state without changing code.

1. Run:

   ```bash
   python3 .agents/skills/milestone-workflow/scripts/workflow.py status
   python3 .agents/skills/milestone-workflow/scripts/workflow.py worktree-list
   python3 .agents/skills/milestone-workflow/scripts/workflow.py next \
     --milestone <ID> --json
   ```

2. Compare ticket metadata with branches, worktrees, commits, roadmap, and CI status.
3. Report inconsistencies instead of silently repairing them.
4. Do not mutate tracked files unless the user explicitly asks for reconciliation.

Output: milestone counts, next scheduler action, ready frontier, active/review work,
worktrees, blockers, and recommended next mode.

## Mode: `execute`

Purpose: drain all executable work for one milestone through subagents, integration,
and validation in a single primary-thread invocation.

### A. Resolve scheduler policy

1. Resolve `strategy`, `max_parallel`, `max_waves`, and `auto_close` from the request,
   then `workflow.toml` defaults.
2. `drain` means continue scheduling waves automatically. `wave` means run exactly
   one frontier and return after checkpointing it.
3. `max_waves = 0` means no artificial cap. A positive value caps waves in this run,
   not the milestone itself.
4. Use at most the smaller of the requested concurrency, `workflow.toml` limit, and
   current Codex thread capacity.
5. Initialize a no-progress counter. Every loop must produce durable progress such as
   a ticket state transition, a new commit, a completed gate, or an integration
   checkpoint. Stop when the same scheduler state repeats up to
   `execution.no_progress_limit`.

### B. Reconcile before scheduling

1. Require the configured base branch and a clean base worktree. If dirty, stop and
   identify exact paths; never stash or discard them.
2. Inspect tickets, branches, worktrees, commits, and any integration branch.
3. Run:

   ```bash
   python3 .agents/skills/milestone-workflow/scripts/workflow.py next \
     --milestone <ID> --limit <N> --json
   ```

4. If the action is `resume_active`, complete the earliest unfinished gate before
   selecting new tickets:
   - `in_progress`: resume or replace the assigned Engineer in the existing worktree
   - `review`: run or finish Architect/QA ticket gates
   - `failed`: inspect preserved evidence and retry only when the failure is
     recoverable and the repair budget permits it
   - active integration: finish merge, validation, or base fast-forward recovery
5. Never recreate an existing branch or worktree containing partial work.

### C. Execute one wave

When the scheduler action is `execute_frontier`:

#### C1. Coordination checkpoint

1. Select the dependency-ready, ownership-disjoint frontier reported by `workflow.py`.
2. Change selected tickets to `in_progress`; update roadmap only when necessary.
3. Commit this coordination-only change on the base branch.
4. Confirm the base worktree is clean again.

#### C2. Isolated Engineer implementation

For each selected ticket:

1. Create or reuse its branch/worktree from the coordination commit:

   ```bash
   python3 .agents/skills/milestone-workflow/scripts/workflow.py \
     worktree-create <TICKET_ID>
   ```

2. Spawn one `engineer` with the ticket ID/path, absolute worktree, branch, spec,
   test plan, ownership paths, and quick validation commands.
3. Engineers in the same wave may run in parallel because their worktrees and
   ownership paths are isolated.
4. Explicitly wait for all selected Engineers. Do not ask the user to trigger or
   continue them.
5. Verify every reported commit exists, belongs to the assigned branch, contains no
   out-of-scope tracked changes, and leaves its worktree clean.
6. Mark successful tickets `review`; retain blocked/failed worktrees and record their
   state. Commit the coordination update on the base branch.
7. Close completed Engineer threads after collecting their summaries.

#### C3. Ticket review and bounded repair

For every ticket in `review`:

1. Spawn an `architect` to review the branch diff against ADR/spec/acceptance.
2. Spawn a `qa` to run ticket tests and configured quick validation in the assigned
   worktree.
3. Architect and QA reviews may run concurrently; wait for both.
4. PASS proceeds to integration.
5. PASS_WITH_ACTIONS or a recoverable BLOCK returns the exact findings to an Engineer
   in the same worktree. Allow at most
   `execution.max_repair_attempts_per_ticket` repair rounds. Rerun both gates after
   each repair commit.
6. A contract contradiction, ambiguous product decision, exhausted repair budget,
   or non-recoverable failure marks the ticket `blocked` or `failed`; preserve its
   branch/worktree and do not integrate it.
7. Close completed reviewer threads after collecting verdicts.

#### C4. Integrate passing tickets

1. Create or reuse the milestone integration worktree:

   ```bash
   python3 .agents/skills/milestone-workflow/scripts/workflow.py \
     integration-create <ID>
   ```

2. Before each wave, fast-forward the clean integration branch to the current base
   coordination commit when needed.
3. Merge passing ticket branches one at a time with `--no-ff`.
4. After every merge, run configured quick validation.
5. Resolve conflicts by intent using user request, exit criteria, ADR, spec, test
   plan, and current public behavior in that order. When intent is ambiguous, stop
   and preserve the conflict state.
6. Run configured full validation after the wave is assembled.
7. Spawn final `architect` and `qa` integration gates; wait for both.
8. Only when full validation and both gates PASS, fast-forward the clean base branch
   to the integration branch. If the base moved, stop and rebuild/review integration;
   never force it.
9. Mark integrated tickets `done`, update roadmap and CI status with commit and test
   evidence, and commit those document updates on the base branch.
10. Passing independent tickets may be integrated even when another ticket in the
    wave failed, when `execution.continue_after_independent_failure = true` and no
    contract or ownership dependency connects them.

### D. Automatic drain loop

After checkpointing a wave, run `workflow.py next` again.

- `execute_frontier`: start the next wave immediately. Do not return to the user.
- `resume_active`: complete the active gate immediately.
- `ready_to_close`: run one final full validation against the milestone head. When
  `auto_close = true`, continue directly into the `close` procedure; otherwise return
  `READY_TO_CLOSE` with the exact close command.
- `blocked`: stop with exact ticket IDs, blocker states, preserved worktrees, and the
  decision or repair needed.
- `no_tickets`: stop because planning is incomplete or the milestone ID is wrong.

When strategy is `wave`, return after the first durable wave checkpoint. When
strategy is `drain`, continue until `ready_to_close`, `blocked`, a configured wave cap,
or a stop condition occurs.

### E. Execute stop conditions

Stop without asking routine progress questions only for a material condition:

- dirty base worktree or unexpected user changes
- missing/contradictory ADR, spec, test plan, or acceptance contract
- permission or approval that cannot be surfaced or granted in the current run
- ambiguous merge conflict or base-branch movement requiring re-planning
- exhausted repair/no-progress budget
- validation failure that cannot be repaired within ticket scope
- all remaining tickets are draft, blocked, failed, or depend on such tickets
- user interrupt or execution-environment interruption

On interruption, persist the latest checkpoint and return the exact `resume` command.

Output: all waves attempted, subagent results, repair rounds, integration commits,
validation evidence, ticket/document updates, retained worktrees, final scheduler
state, and publish state.

## Mode: `resume`

Purpose: recover safely after interruption and continue the same drain loop.

1. Run `status`, `worktree-list`, `next`, and inspect the newest handoff document.
2. Reconcile ticket states with actual clean/dirty worktrees, branches, commits, and
   integration state.
3. Never recreate a branch/worktree that already contains work.
4. Resume at the earliest incomplete gate:
   - implementation
   - ticket review/repair
   - integration
   - full validation
   - milestone closeout
5. After recovering that gate, continue using the configured `drain` or `wave`
   strategy. In `drain`, do not return merely because the recovered gate completed.
6. If state is ambiguous, preserve everything and produce a recovery plan rather than
   guessing or resetting.

Output: recovered evidence, inconsistencies, selected resume point, subsequent waves
completed, and final scheduler state.

## Mode: `close`

Purpose: prove that a milestone is complete and create a durable handoff.

1. Require every in-scope ticket to be `done` or explicitly deferred with rationale.
2. Require a recorded successful full-validation run for the integrated commit.
3. Spawn in parallel:
   - `product_manager` to check exit criteria and deferred scope
   - `architect` to check ADR/spec conformance and architectural debt
   - `qa` to check test evidence, CI coverage, and unresolved failures
4. Wait for all three. A BLOCK verdict prevents closeout.
5. The Team Lead updates roadmap and CI status and writes
   `docs/handoffs/HANDOFF-<milestone>-<date>.md` with commit IDs, decisions, known
   risks, deferred work, and the next milestone entry point.
6. Commit closeout documents. Do not tag, push, release, or delete branches unless
   separately requested.

Output: exit-criteria matrix, gate verdicts, closeout commit, handoff path, deferred
work, and next milestone.

## Final response contract

Always state:

- mode, milestone, strategy, and final scheduler state
- waves completed and why execution stopped
- subagents used, repair rounds, and gate verdicts
- documents, tickets, branches, worktrees, and files changed
- exact validation commands and exit status
- commit IDs and integration state
- blockers, risks, and deferred work
- whether anything was pushed or published; default is **no**
