---
name: milestone-workflow
description: Orchestrate a repository milestone with Product Manager, Architect, Engineer, and QA subagents. Use explicitly for bootstrap, plan, execute, status, resume, or close modes; creates ADR/spec/test-plan/ticket contracts, drains dependency-ready tickets through isolated Git worktrees, reviews and integrates them, and records milestone evidence. Never pushes or publishes by default.
---

# Milestone Workflow

The primary thread is the **Team Lead** and sole scheduler/integrator. Subagents do
bounded specialist work and return evidence to the primary thread. Subagents must not
schedule other subagents. Engineers are the only subagents that normally edit product
code, and every Engineer works in a separate Git worktree.

## Agent launch contract

Always spawn the configured named role with an explicit `agent_type`; never use a
generic/default agent for a milestone gate. Before assigning work, verify the role
profile with `workflow.py doctor`. The repository defaults are:

| Role | Reasoning effort | Mutation |
|---|---|---|
| `product_manager` | `max` | read-only |
| `architect` | `max` | read-only |
| `engineer` | `high` | assigned worktree only |
| `qa` | `high` | test artifacts only; no tracked edits |

If the runtime exposes actual launch metadata, compare it with the configured
profile before the agent starts. If it does not, report the launch profile as
`unverified`; never claim a reasoning level merely from the requested role.

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
  -> resume active work and select every independent implementation-ready ticket
  -> spawn isolated Engineers up to capacity
  -> review each completed candidate without waiting for unrelated Engineers
  -> repair bounded failures when possible
  -> integrate compatible passing candidates as a batch
  -> validate and write one material checkpoint
  -> recompute the next wave
  -> repeat without asking the user to invoke execute again
```

Do **not** return after the first frontier when strategy is `drain`. Return after one
frontier only when the user explicitly selects `strategy: wave`, the configured wave
cap is reached, or a stop condition below applies.

## Mandatory preflight

For every mode:

1. Read the applicable `AGENTS.md` chain and `workflow.toml`.
2. Resolve a Python 3.11+ launcher once (`python` in this repository's Windows
   workflow; use `python3` only where that is the installed launcher). Run `doctor`
   and `validate`. When a milestone is known, also inspect its state:

   ```bash
   python .agents/skills/milestone-workflow/scripts/workflow.py doctor
   python .agents/skills/milestone-workflow/scripts/workflow.py validate
   python .agents/skills/milestone-workflow/scripts/workflow.py state \
     --milestone <ID>
   ```

3. Read `references/state-machine.md` and the mode-specific section below.
4. Treat approved ADRs, specs, test plans, and ticket frontmatter as contracts.
5. Never claim a gate passed without direct evidence.

For `execute`, `resume`, and `close`, also read
`references/integration-and-recovery.md`. For document creation or ticket changes,
read `references/document-contracts.md`. For optional third-party skills, read
`references/mattpocock-integration.md`. For any blocked or failed gate, read
`references/blocker-taxonomy.md`.

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
- Only `implementation_blocked_by` prevents Engineer startup. Review, integration,
  and release dependencies are enforced at their named gates. Legacy `blocked_by`
  means `implementation_blocked_by`.
- Record explicit user authorization in the local runtime ledger with its exact
  action, ticket, risk, blocker class, and remote-effects boundary. A matching
  granted local authorization is reusable after resume; it never implies remote,
  destructive, publish, contract-expansion, or ownership-expansion authority.
- Authorization ticket and blocker-class lists must be non-empty; an empty list is
  never a wildcard. `kind = remote` and `remote_effects = true` must agree. A repair
  budget override requires its own exact `repair_budget_override` action.
  Authorization scope IDs are immutable: revoke an existing scope and grant a new
  ID rather than overwriting its use history.
- A remote authorization also names the exact remote ref, full commit SHA, and
  maximum use count. Run `consume-authorization` immediately before the remote
  mutation; consumption is atomic and an exhausted grant cannot match again.
- A blocker's `authorization` label is descriptive only: any value other than
  `not_required` still requires an exact matching ledger scope. A bounded local
  repair consumes one use atomically with the repair record; record repair and
  budget-override scope IDs separately.
- Repair budget is counted per canonical root. An exhausted root resumes only after
  one exact `repair_budget_override` use is consumed with that root ID, producing one
  persisted extra attempt.
- Classify every stop by canonical root blocker. Derived failures, poisoned follow-on
  tests, skipped commands, and environment setup attempts do not become independent
  product blockers. Resolving a root resolves its direct derivatives atomically.
- Open canonical roots fail their named gate and every later gate. A ticket cannot
  become `done`, and a milestone cannot become `ready_to_close`, while an applicable
  root remains open.
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
   - declare `risk = low | medium | high | critical`
   - declare implementation, review, integration, and release dependencies
   - declare required review roles for its risk and change surface
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
   python .agents/skills/milestone-workflow/scripts/workflow.py status
   python .agents/skills/milestone-workflow/scripts/workflow.py worktree-list
   python .agents/skills/milestone-workflow/scripts/workflow.py state \
     --milestone <ID>
   python .agents/skills/milestone-workflow/scripts/workflow.py next \
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
5. A new execute invocation starts its wave/no-progress counter with
   `workflow.py checkpoint --milestone <ID> --progress material --new-run`; resume
   reuses the existing checkpoint.
6. Only a product/test delta, root
   blocker resolution, new candidate-SHA evidence, or integration result is material
   progress. Pure status edits, coordination commits, repeated derived failures, and
   unchanged gate reruns do not reset the no-progress counter. Persist checkpoints
   with `workflow.py checkpoint`.

### B. Reconcile before scheduling

1. Require the configured base branch and a clean base worktree. If dirty, stop and
   identify exact paths; never stash or discard them.
2. Inspect tickets, branches, worktrees, commits, and any integration branch.
3. Run:

   ```bash
   python .agents/skills/milestone-workflow/scripts/workflow.py next \
     --milestone <ID> --limit <N> --json
   ```

4. If the action is `resume_active` or `resume_and_execute_frontier`, resume active
   gates while also starting every selected, ownership-disjoint ticket:
   - `implementation` phase: resume or replace the assigned Engineer in the existing
     worktree
   - `review` phase: run or finish Architect/QA ticket gates
   - `repair` phase: inspect preserved evidence and retry only when the failure is
     recoverable and the repair budget permits it
   - `integration` phase: finish merge, validation, or base fast-forward recovery
5. Never recreate an existing branch or worktree containing partial work.

### C. Execute one pipeline batch

When the scheduler action is `execute_frontier` or
`resume_and_execute_frontier`:

#### C1. Local execution checkpoint

1. Select the implementation-ready, ownership-disjoint frontier reported by
   `workflow.py`.
2. Record transient execution phase in the local runtime ledger with `set-phase`.
   Clear it with `clear-phase` or a durable `set-status` transition. Do not create a
   Git commit solely for implementation/review phase, repair count, or authorization
   state.
3. Update and commit contracts only for a material scope/decision change.
4. Confirm the base worktree remains clean.

#### C2. Isolated Engineer implementation

For each selected ticket:

1. Reconcile the ledger, `worktree-list`, and branch history first. If any existing
   ticket or repair worktree contains partial/current work, adopt its exact absolute
   path, branch, and HEAD with `set-phase`; do not redirect the ticket to the default
   worktree name. Only when no existing worktree applies, create one from the current
   material base commit:

   ```bash
   python .agents/skills/milestone-workflow/scripts/workflow.py \
     worktree-create <TICKET_ID>
   ```

2. Spawn one `engineer` with the ticket ID/path, absolute worktree, branch, spec,
   test plan, ownership paths, and quick validation commands.
3. Engineers in the same wave may run in parallel because their worktrees and
   ownership paths are isolated.
4. As each Engineer finishes, verify and start its review; unrelated Engineers may
   continue. Do not impose a wait-for-all barrier.
5. Verify every reported commit exists, belongs to the assigned branch, contains no
   out-of-scope tracked changes, and leaves its worktree clean.
6. Record successful candidates as review-ready in the local ledger; retain
   blocked/failed worktrees and record the canonical root blocker. Do not commit a
   review-only coordination update.
7. Close completed Engineer threads after collecting their summaries.

#### C3. Ticket review and bounded repair

For every ticket with runtime phase `review`:

1. Resolve the gate profile from risk and `required_reviews`. Security, protocol,
   concurrency, cross-module, public API, or hard-to-reverse changes require both
   `architect` and `qa`; a mechanical/evidence-only repair reruns only affected gates.
2. Bind every verdict to the explicit role profile and exact candidate SHA.
3. Required reviews may run concurrently; wait for those reviews only.
4. PASS proceeds to integration.
5. PASS_WITH_ACTIONS or a recoverable BLOCK returns the canonical root finding to an
   Engineer in the same worktree. Apply the risk-aware budget. Mechanical repairs do
   not consume substantive budget; derived failures do not consume another attempt.
   Rerun only invalidated gates. An unintegrated local candidate may be amended when
   provenance remains explicit; never rewrite published history.
6. A contract contradiction, ambiguous product decision, exhausted repair budget,
   or non-recoverable failure marks the durable ticket `blocked`. A recoverable
   failure enters runtime phase `repair`. Preserve its branch/worktree and do not
   integrate it.
7. Close completed reviewer threads after collecting verdicts.

#### C4. Integrate passing tickets

1. Create or reuse the milestone integration worktree:

   ```bash
   python .agents/skills/milestone-workflow/scripts/workflow.py \
     integration-create <ID>
   ```

2. Before each batch, fast-forward the clean integration branch to the current
   material base commit when needed.
3. Integrate passing ticket commits with traceable provenance; do not create an
   extra merge solely to record a workflow state.
4. Run affected quick validation as candidates enter the batch, then the configured
   full gate once on the assembled integration SHA.
5. Resolve conflicts by intent using user request, exit criteria, ADR, spec, test
   plan, and current public behavior in that order. When intent is ambiguous, stop
   and preserve the conflict state.
6. Run final integration reviews when required by risk, cross-ticket interaction, or
   release-candidate policy. Final release evidence remains bound to the exact SHA.
7. Only when full validation and all required gates PASS, fast-forward the clean base branch
   to the integration branch. If the base moved, stop and rebuild/review integration;
   never force it.
8. Mark integrated tickets `done`, update roadmap and CI status with material commit
   and test evidence, and create at most one consolidated evidence checkpoint for
   the integrated batch.
9. Passing independent tickets may be integrated even when another ticket in the
    wave failed, when `execution.continue_after_independent_failure = true` and no
    contract or ownership dependency connects them.

### D. Automatic drain loop

After checkpointing a wave, run `workflow.py next` again.

- `execute_frontier`: start the next wave immediately. Do not return to the user.
- `resume_and_execute_frontier`: resume active work and start the disjoint frontier
  concurrently.
- `resume_active`: complete the active gate immediately.
- `ready_to_close`: run one final full validation against the milestone head. When
  `auto_close = true`, continue directly into the `close` procedure; otherwise return
  `READY_TO_CLOSE` with the exact close command.
- `blocked`: stop only after exhausting independent work and matching authorization.
  Report blocker ID/class/gate/root cause/derived failures/owner/evidence/unblock
  condition.
- `run_limit_reached`: return after the configured wave/no-progress guard and include
  the exact resume invocation; do not start the suppressed frontier.
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
- all remaining tickets are draft, blocked, or depend on such tickets
- user interrupt or execution-environment interruption

On interruption, persist the latest local checkpoint without requiring a Git commit
and return the exact `resume` command.

Output: all waves attempted, subagent results, repair rounds, integration commits,
validation evidence, ticket/document updates, retained worktrees, final scheduler
state, and publish state.

## Mode: `resume`

Purpose: recover safely after interruption and continue the same drain loop.

1. Run `status`, `worktree-list`, `state`, `next`, and inspect the newest handoff.
2. Reconcile ticket states with actual clean/dirty worktrees, branches, commits, and
   integration state.
3. Never recreate a branch/worktree that already contains work.
4. Recover active authorization, canonical blockers, repair usage, and execution
   phases. Resume incomplete gates and independent ready work together:
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
- requested and, when observable, actual role/reasoning profile
- documents, tickets, branches, worktrees, and files changed
- exact validation commands and exit status
- commit IDs and integration state
- blockers, risks, and deferred work
- canonical root blockers, derived failures, and authorization scope used/remaining
- whether anything was pushed or published; default is **no**
