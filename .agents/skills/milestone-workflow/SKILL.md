---
name: milestone-workflow
description: Plan, execute, resume, inspect, and close repository milestones with concise Markdown contracts, isolated Git worktrees, bounded review, and explicit validation. Use when the user asks for milestone or feature planning, coordinated ticket execution, status, recovery, or closeout. Never pushes or publishes without explicit approval.
---

# Milestone workflow

Keep the workflow visible and repository-native. Git records implementation state;
tracked Markdown records intent, decisions, acceptance, evidence, and handoff.

## Inputs

Accept natural language or these fields:

```text
mode: bootstrap | feature | plan | execute | status | resume | close | recover
milestone: M3
goal: outcome to deliver
scope: optional paths or modules
strategy: drain | wave
```

Infer non-critical omissions from the repository and state each assumption. Do not turn
an execution request into a long interview.

## Read first

1. The applicable `AGENTS.md` chain.
2. `docs/agents/milestone-workflow.md` if present.
3. `docs/roadmap.md`, the active milestone file, and relevant ADR/spec/test plan/tickets.
4. `git status`, current branch, worktrees, recent commits, and the fixed comparison base.

A bad ref, dirty base, conflicting contract, or missing required evidence is a blocker;
do not hide it with generated state.

## Invariants

- The primary thread schedules and integrates. Subagents do not spawn subagents.
- One Engineer owns one ticket, branch, and worktree. Parallel writers need disjoint paths.
- Product work does not edit this skill or `.codex/agents/**`.
- Contracts describe outcomes and invariants, not an implementation transcript.
- Use existing tests and seams before creating another harness or evidence layer.
- One full review and one targeted re-review are the default bound. Remaining blockers
  escalate; notes become debt.
- Run commands exactly as recorded. Never claim an unrun or skipped gate passed.
- Never reset unknown work, force-push, publish, release, or mutate remotes without
  explicit authorization.

## Route

- `bootstrap`, `feature`, `plan`: read `references/plan.md`.
- `execute`, `resume`: read `references/execute.md`.
- `status`, `close`: read `references/close.md`.
- `recover`: read `references/recovery.md`.
- Before writing workflow documents, read `references/documents.md`.

Load only the relevant reference. Do not preload every file.

## Minimal lifecycle

```text
inspect -> define outcome -> split dependency-ready tickets -> implement in worktrees
-> review exact commits -> integrate -> validate -> close -> handoff
```

Use `strategy: drain` unless the user asks for one wave. Recompute readiness after each
integration; stop on completion, a real blocker, a moved/dirty base, exhausted review
bound, or missing authorization.

## Repository files

Default paths are defined in `docs/agents/milestone-workflow.md`:

```text
docs/milestones/   active milestone summaries
docs/tickets/      executable work items
docs/adr/          durable decisions
docs/specs/        observable behavior contracts
docs/test-plans/   evidence plan
docs/handoffs/     concise continuation notes
docs/history/      archived closed work
.worktrees/        local isolated worktrees
```

Templates live under `assets/templates/`. Copy and fill them; remove unused headings.

## Shell helper

`./scripts/migrate-history.sh` archives closed ticket and handoff bodies. It is
idempotent and dry-run-first. It is not a workflow runtime or source of truth.

## Completion response

Report:

1. outcome and current milestone state;
2. files, tickets, branches, worktrees, and commits changed;
3. reviews and unresolved finding IDs;
4. commands with exit status and any unrun gates;
5. next action, blocker, and remote-action status.
