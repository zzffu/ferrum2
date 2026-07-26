# Repository instructions

Replace or extend the project-specific sections below with the repository's real
architecture, commands, conventions, and security constraints. Keep version numbers
and command definitions in their authoritative build/config files where possible.

## Project-specific context

- Product purpose: TODO
- Primary languages/frameworks: TODO
- Architecture entry points: TODO
- Critical invariants: TODO
- Generated files: TODO
- Local development setup: TODO

## Project validation

The authoritative machine-readable command lists live in `workflow.toml`.
Document any additional package/module-specific validation rules here.

<!-- BEGIN CODEX MILESTONE WORKFLOW -->
## Codex milestone workflow

### Control model

- The primary Codex thread is the Team Lead and sole integrator.
- Use the `milestone-workflow` skill for milestone bootstrap, planning, execution,
  status, recovery, and closeout.
- Delegate product planning to `product_manager`, system design/review to
  `architect`, implementation to `engineer`, and test gates to `qa`.
- Subagents return evidence to the Team Lead. They do not schedule other agents,
  merge, or publish work.
- In `execute` mode, the default `drain` strategy keeps recomputing frontiers and
  scheduling later dependency waves in the same primary-thread invocation. The user
  does not need to invoke `execute` once per frontier.

### Sources of truth

Read these before milestone work:

1. The nearest applicable `AGENTS.md` or `AGENTS.override.md`.
2. `workflow.toml` for branch, worktree, document, and validation configuration.
3. `docs/vision.md` and `docs/roadmap.md` for product and milestone intent.
4. Applicable files under `docs/adr/`, `docs/specs/`, `docs/test-plans/`, and
   `docs/tickets/`.
5. The real source code, tests, build files, and CI definitions.

Approved ADRs and specs are contracts. Do not silently rewrite them to justify an
implementation. When implementation evidence invalidates a decision, stop the gate
and propose an explicit ADR/spec revision.

### Required gates

For cross-module, protocol, persistence, public API, security, concurrency, or
hard-to-reverse changes:

1. Product scope and measurable exit criteria.
2. Architecture decision where required.
3. Implementation-ready spec.
4. Test plan mapped to acceptance criteria and failure modes.
5. Tickets with explicit blockers and non-overlapping ownership paths.
6. Implementation in isolated Git worktrees.
7. Architect and QA review.
8. Integration branch validation.
9. Team Lead fast-forward into the base branch only after all gates pass.

Small local fixes may use a reduced path, but still require a precise acceptance
criterion, focused tests, and repository validation.

### Parallel work and Git rules

- Parallelize read-heavy investigation freely when the questions are independent.
- Never run two write-heavy agents in the same worktree.
- Every Engineer receives one ticket, one branch, one worktree, and explicit
  ownership paths.
- Parallel Engineer tickets must have all blockers complete and disjoint ownership
  paths. Unknown or overlapping ownership means sequential execution.
- Engineers may commit only their assigned branch. They may not merge, rebase,
  push, force-push, delete branches, or modify the base worktree.
- The Team Lead integrates into a milestone integration branch/worktree first.
- After each validated wave, the Team Lead checkpoints state and immediately schedules
  the next ready wave when execution strategy is `drain`.
- Do not use `git add .`. Stage files intentionally.
- Never discard an uncommitted change, abort another agent's operation, or run a
  destructive Git command without explicit user authorization.
- Never push, open/merge a PR, publish a release, or mutate remote issue state unless
  the user explicitly requests that separate action.

### Implementation and validation

- Prefer vertical slices with observable behavior over horizontal scaffolding.
- Use red-green-refactor at agreed test seams.
- Treat configured validation commands as deterministic gates; record commands and
  exit statuses.
- A missing or skipped required command is not a pass.
- Keep unrelated cleanup outside the ticket unless separately approved.
- Do not place credentials, private endpoints, production data, or secrets in code,
  tests, fixtures, logs, or documents.

### Optional Matt Pocock skills

When installed, use model-invoked skills as supporting disciplines:
`research`, `prototype`, `domain-modeling`, `codebase-design`, `tdd`,
`diagnosing-bugs`, `code-review`, and `resolving-merge-conflicts`.

Do not recursively invoke another user-invoked orchestration skill from
`milestone-workflow`. The user may run `grill-with-docs`, `wayfinder`, `to-spec`,
`to-tickets`, `implement`, or `handoff` manually before or between workflow modes.

### Completion report

Every implementation or milestone response must state:

- documents and files changed
- tickets and branches involved
- tests and validation commands actually run
- commit IDs and integration state
- unresolved risks, blockers, and deferred work
- whether anything was pushed or published (default: no)
<!-- END CODEX MILESTONE WORKFLOW -->
