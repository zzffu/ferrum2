# Document Contracts

Contracts exist to coordinate independent agents, not to pre-write the implementation.
Use observable outcomes, explicit boundaries, and the smallest evidence set that proves
them.

## Vision and gap analysis

`docs/vision.md` records target users/operators, outcomes, success measures, scope,
non-goals, constraints, compatibility, and the milestone map. It is stable, not a task
log.

`docs/gap-analysis.md` records current evidence, target behavior, priority,
dependencies, proposed milestone, and uncertainty. Separate correctness, feature,
performance, operational, and platform gaps.

## Roadmap

For each milestone record objective, entry/exit criteria, in-scope tickets, deferred
work, integrated commit, canonical blockers, and risks. Status is evidence-based.

## Project context audit

A new feature requires `docs/context-audits/CONTEXT-<milestone>-<slug>.md`. The audit
binds the feature goal, baseline commit, before/after SHA-256 of the configured
`Project-specific context` section, the complete union of configured and project-added
entries, and Product Manager/Architect/QA review.

Every entry gets current repository evidence, a classification, required update, and
post-update result. The audit is repository truth evidence, not a duplicate spec. At
planning it is `approved` and the feature remains under Active planned changes. At
close it is `verified`, names the integrated commit, and current-state context reflects
only integrated behavior.

## ADR

Use an ADR only for cross-module, protocol, persistence, public API, security,
concurrency, platform abstraction, or hard-to-reverse decisions. Respect
`planning.max_adrs_per_milestone`. Routine implementation, formatting, test placement,
CI spelling, or evidence-only repair does not require an ADR.

An ADR specifies outcome invariants, decision boundaries, alternatives, consequences,
compatibility/migration/rollback, and the cheapest reliable verification seam. It does
not prescribe replaceable internal helpers.

## Spec

A spec states objective/non-goals, visible behavior, current execution path and
ownership, required interfaces/data/state, validation/errors, security/concurrency/
lifecycle invariants, compatibility/migration/rollback, observability, acceptance
criteria, and intentional implementation freedom.

Use `planning.spec_soft_line_limit` as a warning that the contract may be
over-prescriptive. Supporting research belongs in references, not MUST requirements.
Open product/architecture decisions must be resolved before ticket readiness.

## Test plan

Use a MUST-to-primary-evidence matrix. One MUST normally maps to one test or direct
observation at the cheapest reliable seam. A second layer requires a named, distinct
failure mode.

Separate:

- product gate: ticket behavior and invariants;
- integration gate: interactions among accepted tickets;
- release gate: hosted CI, platform matrix, external services, soak, packaging, and
  publication.

Reuse fixtures/harnesses. Justify new infrastructure and state its maintenance owner.
Record expected production/test delta and test-budget allowance. Use
`planning.test_plan_soft_line_limit` as a warning against evidence duplication.

## Ticket

Ticket frontmatter is the scheduler contract:

```toml
+++
id = "M1-T01"
title = "Add protocol handshake validation"
milestone = "M1"
status = "draft"
priority = "P1"
risk = "medium"
implementation_blocked_by = []
review_blocked_by = []
integration_blocked_by = []
release_blocked_by = []
required_reviews = ["architect", "qa"]
owns = ["src/protocol/**", "tests/protocol/**"]
spec = "docs/specs/SPEC-0001-protocol.md"
test_plan = "docs/test-plans/TEST-0001-protocol.md"
acceptance = [
  "Reject malformed handshakes with the documented error",
  "Existing valid clients remain interoperable",
]
+++
```

Active tickets may not exceed `planning.max_acceptance_criteria_per_ticket`. Split a
large vertical slice or consolidate equivalent criteria; do not use a long checklist
to manufacture tests.

Dependencies are cumulative through their named gate. Tracked status is durable:
`draft`, `ready`, `blocked`, `done`, or `deferred`. Implementation/review/repair/
integration/release live in the runtime ledger.

Required body sections: Outcome, In scope, Out of scope, Contract references, Primary
evidence, Validation commands, Ownership/risks, and Completion evidence.

## Review debt

`docs/review-debt.md` contains non-blocking notes accepted for integration. Each entry
identifies ticket, reviewer, candidate SHA, impact, and follow-up trigger. It is not a
hidden blocker list.

## CI status and handoff

CI status records exact SHA, environment, commands, exits, evidence validity,
canonical blockers, flakes/setup attempts, and unresolved failures. “CI green” alone
is insufficient.

A handoff records integrated commit, completed work, decisions, validation and
budget evidence, context-audit status/hash, AGENTS.md context updates,
branches/worktrees, active phases, blockers, authorization scopes, review rounds/debt,
risks, deferred work, recovery commands, and next invocation.
