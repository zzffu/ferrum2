# Document contracts

The templates under `assets/templates/` and `docs/` are starting points. Keep names,
IDs, paths, and evidence concrete.

## Vision: `docs/vision.md`

Required sections:

- Problem and target users/operators
- Desired outcomes and success measures
- Product principles
- Scope and non-goals
- Compatibility or upstream relationship
- Constraints
- Milestone map

Vision should be stable. Do not turn it into a task log.

## Gap analysis: `docs/gap-analysis.md`

For each capability or subsystem record:

- current behavior and evidence
- target behavior
- severity/priority
- dependencies
- proposed milestone
- uncertainty and research needed

Separate correctness gaps from feature gaps, performance gaps, operational gaps, and
platform gaps.

## Roadmap: `docs/roadmap.md`

For each milestone record:

- objective
- status
- entry conditions
- exit criteria
- in-scope ticket IDs
- explicit deferred/out-of-scope work
- integrated commit when available
- open blockers and risks

Roadmap status must be evidence-based, not aspirational.

## ADR: `docs/adr/ADR-NNNN-slug.md`

Required sections:

- Status: Proposed, Accepted, Superseded, or Rejected
- Context and problem
- Decision drivers and invariants
- Options considered
- Decision
- Consequences and tradeoffs
- Compatibility/upstream divergence
- Migration and rollback
- Verification plan
- References

Use an ADR for cross-module, public API, persistence, protocol, security, concurrency,
platform abstraction, or hard-to-reverse choices. Do not use ADRs for routine local
implementation details.

## Spec: `docs/specs/SPEC-NNNN-slug.md`

Required sections:

- Objective and non-goals
- User/operator-visible behavior
- Current execution path
- Proposed architecture and module ownership
- Configuration/schema and validation
- Types, interfaces, state transitions, and data flow
- Errors and failure semantics
- Security and privacy
- Concurrency and resource lifecycle
- Compatibility and upstream divergence
- Observability
- Migration/rollback
- Acceptance criteria
- Open questions
- Linked ADRs, test plan, and tickets

A spec must be implementable without inventing core behavior during coding.

## Test plan: `docs/test-plans/TEST-NNNN-slug.md`

Required sections:

- Scope and test seams
- Acceptance-criteria matrix
- Unit tests
- Integration/interoperability tests
- Negative/error tests
- Security tests
- Concurrency/race/soak tests where relevant
- Compatibility and platform matrix
- Performance/resource tests where relevant
- CI placement and commands
- Test data, fixtures, and isolation
- Exit conditions and known gaps

Every acceptance criterion must map to a test or explicitly justified evidence.

## Ticket: `docs/tickets/<ID>-slug.md`

Ticket files use TOML frontmatter so the helper script can validate and schedule them:

```toml
+++
id = "M1-T01"
title = "Add protocol handshake validation"
milestone = "M1"
status = "draft"
priority = "P1"
blocked_by = []
owns = ["src/protocol/**", "tests/protocol/**"]
spec = "docs/specs/SPEC-0001-protocol.md"
test_plan = "docs/test-plans/TEST-0001-protocol.md"
acceptance = [
  "Reject malformed handshakes with the documented error",
  "Existing valid clients remain interoperable",
]
+++
```

Required body sections:

- Outcome
- Context
- In scope
- Out of scope
- Implementation notes and constraints
- Validation commands
- Risks
- Completion evidence

Ownership paths are coordination contracts, not broad permission. Prefer narrow
module/test paths. If a lockfile, registry, generated API, or shared interface must be
changed, declare it explicitly or execute sequentially.

## CI status: `docs/ci-status.md`

Record:

- branch/commit tested
- environment/toolchain/platform
- exact commands
- exit status
- date
- known flakes or skipped jobs
- unresolved failures

Do not replace evidence with a generic “CI green”.

## Handoff: `docs/handoffs/HANDOFF-<milestone>-<date>.md`

Required sections:

- Current state and integrated commit
- Completed work
- Decisions and contract references
- Validation evidence
- Existing branches/worktrees
- Known risks and debt
- Deferred work
- Recovery instructions
- Next recommended action and invocation
