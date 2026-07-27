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
- canonical root blockers and risks in separate sections

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
implementation details. CRLF normalization, formatting, exact test-filter spelling,
CI probe portability, and evidence-only repairs do not require an ADR unless they
actually change an approved architecture or public contract.

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

Legacy `blocked_by` remains accepted as `implementation_blocked_by`. New tickets use
the four explicit fields. Dependencies are cumulative through their named gate, so an
integration-only dependency does not serialize implementation. Cycle validation uses
the cumulative graph through integration; release-only edges are closeout checks and
do not falsely block implementation.

Tracked ticket status is durable and uses only `draft`, `ready`, `blocked`, `done`,
or `deferred`. Implementation, review, repair, integration, and release are runtime
ledger phases. Legacy tracked `in_progress`, `review`, and `failed` values are
accepted only for migration.

Risk and required-review policy:

- `low`: mechanical or evidence-only; rerun affected gates
- `medium`: localized behavior; QA is normally required
- `high`/`critical`: security, protocol, concurrency, public API, cross-module, or
  hard-to-reverse; Architect and QA are required

Blocked tickets include a structured `blocker` table or a runtime-ledger record using
`references/blocker-taxonomy.md`.

The checked-in `*-0000-template.md` files must match their corresponding
`assets/templates/` sources. `workflow.py validate` reports drift, and
`workflow.py new-ticket` must emit the same dependency, risk, blocker, reviewer
profile, and exact-candidate-SHA contract.

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

- exact candidate SHA and evidence validity (`current`, `superseded`, or `historical`)
- environment/toolchain/platform
- exact commands
- exit status
- date
- canonical root blocker ID and any `derived_from` relationship
- known flakes, setup attempts, skipped jobs, and unresolved failures

Do not replace evidence with a generic “CI green”.

## Handoff: `docs/handoffs/HANDOFF-<milestone>-<date>.md`

Required sections:

- Current state and integrated commit
- Completed work
- Decisions and contract references
- Validation evidence
- Existing branches/worktrees
- Active transient phases and ownership leases
- Canonical blockers and derivative failures
- Active authorization scopes, exact remote ref/SHA/use limits, and remote-effects
  boundary
- Root-bound repair override allowances
- Requested and observable agent role/reasoning provenance
- Known risks and debt
- Deferred work
- Recovery instructions
- Next recommended action and invocation
