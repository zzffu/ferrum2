+++
id = "M0-T00"
title = "Replace with one verifiable vertical slice"
milestone = "M0"
status = "draft"
priority = "P1"
risk = "medium"
implementation_blocked_by = []
review_blocked_by = []
integration_blocked_by = []
release_blocked_by = []
required_reviews = ["qa"]
owns = ["path/to/module/**", "path/to/tests/**"]
spec = "docs/specs/SPEC-0000-template.md"
test_plan = "docs/test-plans/TEST-0000-template.md"
acceptance = [
  "Replace with a measurable behavior",
]
+++

# M0-T00: Replace with one verifiable vertical slice

## Outcome

TODO

## Context

TODO

## In scope

- TODO

## Out of scope

- TODO

## Implementation notes and constraints

- TODO

## Validation commands

```bash
# Add ticket-specific commands. Repository quick/full gates remain in workflow.toml.
```

## Risks

- TODO

## Blocker record

Use the Git-common-dir runtime ledger for transient blockers. If a durable contract
blocker must be documented here, include ID, class, gate, root cause, derivatives,
owner, evidence, authorization state, and unblock condition.

Tracked status is durable: use only `draft`, `ready`, `blocked`, `done`, or
`deferred`. Record implementation/review/repair/integration/release with
`workflow.py set-phase`, not by editing this frontmatter.

## Completion evidence

To be filled by the Team Lead after integration:

- Branch:
- Commit(s):
- Required reviewer role/profile and verdict:
- Exact candidate SHA:
- Integrated commit:
