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
  "Replace with one measurable outcome",
]
+++

# M0-T00: Replace with one verifiable vertical slice

## Outcome

TODO

## In scope

- TODO

## Out of scope

- Optional hardening, unrelated cleanup, and release qualification not owned here.

## Contract references

- ADR/spec/test-plan sections that constrain this ticket.

## Primary evidence

Map each acceptance criterion to one primary existing or planned test/observation.
Justify any additional layer by a distinct failure mode.

## Validation commands

```bash
# Ticket-specific commands; quick/full remain in workflow.toml.
# workflow.py test-budget --gate ticket --base <base_branch>
```

## Ownership and risks

- TODO

## Completion evidence

Filled by the Team Lead after integration:

- Candidate and integrated commit:
- Full/targeted review records and stable finding IDs:
- Test-budget result:
- Accepted review debt:
