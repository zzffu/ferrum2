# TEST-0000: Feature title

- **Status:** Draft
- **Milestone:** M0
- **Spec:** `docs/specs/SPEC-0000-template.md`
- **Gate profile:** reduced / standard / strict

## Risk summary and cheapest reliable seams

TODO

## MUST-to-primary-evidence matrix

One MUST normally maps to one primary item. Add secondary evidence only for a named,
distinct failure mode.

| MUST / invariant | Primary evidence | Gate | Distinct uncovered failure mode |
|---|---|---|---|
| TODO | TODO | product/integration/release | none / TODO |

## Product gate commands

```bash
# Ticket-local deterministic commands.
```

## Integration gate commands

```bash
# Only cross-ticket interaction evidence.
```

## Release qualification

Hosted CI, platform matrix, external services, soak, packaging, or publication.
Explicitly state when not applicable. Release-only failures do not reopen a product
ticket unless they demonstrate a product defect.

## Fixtures and harness economy

Reuse existing fixtures and helpers. Justify every new harness/process wrapper and
state who maintains it.

## Test-budget expectation

State expected production/test delta and any justified allowance. Do not improve the
ratio by adding meaningless production code.

## Exit conditions and accepted gaps

List blocking gaps separately from review debt.
