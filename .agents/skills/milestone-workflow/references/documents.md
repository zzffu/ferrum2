# Documents

Keep files short enough to scan in one screen where practical. Link to evidence instead
of copying logs.

## Milestone

Outcome, non-goals, baseline, state, exit criteria, ticket table, blockers, next action.

## Ticket

One vertical outcome, dependencies, owned paths, acceptance criteria, validation, and
result. Avoid step-by-step implementation prescriptions unless safety requires them.

## ADR

Context, decision, consequences, and status. Use only for durable or hard-to-reverse
choices.

## Spec and test plan

The spec states observable behavior, errors, compatibility, and invariants. The test
plan maps each MUST to its primary evidence and names any distinct secondary failure
mode.

## Handoff

Current commit/state, completed work, remaining blocker/next action, commands that were
actually run, and links to durable artifacts. Do not duplicate specs, diffs, or logs.

## Status values

Use a small vocabulary:

```text
proposed | planned | executing | validating | closed
todo | ready | active | blocked | deferred | done
```
