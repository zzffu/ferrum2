# Review Convergence

The review protocol is designed to find material defects without moving the target
indefinitely.

## Round 1: full review

Each required reviewer examines the exact candidate SHA once. Findings have stable
IDs and severities:

- `blocker`: unsafe to integrate; correctness, security, data loss, protocol break,
  unrecoverable migration, or equivalent.
- `major`: acceptance/invariant failure or high-probability regression.
- `minor`: useful improvement that does not invalidate the ticket.
- `note`: observation, style, future hardening, or unrelated debt.

Only blocker and major findings block. A blocking verdict must identify one canonical
root; derivative failures refer to that root.

Record the review:

```bash
python .agents/skills/milestone-workflow/scripts/workflow.py record-review \
  M1-T01 --reviewer qa --round full --candidate-sha <sha> --verdict block \
  --finding 'QA-001:major:malformed frame is accepted'
```

## One repair

Return only stable blocking finding IDs to the Engineer. One substantive repair is
automatic. Mechanical corrections do not consume that budget, but they do not earn a
new full review.

## Round 2: targeted re-review

The targeted round checks:

1. original blocking IDs;
2. the repair delta;
3. tests invalidated by the repair.

It does not repeat repository-wide discovery. Resolve IDs explicitly:

```bash
python .agents/skills/milestone-workflow/scripts/workflow.py record-review \
  M1-T01 --reviewer qa --round targeted --candidate-sha <new-sha> \
  --verdict pass --resolved QA-001
```

A new blocker is legal only when the repair introduced it under the configured
policy. Record it with:

```text
--new-finding 'QA-002:major:introduced_by_repair:repair leaks plaintext'
```

If any blocker remains after the targeted round, return `ESCALATE`. Do not start a
third automatic cycle.

## Explicit superseding verification

A targeted `ESCALATE` remains the normal terminal result. Exceptionally, the user may
authorize one later budget-consuming repair and one local superseding verification
for the same canonical root. The repair must name its consumed
`repair_budget_override`. Record the verification as a separate `superseding` round
bound to the active repaired SHA and an unused single-use `review_round_override`
authorization scope.

The superseding round:

- preserves the full and targeted records, including the escalation;
- may address only blocking finding IDs already present in the immutable targeted
  escalation, whether inherited from the full review or marked
  `introduced_by_repair`, and preserves their finding provenance;
- remains bound to the same canonical root and the active SHA produced by the
  separately authorized later repair;
- consumes its exact authorization atomically with the new review record;
- may conclude `PASS`, `PASS_WITH_NOTES`, or retain `ESCALATE`;
- is never an automatic third loop and never authorizes another repair, broader
  findings, ownership, contract, remote, destructive, push, or publish action.

Each reviewer requires its own single-use `review_round_override`. Unknown, newly
discovered, duplicated, or broadened IDs; mismatched roots or candidates; exhausted,
reused, or multi-use scopes; and any additional repair or review loop remain invalid.

## Later hosted or release root cycle

A hosted or release gate may discover a new canonical root after the ticket already
used its legacy full, targeted, and superseding slots. Do not overwrite those records.
Append one root-scoped cycle by passing the new canonical root to every record:

```bash
# Reviewer with a blocking baseline and one repair.
python .agents/skills/milestone-workflow/scripts/workflow.py record-review \
  M2-T05 --reviewer architect --round full --root-blocker M2-T05-HOSTED-001 \
  --candidate-sha <hosted-sha> --verdict block \
  --finding 'ARCH-HOSTED-001:major:hosted failure'
python .agents/skills/milestone-workflow/scripts/workflow.py record-review \
  M2-T05 --reviewer architect --round targeted \
  --root-blocker M2-T05-HOSTED-001 --candidate-sha <repair-sha> \
  --verdict escalate --resolved ARCH-HOSTED-001 \
  --new-finding 'ARCH-HOSTED-002:major:introduced_by_repair:repair gate failed'

# A required reviewer may record a passing baseline on the repaired SHA.
python .agents/skills/milestone-workflow/scripts/workflow.py record-review \
  M2-T05 --reviewer qa --round full --root-blocker M2-T05-HOSTED-001 \
  --candidate-sha <repair-sha> --verdict pass_with_notes --note '<bounded note>'
```

After a separately authorized budget-consuming repair, each required reviewer records
one final `superseding` verification with its own unused `review_round_override`:

```bash
python .agents/skills/milestone-workflow/scripts/workflow.py record-review \
  M2-T05 --reviewer architect --round superseding \
  --root-blocker M2-T05-HOSTED-001 --candidate-sha <final-sha> \
  --verdict pass_with_notes --resolved ARCH-HOSTED-002 --note '<bounded note>' \
  --authorization-scope <architect-scope>
python .agents/skills/milestone-workflow/scripts/workflow.py record-review \
  M2-T05 --reviewer qa --round superseding \
  --root-blocker M2-T05-HOSTED-001 --candidate-sha <final-sha> \
  --verdict pass --authorization-scope <qa-scope>
```

The root and ticket binding is exact. Full and targeted candidates and findings are
immutable; targeted blockers retain their IDs, severity, and provenance. Final
verification accepts no new finding, changes candidate after the escalation or
passing baseline, binds the authorization atomically to that root and reviewer, and
must match the active repair SHA. `review-state` evaluates the latest appended root
cycle and fails until all required reviewers have passing final evidence on the same
SHA. An older cycle or the legacy passing record never substitutes for that evidence.

## Verdicts

- `pass`: integrate.
- `pass_with_notes`: integrate and append notes to `docs/review-debt.md`.
- `block`: first round only; one repair.
- `escalate`: targeted round still blocked or contract decision required.

## External code-review skills

During milestone execution, Architect and QA are the only authoritative review
gates. Disable implicit invocation of a general code-review skill. An explicit user
request for an independent review is allowed, but its advisory output does not silently
restart the milestone repair loop.
