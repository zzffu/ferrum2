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

## Late failures and legacy history

A new failure discovered after a ticket completed its bounded full/targeted cycle is
new work. Create a narrow repair or qualification ticket that records:

- the affected completed ticket;
- the canonical failure/root evidence;
- whether it came from integration, hosted qualification, or release;
- the exact candidate and failing command/evidence;
- minimal ownership and acceptance criteria.

The new ticket receives the ordinary one-full/one-targeted lifecycle. Do not reopen the
completed ticket by adding a third review round.

Runtime ledgers created by older workflow revisions may contain `superseding` records
or append-only `root_cycles`. v1.4 validates and reads those records so historical
milestones remain recoverable, but treats them as immutable compatibility data. The
`record-review` command intentionally creates only `full` and `targeted` records.
