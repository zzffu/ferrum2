---
id: M13-T01
milestone: M13
status: ready
depends_on: []
owns:
  - CONTEXT.md
  - ci/test-budget-baseline.txt
  - docs/adr/ADR-0032-m13-egress-and-module-seams.md
  - docs/milestones/M13-behavior-preserving-architecture-consolidation.md
  - docs/roadmap.md
  - docs/specs/SPEC-0014-m13-behavior-preserving-architecture-consolidation.md
  - docs/test-plans/TEST-0014-m13-behavior-preserving-architecture-consolidation.md
  - docs/tickets/M13-T*.md
---

# M13-T01 — Freeze architecture contracts

## Outcome

Accept one repository-native M13 contract/control commit that pins the real planning baseline，maps all
preserved M12 behavior to evidence and fixes the owned-plan、DNS dependency and client-egress migration
seams before product work。

## Acceptance

- [ ] Qualified product、planning HEAD/tree/parent and current source witnesses resolve exactly；the
      supplied external architecture file is not treated as Git evidence。
- [ ] ADR-0032、SPEC-0014、TEST-0014 and all seven tickets agree on outcome、non-goals、serial dependency
      graph、ownership、review bound and remote boundary。
- [ ] Schema 3 M13 policy is based on exact `4810ec5c…` counts `18940/39748` with unchanged thresholds，
      `policy_revision=1` and `TEST-0014` as `reforecast_ref`。
- [ ] Existing M12 route/DNS/snapshot and architecture evidence passes unchanged；no product、dependency、
      workflow、harness or remote state changes。
- [ ] Plan gate passes：scope is bounded，dependencies are acyclic，overlap is serialized，acceptance is
      observable and every required command is known。

## Validation

Run `TEST-0014` T01 commands and repository Quick commands from
`docs/agents/milestone-workflow.md`。The accepted commit is a control/Markdown change；do not mix Rust
product edits into it。

## Result

- Commit: —
- Review: —
- Notes: —

## Rollback / risk

Rollback restores the M12 footprint policy and removes only M13 planning artifacts。The main risk is
starting implementation from an unaccepted or moved base；T02 must bind the exact accepted T01 commit。
