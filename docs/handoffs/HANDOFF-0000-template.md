# Handoff: milestone M0

- **Date:** YYYY-MM-DD
- **Base branch/commit:** TODO
- **Milestone status:** TODO

## Current state

TODO

## Completed work

- TODO

## Decisions and contracts

- ADRs: TODO
- Specs: TODO
- Test plans: TODO
- Tickets: TODO

## Validation evidence

- TODO

## Existing branches and worktrees

- TODO

## Active execution phases and ownership

- TODO

## Canonical blockers and derivatives

- TODO

## Active authorization scopes

- Actions/tickets/classes/max risk: TODO
- Kind/remote effects: local / false
- Exact remote ref/commit/max uses/uses (remote only): TODO
- Root-bound repair override allowances: TODO

## Agent and gate provenance

- Requested role/model/reasoning, observable actual profile, candidate SHA: TODO

## Known risks and debt

- TODO

## Deferred work

- TODO

## Recovery instructions

```bash
python .agents/skills/milestone-workflow/scripts/workflow.py status
python .agents/skills/milestone-workflow/scripts/workflow.py worktree-list
python .agents/skills/milestone-workflow/scripts/workflow.py state --milestone M0
python .agents/skills/milestone-workflow/scripts/workflow.py next \
  --milestone M0 --json
```

## Next recommended action

```text
$milestone-workflow mode=...
```
