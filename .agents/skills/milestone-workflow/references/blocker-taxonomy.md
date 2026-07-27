# Blocker taxonomy

Record one canonical root blocker for a stopped gate. Link follow-on failures as
derivatives instead of charging them as new repair attempts.

## Classes

| Class | Meaning |
|---|---|
| `decision` | A user/product choice is missing |
| `contract` | Approved ADR/spec/test/ticket contracts conflict or are incomplete |
| `code` | Implementation behavior is wrong |
| `security` | A security invariant is violated |
| `test_evidence` | Test, fixture, CI probe, or evidence selection is wrong |
| `mechanical` | Formatting, line endings, spelling, or equivalent representation |
| `environment` | Required tool/provider/platform is unavailable or broken |
| `dependency` | Another ticket/root blocker prevents this gate |
| `authorization` | The action exceeds granted authority |
| `remote` | A remote provider/action is the blocking boundary |
| `repository_state` | Dirty/conflicted/moved Git state prevents safe progress |
| `none` | No blocker |

## Required record

Every open blocker has:

- stable ID and ticket ID
- class, risk, and gate phase
- concise root cause
- `root_cause_id` and optional `derived_from`
- owner
- evidence references
- authorization state
- explicit unblock condition
- open/resolved status and resolution evidence

Root records have `root_cause_id == id` and no `derived_from`. A derivative points
directly to the root; do not build chains that obscure causality.

## Counting and reporting

- Count repair usage against the root cause, not each symptom.
- `mechanical` repairs do not consume substantive budget.
- Setup failures, skipped downstream commands, poisoned locks, and repeated copies of
  the same failure are derivatives unless independently proven otherwise.
- A budget never grants authority. Authorization never converts a failed gate into a
  pass.
- Authorization scopes name at least one exact ticket and blocker class. Empty
  ticket/class lists are invalid, local and remote kinds cannot be mixed, and budget
  override is a separately named action.
- `authorization = granted` on a blocker is not authority by itself. Every
  authorization-requiring repair must match the ledger exactly. If a local scope has
  `max_uses`, record and consume one use atomically with the repair.
- Scope IDs are immutable. Use `revoke-authorization` and a new scope ID; never
  overwrite a consumed or remote authorization to reset its use count.
- Remote scopes additionally bind the exact remote ref, full commit SHA, and use
  count. Consume one use before the remote action so resume cannot repeat it.
- An exhausted root remains blocked until an exact `repair_budget_override` use is
  atomically consumed for that root. The resulting persisted allowance extends only
  that root by one attempt; it does not refill another root on the same ticket.
- Report both the canonical root and derivatives, but schedule the root once.
- Resolving either a root ID or one of its derivative IDs resolves the canonical root
  and every direct derivative atomically; a resolved root cannot leave an open
  derivative blocking another ticket.
- Each repair event persists whether it consumed budget. Later configuration changes
  do not reclassify historical events; legacy entries without that boolean use the
  current class fallback.
