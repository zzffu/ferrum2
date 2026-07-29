# Feature planning and Project-specific context maintenance

Use this reference for `mode: feature` and for the context-refresh portion of
`mode: close`.

## Why feature mode is separate from bootstrap and plan

`bootstrap` establishes the initial control plane. It is not rerun for every product
change. `plan` assumes the milestone and repository context are already current.
`feature` is the safe bridge for a brand-new capability after previous milestones:

```text
current integrated repository
  -> allocate next milestone
  -> audit every Project-specific context entry
  -> correct stale repository facts
  -> record the requested capability as planned, not shipped
  -> update vision/gaps/roadmap
  -> create ADR/spec/test-plan/tickets
  -> stop before implementation
```

## Context entries are a complete set

Read the configured entries from `workflow.toml [context].required_entries` and the
actual top-level entries returned by `context-inventory`. The audit set is the union.
Never ignore an additional project-specific entry merely because it is not in the
default list.

For each entry, cite current repository evidence and assign one classification:

- `confirmed`: the claim is still supported without material correction;
- `stale`: it was once true or planned but no longer describes the repository;
- `contradicted`: current evidence directly conflicts with it;
- `missing`: the entry or an important current fact is absent;
- `planned-only`: intent that is not yet an integrated capability.

A context audit is incomplete when any entry lacks concrete evidence, a required
update decision, or a post-update result.

## Evidence expectations by entry

### Product purpose

Check binaries/packages, public APIs, configuration schemas, release artifacts,
README/user docs, and closed milestone evidence. Distinguish shipped capabilities,
explicit non-goals, and the new requested outcome.

### Primary languages/frameworks

Check manifests, lockfiles, toolchain files, dependency graph, runtime choices,
workspace lints, build scripts, and currently required tools. Do not retain a planned
framework after implementation selected something else.

### Architecture entry points

Trace actual composition roots, crates/modules/packages, public traits/interfaces,
state owners, and dependency direction. Remove phrases such as “not scaffolded” when
those paths now exist. Cite paths and symbols rather than copying a plan from an old
specification.

### Critical invariants

Check accepted ADRs, security boundaries, protocol/compatibility requirements,
resource limits, concurrency/lifecycle rules, persistence/migration guarantees, and
release promises. Keep only invariants that remain binding. A new feature may add a
planned invariant only under Active planned changes until its contract is approved.

### Generated files

Check ignore rules, build output, code generation, checked-in fixtures, schemas,
benchmark/coverage artifacts, and reproducibility requirements. Distinguish generated
source from reviewed test inputs.

### Local development setup

Check authoritative quick/full commands, toolchain/components, platform prerequisites,
external services, environment variables, task runners, and setup scripts. Commands
belong in `workflow.toml` or their authoritative build files; context explains how to
use them without duplicating unstable versions.

### Active planned changes

At feature planning, write one concise entry such as:

```text
- Active planned changes:
  - M5 — planned — Add authenticated multi-user key selection without changing the
    existing single-user wire behavior.
```

Do not place unimplemented behavior in Product purpose or Architecture entry points.
At close, remove the completed item and update the current-state entries from exact
integrated evidence. If another approved milestone is already active, replace the
entry with that milestone rather than writing `None`.

## Feature preflight

Run from a clean base worktree:

```bash
python .agents/skills/milestone-workflow/scripts/workflow.py feature-preflight \
  --goal "<requested outcome>" --write-audit --json
```

The command:

- inventories known milestones from roadmap, tickets, context audits, and local state;
- allocates the next numeric ID when no milestone is supplied;
- reports previous milestones that are not `closed`;
- inventories every context entry and computes a stable section hash;
- creates a draft audit skeleton when the base is clean and no configured blocker
  applies.

Do not use `--allow-open-milestones` merely to skip closeout. It is for an explicitly
approved parallel roadmap where dependencies and ownership are demonstrably disjoint.
Do not use `--reuse-existing` for a closed milestone.

## Subagent partition

All three read-only investigations use the same baseline commit and context hash:

- Product Manager owns current product purpose, user value, scope/non-goals, roadmap,
  and planned-change wording.
- Architect owns actual execution paths, boundaries, frameworks, invariants, generated
  artifacts, compatibility, migration, and ADR necessity.
- QA independently verifies claims against manifests, commands, tests, CI, platform
  setup, generated artifacts, and test-budget evidence.

Each report must explicitly cover every inventory entry. The Team Lead reconciles
conflicts and is the only writer of AGENTS.md and planning documents.

## Approval gate

After updating AGENTS.md and completing the audit:

1. set audit `status = "approved"`;
2. keep the exact baseline commit and before hash;
3. set `after_context_sha256` to the current inventory hash;
4. list `product_manager`, `architect`, and `qa` in `reviewers`;
5. remove all TODO placeholders;
6. run:

```bash
python .agents/skills/milestone-workflow/scripts/workflow.py context-check \
  --strict --milestone <ID> --require-audit
```

No ticket becomes `ready` until this passes when `context.require_feature_audit = true`.

## Plan economy

The feature context audit is not a second specification. It records repository truth
and planning implications. Put detailed behavior in the feature spec, tests in the
test plan, and hard-to-reverse decisions in an ADR only when needed. Avoid restating
every existing invariant in each document.

## Close refresh

At the exact integrated commit:

1. rerun `context-inventory`;
2. use Product Manager, Architect, and QA closeout evidence to revisit every audit row;
3. update current-state context entries with only verified facts;
4. remove or advance the Active planned changes item;
5. set audit `status = "verified"` and `verified_commit` to the exact integrated SHA;
6. update `after_context_sha256` after the final AGENTS.md edit;
7. rerun strict context check before closeout commit.

A context refresh is not an invitation to redesign completed work. Advisory future
improvements go to roadmap/review debt, not into the closed feature's blocking contract.
