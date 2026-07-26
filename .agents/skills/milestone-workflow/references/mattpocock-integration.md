# Optional integration with mattpocock/skills

This workflow is self-contained. The Matt Pocock skill set is optional and is not
bundled here.

## Recommended installation

From the repository root:

```bash
npx skills@latest add mattpocock/skills
```

Choose Codex and install at least:

- `setup-matt-pocock-skills`
- `research`
- `prototype`
- `tdd`
- `domain-modeling`
- `codebase-design`
- `code-review`
- `diagnosing-bugs`
- `resolving-merge-conflicts`

Then, in Codex, run the setup skill explicitly:

```text
$setup-matt-pocock-skills
```

## Invocation boundary

The Matt repository distinguishes user-invoked orchestration skills from
model-invoked discipline skills. `milestone-workflow` is itself a user-invoked
orchestrator, so it should use only model-invoked skills internally.

Useful internal disciplines:

| Workflow stage | Optional model-invoked skill |
|---|---|
| upstream/API investigation | `research` |
| uncertain design experiment | `prototype` |
| domain vocabulary and invariants | `domain-modeling` |
| module/interface design | `codebase-design` |
| implementation | `tdd` |
| hard failure or regression | `diagnosing-bugs` |
| ticket/integration review | `code-review` |
| integration conflict | `resolving-merge-conflicts` |

User-invoked Matt skills such as `grill-with-docs`, `wayfinder`, `to-spec`,
`to-tickets`, `implement`, and `handoff` remain useful, but the user should call them
manually before or between milestone modes rather than nesting them automatically.

## Suggested hybrid flow

For a highly uncertain project:

```text
$wayfinder
$grill-with-docs
$milestone-workflow mode=bootstrap ...
$milestone-workflow mode=plan milestone=M0 ...
$milestone-workflow mode=execute milestone=M0 ...
$milestone-workflow mode=close milestone=M0
```

For a well-understood feature, start directly with `plan`.
