# Optional integration with mattpocock/skills

This workflow is self-contained. The Matt Pocock skill set is optional and is not
bundled here.

## Safe internal use

Useful model-invoked disciplines include `research`, `prototype`, `domain-modeling`,
`codebase-design`, `diagnosing-bugs`, and `resolving-merge-conflicts`.

`tdd` is optional and must follow `test-economy.md`: selective red-green-refactor at
one approved seam, not test maximization.

Do not implicitly invoke the generic `code-review` skill inside milestone execute.
This workflow's Architect and QA are the authoritative bounded review gates. The
installer patches an existing code-review `agents/openai.yaml` so it remains available
through explicit `$code-review` invocation only.

User-invoked Matt skills such as `grill-with-docs`, `wayfinder`, `to-spec`,
`to-tickets`, `implement`, and `handoff` may be run manually before or between
milestone modes; do not recursively nest them from this orchestrator.
