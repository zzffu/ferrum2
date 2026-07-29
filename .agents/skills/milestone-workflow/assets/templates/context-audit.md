+++
milestone = "M0"
goal = "Replace with the requested feature outcome"
status = "draft"
baseline_commit = ""
verified_commit = ""
before_context_sha256 = ""
after_context_sha256 = ""
entries = [
  "Product purpose",
  "Primary languages/frameworks",
  "Architecture entry points",
  "Critical invariants",
  "Generated files",
  "Local development setup",
  "Active planned changes",
]
reviewers = []
+++

# Context audit: M0 — feature title

This document proves that every top-level entry under `## Project-specific context`
was compared with repository evidence before the feature plan was approved. It also
separates **current shipped facts** from **planned intent** so `AGENTS.md` never claims
an unimplemented feature already exists.

## Feature request

- Requested outcome: TODO
- User/operator value: TODO
- Scope hint: TODO or not supplied
- Proposed milestone: M0

## Repository baseline

- Exact baseline commit: TODO
- Current branch: TODO
- Relevant manifests/build files: TODO
- Relevant source entry points: TODO
- Relevant tests/CI/configuration: TODO

## Entry-by-entry audit

Use one row for every configured required entry and every additional top-level entry
found in the section. `Classification` is one of `confirmed`, `stale`,
`contradicted`, `missing`, or `planned-only`.

| Entry | Classification before update | Repository evidence | Required update | Result after update |
|---|---|---|---|---|
| Product purpose | TODO | TODO | TODO | TODO |
| Primary languages/frameworks | TODO | TODO | TODO | TODO |
| Architecture entry points | TODO | TODO | TODO | TODO |
| Critical invariants | TODO | TODO | TODO | TODO |
| Generated files | TODO | TODO | TODO | TODO |
| Local development setup | TODO | TODO | TODO | TODO |
| Active planned changes | TODO | TODO | TODO | TODO |

## Planned-feature placement

At planning time, describe the requested feature only under `Active planned changes`
with its milestone and `planned` status. Do not rewrite current capabilities as though
the feature has shipped. At milestone close, refresh this audit and move verified facts
into the appropriate current-state entries.

## Context update summary

- Stale claims removed or corrected: TODO
- Current facts added: TODO
- Planned-only statements added: TODO
- Statements deliberately unchanged: TODO

## Plan implications

- Product/roadmap implications: TODO
- Architecture/ownership implications: TODO
- Invariants/security/compatibility implications: TODO
- Generated-file/tooling implications: TODO
- Local development/validation implications: TODO

## Review verdicts

- Product Manager: TODO
- Architect: TODO
- QA: TODO
- Team Lead: TODO
