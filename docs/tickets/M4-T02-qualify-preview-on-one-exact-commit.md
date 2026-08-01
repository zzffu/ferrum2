---
id: M4-T02
milestone: M4
status: ready
depends_on: [M4-T01]
owns:
  - docs/ci-status.md
  - docs/tickets/M4-T02-qualify-preview-on-one-exact-commit.md
---

# M4-T02 — Qualify the preview on one exact commit

## Outcome

Use local gates only as pre-push diagnostics, then run the authoritative M4 driver and
all existing gates in one GitHub Actions run for one exact integrated commit. Record
the bounded summary needed for M4 close.

## Acceptance

- [ ] The hosted `performance` job passes `M4-GHA-01` preflight and reference SHA-256
      verification before measurement; no WSL2 result is accepted as qualification.
- [ ] Throughput records five trials per topology, both medians, ratio, and difference;
      the measured ratio is reported and never used as a pass threshold.
- [ ] The bounded 10k-idle run passes all 180 owner/task/RSS samples, six per-binary RSS
      window comparisons, and exact two-minute drain with both binaries alive.
- [ ] Local Full validation and milestone test-budget checks pass as diagnostic
      integration gates on the candidate SHA.
- [ ] After separate explicit authorization, one `push` run/attempt for that SHA passes
      performance, quality, MSRV, TCP/UDP `24/24`, all three native targets, and final
      qualification.
- [ ] P0/P1 blockers and blocking review findings are zero; runner-temp evidence is
      summarized then deleted, nothing raw is committed or uploaded, and no release or
      publication action occurs.

## Validation

Run the exact T02 commands in TEST-0005, followed by:

```sh
sh scripts/test-budget.sh milestone --candidate <accepted-integration-sha>
git status --short
```

## Result

- Commit: —
- Review: —
- Notes: M4-T01 is integrated at exact `7730ec7`. Local Full and milestone-budget
  diagnostics may proceed; all formal M4 evidence is remote, and push/run remains
  unauthorized until the user grants exact scope.
