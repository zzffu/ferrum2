---
id: M4-T02
milestone: M4
status: blocked
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

- Commit: `4cee0a1e18450eb0a95c3e16a0903a735969591c`
- Review: hosted qualification `FAIL`; no result was waived or spliced
- Notes: local Full `6/6` and the milestone budget passed before the authorized push.
  Single-use scope `M4-REMOTE-4cee0a1-A1` was consumed and auto-revoked before one
  non-force push to `refs/heads/codex/integration/m4`. GitHub Actions run
  [`30697247986`, attempt `1`](https://github.com/zzffu/ferrum2/actions/runs/30697247986)
  completed `failure`: quality, MSRV, interop, and all three native-platform rows
  succeeded; performance job `91362102185` failed after hosted preflight and the
  release build, and final qualification `91362498191` consequently failed. The
  performance log ended with `M4 qualification rejected: bounded identity probe
  failed`; cleanup succeeded, but no throughput or resource evidence was produced.

## Blocker

- `HOSTED-M4-T02-001`: the immutable run proves that one five-second bounded probe
  failed, but `probe_text` collapses timeout, nonzero exit, output truncation, and
  secret detection for every probe into the same redacted message. The log therefore
  cannot identify the failing command without speculation.
- Unblock by making probe identity/failure class observable without emitting captured
  output or secrets, validating the narrow repair locally, and obtaining a new exact,
  single-use authorization for one fresh push-triggered run. No rerun or second push
  is authorized.
