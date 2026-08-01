---
id: PRE-M4-T02
milestone: pre-M4
status: done
depends_on: [PRE-M4-T01]
owns:
  - scripts/test-budget.sh
  - docs/agents/milestone-workflow.md
  - docs/tickets/PRE-M4-T02-test-budget-ci-range-repair.md
  - AGENTS.md
  - CONTEXT.md
  - docs/gap-analysis.md
  - docs/roadmap.md
  - docs/specs/SPEC-0002-m1-complete-tcp-methods-and-interop.md
  - docs/specs/SPEC-0003-m2-sip022-udp-protocol-and-direct-server.md
  - docs/specs/SPEC-0004-m3-operational-lifecycle-platform-contract.md
  - docs/test-plans/TEST-0004-m3-operational-lifecycle-platform-contract.md
  - docs/vision.md
---

# PRE-M4-T02 — Repair test-budget CI range handling

## Outcome

Make the test-budget gate validate a complete push range without mistaking its final
SHA for an intermediate baseline-adoption commit. Keep control-plane edits isolated
from Rust changes, preserve the existing budget and exact-SHA gates, and include the
user-authorized M4 preview/resource-boundary documentation while M4 remains proposed.

## Acceptance

- [x] Initial baseline adoption may occur inside a multi-commit push; its exact source
  and non-Rust migration prefix are validated before the final candidate is measured.
- [x] Every later control-plane edit in the range is a single-parent commit containing
  only protected control paths and Markdown; a mixed Rust/control commit fails closed.
- [x] The historical `deddc806...f7def719` range and this ticket's exact candidate pass
  the test-budget gate without weakening its ratio, allowance, ratchet, or baseline
  verification.
- [x] Existing documentation consistently describes a non-performance-certified v0
  preview and one bounded 10k-idle resource qualification; M4 stays proposed and no
  Accepted ADR or product behavior changes.
- [x] No dependency, production code, environment-variable override, or new harness is
  added.
- [x] Focused and repository validation pass.

## Validation

```sh
sh -n scripts/test-budget.sh
RUSTLOC=rustloc sh scripts/test-budget.sh ci --base deddc8065253a461911e07db70a9d4a16ecbec5a --candidate f7def719a9f6ed59e8c38a1b0f1bc1d292e3aee3
sh scripts/test-budget.sh ticket --base f7def719a9f6ed59e8c38a1b0f1bc1d292e3aee3 --candidate <candidate-sha>
sh scripts/test-budget.sh milestone --candidate <candidate-sha>
cargo fmt --all -- --check
cargo test --workspace --locked
```

## Result

- Commit: this ticket's single commit; exact SHA is reported after commit creation.
- Review: `PRE-M4-T02-REVIEW-001` bounded review PASS; the mixed Rust/control mutation
  was rejected with `control_plane_changed`.
- Notes: Historical adoption/control ranges and staged budget returned `PASS_HOLD`;
  focused, quick, and authoritative full validation passed. No push, rerun,
  publication, production-code change, or M4 activation.
