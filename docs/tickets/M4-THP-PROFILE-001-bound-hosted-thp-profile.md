---
id: M4-THP-PROFILE-001
milestone: M4
status: active
depends_on: [M4-T01]
owns:
  - .github/workflows/m0.yml
  - tools/ferrum2-m4-qualification/src/m4_support/mod.rs
  - tests/m0-harness/tests/workspace_policy.rs
  - docs/specs/SPEC-0005-m4-performance-resource-preview-qualification.md
  - docs/test-plans/TEST-0005-m4-performance-resource-preview-qualification.md
  - docs/milestones/M4-performance-resource-preview-qualification.md
  - docs/tickets/M4-T02-qualify-preview-on-one-exact-commit.md
  - docs/tickets/M4-THP-PROFILE-001-bound-hosted-thp-profile.md
---

# M4-THP-PROFILE-001 — Bind the hosted THP profile

## Outcome

Amend the selected `M4-GHA-01` conformance profile so the bounded 10k-idle resource
qualification runs with
`/sys/kernel/mm/transparent_hugepage/khugepaged/max_ptes_none = 0`, restores the
runner's exact original value, and fails closed when apply, validation, or restoration
cannot be proved. Product behavior and every existing resource quantity, threshold,
and timing remain unchanged.

## Basis and scope

Hosted run `30710439015/1` on exact `a53a5d7` remains failed evidence: paired RSS data
is consistent with delayed THP backing, but does not prove the hosted allocator/kernel
causal path. The separately authorized local repair is based on
`d9aa96860f1388d32b84cc56307e165054557840`; its test-budget base is that exact SHA.
One writer owns only the paths above.

The local scope includes the contract, driver self-check, existing workspace-policy
test, workflow realization, reviews, Full and budget gates, and a complete native-ext4
WSL2 diagnostic. It excludes product crates/binaries, Cargo manifests or lockfile,
allocator/buffer/protocol/dependency changes, changed load/timing/threshold/drain
values, push, rerun, dispatch, PR, packaging, release, and publication.

## Acceptance

- [ ] Throughput completes before the exact THP knob is mutated; a strict decimal
      original is durably recorded before a non-interactive stdin write of `0`, and
      apply readback is exactly `0`.
- [ ] The main step arms `EXIT`/`TERM` restoration and the workflow has an independent
      `always()` backstop. Process reap, restore, restore readback, and evidence deletion
      are each attempted; cleanup failure remains explicit without replacing the primary
      failure. Exact original readback is required.
- [ ] Runner loss or `SIGKILL` invalidates the run because restoration cannot be proved;
      disposal of the temporary VM is fallback containment, not successful restoration.
- [ ] After hosted identity validation and before evidence, temp state, listeners,
      configuration, or children, the driver requires exact `0`; it checks again after
      exact drain and before PASS. `resource_profile` records `max_ptes_none=0`.
- [ ] Static redacted failures are exactly `THP max_ptes_none profile is unavailable`,
      `THP max_ptes_none profile is malformed`, and
      `THP max_ptes_none profile is not zero`, without emitting path or value. The
      profile assumes one dedicated runner and no other authorized privileged mutator;
      it does not claim to eliminate transient TOCTOU.
- [ ] Exact 10,000 sessions, setup concurrency 256, five-minute stabilization,
      `180 x 10`-second samples, six windows, 105%, active/fd/task invariants, two-minute
      drain, and the throughput profile remain unchanged. Absolute RSS is compared only
      between runs naming this selected profile.
- [ ] The existing public release `self-check` command records a distinct RED exit `1`
      then GREEN exit `0` for each canonical-zero, missing/unreadable, malformed, and
      nonzero vertical slice before the next slice; all remain together in driver commit
      2. The policy seam also accepts `511 -> 0 -> 511` while rejecting nonzero applied
      readback. No new harness, dependency, product surface, `VmSize` rule, delay, or
      relaxed gate is added.
- [ ] Focused, Full, test-budget, complete WSL2 diagnostic, Architect, and QA checks pass.

## Validation

```sh
cargo run --release -p ferrum2-m4-qualification --bin m4-qualification --locked -- self-check
cargo test -p ferrum2-m0-harness --test workspace_policy --locked
sh scripts/test-budget.sh ticket --base d9aa96860f1388d32b84cc56307e165054557840 --candidate <candidate-sha>
```

Run the serial Full and milestone-budget commands from
`docs/agents/milestone-workflow.md`, then the complete native-ext4 WSL2 resource
diagnostic. WSL2 remains diagnostic only; formal evidence still requires one later,
separately authorized workflow run for one exact commit.

## Commit topology

1. This Markdown contract.
2. Driver plus public `self-check` RED-to-GREEN evidence.
3. Existing `workspace_policy.rs` workflow-behavior test committed RED with its exact
   failure recorded.
4. One single-parent protected control commit containing the workflow and optional
   Markdown evidence only; the same policy test is GREEN.

## Result

- Commit: —
- Review: —
- Notes: Local repair authorized; no remote mutation authorized.
