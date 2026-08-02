---
id: M4-THP-PROFILE-001
milestone: M4
status: done
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
One writer owned only the paths above.

The local scope included the contract, driver self-check, existing workspace-policy
test, workflow realization, reviews, Full and budget gates, and a complete native-ext4
WSL2 diagnostic. It excludes product crates/binaries, Cargo manifests or lockfile,
allocator/buffer/protocol/dependency changes, changed load/timing/threshold/drain
values, push, rerun, dispatch, PR, packaging, release, and publication.

## Acceptance

- [x] Throughput completes before the exact THP knob is mutated; a strict decimal
      original is durably recorded before a non-interactive stdin write of `0`, and
      apply readback is exactly `0`.
- [x] The main step arms `EXIT`/`TERM` restoration and the workflow has an independent
      `always()` backstop. Process reap, restore, restore readback, and evidence deletion
      are each attempted; cleanup failure remains explicit without replacing the primary
      failure. Exact original readback is required.
- [x] Runner loss or `SIGKILL` invalidates the run because restoration cannot be proved;
      disposal of the temporary VM is fallback containment, not successful restoration.
- [x] After hosted identity validation and before evidence, temp state, listeners,
      configuration, or children, the driver requires exact `0`; it checks again after
      exact drain and before PASS. `resource_profile` records `max_ptes_none=0`.
- [x] Static redacted failures are exactly `THP max_ptes_none profile is unavailable`,
      `THP max_ptes_none profile is malformed`, and
      `THP max_ptes_none profile is not zero`, without emitting path or value. The
      profile assumes one dedicated runner and no other authorized privileged mutator;
      it does not claim to eliminate transient TOCTOU.
- [x] Exact 10,000 sessions, setup concurrency 256, five-minute stabilization,
      `180 x 10`-second samples, six windows, 105%, active/fd/task invariants, two-minute
      drain, and the throughput profile remain unchanged. Absolute RSS is compared only
      between runs naming this selected profile.
- [x] The existing public release `self-check` command records a distinct RED exit `1`
      then GREEN exit `0` for each canonical-zero, missing/unreadable, malformed, and
      nonzero vertical slice before the next slice; all remain together in driver commit
      2. The policy seam also accepts `511 -> 0 -> 511` while rejecting nonzero applied
      readback. No new harness, dependency, product surface, `VmSize` rule, delay, or
      relaxed gate is added.
- [x] Focused, Full, test-budget, complete WSL2 diagnostic, Architect, and QA checks pass.

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

- Commits: contract `4357bb62a65b360ea7bb13a1012d5a0f8c931424`; driver
  `3a77d7fa8074c11ec07875f188f8e72399e0d15e`; policy RED
  `aa7102bf48cb55728e73e24761d32d57a55659d2`; protected workflow GREEN and
  integrated candidate `230594544e88ab555e1718ba92721745705b572b`.
- TDD: the release `self-check` recorded four ordered RED exit-`1` slices for canonical
  zero, unavailable, malformed, and nonzero state, each followed by GREEN exit `0`; the
  final public result is `m4_self_check status=PASS mutations=20`. The workflow policy
  test first failed on the absent fixed-knob marker, then passed `1/1`; a bounded repair
  additionally failed on the absent static applied marker before closing the observed-
  value finding with static applied/restored evidence.
- Review: Product, Architect, and QA returned PASS on exact `2305945`; Architect findings
  `M4-THP-ARCH-001..003` remain closed and QA finding `M4QA-THP-001` is resolved.
- Local gates: the six serial Full commands passed, including the ignored 20-cycle gate
  (`1/1` in `126.59` seconds). Ticket and milestone budgets returned `PASS_ADVANCE` at
  code `14172`, tests `20866`, examples `132`, ratio `1.472340`, with ticket debt `69`.
- Native-ext4 WSL2: the first start rejected a child soft-nofile mismatch before resource
  state and restored `511`; the corrected wrapper then exited `0` after `2104.4` seconds
  with exact 10k, `180/180`, `6/6`, drain PASS, zero remaining processes, and exact
  restoration to `511`. All six client/server `VmRSS` and precise-RSS median-twice values
  were constant at `1909368/1967472` KiB; Anonymous was
  `1900992/1958544` KiB and `AnonHugePages` was zero. The 189-line generated JSONL was
  verified and deleted; WSL2 remains diagnostic only.
- Scope: the local repair scope is consumed. Explicit scope `M4-REMOTE-FINAL-A1`
  permits one next non-force GitHub push of the final closeout SHA and its automatic
  push run; it does not permit rerun, dispatch, PR, release, publication, or a second
  push.
