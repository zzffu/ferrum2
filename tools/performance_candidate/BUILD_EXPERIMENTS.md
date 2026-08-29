# Reproducible build experiments

All commands use the repository's sole performance-controller entry point:

```text
python -B -m tools.performance_candidate <command>
```

These commands create evidence inputs and execute explicitly selected build phases. They do not run
performance workloads, set adoption thresholds, enable a candidate in the product by default, or
claim that a candidate is faster.

## Environment capture

`build-environment` requires a clean worktree checked out at the supplied source SHA. Build
experiments compare artifacts from that one source; they never reuse commit parent/candidate
identity. The v2 environment records the source tree, `comparison_axis=build-artifact`, Rust/Cargo
and manifest identities, the runner image, CPU and
microcode, kernel, frequency governor, NUMA nodes, and a bounded process-name summary. Its stable
`environment_id` deliberately excludes the transient process snapshot, while `build_identity_id`
binds the source and toolchain.

```text
python -B -m tools.performance_candidate build-environment \
  --repository <worktree> \
  --source-sha <full-source-sha> \
  --environment-kind stable-bare-metal \
  --runner-image <reviewed-runner-image> \
  --output <environment.json>
```

Use `environment-kind=github-hosted` for a GitHub runner. Results carrying different environment IDs
must remain separate.

## Workload-set contract

Build and Phase 4 plans consume a bounded, closed JSON document:

```json
{
  "role": "validation",
  "scenarios": [
    {
      "argv": ["<reviewed-runner>", "--scenario", "tcp-request-independent"],
      "category": "tcp-request",
      "coverage": "representative",
      "name": "tcp-request-independent",
      "platforms": ["linux-x86_64"],
      "weight_basis_points": null,
      "working_directory": "."
    }
  ],
  "schema_version": "ferrum2-build-workload-set-v2"
}
```

Every scenario also names its reviewed `producer`. PGO training uses `role=training`,
`coverage=steady-state`, positive weights totalling 10,000 basis points, and the exact six-command
trusted registry: `tcp-request`, `tcp-bulk`, `udp-small`, `udp-mtu`, `dns`, and `rule`.
Its scenario names must be disjoint from validation. PGO validation must separately cover
`representative`, `cold-path`, `error-path`, and `different-cpu`.

PGO workload argv arrays name build artifacts with exact tokens such as
`{artifact:ferrum2-client}`. The generated plan resolves those tokens to the instrumented, baseline,
or profile-use artifact. Phase 4 workload argv arrays use exactly one `{artifact}` token.

## BUILD-001 through BUILD-004

`build-experiment-plan` always creates a `profiling` baseline and a separate candidate phase:

- `thin-lto-cgu1` uses the named `performance-thin-lto` profile.
- `target-cpu` accepts only the reviewed `znver3` class, a fixed deployment ID, and
  `--acknowledge-nonportable`; `native` is rejected and the generic baseline remains the fallback
  artifact.
- `pgo` emits generate, trusted external training, `llvm-profdata merge`, use, and independent
  validation commands. It requires the explicit `x86_64-unknown-linux-gnu` Cargo target so profile
  flags cannot instrument host build scripts or proc macros. Every training command receives a
  unique `LLVM_PROFILE_FILE`; its record
  binds before/after inventories and each nonempty `.profraw` path, size, digest, and producer.
  Merge accepts only the complete six-command record set, enumerates those exact files, hashes the
  exact `llvm-profdata` executable/version, and rejects stale or modified profiles. Validation runs
  with inherited profile variables removed. The hosted record explicitly leaves the different-CPU
  requirement unsatisfied.
- `panic-abort-strip` uses the named `performance-panic-abort-strip` profile and marks panic,
  backtrace, and crash-diagnostic review as mandatory.

Supply each expected binary file name with a separate `--artifact-name`. The manifest records exact
Cargo argv arrays, controlled environment changes, target directories, validation identity, and raw
evidence requirements.

Run one build or profile-merge phase explicitly:

```text
python -B -m tools.performance_candidate build-experiment-run \
  --plan <build-plan.json> \
  --phase <phase-name> \
  --log <build.log> \
  --output <build-record.json>
```

A successful record contains elapsed nanoseconds, a child-process peak-RSS upper bound when the host
exposes it, and the byte size and SHA-256 of every expected artifact. PGO records hash-bound
raw-profile or merged-profile inputs. A failed command is recorded as failed and never claims artifact
measurements.

## Evidence-gated Phase 4 matrix

`phase4-experiment-plan` only emits build and run commands after
`--acknowledge-prerequisites` and hash-bound `KIND=PATH` prerequisite evidence are supplied.

- `metrics` requires `counter-contention` and `perf-c2c` evidence, then compares an ordinary build
  with an explicitly named candidate Cargo feature. Collection includes counter contention,
  cache-line bounces, perf-c2c, CPU, throughput, latency, and counter correctness.
- `runtime` requires `locks-addressed`, `dns-codec-addressed`, and `waiter-herd-addressed` evidence.
  It emits default, explicit physical-core, and explicit lower-worker variants using the pinned
  Tokio `TOKIO_WORKER_THREADS` contract.
- `allocator` requires `known-allocations-addressed`, `allocation-hotspots`, and
  `allocator-cpu-lock` evidence. It compares the system allocator with an explicitly named candidate
  Cargo feature and records CPU, lock contention, RSS, fragmentation, long-run growth, and platform.

Every planned result seed binds the environment, build, workload-set digest, variant, and scenario.
The result identity contract additionally requires the actual artifact and raw-result hashes. Matrix
documents always carry `candidate_enabled_by_default=false`, no performance threshold, and no
adoption claim.

## Hosted AMD qualification boundary

`.github/workflows/performance-build.yml` is manual/reusable and accepts exactly one of
`thin-lto-cgu1`, `pgo`, or `target-cpu`. It builds all variants from one source into fresh target
directories, binds client/server/M4/rule artifact hashes, runs two independent six-pair A/A rounds
and one six-pair ABBA comparison, and retains build cost, binary size, rule diagnostics, raw trials,
and the build-specific calibration candidate. Its terminal decision is always
`NOT_ADOPTED_FOR_GITHUB_HOSTED_AMD_SCOPE`: hosted data has
`performance_authoritative=false`, `bare_metal_gate_satisfied=false`, and
`durable_evidence_gate_satisfied=false`. BUILD-01/02/03 need separate stable bare-metal review and
digest-recoverable immutable storage before a release-profile change.

Before each M4 workload, the selected isolated artifact directory is hash-preservingly materialized
at the runner's reviewed `<repository>/target/profiling` seam. M4 receives only repository-relative
`profiles/...` ready/output paths; the closed output is then moved into the isolated evidence root.

A reusable-workflow caller passes `experiment_kind` plus the exact `source_sha`, and pins `uses:`
to that same commit. The conditional reusable workflow likewise receives `candidate` plus the same
exact source SHA. Manual dispatch may omit `source_sha` and then uses the dispatched commit.

`.github/workflows/performance-conditional.yml` is likewise manual/reusable. It attempts real
`strace`, `perf stat`, `perf c2c`, and allocation-profile collection for UDP-14, OBS-01, BUILD-04,
and BUILD-05. Typed prerequisite records distinguish `DEFERRED`, `INCONCLUSIVE`,
`TRIGGER_PRESENT`, and `NO_TRIGGER`; every hosted result remains not adopted.

The `architecture-decisions` command closes ideas that must not be inferred from hosted results.
TCP-06 is `SUPERSEDED_BY_FAIRNESS_INVARIANT`: retain at most one successful read transition per
outer poll and its self-wake boundary; do not restore the measured continuous-RX regression.
Multi-hop ownership, Linux splice/socket-buffer/GRO-GSO, and Windows ETW lock evidence remain
deferred or external-lab-only, while busy-poll is not adopted.
