# Reproducible build experiments

All commands use the repository's sole performance-controller entry point:

```text
python -B -m tools.performance_candidate <command>
```

These commands create evidence inputs and execute explicitly selected build phases. They do not run
performance workloads, set adoption thresholds, enable a candidate in the product by default, or
claim that a candidate is faster.

## Environment capture

`build-environment` requires a clean candidate worktree checked out at the supplied candidate SHA.
It records both commit tree identities, Rust/Cargo and manifest identities, the runner image, CPU and
microcode, kernel, frequency governor, NUMA nodes, and a bounded process-name summary. Its stable
`environment_id` deliberately excludes the transient process snapshot, while `build_identity_id`
binds the source and toolchain.

```text
python -B -m tools.performance_candidate build-environment \
  --repository <worktree> \
  --parent-sha <full-parent-sha> \
  --candidate-sha <full-candidate-sha> \
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
  "schema_version": "ferrum2-build-workload-set-v1"
}
```

PGO training uses `role=training`, `coverage=steady-state`, positive weights totalling 10,000 basis
points, and all six categories: `tcp-request`, `tcp-bulk`, `udp-small`, `udp-mtu`, `dns`, and `rule`.
Its scenario names must be disjoint from validation. PGO validation must separately cover
`representative`, `cold-path`, `error-path`, and `different-cpu`.

PGO workload argv arrays name build artifacts with exact tokens such as
`{artifact:ferrum2-client}`. The generated plan resolves those tokens to the instrumented, baseline,
or profile-use artifact. Phase 4 workload argv arrays use exactly one `{artifact}` token.

## BUILD-001 through BUILD-004

`build-experiment-plan` always creates a `profiling` baseline and a separate candidate phase:

- `thin-lto-cgu1` uses the named `performance-thin-lto` profile.
- `target-cpu` requires a named CPU, a fixed deployment ID, and
  `--acknowledge-nonportable`; `native` is rejected.
- `pgo` emits generate, external training, `llvm-profdata merge`, use, and independent external
  validation commands. The tool hashes the exact `llvm-profdata` executable and rejects stale raw
  profile directories.
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

A successful record contains elapsed nanoseconds plus the byte size and SHA-256 of every expected
artifact. PGO records hash-bound raw-profile or merged-profile inputs. A failed command is recorded as
failed and never claims artifact measurements.

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
