# Performance evidence ownership

Ferrum2 keeps measurement production, evidence validation, and adoption policy separate. A successful command is not by itself a performance claim.

## Product parent/candidate evidence

The canonical controller entry point is:

```text
python3 -B -m tools.performance_candidate <command> ...
```

Use `python` instead of `python3` on Windows.

`tools/performance_candidate/cli.py` is the composition root. Named shared modules own strict JSON,
identity, atomic output, and paired statistics. The `linux/` package owns Linux plans, trials,
calibration, scale lineage, and decisions. The `windows_tun/` package separates recipe, plan,
policy, trial, and summary contracts into their corresponding modules. `summary.py` validates
build, runtime, cleanup, paired-profile, and lifecycle evidence. Host execution and recovery belong
to the PowerShell owners below. Production code must not be loaded from `tests/`.

The Linux evidence chain is:

```text
workflow inputs -> controller plan -> m4 profile-workload producer
-> bounded JSONL trials -> controller summary -> reviewed policy decision
```

The Windows evidence chain selects one topology per run:

```text
ClientDirect: workload -> real Wintun -> ferrum2-client TUN/TCP/UDP stack
              -> client direct egress -> local support echo
EndToEnd:     workload -> real Wintun -> ferrum2-client -> ferrum2-server
              -> server direct egress -> local support echo
```

Both continue through the same closed evidence path:

```text
host PowerShell transaction -> closed profile plan -> independently built baseline/candidate
-> interleaved real-Wintun trials -> bounded raw evidence
-> host validation/paired summary -> reviewed decision
```

The Windows performance PowerShell implementation is owned by
`tools/powershell/Ferrum2.Performance`. Its only public composition root is
`tools/windows-tun/performance/run_windows_tun_performance_host.ps1`. The runner interface exposes
planning, recovery, one required `ClientDirect|EndToEnd` topology, and the `Quick`, `Confirm`, and
`Lifecycle` profiles; it hides adapter names, benchmark addresses, ports, process IDs, routes,
temporary files, ledgers, cleanup, and evidence construction.
`PerformanceProcessOwner.cs` places every spawned product and support process in one kill-on-close job
instead of embedding process-tree interop in the runner.

`tools/powershell/Ferrum2.Performance/bundle.json` is the canonical closed host-performance source
bundle. It binds every consumed runner, module, collector, scenario, and C# owner by canonical path,
byte length, and SHA-256. Its complete-file digest is the Windows performance runner identity and is
recorded from plan through raw evidence and summary. The bundle contains no qualification source.
Any source, file-map, schema, recipe, or paired-schedule change requires atomic producer/consumer
updates and a new baseline; stale calibration or evidence is not comparable.

`Quick` is the autoresearch feedback profile. Per selected topology it measures TCP single-flow
throughput, 1 KiB TCP request p99 latency, UDP packet rate, and fragment-reassembly throughput using
three interleaved baseline/candidate pairs, for 24 trials. `Confirm` adds 256-flow TCP fairness and
uses five longer-window pairs, for 50 trials per selected topology. Run the two topologies separately
when both attribution and complete client/server behavior are required; evidence never mixes them.

Every raw trial records the primary metric and direction, checked work, I/O completions, applicable
p99 latency, client CPU and peak working set, and failure counters. `EndToEnd` also records server CPU,
peak working set, and failure counters; those server fields are null in `ClientDirect`. Summaries
retain every pair and report direction-normalized improvement ratios, range, outliers, checked work,
I/O, latency, CPU, and memory. The non-target CPU guard normalizes CPU by checked work rather than by
the primary metric, so a lower-is-better latency result cannot invert CPU-cost accounting.

`Lifecycle` is separate: 20 complete product-start, TUN-probe, and product-stop cycles under the
selected topology. It never changes a default route or disables or enables a physical adapter.

Every real run requires an already elevated shell and the literal
`-AcknowledgeHostNetworkMutation` switch. The runner uses dedicated RFC 2544 addresses and only exact
benchmark routes. Both topologies must prove benchmark traffic enters the owned TUN and support
egress excludes it; `EndToEnd` additionally proves the client/server underlay excludes it. Each
mutation is recorded incrementally in a per-RunId recovery ledger. Success requires identity-safe
cleanup plus readback proving no owned adapter, route, process, or port remains.

The host runner's `summary.json` status `PASS` means execution and evidence construction completed.
Use the independent Python validator to check the complete evidence and derive the performance
decision; `PASS` alone does not mean the candidate improved. Host plan, raw trial, runtime, and
summary schemas are v2; build and cleanup schemas remain v1. The host source manifest uses its own
v1 manifest schema and kind `ferrum2.windows-tun-performance-source-bundle.v3`; this is independent
of the product's schema-v2 TOML configuration.

The controller's closed qualification statuses are `CANDIDATE_WIN`, `WITHIN_CALIBRATED_BAND`,
`REGRESSION`, `INCONCLUSIVE`, `CALIBRATION_REQUIRED`, and `INVALID`. Only the first two are accepted.
Invalid evidence exits 2, regression exits 3, and inconclusive or calibration-required results exit 4.
Windows paired scenario decisions use `candidate-win`, `within-noise-band`, and `regression`; the
validator reduces them to the uppercase controller status. A same-commit A/A result characterizes
measurement noise and cannot establish a code-change speedup.

### Windows host commands

Run these from the repository root using PowerShell 7.4 or later. Inspect an unprivileged,
nonmutating A/A plan first:

```powershell
$candidate = (git rev-parse HEAD).Trim()
$baseline = $candidate
pwsh -NoProfile -File tools/windows-tun/performance/run_windows_tun_performance_host.ps1 `
  -PlanOnly -Mode Quick -Topology ClientDirect `
  -BaselineSha $baseline -CandidateSha $candidate
```

For A/B, set `$baseline` to the full 40-character commit of a reviewed baseline with the same
workload, recipe, and evidence contract. For a real run, use an already elevated shell, the reviewed
Wintun archive described in the [host qualification prerequisites](windows-tun-qualification.md#safety-boundary),
and a new evidence directory outside the repository:

```powershell
$evidence = Join-Path $env:TEMP ("ferrum2-host-performance-" + [guid]::NewGuid().ToString("N"))
pwsh -NoProfile -File tools/windows-tun/performance/run_windows_tun_performance_host.ps1 `
  -Mode Quick -Topology ClientDirect `
  -BaselineSha $baseline -CandidateSha $candidate -EvidenceDirectory $evidence `
  -AcknowledgeHostNetworkMutation
```

Validate the exported evidence with the same mode, topology, and commits:

```powershell
python -B -m tools.performance_candidate windows-tun-validate-host-evidence `
  --evidence-root $evidence --baseline-sha $baseline --candidate-sha $candidate `
  --mode Quick --topology ClientDirect --policy tools/windows_tun_performance_policy.json
```

Use `Confirm` or `EndToEnd` consistently in both commands when selecting those profiles/topologies.
After interruption, use the same public runner with `-RecoveryOnly`; removing live network residue
requires elevation. The [2026-09-05 Confirm and CPU report](windows-tun-confirm-cpu-profile-report-2026-09-05.md)
records historical A/A runs and their interpretation limits, not current-checkout qualification.

Windows workload schema 4 and host trial schema 3 retain TCP/UDP p50, p95, and p99
nanoseconds plus `latency_samples` in `workload_measurements`. All three quantiles use
nearest rank over the same bounded, deterministic reservoir (maximum 2,000,000 samples).
The controller binds the sample count to successful checked transactions/datagrams and rejects
missing or unordered quantiles. Timing remains request-send through verified echo completion,
including receive recovery; connection setup and warmup are outside that interval. These closed-loop
observations do not establish open-load queueing SLOs. The p99 adoption policy is unchanged;
p50/p95 are retained observations. Historical schema 2 trial evidence must be read with its own
recorded controller revision. Current readers have no compatibility path.

## Rule qualification evidence

`ferrum2-rule-qualification` emits bounded runner reports. The only Rule controller entry point is `python -B -m tools.performance_rule`; schema, runner-report validation, pairing, policy, evidence, and CLI have separate package owners. Current v6 A/A output is always `CALIBRATION_REQUIRED` until a separately reviewed, source-hash-bound calibration v2 artifact is created. Ordinary tests use the small synthetic fixture under `tests/performance_rule/fixtures`; it proves schema and binding behavior but is never benchmark evidence. Historical v2/v3/v4 readers exist only in the explicit test-owned archive verifier.

Large `release-*.json` reports are ignored by Git. Their exact names, roles, byte lengths, and SHA-256 digests are tracked in `tests/performance_rule/fixtures/external-evidence-manifest-v1.json`. Verify explicitly materialized external evidence with:

```text
python3 -B -m tests.performance_rule.verify_external_evidence \
  --evidence-directory /path/to/materialized-rule-evidence
```

External artifact retrieval must use an immutable identity. Missing or changed raw evidence cannot be replaced by a summary, compact fixture, screenshot, or policy document.

## Ordinary and privileged boundaries

Ordinary CI may compile controllers, validate tracked fixtures, parse PowerShell, reconstruct closed
bundles, and run deterministic contract tests. It must not create a real adapter or claim Wintun,
WFP, or host-network evidence. `-PlanOnly` is unprivileged and nonmutating. Real Windows TUN
performance evidence may be created only by the dedicated host performance runner from an already
elevated shell with explicit acknowledgement; success requires exported raw evidence and verified
per-run cleanup. Correctness uses its separate bounded host runner, fixed check set, source identity,
and `qualification.json` verdict; neither public runner nor verdict is a fallback for the other.
