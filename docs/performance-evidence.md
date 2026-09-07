# Performance evidence ownership

Ferrum2 keeps measurement production, evidence validation, and adoption policy separate. A successful command is not by itself a performance claim.

## DNS resource observations

`m4-qualification dns-resource` schema 2 keeps process fd/task ceilings, RSS windows and
post-load stability checks separate from final product termination/reap, harness worker joins
and listener rebind. Post-load samples are named `direct-post-load-stable` and
`detoured-post-load-stable`; three equal tuple intervals do not prove query resources were released.
`process_owner_delta` is the existing OS-count ceiling, not a query-owner allowance.

Each `dns_resource_phase_completion` records verified queries and `load_work` sent/verified/unfinished
counts. A sent request that times out or fails response validation remains an error even after stop
is requested. These counters describe the load client, not product DNS owners.

The final `dns_resource_summary` reports `status=OBSERVATION_COMPLETE`, with explicit successful
`process_bounds`, `post_load_stability`, `process_shutdown`, `harness_join` and `rebind` checks.
It always retains `query_drain={status:UNVERIFIED,reason:query-owner-observation-unavailable}` and
`production_recovery_qualified=false`. Exit 0 means the named observations and final cleanup
completed and were written; any workload, bound, stability, cleanup or output failure exits 1.
The corresponding CI success cannot serve as production query-recovery acceptance. Product-side
query/request-task/idle-pool observations belong to the later architecture work; neither synthetic
zeros nor observed residues establish an exemption.

The DNS profile and resource clients validate the complete fixed response: flags, ID, one IN/A
question, one matching localhost A answer, exact fixture TTL (profile 0, resource 30), and no extra
sections, EDNS or signature. Wire compression is permitted; trailing bytes and reserved flags are
rejected. Profile completion names its actual final process/worker cleanup rather than claiming
unobserved in-process DNS drain. Current readers do not retain the previous `drain=PASS` contract.

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

Full non-TUN aggregation requires the four canonical group directories, each containing
`performance-plan.json`, `calibrated-summary.json`, and the complete `ab-parent` / `ab-candidate`
JSONL trials. It rebuilds each plan and summary with the same controller, checks exact JSON
fields and scalar types, and requires the same full binary build and environment identities
across groups. Aggregate schema 2 binds the summary and plan file digests, the canonical raw
evidence manifest digest, and the common identities. Summary-only inputs are not accepted.

The `aggregate` command requires `--producer-result`; the workflow supplies
`${{ needs.paired-profile.result }}` from the completed matrix job. Failure, cancellation,
skipping, or an unknown result produces `INVALID` even if uploaded files claim success.
The workflow stages raw evidence before cleanup, generates a summary only after workload,
staging, and final cleanup succeed, and uploads retained evidence even on failure. An upload
failure also prevents a successful matrix job. This terminal result is trusted workflow input,
not a fact an arbitrary local artifact can prove.

The Linux controller source identity includes its imported `tools/ci` initializer and
`required_gate.py`. Changes invalidate previous source-bound plans and calibration; generate
fresh A/A and A/B evidence with the same updated controller and harness. A/A remains a separate
calibration input; the aggregate accepts only distinct parent/candidate A/B identities. Replay
validates the reported measurements and decisions, not physical execution order or profiler data.

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

Windows build-manifest schema 2 distinguishes product source from the executed workload.
Each member's `product_m4_source_bundle_sha256` records its independently verified complete M4
source bundle. These product-tree bundles may differ after API or self-check migrations. The
candidate's harness is not built or executed: both members use the identical baseline-built
harness path and SHA-256. `shared_harness_commit_sha` is the baseline commit, and
`shared_harness_source_bundle_sha256` must equal that baseline's verified M4 bundle. The validator
rejects mismatched shared paths, binary hashes, source identity or commit, malformed member
identities, and schema 1. This does not permit different executed workloads or skip either source
bundle's exact closure/content verification. Old evidence remains historical and must be read
with its original controller; there is no compatibility reader in the current schema.

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
I/O, latency, CPU, and memory. The non-target CPU guard uses process CPU seconds per checked unit:
`cpu_percent / 100 * cpu_sample_seconds / checked_units`. Each member uses its own measured window;
the paired ratio therefore remains comparable when those windows differ. Primary latency direction
does not change this CPU/work calculation. CPU percentages remain in summaries as observations.

The performance trial's zero-failure-delta guard retains failure/drop/error/reject family-name
matching and also checks the emitter's closed result labels: failed network reset/full rebuild,
failed RuleSet load/refresh, DNS resolution, strict-route filter installation and outbound interface
resolution, plus rejected/failed/stale-generation UDP association route work. Started/succeeded
lifecycle observations and association-reset cleanup counts are not failures. Known result families
with missing, duplicate or unknown labels are invalid evidence. Each sample is added at most once;
distinct families can describe the same root cause, so the sum is failure observations, not an
independent incident count or error rate. The existing `family_disabled` and `invalid_destination`
TUN packet-rejection exemptions remain unchanged.

`Lifecycle` is separate: 20 complete product-start, TUN-probe, and product-stop cycles under the
selected topology. It never changes a default route or disables or enables a physical adapter.

Every real run requires an already elevated shell and the literal
`-AcknowledgeHostNetworkMutation` switch. The runner uses dedicated RFC 2544 addresses and only exact
benchmark routes. Both topologies must prove benchmark traffic enters the owned TUN and support
egress excludes it; `EndToEnd` additionally proves the client/server underlay excludes it. Each
mutation is recorded incrementally in a per-RunId recovery ledger. Success requires identity-safe
cleanup plus independent readback proving no owned adapter, route, address, process, or port remains.
Recovery ledger schema 2 keeps historical expected identities after actionable records are retired.
It captures a bounded adapter GUID baseline before startup; an unfinished creation plan requires no
new GUID and no expected-name conflict at final readback. Created adapters remain tracked by GUID
and name. Failed enumeration or ambiguous identity rejects cleanup success and never authorizes
removal of unrelated resources.

The host runner's `summary.json` status `PASS` means execution and evidence construction completed.
Use the independent Python validator to check the complete evidence and derive the performance
decision; `PASS` alone does not mean the candidate improved. Host plan, runtime, and summary schemas
are v2; raw trials are v4, while build and cleanup schemas remain v1. The host source manifest uses its own
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

Windows workload schema 5 and host trial schema 4 retain TCP/UDP p50, p95, and p99
nanoseconds plus `latency_samples` in `workload_measurements`. All three quantiles use
nearest rank over the same bounded, deterministic reservoir (maximum 2,000,000 samples).
The controller binds the sample count to successful checked transactions/datagrams and rejects
missing or unordered quantiles. Timing remains request-send through verified echo completion,
including receive recovery; connection setup and warmup are outside that interval. These closed-loop
observations do not establish open-load queueing SLOs. The p99 adoption policy is unchanged;
p50/p95 are retained observations. Historical schema 2 trial evidence must be read with its own
recorded controller revision. Current readers have no compatibility path.

TCP single-flow, request, fairness, UDP packet and fragment scenarios stop admitting transactions or batches
at the configured active deadline. Already admitted work finishes with complete payload/ACK
validation; its latency and checked work remain included. The original minimum coverage is checked
afterward, and insufficient coverage fails instead of extending admission. Fairness waits for every
flow to finish warmup before the common active release. `active_elapsed_nanoseconds` covers the
common active start through the later of the admission deadline and last verified completion;
`tail_checked_units` counts work completed strictly after that deadline, in the same units as
`checked_units` (single-flow/fairness bytes, TCP request transactions, UDP/fragment unique datagrams). Fragment tails
retain the complete admitted batch and all existing retransmission accounting.

Both host and Python readers check integer counts, coverage, payload alignment, bounded final work,
and the elapsed/tail relationship. They recompute single-flow byte throughput, UDP packet rate, fragment byte rate and fairness
aggregate byte throughput from checked work and that elapsed interval. CPU sampling remains an
independent window including marker/coordination overhead; its duration is not replaced by workload
elapsed time. A shorter CPU duration is rejected as a necessary consistency condition, not proof of
aligned endpoints. The host reads CPU counters before releasing the ready marker and after observing
the completion marker, but trial fields do not retain corresponding interval endpoints. Client and
server counters are read sequentially while sharing a reported duration, so collection skew remains.
Summaries alone cannot reconstruct TCP quantiles or Jain fairness without original
latency samples or per-flow counts. Single-flow `cpu_payload_bytes` retains warmup plus active work
as a total only; warmup bytes never enter the active throughput numerator. New comparisons require
both members to use the same revised harness and bundles.

## Rule qualification evidence

`ferrum2-rule-qualification` emits bounded runner reports. The only Rule controller entry point is `python -B -m tools.performance_rule`; schema, runner-report validation, pairing, policy, evidence, and CLI have separate package owners. Current v6 A/A output is always `CALIBRATION_REQUIRED` until a separately reviewed, source-hash-bound calibration v2 artifact is created. Ordinary tests use the small synthetic fixture under `tests/performance_rule/fixtures`; it proves schema and binding behavior but is never benchmark evidence. Historical v2/v3/v4 readers exist only in the explicit test-owned archive verifier.

Large `release-*.json` reports are ignored by Git. Their exact names, roles, byte lengths, and SHA-256 digests are tracked in `tests/performance_rule/fixtures/external-evidence-manifest-v1.json`. Verify explicitly materialized external evidence with:

```text
python3 -B -m tests.performance_rule.verify_external_evidence \
  --evidence-directory /path/to/materialized-rule-evidence
```

External artifact retrieval must use an immutable identity. Missing or changed raw evidence cannot be replaced by a summary, compact fixture, screenshot, or policy document.

## Linux CPU diagnostic collection

`tools/profile-cpu.sh` remains the only attach entry point, with the existing `--scenario`
(`tcp-bulk` or `udp-small-high`), `--role`, `--pid`, `--duration`, `--frequency`, and `--output`
arguments. It requires Linux, Python 3, perf, and exact Samply 0.13.1 already installed. It never
starts a workload, changes profiler permissions, or signals the Ferrum/M4 target. Its private
Python owners run perf stat and Samply sequentially, for the requested duration each.

A successful diagnostic exits zero with **COLLECTED**, not PASS. The new `metadata.json`
schema 1 (`cpu_profile_diagnostic`) replaces the old unversioned `metadata.txt`; no old reader
or alias is retained. `perf-stat.txt`, `samply.json.gz`, `stage-status.txt`, and private helper
stdout/stderr are retained. Successful collection always states `evidence_validity=unverified`,
`analysis_qualified=false`, and `adoption_claim=false`, with explicit missing build, workload,
active-window, final-workload-result, counter-schema, and sample/loss/symbol-schema reasons.
Controller checkout identity is labelled separately from actual PID/start/executable-hash
observations. Helper invocation timestamps are not claimed as sample-window timestamps.

Each helper has an absolute command deadline and an owned process group. Both output pipes are
drained with at most 64 KiB retained each; excess output, cancellation, timeout, or unconfirmed
cleanup prevents successful collection. Preflight is bounded to 30 seconds, each identity/helper
query to 5 seconds, perf to duration plus 5 seconds, and Samply to duration plus 10 seconds.
The run's collection deadline is twice duration plus 60 seconds; forced cleanup has additional
bounded grace waits and cannot promise immediate termination of an uninterruptible OS call.
Groups that deliberately escape their inherited session are not supported profiler helpers.
Cleanup confirmation requires readable Linux process-group state. An unreadable `/proc` member
or unconfirmed exit fails closed; a restricted host is not assumed to expose the whole process
table. Primary timeout/interruption/output-limit status is retained separately from cleanup
confirmation, so a failed reap cannot erase the original trigger.

Container checks reject empty/unsupported perf output, malformed gzip/JSON, duplicate keys,
non-finite numbers, and byte-limit violations. Samply input is capped at 32 MiB compressed and
128 MiB decompressed before JSON parsing. These are parsing bounds, not sample-quality claims
or hard collector-file-size quotas. No reviewed sample/loss/symbol schema is inferred from an
arbitrary JSON object; valid containers remain unverified. Failed containers and helper logs
are kept in the new 0700 output directory with 0600 files for diagnosis; failed bundles report
`evidence_validity=invalid` and a closed error category.

M4 ready/build/window linkage and a reviewed collector schema must be implemented together
before analysis-qualified capture can be introduced. Until then these diagnostics cannot prove
workload overlap, loss-free sampling, symbol quality, or optimization acceptance. Offline tests
are under the existing `tests/ci/test_cpu_profile*.py` discovery gate; finite fake helpers and
synthetic containers do not count as real profiler evidence.

## Ordinary and privileged boundaries

Ordinary CI may compile controllers, validate tracked fixtures, parse PowerShell, reconstruct closed
bundles, and run deterministic contract tests. It must not create a real adapter or claim Wintun,
WFP, or host-network evidence. `-PlanOnly` is unprivileged and nonmutating. Real Windows TUN
performance evidence may be created only by the dedicated host performance runner from an already
elevated shell with explicit acknowledgement; success requires exported raw evidence and verified
per-run cleanup. Correctness uses its separate bounded host runner, fixed check set, source identity,
and `qualification.json` verdict; neither public runner nor verdict is a fallback for the other.
