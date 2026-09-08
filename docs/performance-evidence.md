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
calibration, scale lineage, and decisions. `tun_mock.py` and `tun_mock_contract.py` own
TUN-only execution and closed evidence. `tools/owned_process.py` owns shared bounded
child lifetimes for mock measurement, CI provisioning, rule execution and CPU diagnostics.
Privileged correctness belongs exclusively to `Ferrum2.Qualification.Host`.
Production code must not be loaded from `tests/`.

The shared owner preserves a Unix leader with non-reaping exit observation until final
process-group termination and cleanup confirmation. Windows children remain suspended
until assigned to their kill-on-close Job, whose active-process count is checked at cleanup.
Output and deadlines are bounded; primary failures remain distinct from unconfirmed cleanup.
Linux groups are not a sandbox for descendants deliberately escaping their inherited session.
Controller source identities include the shared owner wherever those identities are recorded.

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

## TUN-only mock I/O performance

TUN performance measures Ferrum2's packet processing, not Windows TCP throughput or complete
proxy performance. It creates no OS sockets, Wintun adapter, route, DNS or WFP state:

```text
fixed packets and accepted-connection events -> bounded memory I/O adapter
-> production Stack / SystemTcp / UDP / reassembly / owner scheduler
-> bounded packet and datagram capture -> complete output validation
```

The private socket adapter uses a bounded in-memory stream for accepted-flow publication and
retirement. Production builds retain the real system socket implementation. The benchmark shares
owner-stage processing with the live owner, rather than copying its algorithms into a test loop.
OS accept/bind, reactor behavior, Windows TCP congestion/retransmission, driver costs, DNS, routing
policy, relay and proxy protocols are outside this measurement.

Build and inspect a single scenario without privileges:

```text
cargo build -p ferrum2-tun --example tun-benchmark --no-default-features --features benchmark --profile profiling --locked
```

```powershell
target/profiling/examples/tun-benchmark.exe --scenario tcp-rewrite --mode Quick
```

On Unix, omit `.exe`. The six closed scenarios are:

| Scenario | Measured TUN work |
|---|---|
| `tcp-rewrite` | Established IPv4/IPv6 tuple lookup, bidirectional rewrite and packet output |
| `tcp-churn` | Mapping admission, accepted-event association, flow publication, RST retirement and port quarantine |
| `udp-roundtrip` | Association receive, response admission, response construction and output |
| `fragment-reassembly` | Concurrent incomplete fragment ownership, completion and UDP response; Confirm mixes ordered and reverse arrival |
| `mixed-backpressure` | TCP/UDP competition through the actual scheduler with bounded output withheld and resumed |
| `state-reset` | Populated TCP/UDP/reassembly generation fence, retirement and rejection of stale response capabilities |

Quick uses 32 active states and 64-byte payloads. Confirm expands ordinary state populations to
128 and payloads to 512 bytes, includes ordinary TCP/UDP IPv6 traffic, and increases checked work.
These are fixed recipes, not user-selectable unchecked load sizes. Quick has three interleaved
baseline/candidate pairs per scenario (36 trials); Confirm has five (60 trials).

Each trial performs an untimed diagnostic pass, followed by 128 measured batches in Quick or
64 in Confirm. Every batch uses fresh bounded state and preallocated output capture; elapsed time
and checked work are summed across measured windows only. Full packet/payload comparison stays
outside each window, and every captured output must match the diagnostic. Setup, validation and
storage scans are not timed or subtracted. This fixed repetition replaces the initial single-batch
recipe after actual A/A runs exposed large noise in sub-millisecond windows. Failed checks or
capture exhaustion cannot produce a trial. Real monotonic clocks measure elapsed time; injected
logical expiry time is never substituted for it. Recipe v2 binds the repeated-batch counts.

Raw schema 1 records exact checked units, elapsed nanoseconds, unit, workload identity and
input/output/rejection accounting. `peak_packet_storage_bytes` is a diagnostic sampled peak of
retained packet buffers, charged UDP payloads, reassembly pieces, capture and fixtures. It excludes
metadata, allocator overhead, transient buffers between samples, mock socket buffers and process
RSS. It is not total memory consumption. Capture/adapter work remains part of the workload;
there is no subtraction of a guessed harness cost.

### Paired execution and calibration

The controller independently builds both members from exact Git commits in detached worktrees,
including A/A. It retains binaries, build logs and all raw trial files outside the repository.
Both members must have the same four-file benchmark recipe closure, workload identities and mode.
Source SHA, binary digests, controller digest and host/toolchain/environment identity are bound.
Every child is bounded and owned through a Windows kill-on-close job or Unix process group;
worktree or process cleanup failure prevents success.

First create same-commit A/A evidence for a commit containing the new benchmark:

```powershell
$baseline = (git rev-parse HEAD).Trim()
$calibration = Join-Path $env:TEMP ("ferrum2-tun-aa-" + [guid]::NewGuid().ToString("N"))
python -B -m tools.performance_candidate tun-mock-calibrate `
  --baseline-sha $baseline --mode Quick --evidence-root $calibration
python -B -m tools.performance_candidate tun-mock-validate `
  --baseline-sha $baseline --candidate-sha $baseline --mode Quick --evidence-root $calibration
```

`calibrated` characterizes observed noise; it is never a speedup or correctness verdict. Each
scenario's noise bound includes the largest absolute A/A pair change, not only its median.
Review the raw evidence and reported `manifest_sha256` before adopting that calibration.
Do not inherit the retired host runner's 2% or server CPU policy.

After making and committing a product change without changing the benchmark recipe, set
`$candidate` to that distinct commit and pin the reviewed calibration digest:

```powershell
$candidate = (git rev-parse HEAD).Trim()
$calibrationHash = (Get-FileHash (Join-Path $calibration "manifest.json") -Algorithm SHA256).Hash.ToLowerInvariant()
$evidence = Join-Path $env:TEMP ("ferrum2-tun-ab-" + [guid]::NewGuid().ToString("N"))
python -B -m tools.performance_candidate tun-mock-run `
  --baseline-sha $baseline --candidate-sha $candidate --mode Quick --evidence-root $evidence `
  --calibration-root $calibration --calibration-sha256 $calibrationHash
python -B -m tools.performance_candidate tun-mock-validate `
  --baseline-sha $baseline --candidate-sha $candidate --mode Quick --evidence-root $evidence `
  --calibration-root $calibration --calibration-sha256 $calibrationHash
```

Use `Confirm` consistently to select its independent recipe/calibration. A changed recipe,
controller, toolchain or environment requires new A/A evidence. A/B outcomes are `improved`,
`equivalent`, `regressed` or `inconclusive`; all pairs must exceed the noise bound to claim an
improvement, and any pair below the negative bound rejects a scenario. Summaries retain
scenario decisions rather than hiding a regression in an aggregate score.

The former privileged host A/B modes, topology selection and timed Lifecycle performance mode
are retired. Historical host reports require their historical controller and are not comparable
to this benchmark. A TUN-only improvement does not prove real driver or full client/server
performance improvement. Real socket and Wintun/WFP correctness are checked separately by the
[Windows qualification contract](windows-tun-qualification.md).

### Windows CPU profiling interpretation

Collect CPU traces separately from uninstrumented performance comparisons. Preserve the exact
sampled executables and matching PDBs, Windows public-symbol resolution, active-workload windows,
and lost-event/buffer counts. Prefer a bounded, single-scene steady-state trace to a mixed-scene
capture. Profiler overhead must not enter the performance verdict.

Kernel, driver, DPC and interrupt samples attributed to a product process are not automatically
product user-space or syscall costs. Unresolved kernel symbols support only module-level
attribution; symbol-prefix and leaf-sample summaries are not inclusive call-tree costs.
Keep raw traces, symbols and workload evidence private and outside tracked source.

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

## Open qualification and optimization questions

Removing historical reports does not close their unverified work. Earlier architecture changes
have not established overall performance non-regression; new acceptance requires current-source
identities, reviewed A/A calibration and uninstrumented paired A/B evidence under the same workload.

- RuleSet refresh batching and per-resource indexes remain unmeasured design options. Preserve
  complete-successor construction, per-resource atomic disk replacement and snapshot consistency.
- Incremental TLS sniffing, sparse/dense rule-candidate representations, cache sharding and a wider
  process worker budget require current profiles. Preserve parse bounds, metadata re-evaluation,
  budget isolation, fairness and tail latency rather than treating smaller allocations as throughput.
- Removing the SOCKS ready-stream mutex remains conditional on a real relay profile and a design
  preserving exactly-once replies and UDP control lifetime; synthetic ready-poll timings are not
  sufficient adoption evidence.
- Historical Windows host performance reports do not qualify the new TUN-only benchmark. Fresh
  A/A and distinct-source A/B evidence are required. CPU build/workload/window/loss/symbol
  qualification remains separate work; internal packet rates are not whole-product throughput.

## Ordinary and privileged boundaries

Ordinary CI may compile the TUN-only benchmark, validate evidence and fixtures, parse PowerShell,
reconstruct closed bundles, and run deterministic and real-loopback socket tests. It must not
create a real adapter or claim Wintun, WFP or host-network evidence. TUN mock performance needs
no elevation or network acknowledgement. Privileged correctness uses the sole bounded host
runner with explicit acknowledgement, a fixed check set, exact source identity, observed
data-path/reset witnesses, zero-residue cleanup and a final `qualification.json` verdict.
