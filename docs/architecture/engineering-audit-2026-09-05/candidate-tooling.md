# Performance candidate tooling — static engineering audit

Candidate snapshot: `2fb0dd4a`. Scope: every Python production owner in `tools/performance_candidate`; **28/28 files completely read**. See `candidate-tooling-coverage.json` for per-file contracts. No product/controller edits, imports, tests, malformed inputs, benchmarks, profiling capture, network workloads or privileged actions were executed in this follow-up. Small Python scripts only saved audit reports and coverage.

Read applicable root, tools, and performance_candidate AGENTS.md. No more-specific scoped guide was present. Also read docs/performance-evidence.md, the previously read architecture invariant/remediation context, selected workflow producer-build/call boundaries, and selected HostExecution/HostProfiles CPU derivation statements. These supporting PowerShell/workflow selections are not a claim of whole-file audit; their owners are reviewed separately by the team.

## Overall assessment for subsequent stages

The package provides substantial reusable evidence validation, bounded recipes, deterministic paired order and explicit qualification status. It does **not yet justify a general statement that the planned architecture change has no performance regression**. The confirmed static issues CT-01/02 below affect evidence interpretation and final acceptance. Current metric coverage also has explicit limits: ordinary Linux trials carry no CPU-time or RSS measurements, while Windows memory and most secondary metrics are retained but do not gate decisions. Existing thresholds must remain reviewed and unchanged until their own formal policy work; this audit proposes no new thresholds or optimization.

The package is a controller/reducer, not a CPU sampling profiler. Its `profiling` Cargo profile identifies symbol-enabled product builds; that name is not evidence that CPU stacks were collected. It can validate separately measured Quick/Confirm workloads and help preserve identity, but no current Python command captures or validates ETL/perf stack samples, symbol resolution or lost-event counts. Historical documentation explicitly separates profiler-affected runs from uninstrumented Confirm evidence. Therefore stage three's short CPU attribution requires the dedicated profiler evidence chain outside this package and must not be counted as stage-two throughput/latency qualification.

## Findings

### CT-01 / P1 — Windows CPU-per-work guard omits the measured CPU window

Locations: `windows_tun/summary.py:130` `_cpu_cost_ratio`, paired call sites around lines 406–430; `windows_tun/trial.py:217` CPU window acceptance. Producer confirmation: `tools/powershell/Ferrum2.Performance/HostExecution.ps1` computes CPU percent from process CPU milliseconds divided by `cpu_sample_seconds`; `HostProfiles.ps1` repeats the same percent/work formula as Python.

Contract: the scoped guide explicitly says non-target guard compares client/server **CPU per unit of reported work**. Confirmed static arithmetic: reducer uses `(candidate_cpu_percent / baseline_cpu_percent) / (candidate_checked_units / baseline_checked_units)`. It omits `candidate_cpu_sample_seconds / baseline_cpu_sample_seconds`, which is required to recover CPU time per work from those percentages. Trial validation permits each window to vary independently from active seconds through active+60 seconds; equal windows are not required. Host producer actually uses a stopwatch surrounding marker waits, so windows are measured rather than identical constants.

Trigger/impact: different measured windows for a pair can suppress or inflate the CPU regression ratio even when all evidence is accepted. This is a dimensional calculation defect confirmed from both producer and consumer source, not a benchmark observation. No fabricated input or dynamic comparison was run.

Required validation before trusting this guard: reconcile process CPU time, measured window and checked work at the producer/consumer contract; prove equal-cost work is invariant to unequal allowed windows and increased CPU time per work is detected in both ClientDirect/EndToEnd and lower-is-better latency scenarios. Producer, reducer, source bundle and evidence schema identities must change together if implementation is later altered.

### CT-02 / P1 — full-non-TUN aggregation does not validate the canonical scenario/decision closure

Location: `linux/aggregate.py::_validate_summary` and `aggregate_summaries` (approximately lines 39–194).

Confirmed static facts: the aggregator requires exactly four group summary files and several top-level identity/status fields. It only checks that scenario names equal the summary's own `mandatory_scenarios` list. It does not compare either list with the canonical scenario set for that selection, does not enforce the full current summary/nested schemas, does not reconcile per-scenario statuses with the claimed top-level status, and does not require the groups to carry the same full build identities. It does not reconstruct summaries from raw paired evidence. Missing nested keys can later raise KeyError outside the CandidateControlError branch.

Trigger/impact: incomplete or internally inconsistent group summaries can satisfy the self-consistency checks and contribute an accepted full-matrix status; missing nested fields can prevent INVALID output from being written. This is an integrity/robustness weakness at a claimed validation boundary, not proof that the canonical workflow currently emits such files. No abnormal summary was created or executed.

Required validation: complete canonical group/scenario closure, exact schema/types, nested-to-top-level decision consistency, common product/build identity, and bounded invalid-output behavior. Preserve each group summary digest and link/recompute its raw evidence as appropriate to the controller's trust boundary. Root should treat current aggregation as trusting upstream-generated summaries, not independently proving full matrix correctness.

### CT-03 / P2 — Linux trial byte bounds are checked after an unbounded read

Location: `linux/trial.py:62–103`, especially `raw = path.read_bytes()` at line 64.

Contract: evidence parsing must be fail-closed and bounded. Confirmed fact: an entire JSONL file is allocated before checking the 512 KiB outer limit and subsequent 16 KiB ordinary limit. This bypasses the package's existing stat-plus-limited-read helper. A large corrupt file can consume arbitrary memory before rejection. There is also an unbounded glob list before evidence-count closure in decision.py, though the per-file read is the direct issue.

Required validation: enforce a read cap before allocation, retain strict one-row/UTF-8/closed JSON semantics, then apply scenario-specific cap. Verify byte cap boundaries and invalid-output preservation without turning the ordinary validator into a memory stress workload. No large file was generated or read during this review.

### CT-04 / P2 — reported Linux evidence digest may refer to different bytes than the validated trial

Location: `linux/decision.py:257`, after `_read_trial` and `_validate_trial`.

Confirmed fact: the file is parsed once, then independently reopened with `path.read_bytes()` for the reported SHA-256. If a writer modifies the file between those reads, the summary's recorded digest can describe bytes different from the data used for its decision. The second read is also uncapped. Windows/shared bounded JSON readers already couple parsed value with a digest of the same read buffer, illustrating the intended evidence identity boundary.

Impact is conditional on concurrent modification; immutable exported artifacts avoid the trigger. No concurrent writer was run. Required validation: bind parsed value and digest from one bounded read, and preserve immutable artifact lifecycle. Do not present a digest as proof of the evaluated bytes until that boundary is repaired.

### CT-05 / P2 — same-commit Windows A/A can receive a CANDIDATE_WIN machine result

Location: `windows_tun/plan.py::validate_windows_tun_plan` permits equal baseline/candidate (valid for A/A); `windows_tun/summary.py::validate_windows_tun_host_evidence` reduces positive scenarios to CANDIDATE_WIN without distinguishing equal commits.

Confirmed fact: same-commit runs are intentionally permitted for noise characterization, but final classification has no same-commit guard. A positive noisy pair set can be emitted with the same win vocabulary as A/B. Repository documentation explicitly states A/A cannot establish a code-change speedup. Linux A/A calibration is private to the calibration path and validates identical binary identities; its ordinary summary entry point rejects equal commits.

Impact: automated or human consumers may mistake a calibration/noise result for candidate adoption evidence. No A/A input was constructed in this review. Required validation: preserve the ability to characterize A/A while making comparison purpose/adoption eligibility explicit in machine evidence; ensure A/A cannot support an adoption claim. This does not authorize relaxing the current 2% policy.

### CT-06 / P3 — atomic-output failure can leave an untracked temporary file

Location: `output.py::_atomic_text`, lines 15–29.

Confirmed fact: `temporary_name` is assigned only after write/flush/fsync finish. NamedTemporaryFile uses `delete=False`; if any preceding operation fails after file creation, the finally block still sees None and cannot unlink that file. Existing final destination remains protected by atomic replace, but the temporary artifact leaks. No I/O fault injection was performed.

Required validation: track temporary ownership immediately after creation and preserve cleanup on write/flush/fsync/replace failures. Scope is controller output recoverability, not product throughput.

### CT-07 / P2 — parts of the Windows closed numeric schema accept booleans or equivalent numeric types

Locations: `windows_tun/summary.py::_validate_cleanup`, build schema checks and `_validate_lifecycle_summary`; plan/trial fields compared to expected integers without consistently checking `type(value) is int`.

Confirmed Python semantics: False == 0 and True == 1. Several cleanup residual and schema-1 checks use equality alone, unlike `_required_u64` and `_positive_int` elsewhere. Exact field names therefore do not imply exact scalar types. Lifecycle checks and summary pair counts have similar inconsistent numeric validation.

Impact: wrongly typed evidence can pass a supposedly closed contract. This is a schema robustness issue; no claim is made that producer output currently contains these values. No malformed input was constructed. Required validation: uniform scalar checks for versions/counts/zero residue and separate boolean checks, applied across producer/consumer tests.

## Accepted contracts and important limits

- Shared JSON: bounded stat/read, strict UTF-8, duplicate keys rejected, non-finite numbers rejected, integer envelope and exact-field helpers. Most plan/policy/Windows documents use this owner. Trial exception is CT-03.
- Linux plans are rebuilt canonically on load. Scenario payload, wire overhead, topology, metric/unit, warmup/active recipe, six-pair AB/BA schedule and mandatory guards are fixed. Windows has a separate host-only plan with exactly 24 Quick or 50 Confirm trials per topology, or 20 Lifecycle cycles. No guest/qualification fallback exists here.
- Linux raw summaries validate exact per-scenario/pair/member closure, alternate order, stable build identity per member, matching runtime environment, source and semantic bundle hashes, PASS correctness and zero cleanup. Declared order is checked; physical execution order is producer/workflow evidence, not independently inferred by Python.
- Linux A/A calibration validates identical full build identities and derives source/recipe/environment-bound thresholds with six pairs; applicability checks include observed host identity before acceptance. Noise includes worst absolute pair and median+3MAD, so extreme noise is retained rather than discarded. There is no maximum acceptable A/A noise envelope: a broad resulting band is a measurement limitation, not evidence that a small regression was ruled out.
- Linux stability warnings deliberately never affect status, per catalog warning policy. WITHIN_CALIBRATED_BAND includes BETWEEN_THRESHOLDS, and guards only need stay above regression threshold. These are documented implementation semantics and should not be restated as mathematical equivalence or zero regression.
- The fixed 10k scale path has stronger per-flow evidence: exact source counterfactual lineage, 10k/1k flow vectors, checked-byte/completion arithmetic, exact elapsed denominator, recomputed Jain/quantiles, per-phase resources, drain/rebind and paired memory-growth limits. It intentionally cannot make an adoption claim. Its lineage requires a specific 16 KiB/32 KiB counterfactual; it is not a generic arbitrary-architecture comparison gate.
- Windows validates RunId-bound narrow route proofs and loopback exclusion, paired primary metrics, measurement/check field closure, sample count and ordered latency percentiles, null server fields for ClientDirect, zero failure counters and final cleanup. Build documents carry hashes but trial rows have no per-executable hashes; independently proving which executable ran depends on host execution ownership, not this reducer alone.
- Windows plan validation hashes the current bundle manifest bytes. It does not itself reconstruct the manifest's listed source files. Root must retain the separate source reconstruction/build checks before trusting a fresh baseline. Source/recipe/controller changes invalidate past compatibility; no backward-compatible reader exists.
- Memory medians, UDP p99, fairness aggregate throughput and I/O counts are validated as observations, but only the selected primary metric plus CPU guard determine Windows paired scenario verdict. A better fairness score with lower aggregate throughput, for example, is not automatically rejected by this package. Ordinary Linux trial schema has no CPU/RSS fields at all. This is a coverage gap for a broad stage-two acceptance claim, not authority to invent thresholds now.
- Neither Linux nor Windows summaries can establish open-loop overload tail latency, long-lived memory slopes, RuleSet load/refresh bounds, or system-DNS cancellation costs from their current fixed workloads. They also do not prove a profile trace's workload duration, lost events, symbols, sampled PID or CPU-stack attribution. Keep these uncovered properties explicit in the final architecture/qualification assessment.
- `identity.py` uses synchronous git subprocesses without timeouts and reads complete blobs/binaries for hashing. This is a local tooling execution-bound limitation; no subprocess was intentionally stalled. Full source hashing with lru_cache assumes checkout immutability during one controller process.
- Documentation's statement that raw host trial schemas are v2 conflicts with later text and current trial validator schema 3; later detailed description gives the current schema. Public guide consistency needs a small documentation correction in a later authorized implementation batch.

## Evidence and next-stage readiness

All conclusions above are static source analysis. **No tests, benchmark runs, calibration commands, imports or profiling capture were run in this follow-up**, and no new performance verdict was produced. Existing package tests from the separate runtime/DNS audit are unrelated to this Python audit.

Before stage two can use this tooling to support its scoped no-regression claim, the team needs to resolve the identified interpretation/validation defects and explicitly account for the missing metric properties. That is an audit gate, not an implementation design. Stage three can reuse identity and workload records but must preserve independent CPU trace provenance and profiler observer-effect separation. No optimization or new profiler design was attempted here.

## Supporting workflows — bounded static cross-check

Completed a full read of `.github/workflows/performance-candidate.yml` and the entire `performance` job in `.github/workflows/m0.yml` (lines 648–827). No scoped `.github/AGENTS.md` was present. Also read `m4_support/profile_output.rs` completely and selected `profile_contract.rs` argument/ready-marker ownership blocks to check the actual caller seam. Root owns the remainder of m0 and the full Rust producer audit. Nothing described in these YAML scripts was executed during this review.

### CW-01 / P2 — uploaded/aggregated acceptance evidence precedes workflow cleanup outcome

Location: `.github/workflows/performance-candidate.yml:405–459` staging/upload then cleanup, and `aggregate-full-non-tun` job.

Confirmed static facts: calibrated summary and raw evidence are staged/uploaded before the final `Reap processes and remove product worktrees` step. That later step may fail its residue/process/worktree checks. Aggregation uses `always()` and does not include `needs.paired-profile.result` or any exported workflow-cleanup result in its acceptance decision. Consequently an aggregate artifact can still contain an accepted status while its producing group job failed after upload during cleanup. The workflow as a whole still has a failed job; this is not a claim that GitHub reports all jobs successful.

The Rust producer separately checks owner zero before writing a successful trial, which is a meaningful existing safeguard. However, producer-owned cleanup evidence and final runner/worktree cleanup are different boundaries. Current accepted aggregate evidence does not cover the latter. Required later validation: final evidence/aggregate must distinguish successful measurements from complete workflow cleanup; preserve failure logs and job outcome identity rather than allowing standalone summary consumers to infer full cleanup. No workflow or cleanup failure was induced here.

### Workflow-to-controller contracts that are correctly bound

- Manual Linux candidate workflow checks exact full product SHAs, clean checkout and controller SHA, Linux/X64 host, strict ancestor relation for ordinary A/B, and explicit H/P16/C32 lineage for the special scale case. Action revisions are pinned, repository permissions read-only and checkout credentials not persisted.
- Parent/candidate use separate detached worktrees and each builds its own product binaries with locked dependencies. One shared M4 workload binary is built from the exact controller checkout, then its `self-check` is invoked before trials. This resolves the earlier audit's open question about whether the canonical workflow intends different measurement binaries per member: it intentionally supplies the same `$PROFILE_RUNNER` path to all runs. Raw rows also record its hash.
- The profile-workload command passes both absolute `--repository-root` and `--binary-dir`; profile_contract validates these together and restricts binaries to that repository's target/profiling or target/debug directory. Workflow selects target/profiling. All source/semantic contract flags emitted by `linux-trial-contract` are passed to the producer; flag spellings match the inspected Rust parser.
- `--build-profile current` is the evidence label, distinct from Cargo's build profile. Cargo `[profile.profiling]` inherits release, retains debug information and does not strip symbols. The workflow builds those binaries but does not invoke perf, WPR, xperf, or any CPU stack sampling collector. It must not be described as having performed CPU profiling.
- `ReadyFile::publish` writes scenario, client PID, optional server PID, warmup and active lifetime; it publishes without replacing an existing marker and owns marker removal. The workflow names each marker uniquely by scenario/member/pair under separate AA-left/AA-right/AB evidence directories. It does not read the PID marker or attach a profiler; the marker remains a producer-owned readiness seam, not CPU evidence.
- Six-pair ordinary AB/BA ordering and interleaved same-binary AA/AB execution come from the already-reviewed controller schedule. Calibrated qualification is restricted in workflow to 3s warmup/30s active/6 pairs and excludes scale. Calibration is derived from all six A/A pairs, then the plan is regenerated with its run-scoped policy before summary. No selective retry or outlier deletion is present.
- Failure rows produced by profile_output are exported with whatever completed JSONL evidence remains. Summarization runs even after a normal failed step (except cancellation); incomplete evidence fails closed. Product/worker owner checks precede successful raw trial output. The workflow does not synthesize missing success rows.
- Process-substitution commands used by `mapfile`/`while` are not themselves propagated by Bash errexit. A schedule failure can end iteration early, but the later exact trial closure/calibration checks prevent qualifying an incomplete set. This is a diagnostics/early-failure visibility limitation, not a demonstrated false accepted result.
- Candidate job has a 180-minute global deadline. Individual producer invocations are foreground and have no shell `timeout` wrapper. Their workload and owner bounds therefore depend on Rust producer enforcement; the inspected profile phase helper uses a monotonic deadline, checks child/process liveness and polls at <=20ms. This limited supporting read does not prove every native join is interruptible. Cleanup applies TERM then KILL and verifies names are absent; it is a hosted-runner fallback using process names, not PID/creation-time ownership proof. Initial exclusion of existing product processes and hosted isolation narrow that scope.
- Artifacts retain JSONL/plans/policies/summaries for 30 days. This is useful current-run evidence, not indefinite benchmark provenance. Completed evidence is copied before product worktrees are removed. Per-process logs and CPU traces are not part of this candidate artifact contract.

### m0 performance job: separate qualification, not parent/candidate acceptance or CPU sampling

- Manual dispatch-only `performance` uses an exact clean current checkout, ubuntu24/X64 checks, >=4 CPUs, >=15,000,000 KiB RAM, >=6,000,000 KiB free temporary storage and explicit nofile=65536. Its job timeout is 90 minutes.
- The Shadowsocks 1.24.0 reference archive is bound by exact byte size, SHA-256, archive member list and reported executable version. The job builds the current workspace in release, then runs `throughput`, `resource`, and `dns-resource` against the current SHA. Those are separate producer qualification modes, not performance_candidate's A/B raw schema or calibrated policy.
- The resource portion changes one Linux THP/khugepaged knob to a declared value, saves the original, restores it with readback via EXIT/TERM traps and repeats restoration in the final always-cleanup step. This is a distinct measurement environment. Its results must not be combined with candidate profiling-profile trials as if build/THP/recipe conditions were identical. No local sysctl or privileged action was executed by this audit.
- M0 uploads the three raw JSONL products even on failure, then reaps named product/reference processes, restores THP and removes its work directory. Upload again precedes final fallback cleanup; standalone raw qualification artifacts must not imply that later cleanup succeeded without the job evidence. The final `required` job excludes this manual performance job, consistent with performance not being an ordinary required correctness gate.
- No CPU stack capture command or profiler PID attachment occurs here either. `resource` is an RSS/fd/task/owner measurement mode, not CPU sampling. Any exact resource SLO interpretation belongs to the Rust producer/policy audit, not to the presence of this job name.

### Remaining metric and SLO scope after workflow cross-check

The workflow adds reliable build/schedule execution provenance to the Python contracts; it does not add absent CPU time/RSS fields to ordinary Linux candidate rows, a general memory slope acceptance policy, RuleSet loading/refresh budgets, system-DNS worker lifetime qualification, or open-load p50/p95/p99 SLO coverage. M0's dedicated resource modes can provide separate relevant evidence but do not prove no regression between arbitrary architecture revisions. The scale case remains a specific 16KiB/32KiB counterfactual, not a universal replacement for paired resource measurements. A short phase-three trace must record the actual product PID/build/symbol/source identity and stay separate from profiler-free phase-two measurements; neither reviewed YAML currently supplies that trace artifact.

Coverage limitation: two attempted supporting file reads used nonexistent profile.rs/profile_workload.rs paths and returned not-found; this produced no state change. The actual profile_output.rs owner was subsequently located and fully read. No coverage claim is based on the failed reads.
