# Linux baseline matrix evidence

The baseline controller is observation-only. Thresholds and adoption decisions remain in
`tools/performance_candidate_policy.json` and the paired `summarize` command.

On the approved Linux profiling host, first capture the clean checkout and machine identity with
`build-environment`, then create the normal paired plan. Bind both artifacts into the required
raw/perf/RSS/allocator layout:

```text
python3 -B -m tools.performance_candidate linux-baseline-matrix \
  --plan profiles/performance-plan.json \
  --policy tools/performance_candidate_policy.json \
  --environment profiles/build-environment.json \
  --parent-sha <40-hex-parent> \
  --candidate-sha <40-hex-candidate> \
  --build-profile current \
  --output profiles/baseline-matrix.json
```

Each matrix row names four relative artifacts below one caller-owned artifact root: the raw JSONL
trial, `perf stat` capture, RSS capture, and allocator capture. After the approved workload runner
has populated every path, validate the raw trials and bind every artifact hash into one report:

```text
python3 -B -m tools.performance_candidate linux-baseline-report \
  --matrix profiles/baseline-matrix.json \
  --plan profiles/performance-plan.json \
  --policy tools/performance_candidate_policy.json \
  --environment profiles/build-environment.json \
  --artifact-root profiles/baseline-artifacts \
  --output profiles/baseline-report.json
```

These commands read and validate artifacts; they do not launch a performance workload. Ordinary
hosts should run their offline unit tests only.

## GitHub-hosted memory identity

Raw trials and summaries retain the runner's exact `memory_kib` value. Separate GitHub-hosted
allocations may differ slightly, so only cross-round A/A calibration and calibrated-policy
applicability for an A/B comparison compare a nearest 65,536 KiB (64 MiB) memory-capacity class.
The class anchor is `((memory_kib + 32768) // 65536) * 65536`, giving the half-open interval
`[anchor - 32768, anchor + 32768)`. The environment key set and every non-memory value must still
match exactly. A schema-v2 calibration candidate records the class anchor in
`environment_identity.memory_kib`, the quantum in `memory_capacity_quantum_kib`, and all exact raw
observations in sorted `memory_observations_kib`. Reviewed policy environments must store an aligned
class anchor. Within one trial set, runner-environment equality remains strict.
