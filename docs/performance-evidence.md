# Performance evidence ownership

Ferrum2 keeps measurement production, evidence validation, and adoption policy separate. A successful command is not by itself a performance claim.

## Product parent/candidate evidence

The canonical controller entry point is:

```text
python3 -B -m tools.performance_candidate <command> ...
```

`tools/performance_candidate/cli.py` is the composition root. Named shared modules own strict JSON, identity, atomic output, and paired statistics; the `linux/` and `windows_tun/` subpackages own their plans, trials, policies, summaries, and diagnostics. Scale lineage/trials/decisions and Windows UDP schema/value/ledger/capture/source checks have separate owners. The small `tools/performance_candidate/windows_tun/network_model.py` composition root dispatches to identity, route-once, and lifecycle modules. `network_model_bundle.json` binds every model source by byte length and SHA-256, and its complete-file digest is staged and recorded as the controller identity. Production code must not be loaded from `tests/`.

The Linux evidence chain is:

```text
workflow inputs -> controller plan -> m4 profile-workload producer
-> bounded JSONL trials -> controller summary -> reviewed policy decision
```

The Windows evidence chain is:

```text
host PowerShell transaction -> closed profile plan -> independently built baseline/candidate
-> interleaved real-Wintun trials -> bounded raw evidence
-> host validation/paired summary -> reviewed decision
```

The Windows performance PowerShell implementation is owned by
`tools/powershell/Ferrum2.Performance`. Its only public composition root is
`tools/windows-tun/performance/run_windows_tun_performance_host.ps1`. The runner interface exposes
planning, recovery, `Quick`, `Confirm`, and `Lifecycle`; it hides adapter names, benchmark addresses,
ports, process IDs, routes, temporary files, ledgers, cleanup, and evidence construction.
`PerformanceProcessOwner.cs` places every spawned product and support process in one kill-on-close job
instead of embedding process-tree interop in the runner.

`tools/powershell/Ferrum2.Performance/bundle.json` is the canonical closed host-performance source
bundle. It binds every consumed runner, module, collector, scenario, and C# owner by canonical path,
byte length, and SHA-256. Its complete-file digest is the Windows performance runner identity and is
recorded from plan through raw evidence and summary. The bundle contains no qualification source and
no Lab VM, checkpoint, PowerShell Direct, guest staging, or topology owner. Any source, file-map,
schema, recipe, or paired-schedule change requires atomic producer/consumer updates and a new
baseline; stale calibration or evidence is not comparable.

`Quick` is the autoresearch feedback profile: one to three selected data-plane scenarios, short
warmup and active windows, and at least three interleaved baseline/candidate pairs. `Confirm` runs all
directly affected data-plane scenarios with longer windows and at least five interleaved or balanced
pairs; it retains every pair and reports median ratio, range, outliers, CPU, throughput/PPS, drops,
and errors without hiding regressions in an aggregate score. `Lifecycle` is separate, defaults to 20
and caps at 100 complete product-start, TUN-probe, and product-stop cycles; it never changes a
default route or disables or enables a physical adapter. The retired 1000-reset durability soak is
disabled and cannot restart the host network.

Every real run requires an already elevated shell and the literal
`-AcknowledgeHostNetworkMutation` switch. The runner uses dedicated RFC 2544 addresses and only exact
benchmark routes; it must prove benchmark traffic enters the owned TUN and underlay, support, and
127.0.0.1:1080 traffic do not. Each mutation is recorded incrementally in a per-RunId recovery ledger.
Success requires identity-safe cleanup plus readback proving no owned adapter, route, process, or port
remains.

Closed qualification statuses are `CANDIDATE_WIN`, `WITHIN_CALIBRATED_BAND`, `REGRESSION`, `INCONCLUSIVE`, `CALIBRATION_REQUIRED`, and `INVALID`. Only the first two are accepted. Invalid evidence exits 2, regression exits 3, and inconclusive or calibration-required results exit 4.

## Rule qualification evidence

`ferrum2-rule-qualification` emits bounded runner reports. The only Rule controller entry point is `python -B -m tools.performance_rule`; schema, runner-report validation, pairing, policy, evidence, and CLI have separate package owners. Current v6 A/A output is always `CALIBRATION_REQUIRED` until a separately reviewed, source-hash-bound calibration v2 artifact is created. Ordinary tests use the small synthetic fixture under `tests/performance_rule/fixtures`; it proves schema and binding behavior but is never benchmark evidence. Historical v2/v3/v4 readers exist only in the explicit test-owned archive verifier.

Large `release-*.json` reports are ignored by Git. Their exact names, roles, byte lengths, and SHA-256 digests are tracked in `tests/performance_rule/fixtures/external-evidence-manifest-v1.json`. Verify explicitly materialized external evidence with:

```text
python3 -B -m tests.performance_rule.verify_external_evidence \
  --evidence-directory /path/to/materialized-rule-evidence
```

External artifact retrieval must use an immutable identity. Missing or changed raw evidence cannot be replaced by a summary, compact fixture, screenshot, or policy document.

## Ordinary and privileged boundaries

Ordinary CI may compile controllers, validate tracked fixtures, parse PowerShell, reconstruct the
closed bundle, and run deterministic contract tests. It must not create a real adapter or claim
Wintun, WFP, or host-network evidence. `-PlanOnly` is unprivileged and nonmutating. Real Windows TUN
performance evidence may be created only by the dedicated host runner from an already elevated shell
with explicit acknowledgement; success requires exported raw evidence and verified per-run cleanup.
Hyper-V remains a separate correctness-qualification boundary and is not a performance fallback.
