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
host PowerShell transaction -> controller plan -> staged Rust/PowerShell producers
-> bounded raw trials and network-model observations
-> controller validation/summary -> reviewed Windows policy decision
```

The Windows performance PowerShell implementation is owned by
`tools/powershell/Ferrum2.Performance`. The three public scripts remain composition
roots: the host script owns CLI/transaction/final cleanup, the trial collector
dispatches to scenario owners, and the UDP diagnostic dispatches to its source and
evidence owners. `PerformanceProcessOwner.cs` owns the guest process/job-object
interop instead of embedding C# in a script. The module exports only
`Get-Ferrum2PerformanceGuestFileMap`, which defines the exact guest staging surface.

`tools/powershell/Ferrum2.Performance/bundle.json` is the canonical static source
bundle. It binds every host, guest, collector, diagnostic, scenario, module, C#,
controller-bundle bootstrap, and consumed Common, Evidence, and HostHyperV source
by path, byte length, and SHA-256. HostContract owns only policy, plan, and
performance-specific composition; filesystem trust, VM identity/lifecycle, credential,
and PowerShell Direct contracts come from the HostHyperV façade. Its complete-file digest is the Windows
performance recipe/runner identity. At runtime, the host composes a separate
runtime controller bundle from the guest subset, the two guest entrypoints, this
source manifest, and the qualification modules; the controller-bundle root digest
is recorded in the schema-v3 identity ledger and propagated through Windows plan
v4, trial v5, summary/calibration v4, and policy v4. A source, file-map, or module change
therefore requires manifest regeneration and fresh calibration review.

Schema, recipe, source-path, source-hash, runner image, observed CPU/kernel stratum, or paired schedule changes require atomic producer/consumer updates. Linux trial schema v4 binds explicit units, deterministic cleanup, environment identity, and producer/controller/semantic-recipe/bundle digests. Both Linux and Windows use the pre-registered six-pair ABBA schedule; Windows therefore emits 108 ordinary trials. Any binding change makes existing calibration inapplicable until reviewed evidence is regenerated.

Closed qualification statuses are `CANDIDATE_WIN`, `WITHIN_CALIBRATED_BAND`, `REGRESSION`, `INCONCLUSIVE`, `CALIBRATION_REQUIRED`, and `INVALID`. Only the first two are accepted. Invalid evidence exits 2, regression exits 3, and inconclusive or calibration-required results exit 4.

## Rule qualification evidence

`ferrum2-rule-qualification` emits bounded runner v3 reports. The only Rule controller entry point is `python -B -m tools.performance_rule`; schema, runner-report validation, pairing, policy, evidence, and CLI have separate package owners. Current controller v7 A/A output is always `CALIBRATION_REQUIRED` until a separately reviewed, source-hash-bound calibration v3 artifact is created. MatchSet and snapshot-registry A/A noise are calibrated independently and neither suite may exceed the reviewed 10% ceiling. Ordinary tests use the small synthetic fixture under `tests/performance_rule/fixtures`; it proves schema and binding behavior but is never benchmark evidence. Historical controller v2/v3/v4 readers exist only in the explicit test-owned archive verifier.

The manual Rule workflow is also reusable from the reviewed
`performance-candidate.yml` caller. Both entry paths require an explicit full
`candidate_sha`; checkout HEAD, runner reports, reviewed calibration, and both
artifact manifests are validated against that same commit. The reusable inputs
are closed to `stage`, `candidate_sha`, `calibration_run_id`, `reviewed_by`,
`reviewed_utc`, and `candidate_feature`.

Large `release-*.json` reports are ignored by Git. Their exact names, roles, byte lengths, and SHA-256 digests are tracked in `tests/performance_rule/fixtures/external-evidence-manifest-v1.json`. Verify explicitly materialized external evidence with:

```text
python3 -B -m tests.performance_rule.verify_external_evidence \
  --evidence-directory /path/to/materialized-rule-evidence
```

External artifact retrieval must use an immutable identity. Missing or changed raw evidence cannot be replaced by a summary, compact fixture, screenshot, or policy document.

## Same-source build artifacts and conditional ideas

Build candidates use a separate v2 identity axis: one clean source SHA/tree produces a generic
baseline and exactly one ThinLTO, PGO-use, or reviewed `znver3` artifact. Variant identity binds the
plan, phase record, profile/Rust flags, and client/server/M4/rule hashes. The manual/reusable
`performance-build.yml` workflow requires an AMD runner, two six-pair A/A rounds, and one six-pair
ABBA comparison. PGO additionally requires its closed six-command `.profraw` inventory, merged
profile provenance, and independent validation records.

GitHub-hosted evidence is deliberately provisional. Build and conditional records state
`performance_authoritative=false`, `bare_metal_gate_satisfied=false`,
`durable_evidence_gate_satisfied=false`, and either
`NOT_ADOPTED_FOR_GITHUB_HOSTED_AMD_SCOPE` or a deferred/inconclusive trigger status. Artifact
retention is useful workflow evidence but does not satisfy the immutable long-term GATE-07
contract. The closed architecture-decision record separately preserves the TCP fairness invariant,
deferred Linux/multi-hop prerequisites, busy-poll rejection, and the Windows external-lab ETW
boundary.

## Ordinary and privileged boundaries

Ordinary CI may compile controllers, validate tracked fixtures, and run deterministic contract tests. It must not claim local Hyper-V, Wintun, WFP, or host-network evidence. Only the approved Hyper-V procedure may create Windows TUN performance evidence, and success requires exported raw evidence, complete cleanup, restoration of the same checkpoint, and the VM left Off.
