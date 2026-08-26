# Performance Candidate Controller Guidelines

## Purpose and Entry Point

The only supported command entry point is `python -B -m tools.performance_candidate`. Do not add a script shim or a second CLI. `cli.py` only wires commands; shared JSON, identity, output, and pairing contracts have named owners; Linux and Windows TUN behavior stays in their respective subpackages. Scale lineage, trial validation, and decisions are separate owners. Windows UDP schema/value/ledger/capture/source validation and network-model identity/route/lifecycle logic are likewise separated; `windows_tun/network_model.py` is the small production model composition root, not a test helper.

## Contract Ownership

Keep evidence parsing fail-closed and bounded. Preserve exact JSON fields, schema versions, parent/candidate and build identities, metric units, correctness results, cleanup results, pair order, source digests, and calibration applicability unless a dedicated schema change updates every producer and consumer atomically. The only terminal states are `CANDIDATE_WIN`, `WITHIN_CALIBRATED_BAND`, `REGRESSION`, `INCONCLUSIVE`, `CALIBRATION_REQUIRED`, and `INVALID`; qualification accepts only the first two. Linux and Windows use six pre-registered ABBA pairs. Policy decides adoption and regression; observation producers must not invent thresholds.

The Windows TUN recipe binds this package to the canonical runner, collectors, and topology scripts under `tools/windows-tun`, the modules under `tools/powershell`, the topology inputs, the Rust qualification harness, the verified `network_model_bundle.json`, and `tools/powershell/Ferrum2.Performance/bundle.json`. Repository source paths retain the `tools/windows-tun/` prefix. The guest controller is intentionally a flat staging directory, so its file map addresses staged scripts by basename; a flat staging name is not an alternate repository source path.

The performance source bundle is a closed 42-file set that includes the reused Common, Evidence, and HostHyperV module sources as well as the performance-specific owners. Moving or changing any bound source changes recipe identity and requires coordinated consumer updates and fresh calibration review. Update recipe paths, source manifests, exact byte lengths, per-file SHA-256 values, and complete-manifest hashes atomically. The complete-file digests, rather than entrypoint-only hashes, are recorded in plans and raw evidence. The runtime controller bundle is a distinct guest-staging identity and must bind the exact guest subset plus the qualification modules. Its canonical `controller_bundle_sha256` is required by every Windows controller command and is carried through plan v4, trial v5, summary/calibration v4, and policy v4 applicability.

## Verification

Use static checks before running any performance workflow:

```text
python -B -m compileall -q tools/performance_candidate
python -B -c "import tools.performance_candidate.cli; import tools.performance_candidate.windows_tun.network_model"
```

The repository-level performance controller tests and approved Hyper-V procedure remain the behavioral gates. On an ordinary host, do not run performance workloads, Hyper-V orchestration, a real TUN session, or deterministic TUN smoke; restrict verification to static parsing, imports, manifest reconstruction, and non-workload contract tests. Live Windows TUN work is allowed only inside the approved guest boundary.

Tests mirror production owners: shared and Linux plan/policy/summary/scale behavior have separate modules, while Windows TUN plan/summary, trial, UDP diagnostics, and network-model behavior have separate modules with narrow fixture mixins. Do not recreate a monolithic controller test or import an obsolete facade.
