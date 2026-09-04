# Performance Candidate Controller Guidelines

## Purpose and Entry Point

The only supported command entry point is `python -B -m tools.performance_candidate`. Do not add a
script shim or a second CLI. `cli.py` only wires commands; shared JSON, identity, output, and pairing
contracts have named owners; Linux and Windows TUN behavior stays in their respective subpackages.
Scale lineage, trial validation, and decisions are separate owners. Windows host plan, trial,
recovery, cleanup, route-proof, and summary validation likewise have narrow owners; keep the
composition root small rather than rebuilding the former guest/network-model facade.

## Contract Ownership

Keep evidence parsing fail-closed and bounded. Preserve exact JSON fields, schema versions,
baseline/candidate and build identities, metric units, correctness results, cleanup results, pair
order, source digests, and applicability unless a dedicated schema change updates every producer and
consumer atomically. Policy decides retention and regression; observation producers must not invent
thresholds. Windows Quick uses at least three interleaved pairs and Confirm at least five; the
selected profile and scenario recipes are evidence identity.

The Windows TUN recipe binds this package only to the canonical host runner and collectors under
`tools/windows-tun/performance`, host owners under `tools/powershell/Ferrum2.Performance`, the Rust
workload harness, and the verified performance source bundle. It must not bind Lab VM/topology,
checkpoint, guest staging, PowerShell Direct, or qualification sources. Repository source paths stay
canonical; there is no flat guest deployment map.

The performance source bundle is a closed host source set. Moving or changing any bound source
changes runner identity and requires coordinated producer/consumer updates plus a fresh baseline.
Update recipe paths, source manifests, exact byte lengths, per-file SHA-256 values, and
complete-manifest hashes atomically. Plans and raw evidence record the complete bundle digest, not an
entrypoint-only hash.

## Verification

Use static checks before running any performance workflow:

```text
python -B -m compileall -q tools/performance_candidate
python -B -c "import tools.performance_candidate.cli; import tools.performance_candidate.windows_tun.summary"
```

Static tests and manifest reconstruction are the ordinary behavioral gates. They must not execute a
real TUN workload. Live Windows TUN performance is allowed only through the canonical host runner from
an already elevated shell with explicit network-mutation acknowledgement and verified per-RunId
cleanup. Hyper-V is a separate correctness-qualification path, not a performance fallback.

Tests mirror production owners: shared and Linux plan/policy/summary/scale behavior have separate
modules; Windows host plan, trial, recovery/cleanup, and summary behavior use narrow fixture helpers.
Do not keep guest schemas, topology identities, or compatibility readers.
