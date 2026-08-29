# Linux UDP receive-worker qualification

This package owns the provisional GATE-05 controller. It compares the same exact
feature-on client/server/qualification binaries while changing only the server
`udp.receive_workers` configuration axis from `1` to `2`, `4`, or `8`.

The fixed workload contains both one logical SOCKS UDP association
(`same-session`) and 32 independent associations (`multi-session`). Every
`1`-versus-variant comparison uses six paired ABBA trials. Exact
`receive_workers=1` A/A calibration runs twice for each session topology.

Each raw schema-v1 trial binds the checkout/tree, Rust and AMD host identity,
all three binary hashes, producer/controller/recipe digests, packets/s,
nearest-rank p99, process CPU millicores, context-switch deltas, and closed
schema-v7 structural counter snapshots. The admission, UDP server state, and
UDP mappings lock wait/hold/sample deltas are repeated as named evidence.

The hosted workflow is deliberately non-authoritative:

- scope: `github-hosted-amd-provisional`;
- `performance_authoritative=false`;
- `bare_metal_gate=false`;
- `adoption_claim=false`;
- production default remains `receive_workers=1`;
- the only release decision is `DEFERRED`.

Run ordinary parser/controller tests locally. Do not run the workload on an
ordinary host. The manual/reusable GitHub workflow is the approved hosted
entry point.

The reusable contract has one required typed input, `candidate_sha`, containing
the exact lowercase 40-character commit SHA. A same-commit caller uses:

```yaml
jobs:
  udp-workers:
    permissions:
      contents: read
    uses: ./.github/workflows/performance-udp-workers.yml
    with:
      candidate_sha: ${{ github.sha }}
```
