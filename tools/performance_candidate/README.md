# Performance candidate controllers

Use only `python -B -m tools.performance_candidate`; modules in this package are
contract owners, not alternate script entry points.

## Shadowsocks frame-size campaign

`.github/workflows/performance-frame.yml` is an independent Phase 5 experiment.
It builds `default32`, `frame16k`, `frame65535`, and `adaptive` artifacts from the
same clean source SHA and tree. The adaptive build starts at 32 KiB in each
direction and grows to the protocol-exact 65,535-byte cap only after that
direction has encoded 512 KiB. These internal Cargo features are experiment
identities, not runtime configuration or compatibility APIs.

Every selected axis runs two six-pair A/A rounds plus one six-pair ABBA
comparison against `default32`. The closed observations are TCP bulk throughput,
1 KiB request p99, and the 10,000-flow throughput/Jain/p01 fairness record. An
`AuthenticAMD` GitHub-hosted result is retained only as
`github-hosted-amd-provisional`: it is never authoritative and never an adoption
claim.

The reusable workflow accepts one string input named `axis`, with the closed
values `all`, `default32`, `frame16k`, `frame65535`, or `adaptive`. A caller in
the same commit can use:

```yaml
uses: ./.github/workflows/performance-frame.yml
with:
  axis: all
```

Do not run the workload locally. Local verification is limited to Rust tests,
controller unit tests, imports, schema mutation tests, and workflow linting.
