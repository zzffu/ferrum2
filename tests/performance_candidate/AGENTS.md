# Performance Candidate Controller Test Guidelines

Use `unittest`, compact synthetic JSON fixtures and repository-relative paths to validate strict
evidence identity, pairing, policy and failure behavior. Do not execute timed workloads or mutate
host networking in ordinary evidence tests.

TUN mock tests bind exact workload/count/unit contracts, independent binary/source identities,
complete interleaved schedules and reviewed A/A calibration digests. Reject type confusion,
reordered/missing raw trials and forged decisions even when outer hashes are recomputed. Synthetic
fixtures prove validation behavior, not measured performance.

Qualification-owned startup, port reservation and cleanup readback tests live under
`tests/platform`; they are not host performance compatibility tests.
