# Performance Candidate Controller Test Guidelines

These tests validate stable JSON, identity, pairing, policy, plan, trial, recovery, cleanup, and
summary contracts without running live benchmarks or mutating host network state. Use
`unittest`, compact JSON fixtures, and repository-relative paths.

Assert exact schemas, source hashes, profile identity, interleaved pair order, route proofs,
per-RunId ownership, fail-closed recovery, bounded values, and diagnostic output. Keep workload
execution, elevation, adapter creation, and timing variability out of this suite.

Host runner source-capture tests prove that the closed performance bundle contains every imported
local owner before execution, excludes Lab VM/topology/checkpoint/guest staging sources, and binds
exact byte lengths and SHA-256 values. Contract tests cover the small public parameter surface,
nonmutating PlanOnly, explicit authorization, exact-resource cleanup, and fail-closed stale-ledger
behavior without invoking a privileged runner path.
