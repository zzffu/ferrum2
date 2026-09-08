# Tooling Contributor Guide

Ferrum2 tooling separates correctness qualification from performance evidence. Rust qualification
packages live in `tools/ferrum2-m4-qualification` and `tools/ferrum2-rule-qualification`; workflow
controllers live in `tools/ci`; Python performance controllers live in `tools/performance_candidate`
and `tools/performance_rule`. Windows host correctness entrypoints live in `tests/platform`, with
their private transaction owners in `tools/powershell/Ferrum2.Qualification.Host`.

TUN-only performance uses the crate-owned memory benchmark, with calibrated paired execution and
validation in the Python candidate controller. It performs no socket or host network operations.
There is no privileged host performance runner. Neither internal performance nor correctness
may consume the other's verdict. Do not keep compatibility copies after a move.

Repository source identities use canonical repository paths. Every closed source bundle must name
each consumed source and bind exact byte length and SHA-256. When a bound file is added, moved,
changed, or removed, update consumers, file maps, per-file metadata, and the complete manifest
identity atomically; never accept stale evidence through an alias or optional row.

Ordinary hosts may run parsing, manifest reconstruction, static contracts, and nonmutating
`-PlanOnly`. `-RecoveryOnly` may inspect an empty or completed ledger without elevation but requires
an elevated shell before removing live network resources. Real Windows TUN correctness execution
is allowed only through its dedicated host runner in an already elevated shell with explicit
acknowledgement. Memory benchmark execution needs no network-mutation acknowledgement.
