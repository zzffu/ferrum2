# Tooling Contributor Guide

Ferrum2 tooling keeps correctness qualification and host performance as separate products. Rust
qualification packages live in `tools/ferrum2-m4-qualification` and
`tools/ferrum2-rule-qualification`; declarative workflow controllers live in `tools/ci`; Python
performance controllers live in `tools/performance_candidate` and `tools/performance_rule`; reusable
PowerShell modules live in `tools/powershell`; and the sole Windows TUN performance runner lives in
`tools/windows-tun/performance`. Windows TUN correctness entrypoints live in `tests/platform`.
Root-level JSON policy documents are reviewed inputs, not scratch output.

Correctness owns a fixed host check set, source identity, evidence, and verdict. Performance owns its
host profiles, measurements, reducers, thresholds, evidence, and verdict. They may share reviewed
private ownership and bounded-execution primitives, but neither may call the other's public runner,
consume the other's verdict, or retain a guest fallback. Do not keep compatibility copies after a
move.

Repository source identities use canonical repository paths. Every closed source bundle must name
each consumed source and bind exact byte length and SHA-256. When a bound file is added, moved,
changed, or removed, update consumers, file maps, per-file metadata, and the complete manifest
identity atomically; never accept stale evidence through an alias or optional row.

Ordinary hosts may run parsing, manifest reconstruction, static contracts, and nonmutating
`-PlanOnly`. `-RecoveryOnly` may inspect an empty or completed ledger without elevation but requires
an elevated shell before removing live network resources. Real Windows TUN correctness or
performance execution is allowed only through its dedicated host runner in an already elevated
shell with the explicit acknowledgement switch.
