# Tooling Contributor Guide

Ferrum2 tooling keeps privileged qualification, neutral Lab mechanics, and host performance separate.
Rust qualification packages live in `tools/ferrum2-m4-qualification` and
`tools/ferrum2-rule-qualification`; declarative workflow controllers live in `tools/ci`; Python
performance controllers live in `tools/performance_candidate` and `tools/performance_rule`; reusable
PowerShell modules live in `tools/powershell`; neutral Windows TUN lab scripts live in
`tools/windows-tun/lab`; and the sole Windows TUN performance runner lives in
`tools/windows-tun/performance`. Root-level JSON policy documents are reviewed inputs, not scratch
output. Follow the nearest scoped guide for details.

Keep `tests/platform`, `tools/windows-tun/lab`, and `tools/windows-tun/performance` distinct.
Qualification owns guest suites and evidence; Lab owns reusable VM/topology mechanics; Performance
owns the explicitly authorized host runner, profiles, evidence, recovery, and thresholds. Performance
must not import Lab's VM transaction or retain a guest fallback. Do not keep compatibility copies
after a move.

Repository source identities use canonical repository paths. Any closed performance source bundle
must name every consumed source and bind exact byte lengths and SHA-256 values. When a bound file is
added, moved, changed, or removed, update recipes, consumers, file maps, per-file metadata, and the
complete manifest identity atomically; never accept stale evidence through an alias or optional row.

Ordinary hosts may run parsing, manifest reconstruction, static contracts, and the performance
runner's nonmutating `-PlanOnly` mode. `-RecoveryOnly` may inspect an empty or completed ledger
without elevation but requires an elevated shell before removing live network resources. Real Wintun
performance execution is allowed only through `run_windows_tun_performance_host.ps1` in an already
elevated shell with the explicit acknowledgement switch. Hyper-V orchestration remains restricted to
approved qualification.
