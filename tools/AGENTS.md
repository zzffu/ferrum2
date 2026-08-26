# Tooling Contributor Guide

The repository-level `AGENTS.md` remains in force. Rust qualification packages live in `tools/ferrum2-m4-qualification` and `tools/ferrum2-rule-qualification`; Python controller implementations live in `tools/performance_candidate` and `tools/performance_rule`; reusable PowerShell modules live in `tools/powershell`; and canonical Windows TUN operator, provisioning, collector, and performance scripts live in `tools/windows-tun`. Root-level JSON policy and topology documents are reviewed inputs, not scratch output. Follow the nearest scoped guide for details.

Keep `tests/platform` and `tools/windows-tun` distinct. The former owns qualification entry points, guest controllers, and static qualification contracts. The latter owns reusable operator and Windows TUN performance script sources. Do not retain compatibility copies after a move.

Repository source identity and guest staging identity have different path semantics. Source manifests and recipes name canonical repository paths, including the `tools/windows-tun/` prefix. Guest controller bundles may deliberately flatten their selected files to basenames in a staging directory. That flat file map is a deployment layout, not another source tree. When a bound file is added, moved, or changed, update recipes, consumers, closed file maps, exact byte lengths, per-file SHA-256 values, and the complete manifest or controller-bundle hash atomically.

On an ordinary host, use only static parsing, compile/import checks, manifest reconstruction, and non-workload contract tests. Do not run Hyper-V orchestration, real TUN sessions, deterministic TUN smoke, or performance workloads. Those operations require the approved guest procedure.
