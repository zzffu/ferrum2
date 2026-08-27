# Windows TUN Tooling Guide

The repository-level and `tools/AGENTS.md` instructions remain in force. This directory separates neutral Windows TUN lab mechanics from performance policy. `lab/` owns operator-facing topology provisioning, inspection, and host/guest path proofs. `performance/` owns the performance runner, collectors, and diagnostics. Windows TUN correctness qualification entry points and guest controllers remain under `tests/platform`; reusable modules remain under `tools/powershell`. Neither subtree may import or invoke the other through a compatibility copy.

Treat script paths as evidence identity. Recipes and source manifests must use canonical `tools/windows-tun/lab/<script>.ps1` or `tools/windows-tun/performance/<script>.ps1` paths. The runtime controller bundle intentionally stages a reviewed subset into one flat directory and invokes those staged files by basename. Preserve that distinction: a basename is valid inside the flat guest staging file map, but it is not a canonical repository source path.

Any source edit, addition, deletion, or move must atomically update every recipe and consumer, the closed source and staging file maps, exact byte lengths, per-file SHA-256 values, and complete-manifest or `controller_bundle_sha256` identities. Never accept stale evidence through an alias, fallback path, optional manifest member, or partial hash refresh.

Lab topology contracts use `lab_checkpoint` exclusively. Performance has an independent 38-source
closure that hash-binds its four Lab runtime owners plus the six-file Lab module and may reuse only Lab
mechanics; it must not bind qualification Evidence or HostHyperV sources. Qualification's 28/21
runtime closures and 33/25 host-source closures remain owned under `tests/platform`.

On an ordinary host, limit verification to PowerShell parsing, module/manifest validation, file-map reconstruction, and static contract checks. Do not execute these scripts to provision Hyper-V, open a real TUN session, run deterministic TUN smoke, or collect performance evidence. Privileged and workload execution belongs only in the approved guest procedure.
