# Windows TUN Tooling Guide

The repository-level and `tools/AGENTS.md` instructions remain in force. This directory is the canonical repository source tree for Windows TUN operator, Hyper-V support-topology, guest-network-path, collector, diagnostic, and performance runner scripts. Qualification entry points and guest controllers remain under `tests/platform`; reusable modules remain under `tools/powershell`. Do not add root-level compatibility copies of these scripts.

Treat script paths as evidence identity. Recipes and source manifests must use the canonical `tools/windows-tun/<script>.ps1` paths. The runtime controller bundle intentionally stages a reviewed subset into one flat directory and invokes those staged files by basename. Preserve that distinction: a basename is valid inside the flat guest staging file map, but it is not a canonical repository source path.

Any source edit, addition, deletion, or move must atomically update every recipe and consumer, the closed source and staging file maps, exact byte lengths, per-file SHA-256 values, and complete-manifest or `controller_bundle_sha256` identities. Never accept stale evidence through an alias, fallback path, optional manifest member, or partial hash refresh.

On an ordinary host, limit verification to PowerShell parsing, module/manifest validation, file-map reconstruction, and static contract checks. Do not execute these scripts to provision Hyper-V, open a real TUN session, run deterministic TUN smoke, or collect performance evidence. Privileged and workload execution belongs only in the approved guest procedure.
