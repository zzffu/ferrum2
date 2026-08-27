# Platform Qualification Script Guidelines

This directory owns privileged and hosted qualification orchestration. The public Main runner exposes
only `-Suite Core`, `Endurance`, or `Release`; its six live profiles are internal workers executed in
fixed order. Build the candidate artifacts once per campaign, but give every profile a fresh
restore/start/stage/cleanup/stop/restore transaction. Hard owns the independent hard-kill gate. Keep
the 28-file Main and 21-file Hard runtime closures independently enumerated and hash-verified before
importing any script; hard-kill must not depend on Main runtime functions.

Static contract scripts may run on a development host. `native_contract.py` owns the loopback-only,
unprivileged binary behavior checks; `qualify_native.py` is the thin local/hosted entrypoint. Local
execution uses `qualify_native.py --local-contract`, while hosted evidence mode must bind the exact
GitHub SHA, runner identity, clean checkout, and artifact paths. Hyper-V adapter and underlay cases
run only in their designated environment and must preserve bounded cleanup and structured evidence.
Pure Rust tests and deterministic TUN smoke belong to ordinary CI, not this guest controller. Shared
VM, topology, staging, and bundle mechanics come from `Ferrum2.WindowsTun.Lab`; qualification policy
and evidence remain local to this tree.

PowerShell libraries must not execute workflows when dot-sourced. Update the relevant source-bundle
manifest whenever an owned script changes or moves.
Identity ledger schema 4, main staged v6/host v7/campaign v1, and hard static/staged/host v4 are the
only accepted evidence versions. Topology contracts use `lab_checkpoint`; do not add a legacy alias.
