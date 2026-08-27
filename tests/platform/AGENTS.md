# Platform Qualification Script Guidelines

This directory owns privileged and hosted qualification orchestration. Keep Main and Hard controller
bundles independently enumerated and hash-verified before importing any script; the hard-kill workflow
must not depend on Main runtime functions.

Static contract scripts may run on a development host. `native_contract.py` owns the loopback-only,
unprivileged binary behavior checks; `qualify_native.py` is the thin local/hosted entrypoint. Local
execution uses `qualify_native.py --local-contract`, while hosted evidence mode must bind the exact
GitHub SHA, runner identity, clean checkout, and artifact paths. Hyper-V guest execution,
TUN smoke, and adapter or underlay cases run only in their designated environment and must preserve
bounded cleanup and structured evidence.

PowerShell libraries must not execute workflows when dot-sourced. Update the relevant source-bundle
manifest whenever an owned script changes or moves.
