# Platform Qualification Script Guidelines

This directory owns privileged and hosted qualification orchestration. Keep Main and Hard controller
bundles independently enumerated and hash-verified before importing any script; the hard-kill workflow
must not depend on Main runtime functions.

Static contract scripts may run on a development host. Native qualification, Hyper-V guest execution,
TUN smoke, and adapter or underlay cases run only in their designated environment and must preserve
bounded cleanup and structured evidence.

PowerShell libraries must not execute workflows when dot-sourced. Update the relevant source-bundle
manifest whenever an owned script changes or moves.
