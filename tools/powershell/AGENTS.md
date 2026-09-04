# PowerShell Tooling Guidelines

## Boundaries

`Ferrum2.Qualification.Host` owns Windows TUN correctness policy, its fixed check set, evidence, and
the only exported qualification function. `Ferrum2.Performance` owns host performance plans,
profiles, reducers, thresholds, evidence, and recovery. Qualification may compose the reviewed
private host ownership, execution, and process-group primitives from `Ferrum2.Performance`; it must
not call the public performance runner or reuse a performance verdict. Do not duplicate those
primitives or introduce a guest, virtual-machine, or staging fallback.

Canonical performance entry scripts live under `tools/windows-tun/performance`; correctness
entrypoints and workers live under `tests/platform`. Reusable PowerShell modules live here. Public
entry scripts are composition and transaction roots, not compatibility facades.

## Evidence identity

Each performance or qualification source manifest must enumerate every consumed script, module, and
C# source under its canonical repository path with exact byte length and SHA-256. The complete
manifest digest flows through that runner's plan, raw evidence, and summary or verdict. A performance
bundle must not contain qualification sources. A qualification bundle may list only its own sources
and the explicitly shared private host primitives. Update all file rows and bundle identities
atomically; stale source identity is never accepted through an alias, fallback reader, or optional
manifest row.

The private host primitives own address allocation, narrow-route proof, process-job ownership,
incremental recovery ledgers, cleanup verification, and bounded command execution. Qualification
adds correctness witnesses; performance adds scenarios and statistical policy. Pure planning and
ledger-validation helpers should return data rather than mutate state.

## Verification

Parse every changed PowerShell file with the PowerShell parser, validate module manifests and
exports, reconstruct closed source maps, and run static contracts before live execution. Keep new
PowerShell and C# production owners below 1,000 lines unless a reviewed exception documents why a
deeper seam would be worse.

Ordinary hosts may execute nonmutating `-PlanOnly` and identity-safe `-RecoveryOnly` operations. Real
host qualification or performance requires the corresponding dedicated runner, an already elevated
shell, and explicit acknowledgement. A runner may touch only its ledger-owned Wintun adapter, exact
RFC 2544 routes and addresses, processes, ports, files, and any product-owned dynamic WFP session
declared by its plan. It must not change default routes, DNS, physical adapters, WLAN, firewall
rules, sing-box, or unrelated state.
