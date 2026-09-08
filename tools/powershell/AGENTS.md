# PowerShell Tooling Guidelines

## Boundaries

`Ferrum2.Qualification.Host` owns Windows TUN correctness policy, sustained data-path/reset
witnesses, fixed checks, process/ownership/cleanup primitives, and the only exported qualification
function. There is no privileged host performance module or public performance runner.
TUN-only performance belongs to the crate-owned memory benchmark and Python controller.
Do not duplicate ownership primitives or introduce a guest, virtual-machine or staging fallback.

Correctness entrypoints and workers live under `tests/platform`. Reusable PowerShell modules live
here. Public entry scripts are composition and transaction roots, not compatibility facades.

## Evidence identity

The qualification source manifest enumerates every consumed script, module and C# source by
canonical repository path, exact byte length and SHA-256. Its complete digest flows through plan,
raw witnesses and final verdict. Update source rows atomically; stale identity is never accepted
through an alias, fallback reader or optional manifest row.

The private host primitives own address allocation, narrow-route proof, process-job ownership,
incremental recovery ledgers, cleanup verification, and bounded command execution. Correctness
witnesses must distinguish observed workload state from unobserved product ownership. Preserve the
existing recovery ledger identity so already-created resources remain safely recoverable.

## Verification

Parse every changed PowerShell file with the PowerShell parser, validate module manifests and
exports, reconstruct closed source maps, and run static contracts before live execution. Keep new
PowerShell and C# production owners below 1,000 lines unless a reviewed exception documents why a
deeper seam would be worse.

Ordinary hosts may execute nonmutating `-PlanOnly` and identity-safe `-RecoveryOnly` operations. Real
host qualification requires its sole dedicated runner, an already elevated shell, and explicit
acknowledgement. A runner may touch only its ledger-owned Wintun adapter, exact
RFC 2544 routes and addresses, processes, ports, files, and declared product-owned dynamic
strict-route or exact TCP-ingress WFP sessions, plus explicitly authorized per-run Windows Firewall
rules scoped to current test executables and required traffic. Create rules before their process
starts, bind file hash and rule identity in the ledger, and independently verify rule removal.
PersistentStore rules are not kernel-dynamic: interrupted runs require identity-safe recovery.
Never change existing rules, profile notification settings, default routes, DNS, physical adapters,
WLAN, sing-box or unrelated state.
