# PowerShell Tooling Guidelines

## Boundaries

Keep neutral Windows TUN filesystem, controller-bundle, approved-VM transaction, and guest-bootstrap
primitives in `Ferrum2.WindowsTun.Lab`. Qualification may depend on that module. Host performance must
not depend on its VM/checkpoint/staging owners; performance-only host transaction, collector,
evidence, recovery, scenario, and C# owners belong in `Ferrum2.Performance`.
Qualification-specific owners remain in `Ferrum2.Qualification.*`. Do not copy Lab or qualification
helpers into the performance module. Public entry scripts are composition/transaction roots, not
compatibility facades. Keep privileged qualification operations private and export only the file-map
contract needed to compose qualification guest controller bundles.

Canonical operator, provisioning, collector, and Windows TUN performance script sources live under
`tools/windows-tun`; qualification entry points and guest controllers remain under `tests/platform`.
PowerShell modules live under `tools/powershell`. Do not introduce a second source copy at `tools/`,
retain a Hyper-V performance wrapper, or encode a deployment basename as a repository source path.

## Evidence identity

The performance source manifest must enumerate every consumed host-runner, collector, module, and C#
source under its canonical repository path, with exact byte length and SHA-256. It must not contain
qualification sources or Lab VM/checkpoint/staging sources. The complete manifest digest is the
runner identity and must flow through the plan, raw evidence, and summary. Update file maps, every
producer and reader, per-file metadata, and complete-manifest hashes atomically when the file set or
schema changes. Stale source identity requires a new baseline and must never be accepted through an
alias, fallback reader, or optional manifest row.

The host performance module owns the internal seams for address allocation, route proof, process job
ownership, incremental recovery ledgers, profile execution, cleanup verification, and evidence
validation. The public runner passes only the selected mode and commit/evidence inputs across that
seam. Pure planning and ledger-validation helpers should return data rather than mutate state so
static tests can exercise the same interface.

## Verification

Parse every changed PowerShell file with the PowerShell parser, validate module manifests and exported
commands, reconstruct closed source maps, and run static contracts before live execution. Keep new
PowerShell and C# production owners below 1,000 lines unless a reviewed exception documents why a
deeper seam would be worse.

Ordinary hosts may execute nonmutating PlanOnly and identity-safe RecoveryOnly operations. Real host
performance execution requires the dedicated runner, elevation, and explicit acknowledgement; it may
touch only its ledger-owned Wintun adapter, exact benchmark routes, processes, ports, and files.
Hyper-V orchestration and guest workloads remain confined to approved qualification procedures.
