# PowerShell Tooling Guidelines

## Boundaries

Keep qualification-wide helpers in the existing `Ferrum2.Qualification.*` modules.
Windows performance-only host, guest, collector, diagnostic, scenario, and C#
owners belong in `Ferrum2.Performance`; do not copy qualification helpers into that
module. Public entry scripts are composition/transaction roots, not compatibility
facades. Keep privileged operations private and export only the file-map contract
needed to compose the guest controller bundle.

Canonical operator, provisioning, collector, and Windows TUN performance script
sources live under `tools/windows-tun`; qualification entry points and guest
controllers remain under `tests/platform`. PowerShell modules live under
`tools/powershell`. Do not introduce a second source copy at `tools/` or encode a
flat guest-staging filename as though it were a repository path.

## Evidence identity

The performance source manifest must enumerate every production source in the
performance module plus the public scripts under their canonical
`tools/windows-tun/` paths, using exact paths, byte lengths, and SHA-256 digests.
The runtime controller bundle is separately composed from the guest subset and
qualification modules into an intentionally flat staging directory; its basename
entries describe staging, not source ownership. Update file maps, every producer
and reader, per-file metadata, and complete-manifest hashes atomically when either
file set or schema changes. Stale source identity requires new reviewed calibration
and must never be accepted through an alias or fallback reader.

## Verification

Parse every changed PowerShell file with the PowerShell parser, validate module
manifests and exported commands, and reconstruct both bundle file maps without
executing a performance or Hyper-V workflow. Keep new PowerShell and C# production
owners below 1,000 lines unless a reviewed exception documents why a deeper seam
would be worse.

Ordinary hosts must not run Hyper-V orchestration, real TUN sessions, deterministic
TUN smoke, or performance workloads. Those operations belong only in the approved
guest procedure.
