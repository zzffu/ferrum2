# PowerShell Tooling Guidelines

## Boundaries

Keep neutral Windows TUN filesystem, controller-bundle, approved-VM transaction,
and guest-bootstrap primitives in `Ferrum2.WindowsTun.Lab`. Qualification and
performance may depend on this module, but it must not define profiles, scenarios,
thresholds, witnesses, or qualification verdicts. Qualification-specific owners
remain in `Ferrum2.Qualification.*`; performance-only host, guest, collector,
diagnostic, scenario, and C# owners belong in `Ferrum2.Performance`. Do not copy Lab
or qualification helpers into the performance module. Public entry scripts are
composition/transaction roots, not compatibility facades. Keep privileged
qualification operations private and export only the file-map contract needed to
compose the qualification guest controller bundle.

Canonical operator, provisioning, collector, and Windows TUN performance script
sources live under `tools/windows-tun`; qualification entry points and guest
controllers remain under `tests/platform`. PowerShell modules live under
`tools/powershell`. Do not introduce a second source copy at `tools/` or encode a
flat guest-staging filename as though it were a repository path.

## Evidence identity

The performance source manifest must enumerate every production source in the
performance module plus the public scripts under their canonical
`tools/windows-tun/performance/` paths, using exact paths, byte lengths, and SHA-256 digests. Its
closed set is exactly 38 sources: three public performance scripts, 25 Performance owners, the
six-file Lab module, and the four directly executed Lab runtime owners. The source manifest must
hash-bind each helper; Qualification Evidence and HostHyperV sources are forbidden.
The runtime controller bundle is separately composed from the guest subset, the
Lab bootstrap, and the relevant qualification or performance modules. Its staging
paths describe deployment, not source ownership. `Ferrum2.WindowsTun.Lab` owns the
generic controller-bundle manifest operations and
`Get-Ferrum2WindowsTunLabRuntimeFileMap`; bootstrap-only guests use
`Get-Ferrum2WindowsTunLabBootstrapFileMap`. Qualification evidence owns only its
main and hard-kill file maps. Update file maps, every producer and reader, per-file
metadata, and complete-manifest hashes atomically when either file set or schema
changes. Stale source identity requires new reviewed calibration and must never be
accepted through an alias or fallback reader.
`BundleBootstrap.ps1` is also the canonical owner for flat source-manifest capture and private
locked staging. Entry points may perform the minimal same-bytes bootstrap check, then must use its
flat-closure, dependency-capture, stage-open, and stage-close APIs instead of defining local copies.
The neutral controller-bundle schema is `ferrum2.windows-tun-controller-bundle.v1`, and topology
documents use `lab_checkpoint` with no qualification-named alias.

## Verification

Parse every changed PowerShell file with the PowerShell parser, validate module
manifests and exported commands, and reconstruct both bundle file maps without
executing a performance or Hyper-V workflow. Keep new PowerShell and C# production
owners below 1,000 lines unless a reviewed exception documents why a deeper seam
would be worse.

Ordinary hosts must not run Hyper-V orchestration, real TUN sessions, deterministic
TUN smoke, or performance workloads. Those operations belong only in the approved
guest procedure.
