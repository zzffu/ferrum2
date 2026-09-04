# Configuring a Windows TUN Hyper-V lab

The lab is configured by an explicit topology-plan JSON file. The repository file
`tools/windows_tun_hyperv_support_topology_plan.json` is the plan for one existing lab, not a
machine-independent default. Copy it to a machine-owned location, replace every Hyper-V identity
and the isolated support subnet, then pass its absolute path with `-TopologyPlanPath`.

Collect the host-specific identities from an elevated PowerShell 7.4 session:

```powershell
$vm = Get-VM -Name '<VM name>'
$vm | Select-Object Name, Id, AutomaticCheckpointsEnabled
Get-VMSnapshot -VM $vm | Select-Object Name, Id, SnapshotType
Get-VMNetworkAdapter -VM $vm |
    Select-Object Name, Id, SwitchName, SwitchId, MacAddress, DynamicMacAddressEnabled
Get-VMSwitch | Select-Object Name, Id, SwitchType
```

The plan must select an existing source checkpoint and management adapter. The support topology
must use a new Internal switch, a distinct static `00155Dxxxxxx` MAC, and an unused IPv4 `/30`.
`host_ipv4` and `guest_ipv4` are respectively the first and second usable addresses. Gateway and
DNS must remain absent, and the source and lab checkpoint names must differ.

Validate the plan without changing Hyper-V:

```powershell
$plan = (Resolve-Path 'C:\Ferrum2\lab-topology.json').Path
pwsh -File tools/windows-tun/lab/inspect_windows_tun_hyperv_support_topology.ps1 `
    -TopologyPlanPath $plan
```

Provisioning requires the same plan explicitly. The generated manifest must remain outside the
repository:

```powershell
pwsh -File tools/windows-tun/lab/provision_windows_tun_hyperv_support_topology.ps1 `
    -Apply `
    -AuthorizationToken CREATE-FERRUM2-INTERNAL-SUPPORT-V1 `
    -TopologyPlanPath $plan `
    -ManifestPath 'C:\Ferrum2\lab-topology-manifest.json'
```

Replace an existing manifest-bound topology when its generated runtime identities have become stale.
Pin both the old and new manifest paths; the new path must not exist:

```powershell
$oldManifest = 'C:\Ferrum2\lab-topology-manifest.json'
pwsh -File tools/windows-tun/lab/provision_windows_tun_hyperv_support_topology.ps1 `
    -Apply `
    -AuthorizationToken REPROVISION-FERRUM2-INTERNAL-SUPPORT-V1 `
    -TopologyPlanPath $plan `
    -ExistingManifestPath $oldManifest `
    -ExistingManifestSha256 (Get-FileHash $oldManifest -Algorithm SHA256).Hash.ToLowerInvariant() `
    -ManifestPath 'C:\Ferrum2\lab-topology-manifest-replacement.json'
```

Reprovisioning first audits that the live VM adapter, checkpoint, Internal switch, and protected
host TUN match the pinned existing manifest. It then uses the provisioning rollback owner to restore
the exact source checkpoint and remove only those manifest-bound resources before running the normal
create transaction. A failed ownership audit does not mutate state.

Pass that same `-TopologyPlanPath` to the qualification, probe, hard-kill, and performance entry
points together with the generated manifest. The plan and manifest hashes are checked throughout
each run; changing either file requires reprovisioning rather than an in-place override.
