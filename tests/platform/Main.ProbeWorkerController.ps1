param([Parameter(Mandatory)] [Collections.IDictionary]$Context)

$expectedFields = @(
    'repository_root', 'internal_worker_token', 'topology_plan_path', 'topology_manifest_path',
    'topology_manifest_sha256', 'support_tcp_port', 'support_udp_port',
    'support_pid', 'support_owner', 'credential_path',
    'readiness_timeout_seconds', 'shutdown_timeout_seconds'
)
Assert-Ferrum2ClosedProperties $Context $expectedFields 'main probe worker context'
$repositoryRoot = [string]$Context.repository_root
$internalWorkerToken = [string]$Context.internal_worker_token
$topologyPlanPath = [string]$Context.topology_plan_path
$topologyManifestPath = [string]$Context.topology_manifest_path
$topologyManifestSha256 = [string]$Context.topology_manifest_sha256
$supportTcpPort = [int]$Context.support_tcp_port
$supportUdpPort = [int]$Context.support_udp_port
$supportPid = [int]$Context.support_pid
$supportOwner = [string]$Context.support_owner
$credentialPath = [string]$Context.credential_path
$readinessTimeoutSeconds = [int]$Context.readiness_timeout_seconds
$shutdownTimeoutSeconds = [int]$Context.shutdown_timeout_seconds

[void](Initialize-Ferrum2HostHyperVModule -RepositoryRoot $repositoryRoot)
Assert-BoundedHyperVInternalWorker -Token $internalWorkerToken
if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows
    ) -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'X64' -or
    [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne 'X64') {
    throw 'the Hyper-V probe worker requires 64-bit Windows AMD64'
}
$topology = Initialize-ApprovedHyperVTopology `
    -TopologyPlanPath $topologyPlanPath `
    -ManifestPath $topologyManifestPath -ExpectedSha256 $topologyManifestSha256
$document = $topology.Document
$vmName = [string]$document.Value.vm.name
$vmId = [Guid][string]$document.Value.vm.id
$checkpointName = [string]$document.Value.lab_checkpoint.name
$checkpointId = [Guid][string]$document.Value.lab_checkpoint.id
$initialTopology = [pscustomobject][ordered]@{
    Runtime = $topology.Runtime
    VmNetwork = $topology.VmNetwork
}
$supportAddress = [string]$document.Value.support.switch.host_ipv4
$initialSupport = Get-ApprovedHostSupportRuntimeState `
    -TopologyDocument $document -Address $supportAddress `
    -TcpPort $supportTcpPort -UdpPort $supportUdpPort `
    -ProcessId $supportPid -ProcessOwner $supportOwner
$credential = Import-ApprovedGuestCredential -Path $credentialPath
$initialContext = Get-ApprovedVmContext
$initialState = [string]$initialContext.Vm.State
if ($initialState -cnotin @('Off', 'Running')) {
    throw 'probe requires the approved VM to be Off or Running'
}

$startedVm = $false
$cleanupAuthority = $null
$connection = $null
$guestTopology = $null
$primaryFailure = $null
$finalizationFailures = [Collections.Generic.List[string]]::new()
try {
    if ($initialState -ceq 'Off') {
        $cleanupAuthority = New-ApprovedVmCleanupAuthority -Context $initialContext
        $startedVm = $true
        Start-ApprovedVm -TimeoutSeconds $readinessTimeoutSeconds
    }
    $connection = Connect-ApprovedGuest `
        -Credential $credential -TimeoutSeconds $readinessTimeoutSeconds
    $guestTopology = Get-ApprovedGuestSupportTopologyRuntimeState `
        -Session $connection.Session -TopologyDocument $document
} catch {
    $primaryFailure = $_
} finally {
    if ($null -ne $connection) {
        Remove-PSSession -Session $connection.Session -ErrorAction SilentlyContinue
    }
    if ($startedVm) {
        try {
            Stop-ApprovedVmEmergency `
                -Authority $cleanupAuthority -TimeoutSeconds $shutdownTimeoutSeconds
        } catch {
            $finalizationFailures.Add("probe emergency VM stop failed: $($_.Exception.Message)")
        }
    }
}

$finalVmState = $null
$finalTopology = $null
$finalSupport = $null
try {
    $finalVmState = [string](Get-ApprovedVmContext).Vm.State
    if ($finalVmState -cne $initialState) {
        throw "probe changed the approved VM state: expected=$initialState actual=$finalVmState"
    }
} catch {
    $finalizationFailures.Add("probe final VM readback failed: $($_.Exception.Message)")
}
try {
    $finalTopology = Get-ApprovedHyperVTopologyRuntimeState -TopologyDocument $document
    Assert-ApprovedHyperVTopologyRuntimeStateUnchanged `
        -Expected $initialTopology -Actual $finalTopology
} catch {
    $finalizationFailures.Add("probe topology readback failed: $($_.Exception.Message)")
}
try {
    $finalSupport = Get-ApprovedHostSupportRuntimeState `
        -TopologyDocument $document -Address $supportAddress `
        -TcpPort $supportTcpPort -UdpPort $supportUdpPort `
        -ProcessId $supportPid -ProcessOwner $supportOwner
    Assert-ApprovedHostSupportRuntimeStateUnchanged `
        -Expected $initialSupport -Actual $finalSupport
} catch {
    $finalizationFailures.Add("probe support readback failed: $($_.Exception.Message)")
}
try { Assert-ApprovedTopologyHelperSourcesUnchanged } catch {
    $finalizationFailures.Add("probe helper-source readback failed: $($_.Exception.Message)")
}
if ($null -ne $primaryFailure -or $finalizationFailures.Count -ne 0) {
    $messages = [Collections.Generic.List[string]]::new()
    if ($null -ne $primaryFailure) { $messages.Add($primaryFailure.Exception.Message) }
    foreach ($message in $finalizationFailures) { $messages.Add($message) }
    throw [InvalidOperationException]::new(($messages -join '; '))
}
[ordered]@{
    schema = 'ferrum2.windows-tun.hyperv-probe.v2'
    status = 'pass'
    vm_name = $vmName
    vm_id = $vmId.ToString('D')
    checkpoint_name = $checkpointName
    checkpoint_id = $checkpointId.ToString('D')
    initial_vm_state = $initialState.ToLowerInvariant()
    final_vm_state = $finalVmState
    guest_product = [string]$connection.Probe.Product
    guest_edition = [string]$connection.Probe.Edition
    guest_version = [string]$connection.Probe.Version
    guest_build = [string]$connection.Probe.Build
    guest_architecture = [string]$connection.Probe.Architecture
    powershell_version = [string]$connection.Probe.PowerShellVersion
    topology_manifest_sha256 = [string]$document.Sha256
    topology_plan_sha256 = [string]$document.PlanDocument.Sha256
    support_switch_id = [string]$document.Value.support.switch.switch_id
    support_host_ipv4 = $supportAddress
    support_guest = $guestTopology
    protected_host_tun = $finalTopology.Runtime.ProtectedHostTun
    support_listener = $finalSupport
    checkpoint_restored = $false
    files_staged = $false
    controller_invoked = $false
    host_tun_unchanged = $true
    host_network_mutations = 0
} | ConvertTo-Json -Compress
