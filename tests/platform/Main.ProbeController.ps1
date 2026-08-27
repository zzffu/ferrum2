param([Parameter(Mandatory)] [Collections.IDictionary]$Context)

$expectedFields = @(
    'repository_root', 'topology_manifest_path', 'topology_manifest_sha256',
    'support_tcp_port', 'support_udp_port', 'support_pid', 'support_owner',
    'credential_path', 'readiness_timeout_seconds', 'shutdown_timeout_seconds'
)
Assert-Ferrum2ClosedProperties $Context $expectedFields 'main probe context'
$repositoryRoot = [string]$Context.repository_root
$topologyManifestPath = [string]$Context.topology_manifest_path
$topologyManifestSha256 = [string]$Context.topology_manifest_sha256
$supportTcpPort = [int]$Context.support_tcp_port
$supportUdpPort = [int]$Context.support_udp_port
$supportPid = [int]$Context.support_pid
$supportOwner = [string]$Context.support_owner
$credentialPath = [string]$Context.credential_path
$readinessTimeoutSeconds = [int]$Context.readiness_timeout_seconds
$shutdownTimeoutSeconds = [int]$Context.shutdown_timeout_seconds

if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows
    ) -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'X64' -or
    [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne 'X64') {
    throw 'the Hyper-V probe supervisor requires 64-bit Windows AMD64'
}
[void](Initialize-Ferrum2HostHyperVModule -RepositoryRoot $repositoryRoot)
$topology = Initialize-ApprovedHyperVTopology `
    -ManifestPath $topologyManifestPath -ExpectedSha256 $topologyManifestSha256
$document = $topology.Document
$vmName = [string]$document.Value.vm.name
$vmId = [Guid][string]$document.Value.vm.id
$supportAddress = [string]$document.Value.support.switch.host_ipv4
[void](Get-ApprovedHostSupportRuntimeState `
    -TopologyDocument $document -Address $supportAddress `
    -TcpPort $supportTcpPort -UdpPort $supportUdpPort `
    -ProcessId $supportPid -ProcessOwner $supportOwner)
$initialContext = Get-ApprovedVmContext
$initialState = [string]$initialContext.Vm.State
if ($initialState -cnotin @('Off', 'Running')) {
    throw 'probe requires the approved VM to be Off or Running'
}
$cleanupAuthority = if ($initialState -ceq 'Off') {
    New-ApprovedVmCleanupAuthority -Context $initialContext
} else { $null }
$workerParameters = [ordered]@{
    TopologyManifestPath = $document.Path
    TopologyManifestSha256 = $document.Sha256
    SupportTcpPort = $supportTcpPort
    SupportUdpPort = $supportUdpPort
    SupportPid = $supportPid
    SupportOwner = $supportOwner
    ReadinessTimeoutSeconds = $readinessTimeoutSeconds
    ShutdownTimeoutSeconds = $shutdownTimeoutSeconds
}
if (-not [string]::IsNullOrWhiteSpace($credentialPath)) {
    $workerParameters.CredentialPath = $credentialPath
}
$terminal = Invoke-BoundedHyperVWorkerSupervisor `
    -ScriptPath (Join-Path $repositoryRoot `
        'tests/platform/invoke_windows_tun_hyperv_probe_worker.ps1') `
    -BoundParameters $workerParameters `
    -ForwardedParameterNames @(
        'TopologyManifestPath', 'TopologyManifestSha256', 'SupportTcpPort',
        'SupportUdpPort', 'SupportPid', 'SupportOwner', 'CredentialPath',
        'ReadinessTimeoutSeconds', 'ShutdownTimeoutSeconds'
    ) `
    -WorkerTimeoutSeconds 1800 `
    -ShutdownTimeoutSeconds $shutdownTimeoutSeconds `
    -ExpectedVmId $vmId -ExpectedVmName $vmName `
    -ExpectedFinalState $initialState `
    -CleanupAuthority $cleanupAuthority -CleanupMode StopOnly `
    -WorkerContract Probe -FailureManifestPath $null `
    -Label 'Windows TUN HyperV probe'
Write-Output $terminal
