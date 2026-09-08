[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..') `
    -ErrorAction Stop).Path
$runner = Join-Path $PSScriptRoot 'run_windows_tun_qualification_host.ps1'
$moduleRoot = Join-Path $repositoryRoot 'tools\powershell\Ferrum2.Qualification.Host'
$moduleManifest = Join-Path $moduleRoot 'Ferrum2.Qualification.Host.psd1'
$bundlePath = Join-Path $moduleRoot 'bundle.json'
. (Join-Path $moduleRoot 'SourceBundle.ps1')
$bundle = Read-Ferrum2HostQualificationSourceBundle `
    -RepositoryRoot $repositoryRoot -ManifestPath $bundlePath

$manifest = Test-ModuleManifest -Path $moduleManifest -ErrorAction Stop
Assert-True (
    (@($manifest.ExportedFunctions.Keys) -join '|') -ceq
        'Invoke-Ferrum2HostQualification'
) 'host qualification module export contract changed'
$loadedModule = Import-Module -Name $moduleManifest -Force -PassThru -ErrorAction Stop
$multiRootState = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
    '<wfpstate><sessions/></wfpstate><firewallState><dynamicKeywordAddresses/></firewallState>'
$parsedState = & $loadedModule {
    param([string]$Text)
    ConvertFrom-Ferrum2QualificationWfpStateXml -Text $Text
} $multiRootState
$parsedRootNames = @($parsedState.DocumentElement.ChildNodes | Where-Object {
    $_.NodeType -eq [Xml.XmlNodeType]::Element
} | ForEach-Object { $_.LocalName })
Assert-True ($parsedState.DocumentElement.LocalName -ceq 'ferrum2WfpState' -and
    ($parsedRootNames -join '|') -ceq 'wfpstate|firewallState') `
    'netsh multi-root WFP state parsing changed'
$parsedBomState = & $loadedModule {
    param([string]$Text)
    ConvertFrom-Ferrum2QualificationWfpStateXml -Text (([string][char]0xfeff) + $Text)
} $multiRootState
Assert-True ($parsedBomState.DocumentElement.LocalName -ceq 'ferrum2WfpState' -and
    @($parsedBomState.DocumentElement.ChildNodes | Where-Object {
        $_.NodeType -eq [Xml.XmlNodeType]::Element
    }).Count -eq 2) 'UTF-8 BOM WFP fragment parsing changed'

$tcpIngressOffline = & $loadedModule {
    function New-ConditionXml(
        [string]$Field,
        [string]$Type,
        [string]$Element,
        [string]$Value
    ) {
        return "<item><fieldKey>$Field</fieldKey><matchType>FWP_MATCH_EQUAL</matchType>" +
            "<conditionValue><type>$Type</type><$Element>$Value</$Element>" +
            '</conditionValue></item>'
    }
    $applicationPath = Join-Path ([IO.Path]::GetTempPath()) (
        "ferrum2-wfp-fixture-$([Guid]::NewGuid().ToString('N')).exe"
    )
    try {
        [IO.File]::WriteAllBytes($applicationPath, [byte[]]@(0))
        $applicationBytes =
            [Ferrum2QualificationRouteNotification]::ApplicationId($applicationPath)
        $applicationIdentity = [Text.Encoding]::Unicode.GetString($applicationBytes)
        $appBlob = [Convert]::ToHexString($applicationBytes)
        $appBlobXml = "<size>$($appBlob.Length / 2)</size><data>$appBlob</data>"
        $wrongApplicationIdentity =
            $applicationIdentity.TrimEnd([char]0) + '.mismatch' + [char]0
        $wrongAppBlob = [Convert]::ToHexString(
            [Text.Encoding]::Unicode.GetBytes($wrongApplicationIdentity)
        )
        $wrongVolumeIdentity = [regex]::Replace(
            $applicationIdentity,
            '^\\device\\[^\\]+',
            '\device\ferrum2-wrong-volume',
            [Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
        if ($wrongVolumeIdentity -ceq $applicationIdentity) {
            throw 'fixture application ID did not contain an NT volume identity'
        }
        $wrongVolumeBlob = [Convert]::ToHexString(
            [Text.Encoding]::Unicode.GetBytes($wrongVolumeIdentity)
        )
    $strictRows = [Collections.Generic.List[string]]::new()
    $names = @(
        'Ferrum2 app permit IPv4',
        'Ferrum2 app permit IPv6',
        'Ferrum2 TUN permit IPv4',
        'Ferrum2 TUN permit IPv6',
        'Ferrum2 family block IPv6'
    )
    $keys = @(
        '{a158b31d-7a59-40bc-9339-38b5e8701001}',
        '{a158b31d-7a59-40bc-9339-38b5e8701002}',
        '{a158b31d-7a59-40bc-9339-38b5e8701003}',
        '{a158b31d-7a59-40bc-9339-38b5e8701004}',
        '{a158b31d-7a59-40bc-9339-38b5e8701006}'
    )
    foreach ($index in 0..4) {
        $condition = switch ($index) {
            0 {
                New-ConditionXml 'FWPM_CONDITION_ALE_APP_ID' 'FWP_BYTE_BLOB_TYPE' `
                    'byteBlob' $appBlobXml
            }
            2 {
                New-ConditionXml 'FWPM_CONDITION_IP_LOCAL_INTERFACE' 'FWP_UINT64' `
                    'uint64' '42'
            }
            default { '' }
        }
        $strictRows.Add(
            "<item><filterKey>$($keys[$index])</filterKey>" +
            "<displayData><name>$($names[$index])</name></displayData>" +
            "<subLayerKey>{ddbc2fa2-d52f-4a79-8a63-8446c308cf02}</subLayerKey>" +
            "<filterId>$($index + 100)</filterId><filterCondition>$condition</filterCondition></item>"
        )
    }
    $ingressConditions = @(
        (New-ConditionXml 'FWPM_CONDITION_ALE_APP_ID' 'FWP_BYTE_BLOB_TYPE' `
            'byteBlob' $appBlobXml),
        (New-ConditionXml 'FWPM_CONDITION_IP_LOCAL_INTERFACE' 'FWP_UINT64' 'uint64' '42'),
        (New-ConditionXml 'FWPM_CONDITION_IP_PROTOCOL' 'FWP_UINT8' 'uint8' '6'),
        (New-ConditionXml 'FWPM_CONDITION_IP_LOCAL_ADDRESS' 'FWP_UINT32' `
            'uint32' '198.18.1.2'),
        (New-ConditionXml 'FWPM_CONDITION_IP_LOCAL_PORT' 'FWP_UINT16' 'uint16' '45000'),
        (New-ConditionXml 'FWPM_CONDITION_IP_REMOTE_ADDRESS' 'FWP_UINT32' `
            'uint32' '198.18.1.1')
    ) -join ''
    $text = '<ferrum2WfpState><items>' + ($strictRows -join '') +
        '<item><displayData><name>Ferrum2 strict route</name></displayData>' +
        '<subLayerKey>{ddbc2fa2-d52f-4a79-8a63-8446c308cf02}</subLayerKey>' +
        '<weight>32767</weight></item>' +
        '<item><displayData><name>Ferrum2 strict route dynamic session</name></displayData>' +
        '<sessionKey>{8ea35b4e-6629-4e26-9776-95c5bf9c6b01}</sessionKey>' +
        '<processId>321</processId><flags numItems="1"><item>FWPM_SESSION_FLAG_DYNAMIC</item></flags></item>' +
        '<item><displayData><name>Ferrum2 TCP ingress</name></displayData>' +
        '<subLayerKey>{5e741969-f578-43bd-a1e2-a420c49a7f01}</subLayerKey>' +
        '<weight>32766</weight></item>' +
        '<item><displayData><name>Ferrum2 TCP ingress dynamic session</name></displayData>' +
        '<sessionKey>{41b9d0c7-65ac-49a7-8d97-bf8ad5abbe01}</sessionKey>' +
        '<processId>321</processId><flags numItems="1"><item>FWPM_SESSION_FLAG_DYNAMIC</item></flags></item>' +
        '<item><filterKey>{a158b31d-7a59-40bc-9339-38b5e8701010}</filterKey>' +
        '<displayData><name>Ferrum2 TCP ingress IPv4</name></displayData>' +
        '<layerKey>FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4</layerKey>' +
        '<subLayerKey>{5e741969-f578-43bd-a1e2-a420c49a7f01}</subLayerKey>' +
        '<weight><type>FWP_UINT8</type><uint8>15</uint8></weight>' +
        '<effectiveWeight><type>FWP_UINT64</type><uint64>983040</uint64></effectiveWeight>' +
        '<filterId>200</filterId><providerKey/><providerData/>' +
        '<flags numItems="2"><item>FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT</item>' +
        '<item>FWPM_FILTER_FLAG_INDEXED</item></flags>' +
        '<action><type>FWP_ACTION_PERMIT</type><filterType/></action>' +
        '<reserved/><rawContext>0</rawContext>' +
        "<filterCondition numItems=`"6`">$ingressConditions</filterCondition></item></items></ferrum2WfpState>"
    $runtime = [pscustomobject]@{ client = [pscustomobject]@{ pid = 321 } }
    $network = [pscustomobject]@{ tun_address = '198.18.1.2'; tun_prefix_length = 30 }
    $listener = [pscustomobject]@{
        address_family = 'IPv4'; local_address = '198.18.1.2'; local_port = 45000
        process_id = 321; wildcard_listener_count = 0
    }
    [xml]$document = $text
    $strict = Get-Ferrum2QualificationStrictRouteWfpWitness `
        -Document $document -Runtime $runtime
    $ingress = Get-Ferrum2QualificationTcpIngressWfpWitness `
        -Document $document -Runtime $runtime -Network $network `
        -StrictRoute $strict -Listener $listener -ExecutablePath $applicationPath
    $after = $ingress | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20
    $after.filter.key = 'a158b31d-7a59-40bc-9339-38b5e8701011'
    $after.filter.id = '201'
    $after.listener.local_port = 45001
    $epoch = Compare-Ferrum2QualificationTcpIngressEpoch -Before $ingress -After $after
    $unchangedRejected = $false
    try {
        [void](Compare-Ferrum2QualificationTcpIngressEpoch -Before $ingress -After $ingress)
    } catch { $unchangedRejected = $true }
    function Test-IngressXmlRejected([string]$Candidate) {
        try {
            [xml]$candidateDocument = $Candidate
            $candidateStrict = Get-Ferrum2QualificationStrictRouteWfpWitness `
                -Document $candidateDocument -Runtime $runtime
            [void](Get-Ferrum2QualificationTcpIngressWfpWitness `
                -Document $candidateDocument -Runtime $runtime -Network $network `
                -StrictRoute $candidateStrict -Listener $listener `
                -ExecutablePath $applicationPath)
            return $false
        } catch { return $true }
    }
    [xml]$empty = '<ferrum2WfpState><items/></ferrum2WfpState>'
    $absent = Assert-Ferrum2QualificationWfpDocumentAbsent -Document $empty -Label 'offline'
    $residueRejected = $false
    try {
        [void](Assert-Ferrum2QualificationWfpDocumentAbsent -Document $document -Label 'offline')
    } catch { $residueRejected = $true }
    return [pscustomobject]@{
        action = $ingress.filter.action
        layer = $ingress.filter.layer
        conditions = @($ingress.filter.conditions).Count
        old_absent = $epoch.old_filter_absent_after_reset
        unchanged_rejected = $unchangedRejected
        missing_hard_permit_rejected = Test-IngressXmlRejected (
            $text.Replace('FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT',
                'FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED')
        )
        wrong_peer_rejected = Test-IngressXmlRejected (
            $text.Replace('<uint32>198.18.1.1</uint32>', '<uint32>198.18.1.9</uint32>')
        )
        widened_filter_rejected = Test-IngressXmlRejected (
            [regex]::Replace(
                $text,
                '<item><fieldKey>FWPM_CONDITION_IP_REMOTE_ADDRESS</fieldKey>.*?</item>',
                ''
            )
        )
        application_mismatch_rejected = Test-IngressXmlRejected (
            $text.Replace($appBlob, $wrongAppBlob)
        )
        wrong_volume_rejected = Test-IngressXmlRejected (
            $text.Replace($appBlob, $wrongVolumeBlob)
        )
        absence = $absent.tcp_ingress_objects
        residue_rejected = $residueRejected
    }
    } finally {
        Remove-Item -LiteralPath $applicationPath -Force -ErrorAction SilentlyContinue
    }
}
Assert-True (
    $tcpIngressOffline.action -ceq 'FWP_ACTION_PERMIT' -and
    $tcpIngressOffline.layer -ceq 'FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4' -and
    $tcpIngressOffline.conditions -eq 6 -and
    $tcpIngressOffline.old_absent -eq $true -and
    $tcpIngressOffline.unchanged_rejected -eq $true -and
    $tcpIngressOffline.missing_hard_permit_rejected -eq $true -and
    $tcpIngressOffline.wrong_peer_rejected -eq $true -and
    $tcpIngressOffline.widened_filter_rejected -eq $true -and
    $tcpIngressOffline.application_mismatch_rejected -eq $true -and
    $tcpIngressOffline.wrong_volume_rejected -eq $true -and
    $tcpIngressOffline.absence -eq 0 -and
    $tcpIngressOffline.residue_rejected -eq $true
) 'TCP ingress WFP identity, isolation, epoch, or rollback contract changed'

. (Join-Path $moduleRoot 'WorkloadEvidence.ps1')
$readyWitness = [pscustomobject]@{
    schema_version = 1; kind = 'ferrum2.windows-tun-reset-ready'; generation = 1
    tcp_pending = $true; udp_pending = $true; tcp_paused_bytes_sent = 65536
    tcp_unwritable_milliseconds = 100; udp_pending_datagrams = 1
    udp_local_endpoint = '198.18.0.1:42000'
}
Assert-Ferrum2QualificationResetReady -Witness $readyWitness
$trafficWitness = [pscustomobject]@{
    schema_version = 1; kind = 'ferrum2.windows-tun-qualification'; status = 'PASS'
    generations = @(foreach ($generation in 1..2) {
        [pscustomobject]@{
            generation = $generation; payload_identity = "generation-$generation"
            concurrent_flows = 4
            all_flows_established_barrier = $true
            flows = @(foreach ($flow in 0..3) {
                [pscustomobject]@{
                    flow = $flow; generation = $generation
                    local_endpoint = "198.18.0.1:$(40000 + $generation * 4 + $flow)"
                    same_connection_phases = @(
                        'request_before', 'paused_reader', 'full_duplex', 'request_after', 'half_close')
                    bulk_bytes = 8388608; paused_bytes_sent = 65536
                    paused_unwritable_milliseconds = 100; resumed_bytes_sent = 8323072
                    checked_tcp_bytes = 8391680; udp_replies_during_tcp = 4
                    fragment_replies_during_tcp = 4; fragment_request_bytes = 4096
                    payload_exact = $true; half_close_reply_checked = $true; remote_eof = $true
                }
            })
        }
    })
    reset = [pscustomobject]@{
        ready_generation = 1; release_generation = 2; old_tcp_retired = $true
        old_tcp_retirement = 'reset'; old_tcp_pending_bytes = 65536; old_tcp_drained_bytes = 0
        old_udp_pending_datagrams = 1; old_udp_buffered_replies = 1
        same_tuple_udp_fresh_reply_checked = $true; udp_fresh_payload_identity = 'generation-2'
        udp_local_endpoint = '198.18.0.1:42000'
    }
}
Assert-Ferrum2QualificationWorkloadWitness -Witness $trafficWitness
foreach ($mutation in @(
    { param($w) $w.generations = @($w.generations[0]) },
    { param($w) $w.generations[0].all_flows_established_barrier = $false },
    { param($w) $w.generations[1].payload_identity = 'generation-1' },
    { param($w) $w.generations[1].flows[0].local_endpoint = $w.generations[0].flows[0].local_endpoint },
    { param($w) $w.generations[0].flows[0].paused_bytes_sent = 0 },
    { param($w) $w.generations[0].flows[0].resumed_bytes_sent = 1 },
    { param($w) $w.generations[0].flows[0].udp_replies_during_tcp = 0 },
    { param($w) $w.generations[0].flows[0].fragment_replies_during_tcp = 0 },
    { param($w) $w.generations[0].flows[0].half_close_reply_checked = $false },
    { param($w) $w.generations[0].flows[0].payload_exact = $false },
    { param($w) $w.reset.old_tcp_retirement = 'timeout' },
    { param($w) $w.reset.old_tcp_retired = $false },
    { param($w) $w.reset.same_tuple_udp_fresh_reply_checked = $false },
    { param($w) $w.reset.udp_fresh_payload_identity = 'generation-1' },
    { param($w) $w.reset.old_udp_buffered_replies = 2 },
    { param($w) $w.reset.old_udp_pending_datagrams = 0 }
)) {
    $changed = $trafficWitness | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20
    & $mutation $changed
    $rejected = $false
    try { Assert-Ferrum2QualificationWorkloadWitness -Witness $changed } catch { $rejected = $true }
    Assert-True $rejected 'incomplete or stale workload evidence was accepted'
}
$readyWitness.tcp_pending = $false
$rejected = $false
try { Assert-Ferrum2QualificationResetReady -Witness $readyWitness } catch { $rejected = $true }
Assert-True $rejected 'idle reset was accepted as active work'


$candidateSha = (& git -C $repositoryRoot rev-parse HEAD).Trim()
Assert-True ($LASTEXITCODE -eq 0 -and $candidateSha -cmatch '^[0-9a-f]{40}$') `
    'current candidate SHA is unavailable'
$pwsh = [string](Get-Command pwsh -CommandType Application -ErrorAction Stop).Source
$planOutput = & $pwsh -NoProfile -File $runner -PlanOnly -CandidateSha $candidateSha
Assert-True ($LASTEXITCODE -eq 0) 'host qualification PlanOnly failed'
$plan = ($planOutput -join "`n") | ConvertFrom-Json -Depth 12 -ErrorAction Stop
Assert-True ($plan.kind -ceq 'ferrum2.windows-tun.host-qualification-plan' -and
    $plan.execution -ceq 'explicit-authorized-windows-host' -and
    $plan.candidate_sha -ceq $candidateSha -and
    $plan.qualification_source_bundle_sha256 -ceq $bundle.sha256 -and
    [int]$plan.maximum_elapsed_seconds -eq 900 -and
    [int]$plan.worker_timeout_seconds -eq 840 -and
    [int]$plan.build_timeout_seconds -eq 600 -and
    (@($plan.checks) -join '|') -ceq (
        'single-candidate-build|wintun-create-and-delete|' +
        'system-tcp-and-udp-through-owned-tun|narrow-route-isolation|' +
        'exact-tcp-ingress-wfp-live-readback|' +
        'network-reset-retains-strict-route-and-replaces-tcp-ingress-epoch|' +
        'forced-process-tree-recovery|zero-residue-cleanup'
    ) -and
    $plan.safety.requires_elevation -eq $true -and
    $plan.safety.requires_explicit_acknowledgement -eq $true -and
    $plan.safety.automatic_elevation -eq $false -and
    $plan.safety.live_address_family -ceq 'IPv4 only (RFC2544 198.18.0.0/15)' -and
    $plan.safety.route_scope -ceq 'run-owned /32 only' -and
    $plan.safety.tcp_ingress_scope -ceq
        'exact app, TCP, TUN LUID, local address/port, and remote peer' -and
    $plan.safety.wfp_lifetime -ceq 'process-owned dynamic sessions only' -and
    $plan.safety.tcp_ingress_installation -ceq
        'automatic after listener bind and before admission' -and
    @($plan.safety.mutations) -contains
        'process-owned dynamic exact TCP ingress WFP session' -and
    $plan.safety.firewall_rule_store -ceq 'PersistentStore with exact ActiveStore readback' -and
    @($plan.safety.mutations) -contains 'run-owned narrowly scoped Windows Firewall rules before executable launch' -and
    @($plan.safety.forbidden_mutations) -contains 'unrelated Windows Firewall rules' -and
    @($plan.safety.forbidden_mutations) -contains 'global firewall profile/notification settings' -and
    @($plan.safety.forbidden_mutations) -contains 'unrelated WFP sessions') `
    'host qualification plan contract changed'

$missingAckEvidence = Join-Path ([IO.Path]::GetTempPath()) (
    'ferrum2-qualification-missing-ack-' + [Guid]::NewGuid().ToString('N')
)
$missingAckOutput = @(& $pwsh -NoProfile -File $runner -CandidateSha $candidateSha `
    -EvidenceDirectory $missingAckEvidence 2>&1)
Assert-True ($LASTEXITCODE -ne 0 -and
    ($missingAckOutput -join "`n") -match 'requires -AcknowledgeHostNetworkMutation' -and
    -not (Test-Path -LiteralPath $missingAckEvidence)) `
    'host qualification did not reject missing mutation acknowledgement before effects'

$obsoletePlatformFiles = @(
    Get-ChildItem -LiteralPath $PSScriptRoot -File -ErrorAction Stop | Where-Object {
        $_.Name -match '^(?:Main\.|Hard\.|Guest\.)' -or
        $_.Name -match 'hyperv' -or
        $_.Name -in @(
            'qualify_windows_tun.ps1',
            'qualify_windows_tun_cleanup.ps1',
            'qualify_windows_tun_hard_kill.ps1'
        )
    }
)
Assert-True ($obsoletePlatformFiles.Count -eq 0) `
    'obsolete Hyper-V qualification sources remain'
foreach ($path in @(
    'tools\powershell\Ferrum2.WindowsTun.Lab',
    'tools\powershell\Ferrum2.Qualification.Evidence',
    'tools\powershell\Ferrum2.Qualification.HostHyperV',
    'tools\powershell\Ferrum2.Qualification.GuestController',
    'tools\windows-tun\lab'
)) {
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $repositoryRoot $path))) `
        "obsolete Hyper-V qualification module remains: $path"
}

Write-Output (
    'windows_tun_host_qualification_static status=PASS ' +
    "source_bundle_sha256=$($bundle.sha256) max_elapsed_seconds=900"
)
