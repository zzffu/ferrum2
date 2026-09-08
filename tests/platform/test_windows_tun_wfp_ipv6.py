"""Offline native-format IPv6 WFP and workload witness rejection contracts."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
OWNERS = ROOT / "tools/powershell/Ferrum2.Qualification.Host"
HARNESS = r'''
param([string]$Owners)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$ErrorActionPreference = 'Stop'
$PSModuleAutoLoadingPreference = 'None'
Import-Module Microsoft.PowerShell.Management
Import-Module Microsoft.PowerShell.Utility
. (Join-Path $Owners 'AddressFamily.ps1')
. (Join-Path $Owners 'WfpEvidence.ps1')
. (Join-Path $Owners 'WorkloadEvidence.ps1')
# Inject only native application-ID resolution. XML and witness validation are real.
Add-Type -TypeDefinition @'
public static class Ferrum2QualificationRouteNotification {
    public static byte[] ApplicationId(string path) { return new byte[] { 1, 2, 3, 4 }; }
}
'@
function Assert-True([bool]$Value, [string]$Message) { if (-not $Value) { throw $Message } }
function Assert-Rejected([scriptblock]$Action) {
    $rejected = $false
    try { & $Action | Out-Null } catch { $rejected = $true }
    Assert-True $rejected 'invalid witness accepted'
}
function Condition([string]$Field, [string]$Type, [string]$Tag, [string]$Value) {
    return "<item><fieldKey>FWPM_CONDITION_$Field</fieldKey><matchType>FWP_MATCH_EQUAL</matchType><conditionValue><type>$Type</type><$Tag>$Value</$Tag></conditionValue></item>"
}
$network = [pscustomobject]@{ address_family = 'IPv6'; tun_address = 'fd00:123:45ab:cdef::2'; peer_address = 'fd00:123:45ab:cdef::1'; tun_prefix_length = 126 }
$runtime = [pscustomobject]@{ client = [pscustomobject]@{ pid = 321 } }
$listener = [pscustomobject]@{ address_family = 'IPv6'; local_address = $network.tun_address; local_port = 50000; process_id = 321; wildcard_listener_count = 0 }
$app = Condition 'ALE_APP_ID' 'FWP_BYTE_BLOB_TYPE' 'byteBlob' '<size>4</size><data>01020304</data>'
$luid = Condition 'IP_LOCAL_INTERFACE' 'FWP_UINT64' 'uint64' '12345'
$rows = foreach ($identity in @(Get-Ferrum2QualificationStrictFilterIdentities -AddressFamily IPv6)) {
    $conditions = if ($identity.name -ceq 'Ferrum2 app permit IPv4') { $app } elseif ($identity.name -ceq 'Ferrum2 TUN permit IPv4') { $luid } else { '' }
    "<item><displayData><name>$($identity.name)</name></displayData><subLayerKey>$script:QualificationSublayerKey</subLayerKey><filterId>1</filterId><filterKey>$($identity.key)</filterKey><filterCondition>$conditions</filterCondition></item>"
}
$conditions = $app + $luid + (Condition 'IP_PROTOCOL' 'FWP_UINT8' 'uint8' '6') +
    (Condition 'IP_LOCAL_ADDRESS' 'FWP_BYTE_ARRAY16_TYPE' 'byteArray16' 'fd00:123:45ab:cdef::2') +
    (Condition 'IP_LOCAL_PORT' 'FWP_UINT16' 'uint16' '50000') +
    (Condition 'IP_REMOTE_ADDRESS' 'FWP_BYTE_ARRAY16_TYPE' 'byteArray16' 'fd00:123:45ab:cdef::1')
$text = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' + '<wfpstate><items>' + ($rows -join '') + @"
<item><displayData><name>Ferrum2 strict route</name></displayData><subLayerKey>$script:QualificationSublayerKey</subLayerKey><weight>32767</weight></item>
<item><displayData><name>Ferrum2 strict route dynamic session</name></displayData><sessionKey>$script:QualificationSessionKey</sessionKey><processId>321</processId></item>
<item><displayData><name>Ferrum2 TCP ingress dynamic session</name></displayData><sessionKey>$script:QualificationTcpIngressSessionKey</sessionKey><processId>321</processId><flags numItems="1"><item>FWPM_SESSION_FLAG_DYNAMIC</item></flags></item>
<item><displayData><name>Ferrum2 TCP ingress</name></displayData><subLayerKey>$script:QualificationTcpIngressSublayerKey</subLayerKey><weight>32768</weight></item>
<item><displayData><name>Ferrum2 TCP ingress IPv6</name></displayData><subLayerKey>$script:QualificationTcpIngressSublayerKey</subLayerKey><filterId>10</filterId><filterKey>{f37b47e8-22ab-4ee5-bc98-28e67abcde01}</filterKey><layerKey>FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6</layerKey><action><type>FWP_ACTION_PERMIT</type><filterType/></action><flags numItems="1"><item>FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT</item></flags><weight><type>FWP_UINT8</type><uint8>15</uint8></weight><effectiveWeight><type>FWP_UINT64</type><uint64>17293822569102704640</uint64></effectiveWeight><providerKey/><providerContextKey/><providerData/><reserved/><rawContext>0</rawContext><filterCondition numItems="6">$conditions</filterCondition></item>
</items></wfpstate><firewallState/>
"@
function Read-Ingress([string]$Text) {
    $document = ConvertFrom-Ferrum2QualificationWfpStateXml -Text $Text
    $strict = Get-Ferrum2QualificationStrictRouteWfpWitness -Document $document -Runtime $runtime -AddressFamily IPv6
    return Get-Ferrum2QualificationTcpIngressWfpWitness -Document $document -Runtime $runtime -Network $network -StrictRoute $strict -Listener $listener -ExecutablePath ([IO.Path]::GetFullPath('fixture.exe'))
}
'''


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is unavailable")
class WindowsTunWfpIpv6Tests(unittest.TestCase):
    def run_script(self, body: str) -> None:
        with tempfile.TemporaryDirectory(prefix="ferrum2-wfp-v6-") as temporary:
            script = Path(temporary) / "test.ps1"
            script.write_text(HARNESS + body, encoding="utf-8")
            result = subprocess.run(
                ["pwsh", "-NoProfile", "-File", str(script), str(OWNERS)],
                capture_output=True, text=True, encoding="utf-8", timeout=30, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_native_ipv6_literals_are_exact_and_canonical(self) -> None:
        self.run_script(r'''
$witness = Read-Ingress $text
Assert-True ($witness.address_family -ceq 'IPv6' -and $witness.filter.layer -ceq 'FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6' -and $witness.peer_address -ceq $network.peer_address) 'selected family lost'
$expanded = Read-Ingress ($text.Replace('fd00:123:45ab:cdef::2', 'FD00:0123:45AB:CDEF:0000:0000:0000:0002'))
$local = @($expanded.filter.conditions | Where-Object field_key -CEQ 'FWPM_CONDITION_IP_LOCAL_ADDRESS')[0]
Assert-True ($local.type -ceq 'FWP_BYTE_ARRAY16_TYPE' -and $local.value -ceq 'fd00012345abcdef0000000000000002') 'native bytes not canonicalized'
''')

    def test_ipv6_wrong_bytes_family_layer_peer_and_unknown_forms_rejected(self) -> None:
        mutations = [
            ("fd00:123:45ab:cdef::2", "fd00:123:45ab:cdef::3"),
            ("fd00:123:45ab:cdef::1", "fd00:123:45ab:cdef::9"),
            ("FWP_BYTE_ARRAY16_TYPE", "FWP_UINT32"),
            ("FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6", "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4"),
            ("fd00:123:45ab:cdef::2", "fd00012345abcdef0000000000000002"),
            ("fd00:123:45ab:cdef::2", "127.0.0.1"),
            ("fd00:123:45ab:cdef::2", "::ffff:127.0.0.1"),
            ("fd00:123:45ab:cdef::2", "fd00:123:45ab:cdef::2%0"),
            ("fd00:123:45ab:cdef::2", "<item>fd00:123:45ab:cdef::2</item>"),
            ("byteArray16", "unknownArray"),
        ]
        for old, new in mutations:
            with self.subTest(mutation=new):
                self.run_script(f"Assert-Rejected {{ Read-Ingress ($text.Replace('{old}', '{new}')) }}\n")

    def test_absent_family_block_and_all_fixed_key_cleanup(self) -> None:
        self.run_script(r'''
Read-Ingress $text | Out-Null
Assert-Rejected { Read-Ingress ($text.Replace('Ferrum2 family block IPv4', 'Ferrum2 family block IPv6').Replace('38b5e8701005', '38b5e8701006')) }
foreach ($key in $script:QualificationFilterKeys) {
    [xml]$residue = "<state><item><filterKey>$key</filterKey></item></state>"
    Assert-Rejected { Assert-Ferrum2QualificationWfpDocumentAbsent -Document $residue -Label offline -AddressFamily IPv6 }
}
''')

    def test_reset_ready_selected_family_and_endpoint_must_agree(self) -> None:
        self.run_script(r'''
$ready = [pscustomobject]@{ schema_version = 1; kind = 'ferrum2.windows-tun-reset-ready'; address_family = 'IPv6'; generation = 1; tcp_pending = $true; udp_pending = $true; tcp_paused_bytes_sent = 4096; tcp_unwritable_milliseconds = 100; udp_pending_datagrams = 1; udp_local_endpoint = '[fd00:123:45ab:cdef::2]:50000' }
Assert-Ferrum2QualificationResetReady -Witness $ready -AddressFamily IPv6
Assert-Rejected { Assert-Ferrum2QualificationResetReady -Witness $ready -AddressFamily IPv4 }
$ready.udp_local_endpoint = '198.18.1.2:50000'
Assert-Rejected { Assert-Ferrum2QualificationResetReady -Witness $ready -AddressFamily IPv6 }
$ready.udp_local_endpoint = '[fd00:123:45ab:cdef::2]:50000'
$ready.PSObject.Properties.Remove('address_family')
Assert-Rejected { Assert-Ferrum2QualificationResetReady -Witness $ready -AddressFamily IPv6 }
''')

    def test_workload_reset_and_flow_endpoint_families_are_checked(self) -> None:
        self.run_script(r'''
$witness = [pscustomobject]@{
    schema_version = 1; kind = 'ferrum2.windows-tun-qualification'; status = 'PASS'; address_family = 'IPv6'
    generations = @(foreach ($generation in 1..2) {
        [pscustomobject]@{
            generation = $generation; payload_identity = "generation-$generation"
            concurrent_flows = 4; all_flows_established_barrier = $true
            flows = @(foreach ($flow in 0..3) {
                [pscustomobject]@{
                    flow = $flow; generation = $generation
                    local_endpoint = "[fd00:123:45ab:cdef::2]:$(40000 + $generation * 4 + $flow)"
                    same_connection_phases = @('request_before', 'paused_reader', 'full_duplex', 'request_after', 'half_close')
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
        udp_local_endpoint = '[fd00:123:45ab:cdef::2]:42000'
    }
}
Assert-Ferrum2QualificationWorkloadWitness -Witness $witness -AddressFamily IPv6
foreach ($mutation in @(
    { param($w) $w.address_family = 'IPv4' },
    { param($w) $w.reset.udp_local_endpoint = '198.18.0.1:42000' },
    { param($w) $w.generations[0].flows[0].local_endpoint = '198.18.0.1:40004' },
    { param($w) $w.generations[0].flows[0].local_endpoint = '[::ffff:198.18.0.1]:40004' },
    { param($w) $w.generations[0].flows[0].fragment_replies_during_tcp = 0 },
    { param($w) $w.generations[0].flows[0].half_close_reply_checked = $false }
)) {
    $changed = $witness | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20
    & $mutation $changed
    Assert-Rejected { Assert-Ferrum2QualificationWorkloadWitness -Witness $changed -AddressFamily IPv6 }
}
''')
