Set-StrictMode -Version Latest
$script:QualificationSessionKey = '{8ea35b4e-6629-4e26-9776-95c5bf9c6b01}'
$script:QualificationSublayerKey = '{ddbc2fa2-d52f-4a79-8a63-8446c308cf02}'
$script:QualificationFilterKeys = @(1..10 | ForEach-Object {
    '{a158b31d-7a59-40bc-9339-38b5e870100' + $_.ToString('x') + '}'
})

function Get-Ferrum2QualificationStrictFilterIdentities {
    param([ValidateSet('IPv4', 'IPv6')][string]$AddressFamily = 'IPv4')
    $names = @('Ferrum2 app permit IPv4', 'Ferrum2 app permit IPv6',
        'Ferrum2 TUN permit IPv4', 'Ferrum2 TUN permit IPv6')
    for ($index = 0; $index -lt $names.Count; $index++) {
        [pscustomobject]@{ name = $names[$index]; key = $script:QualificationFilterKeys[$index] }
    }
    $blockIndex = if ($AddressFamily -ceq 'IPv6') { 4 } else { 5 }
    $absentFamily = if ($AddressFamily -ceq 'IPv6') { 'IPv4' } else { 'IPv6' }
    [pscustomobject]@{ name = "Ferrum2 family block $absentFamily"; key = $script:QualificationFilterKeys[$blockIndex] }
}
$script:QualificationTcpIngressSessionKey = '{41b9d0c7-65ac-49a7-8d97-bf8ad5abbe01}'
$script:QualificationTcpIngressSublayerKey = '{5e741969-f578-43bd-a1e2-a420c49a7f01}'
$script:QualificationTcpIngressSessionName = 'Ferrum2 TCP ingress dynamic session'
$script:QualificationTcpIngressSublayerName = 'Ferrum2 TCP ingress'
function ConvertFrom-Ferrum2QualificationWfpStateXml {
    param([Parameter(Mandatory = $true)][string]$Text)
    $bom = [string][char]0xfeff
    if ($Text.StartsWith($bom, [StringComparison]::Ordinal)) {
        $Text = $Text.Substring(1)
    }

    $declaration = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    if (-not $Text.StartsWith($declaration, [StringComparison]::Ordinal)) {
        throw 'host qualification WFP snapshot declaration is invalid'
    }
    $document = [Xml.XmlDocument]::new()
    try {
        $document.LoadXml(
            "<ferrum2WfpState>$($Text.Substring($declaration.Length))</ferrum2WfpState>"
        )
    } catch {
        throw "host qualification WFP snapshot XML is invalid: $($_.Exception.Message)"
    }
    $rootNames = @($document.DocumentElement.ChildNodes | Where-Object {
        $_.NodeType -eq [Xml.XmlNodeType]::Element
    } | ForEach-Object { $_.LocalName })
    if (($rootNames -join '|') -cne 'wfpstate|firewallState') {
        throw 'host qualification WFP snapshot root set is invalid'
    }
    return $document
}

function Invoke-Ferrum2QualificationWfpState {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $path = Join-Path $Context.run_root "wfp-$Label.xml"
    if (Test-Path -LiteralPath $path) {
        throw 'host qualification WFP snapshot baseline must be absent'
    }
    $netsh = Join-Path ([Environment]::SystemDirectory) 'netsh.exe'
    try {
        [void](Invoke-Ferrum2OwnedCommand -Context $Context -Application $netsh `
            -Arguments "wfp show state file=`"$path`"" `
            -WorkingDirectory $Context.run_root -LogPrefix "wfp-$Label" -TimeoutSeconds 45)
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if ($item.PSIsContainer -or $item.Length -le 0 -or $item.Length -gt 64MB) {
            throw 'host qualification WFP snapshot size is invalid'
        }
        $text = Get-Content -LiteralPath $path -Raw -Encoding utf8 -ErrorAction Stop
        return ConvertFrom-Ferrum2QualificationWfpStateXml -Text $text
    } finally {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-Ferrum2QualificationWfpFlags {
    param(
        [Parameter(Mandatory = $true)][Xml.XmlElement]$Item,
        [Parameter(Mandatory = $true)][string]$Identity
    )
    $node = $Item.SelectSingleNode("./*[local-name()='flags']")
    if ($null -eq $node) { return @() }
    $leafText = @($node.SelectNodes(".//*[not(*)]") | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_.InnerText)
    } | ForEach-Object { $_.InnerText.Trim() })
    if ($leafText.Count -eq 0 -and
        -not [string]::IsNullOrWhiteSpace($node.InnerText)) {
        $leafText = @($node.InnerText.Trim())
    }
    $flags = @($leafText | ForEach-Object {
        [regex]::Matches($_, 'FWP[A-Z0-9_]+') | ForEach-Object { $_.Value }
    } | Sort-Object -Unique)
    $count = $node.GetAttribute('numItems')
    if ($count -cnotmatch '^[0-9]+$' -or [int]$count -ne $flags.Count) {
        throw "host qualification $Identity WFP flag count is not exact"
    }
    if ($flags.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($node.InnerText)) {
        throw "host qualification $Identity WFP flags are unreadable"
    }
    return $flags
}

function Get-Ferrum2QualificationWfpTypedValue {
    param(
        [Parameter(Mandatory = $true)][Xml.XmlElement]$Node,
        [Parameter(Mandatory = $true)][string]$Identity
    )
    $typeNode = $Node.SelectSingleNode("./*[local-name()='type']")
    if ($null -eq $typeNode -or [string]::IsNullOrWhiteSpace($typeNode.InnerText)) {
        throw "host qualification $Identity WFP value type is unavailable"
    }
    if ($typeNode.InnerText.Trim() -ceq 'FWP_BYTE_ARRAY16_TYPE') {
        $children = @($Node.SelectNodes("./*"))
        $arrays = @($Node.SelectNodes("./*[local-name()='byteArray16']"))
        if ($children.Count -ne 2 -or $arrays.Count -ne 1 -or
            @($arrays[0].SelectNodes("./*")).Count -ne 0) {
            throw "host qualification $Identity WFP IPv6 byte array form is unknown"
        }
        # netsh renders this sixteen-byte value as an IPv6 literal, not a hex dump.
        $literal = $arrays[0].InnerText.Trim()
        $address = $null
        if (-not [Net.IPAddress]::TryParse($literal, [ref]$address) -or
            $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetworkV6 -or
            $address.IsIPv4MappedToIPv6 -or $literal.Contains('%')) {
            throw "host qualification $Identity WFP IPv6 byte array must be an unscoped IPv6 literal"
        }
        $hex = [Convert]::ToHexString($address.GetAddressBytes()).ToLowerInvariant()
        return [pscustomobject][ordered]@{ type = 'FWP_BYTE_ARRAY16_TYPE'; value = $hex }
    }
    $valueNodes = if ($typeNode.InnerText.Trim() -ceq 'FWP_BYTE_BLOB_TYPE') {
        @($Node.SelectNodes(".//*[local-name()='byteBlob']/*[local-name()='data']"))
    } else {
        @($Node.SelectNodes(".//*[not(*)]") | Where-Object {
            $_.LocalName -notin @('type', 'size') -and
                -not [string]::IsNullOrWhiteSpace($_.InnerText)
        })
    }
    $leaves = @($valueNodes | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_.InnerText)
    } | ForEach-Object { $_.InnerText.Trim() })
    if ($leaves.Count -eq 0) {
        throw "host qualification $Identity WFP value is unavailable"
    }
    return [pscustomobject][ordered]@{
        type = $typeNode.InnerText.Trim()
        value = (($leaves -join '') -replace '\s', '')
    }
}

function Get-Ferrum2QualificationWfpCondition {
    param(
        [Parameter(Mandatory = $true)][Xml.XmlElement]$Filter,
        [Parameter(Mandatory = $true)][string]$FieldKey
    )
    $matches = @($Filter.SelectNodes(
        "./*[local-name()='filterCondition']/*[local-name()='item']"
    ) | Where-Object {
        $field = $_.SelectSingleNode("./*[local-name()='fieldKey']")
        $null -ne $field -and $field.InnerText.Trim() -ceq $FieldKey
    })
    if ($matches.Count -ne 1) {
        throw "host qualification TCP ingress WFP condition is not exact: $FieldKey"
    }
    $matchType = $matches[0].SelectSingleNode("./*[local-name()='matchType']")
    $conditionValue = $matches[0].SelectSingleNode("./*[local-name()='conditionValue']")
    if ($null -eq $matchType -or $matchType.InnerText.Trim() -cne 'FWP_MATCH_EQUAL' -or
        $null -eq $conditionValue) {
        throw "host qualification TCP ingress WFP condition comparison changed: $FieldKey"
    }
    $typed = Get-Ferrum2QualificationWfpTypedValue -Node $conditionValue `
        -Identity "condition $FieldKey"
    return [pscustomobject][ordered]@{
        field_key = $FieldKey
        match_type = 'FWP_MATCH_EQUAL'
        type = $typed.type
        value = $typed.value
    }
}

function Test-Ferrum2QualificationWfpIpv4Value {
    param(
        [Parameter(Mandatory = $true)][string]$Actual,
        [Parameter(Mandatory = $true)][string]$Expected
    )
    if ($Actual -ceq $Expected) { return $true }
    $octets = @($Expected.Split('.') | ForEach-Object { [byte]$_ })
    if ($octets.Count -ne 4) { return $false }
    [uint64]$hostOrder = ([uint64]$octets[0] -shl 24) -bor
        ([uint64]$octets[1] -shl 16) -bor ([uint64]$octets[2] -shl 8) -bor $octets[3]
    $decimal = $hostOrder.ToString([Globalization.CultureInfo]::InvariantCulture)
    $hex = '0x{0:x8}' -f $hostOrder
    return $Actual -ceq $decimal -or $Actual -ceq $hex
}

function Test-Ferrum2QualificationWfpAddressValue {
    param(
        [string]$Actual, [string]$Expected,
        [ValidateSet('IPv4', 'IPv6')][string]$AddressFamily
    )
    $profile = Get-Ferrum2AddressFamilyProfile -AddressFamily $AddressFamily
    $address = $null
    if (-not [Net.IPAddress]::TryParse($Expected, [ref]$address) -or
        $address.AddressFamily -ne $profile.socket_family -or
        $address.ToString() -cne $Expected -or $address.IsIPv4MappedToIPv6) { return $false }
    if ($AddressFamily -ceq 'IPv4') {
        return Test-Ferrum2QualificationWfpIpv4Value -Actual $Actual -Expected $Expected
    }
    return $Actual -cmatch '\A[0-9a-fA-F]{32}\z' -and
        $Actual.Equals([Convert]::ToHexString($address.GetAddressBytes()), [StringComparison]::OrdinalIgnoreCase)
}

function Test-Ferrum2QualificationWfpAppId {
    param(
        [Parameter(Mandatory = $true)][string]$Actual,
        [Parameter(Mandatory = $true)][string]$ExecutablePath
    )
    if ($Actual.Length -eq 0 -or $Actual.Length % 2 -ne 0 -or
        $Actual -cnotmatch '^[0-9a-fA-F]+$') {
        return $false
    }
    try {
        $expected = [Ferrum2QualificationRouteNotification]::ApplicationId(
            [IO.Path]::GetFullPath($ExecutablePath)
        )
        $expectedHex = [Convert]::ToHexString($expected)
        return $Actual.Equals($expectedHex, [StringComparison]::OrdinalIgnoreCase)
    } catch {
        return $false
    }
}

function Get-Ferrum2QualificationStrictRouteWfpWitness {
    param(
        [Parameter(Mandatory = $true)][Xml.XmlDocument]$Document,
        [Parameter(Mandatory = $true)][object]$Runtime,
        [ValidateSet('IPv4', 'IPv6')][string]$AddressFamily = 'IPv4'
    )
    $sublayerKey = $script:QualificationSublayerKey.ToLowerInvariant()
    $sessionKey = $script:QualificationSessionKey.ToLowerInvariant()
    $identities = @(Get-Ferrum2QualificationStrictFilterIdentities -AddressFamily $AddressFamily)
    $filters = @($Document.SelectNodes("//*[local-name()='item']") | Where-Object {
        $key = $_.SelectSingleNode("./*[local-name()='subLayerKey']")
        $id = $_.SelectSingleNode("./*[local-name()='filterId']")
        $null -ne $key -and $null -ne $id -and
            $key.InnerText.ToLowerInvariant() -ceq $sublayerKey
    })
    if ($filters.Count -ne $identities.Count) {
        throw 'host qualification strict-route WFP filter count is not exact'
    }
    $filterRows = [Collections.Generic.List[object]]::new()
    $appId = $null
    $tunLuid = $null
    foreach ($identity in $identities) {
        $expectedName = $identity.name
        $matches = @($filters | Where-Object {
            $name = $_.SelectSingleNode("./*[local-name()='displayData']/*[local-name()='name']")
            $null -ne $name -and $name.InnerText -ceq $expectedName
        })
        if ($matches.Count -ne 1) {
            throw "host qualification WFP filter identity changed: $expectedName"
        }
        $filter = $matches[0]
        $key = $filter.SelectSingleNode("./*[local-name()='filterKey']")
        $id = $filter.SelectSingleNode("./*[local-name()='filterId']")
        if ($null -eq $key -or
            $key.InnerText.ToLowerInvariant() -cne $identity.key -or
            $null -eq $id -or [string]$id.InnerText -cnotmatch '^[1-9][0-9]*$') {
            throw "host qualification WFP filter readback is invalid: $expectedName"
        }
        if ($expectedName -ceq 'Ferrum2 app permit IPv4') {
            $appId = Get-Ferrum2QualificationWfpCondition -Filter $filter `
                -FieldKey 'FWPM_CONDITION_ALE_APP_ID'
            if ($appId.type -cne 'FWP_BYTE_BLOB_TYPE') {
                throw 'host qualification strict-route application identity type changed'
            }
        } elseif ($expectedName -ceq 'Ferrum2 TUN permit IPv4') {
            $tunLuid = Get-Ferrum2QualificationWfpCondition -Filter $filter `
                -FieldKey 'FWPM_CONDITION_IP_LOCAL_INTERFACE'
            if ($tunLuid.type -cne 'FWP_UINT64' -or
                [string]$tunLuid.value -cnotmatch '^[1-9][0-9]*$') {
                throw 'host qualification strict-route TUN LUID readback changed'
            }
        }
        $filterRows.Add([pscustomobject][ordered]@{
            name = $expectedName
            key = $key.InnerText.Trim('{}').ToLowerInvariant()
            id = [string]$id.InnerText
        })
    }
    if ($null -eq $appId -or $null -eq $tunLuid) {
        throw 'host qualification strict-route comparison identities are unavailable'
    }
    $sublayers = @($Document.SelectNodes("//*[local-name()='item']") | Where-Object {
        $key = $_.SelectSingleNode("./*[local-name()='subLayerKey']")
        $id = $_.SelectSingleNode("./*[local-name()='filterId']")
        $name = $_.SelectSingleNode("./*[local-name()='displayData']/*[local-name()='name']")
        $null -ne $key -and $null -eq $id -and
            $key.InnerText.ToLowerInvariant() -ceq $sublayerKey -and
            $null -ne $name -and $name.InnerText -ceq 'Ferrum2 strict route'
    })
    if ($sublayers.Count -ne 1) {
        throw 'host qualification strict-route WFP sublayer identity is not exact'
    }
    $weightNode = $sublayers[0].SelectSingleNode("./*[local-name()='weight']")
    if ($null -eq $weightNode -or [string]::IsNullOrWhiteSpace($weightNode.InnerText)) {
        throw 'host qualification strict-route WFP sublayer weight is unavailable'
    }
    $sessions = @($Document.SelectNodes("//*[local-name()='item']") | Where-Object {
        $key = $_.SelectSingleNode("./*[local-name()='sessionKey']")
        $name = $_.SelectSingleNode("./*[local-name()='displayData']/*[local-name()='name']")
        $null -ne $key -and $key.InnerText.ToLowerInvariant() -ceq $sessionKey -and
            $null -ne $name -and $name.InnerText -ceq 'Ferrum2 strict route dynamic session'
    })
    if ($sessions.Count -ne 1) {
        throw 'host qualification strict-route WFP session identity is not exact'
    }
    $processNode = $sessions[0].SelectSingleNode("./*[local-name()='processId']")
    if ($null -eq $processNode -or [uint32]$processNode.InnerText -ne [uint32]$Runtime.client.pid) {
        throw 'host qualification strict-route WFP owner process is not exact'
    }
    return [pscustomobject][ordered]@{
        address_family = $AddressFamily
        session_key = $script:QualificationSessionKey.Trim('{}')
        sublayer_key = $script:QualificationSublayerKey.Trim('{}')
        sublayer_weight = [string]$weightNode.InnerText
        process_id = [uint32]$Runtime.client.pid
        app_id = $appId
        tun_luid = $tunLuid
        filters = @($filterRows)
    }
}

function Get-Ferrum2QualificationTcpIngressListener {
    param(
        [Parameter(Mandatory = $true)][object]$Runtime,
        [Parameter(Mandatory = $true)][object]$Network
    )
    $listeners = @(Get-NetTCPConnection -OwningProcess ([uint32]$Runtime.client.pid) `
        -State Listen -ErrorAction Stop)
    $wildcard = @($listeners | Where-Object {
        [string]$_.LocalAddress -in @('0.0.0.0', '::')
    })
    $exact = @($listeners | Where-Object {
        [string]$_.LocalAddress -ceq [string]$Network.tun_address
    })
    if ($wildcard.Count -ne 0 -or $exact.Count -ne 1 -or
        [uint16]$exact[0].LocalPort -eq 0) {
        throw 'host qualification TCP ingress listener address scope is not exact'
    }
    return [pscustomobject][ordered]@{
        address_family = [string]$Network.address_family
        local_address = [string]$exact[0].LocalAddress
        local_port = [uint16]$exact[0].LocalPort
        process_id = [uint32]$Runtime.client.pid
        wildcard_listener_count = $wildcard.Count
    }
}

function Get-Ferrum2QualificationTcpIngressWfpWitness {
    param(
        [Parameter(Mandatory = $true)][Xml.XmlDocument]$Document,
        [Parameter(Mandatory = $true)][object]$Runtime,
        [Parameter(Mandatory = $true)][object]$Network,
        [Parameter(Mandatory = $true)][object]$StrictRoute,
        [Parameter(Mandatory = $true)][object]$Listener,
        [Parameter(Mandatory = $true)][string]$ExecutablePath
    )
    $profile = Get-Ferrum2AddressFamilyProfile -AddressFamily $Network.address_family
    $filterName = "Ferrum2 TCP ingress $($profile.address_family)"
    if ($Listener.address_family -cne $profile.address_family -or
        $StrictRoute.address_family -cne $profile.address_family -or
        $Listener.local_address -cne $Network.tun_address -or
        [int]$Network.tun_prefix_length -ne $profile.tun_prefix_length) {
        throw 'host qualification TCP ingress selected family or listener identity differs'
    }
    $sessionKey = $script:QualificationTcpIngressSessionKey.ToLowerInvariant()
    $sublayerKey = $script:QualificationTcpIngressSublayerKey.ToLowerInvariant()
    $sessions = @($Document.SelectNodes("//*[local-name()='item']") | Where-Object {
        $key = $_.SelectSingleNode("./*[local-name()='sessionKey']")
        $name = $_.SelectSingleNode("./*[local-name()='displayData']/*[local-name()='name']")
        $null -ne $key -and $key.InnerText.ToLowerInvariant() -ceq $sessionKey -and
            $null -ne $name -and $name.InnerText -ceq $script:QualificationTcpIngressSessionName
    })
    if ($sessions.Count -ne 1) {
        throw 'host qualification TCP ingress WFP session identity is not exact'
    }
    $sessionProcess = $sessions[0].SelectSingleNode("./*[local-name()='processId']")
    $sessionFlags = @(Get-Ferrum2QualificationWfpFlags -Item $sessions[0] `
        -Identity 'TCP ingress session')
    if ($null -eq $sessionProcess -or
        [uint32]$sessionProcess.InnerText -ne [uint32]$Runtime.client.pid -or
        ($sessionFlags -join '|') -cne 'FWPM_SESSION_FLAG_DYNAMIC') {
        throw 'host qualification TCP ingress WFP session ownership is not exact'
    }
    $sublayers = @($Document.SelectNodes("//*[local-name()='item']") | Where-Object {
        $key = $_.SelectSingleNode("./*[local-name()='subLayerKey']")
        $id = $_.SelectSingleNode("./*[local-name()='filterId']")
        $name = $_.SelectSingleNode("./*[local-name()='displayData']/*[local-name()='name']")
        $null -ne $key -and $null -eq $id -and
            $key.InnerText.ToLowerInvariant() -ceq $sublayerKey -and
            $null -ne $name -and $name.InnerText -ceq $script:QualificationTcpIngressSublayerName
    })
    if ($sublayers.Count -ne 1) {
        throw 'host qualification TCP ingress WFP sublayer identity is not exact'
    }
    $sublayerWeight = $sublayers[0].SelectSingleNode("./*[local-name()='weight']")
    if ($null -eq $sublayerWeight -or
        $sublayerWeight.InnerText.Trim() -cnotmatch '^[1-9][0-9]{0,4}$' -or
        [uint32]$sublayerWeight.InnerText.Trim() -gt [uint16]::MaxValue) {
        throw 'host qualification TCP ingress WFP assigned sublayer weight is unavailable'
    }
    $filters = @($Document.SelectNodes("//*[local-name()='item']") | Where-Object {
        $key = $_.SelectSingleNode("./*[local-name()='subLayerKey']")
        $id = $_.SelectSingleNode("./*[local-name()='filterId']")
        $null -ne $key -and $null -ne $id -and
            $key.InnerText.ToLowerInvariant() -ceq $sublayerKey
    })
    if ($filters.Count -ne 1) {
        throw 'host qualification TCP ingress WFP filter count is not exact for selected family'
    }
    $filter = $filters[0]
    $name = $filter.SelectSingleNode("./*[local-name()='displayData']/*[local-name()='name']")
    $key = $filter.SelectSingleNode("./*[local-name()='filterKey']")
    $id = $filter.SelectSingleNode("./*[local-name()='filterId']")
    $layer = $filter.SelectSingleNode("./*[local-name()='layerKey']")
    $action = $filter.SelectSingleNode("./*[local-name()='action']/*[local-name()='type']")
    $actionFilterType =
        $filter.SelectSingleNode("./*[local-name()='action']/*[local-name()='filterType']")
    $provider = $filter.SelectSingleNode("./*[local-name()='providerKey']")
    $providerContext = $filter.SelectSingleNode("./*[local-name()='providerContextKey']")
    $providerData = $filter.SelectSingleNode("./*[local-name()='providerData']")
    $providerDataElements = if ($null -eq $providerData) {
        0
    } else {
        @($providerData.SelectNodes("./*")).Count
    }
    $reserved = $filter.SelectSingleNode("./*[local-name()='reserved']")
    $rawContext = $filter.SelectSingleNode("./*[local-name()='rawContext']")
    $filterFlags = @(Get-Ferrum2QualificationWfpFlags -Item $filter -Identity 'TCP ingress filter')
    $allowedFlags = @('FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT', 'FWPM_FILTER_FLAG_INDEXED')
    if ($null -eq $name -or $name.InnerText -cne $filterName -or
        $null -eq $key -or $null -eq $id -or
        [string]$id.InnerText -cnotmatch '^[1-9][0-9]*$' -or
        $null -eq $layer -or
        $layer.InnerText.Trim() -cne $profile.wfp_layer -or
        $null -eq $action -or $action.InnerText.Trim() -cne 'FWP_ACTION_PERMIT' -or
        $null -eq $actionFilterType -or
        @($actionFilterType.SelectNodes("./*")).Count -ne 0 -or
        -not [string]::IsNullOrWhiteSpace($actionFilterType.InnerText) -or
        'FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT' -cnotin $filterFlags -or
        @($filterFlags | Where-Object { $_ -cnotin $allowedFlags }).Count -ne 0 -or
        ($null -ne $provider -and
            (@($provider.SelectNodes("./*")).Count -ne 0 -or
                -not [string]::IsNullOrWhiteSpace($provider.InnerText))) -or
        ($null -ne $providerContext -and
            (@($providerContext.SelectNodes("./*")).Count -ne 0 -or
                -not [string]::IsNullOrWhiteSpace($providerContext.InnerText))) -or
        ($null -ne $providerData -and
            ($providerDataElements -ne 0 -or
                -not [string]::IsNullOrWhiteSpace($providerData.InnerText))) -or
        ($null -ne $reserved -and
            (@($reserved.SelectNodes("./*")).Count -ne 0 -or
                -not [string]::IsNullOrWhiteSpace($reserved.InnerText))) -or
        $null -eq $rawContext -or $rawContext.InnerText.Trim() -cne '0') {
        throw 'host qualification TCP ingress WFP filter identity or hard-permit action changed'
    }
    try {
        $filterGuid = ([Guid]$key.InnerText).ToString('D').ToLowerInvariant()
    } catch {
        throw 'host qualification TCP ingress WFP generated filter key is invalid'
    }
    if ($filterGuid -ceq [Guid]::Empty.ToString('D')) {
        throw 'host qualification TCP ingress WFP generated filter key is empty'
    }
    $weightNode = $filter.SelectSingleNode("./*[local-name()='weight']")
    $effectiveWeight = $filter.SelectSingleNode("./*[local-name()='effectiveWeight']")
    if ($null -eq $weightNode -or $null -eq $effectiveWeight) {
        throw 'host qualification TCP ingress WFP filter weight readback is unavailable'
    }
    $weight = Get-Ferrum2QualificationWfpTypedValue -Node $weightNode `
        -Identity 'TCP ingress filter weight'
    $effective = Get-Ferrum2QualificationWfpTypedValue -Node $effectiveWeight `
        -Identity 'TCP ingress effective filter weight'
    if ($weight.type -cne 'FWP_UINT8' -or $weight.value -cne '15' -or
        $effective.type -cne 'FWP_UINT64' -or
        $effective.value -cnotmatch '^[1-9][0-9]*$') {
        throw 'host qualification TCP ingress WFP filter weight changed'
    }
    $conditionList = $filter.SelectSingleNode("./*[local-name()='filterCondition']")
    $conditionNodes = if ($null -eq $conditionList) {
        @()
    } else {
        @($conditionList.SelectNodes("./*[local-name()='item']"))
    }
    $conditionCount = if ($null -eq $conditionList) {
        $null
    } else {
        $conditionList.GetAttribute('numItems')
    }
    $expectedFields = @(
        'FWPM_CONDITION_ALE_APP_ID',
        'FWPM_CONDITION_IP_LOCAL_ADDRESS',
        'FWPM_CONDITION_IP_LOCAL_INTERFACE',
        'FWPM_CONDITION_IP_LOCAL_PORT',
        'FWPM_CONDITION_IP_PROTOCOL',
        'FWPM_CONDITION_IP_REMOTE_ADDRESS'
    ) | Sort-Object
    $actualFields = @($conditionNodes | ForEach-Object {
        $_.SelectSingleNode("./*[local-name()='fieldKey']").InnerText.Trim()
    } | Sort-Object)
    if ([string]$conditionCount -cne '6' -or
        $conditionNodes.Count -ne 6 -or
        ($actualFields -join '|') -cne ($expectedFields -join '|')) {
        throw 'host qualification TCP ingress WFP condition set is not exact'
    }
    $app = Get-Ferrum2QualificationWfpCondition -Filter $filter `
        -FieldKey 'FWPM_CONDITION_ALE_APP_ID'
    $luid = Get-Ferrum2QualificationWfpCondition -Filter $filter `
        -FieldKey 'FWPM_CONDITION_IP_LOCAL_INTERFACE'
    $protocol = Get-Ferrum2QualificationWfpCondition -Filter $filter `
        -FieldKey 'FWPM_CONDITION_IP_PROTOCOL'
    $localAddress = Get-Ferrum2QualificationWfpCondition -Filter $filter `
        -FieldKey 'FWPM_CONDITION_IP_LOCAL_ADDRESS'
    $localPort = Get-Ferrum2QualificationWfpCondition -Filter $filter `
        -FieldKey 'FWPM_CONDITION_IP_LOCAL_PORT'
    $remoteAddress = Get-Ferrum2QualificationWfpCondition -Filter $filter `
        -FieldKey 'FWPM_CONDITION_IP_REMOTE_ADDRESS'
    $peerAddress = [string]$Network.peer_address
    if ($app.type -cne 'FWP_BYTE_BLOB_TYPE' -or
        $app.value -cne $StrictRoute.app_id.value -or
        -not (Test-Ferrum2QualificationWfpAppId `
            -Actual $app.value -ExecutablePath $ExecutablePath) -or
        $luid.type -cne 'FWP_UINT64' -or
        $luid.value -cne $StrictRoute.tun_luid.value -or
        $protocol.type -cne 'FWP_UINT8' -or $protocol.value -cne '6' -or
        $localAddress.type -cne $profile.wfp_address_type -or
        -not (Test-Ferrum2QualificationWfpAddressValue -AddressFamily $profile.address_family `
            -Actual $localAddress.value -Expected $Listener.local_address) -or
        $localPort.type -cne 'FWP_UINT16' -or
        [uint16]$localPort.value -ne [uint16]$Listener.local_port -or
        $remoteAddress.type -cne $profile.wfp_address_type -or
        -not (Test-Ferrum2QualificationWfpAddressValue -AddressFamily $profile.address_family `
            -Actual $remoteAddress.value -Expected $peerAddress)) {
        throw 'host qualification TCP ingress WFP condition identity changed'
    }
    return [pscustomobject][ordered]@{
        address_family = $profile.address_family
        session_key = $script:QualificationTcpIngressSessionKey.Trim('{}')
        session_flags = $sessionFlags
        sublayer_key = $script:QualificationTcpIngressSublayerKey.Trim('{}')
        sublayer_weight = [string]$sublayerWeight.InnerText
        process_id = [uint32]$Runtime.client.pid
        listener = $Listener
        peer_address = $peerAddress
        filter = [pscustomobject][ordered]@{
            name = $filterName
            key = $filterGuid
            id = [string]$id.InnerText
            layer = $profile.wfp_layer
            action = 'FWP_ACTION_PERMIT'
            flags = $filterFlags
            requested_weight = $weight
            effective_weight = $effective
            provider_key = $null
            provider_context_key = $null
            provider_data_size = 0
            reserved = $null
            raw_context = 0
            conditions = @($app, $luid, $protocol, $localAddress, $localPort, $remoteAddress)
        }
    }
}

function Get-Ferrum2QualificationLiveWfpWitness {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Runtime,
        [Parameter(Mandatory = $true)][object]$Network,
        [Parameter(Mandatory = $true)][string]$ExecutablePath,
        [Parameter(Mandatory = $true)][string]$Label
    )
    [xml]$document = Invoke-Ferrum2QualificationWfpState -Context $Context -Label $Label
    $strictRoute = Get-Ferrum2QualificationStrictRouteWfpWitness `
        -Document $document -Runtime $Runtime -AddressFamily $Network.address_family
    $interfaceLuid = [Ferrum2QualificationRouteNotification]::InterfaceLuid(
        [uint32]$Runtime.adapter.ifIndex
    )
    if ($strictRoute.tun_luid.value -cne
        $interfaceLuid.ToString([Globalization.CultureInfo]::InvariantCulture)) {
        throw 'host qualification strict-route WFP LUID does not match the run-owned TUN'
    }
    $listener = Get-Ferrum2QualificationTcpIngressListener `
        -Runtime $Runtime -Network $Network
    $tcpIngress = Get-Ferrum2QualificationTcpIngressWfpWitness `
        -Document $document -Runtime $Runtime -Network $Network `
        -StrictRoute $strictRoute -Listener $listener -ExecutablePath $ExecutablePath
    if ($Network.address_family -ceq 'IPv6') {
        $ipv4Addresses = @(Get-NetIPAddress -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop)
        if ($ipv4Addresses.Count -gt 16384) {
            throw 'qualification IPv4 address inventory exceeds its identity bound'
        }
        $ipv4Count = @($ipv4Addresses | Where-Object {
            [uint32]$_.InterfaceIndex -eq [uint32]$Runtime.adapter.ifIndex
        }).Count
        if ($ipv4Count -ne 0) {
            throw 'IPv6-only qualification TUN acquired an unconfigured IPv4 address'
        }
        $tcpIngress | Add-Member -NotePropertyName ipv4_address_count -NotePropertyValue $ipv4Count
    }
    return [pscustomobject][ordered]@{
        address_family = [string]$Network.address_family
        strict_route = $strictRoute
        tcp_ingress = $tcpIngress
    }
}

function Compare-Ferrum2QualificationTcpIngressEpoch {
    param(
        [Parameter(Mandatory = $true)][object]$Before,
        [Parameter(Mandatory = $true)][object]$After
    )
    if ($Before.address_family -cne $After.address_family -or
        $Before.listener.local_address -cne $After.listener.local_address -or
        $Before.peer_address -cne $After.peer_address -or
        $Before.process_id -ne $After.process_id -or
        $Before.listener.local_port -eq $After.listener.local_port -or
        $Before.filter.key -ceq $After.filter.key -or
        $Before.filter.id -ceq $After.filter.id) {
        throw 'host qualification TCP ingress listener epoch was not replaced exactly'
    }
    return [pscustomobject][ordered]@{
        address_family = [string]$Before.address_family
        old_filter_key = $Before.filter.key
        old_filter_id = $Before.filter.id
        old_local_port = [uint16]$Before.listener.local_port
        new_filter_key = $After.filter.key
        new_filter_id = $After.filter.id
        new_local_port = [uint16]$After.listener.local_port
        old_filter_absent_after_reset = $true
    }
}

function Assert-Ferrum2QualificationWfpDocumentAbsent {
    param(
        [Parameter(Mandatory = $true)][Xml.XmlDocument]$Document,
        [Parameter(Mandatory = $true)][string]$Label,
        [ValidateSet('IPv4', 'IPv6')][string]$AddressFamily = 'IPv4'
    )
    $keys = @(
        $script:QualificationSessionKey,
        $script:QualificationSublayerKey,
        $script:QualificationTcpIngressSessionKey,
        $script:QualificationTcpIngressSublayerKey
    ) + @($script:QualificationFilterKeys)
    $normalized = @($keys | ForEach-Object { $_.ToLowerInvariant() })
    $matches = @($Document.SelectNodes("//*[local-name()='item']") | Where-Object {
        $item = $_
        @('sessionKey', 'subLayerKey', 'filterKey') | Where-Object {
            $node = $item.SelectSingleNode("./*[local-name()='$_']")
            $null -ne $node -and $node.InnerText.ToLowerInvariant() -cin $normalized
        }
    })
    if ($matches.Count -ne 0) {
        throw 'host qualification product-owned dynamic WFP objects remain after process exit'
    }
    return [pscustomobject][ordered]@{
        address_family = $AddressFamily
        label = $Label
        strict_route_objects = 0
        tcp_ingress_objects = 0
    }
}

function Assert-Ferrum2QualificationWfpAbsent {
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][string]$Label
    )
    [xml]$document = Invoke-Ferrum2QualificationWfpState -Context $Context -Label $Label
    return Assert-Ferrum2QualificationWfpDocumentAbsent -Document $document -Label $Label -AddressFamily $Context.address_family
}
