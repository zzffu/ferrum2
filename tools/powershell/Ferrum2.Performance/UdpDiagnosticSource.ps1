function Get-DiagnosticSourcePreflight {
    param([string]$AdapterName)
    $violations = [Collections.Generic.List[string]]::new()
    $errors = [Collections.Generic.List[string]]::new()
    $adapterRows = @()
    try {
        $adapterRows = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
            [string]$_.Name -ceq $AdapterName
        })
        if ($adapterRows.Count -ne 1) {
            $violations.Add("adapter_identity")
        } elseif ([string]$adapterRows[0].Status -cne "Up") {
            $violations.Add("adapter_not_up")
        }
    } catch {
        $violations.Add("adapter_query")
        $errors.Add("adapter query: $($_.Exception.Message)")
    }
    $adapterEvidence = @($adapterRows | Select-Object -First 16 | ForEach-Object {
        [ordered]@{
            name = [string]$_.Name
            interface_description = [string]$_.InterfaceDescription
            interface_index = [int]$_.ifIndex
            status = [string]$_.Status
            mac_address = [string]$_.MacAddress
        }
    })
    $adapterInterfaceIndex = if ($adapterRows.Count -eq 1) {
        [int]$adapterRows[0].ifIndex
    } else {
        $null
    }

    $ipRows = @()
    try {
        $ipRows = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object {
            [string]$_.IPAddress -ceq $script:diagnosticSourceIpv4
        })
        if ($ipRows.Count -ne 1) {
            $violations.Add("source_ip_identity")
        } else {
            if ([int]$ipRows[0].PrefixLength -ne 30) {
                $violations.Add("source_ip_prefix")
            }
            if ($null -eq $adapterInterfaceIndex -or
                [int]$ipRows[0].InterfaceIndex -ne $adapterInterfaceIndex) {
                $violations.Add("source_ip_owner")
            }
        }
    } catch {
        $violations.Add("source_ip_query")
        $errors.Add("source IP query: $($_.Exception.Message)")
    }
    $ipEvidence = @($ipRows | Select-Object -First 16 | ForEach-Object {
        [ordered]@{
            ip_address = [string]$_.IPAddress
            prefix_length = [int]$_.PrefixLength
            interface_index = [int]$_.InterfaceIndex
            interface_alias = [string]$_.InterfaceAlias
            address_state = [string]$_.AddressState
            prefix_origin = [string]$_.PrefixOrigin
            suffix_origin = [string]$_.SuffixOrigin
        }
    })

    $conflictRows = @()
    try {
        $conflictRows = @(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object {
            [int]$_.LocalPort -ge $script:diagnosticSourcePortFirst -and
            [int]$_.LocalPort -le $script:diagnosticSourcePortLast
        } | Sort-Object LocalPort, LocalAddress, OwningProcess)
        if ($conflictRows.Count -ne 0) {
            $violations.Add("source_port_conflict")
        }
    } catch {
        $violations.Add("udp_endpoint_query")
        $errors.Add("UDP endpoint query: $($_.Exception.Message)")
    }
    $conflictEvidence = @($conflictRows | Select-Object -First 256 | ForEach-Object {
        [ordered]@{
            local_address = [string]$_.LocalAddress
            local_port = [int]$_.LocalPort
            owning_process = [int]$_.OwningProcess
        }
    })

    $dynamicSnapshot = $null
    $dynamicRange = $null
    $dynamicIntersects = $null
    try {
        $dynamicSnapshot = Invoke-NetshBounded @(
            "interface", "ipv4", "show", "dynamicport", "udp"
        )
        $dynamicRange = ConvertFrom-NetshUdpDynamicPortRange -Snapshot $dynamicSnapshot
        $dynamicIntersects = Test-PortRangeIntersection `
            -FirstA $script:diagnosticSourcePortFirst `
            -LastA $script:diagnosticSourcePortLast `
            -FirstB ([int]$dynamicRange.first_port) `
            -LastB ([int]$dynamicRange.last_port)
        if ($dynamicIntersects) {
            $violations.Add("dynamic_port_intersection")
        }
    } catch {
        $violations.Add("dynamic_port_query_or_parse")
        $errors.Add("UDP dynamic-port query: $($_.Exception.Message)")
    }

    $excludedSnapshot = $null
    $excludedRanges = @()
    $excludedIntersections = [Collections.Generic.List[object]]::new()
    try {
        $excludedSnapshot = Invoke-NetshBounded @(
            "interface", "ipv4", "show", "excludedportrange", "protocol=udp"
        )
        $excludedRanges = @(ConvertFrom-NetshUdpExcludedPortRangeOutput `
            -Snapshot $excludedSnapshot)
        foreach ($range in $excludedRanges) {
            if (Test-PortRangeIntersection `
                    -FirstA $script:diagnosticSourcePortFirst `
                    -LastA $script:diagnosticSourcePortLast `
                    -FirstB ([int]$range.first_port) `
                    -LastB ([int]$range.last_port)) {
                $excludedIntersections.Add($range)
            }
        }
        if ($excludedIntersections.Count -ne 0) {
            $violations.Add("excluded_port_intersection")
        }
    } catch {
        $violations.Add("excluded_port_query_or_parse")
        $errors.Add("UDP excluded-port query: $($_.Exception.Message)")
    }

    return [ordered]@{
        schema = "ferrum2.windows-tun.udp-fixed-source-preflight.v1"
        captured_utc = [DateTime]::UtcNow.ToString("o")
        source_contract = [ordered]@{
            adapter_name = $AdapterName
            source_ip = $script:diagnosticSourceIpv4
            source_prefix_length = 30
            source_port_first = $script:diagnosticSourcePortFirst
            source_port_last = $script:diagnosticSourcePortLast
            source_port_count = $script:diagnosticSourcePortCount
        }
        adapter = [ordered]@{
            match_count = $adapterRows.Count
            retained_count = $adapterEvidence.Count
            matches = $adapterEvidence
        }
        ip_owner = [ordered]@{
            match_count = $ipRows.Count
            retained_count = $ipEvidence.Count
            matches = $ipEvidence
        }
        udp_endpoint_conflicts = [ordered]@{
            count = $conflictRows.Count
            retained_count = $conflictEvidence.Count
            truncated = $conflictRows.Count -gt $conflictEvidence.Count
            endpoints = $conflictEvidence
        }
        dynamic_port_udp = $dynamicSnapshot
        dynamic_port_range = $dynamicRange
        dynamic_port_intersects_source = $dynamicIntersects
        excluded_port_ranges_udp = $excludedSnapshot
        excluded_port_ranges = $excludedRanges
        excluded_port_intersections = $excludedIntersections.ToArray()
        valid = $violations.Count -eq 0
        violations = $violations.ToArray()
        errors = $errors.ToArray()
    }
}
