function Test-SamePath([string]$Left, [string]$Right) {
    if ([string]::IsNullOrWhiteSpace($Left) -or [string]::IsNullOrWhiteSpace($Right)) {
        return $false
    }
    return [IO.Path]::GetFullPath($Left).TrimEnd('\', '/').Equals(
        [IO.Path]::GetFullPath($Right).TrimEnd('\', '/'),
        [StringComparison]::OrdinalIgnoreCase
    )
}

function Get-ResidueSnapshot {
    $workPaths = @(
        "ferrum2-m15-tun-",
        "ferrum2-m16-network-",
        "ferrum2-m16-product-",
        "ferrum2-m17-tun-"
    ) | ForEach-Object {
        [IO.Path]::GetFullPath(
            (Join-Path ([IO.Path]::GetTempPath()) "$_$($script:runToken)")
        ).TrimEnd('\', '/')
    }
    $adapterNames = @(
        "Ferrum2-M15-$($script:runToken)",
        "Ferrum2-M16-$($script:runToken)",
        "F2-M16P-A-$($script:runToken)",
        "F2-M16P-M-$($script:runToken)",
        "F2-M17-$($script:runToken)"
    )
    $executables = @($script:clientBinary, $script:serverBinary)
    $processes = @(
        Get-CimInstance -ClassName Win32_Process -ErrorAction Stop | Where-Object {
            $row = $_
            @($executables | Where-Object {
                Test-SamePath ([string]$row.ExecutablePath) $_
            }).Count -eq 1 -and
                $row.CommandLine -and
                $row.CommandLine.IndexOf("--config", [StringComparison]::Ordinal) -ge 0 -and
                @($workPaths | Where-Object {
                    $row.CommandLine.IndexOf(
                        $_ + [IO.Path]::DirectorySeparatorChar,
                        [StringComparison]::OrdinalIgnoreCase
                    ) -ge 0
                }).Count -ge 1
        }
    ).Count
    $adapters = @($adapterNames | ForEach-Object {
        $name = $_
        Get-NetAdapter -Name $name -IncludeHidden -ErrorAction SilentlyContinue |
            Where-Object {
                [string]::Equals(
                    [string]$_.Name,
                    $name,
                    [StringComparison]::OrdinalIgnoreCase
                )
            }
    }).Count
    $targets = @(
        "192.0.2.201", "2001:db8::202", "192.0.2.203", "2001:db8::204",
        "192.0.2.205", "2001:db8::206", "192.0.2.207", "2001:db8::208",
        "192.0.2.250", "192.0.2.241", "192.0.2.242", "2001:db8::241"
    )
    $addresses = @($targets | Where-Object {
        @(Get-NetIPAddress -InterfaceIndex 1 -IPAddress $_ -ErrorAction SilentlyContinue).Count -ne 0
    }).Count
    $routes = @($targets | Where-Object {
        $prefix = if ($_.Contains(":")) { "$_/128" } else { "$_/32" }
        @(Get-NetRoute -InterfaceIndex 1 -DestinationPrefix $prefix -PolicyStore ActiveStore `
            -ErrorAction SilentlyContinue).Count -ne 0
    }).Count
    $dnsRows = @($adapterNames | ForEach-Object {
        $name = $_
        Get-DnsClientServerAddress -InterfaceAlias $name -ErrorAction SilentlyContinue |
            Where-Object {
                [string]::Equals(
                    [string]$_.InterfaceAlias,
                    $name,
                    [StringComparison]::OrdinalIgnoreCase
                )
            }
    }).Count
    $journalRoot = Join-Path (
        [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    ) "Ferrum2\ControllerRunIdentities"
    $journalPath = Join-Path $journalRoot "$($script:runToken).json"
    $siblingDll = Join-Path (Split-Path -Parent $script:clientBinary) "wintun.dll"

    return [pscustomobject][ordered]@{
        processes = [long]$processes
        adapters = [long]$adapters
        target_addresses = [long]$addresses
        target_routes = [long]$routes
        dns_rows = [long]$dnsRows
        sibling_dll = [long]$(if (Test-Path -LiteralPath $siblingDll) { 1 } else { 0 })
        work_directories = [long]@(
            $workPaths | Where-Object { Test-Path -LiteralPath $_ }
        ).Count
        mutation_journals = [long]@($workPaths | Where-Object {
            Test-Path -LiteralPath (Join-Path $_ "m17-network-mutations")
        }).Count
        firewall_rules = [long]@(
            Get-NetFirewallRule -Name "Ferrum2-M17-UDP-$($script:runToken)" `
                -PolicyStore ActiveStore -ErrorAction SilentlyContinue
        ).Count
        identity_journal = [long]@(
            @($journalPath, "$journalPath.pending") | Where-Object {
                Test-Path -LiteralPath $_
            }
        ).Count
    }
}

function Assert-ZeroResidue([object]$Residue) {
    foreach ($name in @(
        "processes", "adapters", "target_addresses", "target_routes", "dns_rows",
        "sibling_dll", "work_directories", "mutation_journals", "firewall_rules",
        "identity_journal"
    )) {
        Assert-True ([long]$Residue.$name -eq 0) `
            "token-scoped cleanup residue remained: $name=$($Residue.$name)"
    }
}
