function Get-Tcp08MonotonicSample {
    $timestamp = [Diagnostics.Stopwatch]::GetTimestamp()
    return [ordered]@{
        monotonic_ticks = $timestamp
        elapsed_ms = Get-Tcp08ElapsedMilliseconds $timestamp
    }
}

function Write-Tcp08Json([string]$Name, [object]$Value) {
    if (-not $script:tcp08ArtifactInitialized) { return }
    $path = Join-Path $script:tcp08ArtifactPath $Name
    $Value | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding utf8NoBOM
}

function Get-Tcp08ProcessSnapshot {
    $captured = Get-Tcp08MonotonicSample
    $controller = Get-Process -Id $PID -ErrorAction Stop
    $products = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        $_.ExecutablePath -and @($script:binary, $script:serverBinary) -contains $_.ExecutablePath
    } | ForEach-Object {
        [ordered]@{
            process_id = [uint32]$_.ProcessId
            parent_process_id = [uint32]$_.ParentProcessId
            name = [string]$_.Name
            executable_path = [string]$_.ExecutablePath
            creation_date = if ($_.CreationDate) { ([DateTime]$_.CreationDate).ToUniversalTime().ToString("o") } else { $null }
        }
    })
    return [ordered]@{
        captured_monotonic_ticks = $captured.monotonic_ticks
        captured_elapsed_ms = $captured.elapsed_ms
        controller = [ordered]@{
            process_id = [uint32]$PID
            name = $controller.ProcessName
            start_time_utc = $controller.StartTime.ToUniversalTime().ToString("o")
        }
        products = $products
    }
}

function Get-Tcp08ResidueNetworkSnapshot {
    $captured = Get-Tcp08MonotonicSample
    $testAddresses = @(
        "198.18.0.2", "fd00::2", "192.0.2.201", "2001:db8::202", "192.0.2.203",
        "2001:db8::204", "192.0.2.205", "2001:db8::206", "192.0.2.207", "2001:db8::208",
        "192.0.2.250", "192.0.2.241", "192.0.2.242", "2001:db8::241"
    )
    $adapterNames = @($script:adapterName, $script:managedAutoAdapterName, $script:managedManualAdapterName)
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object {
        $adapterNames -contains $_.Name
    } | ForEach-Object {
        [ordered]@{ name = $_.Name; interface_index = [int]$_.ifIndex; status = [string]$_.Status }
    })
    $addresses = @(Get-NetIPAddress -ErrorAction SilentlyContinue | Where-Object {
        $adapterNames -contains $_.InterfaceAlias -or $testAddresses -contains $_.IPAddress
    } | ForEach-Object {
        [ordered]@{
            interface_index = [int]$_.InterfaceIndex
            interface_alias = [string]$_.InterfaceAlias
            address_family = [string]$_.AddressFamily
            ip_address = [string]$_.IPAddress
            prefix_length = [int]$_.PrefixLength
            address_state = [string]$_.AddressState
        }
    })
    $routes = @(Get-NetRoute -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object {
        $adapterNames -contains $_.InterfaceAlias -or
        $testAddresses -contains ([string]$_.DestinationPrefix).Split('/')[0]
    } | ForEach-Object {
        [ordered]@{
            interface_index = [int]$_.InterfaceIndex
            interface_alias = [string]$_.InterfaceAlias
            destination_prefix = [string]$_.DestinationPrefix
            next_hop = [string]$_.NextHop
            route_metric = [int]$_.RouteMetric
        }
    })
    return [ordered]@{
        captured_monotonic_ticks = $captured.monotonic_ticks
        captured_elapsed_ms = $captured.elapsed_ms
        adapters = $adapters
        addresses = $addresses
        routes = $routes
    }
}

function Initialize-Tcp08Artifacts {
    if (-not $script:tcp08Enabled) { return }
    $artifactFullPath = [IO.Path]::GetFullPath($script:tcp08ArtifactPath).TrimEnd('\', '/')
    $workFullPath = [IO.Path]::GetFullPath($script:work).TrimEnd('\', '/')
    $workPrefix = $workFullPath + [IO.Path]::DirectorySeparatorChar
    Assert-True (-not $artifactFullPath.Equals($workFullPath, [StringComparison]::OrdinalIgnoreCase) -and
        -not $artifactFullPath.StartsWith($workPrefix, [StringComparison]::OrdinalIgnoreCase)) "ArtifactDirectory must be outside the disposable run work directory"
    $script:tcp08ArtifactPath = $artifactFullPath
    if (Test-Path -LiteralPath $artifactFullPath) {
        $ownedArtifactNames = @($script:tcp08RequiredJsonNames) + @(
            "artifact-hashes.json", "client.stdout.log", "client.stderr.log",
            "server.stdout.log", "server.stderr.log"
        )
        $ownedBaseline = @(Get-ChildItem -LiteralPath $artifactFullPath -Force | Where-Object {
            $ownedArtifactNames -contains $_.Name
        })
        Assert-True ($ownedBaseline.Count -eq 0) "ArtifactDirectory already contains controller-owned evidence"
    } else {
        New-Item -ItemType Directory -Path $artifactFullPath | Out-Null
    }
    $script:tcp08ArtifactInitialized = $true
    Add-Tcp08Event "vm_test_started" ([ordered]@{
        controller_started_utc = $script:controllerStartedUtc
        clock_origin_timestamp = $script:tcp08ClockOriginTimestamp
    })
    foreach ($name in @("client.stdout.log", "client.stderr.log", "server.stdout.log", "server.stderr.log")) {
        New-Item -ItemType File -Path (Join-Path $artifactFullPath $name) -ErrorAction Stop | Out-Null
    }
    foreach ($name in @("controller.stdout.log", "controller.stderr.log")) {
        Assert-True (Test-Path -LiteralPath (Join-Path $artifactFullPath $name) -PathType Leaf) "outer pwsh redirection must create $name before controller startup"
    }
    try { Write-Tcp08Json "process-before.json" (Get-Tcp08ProcessSnapshot) }
    catch {
        Write-Tcp08Json "process-before.json" ([ordered]@{
            schema = "ferrum2.windows-tun.tcp08-capture-unavailable.v1"
            capture = "process-before"
            error_type = $_.Exception.GetType().FullName
        })
        throw
    }
    try { Write-Tcp08Json "network-before.json" (Get-Tcp08ResidueNetworkSnapshot) }
    catch {
        Write-Tcp08Json "network-before.json" ([ordered]@{
            schema = "ferrum2.windows-tun.tcp08-capture-unavailable.v1"
            capture = "network-before"
            error_type = $_.Exception.GetType().FullName
        })
        throw
    }
}

function Write-Tcp08BinaryEvidence([string]$WintunDll) {
    if (-not $script:tcp08ArtifactInitialized) { return }
    Assert-True (Test-Path -LiteralPath $script:binary) "client binary is missing"
    Assert-True (Test-Path -LiteralPath $script:serverBinary) "server binary is missing"
    $controllerPath = $MyInvocation.ScriptName
    if ([string]::IsNullOrWhiteSpace($controllerPath)) { $controllerPath = Join-Path $script:PSScriptRoot "qualify_windows_tun.ps1" }
    Write-Tcp08Json "binary-hashes.json" ([ordered]@{
        client = [ordered]@{
            path = $script:binary
            sha256 = (Get-FileHash -LiteralPath $script:binary -Algorithm SHA256).Hash.ToLowerInvariant()
            bytes = (Get-Item -LiteralPath $script:binary).Length
            explicit = $script:clientBinaryExplicit
        }
        server = [ordered]@{
            path = $script:serverBinary
            sha256 = (Get-FileHash -LiteralPath $script:serverBinary -Algorithm SHA256).Hash.ToLowerInvariant()
            bytes = (Get-Item -LiteralPath $script:serverBinary).Length
            explicit = $script:serverBinaryExplicit
        }
        controller = [ordered]@{
            path = $controllerPath
            sha256 = (Get-FileHash -LiteralPath $controllerPath -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        runtime_library = [ordered]@{
            explicit = [bool]$script:runtimeLibraryDirectoryExplicit
            directory = $script:resolvedRuntimeLibraryDirectory
            vcruntime140_dll = [ordered]@{
                path = $script:runtimeVcruntimePath
                bytes = $script:runtimeVcruntimeBytes
                sha256 = $script:runtimeVcruntimeSha256
            }
        }
        wintun_zip = [ordered]@{ path = $script:zip; sha256 = $script:expectedZipHash.ToLowerInvariant() }
        wintun_dll = [ordered]@{ path = $WintunDll; sha256 = $script:expectedDllHash.ToLowerInvariant() }
    })
}

function Write-Tcp08Metadata([string]$Target, [int]$TargetPort, [int]$GatePort, [int]$ServerPort, [int]$MetricsPort) {
    if (-not $script:tcp08ArtifactInitialized) { return }
    $currentVersion = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    Write-Tcp08Json "metadata.json" ([ordered]@{
        schema = "ferrum2.windows-tun.tcp08-metadata.v1"
        mode = $script:Mode
        run_token = $script:runIdentity
        controller_started_utc = $script:controllerStartedUtc
        product_root = $script:resolvedProductRoot
        client_binary_explicit = $script:clientBinaryExplicit
        server_binary_explicit = $script:serverBinaryExplicit
        runtime_library = [ordered]@{
            explicit = [bool]$script:runtimeLibraryDirectoryExplicit
            directory = $script:resolvedRuntimeLibraryDirectory
            vcruntime140_dll = [ordered]@{
                path = $script:runtimeVcruntimePath
                bytes = $script:runtimeVcruntimeBytes
                sha256 = $script:runtimeVcruntimeSha256
            }
        }
        artifact_directory = $script:tcp08ArtifactPath
        cleanup_identity = [ordered]@{
            journal_path = $script:runIdentityJournalPath
            journal_sha256 = (Get-FileHash -LiteralPath $script:runIdentityJournalPath -Algorithm SHA256).Hash.ToLowerInvariant()
            consumption = "external cleanup with the same run token"
        }
        windows = [ordered]@{
            product_name = [string]$currentVersion.ProductName
            edition = [string]$currentVersion.EditionID
            build = "$($currentVersion.CurrentBuildNumber).$($currentVersion.UBR)"
        }
        powershell_version = $PSVersionTable.PSVersion.ToString()
        monotonic_clock = [ordered]@{
            kind = "System.Diagnostics.Stopwatch"
            frequency = [Diagnostics.Stopwatch]::Frequency
            origin_timestamp = $script:tcp08ClockOriginTimestamp
            origin_wall_clock_utc = $script:tcp08ClockOriginUtc
        }
        logs = [ordered]@{
            client_stdout = [ordered]@{ name = "client.stdout.log"; producer = "CreateProcessW redirected child handle"; mode = "append" }
            client_stderr = [ordered]@{ name = "client.stderr.log"; producer = "CreateProcessW redirected child handle"; mode = "append" }
            server_stdout = [ordered]@{ name = "server.stdout.log"; producer = "CreateProcessW redirected child handle"; mode = "append" }
            server_stderr = [ordered]@{ name = "server.stderr.log"; producer = "CreateProcessW redirected child handle"; mode = "append" }
            controller_stdout = [ordered]@{ name = "controller.stdout.log"; producer = "outer pwsh stream redirection"; mode = "append" }
            controller_stderr = [ordered]@{ name = "controller.stderr.log"; producer = "outer pwsh stream redirection"; mode = "append" }
        }
        artifact_manifest = [ordered]@{
            controller_capture_is_point_in_time = $true
            outer_redirection_may_still_be_open = $true
            final_outer_recalculation_required = $true
        }
        tcp08 = [ordered]@{
            target = $Target
            target_port = $TargetPort
            gate_port = $GatePort
            server_port = $ServerPort
            metrics_port = $MetricsPort
            require_product_owner_metrics = [bool]$script:RequireTcp08ProductMetrics
            pressure_chunk_bytes = 1048576
            pressure_attempt_limit = 128
            pressure_attempt_wait_ms = 100
            pressure_stable_wait_ms = $script:tcp08PressureStableWaitMilliseconds
            runtime_idle_timeout_ms = $script:runtimeIdleTimeoutMilliseconds
            ctrl_break_internal_wait_ms = 250
            controller_grace_probe_ms = 300
            shutdown_grace_ms = 1000
            process_exit_wait_ms = 10000
        }
    })
}

function Get-Tcp08JsonProperty([object]$Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function Test-Tcp08JsonNumber([object]$Value) {
    return $Value -is [byte] -or $Value -is [sbyte] -or
        $Value -is [uint16] -or $Value -is [int16] -or
        $Value -is [uint32] -or $Value -is [int32] -or
        $Value -is [uint64] -or $Value -is [int64] -or
        $Value -is [single] -or $Value -is [double] -or $Value -is [decimal]
}

function ConvertTo-Tcp08NonNegativeUInt64([object]$Value, [string]$Field) {
    Assert-True (Test-Tcp08JsonNumber $Value) "process shutdown report $Field is not numeric"
    try { $number = [decimal]$Value }
    catch { throw "process shutdown report $Field is outside the supported integer range" }
    Assert-True ($number -ge 0 -and $number -le [decimal]([uint64]::MaxValue) -and
        $number -eq [decimal]::Truncate($number)) "process shutdown report $Field is not a non-negative integer"
    return [uint64]$number
}

function ConvertTo-Tcp08SignedInt64([object]$Value, [string]$Field) {
    Assert-True (Test-Tcp08JsonNumber $Value) "process shutdown report $Field is not numeric"
    try { $number = [decimal]$Value }
    catch { throw "process shutdown report $Field is outside the supported integer range" }
    Assert-True ($number -ge [decimal]([int64]::MinValue) -and $number -le [decimal]([int64]::MaxValue) -and
        $number -eq [decimal]::Truncate($number)) "process shutdown report $Field is not an integer"
    return [int64]$number
}

function ConvertTo-Tcp08ProductRoot([object]$Root) {
    if ($null -eq $Root) { return $null }
    Assert-ClosedJsonProperties $Root @("name", "id") "process shutdown report root"
    $name = [string](Get-Tcp08JsonProperty $Root "name")
    Assert-True (@("socks", "dns", "metrics", "tun") -ccontains $name) "process shutdown report root name is invalid"
    $id = ConvertTo-Tcp08NonNegativeUInt64 (Get-Tcp08JsonProperty $Root "id") "root.id"
    Assert-True ($id -lt 4) "process shutdown report root ID is outside the closed client topology"
    return [ordered]@{
        name = $name
        id = $id
    }
}

function ConvertTo-Tcp08OwnerCounters([object]$Counters, [bool]$AllowNegative = $false) {
    if ($null -eq $Counters) { return $null }
    $names = @(
        "process_supervisors", "prepared_process_roots", "active_process_roots", "process_root_reaps",
        "process_root_rollbacks", "process_forced_roots", "active_tun_tcp_flows", "active_tun_handler_tasks",
        "active_supervisor_children", "connection_tasks", "owned_buffers", "owned_permits", "listeners",
        "forced_shutdowns", "udp_sessions", "udp_sockets", "udp_tasks", "udp_queued_datagrams",
        "udp_buffered_bytes", "udp_scratch_buffers", "udp_forced_shutdowns", "sniff_buffered_bytes",
        "network_reset_hooks", "network_runtime_owners", "network_reset_drivers"
    )
    Assert-ClosedJsonProperties $Counters $names "process shutdown report owner counters"
    $sanitized = [ordered]@{}
    foreach ($name in $names) {
        $value = Get-Tcp08JsonProperty $Counters $name
        $sanitized[$name] = if ($AllowNegative) {
            ConvertTo-Tcp08SignedInt64 $value "owner.$name"
        } else {
            ConvertTo-Tcp08NonNegativeUInt64 $value "owner.$name"
        }
    }
    return $sanitized
}

function ConvertTo-Tcp08CleanupFailure([object]$Failure, [int]$Depth = 0) {
    if ($null -eq $Failure) { return $null }
    Assert-True ($Depth -le 4) "process shutdown report cleanup nesting is invalid"
    $allowedProperties = @("kind", "root", "roots", "root_error_category", "prior", "owner_baseline", "owner_stopped", "owner_delta")
    $actualProperties = @($Failure.PSObject.Properties.Name)
    Assert-True (@($actualProperties | Where-Object { -not ($allowedProperties -ccontains $_) }).Count -eq 0 -and
        $actualProperties -ccontains "kind") "process shutdown report cleanup property set is invalid"
    $kind = [string](Get-Tcp08JsonProperty $Failure "kind")
    Assert-True ($kind -in @("RootFailed", "RootPanicked", "RootJoinFailed", "ForceReapTimedOut", "OwnerMismatch")) "process shutdown report cleanup kind is invalid"
    $sanitized = [ordered]@{ kind = $kind }
    $root = Get-Tcp08JsonProperty $Failure "root"
    if ($null -ne $root) { $sanitized.root = ConvertTo-Tcp08ProductRoot $root }
    $roots = Get-Tcp08JsonProperty $Failure "roots"
    if ($null -ne $roots) {
        $sanitizedRoots = @($roots | ForEach-Object { ConvertTo-Tcp08ProductRoot $_ })
        Assert-True (@($sanitizedRoots | Group-Object id | Where-Object Count -gt 1).Count -eq 0 -and
            @($sanitizedRoots | Group-Object name | Where-Object Count -gt 1).Count -eq 0) "process shutdown report cleanup roots contain duplicates"
        $sanitized.roots = $sanitizedRoots
    }
    $errorCategory = Get-Tcp08JsonProperty $Failure "root_error_category"
    if ($null -ne $errorCategory) {
        $errorCategory = [string]$errorCategory
        Assert-True ($errorCategory -match '^(startup|runtime|shutdown)\.[a-z]+$') "process shutdown report error category is invalid"
        $sanitized.root_error_category = $errorCategory
    }
    $prior = Get-Tcp08JsonProperty $Failure "prior"
    if ($null -ne $prior) { $sanitized.prior = ConvertTo-Tcp08CleanupFailure $prior ($Depth + 1) }
    foreach ($name in @("owner_baseline", "owner_stopped", "owner_delta")) {
        $value = Get-Tcp08JsonProperty $Failure $name
        if ($null -ne $value) { $sanitized[$name] = ConvertTo-Tcp08OwnerCounters $value ($name -ceq "owner_delta") }
    }
    return $sanitized
}

function ConvertTo-Tcp08ProductShutdownReport([object]$Report) {
    $requiredReportProperties = @(
        "event", "role", "process_states", "process_transitions", "shutdown_grace_ns",
        "actual_grace_deadline_elapsed_ns", "actual_grace_deadline_source", "termination_cause",
        "root", "root_exit_category", "root_error_category", "forced_root_count",
        "owner_baseline", "owner_stopped", "owner_delta", "cleanup_failure", "root_exit_events"
    )
    $actualReportProperties = @($Report.PSObject.Properties.Name)
    Assert-True (@($actualReportProperties | Where-Object { -not ($requiredReportProperties -ccontains $_) }).Count -eq 0) "process shutdown report has unknown properties"
    Assert-True (@($requiredReportProperties | Where-Object { -not ($actualReportProperties -ccontains $_) }).Count -eq 0) "process shutdown report is missing required properties"
    Assert-True ((Get-Tcp08JsonProperty $Report "event") -ceq "process_shutdown_report") "process shutdown report event is invalid"
    Assert-True ((Get-Tcp08JsonProperty $Report "role") -ceq "client") "process shutdown report role is invalid"
    $allowedStates = @("Validated", "Preparing", "Prepared", "Active", "Rollback", "Fatal", "Quiescing", "Draining", "Forced", "Stopped")
    $states = @(Get-Tcp08JsonProperty $Report "process_states")
    Assert-True ($states.Count -gt 0 -and @($states | Where-Object { -not ($allowedStates -ccontains [string]$_) }).Count -eq 0) "process shutdown report states are invalid"
    $rawTransitions = @(Get-Tcp08JsonProperty $Report "process_transitions")
    Assert-True ($rawTransitions.Count -eq $states.Count) "process shutdown report state/transition count is inconsistent"
    $transitions = [System.Collections.Generic.List[object]]::new()
    $seenStates = @{}
    $previousTransitionElapsed = $null
    for ($index = 0; $index -lt $rawTransitions.Count; $index++) {
        Assert-ClosedJsonProperties $rawTransitions[$index] @("state", "elapsed_ns") "process shutdown report transition"
        $state = [string](Get-Tcp08JsonProperty $rawTransitions[$index] "state")
        Assert-True ($allowedStates -ccontains $state) "process shutdown report transition is invalid"
        Assert-True ($state -ceq [string]$states[$index]) "process shutdown report state/transition sequence is inconsistent"
        Assert-True (-not $seenStates.ContainsKey($state)) "process shutdown report contains a duplicate state transition"
        $seenStates[$state] = $true
        $elapsed = ConvertTo-Tcp08NonNegativeUInt64 (Get-Tcp08JsonProperty $rawTransitions[$index] "elapsed_ns") "process_transitions[$index].elapsed_ns"
        if ($null -ne $previousTransitionElapsed) {
            Assert-True ($elapsed -ge $previousTransitionElapsed) "process shutdown report transitions are not monotonic"
        }
        $previousTransitionElapsed = $elapsed
        $transitions.Add([ordered]@{ state = $state; elapsed_ns = $elapsed })
    }
    Assert-True ([string]$states[$states.Count - 1] -ceq "Stopped") "process shutdown report is not closed by Stopped"
    $reportElapsed = [uint64]$previousTransitionElapsed

    $rootExitEvents = [System.Collections.Generic.List[object]]::new()
    $rawRootExitEvents = Get-Tcp08JsonProperty $Report "root_exit_events"
    Assert-True ($rawRootExitEvents -is [System.Array]) "process shutdown report root_exit_events is not an array"
    Assert-True (@($rawRootExitEvents).Count -le 4) "process shutdown report has too many root exit events"
    $seenRootIds = @{}
    $seenRootNames = @{}
    $previousRootElapsed = $null
    $allowedRootPhases = @("Active", "Draining", "Forced", "WatchdogAbort")
    $allowedRootExitCategories = @("Completed", "Failed", "Panicked", "JoinFailed", "Aborted")
    foreach ($rawRootEvent in @($rawRootExitEvents)) {
        Assert-ClosedJsonProperties $rawRootEvent @("root", "phase", "exit_category", "elapsed_ns") "process shutdown report root exit event"
        $root = ConvertTo-Tcp08ProductRoot (Get-Tcp08JsonProperty $rawRootEvent "root")
        Assert-True ($null -ne $root) "process shutdown report root exit event has no root"
        $rootIdKey = ([uint64]$root.id).ToString([Globalization.CultureInfo]::InvariantCulture)
        $rootNameKey = [string]$root.name
        Assert-True (-not $seenRootIds.ContainsKey($rootIdKey)) "process shutdown report has a duplicate root exit ID"
        Assert-True (-not $seenRootNames.ContainsKey($rootNameKey)) "process shutdown report has a duplicate stable root exit name"
        $seenRootIds[$rootIdKey] = $true
        $seenRootNames[$rootNameKey] = $true
        $phase = [string](Get-Tcp08JsonProperty $rawRootEvent "phase")
        Assert-True ($allowedRootPhases -ccontains $phase) "process shutdown report root exit phase is invalid"
        $exitCategory = [string](Get-Tcp08JsonProperty $rawRootEvent "exit_category")
        Assert-True ($allowedRootExitCategories -ccontains $exitCategory) "process shutdown report root exit category is invalid"
        $elapsed = ConvertTo-Tcp08NonNegativeUInt64 (Get-Tcp08JsonProperty $rawRootEvent "elapsed_ns") "root_exit_events.elapsed_ns"
        if ($null -ne $previousRootElapsed) {
            Assert-True ($elapsed -ge $previousRootElapsed) "process shutdown report root exit events are not monotonic"
        }
        Assert-True ($elapsed -le $reportElapsed) "process shutdown report root exit event is later than report completion"
        $previousRootElapsed = $elapsed
        $rootExitEvents.Add([ordered]@{
            root = $root
            phase = $phase
            exit_category = $exitCategory
            elapsed_ns = $elapsed
        })
    }
    $terminationCause = [string](Get-Tcp08JsonProperty $Report "termination_cause")
    Assert-True (@("ExternalShutdown", "PreparationFailed", "PreparationPanicked", "ActivationFailed", "ActivationPanicked", "RootStopped") -ccontains $terminationCause) "process shutdown report cause is invalid"
    $rootExitCategory = Get-Tcp08JsonProperty $Report "root_exit_category"
    if ($null -ne $rootExitCategory) {
        $rootExitCategory = [string]$rootExitCategory
        Assert-True (@("Completed", "Failed", "Panicked", "JoinFailed") -ccontains $rootExitCategory) "process shutdown report root exit category is invalid"
    }
    $rootErrorCategory = Get-Tcp08JsonProperty $Report "root_error_category"
    if ($null -ne $rootErrorCategory) {
        $rootErrorCategory = [string]$rootErrorCategory
        Assert-True ($rootErrorCategory -match '^(startup|runtime|shutdown)\.[a-z]+$') "process shutdown report root error category is invalid"
    }
    $actualGraceDeadline = Get-Tcp08JsonProperty $Report "actual_grace_deadline_elapsed_ns"
    $actualGraceDeadlineSource = Get-Tcp08JsonProperty $Report "actual_grace_deadline_source"
    if ($null -ne $actualGraceDeadlineSource) {
        $actualGraceDeadlineSource = [string]$actualGraceDeadlineSource
        Assert-True ($actualGraceDeadlineSource -eq "runtime_process_supervisor") "process shutdown report grace deadline source is invalid"
    }
    Assert-True (($null -eq $actualGraceDeadline) -eq ($null -eq $actualGraceDeadlineSource)) "process shutdown report actual grace deadline pair is incomplete"
    if ($null -ne $actualGraceDeadline) {
        $actualGraceDeadline = ConvertTo-Tcp08NonNegativeUInt64 $actualGraceDeadline "actual_grace_deadline_elapsed_ns"
    }
    $graceDeadlineSemantics = if ($null -ne $actualGraceDeadline) { "actual_runtime_deadline" }
        else { "unavailable" }
    $ownerBaseline = Get-Tcp08JsonProperty $Report "owner_baseline"
    $ownerStopped = Get-Tcp08JsonProperty $Report "owner_stopped"
    $ownerDelta = Get-Tcp08JsonProperty $Report "owner_delta"
    Assert-True ($null -ne $ownerBaseline -and $null -ne $ownerStopped -and $null -ne $ownerDelta) "process shutdown report top-level owner triplet is incomplete"
    return [ordered]@{
        event = "process_shutdown_report"
        role = "client"
        process_states = @($states | ForEach-Object { [string]$_ })
        process_transitions = $transitions
        report_elapsed_ns = $reportElapsed
        report_elapsed_source = "final_Stopped_process_transition"
        root_exit_events = $rootExitEvents
        shutdown_grace_ns = ConvertTo-Tcp08NonNegativeUInt64 (Get-Tcp08JsonProperty $Report "shutdown_grace_ns") "shutdown_grace_ns"
        actual_grace_deadline_elapsed_ns = $actualGraceDeadline
        actual_grace_deadline_source = $actualGraceDeadlineSource
        grace_deadline_semantics = $graceDeadlineSemantics
        termination_cause = $terminationCause
        root = ConvertTo-Tcp08ProductRoot (Get-Tcp08JsonProperty $Report "root")
        root_exit_category = $rootExitCategory
        root_error_category = $rootErrorCategory
        forced_root_count = ConvertTo-Tcp08NonNegativeUInt64 (Get-Tcp08JsonProperty $Report "forced_root_count") "forced_root_count"
        owner_baseline = ConvertTo-Tcp08OwnerCounters $ownerBaseline
        owner_stopped = ConvertTo-Tcp08OwnerCounters $ownerStopped
        owner_delta = ConvertTo-Tcp08OwnerCounters $ownerDelta $true
        cleanup_failure = ConvertTo-Tcp08CleanupFailure (Get-Tcp08JsonProperty $Report "cleanup_failure")
    }
}
