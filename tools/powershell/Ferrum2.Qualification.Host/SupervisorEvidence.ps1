Set-StrictMode -Version Latest

function Write-Ferrum2QualificationSupervisorOutcome {
    param(
        [Parameter(Mandatory = $true)][string]$SupervisorRoot,
        [Parameter(Mandatory = $true)][string]$EvidenceDirectory,
        [Parameter(Mandatory = $true)][object]$Outcome
    )
    $written = $false
    foreach ($directory in @($SupervisorRoot, $EvidenceDirectory)) {
        if (Test-Path -LiteralPath $directory -PathType Container) {
            try {
                [IO.File]::WriteAllText((Join-Path $directory 'supervisor-outcome.json'),
                    (($Outcome | ConvertTo-Json -Depth 10) + "`n"), [Text.UTF8Encoding]::new($false))
                $written = $true
            } catch {
                Write-Warning "supervisor outcome write failed; directory=$directory"
            }
        }
    }
    if (-not $written) { throw 'supervisor outcome could not be retained' }
}

# Only run-owned files are exported. Failure to export leaves the supervisor tree intact,
# so even a missing/unwritable evidence destination cannot erase recovery diagnostics.
function Export-Ferrum2QualificationSupervisorEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$SupervisorRoot,
        [Parameter(Mandatory = $true)][string]$EvidenceDirectory,
        [Parameter(Mandatory = $true)][object]$Outcome
    )
    $metadata = Join-Path $SupervisorRoot 'supervisor-outcome.json'
    try {
        [IO.File]::WriteAllText($metadata, (($Outcome | ConvertTo-Json -Depth 10) + "`n"),
            [Text.UTF8Encoding]::new($false))
        if (-not (Test-Path -LiteralPath $EvidenceDirectory -PathType Container)) {
            New-Item -ItemType Directory -Path $EvidenceDirectory -ErrorAction Stop | Out-Null
        }
        foreach ($entry in @(
            @{ Source = 'worker.stdout.log'; Name = 'supervisor.stdout.log' },
            @{ Source = 'worker.stderr.log'; Name = 'supervisor.stderr.log' },
            @{ Source = 'recovery.stdout.log'; Name = 'recovery.stdout.log' },
            @{ Source = 'recovery.stderr.log'; Name = 'recovery.stderr.log' },
            @{ Source = 'supervisor-outcome.json'; Name = 'supervisor-outcome.json' }
        )) {
            $source = Join-Path $SupervisorRoot $entry.Source
            if (Test-Path -LiteralPath $source -PathType Leaf) {
                Copy-Item -LiteralPath $source -Destination (Join-Path $EvidenceDirectory $entry.Name) `
                    -Force -ErrorAction Stop
            }
        }
        return $true
    } catch {
        $Outcome.cleanup_phase = 'export-diagnostics'
        $Outcome.cleanup_error = [string]$_.Exception.Message
        $Outcome.cleanup_failures = @($Outcome.cleanup_failures) + @(
            [pscustomobject]@{ phase = $Outcome.cleanup_phase; error = $Outcome.cleanup_error })
        Write-Ferrum2QualificationSupervisorOutcome -SupervisorRoot $SupervisorRoot `
            -EvidenceDirectory $EvidenceDirectory -Outcome $Outcome
        Write-Warning "supervisor diagnostic export failed; retained evidence=$SupervisorRoot"
        return $false
    }
}

# This is the supervisor's file finalization protocol. Only after it returns may a verdict
# be published; failed export/removal leaves raw evidence and a phase-specific outcome.
function Complete-Ferrum2QualificationSupervisorEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$SupervisorRoot,
        [Parameter(Mandatory = $true)][string]$EvidenceDirectory,
        [Parameter(Mandatory = $true)][object]$Outcome
    )
    if (-not (Export-Ferrum2QualificationSupervisorEvidence -SupervisorRoot $SupervisorRoot `
        -EvidenceDirectory $EvidenceDirectory -Outcome $Outcome)) {
        throw "supervisor diagnostic export failed; retained evidence=$SupervisorRoot"
    }
    try {
        $resolvedRoot = [IO.Path]::GetFullPath($SupervisorRoot).TrimEnd('\', '/')
        $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
        $resolvedEvidence = [IO.Path]::GetFullPath($EvidenceDirectory).TrimEnd('\', '/')
        if (-not [string]::Equals([IO.Path]::GetDirectoryName($resolvedRoot),
                $temporaryRoot, [StringComparison]::OrdinalIgnoreCase) -or
            [IO.Path]::GetFileName($resolvedRoot) -cnotmatch
                '^ferrum2-host-qualification-supervisor-[0-9a-f]{32}$' -or
            [string]::Equals($resolvedRoot, $resolvedEvidence, [StringComparison]::OrdinalIgnoreCase) -or
            $resolvedEvidence.StartsWith($resolvedRoot + [IO.Path]::DirectorySeparatorChar,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'supervisor directory ownership path is invalid'
        }
        $directory = Get-Item -LiteralPath $resolvedRoot -Force -ErrorAction Stop
        if (-not $directory.PSIsContainer -or
            ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'supervisor directory ownership type is invalid'
        }
        Remove-Item -LiteralPath $resolvedRoot -Recurse -Force -ErrorAction Stop
    } catch {
        $Outcome.cleanup_phase = 'remove-supervisor-directory'
        $Outcome.cleanup_error = [string]$_.Exception.Message
        $Outcome.cleanup_failures = @($Outcome.cleanup_failures) + @(
            [pscustomobject]@{ phase = $Outcome.cleanup_phase; error = $Outcome.cleanup_error })
        Write-Ferrum2QualificationSupervisorOutcome -SupervisorRoot $SupervisorRoot `
            -EvidenceDirectory $EvidenceDirectory -Outcome $Outcome
        throw
    }
    if (@($Outcome.cleanup_failures).Count -eq 0) { $Outcome.cleanup_phase = 'complete' }
    Write-Ferrum2QualificationSupervisorOutcome -SupervisorRoot $SupervisorRoot `
        -EvidenceDirectory $EvidenceDirectory -Outcome $Outcome
}
