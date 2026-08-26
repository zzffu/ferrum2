$cpuBefore = Get-ProcessCpuNanoseconds @($clientProcess, $serverProcess)
$observation = Invoke-Workload $Scenario 120
$cpuAfter = Get-ProcessCpuNanoseconds @($clientProcess, $serverProcess)
$checkedUnits = [uint64]$observation.checked_units
Assert-Condition ($checkedUnits -ge 67108864) "TCP checked-byte floor was not met"
[uint64]$cpuPayloadBytes = $observation.measurements.cpu_payload_bytes
Assert-Condition ($cpuPayloadBytes -ge $checkedUnits) "TCP CPU byte denominator is incomplete"
[uint64]$cpuDelta = $cpuAfter - $cpuBefore
Assert-Condition ($cpuDelta -gt 0) "TCP CPU delta is zero"
$cpuCost = [uint64][Math]::Ceiling(
    ([decimal]$cpuDelta * [decimal]1073741824) / [decimal]$cpuPayloadBytes
)
$measurements.throughput = [ordered]@{
    unit = "bytes_per_second"; value = [uint64]$observation.measurements.throughput
}
$measurements.cpu_cost = [ordered]@{
    unit = "cpu_nanoseconds_per_gibibyte"; value = $cpuCost
}
$checks.single_flow_only = $observation.checks.single_flow_only -eq $true
$checks.payload_exact = $observation.checks.payload_exact -eq $true
$checks.no_gso = $observation.checks.no_gso -eq $true
[void](Wait-CleanDrain $false)
