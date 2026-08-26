$observation = Invoke-Workload $Scenario 90
$checkedUnits = [uint64]$observation.checked_units
$measurements.fairness = [ordered]@{
    unit = "jain_index_parts_per_billion"; value = [uint64]$observation.measurements.fairness
}
$checks.all_256_flows_ready = $observation.checks.all_256_flows_ready -eq $true
$checks.all_256_flows_nonzero = $observation.checks.all_256_flows_nonzero -eq $true
$checks.payload_exact = $observation.checks.payload_exact -eq $true
$checks.no_gso = $observation.checks.no_gso -eq $true
[void](Wait-CleanDrain $false)
