$observation = Invoke-Workload $Scenario 60
$checkedUnits = [uint64]$observation.checked_units
$measurements.packet_rate = [ordered]@{
    unit = "datagrams_per_second"; value = [uint64]$observation.measurements.packet_rate
}
$checks.every_reply_accounted = $observation.checks.every_reply_accounted -eq $true
$checks.payload_exact = $observation.checks.payload_exact -eq $true
$checks.no_gso = $observation.checks.no_gso -eq $true
[void](Wait-CleanDrain $true)
