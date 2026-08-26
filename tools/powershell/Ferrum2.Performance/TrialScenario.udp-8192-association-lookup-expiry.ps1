$sourcePreflight = Get-UdpAssociationSourcePreflight `
    -TunAdapterName $AdapterName
$diagnostics = [ordered]@{
    udp_association_source_preflight = $sourcePreflight
}
Assert-Condition ($sourcePreflight.valid -eq $true) (
    "fixed UDP association source preflight failed: " +
    ($sourcePreflight.violations -join ",")
)
$observation = Invoke-Workload $Scenario 1800
$checkedUnits = [uint64]$observation.checked_units
$peakMetrics = Get-Metrics $MetricsPort 5
$activeAssociations = Get-Metric $peakMetrics "ferrum2_tun_udp_associations_active"
Assert-Condition ($activeAssociations -eq 8192) "product did not retain exactly 8192 associations"
$expiry = [Diagnostics.Stopwatch]::StartNew()
[void](Wait-Metric "ferrum2_tun_udp_associations_active" { param($value) $value -eq 0 } 180)
$expiry.Stop()
$expiryNanoseconds = [uint64][Math]::Ceiling(
    ([decimal]$expiry.ElapsedTicks * [decimal]1000000000) /
    [decimal][Diagnostics.Stopwatch]::Frequency
)
Assert-Condition ($expiryNanoseconds -gt 0) "association expiry duration is zero"
$measurements.lookup_rate = [ordered]@{
    unit = "lookups_per_second"; value = [uint64]$observation.measurements.lookup_rate
}
$measurements.expiry_cost = [ordered]@{
    unit = "nanoseconds_per_8192_expirations"; value = $expiryNanoseconds
}
$checks.exactly_8192_associations = $observation.checks.exactly_8192_associations -eq $true
$checks.all_lookups_hit = $observation.checks.all_lookups_hit -eq $true
$checks.all_associations_expired = $true
[void](Wait-CleanDrain $true)
$checks.clean_drain = $true
