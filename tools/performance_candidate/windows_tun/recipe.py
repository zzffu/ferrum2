"""Canonical Windows-host TUN performance profile contract."""

from __future__ import annotations

from types import MappingProxyType

WINDOWS_TUN_SELECTION = "windows-tun-host"
WINDOWS_TUN_MODES = frozenset({"Quick", "Confirm", "Lifecycle"})
WINDOWS_TUN_THRESHOLD_PERCENT = 2.0
WINDOWS_TUN_PERFORMANCE_SOURCE_PATHS = (
    "tools/powershell/Ferrum2.Performance/Ferrum2.Performance.psd1",
    "tools/powershell/Ferrum2.Performance/Ferrum2.Performance.psm1",
    "tools/powershell/Ferrum2.Performance/HostExecution.ps1",
    "tools/powershell/Ferrum2.Performance/HostOwnership.ps1",
    "tools/powershell/Ferrum2.Performance/HostPerformance.ps1",
    "tools/powershell/Ferrum2.Performance/HostPlan.ps1",
    "tools/powershell/Ferrum2.Performance/HostProfiles.ps1",
    "tools/powershell/Ferrum2.Performance/PerformanceProcessOwner.cs",
    "tools/windows-tun/performance/run_windows_tun_performance_host.ps1",
)

WINDOWS_TUN_PROFILES = MappingProxyType(
    {
        "Quick": MappingProxyType(
            {
                "pair_count": 3,
                "warmup_seconds": 2,
                "active_seconds": 10,
                "lifecycle_cycles": 0,
                "scenarios": (
                    ("udp-packets-per-second", "packet_rate", "packets_per_second"),
                    (
                        "fragment-reassembly-throughput",
                        "reassembly_rate",
                        "bytes_per_second",
                    ),
                ),
            }
        ),
        "Confirm": MappingProxyType(
            {
                "pair_count": 5,
                "warmup_seconds": 5,
                "active_seconds": 30,
                "lifecycle_cycles": 0,
                "scenarios": (
                    ("udp-packets-per-second", "packet_rate", "packets_per_second"),
                    (
                        "fragment-reassembly-throughput",
                        "reassembly_rate",
                        "bytes_per_second",
                    ),
                    ("tcp-single-flow", "throughput", "bytes_per_second"),
                ),
            }
        ),
        "Lifecycle": MappingProxyType(
            {
                "pair_count": 0,
                "warmup_seconds": 0,
                "active_seconds": 0,
                "lifecycle_cycles": 20,
                "scenarios": (),
            }
        ),
    }
)

WINDOWS_TUN_WORKLOAD_CHECKS = MappingProxyType(
    {
        "udp-packets-per-second": frozenset(
            {
                "every_reply_accounted",
                "payload_exact",
                "receive_retries_penalized",
                "no_gso",
            }
        ),
        "fragment-reassembly-throughput": frozenset(
            {
                "payload_exact",
                "no_gso",
                "all_sequences_acknowledged",
                "bounded_retransmissions",
            }
        ),
        "tcp-single-flow": frozenset(
            {
                "single_flow_only",
                "payload_exact",
                "no_gso",
            }
        ),
    }
)
