"""Canonical Windows-host TUN performance profile contract."""

from __future__ import annotations

from types import MappingProxyType

WINDOWS_TUN_SELECTION = "windows-tun-host"
WINDOWS_TUN_MODES = frozenset({"Quick", "Confirm", "Lifecycle"})
WINDOWS_TUN_TOPOLOGIES = frozenset({"ClientDirect", "EndToEnd"})
WINDOWS_TUN_THRESHOLD_PERCENT = 2.0
WINDOWS_TUN_PERFORMANCE_SOURCE_PATHS = (
    "tools/powershell/Ferrum2.Performance/Ferrum2.Performance.psd1",
    "tools/powershell/Ferrum2.Performance/Ferrum2.Performance.psm1",
    "tools/powershell/Ferrum2.Performance/HostExecution.ps1",
    "tools/powershell/Ferrum2.Performance/HostProduct.ps1",
    "tools/powershell/Ferrum2.Performance/HostTrial.ps1",
    "tools/powershell/Ferrum2.Performance/HostOwnership.ps1",
    "tools/powershell/Ferrum2.Performance/HostCleanup.ps1",
    "tools/powershell/Ferrum2.Performance/HostPerformance.ps1",
    "tools/powershell/Ferrum2.Performance/HostPlan.ps1",
    "tools/powershell/Ferrum2.Performance/HostProfiles.ps1",
    "tools/powershell/Ferrum2.Performance/PerformanceProcessOwner.cs",
    "tools/windows-tun/performance/run_windows_tun_performance_host.ps1",
)

_QUICK_SCENARIOS = (
    ("tcp-single-flow", "throughput", "bytes_per_second", "higher_is_better"),
    ("tcp-request-1k-p99", "p99_nanoseconds", "nanoseconds", "lower_is_better"),
    (
        "udp-packets-per-second",
        "packet_rate",
        "packets_per_second",
        "higher_is_better",
    ),
    (
        "fragment-reassembly-throughput",
        "reassembly_rate",
        "bytes_per_second",
        "higher_is_better",
    ),
)

WINDOWS_TUN_PROFILES = MappingProxyType(
    {
        "Quick": MappingProxyType(
            {
                "pair_count": 3,
                "warmup_seconds": 2,
                "active_seconds": 10,
                "lifecycle_cycles": 0,
                "scenarios": _QUICK_SCENARIOS,
            }
        ),
        "Confirm": MappingProxyType(
            {
                "pair_count": 5,
                "warmup_seconds": 5,
                "active_seconds": 30,
                "lifecycle_cycles": 0,
                "scenarios": _QUICK_SCENARIOS
                + (
                    (
                        "tcp-256-flow-fairness",
                        "fairness",
                        "jain_ppb",
                        "higher_is_better",
                    ),
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

WINDOWS_TUN_WORKLOAD_MEASUREMENTS = MappingProxyType(
    {
        "tcp-single-flow": frozenset(
            {"throughput", "cpu_payload_bytes", "io_completions", "active_elapsed_nanoseconds", "tail_checked_units"}
        ),
        "tcp-request-1k-p99": frozenset(
            {"p50_nanoseconds", "p95_nanoseconds", "p99_nanoseconds",
             "latency_samples", "io_completions", "active_elapsed_nanoseconds", "tail_checked_units"}
        ),
        "tcp-256-flow-fairness": frozenset(
            {"fairness", "aggregate_throughput", "io_completions", "active_elapsed_nanoseconds", "tail_checked_units"}
        ),
        "udp-packets-per-second": frozenset(
            {"packet_rate", "p50_nanoseconds", "p95_nanoseconds", "p99_nanoseconds",
             "latency_samples", "io_completions", "active_elapsed_nanoseconds", "tail_checked_units"}
        ),
        "fragment-reassembly-throughput": frozenset(
            {"reassembly_rate", "io_completions", "active_elapsed_nanoseconds", "tail_checked_units"}
        ),
    }
)

WINDOWS_TUN_WORKLOAD_CHECKS = MappingProxyType(
    {
        "tcp-single-flow": frozenset(
            {"single_flow_only", "payload_exact", "no_gso"}
        ),
        "tcp-request-1k-p99": frozenset(
            {
                "single_flow_only",
                "payload_exact",
                "bounded_latency_samples",
                "no_gso",
            }
        ),
        "tcp-256-flow-fairness": frozenset(
            {
                "all_256_flows_ready",
                "all_256_flows_nonzero",
                "payload_exact",
                "no_gso",
            }
        ),
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
    }
)
