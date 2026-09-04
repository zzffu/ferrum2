# Windows TUN Performance Tooling Guide

The repository, `tools/`, and parent Windows TUN guides remain in force. This directory is the only
canonical home for the Windows TUN host performance runner and collectors. Performance code may
measure throughput, latency, packet rate, lifecycle cost, and resource use; it must not define or emit
a Windows TUN correctness-qualification verdict.

The public interface is
`tools/windows-tun/performance/run_windows_tun_performance_host.ps1`. Keep it deep: callers choose
`-PlanOnly`, `-RecoveryOnly`, or `-Mode Quick|Confirm|Lifecycle`, provide baseline/candidate commits
and an evidence directory when measuring, and explicitly pass `-AcknowledgeHostNetworkMutation`.
Adapter names, addresses, ports, process ownership, route identity, temporary configuration, ledgers,
cleanup, recovery, and evidence validation are implementation details, not public parameters.

`-PlanOnly` must be nonmutating and unprivileged. `-RecoveryOnly` may inspect an empty or completed
ledger without elevation, but must require elevation before removing live network resources. Real
execution must fail closed unless the shell is already elevated, acknowledgement is explicit, no
concurrent run or stale ledger exists, every dedicated address and route is conflict-free, and route
lookup proves benchmark traffic enters the owned TUN while underlay, support, and 127.0.0.1:1080
traffic do not. Never auto-elevate, change a default route, replace DNS, disable/enable a physical
adapter, change WLAN, alter firewall/WFP, touch sing-box, or clean resources not named by the current
RunId ledger.

Every mutation belongs to one try/finally transaction and is recorded incrementally in
`%LOCALAPPDATA%\Ferrum2\host-performance\<RunId>\recovery.json`. Recovery validates adapter, route,
process, file, and port identity before removing only the ledger-owned resource; mismatch fails
closed. Cleanup is part of benchmark success. Quick runs selected data-plane scenarios with at least
three interleaved pairs; Confirm runs affected scenarios with at least five pairs and retains raw
per-pair metrics; Lifecycle defaults to 20 and caps at 100 complete product-start, TUN-probe, and
product-stop cycles. The retired 1000-reset durability soak is never run by autoresearch.

The performance source manifest is a closed host-runner source set. Any source change requires an
atomic refresh of canonical paths, exact byte lengths, SHA-256 values, recipe bindings, and tests.
Performance must not import Lab VM/checkpoint/staging owners or qualification modules. Parse/static
tests may run ordinarily; real execution occurs only by an informed operator using the public runner.
