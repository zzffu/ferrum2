# Windows TUN Performance Tooling Guide

The repository, `tools/`, and parent Windows TUN guides remain in force. This directory is the only
canonical home for the Windows TUN host performance runner and collectors. Performance code may
measure throughput, latency, packet rate, lifecycle cost, and resource use; it must not define or emit
a Windows TUN correctness-qualification verdict.

The public interface is
`tools/windows-tun/performance/run_windows_tun_performance_host.ps1`. Keep it deep: callers choose
`-PlanOnly`, `-RecoveryOnly`, or `-Mode Quick|Confirm|Lifecycle`; PlanOnly and real execution select
exactly one `-Topology ClientDirect|EndToEnd`. ClientDirect runs the workload through real Wintun and
the ferrum2-client TUN/TCP/UDP stack to direct local support egress without a ferrum2-server process.
EndToEnd retains the client/server path. Callers provide baseline/candidate commits and an evidence
directory when measuring, and explicitly pass `-AcknowledgeHostNetworkMutation`. Adapter names,
addresses, ports, process ownership, route identity, temporary configuration, ledgers, cleanup,
recovery, and evidence validation are implementation details, not public parameters.

`-PlanOnly` must be nonmutating and unprivileged. `-RecoveryOnly` may inspect an empty or completed
ledger without elevation, but must require elevation before removing live network resources. Real
execution must fail closed unless the shell is already elevated, acknowledgement is explicit, no
concurrent run or stale ledger exists, every dedicated address and route is conflict-free, and route
lookup proves benchmark traffic enters the owned TUN while support egress does not. EndToEnd must
also prove its client/server underlay excludes the TUN. Never auto-elevate, change a default route,
replace DNS, disable/enable a physical adapter, change WLAN, alter firewall/WFP, touch sing-box, or
clean resources not named by the current RunId ledger.

Every mutation belongs to one try/finally transaction and is recorded incrementally in
`%PROGRAMDATA%\Ferrum2HostPerformance-v2\<RunId>\recovery.json`, beneath an exact ACL owned by
Administrators and writable only by Administrators and SYSTEM. Recovery validates adapter, route,
process, file, and port identity before removing only the ledger-owned resource; mismatch fails
closed. After successful cleanup, retain external evidence and remove the transient RunId tree,
including exported sources, Cargo targets, and logs. Cleanup is part of benchmark success. Per
selected topology, Quick measures four scenarios with three interleaved pairs, for 24 trials; Confirm
measures five scenarios with five pairs, for 50 trials. Both retain raw primary metrics and
directions, checked work, I/O completions, applicable p99 latency, client/server CPU and peak working
set, route proofs, and failure counters. Server measurements are null for ClientDirect. Lifecycle
runs 20 complete product-start, TUN-probe, and product-stop cycles under the selected topology.

The performance source manifest is a closed host-runner source set. Any source change requires an
atomic refresh of canonical paths, exact byte lengths, SHA-256 values, recipe bindings, and tests.
Performance must not import virtual-machine, checkpoint, guest-staging, or qualification owners. Parse/static
tests may run ordinarily; real execution occurs only by an informed operator using the public runner.
