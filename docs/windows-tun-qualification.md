# Windows TUN host correctness qualification

This runbook defines the only privileged Windows TUN correctness qualification. It runs directly on
an explicitly authorized Windows host. There are no suites, profiles, guest stages, checkpoints, or
virtual-machine fallbacks.

The qualification is intentionally fixed and bounded. It builds one exact candidate and exercises
one real single-stack Wintun adapter (`-AddressFamily IPv4|IPv6`, default `IPv4`) through eight required checks:

1. one candidate build bound to the requested commit;
2. Wintun creation and deletion, including normal-exit cleanup of both product-owned dynamic WFP
   sessions;
3. sustained, checked system TCP and UDP/fragment traffic through the run-owned TUN;
4. isolation to run-owned `/32` IPv4 or `/128` IPv6 routes, with the owned TUN's connected prefix;
5. simultaneous live readback of the persistent strict-route identity and the exact, process-owned
   TCP-ingress filter;
6. a real network reset with active work that preserves strict-route filter IDs and sublayer weight,
   replaces the listener/filter epoch, retires old TCP, and validates fresh TCP and same-tuple UDP;
7. forced process-tree termination followed by ownership-safe recovery and dynamic-WFP absence;
8. zero adapter, route, address, process, port, strict-route WFP, and TCP-ingress WFP residue.

Each run proves only its selected family. IPv4 and IPv6 require separate successful runs; neither
proves dual-stack correctness. All product, support, metrics, workload and listener endpoints use
the selected family, and IPv6 sockets disable IPv4-mapped operation.

A result is qualified only when every check passes, cleanup reports zero residue, and the complete
supervised command finishes in less than 900 seconds.

## Data-path and socket qualification

The live workload establishes four TCP connections and waits at a shared barrier before exercising
each generation. Every connection verifies an initial 1 KiB exchange, pauses its reader until the
writer is observably unwritable for 100 ms, exchanges 8 MiB with concurrent sending and receiving,
verifies another request, then sends a final request with write-half shutdown and checks its response
and remote EOF. Each paused TCP flow also completes four small UDP and four 4096-byte UDP requests.
The support endpoint validates every request byte and returns a small acknowledgement binding its
length and generation/flow identity; it does not send oversized UDP responses unsupported by TUN.
The runner reads back the selected-family owned interface's `NlMtu = 1420`. IPv6 workload UDP
sockets explicitly enable source fragmentation with `IPV6_MTU_DISCOVER = IP_PMTUDISC_DONT`;
the live fragment/reassembly counters must independently prove fragmented ingress. Loopback
self-checks do not establish IP fragmentation. No throughput threshold makes this a performance test.

Before route reset, another TCP flow has an unsatisfied checked transfer and the workload has sent
one UDP request without consuming its reply. The ready/release handshake binds this work to the
controller's real reset and WFP epoch observations. Old TCP must terminate by EOF or connection
reset, not timeout. The same UDP socket sends a new generation-tagged request; any buffered old
response is separately accounted and cannot count as fresh success. Four fresh TCP connections
then repeat all phases. This does not claim that an externally buffered old datagram proves an
internal product task survived reset, or that old TCP connections resume seamlessly.

The Rust workload has a 55-second aggregate deadline inside the controller's 60-second workload
bound. A missing concurrency, pressure, payload, retirement or fresh-response witness fails the
fixed data-path/reset check; a generic short-probe `PASS` is insufficient.

Ordinary `ferrum2-tun` library tests separately use real loopback sockets to verify exhausted
readiness rearming, saturated-write recovery, half-close and fencing a blocked writer. These do
not create Wintun or change host networking. The memory performance adapter cannot replace this
reactor coverage. Packet-generation tests retain deterministic stale-capability isolation checks.

Generation fencing uses abortive closure for still-owned sockets, not normal graceful-drop
semantics. The TUN owner retains the old tuple maps and ingress guard while it delivers the
kernel-generated reset back to the application. Only successful adapter delivery satisfies that
obligation; a previously delivered FIN does not. This drain is bounded and fails closed rather
than publishing a completed reset while the application connection remains stuck.

## Safety boundary

Real execution requires:

- Windows PowerShell 7.4 or later;
- an already elevated shell; the runner never elevates itself;
- the literal `-AcknowledgeHostNetworkMutation` switch;
- a clean, exact 40-character candidate commit available in the local repository;
- the reviewed Wintun 0.14.1 archive in `%LOCALAPPDATA%\Ferrum2\assets`,
  `%LOCALAPPDATA%\Ferrum2`, or the current user's Downloads directory. Its required SHA-256 is
  `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`.

The runner may create only one run-owned Wintun adapter at a time, one run-owned loopback support
address, exact run-owned host routes, bounded child processes and ports, the product process's
dynamic WFP sessions, and narrowly scoped, ledger-owned Windows Firewall rules for the current
test executable paths. IPv4 retains RFC 2544 addresses and `/32` explicit routes, with a `/30`
connected prefix on the owned TUN. IPv6 derives a run-unique ULA namespace from the run ID:
the TUN uses `fd00:<run-id groups>::2/126`, its synthetic peer is `::1` in that prefix, and support
and reset use distinct `/128` addresses in the same run's separate `:1::` namespace. Only the
owned TUN may receive the `/126` connected route; all explicit IPv6 routes remain `/128`.
Rules are installed before launching each new build so previous-path authorization is not relied
upon; there is no automatic clicking of security dialogs.
The ingress filter is a hard permit at the selected family's `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4`
or `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6`, scoped by all of the
candidate application ID, TCP protocol, run-owned TUN LUID, exact listener address and ephemeral
port, and exact synthetic peer. The product's WFP session and sublayer remain process-owned and
dynamic. Runner-owned firewall rules are separate: they use Windows PersistentStore and must be
deleted by normal cleanup or recovery, not mistaken for kernel-dynamic rules.

Windows NetSecurity rejects IPv6 `::1` firewall address scopes. IPv6 therefore installs six real
rules: two exact ULA support rules, one exact TUN client-ingress rule per product lifetime, and
one exact TUN workload-UDP reply rule. It does not create substitute or widened rules for the
four `::1` services in each lifetime. Their actual IPv6 loopback communications must succeed under
unchanged host policy; a policy failure is not bypassed. IPv4 retains its eighteen-rule contract.
The plan records the selected rule count, and the final supervisor requires exactly that evidence.
Metrics requests connect directly to the selected loopback endpoint with `-NoProxy`; inherited
HTTP proxy settings must not redirect readiness or reset evidence.

The client listener uses a closed two-phase rule because Windows cannot resolve an interface alias
before the product creates that TUN. Before launch, the rule is limited to the exact executable,
run-owned local address, synthetic peer and observed dynamic TCP port range, without an
interface filter. After adapter identity and MTU readback, the same rule is narrowed to that exact
TUN alias before test traffic. The planned alias and transition are written before each mutation;
recovery accepts only the two recorded transition states, never an arbitrary foreign interface.
Final qualification rejects a rule left in its prelaunch state. Other support, metrics, server and
workload reply rules use exact existing interfaces throughout. Both initial and narrowed readbacks
are retained, along with independent absence checks after cleanup.
Before mutation the ledger also records the interface GUID and LUID. Recovery recognizes only those
recorded identities when Windows replaces a deleted adapter's alias with its GUID or LUID in rule
readback; it does not accept an arbitrary replacement interface.

The narrowly scoped hard permit remains subject to higher-priority hard blocks, callout vetoes, and
policy at other filtering layers. A policy conflict is a real qualification failure: the runner
must not broaden the filter, disable Base Filtering Engine or firewall enforcement, change profile
notification settings or modify existing rules. Only the declared run-owned test rules are allowed.
It must not change a default route, system DNS, physical adapter, WLAN state, sing-box or unrelated
resource. A catastrophic interruption can leave run-owned rules until recovery; the durable ledger
retains exact rule and executable identities, and ambiguous ownership never authorizes deletion.

IPv4 preserves its reset stimulus: two successive `/32` rows for an otherwise unused RFC 2544
address, first through an existing hardware interface's current gateway and then on-link at a
lower metric after removing the exact first owned row. IPv6 uses an unused run-owned ULA `/128`
on the existing loopback interface, replacing an on-link metric-4094 row with metric 4093.
IPv6 needs no physical IPv6 gateway. Neither path modifies existing routes or interface settings.
A selector keeps the unused endpoint in the underlay snapshot while retaining the normal proxy
as selected exit; no workload traffic uses the probe. Both paths must observe an actual session
generation change, old-TCP retirement and a replaced ingress epoch. A route notification alone
does not constitute the required semantic reset.

The evidence directory must be an absolute or relative path whose final directory does not already
exist. Keep it outside the repository. The persistent recovery ledger is under
`%PROGRAMDATA%\Ferrum2HostPerformance-v2\<RunId>\recovery.json`; recovery removes only identities
whose ownership the ledger proves.

Recovery ledger schema 2 retains expected adapter, route, address, process, and port identities even
after their actionable records are retired. The WFP sessions require no recovery mutation: normal
exit closes them explicitly and Windows removes them on process death. Qualification nevertheless
enumerates their fixed session/sublayer identities after normal exit, network-reset epoch replacement,
and strong kill; an unreadable WFP snapshot cannot establish absence.

Before product startup the ledger records at most 4096 distinct adapter GUIDs. Final cleanup
independently enumerates adapters, routes, addresses, processes, listening ports, both dynamic WFP
identity sets and owned firewall rules; read failures cannot establish zero residue. A created adapter is tracked by GUID
as well as name. An unfinished creation plan can close only when its name is absent and every
observed adapter GUID was in the baseline. Unknown new adapter GUIDs fail closed. Process absence
uses PID plus valid UTC creation-time identity, not PID alone: a different verified birth belongs
to another lifetime and is never removed. Missing birth information or a changed executable within
the same lifetime still fails closed. ISO strings and PowerShell's materialized UTC DateTime values
are normalized to ticks before comparison.

### Standing authorization on the owner's development host

On 2026-09-08 the repository owner authorized subsequent IPv4 and IPv6 single-stack qualification
runs on this Windows development host without repeated interactive confirmation, including the
test TUN's IPv6 `/126` connected prefix. This authorization is limited to the ledger-owned,
bounded resources above and requires independently verified zero residue. It does not authorize
other hosts, default routes, physical adapter configuration, system DNS or unrelated firewall/WFP
changes. The runner still requires elevation and the literal `-AcknowledgeHostNetworkMutation`
switch on every real run; automation supplies that switch under this recorded authorization.

## Inspect the fixed plan

`-PlanOnly` is unprivileged and nonmutating:

```powershell
$candidate = (git rev-parse HEAD).Trim()
pwsh -NoProfile -File tests/platform/run_windows_tun_qualification_host.ps1 `
  -PlanOnly `
  -CandidateSha $candidate
pwsh -NoProfile -File tests/platform/run_windows_tun_qualification_host.ps1 `
  -PlanOnly -CandidateSha $candidate -AddressFamily IPv6
```

The plan must report `maximum_elapsed_seconds = 900`, `worker_timeout_seconds = 840`,
`build_timeout_seconds = 600`, the eight checks above, selected `address_family`,
`tun_connected_prefix_length` of 30 or 126, the full exact TCP-ingress scope,
dynamic-only WFP lifetime, and `execution = explicit-authorized-windows-host`.

## Execute qualification

From an already elevated PowerShell process:

```powershell
$candidate = (git rev-parse HEAD).Trim()
$evidence = Join-Path $env:TEMP (
  "ferrum2-host-qualification-" + [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")
)
pwsh -NoProfile -File tests/platform/run_windows_tun_qualification_host.ps1 `
  -CandidateSha $candidate `
  -AddressFamily IPv6 `
  -EvidenceDirectory $evidence `
  -AcknowledgeHostNetworkMutation
```

The outer supervisor terminates the worker process group after 840 seconds, reserves 45 seconds for
bounded recovery, and rejects any successful-looking result at or beyond 900 seconds. The candidate
build itself is capped at 600 seconds. The fixed check set has no operator-adjustable repeat count.
The acknowledgement authorizes the narrowly enumerated temporary host mutations above; it does not
authorize retaining rules after cleanup, changing unrelated firewall policy or enabling another family.
Omit `-AddressFamily IPv6` (or pass `IPv4`) for the retained IPv4 qualification. Run families serially.

After an interrupted run, inspect and recover run-owned residue with:

```powershell
pwsh -NoProfile -File tests/platform/run_windows_tun_qualification_host.ps1 -RecoveryOnly
```

`-RecoveryOnly` derives the family from the durable ledger and verified resource identities; it
accepts no family override and refuses ambiguous ownership. Removing live, ledger-owned network
resources still requires an elevated shell.

## Evidence and verdict

`tools/powershell/Ferrum2.Qualification.Host/bundle.json` is the closed qualification source identity.
Every listed canonical path, byte length, and SHA-256 must match before planning or mutation.
Plan, build, runtime, worker, cleanup, final verdict and native workload/reset handshakes carry
`address_family`; mismatched families fail closed. The qualification writes:

- `plan.json`: candidate, time limits, fixed checks, exact ingress scope, and safety contract;
- `build.json`: exact candidate and reviewed Wintun identities;
- `runtime.json`: build, execution, worker, and total elapsed observations;
- `qualification-worker.json`: per-check, route, strict-route WFP, TCP-ingress listener/filter, reset
  epoch, checked data-path/reset workload, and cleanup-absence witnesses;
- `qualification-cleanup.json`: bounded adapter, route, address, process, port, and dynamic-WFP
  cleanup counts;
- `qualification.json`: final supervisor verdict, including TCP-ingress and data-path evidence;
- `supervisor-outcome.json`: worker/recovery exit and timeout observations, primary error, and
  phase-specific cleanup failures;
- bounded worker/supervisor logs and lower-level transaction evidence.

The supervisor retains worker and recovery logs before deleting its owned temporary directory.
Export, process-group close, or directory cleanup failure prevents publication of `qualification.json`;
the total deadline includes this finalization. Failed export retains the temporary evidence tree.

Accept the run only if `qualification.json` has `status = QUALIFIED`, `qualification = true`, the
requested candidate and source-bundle identities, all eight `PASS` checks, four exact IPv4
TCP-ingress filter snapshots with the six required equality conditions and hard-permit flag, a
strict-route-preserving/ingress-replacing reset witness, checked two-generation data-path evidence,
normal-exit and strong-kill WFP absence, cleanup counts of zero, and
`supervisor_elapsed_seconds < 900`. A worker `PASS` without
`qualification.json` is not a verdict.

## Static verification

The hosted Windows gate is nonmutating:

```powershell
pwsh -NoProfile -File tests/platform/test_windows_tun_host_qualification.ps1
```

It validates the module export, closed source bundle, fixed PlanOnly contract, acknowledgement
fail-closed behavior, exact fixed check set, and single public entrypoint. Its offline controller
fixtures also reject a widened ingress filter, a missing hard-permit flag, an unchanged listener
epoch, and dynamic-WFP rollback residue. It does not create an adapter, mutate WFP, or claim live
correctness.

Run the ordinary Python platform discovery to cover startup failure preservation, exclusive
listener handoff and independent cleanup readback:

```text
python -B -m unittest discover -s tests/platform -p 'test_*.py' -v
```

Use `python3` on Unix. PowerShell-dependent cases skip when `pwsh` is absent; such a skip is not
proof of Windows/Unix port exclusivity. TCP reservations bind and listen, while UDP reservations
bind only. Reservations are held through preceding product startup and released immediately before
their owning product starts. The final explicit-bind handoff remains fallible and is not retried.

Private process, build, ownership and cleanup primitives now live in
`tools/powershell/Ferrum2.Qualification.Host`. The historical recovery ledger directory and schema
remain unchanged solely so already-created resources can still be recovered safely; this is not
an alternate performance entrypoint.

## Performance is separate

TUN performance uses the crate-owned `tun-benchmark` example and
`python -B -m tools.performance_candidate tun-mock-calibrate|tun-mock-run|tun-mock-validate`.
It runs real TUN logic against bounded memory I/O without host network mutation. Quick uses
36 trials and Confirm 60 across six scenarios. See the [performance evidence guide](performance-evidence.md).
There is no privileged host A/B performance runner or timed Lifecycle performance mode.
Neither internal packet performance nor this fixed IPv4 correctness qualification proves
whole-product throughput or correctness on an untested host policy.
