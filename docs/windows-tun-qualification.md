# Windows TUN host correctness qualification

This runbook defines the only privileged Windows TUN correctness qualification. It runs directly on
an explicitly authorized Windows host. There are no suites, profiles, guest stages, checkpoints, or
virtual-machine fallbacks.

The qualification is intentionally fixed and bounded. It builds one exact candidate and exercises
one real IPv4 Wintun adapter through eight required checks:

1. one candidate build bound to the requested commit;
2. Wintun creation and deletion, including normal-exit cleanup of both product-owned dynamic WFP
   sessions;
3. candidate system TCP and unchanged UDP transport through the run-owned TUN;
4. isolation to run-owned `/32` routes;
5. simultaneous live readback of the persistent strict-route identity and the exact, process-owned
   TCP-ingress filter;
6. a real network reset that preserves strict-route filter IDs and sublayer weight, replaces the
   listener/filter epoch, proves the old ingress filter absent, and passes TCP and UDP again;
7. forced process-tree termination followed by ownership-safe recovery and dynamic-WFP absence;
8. zero adapter, route, address, process, port, strict-route WFP, and TCP-ingress WFP residue.

The live runner proves only this IPv4 scenario. It neither establishes an IPv6 address/route nor
claims IPv6 host correctness; packet-level IPv6 coverage is not a substitute for separately
authorized live IPv6 qualification.

A result is qualified only when every check passes, cleanup reports zero residue, and the complete
supervised command finishes in less than 900 seconds.

## Safety boundary

Real execution requires:

- Windows PowerShell 7.4 or later;
- an already elevated shell; the runner never elevates itself;
- the literal `-AcknowledgeHostNetworkMutation` switch;
- a clean, exact 40-character candidate commit available in the local repository;
- the reviewed Wintun 0.14.1 archive in `%LOCALAPPDATA%\Ferrum2\assets`,
  `%LOCALAPPDATA%\Ferrum2`, or the current user's Downloads directory. Its required SHA-256 is
  `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`.

The runner may create only one run-owned Wintun adapter at a time, a run-owned RFC 2544 loopback
support address, run-owned RFC 2544 `/32` routes, bounded child processes and ports, the product
process's dynamic strict-route WFP session, and its separate dynamic exact TCP-ingress WFP session.
The ingress filter is a hard permit at `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4`, scoped by all of the
candidate application ID, TCP protocol, run-owned TUN LUID, exact listener address and ephemeral
port, and exact synthetic peer. Its session and sublayer are process-owned and dynamic; the runner
does not create a provider object or a persistent Windows Firewall/COM rule.

The narrowly scoped hard permit remains subject to higher-priority hard blocks, callout vetoes, and
policy at other filtering layers. A policy conflict is a real qualification failure: the runner
must not broaden the filter, disable Base Filtering Engine or firewall enforcement, or add a
persistent exception. It must not change a default route, system DNS, physical adapter, WLAN state,
sing-box process, or unrelated resource.

The reset stimulus records two successive `/32` rows for an otherwise unused RFC 2544 address:
first through an existing hardware interface's current gateway, then it removes that exact owned
row before adding a lower-metric on-link row on the same interface. Existing unrelated routes and
interface settings are not modified. A selector keeps
the probe endpoint in the underlay snapshot while retaining the normal proxy as its selected exit;
no workload traffic uses the probe endpoint. An unrelated loopback route notification alone does
not constitute the required semantic reset.

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
independently enumerates adapters, routes, addresses, processes, listening ports, and both dynamic
WFP identity sets; read failures cannot establish zero residue. A created adapter is tracked by GUID
as well as name. An unfinished creation plan can close only when its name is absent and every
observed adapter GUID was in the baseline. An unknown new GUID or reused process identity fails
closed without authorizing removal.

## Inspect the fixed plan

`-PlanOnly` is unprivileged and nonmutating:

```powershell
$candidate = (git rev-parse HEAD).Trim()
pwsh -NoProfile -File tests/platform/run_windows_tun_qualification_host.ps1 `
  -PlanOnly `
  -CandidateSha $candidate
```

The plan must report `maximum_elapsed_seconds = 900`, `worker_timeout_seconds = 840`,
`build_timeout_seconds = 600`, the eight checks above,
`live_address_family = "IPv4 only (RFC2544 198.18.0.0/15)"`, the full exact TCP-ingress scope,
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
  -EvidenceDirectory $evidence `
  -AcknowledgeHostNetworkMutation
```

The outer supervisor terminates the worker process group after 840 seconds, reserves 45 seconds for
bounded recovery, and rejects any successful-looking result at or beyond 900 seconds. The candidate
build itself is capped at 600 seconds. The fixed check set has no operator-adjustable repeat count.
The acknowledgement authorizes the narrowly enumerated temporary host mutations above; it does not
authorize persistent firewall changes or expand the run beyond IPv4.

After an interrupted run, inspect and recover run-owned residue with:

```powershell
pwsh -NoProfile -File tests/platform/run_windows_tun_qualification_host.ps1 -RecoveryOnly
```

`-RecoveryOnly` refuses ambiguous planned resources. Removing live, ledger-owned network resources
still requires an elevated shell.

## Evidence and verdict

`tools/powershell/Ferrum2.Qualification.Host/bundle.json` is the closed qualification source identity.
Every listed canonical path, byte length, and SHA-256 must match before planning or mutation. The
qualification writes:

- `plan.json`: candidate, time limits, fixed checks, exact ingress scope, and safety contract;
- `build.json`: exact candidate and reviewed Wintun identities;
- `runtime.json`: build, execution, worker, and total elapsed observations;
- `qualification-worker.json`: per-check, route, strict-route WFP, TCP-ingress listener/filter, reset
  epoch, and cleanup-absence witnesses;
- `qualification-cleanup.json`: bounded adapter, route, address, process, port, and dynamic-WFP
  cleanup counts;
- `qualification.json`: final supervisor verdict, including the complete TCP-ingress evidence;
- `supervisor-outcome.json`: worker/recovery exit and timeout observations, primary error, and
  phase-specific cleanup failures;
- bounded worker/supervisor logs and lower-level transaction evidence.

The supervisor retains worker and recovery logs before deleting its owned temporary directory.
Export, process-group close, or directory cleanup failure prevents publication of `qualification.json`;
the total deadline includes this finalization. Failed export retains the temporary evidence tree.

Accept the run only if `qualification.json` has `status = QUALIFIED`, `qualification = true`, the
requested candidate and source-bundle identities, all eight `PASS` checks, four exact IPv4
TCP-ingress filter snapshots with the six required equality conditions and hard-permit flag, a
strict-route-preserving/ingress-replacing reset witness, normal-exit and strong-kill WFP absence,
cleanup counts of zero, and `supervisor_elapsed_seconds < 900`. A worker `PASS` without
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

## Performance is separate

Correctness qualification does not call the public performance runner and does not apply performance
thresholds. Performance remains at
`tools/windows-tun/performance/run_windows_tun_performance_host.ps1`. Each run selects either the
serverless ClientDirect topology or the complete EndToEnd client/server topology. Per topology,
Quick is 24 trials (four scenarios, three interleaved pairs), Confirm is 50 trials (five scenarios,
five pairs), and Lifecycle is 20 complete product-start/probe/stop cycles. Performance evidence
cannot substitute for `qualification.json`, and qualification evidence cannot substitute for a
performance result.
