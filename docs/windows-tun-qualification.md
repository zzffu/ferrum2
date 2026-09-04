# Windows TUN host correctness qualification

This runbook defines the only privileged Windows TUN correctness qualification. It runs directly on
an explicitly authorized Windows host. There are no suites, profiles, guest stages, checkpoints, or
virtual-machine fallbacks.

The qualification is intentionally fixed and bounded. It builds one exact candidate and exercises
one real IPv4 Wintun adapter through eight required checks:

1. one candidate build bound to the requested commit;
2. Wintun creation and deletion;
3. TCP and UDP transport through the run-owned TUN;
4. isolation to run-owned `/32` routes;
5. live strict-route WFP object readback;
6. a network notification without replacing the WFP filter identity or sublayer weight;
7. forced process-tree termination followed by ownership-safe recovery;
8. zero adapter, route, address, process, and port residue.

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
support address, run-owned RFC 2544 `/32` routes, bounded child processes and ports, and the product
process's dynamic strict-route WFP session. It must not change a default route, system DNS, physical
adapter, WLAN state, firewall rule, sing-box process, or unrelated resource.

The evidence directory must be an absolute or relative path whose final directory does not already
exist. Keep it outside the repository. The persistent recovery ledger is under
`%PROGRAMDATA%\Ferrum2HostPerformance-v2\<RunId>\recovery.json`; recovery removes only identities
whose ownership the ledger proves.

## Inspect the fixed plan

`-PlanOnly` is unprivileged and nonmutating:

```powershell
$candidate = (git rev-parse HEAD).Trim()
pwsh -NoProfile -File tests/platform/run_windows_tun_qualification_host.ps1 `
  -PlanOnly `
  -CandidateSha $candidate
```

The plan must report `maximum_elapsed_seconds = 900`, `worker_timeout_seconds = 840`,
`build_timeout_seconds = 600`, the eight checks above, and
`execution = explicit-authorized-windows-host`.

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

- `plan.json`: candidate, time limits, fixed checks, and safety contract;
- `build.json`: exact candidate and reviewed Wintun identities;
- `runtime.json`: build, execution, worker, and total elapsed observations;
- `qualification-worker.json`: per-check, route, and WFP witnesses;
- `qualification-cleanup.json`: bounded cleanup counts;
- `qualification.json`: final supervisor verdict;
- bounded worker/supervisor logs and lower-level transaction evidence.

Accept the run only if `qualification.json` has `status = QUALIFIED`, `qualification = true`, the
requested candidate and source-bundle identities, all eight `PASS` checks, cleanup counts of zero, and
`supervisor_elapsed_seconds < 900`. A worker `PASS` without `qualification.json` is not a verdict.

## Static verification

The hosted Windows gate is nonmutating:

```powershell
pwsh -NoProfile -File tests/platform/test_windows_tun_host_qualification.ps1
```

It validates the module export, closed source bundle, fixed PlanOnly contract, acknowledgement
fail-closed behavior, exact fixed check set, and single public entrypoint. It does not create an
adapter or claim live correctness.

## Performance is separate

Correctness qualification does not call the public performance runner and does not apply performance
thresholds. Performance remains at
`tools/windows-tun/performance/run_windows_tun_performance_host.ps1`. Each run selects either the
serverless ClientDirect topology or the complete EndToEnd client/server topology. Per topology,
Quick is 24 trials (four scenarios, three interleaved pairs), Confirm is 50 trials (five scenarios,
five pairs), and Lifecycle is 20 complete product-start/probe/stop cycles. Performance evidence
cannot substitute for `qualification.json`, and qualification evidence cannot substitute for a
performance result.
