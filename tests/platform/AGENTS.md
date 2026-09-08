# Platform Qualification Script Guidelines

This directory owns the unprivileged native contract and the sole privileged Windows TUN correctness
entrypoint, `run_windows_tun_qualification_host.ps1`. The public correctness interface has only
`-PlanOnly`, `-RecoveryOnly`, and the acknowledged real run; do not add profiles, suites, repeat
counts, guest stages, or alternate runners.

The real run builds one exact candidate and executes the fixed eight-check plan. Its outer deadline
is 900 seconds, worker deadline is 840 seconds, and build deadline is 600 seconds. It requires an
already elevated PowerShell process and `-AcknowledgeHostNetworkMutation`, never auto-elevates, and
may touch only ledger-owned Wintun, RFC 2544 `/32` route/address, process, port, and the product's
dynamic strict-route and exact TCP-ingress WFP identities. The acknowledged run also owns narrowly
scoped Windows Firewall rules for the exact current test binaries, installed before launch and
removed/read back by cleanup or recovery. Existing rules, global notification settings, default
routes, host DNS, physical adapters, WLAN, sing-box and unrelated resources remain outside scope.

`native_contract.py` owns loopback-only binary behavior; `qualify_native.py` is its thin local/hosted
entrypoint. Hosted evidence mode binds the exact GitHub SHA, runner identity, clean checkout, and
artifact paths. Static contracts and `-PlanOnly` are nonmutating and must not claim live evidence.

PowerShell libraries must not execute workflows when dot-sourced. The qualification source bundle
must enumerate every consumed file by canonical path, exact byte length, and SHA-256. Update it
atomically whenever an owned or shared source changes. A verdict requires all eight checks, the
requested candidate and bundle identities, less than 900 seconds, and zero cleanup residue.

The data-path check requires four established flows behind a barrier in each generation, sustained
checked full-duplex transfers, observed backpressure/recovery, half-close and UDP/fragments during
TCP activity. Active reset must retire old TCP and validate a fresh tagged reply on the same UDP
socket without counting an old buffered reply as new success. Keep all workload witnesses in the
final supervisor verdict; a short probe or harness-owned socket drop cannot substitute.

Ordinary `python -B -m unittest discover -s tests/platform -p 'test_*.py' -v` includes injected
startup/cleanup contracts and exclusive loopback port handoff. PowerShell-dependent tests skip
without `pwsh`, not silently pass. TUN-only performance lives in the crate/Python controller and
does not belong to this privileged execution interface.
