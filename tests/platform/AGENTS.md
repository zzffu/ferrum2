# Platform Qualification Script Guidelines

This directory owns the unprivileged native contract and the sole privileged Windows TUN correctness
entrypoint, `run_windows_tun_qualification_host.ps1`. The public correctness interface has only
`-PlanOnly`, `-RecoveryOnly`, and the acknowledged real run; do not add profiles, suites, repeat
counts, guest stages, or alternate runners.

The real run builds one exact candidate and executes the fixed eight-check plan. Its outer deadline
is 900 seconds, worker deadline is 840 seconds, and build deadline is 600 seconds. It requires an
already elevated PowerShell process and `-AcknowledgeHostNetworkMutation`, never auto-elevates, and
may touch only ledger-owned Wintun, RFC 2544 `/32` route/address, process, port, and the product's
dynamic strict-route and exact TCP-ingress WFP identities. Default routes, host DNS, physical
adapters, WLAN, persistent firewall rules, sing-box, and unrelated resources are outside the transaction.

`native_contract.py` owns loopback-only binary behavior; `qualify_native.py` is its thin local/hosted
entrypoint. Hosted evidence mode binds the exact GitHub SHA, runner identity, clean checkout, and
artifact paths. Static contracts and `-PlanOnly` are nonmutating and must not claim live evidence.

PowerShell libraries must not execute workflows when dot-sourced. The qualification source bundle
must enumerate every consumed file by canonical path, exact byte length, and SHA-256. Update it
atomically whenever an owned or shared source changes. A verdict requires all eight checks, the
requested candidate and bundle identities, less than 900 seconds, and zero cleanup residue.
