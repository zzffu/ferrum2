# Windows TUN Tooling Guide

The repository-level and `tools/AGENTS.md` instructions remain in force. This directory separates
neutral Windows TUN Lab mechanics from performance policy and execution. `lab/` owns qualification-
reusable topology and VM transaction support. `performance/` owns the sole operator-facing real-host
performance runner and its collectors. Windows TUN correctness qualification entry points and guest
controllers remain under `tests/platform`; reusable modules remain under `tools/powershell`. No
subtree may retain a compatibility copy or fallback into another execution path.

Treat script paths as evidence identity. Recipes and source manifests use canonical
`tools/windows-tun/<subtree>/<script>.ps1` paths. Any performance source edit, addition, deletion, or
move must atomically update every consumer, closed file map, exact byte length, per-file SHA-256, and
complete bundle identity. Never make a manifest member optional to preserve stale evidence.

Lab topology contracts use `lab_checkpoint` exclusively and remain available to qualification.
Performance must not bind or invoke Lab VM/checkpoint/staging owners, qualification evidence, or
qualification host controllers. Its host runner must hide per-run adapter names, ports, temporary
paths, route identities, process IDs, ledgers, cleanup, and recovery behind the small public interface.

Plan-only, recovery, parsing, and static verification may run without privilege. A real performance
run requires an already elevated shell and the literal `-AcknowledgeHostNetworkMutation` switch; the
runner must never auto-elevate. It may mutate only uniquely identified per-run Wintun resources,
dedicated RFC 2544 benchmark addresses, and the narrowest benchmark routes inside a try/finally
transaction. It must not change default routes, DNS, WFP, firewall, physical adapters, WLAN, sing-box,
or unrelated state. Ordinary tests and qualification scripts must not invoke this host runner.
