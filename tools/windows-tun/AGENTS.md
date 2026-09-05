# Windows TUN Tooling Guide

The repository-level and `tools/AGENTS.md` instructions remain in force. This directory owns Windows
TUN performance policy and its sole operator-facing runner,
`performance/run_windows_tun_performance_host.ps1`. Correctness qualification entrypoints stay under
`tests/platform`; reusable host modules stay under `tools/powershell`. No subtree may retain a
compatibility copy, guest fallback, or second execution path.

Treat script paths as evidence identity. Performance recipes and source manifests use canonical
`tools/windows-tun/performance/<script>.ps1` paths. Any source edit, addition, deletion, or move must
atomically update every consumer, closed file map, exact byte length, per-file SHA-256, and complete
bundle identity. Never make a manifest member optional to preserve stale evidence.

The performance host runner hides per-run adapter names, ports, temporary paths, route identities,
process IDs, ledgers, cleanup, and recovery behind its small public interface. It must not call the
correctness runner or consume a correctness verdict.

Plan-only, parsing, and static verification may run without privilege. Recovery may inspect an
empty or completed ledger without elevation, but removing live network resources requires an
already elevated shell. A real performance
run requires an already elevated shell and the literal `-AcknowledgeHostNetworkMutation` switch; the
runner must never auto-elevate. It may mutate only uniquely identified per-run Wintun resources,
dedicated RFC 2544 benchmark addresses, and the narrowest benchmark routes inside a try/finally
transaction. It must not change default routes, DNS, WFP, firewall rules, physical adapters, WLAN,
sing-box, or unrelated state.
