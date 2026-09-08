# Documentation index

Start with the [project README](../README.md) for building and running the local SOCKS5 example.
Commands assume the repository root unless a guide says otherwise. Use `python` on Windows and
`python3` on Unix; multiline shell examples identify their shell.

## Configuration

| Guide or example | Scope |
|---|---|
| [Local SOCKS5 client](examples/client-v2-socks5.toml) and [Shadowsocks server](examples/server-v2.toml) | Matching loopback-only schema-v2 examples with a synthetic test key |
| [F2P client](examples/client-v2-f2p.toml) and [F2P server](examples/server-v2-f2p.toml) | TLS/TCP proxy with UDP over TCP and balanced/realtime profiles; provision token/certificate files before running |
| [DNS and RuleSets](config-v2-dns-rulesets.md) | Offline validation, materialization, resolution/detours, SRS loading, cache, refresh, and diagnostics |
| [DNS/RuleSet example](examples/client-v2-dns-rulesets.toml) | Annotated client configuration; replace documentation endpoints and key before deployment |
| [Managed TUN](config-v2-tun.md) and [TUN example](examples/client-v2-tun.toml) | Windows x86_64, IPv4/IPv6, route/dial policy, UDP associations, lifecycle, and metrics |
| [Embedded rocom recording and decoder](architecture/rocom-recording-design.md) | Opt-in sensitive TCP/key evidence, single-process integration, offline decoding, and failure replay |
| [Embedded client dashboard](architecture/dashboard-design.md) | Bun/React single-HTML build, loopback authentication, live connections, generation-bound controls, private config transactions and verification evidence |

## Qualification and performance

| Guide | Scope |
|---|---|
| [Windows TUN correctness](windows-tun-qualification.md) | Real socket coverage and fixed eight-check host plan: sustained traffic, active reset, WFP, 900-second bound and recovery |
| [Performance evidence](performance-evidence.md) | TUN-only mock I/O, calibrated paired evidence, Linux controller ownership and retention |
| [Rule qualification runner](../tools/ferrum2-rule-qualification/README.md) | Explicit measurement commands, schemas, and reviewed A/A calibration |
| [Rule performance controller](../tools/performance_rule/README.md) | Calibration preflight, requested workload identity, evidence budget, and atomic output |
| [Rule evidence tests](../tests/performance_rule/README.md) | Offline synthetic contracts and content-addressed external archive verification |

## Architecture and contribution

| Guide | Scope |
|---|---|
| [Repository guidelines](../AGENTS.md) | Build/test commands, compatibility policy, and contribution rules; scoped guides refine ownership |
| [Invariant ledger](architecture/invariants.md) | Owner boundaries, behavioral contracts, evidence, and remaining gaps |
| [TUN system TCP design](architecture/tun-system-tcp-design.md) | Windows TCP conversion with native UDP unchanged; selected minimal temporary ingress allowance and authorized host qualification |
| [F2P protocol design and evidence](architecture/f2p-design.md) | Protocol ownership, TLS/auth, two-stage TCP admission, bounded UDP profiles, configuration and loopback evidence |
| [Gate ledger](architecture/gates.md) | Current workflows, triggers, commands, privilege boundaries, and required contexts |
| [Fixture and evidence ledger](architecture/fixtures-and-evidence.md) | Reviewed inputs, vendor patches, hashes, and retention requirements |
| [Refactor consumer ledger](architecture/refactor-consumers.md) | Identities and consumers that must change atomically during moves or renames |

Shared fixture provenance is documented alongside [SRS inputs](../tests/fixtures/srs/README.md) and
[DNS TLS inputs](../tests/fixtures/dns-tls/README.md). One-off audits, implementation plans and
measurement reports remain in Git history, not the current guide index. Their results do not
qualify the current checkout; outstanding performance questions are tracked in the
[performance evidence guide](performance-evidence.md#open-qualification-and-optimization-questions).
