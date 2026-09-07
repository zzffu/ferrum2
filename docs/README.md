# Documentation index

Start with the [project README](../README.md) for building and running the local SOCKS5 example.
Commands assume the repository root unless a guide says otherwise. Use `python` on Windows and
`python3` on Unix; multiline shell examples identify their shell.

## Configuration

| Guide or example | Scope |
|---|---|
| [Local SOCKS5 client](examples/client-v2-socks5.toml) and [Shadowsocks server](examples/server-v2.toml) | Matching loopback-only schema-v2 examples with a synthetic test key |
| [DNS and RuleSets](config-v2-dns-rulesets.md) | Offline validation, materialization, resolution/detours, SRS loading, cache, refresh, and diagnostics |
| [DNS/RuleSet example](examples/client-v2-dns-rulesets.toml) | Annotated client configuration; replace documentation endpoints and key before deployment |
| [Managed TUN](config-v2-tun.md) and [TUN example](examples/client-v2-tun.toml) | Windows x86_64, IPv4/IPv6, route/dial policy, UDP associations, lifecycle, and metrics |
| [Network model v2 migration](network-model-v2-migration.md) | Removed schema/fields and current behavior; no compatibility runtime |

## Qualification and performance

| Guide | Scope |
|---|---|
| [Windows TUN correctness](windows-tun-qualification.md) | Fixed eight-check host plan, 900-second bound, source identity, recovery, and final verdict |
| [Performance evidence](performance-evidence.md) | Controller ownership, host performance planning/validation, paired evidence, and retention |
| [Rule qualification runner](../tools/ferrum2-rule-qualification/README.md) | Explicit measurement commands, schemas, and reviewed A/A calibration |
| [Rule performance controller](../tools/performance_rule/README.md) | Calibration preflight, requested workload identity, evidence budget, and atomic output |
| [Rule evidence tests](../tests/performance_rule/README.md) | Offline synthetic contracts and content-addressed external archive verification |
| [2026-09-05 Windows TUN Confirm and CPU report](windows-tun-confirm-cpu-profile-report-2026-09-05.md) | Historical A/A measurements and CPU attribution; not proof of a code-change speedup |

## Architecture and contribution

| Guide | Scope |
|---|---|
| [Repository guidelines](../AGENTS.md) | Build/test commands, compatibility policy, and contribution rules; scoped guides refine ownership |
| [Invariant ledger](architecture/invariants.md) | Owner boundaries, behavioral contracts, evidence, and remaining gaps |
| [2026-09-05 full engineering audit](architecture/engineering-audit-2026-09-05.md) | Current full-crate audit; architecture and profiling follow after review |
| [2026-09-05 engineering design](architecture/engineering-design-2026-09-05.md) | Selected module ownership, interface changes, alternatives, costs, and implementation/qualification order |
| [TUN system TCP design](architecture/tun-system-tcp-design.md) | Windows TCP conversion with native UDP unchanged; firewall policy and live qualification authorization remain implementation gates |
| [2026-09-05 engineering remediation](architecture/engineering-remediation-2026-09-05.md) | Current review coverage, fixes, validation, and remaining gaps; [batch evidence](architecture/engineering-remediation-evidence-2026-09-05.md) retains failures and measurements |
| [Gate ledger](architecture/gates.md) | Current workflows, triggers, commands, privilege boundaries, and required contexts |
| [Fixture and evidence ledger](architecture/fixtures-and-evidence.md) | Reviewed inputs, vendor patches, hashes, and retention requirements |
| [Refactor consumer ledger](architecture/refactor-consumers.md) | Identities and consumers that must change atomically during moves or renames |

Shared fixture provenance is documented alongside [SRS inputs](../tests/fixtures/srs/README.md) and
[DNS TLS inputs](../tests/fixtures/dns-tls/README.md). Historical measurements and baseline counts
describe their recorded revisions; they do not automatically qualify the current checkout.
