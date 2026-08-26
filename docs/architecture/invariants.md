# Invariant Ledger

This ledger is the review index for behavior that a structural refactor must preserve. It is not a
second implementation. A change updates the owner, evidence, gap, and affected-PR columns in the same
pull request. `last verified` identifies the source snapshot whose evidence was inspected; `pending`
means the contract is known but its automated proof is incomplete.

## R0 baseline identity

| Field | Baseline |
|---|---|
| Git commit | `88d169686a3f87037d968f92f9c143e1e33c1169` |
| Rust/Cargo | `1.97.1`; edition 2024; resolver 3 |
| Supported build targets | `x86_64-pc-windows-msvc`, `x86_64-unknown-linux-gnu`, `x86_64-unknown-linux-musl` |
| Workspace members | 17 at the baseline commit; the current locked workspace has 19 members |
| Production Rust | 104 tracked `bins/*/src` and `crates/*/src` files, 109,756 physical lines |
| Non-vendor repository Rust | 189 files, 171,739 physical lines |
| Tracked non-vendor code | 217 `.rs/.py/.ps1/.sh/.yml/.yaml` files, 226,247 physical lines |
| Production `#[cfg` occurrences | 604 |
| Production lines containing the `unsafe` keyword | 209 |
| `#[allow(unsafe_code)]` declarations | 1 |

Counts above are navigation data, not mechanical acceptance thresholds. They were measured from the
committed tree (`git show HEAD:<path>`), so concurrent uncommitted refactors do not contaminate the
baseline.

The current `cargo metadata --locked --no-deps` member set and direct internal normal/dev dependency
declarations reduce to the following graph (a dash means no internal Ferrum2 dependency):

```text
core/crypto/net/observability/sniff/m0-harness -> -
rule -> core                       socks5 -> core
config -> core, crypto, rule       shadowsocks -> core, crypto
dns -> core, net, rule             ruleset -> core, dns, rule
runtime -> core, net               platform-windows -> net
tun -> net, platform-windows, runtime
client -> config, core, crypto, dns, net, observability, platform-windows,
          rule, ruleset, runtime, shadowsocks, sniff, socks5, tun
server -> config, core, crypto, dns, net, observability, platform-windows,
          rule, ruleset, runtime, shadowsocks, sniff
m4-qualification -> core, crypto, shadowsocks, socks5
rule-qualification -> core, dns, rule
```

The executable declarative policy fails if an unrecorded member appears. Exact internal dependency
allowlists keep runtime limited to core/net, the Windows platform crate limited to net, RuleSet free
of runtime/config/platform back-edges, and observability free of all Ferrum2 dependencies.

### Reviewed size exceptions

`crates/ferrum2-tun/src/packet.rs` and `crates/ferrum2-tun/src/reassembly.rs` are the only production
Rust files above 1,000 physical lines. They remain explicit protocol-owner exceptions: `packet.rs`
keeps the canonical IPv4/IPv6 validation and checksum vocabulary together, while `reassembly.rs`
keeps fragment interval accounting, overlap rejection, expiry, and completed-packet reconstruction
inside one bounded state machine. Their reviewed packet corpus and fuzz seeds exercise those coupled
invariants. Any further growth, duplicated parser, second reassembly owner, or independent policy
branch ends the exception and requires an owner-preserving split.

## Configuration and lifecycle

| ID | Owner | Observable contract | Existing test/evidence | Gap / affected PRs | Gate | Last verified |
|---|---|---|---|---|---|---|
| CFG-01/02 | `ferrum2-config` | 1 MiB pre-parse bound; UTF-8/TOML/unknown/version/legacy input fails closed and redacted | `crates/ferrum2-config/tests/config_contract.rs`; root config fixtures | None known; CFG refactors | ordinary Rust | baseline |
| CFG-03A | bins + config | Bare `--check-config` performs prepare only and has no runtime/network side effects | `tests/m0-harness/tests/config_cli.rs` | Side-effect sentinel coverage remains explicit | ordinary m0 | current |
| CFG-03B/04 | bins + role-local materializers | Materialized check is bounded, starts no steady-state root, joins resources, and retains client/server failure codes 1/2 | `tests/m0-harness/tests/config_materialize.rs` | No shared bootstrap crate: private egress/platform capabilities stay in each binary | ordinary m0 | architecture stabilization |
| CFG-05/06 | config + role-local materializers | Dependency plan is complete, deterministic and dependency-first; prepare/finish hide no I/O and reject incomplete resources | `crates/ferrum2-config/tests/v2_prepare_contract.rs`; bin `run/materialize` tests | None known | ordinary Rust | current |
| CFG-07 | config + TUN | Removed aggregate TUN byte-budget fields remain unknown; no aggregate memory formula returns | config contract + TUN fuzz `config_legacy_fields` | Preserve seed provenance | ordinary + fuzz compile; guest smoke | baseline |
| LIFE-01/02/03 | runtime + bins | Prepare-before-activate, reverse rollback, admission/drain/cancel/join order, owner baseline, exactly-once reap and rebind | runtime `lifecycle_{transaction,root_events,accept,relay}.rs` and `shutdown.rs`; m0 `lifecycle_cycles.rs` | Cross-bin rollback matrix remains a characterization task | ordinary; scheduled stress | current |
| LIFE-04/05 | bins + runtime | Readiness cannot be spoofed; shared TCP/UDP bind ownership rolls back atomically | bin root/readiness tests; m0 local/UDP lifecycle cohorts | None known | ordinary m0 | current |
| TCP-01 | runtime | Relay preserves raw bytes, half-close/backpressure and the real opened local endpoint | runtime `half_close.rs`, `backpressure.rs`, `local_endpoint.rs`, `abortive_close.rs` | None known | ordinary Rust | baseline |

## Network, Windows and TUN

| ID | Owner | Observable contract | Existing test/evidence | Gap / affected PRs | Gate | Last verified |
|---|---|---|---|---|---|---|
| NET-01..04 | `ferrum2-net` + runtime | One immutable resolve decision per attempt; stale generations fail; best-route remains target/family aware; publisher ordering remains in runtime | net `network_model.rs`/`network_interface_resolution_cache.rs`; runtime network reset/socket tests | None known | ordinary + Windows compile | current |
| WIN-01 | `ferrum2-platform-windows` | Crate root denies unsafe; exactly one inner allow declaration exists at `src/windows/ffi/mod.rs`; legacy `src/windows.rs` is disallowed and every other source is token-safe | `workspace_policy` structured token scan | None known | ordinary policy + Windows compile | current |
| WIN-02..06 | Windows platform crate | DLL identity/export/System32 rules, typed handles, immediate LastError, exact managed rollback, callback/WFP/session cleanup | Wintun unit cohorts enumerated in `refactor-consumers.md`; M17 runbook | Hosted execution forbidden; rename/split must update exact IDs | Windows no-run + approved Hyper-V | pending live |
| WIN-07 | platform + TUN | Ring full is one counted drop with no retry/reset/rebuild | exact Wintun/TUN tests + scheduler-ring-full profile | Retain exact counter witness | approved Hyper-V | pending live |
| TUN-01..05 | TUN owner | Lightweight reset versus full rebuild, debounce/audit, transition ordering, same-logical-reset settle and exactly-once events | TUN unit binary; network-reset/restart profiles | Ordinary host may compile only | approved Hyper-V | pending live |
| TUN-06/07 | TUN data plane | Canonical packet validation and strict bounded reassembly; reviewed corpus remains separate from fuzz seeds | `reassembly-v1.hex` + provenance; four fuzz targets | Hosted fuzz is compile-only | ordinary compile + guest smoke/fuzz | baseline |
| TUN-08..10 | TUN data plane | Initial-SYN admission, TCP cleanup/backpressure, UDP EIM/EIF/ADF, no live eviction, unmetered exception remains narrow | TUN test binary and fuzz race corpus | Exact test IDs remain in Consumer Ledger | approved Hyper-V | pending live |
| ROUTE-01..04 | bins + TUN/runtime/SS | First-valid routing freeze, authenticated server commit, unique concurrent winner, no tagged fallback and fixed admission bounds | m0 UDP/SOCKS cohorts; client/TUN and SS tests | Cross-refresh/reset live coverage remains platform-bound | ordinary protocol + approved guest | pending live |

## DNS, RuleSet, protocols and observability

| ID | Owner | Observable contract | Existing test/evidence | Gap / affected PRs | Gate | Last verified |
|---|---|---|---|---|---|---|
| DNS-01..04 | `ferrum2-dns` | One server/permit/deadline, same-server TC upgrade, strict encrypted DNS, no system fallback, complete nonblocking cleanup | DNS policy/proxy/tagged/resource/application tests | None known | ordinary DNS interop-root | architecture stabilization |
| RS-01..05 | `ferrum2-ruleset` | Remote HTTPS only, verified cache, redirect/deadline preservation, atomic initial snapshot, monotonic refresh and redaction | ruleset loader/HTTPS tests; SRS and shared DNS-TLS fixtures | None known | ordinary ruleset | architecture stabilization |
| CORE-01/02 | `ferrum2-core` + rule | Debug redaction, no TargetAddr Display, atomic selector publication and bounded compile | crate unit/contract tests | Policy ledger must reject back-edges | ordinary Rust | baseline |
| CRYPTO-01/02 | `ferrum2-crypto` | Non-cloneable/redacted/zeroized secrets; widths/nonces/entropy/exhaustion; mutation only after auth | primitive/SIP022/entropy tests | Generator independence retained in Fixture Ledger | ordinary vectors | baseline |
| SS-01/02 | `ferrum2-shadowsocks` | Authentication and semantics precede replay/connect/plaintext; UDP prepare is mutation-free and commit-token owned | TCP ordering/replay/negative and UDP replay/session tests | None known | ordinary protocol | baseline |
| SOCKS-01/02 | `ferrum2-socks5` + client | Exact wire/status and allocation bounds; first-valid UDP source pin and EOF cleanup | crate tests + m0 SOCKS UDP | Client binary remains compile-only on ordinary host | ordinary crate/m0 + guest client | baseline |
| SNIFF-01 | `ferrum2-sniff` | Bounded, transport-strict, fragmented-input safe and redacted | crate tests | None known | ordinary Rust | baseline |
| OBS-01/02 | `ferrum2-observability` | Closed low-cardinality schema, deterministic rendering, balanced lifecycle gauges, no global subscriber | observability tests | Module split must not duplicate registration | ordinary Rust | baseline |
| SEC-01 | all | Errors/logs/evidence retain no config path, endpoint, key, domain, peer, payload or source detail | redaction tests across crates and m0 | Every new evidence schema needs sentinel coverage | all applicable gates | ongoing |

## Tests, CI, vendor and performance

| ID | Owner | Observable contract | Existing test/evidence | Gap / affected PRs | Gate | Last verified |
|---|---|---|---|---|---|---|
| TEST-01/02 | m0 harness | No production crate dependency; observable black-box assertions; every child/wait bounded and reaped | `workspace_policy`; m0 support/tests | Keep policy separate from tooling behavior tests | ordinary m0 | baseline |
| FIX-01 | fixture owners | Hash/provenance/oracle separation remains exact | `fixtures-and-evidence.md` and provenance files | Changes require standalone provenance PR | ordinary contract | baseline |
| FUZZ-01 | TUN fuzz workspace | Independent lock/nightly, empty defaults; hosted only compiles | fuzz manifest/toolchain/workflow | Main required context remains separate | fuzz-static + guest execution | baseline |
| VENDOR-01 | crypto + policy | Normal refactors do not edit vendor; intentional changes replay archive/diff and update both locks | FERRUM_PATCH + workspace policy | No automated archive download in ordinary gate | ordinary policy + explicit qualification | baseline |
| CI-01/02 | root workflows | Root Actions use immutable SHAs, read-only permissions, exact clean checkout; named gates feed explicit main and fuzz `required` jobs; the independently required fuzz workflow runs on every PR/protected push | root workflows + workspace policy | Branch-protection must require both contexts; external settings readback pending | hosted CI | pending external |
| PLAT-01/02 | platform scripts | Privileged execution only in approved guest; every imported controller source is bound by the canonical bundle root; restore exact checkpoint, finish Off; hard-kill stays independent and cleanup failure cannot pass | M17 runbook, module/static tests and versioned schemas | Live evidence intentionally unavailable in ordinary R0 | ordinary static + approved Hyper-V live | pending live |
| PERF-01..04 | qualification/controller | Producer correctness separated from reviewed adoption policy; calibration identities closed; inconclusive states never pass; raw evidence recoverable by digest | performance policy/controller tests and Gate Ledger | 30-day workflow artifact is not durable provenance | manual performance only | pending retention |
