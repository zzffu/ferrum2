# Invariant Ledger

This ledger is the review index for behavior that a structural refactor must preserve. It is not a
second implementation. A change updates the owner, evidence, gap, and affected-PR columns in the same
pull request. `last verified` identifies the source snapshot whose evidence was inspected; `pending`
means the contract is known but its automated proof is incomplete.

## Policy sources

The root `Cargo.toml`, locked Cargo metadata and the executable policy in
`tests/m0-harness/tests/workspace_policy/architecture.toml` own current membership and dependency
boundaries. Inspect them rather than maintaining a second graph or source-line inventory here:

```text
cargo metadata --locked --no-deps --format-version 1
```

Dependency allowlists are upper bounds, not required edge inventories. They keep runtime limited
to core/net, the Windows platform crate limited to net, RuleSet free of runtime/config/platform
back-edges, and observability free of Ferrum2 dependencies.

Historical entries marked `baseline` refer to `88d169686a3f87037d968f92f9c143e1e33c1169`,
not validation of the current checkout. Snapshot counts and audit chronology remain in Git history.

### Reviewed size exceptions

`crates/ferrum2-tun/src/reassembly.rs` remains an explicit protocol-owner exception because fragment
interval accounting, overlap rejection, expiry, and completed-packet reconstruction form one bounded
state machine. The packet
owner is already split: `packet.rs` owns target-neutral parsing and validation,
`packet/control.rs` owns local ICMP/control generation, and `packet/{test_support,tests}.rs` own
packet-only fixtures and cases. The reviewed packet corpus and fuzz seeds exercise the coupled
invariants. Any further reassembly growth, duplicated parser, second reassembly owner, or independent
policy branch ends the exception and requires an owner-preserving split.

This is not a claim that every other source file is currently below 1,000 physical lines. As of
the 2026-09-05 documentation audit, `crates/ferrum2-runtime/src/connection_executor.rs` also exceeds
that count when its inline tests are included, and
`tools/ferrum2-m4-qualification/src/m4_support/windows_tun/workload.rs` exceeds the tooling guide's
production-file limit. The latter remains a maintainability gap, not an additional reviewed exception.

## Configuration and lifecycle

| ID | Owner | Observable contract | Existing test/evidence | Gap / affected PRs | Gate | Last verified |
|---|---|---|---|---|---|---|
| CFG-01/02 | `ferrum2-config` | 1 MiB pre-parse bound; UTF-8/TOML/unknown/version/legacy input fails closed and redacted | `crates/ferrum2-config/tests/config_contract.rs`; root config fixtures | None known; CFG refactors | ordinary Rust | baseline |
| CFG-03A | bins + config | Bare `--check-config` performs prepare only and has no runtime/network side effects | `tests/m0-harness/tests/config_cli.rs` | Side-effect sentinel coverage remains explicit | ordinary m0 | current |
| CFG-03B/04 | bins + role-local materializers | Materialized check is bounded, starts no steady-state root, joins resources, and retains client/server failure codes 1/2 | `tests/m0-harness/tests/config_materialize.rs` | No shared bootstrap crate: private egress/platform capabilities stay in each binary | ordinary m0 | architecture stabilization |
| CFG-05/06 | config + role-local materializers | Dependency plan is complete, deterministic and dependency-first; prepare/finish hide no I/O and reject incomplete resources | `crates/ferrum2-config/tests/v2_prepare_contract.rs`; bin `run/materialize` tests | None known | ordinary Rust | current |
| CFG-07 | config + TUN | Unknown and retired fields fail closed; TUN UDP payload and egress buffers use an independent byte budget, not an aggregate process RSS estimate | config contract, TUN budget tests and [current TUN configuration](../config-v2-tun.md#udp-mapping-and-filtering) | Preserve ordinary/TUN budget isolation and seed provenance | ordinary + hosted fuzz smoke/campaign | current |
| CFG-08 | config `validation/egress_graph` | Existing graph bounds precede DNS/endpoint drafts; typed edges reject cycles and invalid chains; shared successors produce one first-hop/domain summary | adjacent small DAG/cycle/64–65 boundary tests; config/v2 contracts; Windows workspace gates; Quick A/A and A/B 24/24 | Independent core/rule validation retained; both Quick performance guards report REGRESSION, so performance acceptance remains open | ordinary config + m0; explicit qualification | M2a `804f0dc0`, 2026-09-06 |
| LIFE-01/02/03 | runtime + bins | Prepare-before-activate, reverse rollback, admission/drain/cancel/join order, owner baseline, exactly-once reap and rebind | runtime `lifecycle_{transaction,root_events,accept,relay}.rs` and `shutdown.rs`; m0 `lifecycle_cycles.rs` | Cross-bin rollback matrix remains a characterization task | ordinary; every-push lifecycle stress | current |
| LIFE-04/05 | bins + runtime | Readiness cannot be spoofed; shared TCP/UDP bind ownership rolls back atomically | bin root/readiness tests; m0 local/UDP lifecycle cohorts | None known | ordinary m0 | current |
| TCP-01 | runtime | Relay preserves raw bytes, half-close/backpressure and the real opened local endpoint | runtime `half_close.rs`, `backpressure.rs`, `local_endpoint.rs`, `abortive_close.rs` | None known | ordinary Rust | baseline |

## Network, Windows and TUN

| ID | Owner | Observable contract | Existing test/evidence | Gap / affected PRs | Gate | Last verified |
|---|---|---|---|---|---|---|
| NET-01..04 | `ferrum2-net` + runtime | One immutable resolve decision per attempt; stale generations fail; best-route remains target/family aware; publisher ordering remains in runtime | net `network_model.rs`/`network_interface_resolution_cache.rs`; runtime network reset/socket tests | None known | ordinary + Windows compile | current |
| WIN-01 | `ferrum2-platform-windows` | Crate root denies unsafe; the live backend allow boundary is `src/windows/live/mod.rs`, the hosted-safe raw event boundary is `src/windows/core/raw.rs`, legacy `src/windows.rs` and the old `src/windows/ffi` subtree are disallowed, and every other source is token-safe | `workspace_policy` structured token scan | None known | ordinary policy + Windows compile | current |
| WIN-02..06 | Windows platform crate | DLL identity/export/System32 rules, typed handles, immediate LastError, exact managed rollback, callback/WFP/session cleanup | injected Windows unit cohorts enumerated in `refactor-consumers.md`; live host qualification | Hosted tests stay behind injected operations; rename/split must update exact IDs | ordinary Linux + hosted Windows + explicit host qualification | 2026-09-04 host |
| WIN-07 | platform + TUN | Ring full is one counted drop with no retry/reset/rebuild | hosted-safe Wintun/TUN unit tests | Live ring saturation is intentionally outside the bounded host check set | ordinary unit | baseline |
| TUN-01..05 | TUN owner | Lightweight reset versus full rebuild, debounce/audit, transition ordering, same-logical-reset settle and exactly-once events | hosted-safe TUN library suite; host notification/WFP-retention witness | Default tests remain adapter-free; live qualification covers one real notification, not a durability matrix | ordinary Linux/Windows + explicit host qualification | 2026-09-04 host |
| TUN-06/07 | TUN data plane | Canonical packet validation and strict bounded reassembly; reviewed corpus remains separate from fuzz seeds | `reassembly-v1.hex` + provenance; deterministic smoke; four fuzz targets | Hosted execution remains pure in-memory; live qualification covers transport integration, not corpus replay | ordinary unit + hosted smoke/fuzz | baseline |
| TUN-08..10 | TUN data plane | Initial-SYN admission, system TCP cleanup/backpressure, UDP EIM/EIF/ADF, no live eviction, and independent TUN UDP byte admission | hosted-safe TUN library suite and fuzz race corpus; live TCP/UDP host probe | Detailed policy evidence remains hosted; the live gate proves basic real-adapter transport | ordinary unit/fuzz + explicit host qualification | current contracts; live evidence is revision-bound |
| ROUTE-01..04 | bins + TUN/runtime/SS | First-valid routing freeze, authenticated server commit, unique concurrent winner, no tagged fallback and fixed admission bounds | m0 UDP/SOCKS cohorts; client/TUN and SS tests; live narrow-route probe before/after notification | Cross-refresh policy breadth remains hosted; live gate proves retained route/WFP identity | ordinary protocol + explicit host qualification | 2026-09-04 host |

## DNS, RuleSet, protocols and observability

| ID | Owner | Observable contract | Existing test/evidence | Gap / affected PRs | Gate | Last verified |
|---|---|---|---|---|---|---|
| DNS-01..04 | `ferrum2-dns` | One server/permit/deadline, same-server TC upgrade, strict encrypted DNS, no system fallback, complete nonblocking cleanup | DNS policy/proxy/tagged/resource/application tests | None known | ordinary DNS interop-root | architecture stabilization |
| RS-01..05 | `ferrum2-ruleset` | Remote HTTPS only, verified cache, redirect/deadline preservation, atomic initial snapshot, monotonic refresh and redaction | ruleset loader/HTTPS tests; SRS and shared DNS-TLS fixtures | None known | ordinary ruleset | architecture stabilization |
| CORE-01/02 | `ferrum2-core` + rule | Debug redaction, no TargetAddr Display, atomic selector publication and bounded compile | crate unit/contract tests | Policy ledger must reject back-edges | ordinary Rust | baseline |
| SRS-01 | rule `srs/limits` + `decode/context` | Explicit per-file admission before reserve/expansion; attempted entries include duplicates; exact byte caps preserve strict EOF; IPv6 inclusive maximum terminates | small-budget public decoder contracts and four pinned SRS fixture decode/compile tests | Matcher/snapshot/cache bounds and timed 100k qualification remain separate; no decoder speed or RSS claim | ordinary rule/config/ruleset; qualification compile-only | M2b, 2026-09-06 |
| CRYPTO-01/02 | `ferrum2-crypto` | Non-cloneable/redacted/zeroized secrets; widths/nonces/entropy/exhaustion; mutation only after auth | primitive/SIP022/entropy tests | Generator independence retained in Fixture Ledger | ordinary vectors | baseline |
| SS-01/02 | `ferrum2-shadowsocks` | Authentication and semantics precede replay/connect/plaintext; UDP prepare is mutation-free and commit-token owned | TCP ordering/replay/negative and UDP replay/session tests | None known | ordinary protocol | baseline |
| SOCKS-01/02 | `ferrum2-socks5` + client | Exact wire/status and allocation bounds; first-valid UDP source pin and EOF cleanup | crate tests + m0 SOCKS UDP | Client binary remains compile-only on ordinary host | ordinary crate/m0 + host-qualified client | baseline |
| SNIFF-01 | `ferrum2-sniff` | Bounded, transport-strict, fragmented-input safe and redacted | crate tests | None known | ordinary Rust | baseline |
| OBS-01/02 | `ferrum2-observability` | Closed low-cardinality schema, deterministic rendering, balanced lifecycle gauges, caller-owned globally filtered subscribers and dynamic severity; the crate does not install a global subscriber | observability tests, including nested-event rejection | Module split must not duplicate registration or weaken the log admission boundary | ordinary Rust | current |
| SEC-01 | all | Ordinary errors/logs/evidence exclude config paths, endpoints, keys, domains, peers, payloads and source detail; authenticated sensitive management operations and opt-in rocom captures have separate explicit contracts | redaction tests across crates and m0; [dashboard](dashboard-design.md) and [recording](rocom-recording-design.md) contracts | Every new evidence schema needs sentinel coverage | all applicable gates | ongoing |

## Tests, CI, vendor and performance

| ID | Owner | Observable contract | Existing test/evidence | Gap / affected PRs | Gate | Last verified |
|---|---|---|---|---|---|---|
| TEST-01/02 | m0 harness | No production crate dependency; observable black-box assertions; every child/wait bounded and reaped | `workspace_policy`; m0 support/tests | Keep policy separate from tooling behavior tests | ordinary m0 | baseline |
| FIX-01 | fixture owners | Hash/provenance/oracle separation remains exact | `fixtures-and-evidence.md` and provenance files | Changes require standalone provenance PR | ordinary contract | baseline |
| FUZZ-01 | TUN fuzz workspace | Independent lock/nightly, empty defaults; hosted Linux executes deterministic smoke and only the four pure in-memory targets for a one-hour total campaign; every non-Markdown input under the fuzz crate triggers the campaign | fuzz manifest/toolchain/workflow and typed Markdown exclusions | Main required context remains separate; no adapter or network mutation is permitted | fuzz-static + hosted smoke/campaign | baseline |
| VENDOR-01 | crypto + policy | Normal refactors do not edit vendor; intentional changes replay archive/diff and update both locks | FERRUM_PATCH + workspace policy | No automated archive download in ordinary gate | ordinary policy + explicit qualification | baseline |
| CI-01/02 | root workflows | Root Actions use immutable SHAs, read-only permissions, exact clean checkout; named gates feed explicit main and fuzz `required` jobs through the sole typed `tools.ci.required_gate` result owner; the fuzz workflow always emits its required context and runs its one-hour pure in-memory campaign when reviewed owner paths change | root workflows + workspace policy mutation tests | Branch-protection must require both contexts; external settings readback pending | hosted CI | pending external |
| PLAT-01/02 | platform scripts | One exact candidate, explicit elevation acknowledgement, run-owned IPv4 `/32` resources; barrier-synchronized sustained TCP, observed backpressure, UDP/fragments, active-work reset with old TCP retirement and fresh tagged UDP, exact WFP identity, forced recovery, <900s and zero residue | host runbook, closed bundle and required data-path/reset witnesses in final qualification | Live evidence unavailable in ordinary R0; no IPv6 or arbitrary host-policy claim | ordinary static/socket tests + explicit host live | source-bound run evidence required |
| PERF-01..04 | TUN benchmark/controller | Production packet/owner logic with bounded mock I/O; six Quick/Confirm scenarios, 36/60 interleaved trials, exact checked work, independent builds and reviewed A/A-bound A/B decisions; no host network mutation | crate-owned example, strict evidence tests and [performance contract](../performance-evidence.md) | Internal packet rates are not kernel or full-product throughput; old host evidence is incomparable | portable compile + explicit paired measurement | source-bound A/A and A/B required |
