# TEST-0017 — M16 Windows managed TUN routing, DNS and direct egress

- **Status:** Planned
- **Milestone:** M16
- **Baseline:** `fcef80dcc7e62bbca63ffbf7832df369dd418abd`
- **Performance:** required；regression/resource evidence only，no minimum throughput or improvement claim

## Entry capability gate

M16-T01 runs before product implementation and is blocking。It MUST use isolated Hyper-V guests/checkpoints，
never the host currently running a TUN product，and MUST record guest build、candidate/probe hashes、before/
active/after snapshots and one cleanup-complete marker。Both Windows 10 build 19041+ and Windows 11 AMD64
assets are required。

The existing `tests/platform/qualify_windows_tun.ps1` is extended with one `network-feasibility` mode；M16
does not add a third equivalent controller。The mode MUST prove all of the following：

1. exact IPv4/IPv6 split capture rows can be created with fully initialized fields，read back from
   ActiveStore，deleted by exact journal identity and leave address-derived rows untouched；the evidence
   freezes next-hop、row metric and whether any interface-metric lease is necessary；
2. before capture，`GetBestInterfaceEx` → validated interface → constrained `GetBestRoute2` yields the
   expected physical interface/source for fixed endpoints，and one eligible default physical interface per
   family can be frozen for dynamic direct；
3. after capture，unpinned off-link TCP and UDP controls enter Wintun，while family-correct pre-connect/
   pre-send pinned controls reach the physical endpoint without a Wintun packet；
4. Wintun per-interface DNS plus the two configured synthetic addresses makes Windows resolver UDP and TCP
   queries reach the local DNS answer path，without modifying physical-interface DNS；
5. the final-prepare capture-before-admission interval remains bounded and does not overflow the Wintun ring；
6. partial apply and normal supervised stop leave zero OS and process-private owners；external
   `TerminateProcess` separately leaves process absence plus zero adapter、address、route and DNS residue
   before controller remediation。

Each guest emits exactly one successful capability marker only after audit：

```text
m16_windows_network_feasibility status=PASS routes=2/2 tcp_pin=4/4 udp_pin=4/4 dns=4/4 capture_window=1/1 hard_kill=1/1 interface_metric=<unchanged|leased> cleanup=PASS build=<exact-build> sha=<exact-sha>
```

Missing Windows 11 assets，an ambiguous/no default underlay，a failed pinned/unpinned distinction，unreliable
DNS steering，capture-window overflow or hard-kill residue makes T01 `BLOCKED` and stops T02～T07。It is not
waived by unit fakes or ordinary RAII evidence。

## Evidence map

| Requirement | Cheapest primary evidence | Command / profile |
|---|---|---|
| Exact planning SHA/tree/parent and isolated M16 footprint control | Git identity + schema-3 control verification | `git rev-parse HEAD 'HEAD^{tree}' 'HEAD^'`；`sh scripts/test-budget.sh verify` |
| Legacy omission、direct closed shape、direct-only graph、server/v1/chain negatives | Extend existing table-driven config contract | `cargo test -p ferrum2-config --test config_contract --locked m16_` |
| Static/rule/final/selector/DNS-detour direct plan snapshots and no core protocol variant | Existing selector/route contract + architecture mutation guard | `cargo test -p ferrum2-core --locked`；`cargo test -p ferrum2-m0-harness --test architecture --locked` |
| Direct TCP raw target、bounded domain resolve、half-close、selected failure/no fallback、zero SIP022 owner | Client egress focused table and real process echo | `cargo test -p ferrum2-client direct_tcp --locked`；focused local E2E row |
| Direct UDP numeric/domain、raw payload、response binding、bounds/expiry/cancel、zero SIP022 owner | Reuse existing client association/direct-runtime tables | `cargo test -p ferrum2-client direct_udp --locked`；`cargo test -p ferrum2-runtime direct_udp --locked` |
| Manual-route TUN+direct binder is ready before controller capture and avoids re-entry | VM post-Ready narrow-route A/B；no product route mutation | qualifier full/manual-direct row |
| TUN and SOCKS share one dispatch and callers create no physical socket | Composition tests + source mutation guards | `cargo test -p ferrum2-client direct_ --locked`；architecture test |
| Prefix subtraction、collapse、order independence、dual `/1` split、empty/257-row failure | Pure table-driven compiler tests in existing Windows Adapter module | `cargo test -p ferrum2-wintun capture_prefix --locked` |
| Fully initialized Win32 rows、precheck/readback/journal/reverse conditional delete | One fake ABI failure-position table | `cargo test -p ferrum2-wintun managed_route --locked` |
| Correct API order and IPv4/IPv6 byte order、no unpinned fallback | Fake socket-option recorder + source guard | `cargo test -p ferrum2-wintun underlay --locked` |
| Win10/Win11 route values、pinned positive/unpinned negative、capture interval、hard kill | Blocking isolated-VM capability mode | `pwsh tests/platform/qualify_windows_tun.ps1 -Mode network-feasibility ...` |
| Product capture routes do not change third-party/default/LAN/VPN rows | Before/active/after exact route snapshots and sentinels | same capability/full VM profile |
| Synthetic IPv4/IPv6 UDP/TCP 53 enters existing DnsProxy before ordinary route | Client TUN composition counter table | `cargo test -p ferrum2-client tun_auto_dns --locked` |
| Wintun-only DNS apply/readback/conditional restore and external-change conflict | Fake DNS lease table + VM resolver witnesses | `cargo test -p ferrum2-wintun managed_dns --locked`；VM full profile |
| Direct/no-detour bootstrap and proxy-detoured first-hop UDP/TCP/DoT/DoH use the correct pinned endpoint | Existing DNS transport tests with binding recorder | `cargo test -p ferrum2-client dns_egress --locked` |
| TUN root prepares last；capture last；activation remains admission-only | Process-root call-order mutation table | `cargo test -p ferrum2-client managed_tun_lifecycle --locked` |
| Every partial/later failure and graceful/forced stop reverses exact owned state | Fake failure-position table + existing lifecycle harness | focused crate tests；repository lifecycle command below |
| Route/interface/address invalidation removes capture and terminates；no live migration | Notification callback/owner ordering tests + real VM route、interface and IPv4/IPv6 unicast-address mutations on each baseline | `cargo test -p ferrum2-wintun network_change --locked`；VM full profile |
| 100 cycles and exact adapter/listener rebind with zero owners | Existing qualifier and lifecycle harness | VM `-Mode cycles`；repository lifecycle command below |
| No target/tag/interface/route/DNS/secret cardinality | Error/log/trace/metrics sentinel scans | `cargo test -p ferrum2-client m16_redaction --locked`；`cargo test -p ferrum2-wintun m16_redaction --locked`；`cargo test -p ferrum2-m0-harness --test architecture m16_observability --locked` |
| TUN omission/non-Windows builds/SIP022/DNS interop preserve M0～M15 | Existing Full、platform and interop profiles | repository/hosted gates below |
| Hot-path/resource regression on one exact SHA | Independent Windows TUN performance profile | authorized existing workflow dispatch after exact candidate is fixed |
| Final contract and exact evidence ledger | Independent Architect and QA review | M16-T07 bounded full review；targeted re-review only for fixes |

## Required negative and mutation rows

### Configuration and graph

- Omitted type and explicit Shadowsocks normalize identically。Unknown/case-changed type，direct with each
  forbidden field alone or together，proxy missing server，partial credentials，direct in every chain
  position，direct-only with/without meaningless global credentials，server type and schema-v1 M16 fields。
- Direct as static binding、route rule、final、selector direct/nested member and DNS detour；selector switches
  before/after selection；selected direct failure cannot inspect a sibling、later rule or final。Empty、mixed
  and multi-direct defensive plan inputs create no socket。
- Each auto-route/DNS boolean relation；missing/extra synthetic address；address equals local/outside family
  prefix/unspecified/loopback/multicast；prefix list `0/1/64/65` and output `0/1/256/257`；unknown fields and
  unsupported role/platform all fail before OS calls。

### Direct data plane

- TCP numeric IPv4/IPv6、SOCKS domain with zero/one/max/max+1 resolver candidates、deadline/cancel/connect
  failure、prefix replay、half-close and force drain。Domain rows cover auto-route off，auto-route with
  auto-DNS synthetic answer，and auto-route without auto-DNS where the numeric resolver packet follows
  ordinary direct/proxy/reject policy under one deadline。Wire witnesses must show application bytes at the
  target and zero bytes at every Shadowsocks endpoint for selected direct。
- UDP numeric IPv4/IPv6 and SOCKS domain，minimum/maximum/max+1 raw payload，wrong-source response，queue/full
  byte/session limits，first invalid/over-limit then valid，mapping expiry and selector reselection，socket/
  resolver failure and forced cancellation。Every direct row proves zero SIP022 session/live-ID/crypto owner。
- TUN original target is invariant under DNS/TLS/HTTP sniff metadata。Ordinary direct port 53 is not synthetic
  hijack unless the exact configured address also matches。

### Capture, binding and ownership

- Prefix subtraction covers disjoint、nested、equal、covering、v4/v6 mixed、host prefix、exclude-outside-
  include、order/duplicate normalization and a `/0` minus many prefixes that crosses the output ceiling。
- Route fake injects failure before/after every query/init/create/readback/journal/delete，initializer booleans
  and illegal values，duplicate/conflicting row，readback mismatch，third-party replacement and cleanup error。
  It must fail if any broad delete/flush/adopt or address-derived-row journal is introduced。
- Underlay rows cover fixed endpoints on different physical interfaces，one unique default per family，missing/
  down/loopback/Wintun/ambiguous default，index/LUID conversion，wrong IPv4/IPv6 byte order，option failure and
  a mutation that connects/sends before bind。No path may retry without a binding。
- VM negative control must be observably captured；a positive that merely succeeds without proving zero Wintun
  ingress is insufficient。Off-link targets must be owned test endpoints，not production/public services。

### DNS and lifecycle

- DNS fake covers query/snapshot/apply/readback/restore failure for both families，partial family apply，owned
  value replaced externally and cleanup conflict。Physical-interface settings are read-only sentinels。
- Resolver witnesses cover UDP truncation/TCP upgrade，direct and proxy-detoured UDP/TCP/DoT/DoH，upstream
  failure no fallback，synthetic wrong address/port/family and auto-DNS-off exact M15 behavior。
- Setup ordinal covers notification-before-snapshot、generation change at every interval、underlay、adapter、
  address、DAD、session、DNS family、each capture row、post-capture physical revalidation，the conditional
  per-family interface-metric snapshot/apply/readback/conflict/restore path when T01 selects it，owner panic and
  prepared acknowledgement；later-root failure is prevented by TUN-last composition。Own Wintun events are
  excluded by exact identity，while any external fingerprint change rolls back before ready。Cleanup order is
  reject new socket → cancel/await notification → remove capture → conditional DNS/metric restore → existing
  TUN teardown。
- Route/interface/address notification callback performs no blocking/logging/allocation/product policy work，
  cannot race context free，and repeated/coalesced notifications still trigger one bounded shutdown。
- On each Windows baseline，the full VM profile separately mutates one relevant route、one physical-interface
  state、one IPv4 unicast address and one IPv6 unicast address。Each row MUST observe the corresponding real
  callback ABI，reject new admission，remove capture/DNS steering，terminate under supervision and leave zero
  owned residue；unit injection cannot replace any of these four rows。
- Graceful、forced supervised、panic and 100-cycle rows inspect adapter、address、route、DNS、process、HANDLE、
  callback、thread、flow、mapping、UDP live-ID and crypto owners。`TerminateProcess` rows inspect only process
  absence plus externally observable adapter/address/route/DNS state before cleanup。PASS marker is emitted
  only after the applicable residue audit。

## Test-footprint forecast

Planning baseline is code/tests `29771/50323`，ratio `1.690336`，with case/support/fixture
`44574/5152/597`。Forecast Rust test growth is `+2250..3650 / +160..460 / +0`；the existing PowerShell
qualifier may grow `+450..850` non-Rust lines。Tables and current helpers are preferred；no second Rust
harness、third equivalent helper or committed network/binary fixture is planned。

Any ticket above `+600` Rust test LOC or any growing test file above `1200` semantic test LOC receives an
explicit Architect/QA disposition。Numeric `REVIEW_REQUIRED` is not a waiver and does not permit deleting
independent evidence。T01 may split the already-large PowerShell controller by ownership if review proves a
private helper file is cheaper than further growth；it must remain one qualifier，not a second harness。

## Repository gates

Run Full serially on the accepted integration SHA：

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo build --workspace --bins --locked
cargo test --workspace --all-features --locked
cargo test -p ferrum2-m0-harness --test lifecycle_cycles full_qualification_runs_twenty_cycles_per_category_and_at_least_100_per_binary --locked -- --ignored --exact --nocapture
cargo doc --workspace --all-features --no-deps --locked
cargo +1.97.1 check --workspace --all-targets --locked
sh scripts/test-budget.sh milestone --candidate <accepted-integration-sha>
git diff --check <accepted-M16-base>..<accepted-integration-sha>
```

Required hosted/VM evidence must bind one exact SHA/run/attempt and report unique markers for Windows 10、
Windows 11、functional full、cycles、cleanup and independent performance。A failed candidate/attempt remains
recorded and is never rerun or combined with another SHA to create a pass。

The existing qualifier adds exact `network-feasibility` and `hard-kill` modes。Hard-kill runs exactly three
externally observed cases：active auto-route only，active auto-route+auto-DNS，and active mixed direct/proxy/DNS
traffic。It emits exactly one marker after pre-remediation audit：

```text
m16_windows_hard_kill status=PASS cases=3/3 process_absent=PASS adapter=ABSENT addresses=ABSENT routes=ABSENT dns=ABSENT cleanup=PASS build=<exact-build> sha=<exact-sha>
```

The full controller and hosted wrappers require these exact schemas，with concrete values replacing angle
placeholders：

```text
m16_windows_tun_full status=PASS m15_transport=16/16 direct_tcp=2/2 direct_udp=2/2 dns=4/4 network_change=4/4 route_change=1/1 interface_change=1/1 address_change=2/2 cycles=100/100 hard_kill=3/3 cleanup=PASS build=<exact-build> sha=<exact-sha>
m16_windows_tun_qualification status=PASS profile=full m15_transport=16/16 direct_tcp=2/2 direct_udp=2/2 dns=4/4 network_change=4/4 route_change=1/1 interface_change=1/1 address_change=2/2 cycles=100/100 hard_kill=3/3 cleanup=PASS sha=<GITHUB_SHA> run_id=<GITHUB_RUN_ID> run_attempt=<GITHUB_RUN_ATTEMPT>
m16_windows_tun_performance status=PASS proxy=PASS direct=PASS dns=PASS cleanup=PASS sha=<GITHUB_SHA> run_id=<GITHUB_RUN_ID> run_attempt=<GITHUB_RUN_ATTEMPT>
```
