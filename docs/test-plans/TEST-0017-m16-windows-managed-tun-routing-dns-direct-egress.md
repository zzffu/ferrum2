# TEST-0017 — M16 Windows managed TUN routing, DNS and direct egress

- **Status:** Planned
- **Milestone:** M16
- **Baseline:** `fcef80dcc7e62bbca63ffbf7832df369dd418abd`
- **Qualification VM:** `Windows 10 MSIX packaging environment`
- **Qualification checkpoint:** `M15-T04-before-2b0c25b-20260810`
- **Performance:** required；regression/resource evidence only，no minimum throughput or improvement claim

## Entry capability gate

M16-T01 runs before product implementation and is blocking。It MUST restore the exact qualification VM/
checkpoint above，never run on the host currently using a TUN product，and MUST record the guest's actual
product、edition、architecture、full version/build、candidate/probe hashes、before/active/after snapshots and
one cleanup-complete marker。No second VM or independent Windows-release baseline is required or credited。

The exact restored-VM preflight observed one usable IPv4 physical default but no IPv6 physical default，no
non-link-local physical IPv6 address and no owned off-link dual-stack endpoint。That observation authorizes
this IPv4 contract replan but is not a capability PASS，and no local identifiers、addresses or credentials are
repository evidence。The unique failure mode is an unprovable IPv6 managed socket escaping the required pinned/
unpinned distinction。The cheapest sufficient layer remains the existing qualifier：reuse its route、socket、
resolver and cleanup helpers with table rows，not a new harness or third equivalent helper。

Before any guest mutation，the host workflow MUST write one canonical JSON identity ledger with exactly these
ordered keys and no extras。Canonical encoding is one-line PowerShell `ConvertTo-Json -Compress` output from
an ordered map，UTF-8 without BOM，terminated by one LF：

```json
{
  "schema": 1,
  "vm_name": "Windows 10 MSIX packaging environment",
  "vm_id": "<exact-hyper-v-vm-guid>",
  "checkpoint_name": "M15-T04-before-2b0c25b-20260810",
  "checkpoint_id": "<exact-hyper-v-checkpoint-guid>",
  "guest_product": "<observed-product-name>",
  "guest_edition": "<observed-edition-id>",
  "guest_architecture": "AMD64",
  "guest_version": "<observed-full-version>",
  "guest_build": "<observed-build-and-ubr>",
  "candidate_sha": "<exact-candidate-git-sha>",
  "probe_sha256": "<exact-qualifier-sha256>"
}
```

The host obtains VM/checkpoint IDs through exact Hyper-V readback and obtains guest fields through PowerShell
Direct after restore；it MUST NOT infer any field from the VM display name。The ledger SHA-256 binds every
local marker below。The raw ledger is local evidence，not product telemetry or a committed fixture。

The existing `tests/platform/qualify_windows_tun.ps1` is extended with one `network-feasibility` mode；M16
does not add a third equivalent controller。The mode MUST prove all of the following：

1. exact IPv4 split capture rows can be created with fully initialized fields，read back from
   ActiveStore，deleted by exact journal identity and leave address-derived rows untouched；the evidence
   freezes next-hop、row metric and whether any interface-metric lease is necessary；
2. before capture，`GetBestInterfaceEx` → validated interface → constrained `GetBestRoute2` yields the
   expected IPv4 physical interface/source for one fixed proxy first hop，and one eligible IPv4 physical
   default interface can be frozen for dynamic direct；
3. after capture，the fixed-first-hop and dynamic-direct tables each prove unpinned off-link TCP and UDP enter
   Wintun while pre-connect/pre-send IPv4-pinned controls reach the owned endpoint with zero Wintun ingress；
4. Wintun per-interface IPv4 DNS plus the configured synthetic IPv4 address makes Windows resolver UDP and
   TCP queries reach the local DNS answer path，without modifying physical-interface DNS or the M15 IPv6
   adapter address；
5. the final-prepare capture-before-admission interval remains bounded and does not overflow the Wintun ring；
6. partial apply and normal supervised stop leave zero OS and process-private owners；external
   `TerminateProcess` separately leaves process absence plus zero adapter、address、route and DNS residue
   before controller remediation。

The restored qualification VM emits exactly one successful capability marker only after audit：

```text
m16_windows_network_feasibility status=PASS routes=2/2 tcp_pin=4/4 udp_pin=4/4 dns=2/2 capture_window=1/1 hard_kill=1/1 interface_metric=<unchanged|leased> cleanup=PASS guest_build=<exact-build-and-ubr> run_token=<unique> candidate_sha=<exact-candidate-sha> probe_sha256=<exact-probe-sha256> identity_sha256=<exact-ledger-sha256>
```

An inaccessible/mismatched VM or checkpoint，an ambiguous/no IPv4 default underlay，a failed pinned/unpinned
distinction，unreliable DNS steering，capture-window overflow or hard-kill residue makes T01 `BLOCKED` and
stops T02～T07。It is not replaced by another VM or waived by unit fakes or ordinary RAII evidence。

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
| IPv4 prefix subtraction、collapse、order independence、`/0`→two `/1` split、IPv6 rejection、empty/257-row failure | Pure table-driven compiler tests in existing Windows Adapter module | `cargo test -p ferrum2-wintun capture_prefix --locked` |
| Fully initialized Win32 rows、precheck/readback/journal/reverse conditional delete | One fake ABI failure-position table | `cargo test -p ferrum2-wintun managed_route --locked` |
| Correct IPv4 API order/network byte order、managed IPv6 endpoint rejection、no unpinned fallback | Fake socket-option recorder + source guard | `cargo test -p ferrum2-wintun underlay --locked` |
| Current-VM route values、pinned positive/unpinned negative、capture interval、hard kill | Blocking exact-asset capability mode | `pwsh tests/platform/qualify_windows_tun.ps1 -Mode network-feasibility ...` |
| Product capture routes do not change third-party/default/LAN/VPN rows | Before/active/after exact route snapshots and sentinels | same capability/full VM profile |
| Synthetic IPv4 UDP/TCP 53 enters existing DnsProxy before ordinary route；IPv6 DNS field rejected | Client TUN composition counter table | `cargo test -p ferrum2-client tun_auto_dns --locked` |
| Wintun-only DNS apply/readback/conditional restore and external-change conflict | Fake DNS lease table + VM resolver witnesses | `cargo test -p ferrum2-wintun managed_dns --locked`；VM full profile |
| Direct/no-detour bootstrap and proxy-detoured first-hop UDP/TCP/DoT/DoH use the correct pinned endpoint | Existing DNS transport tests with binding recorder | `cargo test -p ferrum2-client dns_egress --locked` |
| TUN root prepares last；capture last；activation remains admission-only | Process-root call-order mutation table | `cargo test -p ferrum2-client managed_tun_lifecycle --locked` |
| Every partial/later failure and graceful/forced stop reverses exact owned state | Fake failure-position table + existing lifecycle harness | focused crate tests；repository lifecycle command below |
| IPv4 route/interface/address invalidation removes capture and terminates；no live migration | Notification callback/owner ordering tests + real IPv4 route、interface and unicast-address mutations on the exact current VM | `cargo test -p ferrum2-wintun network_change --locked`；VM full profile |
| 100 cycles and exact adapter/listener rebind with zero owners | Identity-bound full marker plus existing lifecycle harness | VM full profile `cycles=100/100`；repository lifecycle command below |
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
- Each auto-route/DNS boolean relation；missing/extra IPv4 synthetic address；address equals local/outside
  prefix/unspecified/loopback/multicast；`ipv6_dns_address` and every IPv6 route include/exclude are rejected；
  IPv4 prefix list `0/1/64/65` and output `0/1/256/257`；unknown fields and unsupported role/platform all fail
  before OS calls。The existing M15 `ipv6_address` remains accepted and unchanged。

### Direct data plane

- TCP numeric IPv4/IPv6、SOCKS domain with zero/one/max/max+1 resolver candidates、deadline/cancel/connect
  failure、prefix replay、half-close and force drain。Domain rows cover auto-route off，auto-route with
  auto-DNS synthetic answer，and auto-route without auto-DNS where the numeric resolver packet follows
  ordinary direct/proxy/reject policy under one deadline。Wire witnesses must show application bytes at the
  target and zero bytes at every Shadowsocks endpoint for selected direct。
- Windows TUN-selected direct IPv6，with auto-route off and on，fails before resolver/socket creation；the
  neighboring SOCKS/non-Windows direct IPv6 and M15 manual-route IPv6 proxy rows remain positive。
- UDP numeric IPv4/IPv6 and SOCKS domain，minimum/maximum/max+1 raw payload，wrong-source response，queue/full
  byte/session limits，first invalid/over-limit then valid，mapping expiry and selector reselection，socket/
  resolver failure and forced cancellation。Every direct row proves zero SIP022 session/live-ID/crypto owner。
- Windows TUN-selected direct IPv6 UDP fails before physical socket creation for both auto-route states and
  never retries unpinned；existing M15 IPv6 proxy/reject/DNS-hijack mapping rows remain in the `16/16` matrix。
- TUN original target is invariant under DNS/TLS/HTTP sniff metadata。Ordinary direct port 53 is not synthetic
  hijack unless the exact configured address also matches。

### Capture, binding and ownership

- IPv4 prefix subtraction covers disjoint、nested、equal、covering、host prefix、exclude-outside-include、
  order/duplicate normalization and a `/0` minus many prefixes that crosses the output ceiling；each IPv6
  include/exclude is a table-driven pre-side-effect rejection。
- Route fake injects failure before/after every query/init/create/readback/journal/delete，initializer booleans
  and illegal values，duplicate/conflicting row，readback mismatch，third-party replacement and cleanup error。
  It must fail if any broad delete/flush/adopt or address-derived-row journal is introduced。
- Underlay rows cover IPv4 fixed endpoints on different physical interfaces，one unique IPv4 default，missing/
  down/loopback/Wintun/ambiguous default，index/LUID conversion，wrong IPv4 byte order，option failure and a
  mutation that connects/sends before bind。IPv6 concrete proxy and direct/no-detour DNS physical endpoints
  fail validation/prepare before mutation，while a logical IPv6 DNS bootstrap behind an IPv4 proxy first hop
  remains valid。No path may retry without a binding。
- VM negative control must be observably captured；a positive that merely succeeds without proving zero Wintun
  ingress is insufficient。Off-link targets must be owned test endpoints，not production/public services。

### DNS and lifecycle

- DNS fake covers IPv4 query/snapshot/apply/readback/restore failure，owned value replaced externally and
  cleanup conflict。Physical-interface settings and the M15 IPv6 adapter address are read-only sentinels。
- Resolver witnesses cover UDP truncation/TCP upgrade，direct and proxy-detoured UDP/TCP/DoT/DoH，upstream
  failure no fallback，synthetic wrong address/port/family and auto-DNS-off exact M15 behavior。
- Setup ordinal covers notification-before-snapshot、generation change at every interval、underlay、adapter、
  address、DAD、session、IPv4 DNS、each capture row、post-capture physical revalidation，the conditional
  IPv4 interface-metric snapshot/apply/readback/conflict/restore path when T01 selects it，owner panic and
  prepared acknowledgement；later-root failure is prevented by TUN-last composition。Own Wintun events are
  excluded by exact identity，while any external fingerprint change rolls back before ready。Cleanup order is
  reject new socket → cancel/await notification → remove capture → conditional DNS/metric restore → existing
  TUN teardown。
- IPv4 route/interface/address notification callback performs no blocking/logging/allocation/product policy work，
  cannot race context free，and repeated/coalesced notifications still trigger one bounded shutdown。
- On the exact current qualification VM，the full profile separately mutates one relevant IPv4 route、one
  physical-interface state and one IPv4 unicast address。Each row MUST observe the corresponding real callback
  ABI，reject new admission，remove capture/DNS steering，terminate under supervision and leave zero owned
  residue；unit injection cannot replace any of these three rows。
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

All required ledgers MUST bind one exact candidate SHA。Each current-VM profile binds its own unique
`RunToken`；each hosted qualification or performance workflow binds its own run ID and attempt。Distinct
dispatches are not required or allowed to share a run ID。Hosted Windows jobs remain regression/resource gates
and are not a second OS qualification baseline。A failed candidate/attempt remains recorded and is never
rerun or combined with another SHA to create a pass。

The existing qualifier adds exact `network-feasibility` and `hard-kill` modes。Hard-kill runs exactly three
externally observed cases：active auto-route only，active auto-route+auto-DNS，and active mixed direct/proxy/DNS
traffic。It emits exactly one marker after pre-remediation audit：

```text
m16_windows_hard_kill status=PASS cases=3/3 process_absent=PASS adapter=ABSENT addresses=ABSENT routes=ABSENT dns=ABSENT cleanup=PASS guest_build=<exact-build-and-ubr> run_token=<unique> candidate_sha=<exact-candidate-sha> probe_sha256=<exact-probe-sha256> identity_sha256=<exact-ledger-sha256>
```

The full controller and hosted wrappers require these exact schemas，with concrete values replacing angle
placeholders：

```text
m16_windows_tun_full status=PASS m15_transport=16/16 direct_tcp=1/1 direct_udp=1/1 dns=2/2 network_change=3/3 route_change=1/1 interface_change=1/1 address_change=1/1 cycles=100/100 hard_kill=3/3 cleanup=PASS guest_build=<exact-build-and-ubr> run_token=<unique> candidate_sha=<exact-candidate-sha> probe_sha256=<exact-probe-sha256> identity_sha256=<exact-ledger-sha256>
m16_windows_tun_qualification status=PASS profile=full m15_transport=16/16 direct_tcp=1/1 direct_udp=1/1 dns=2/2 network_change=3/3 route_change=1/1 interface_change=1/1 address_change=1/1 cycles=100/100 hard_kill=3/3 cleanup=PASS candidate_sha=<GITHUB_SHA> run_id=<GITHUB_RUN_ID> run_attempt=<GITHUB_RUN_ATTEMPT>
m16_windows_tun_performance status=PASS proxy=PASS direct=PASS dns=PASS cleanup=PASS candidate_sha=<GITHUB_SHA> run_id=<GITHUB_RUN_ID> run_attempt=<GITHUB_RUN_ATTEMPT>
```

The identity-bound full marker is the sole privileged VM cycle evidence for M16。No separate `-Mode cycles`
run or independently mergeable cycles marker is required。
