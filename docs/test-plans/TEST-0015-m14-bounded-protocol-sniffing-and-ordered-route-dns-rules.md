# TEST-0015 — M14 bounded routing、sniffing and DNS hijack evidence

- **Status:** Approved
- **Milestone:** M14
- **Spec:** `docs/specs/SPEC-0015-m14-bounded-protocol-sniffing-and-ordered-route-dns-rules.md`

## Evidence map

| Requirement | Cheapest sufficient primary evidence | Gate |
|---|---|---|
| M14-MUST-01 version/migration/scope | schema-v1 preservation+migration table、schema-v2 config cohort and lock/source diff | T01、T03～T09 |
| M14-MUST-02 ordered program | core table-driven cursor/action/final tests through the public interface | T02 core |
| M14-MUST-03 matchers | core normalization tables plus config scalar/list/bounds/error tables | T02/T03 |
| M14-MUST-04 pure sniff | one `ferrum2-sniff` package table per Hickory/rustls/httparse adapter and fragmentation mutations | T04 |
| M14-MUST-05 capabilities/config | existing `config_contract` and `config_cli` tables extended for both roles | T03 |
| M14-MUST-06 resource/failure/prefix | runtime collector unit table and server exact-prefix/cancel/I/O tests | T05 |
| M14-MUST-07 selector/no fallback | existing `selector_contract` plus terminal-time switch/open-failure mutations | T02、T05～T07 |
| M14-MUST-08 client behavior | SOCKS command mapping、first-valid association-state table and real TCP/UDP process witnesses | T07/T08 |
| M14-MUST-09 server behavior | server TCP/UDP authenticated ordering tables and real process witnesses | T05/T08 |
| M14-MUST-10 DNS policy/answering | existing `proxy_contract`、`tagged_upstreams`、resource tests plus client/server policy tables | T06～T08 |
| M14-MUST-11 security/lifecycle/telemetry | negative mutation tables、owner counters、100+ lifecycle、rebind and redaction guards | T05～T09 |
| M14-MUST-12 architecture/qualification | workspace metadata/source guard、Full/MSRV/platform/interop/review and independent performance job | T01/T04/T08/T09 |

## Existing evidence to extend

- `crates/ferrum2-core/tests/selector_contract.rs` remains the plan identity/switch/no-fallback oracle；
  `route_program.rs` may reuse its target/selector builders rather than create another graph helper。
- `crates/ferrum2-config/tests/config_contract.rs` and
  `tests/m0-harness/tests/config_cli.rs` remain the schema/error/zero-side-effect surfaces。
- `crates/ferrum2-dns/tests/proxy_contract.rs` remains the only DNS answering/framing contract；
  `tagged_upstreams.rs` and `resource_lifecycle.rs` retain selected-server/TC/detour/owner evidence。
- Existing client tests `routed_tcp_selects_after_target_and_never_falls_back`、
  `dns_proxy_first_match_direct_and_detoured_transports` and
  `dns_proxy_detour_saturation_shutdown_and_exact_rebind` remain mandatory。The baseline
  `routed_udp_uses_lazy_endpoint_legs_and_rejects_cross_leg_responses` records the behavior being
  superseded；T07 replaces its multi-plan/per-datagram assertions with one association-level table rather
  than preserving a compatibility path。
- Existing server tests
  `tagged_tcp_shares_static_direct_mapping_and_one_replay_store`、
  `tagged_udp_is_process_bounded_and_bound_to_its_local_inbound` and prefix lifecycle rows remain
  mandatory。
- Existing real-process `local_e2e`、`socks_udp_local_e2e`、`udp_local_e2e` and lifecycle harnesses are
  extended in place。No second process harness or copied DNS/SIP022 codec is permitted。

## TDD seams

Each T02～T08 slice starts with one failing assertion at the module interface and lands green：

1. generic core ordered-program interface；
2. pure `ferrum2-sniff` byte-slice interface；
3. config's declared-version gate and validated compiled route/DNS model；
4. existing `DnsProxy::answer` and tagged resolver interface；
5. `ClientEgressEngine` plus private SOCKS UDP endpoint/association interface；
6. authenticated server TCP/UDP composition and `ProcessRoot` lifecycle；
7. existing real-process and qualification-driver interfaces。

Tests assert observable results through those interfaces。Parser internals、private UDP fields and route
cursor storage are not separate test surfaces。

## T01 baseline、contract and dependency evidence

- Resolve qualified product `1af1bbf…` and planning HEAD/tree/parent `cc8a0c2…` /
  `7eccfc6…` / `f4dcebc…`；prove the intervening diff contains no Rust/manifests/lock changes。
- Keep T01's docs-only ticket base `5c2c7ab4818cfcddd9b2cd0a45adc5880a74869b` / tree
  `1794b60c6c8b0d3ca65dd5f32cb82f2504ba07cd` / parent `cc8a0c2…` distinct from the schema-3 planning
  measurement baseline。
- Amend SPEC-0014/ADR-0032 wording so client/multi-hop/DNS use owned snapshots while server may use its
  validated one-hop scalar path；record the architecture guard required before server route changes。
- Freeze the explicit schema-v2 migration boundary：v1 client routed+UDP is a zero-side-effect config
  error，v2 selects once per association，and no old client data-plane branch is planned。Record the pinned
  sing-box inference and RFC-neutrality separately。
- Review exact Hickory/rustls reuse、locked `ipnet 2.12.1` and new `httparse 1.10.1` for source、
  checksum、license、MSRV、features、unsafe and dependency graph before activation。
- Reset schema 3 to M14 at `cc8a0c2…` counts `21814/39632` and case/support/fixture
  `33883/5152/597`，with unchanged thresholds、`policy_revision=1` and this file as `reforecast_ref`。
- Run current selector、config、DNS proxy and architecture cohorts unchanged；a baseline failure blocks
  implementation。

### T01 dependency review disposition

Evidence sources are the exact `Cargo.lock` and workspace manifest，locked `cargo tree -e features`，and
the crates.io index/archive plus unpacked `Cargo.toml`、source and `.cargo_vcs_info.json`。The no-default
`ipnet` and `httparse` library sources also compile directly with `rustc 1.88.0`。No dependency is
activated by T01。

| Use | Exact source identity | License / MSRV / features | Unsafe and dependency disposition |
|---|---|---|---|
| DNS parser reuse | `hickory-proto 0.26.1`，crates.io checksum `0bab31817bfb44672a252e97fe81cd0c18d1b2cf892108922f6818820df8c643`，VCS `f09321075b1f97902b7bc4ca4ffda7816fcf2971:crates/proto` | `MIT OR Apache-2.0`；`rust-version = 1.88`；existing exact no-default workspace edge selects `std`，while existing resolver/server edges account for the already-resolved `access-control`/`serde` features | Proto source has no actual unsafe statement。T04 may add only a direct workspace edge and use Hickory message parsing；no identity、feature、provider、resolver or DNS-answering change。Exact existing resolver/net/server checksums remain `f0d58d28879ceecde6607729660c2667a081ccdc082e082675042793960f178c` / `e2295ed2f9c31e471e1428a8f88a3f0e1f4b27c15049592138d1eebe9c35b183` / `130236ba6abba90da6a7acf7a87b27d862b592c3145dc74bc47bf86d8ff198ec`；resolver platform `system_conf` unsafe stays uncompiled because `system-config` is not selected。 |
| TLS ClientHello reuse | `rustls 0.23.43`，crates.io checksum `0283386ce02abc0151e1761d08802dfe86c173b0b494af5cbc086574e453da06`，VCS `fcf61cdbba30913cfd5b40aefa83989c6233812d:rustls` | `Apache-2.0 OR ISC OR MIT`；`rust-version = 1.71`；existing exact no-default workspace edge retains `ring,std,tls12` | Rustls forbids unsafe code。T04 uses only `server::Acceptor` through public `ClientHello::server_name()`；the API exposes no ECH marker，so ECH metadata is the observable outer public/cover SNI and never claims the encrypted inner name。No second TLS/ECH parser、provider、handshake、feature or package change。 |
| CIDR matcher | locked `ipnet 2.12.1`，crates.io checksum `6a756c3fac73139e83f14c2d742155dd2b78d3ee56597b419a0579b7bdd6dd78`，VCS `bdc02c67c85b0298e8315b32bb9018bdd0f8e8f7` | `MIT OR Apache-2.0`；manifest has no `rust-version` and upstream documents Rust 1.26+；no-default source passes Rust 1.88 | Source has no unsafe。T02 may add exact `=2.12.1`、no-default direct core edge with no new feature；the package is already locked through Hickory，so no new identity or transitive package is allowed。 |
| HTTP/1 request parser | `httparse 1.10.1`，crates.io checksum `6dbf3de79e51f3d586ab4cb9d5c3e2c14aa28ed23d180cf89b4df0454a69cc87`，VCS `9f29e79f9832dbd0ae5220acb17c1866745bdecd` | `MIT OR Apache-2.0`；manifest declares no `rust-version`；no-default/no-feature source passes Rust 1.88；default `std` stays disabled | The external package uses reviewed unsafe pointer/`MaybeUninit` and SWAR/SSE4.2/AVX2/NEON internals with source safety guards。T04 may consume only safe `httparse::Request::parse` with a 64-header caller-owned array and must retain malformed/fragmentation/boundary mutations。This is the sole new package identity，has no normal/build dependencies，and grants no workspace unsafe exception；upgrade or feature change requires renewed review。 |

These dispositions are blocking inputs to T02/T04：a checksum、MSRV、feature、provider、unsafe surface or
dependency-closure mismatch stops activation and returns to contract amendment rather than being hidden
in `Cargo.lock`。

```powershell
git rev-parse HEAD
git show -s --format='%H%n%T%n%P' cc8a0c2946788c16e5d7af2658a7d80bac0a844b
git diff --name-only 1af1bbf44b37a81c2ae03c562288b2a6e09694b5..cc8a0c2946788c16e5d7af2658a7d80bac0a844b
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh verify
cargo test -p ferrum2-core --test selector_contract --locked
cargo test -p ferrum2-config --test config_contract --locked
cargo test -p ferrum2-dns --test proxy_contract --locked
cargo test -p ferrum2-client routed_udp_uses_lazy_endpoint_legs_and_rejects_cross_leg_responses --locked
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo fmt --all -- --check
git diff --check
```

## T02 core program、matcher and egress-graph evidence

- Add `crates/ferrum2-core/tests/route_program.rs` and reuse selector-contract builders；do not create a
  second graph implementation or support tree。
- A table proves unconditional sniff then metadata match，unknown/timeout/limit continuation，terminal
  route/reject/hijack stop，mandatory final，private cursor monotonicity and at most `rules.len()` visits。
- Matcher tables cover ASCII case/terminal dot/label suffix、original versus sniffed domain、IPv4/IPv6
  exact and canonical CIDR、port/range boundaries、legacy exact target、field AND/list OR and 64 limits。
- Hold a selector across a synthetic non-terminal step，switch，then prove terminal selection sees the
  new member；switch after terminal leaves the snapshot fixed。Selected failure cannot re-enter program。
- Architecture guards reject concrete protocol/action names in core、a second ordinary engine and a
  server scalar path capable of multi-hop。

```powershell
cargo test -p ferrum2-core --test route_program --locked
cargo test -p ferrum2-core --test selector_contract --locked
cargo test -p ferrum2-core --locked
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo clippy -p ferrum2-core --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## T03 schema-version config and capability evidence

- Add an explicit version matrix：supported v1 shapes remain normalized-identical；v1 client route plus
  enabled UDP fails on redacted `schema_version` before side effects；v2 accepts that shape and M14 fields。
  Unknown versions、M14 fields in v1、heuristic fallback and automatic rewrite all fail。
- Extend existing config tables with scalar/list equivalence for every matcher and sniffer field；
  duplicates、empty/over-64 values and legacy/new target mixing fail with the exact owned field。
- Cover action required/forbidden fields、unconditional-terminal reachability and no-match final。
- Cover both role matrices：client TCP sniff、client UDP TLS/HTTP、server UDP TLS/HTTP-only、server
  hijack and client hijack without DNS all fail before side effects。
- Cover conservative earlier-sniff proof for each protocol rule，including inbound/network narrowing and
  a valid broader rule。No runtime no-op substitutes for validation。
- DNS tables cover client qname/qtype/transport and server domain/suffix/port without qtype，including
  the closed qtype set and listener/ordinary tag identity。
- Repository Quick updates the existing `socks_udp_local_e2e` table in place：the superseded schema-v1
  per-datagram multi-outbound row is retired，two-hop success retains only static/selector roots and its
  credential-failure matrix uses the supported static root。T07/T08 own the replacement schema-v2
  association-route-once process row；no compatibility branch or second harness is added。

```powershell
cargo test -p ferrum2-config --test config_contract --locked
cargo test -p ferrum2-m0-harness --test config_cli --locked
cargo test -p ferrum2-config --locked
cargo clippy -p ferrum2-config --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## T04 pure sniff-module evidence

- DNS tables use Hickory-built messages for valid UDP、complete/partial TCP、one IN question and negative
  response/multi-question/class/length/max-byte/non-53 behavior。
- TLS ClientHello bytes are generated by the rustls client interface at test time。TLS 1.2/1.3、SNI
  present/absent、multi-record and every fragmentation boundary are covered，with plausible-prefix、
  malformed、exact-limit/+1 and no raw-error mutations。A generated TLS 1.3 outer-SNI ClientHello is
  mutated with a syntactically valid ECH ClientHelloOuter extension and checked to retain only the same
  rustls-observable outer public/cover name；the row is not ECH termination、decryption or interoperability
  evidence and makes no claim about an encrypted inner name。
- HTTP tables cover GET/POST/CONNECT、Host case、authority、every fragmentation boundary、partial request、
  64/65 headers、duplicate/invalid Host、IP literal、body exclusion and response rejection。
- Composite order、first-match、Invalid-continues and NeedMore arbitration are one shared table。No opaque
  fixture、handwritten parser or parser registry is added。
- Metadata/source guards prove the new crate has no Tokio/config/runtime/binary edge and that exact
  dependency identities/features match ADR-0033。

```powershell
cargo test -p ferrum2-sniff --locked
cargo test -p ferrum2-m0-harness --test workspace_policy --locked
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo clippy -p ferrum2-sniff --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## T05 server vertical-slice evidence

- Runtime collector tables prove lazy growth、one absolute deadline、checked maximum、buffer ownership、
  cancellation、read I/O failure and exact returned prefix。
- Server TCP tables cover authenticated initial+fragmented reads for DNS/TLS/HTTP，unknown/server-first
  timeout continuation，terminal reject before direct open and byte-for-byte prefix replay exactly once。
- Server UDP tables place borrowed DNS sniff after authenticated prepare and before reservation；route
  retains reserve/commit behavior，reject forwards nothing but consumes required replay/binding state，
  and unauthenticated invalid input emits no sniff metadata。
- Selector switch during TCP wait and after terminal selection、selected open failure、cancel、grace、
  force and rebind are mutation-tested through current owner interfaces。

```powershell
cargo test -p ferrum2-runtime sniff_prefix --locked
cargo test -p ferrum2-server route_sniff_reject --locked
cargo test -p ferrum2-server lifecycle_composition_contract_prefix --locked
cargo test -p ferrum2-server --locked
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo clippy -p ferrum2-runtime -p ferrum2-server --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## T06 DNS policy and answering evidence

- Extend `proxy_contract.rs` through `DnsProxy::answer` for listener and ordinary identities、qname
  exact/suffix/qtype、UDP/TCP framing、multi-query TCP and malformed terminal behavior。A mutation that
  adds a delegating service or copied codec must fail architecture evidence。
- Extend tagged upstream tables for client query and server application-resolution policy，mandatory
  final、selected failure no fallback and UDP TC same server/address/plan。
- Preserve direct/detoured UDP/TCP/DoT/DoH、busy/timeout/SERVFAIL、absolute deadline and owner shutdown
  evidence。Server A+AAAA uses one selection and exposes no qtype policy。
- Prove listener and ordinary inbound index zero cannot collide even though their tags are globally
  unique。

```powershell
cargo test -p ferrum2-dns --test proxy_contract --locked
cargo test -p ferrum2-dns --test tagged_upstreams --locked -- --nocapture
cargo test -p ferrum2-dns --test resource_lifecycle --locked -- --nocapture
cargo test -p ferrum2-client dns_proxy_first_match_direct_and_detoured_transports --locked
cargo test -p ferrum2-server tagged_dns_selection_uses_authenticated_original_context_and_final --locked
cargo test -p ferrum2-client -p ferrum2-server -p ferrum2-dns --locked
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo clippy -p ferrum2-dns -p ferrum2-client -p ferrum2-server --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## T07 client route、hijack and UDP ownership evidence

- SOCKS command tables prove policy denied maps exactly to reply `0x02` and other mappings remain exact。
- Client TCP tests cover known-target route、reject and port-53 hijack with multiple framed queries；
  config and runtime tests prove no TCP sniff wait and no ordinary fallback after hijack。
- One client UDP state table proves wrong-source/malformed/fragmented input cannot classify the endpoint；
  an over-limit candidate may calculate selector A's plan limit but commits zero source/terminal/activity/
  owner/live-ID/target/wire state，then after A→B the first eligible packet uses B exactly once。
- Its routed row switches B→A after commitment and sends a later target that would match another rule，then
  proves both packets retain their own destinations through B with no rule/final/selector re-read、second
  plan/session or fallback。
- Separate first-packet rows prove DNS hijack holds the whole association in DNS answering，later non-DNS
  traffic cannot route，reject drops and ends the association，and neither action creates a Shadowsocks
  socket/plan/session/live ID。
- Source and failure mutations prove `SocksUdpEndpoint` alone owns application socket/source/SOCKS wire，
  all `ClientUdpAssociation` fields are private and describe one plan，DNS cannot reach codec/session
  internals，no per-datagram route/plan map remains，and existing shutdown/rebind stays green。

```powershell
cargo test -p ferrum2-socks5 --test command --locked
cargo test -p ferrum2-client client_route_reject_hijack --locked
cargo test -p ferrum2-client routed_udp_first_valid_packet_selects_association_once --locked
cargo test -p ferrum2-client dns_proxy_detour_saturation_shutdown_and_exact_rebind --locked
cargo test -p ferrum2-client udp_chain_invalid_inner_state_and_shutdown_are_atomic --locked
cargo test -p ferrum2-client -p ferrum2-dns -p ferrum2-socks5 --locked
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo clippy -p ferrum2-client -p ferrum2-dns -p ferrum2-socks5 --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## T08 real-process、architecture and qualification-tool evidence

- Extend the existing process harness with four primary rows：
  `m14_server_tcp_sniff_routes_rejects_and_replays_prefix`、
  `m14_server_udp_dns_sniff_routes_and_rejects_before_target`、
  `m14_client_tcp_dns_hijack_reuses_policy_and_reaps` and
  `m14_client_udp_association_actions_route_once_and_reap`。
- Each row includes one distinct malformed/no-fallback negative，exact zero flow/session owners、return to
  the fresh process's exact fixed root-buffer baseline and exact rebind。A running server UDP listener
  intentionally retains four bounded wire buffers；the process row MUST prove this baseline is unchanged
  after session idle/reap，then prove process shutdown releases the listener by exact rebind rather than
  misreport the live root buffers as zero。The client UDP process row uses separate associations for
  route/hijack/reject and includes two targets with one observed real outbound。The mandatory T07
  `routed_udp_first_valid_packet_selects_association_once` row performs the actual post-selection selector
  switch and observes the same captured plan，while the T08 architecture guard forbids selector/rule/final
  reads after classification；these three executable layers form the no-re-read oracle without a binary
  management/test endpoint。Existing compatible M10～M13 TCP/UDP/DNS rows remain independent；the former
  per-datagram multi-outbound expectation is explicitly superseded，not run as compatibility。
- Extend the existing architecture test and qualification driver；do not create another harness/job。
  Any workflow edit is an isolated reviewed control commit and keeps automatic qualification separate
  from manual performance。
- Performance workload additions measure legacy no-sniff TCP/UDP、schema-v1 routed-UDP migration
  rejection、64-rule evaluation、server TLS/HTTP sniff with valid distinguishable inputs and terminal
  outcomes、schema-v2 association route once、client TCP/UDP DNS hijack、RSS/tasks/connections/sessions/
  queries and drain/rebind without a threshold claim。Self-check mutations reject a missing phase、invalid
  TLS sample and non-distinguishing terminal oracle。

```powershell
cargo build --workspace --bins --locked
cargo test -p ferrum2-client routed_udp_first_valid_packet_selects_association_once --locked
cargo test -p ferrum2-m0-harness --test local_e2e m14_server_tcp_sniff_routes_rejects_and_replays_prefix --locked -- --exact --nocapture
cargo test -p ferrum2-m0-harness --test udp_local_e2e m14_server_udp_dns_sniff_routes_and_rejects_before_target --locked -- --exact --nocapture
cargo test -p ferrum2-m0-harness --test local_e2e m14_client_tcp_dns_hijack_reuses_policy_and_reaps --locked -- --exact --nocapture
cargo test -p ferrum2-m0-harness --test socks_udp_local_e2e m14_client_udp_association_actions_route_once_and_reap --locked -- --exact --nocapture
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo test -p ferrum2-m0-harness --test qualification_contract --locked
cargo test -p ferrum2-m4-qualification --locked
cargo run -p ferrum2-m4-qualification --locked -- self-check
cargo test --workspace --all-features --locked
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## T09 exact qualification evidence

- Re-run every T01～T08 focused command serially on the accepted integration SHA；ticket/worktree results
  do not substitute for integration evidence。
- Confirm the T08 full Architect/QA review and any single targeted re-review bind the accepted product
  SHA；do not run a second full review when the exact product is unchanged。If integration changes that
  SHA，the review bound restarts for the new candidate and blocking findings must again be zero。
- After separate authorization，one non-force push must pass automatic quality、footprint、MSRV、Windows/
  GNU/musl、SIP022 and CoreDNS/BIND qualification。A separately authorized manual dispatch must pass the
  extended performance/resource job on the same exact SHA。
- A hosted failure caused by a stale qualification-generated schema is preserved as failed evidence and
  is not rerun。Repair only the existing generator on a new descendant SHA：native routed+enabled UDP and
  CoreDNS/BIND routed-UDP clients must emit explicit schema v2，while non-routed legacy schema-v1 cases
  remain unchanged。An existing contract test must mutation-kill either generator reverting to v1 before
  the new SHA receives one automatic push。This ordering was followed：manual performance was dispatched
  only after the repaired automatic run passed。

## Test-footprint forecast

Schema 3 resets at exact planning baseline `cc8a0c2946788c16e5d7af2658a7d80bac0a844b` with code/tests
`21814/39632`、ratio `1.816815` and case/support/fixture `33883/5152/597`。

| Slice | Case LOC | Support LOC | Fixture LOC |
|---|---:|---:|---:|
| T01 contract/control | 0 | 0 | 0 |
| T02 core program/matcher | 280 | 0 | 0 |
| T03 config compiler | 320 | 80 | 0 |
| T04 sniff adapters | 420 | 120 | 0 |
| T05 server slice | 300 | 80 | 0 |
| T06 DNS policy | 300 | 80 | 0 |
| T07 client/UDP ownership | 420 | 120 | 0 |
| T08 process/qualification | 320 | 80 | 0 |
| T09 qualification | 0 | 0 | 0 |
| **Total** | **2360** | **560** | **0** |

Each implementation ticket forecasts numeric `WARN` but stays at or below the `600` ticket review
threshold；the milestone necessarily forecasts `REVIEW_REQUIRED`。T02 support is zero because it reuses
the existing selector helpers，correcting the source plan's row/total arithmetic without compressing
evidence。Any new/expanded file above its independent threshold or third equivalent helper receives
explicit Architect/QA disposition。No Rust/static fixture or second harness is forecast。

## Serial integration gate

Run exactly on one accepted integration SHA：

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo build --workspace --bins --locked
cargo test --workspace --all-features --locked
cargo +1.88.0 check --workspace --all-targets --locked
cargo +1.88.0 build --workspace --bins --locked
cargo +1.88.0 test --workspace --locked
cargo test -p ferrum2-m0-harness --test lifecycle_cycles full_qualification_runs_twenty_cycles_per_category_and_at_least_100_per_binary --locked -- --ignored --exact --nocapture
cargo doc --workspace --all-features --no-deps --locked
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh milestone --candidate <accepted-integration-sha>
git diff --check
```

## Close evidence

Qualified product `bc6963472d9ae8e3c84d82851fd64d78c9f2a65f` passes the serial integration gate，
Rust 1.88、100+ lifecycle、three platforms、SIP022 TCP/UDP `12/12` each、all 12 CoreDNS/BIND DNS
cases、schema-3 integrity and final reviews。Automatic run
[`31284062682/1`](https://github.com/zzffu/ferrum2/actions/runs/31284062682) and independent manual
performance/resource run
[`31284310711/1`](https://github.com/zzffu/ferrum2/actions/runs/31284310711) bind the same SHA。The
manual job reports 10 throughput trials、10,000 sessions、180 resource samples、48 DNS samples、THP
restore、drain/rebind and cleanup PASS；the measured ratio is diagnostic only。

Failed run `31282591585/1` is preserved and was not rerun。Its schema-v1 hosted-generator defect is
mutation-guarded by `hosted_routed_udp_generators_use_schema_v2` on the repaired descendant；unrelated
schema-v1 cases remain v1。Final code/tests are `25586/45009`，ratio `1.759126` PASS。The cumulative
case/support/fixture delta `+5377/0/0` is an accepted `REVIEW_REQUIRED` disposition for distinct required
evidence in existing harnesses；integrity passes and no fixture or second harness was added。

## Stop rules

- Client TCP payload wait、target replacement/resolution、parser socket/route ownership、second ordinary
  engine、second DNS/SIP022 path or concrete protocol type in core blocks integration。
- Malformed/failed terminal traffic returning to policy，prefix loss/duplication，unauthenticated sniff，
  UDP reserve/commit reordering，server multi-hop scalar selection or client UDP field reach-through
  blocks integration。
- Any schema-v1 client routed UDP runtime branch、invalid first packet fixing association state、cached
  first-packet loss/duplication、later ordinary-route/selector re-entry or first-target pinning blocks
  integration。
- Integrity failure、missing dependency review、failed exact-SHA evidence、blocking review or missing
  remote authorization blocks close。Numeric footprint `WARN`/`REVIEW_REQUIRED` alone does not。
