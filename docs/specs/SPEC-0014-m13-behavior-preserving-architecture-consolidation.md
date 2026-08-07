# SPEC-0014 — M13 behavior-preserving architecture consolidation

- **Status:** Approved
- **Milestone:** M13
- **Baseline:** `4810ec5c5a1063cb8e60d1b950900c7f38d74548`
- **Qualified behavior source:** `c06386e9344c07d86ea4a3b63dc73f37f20ceb0e`
- **Decision:** `docs/adr/ADR-0032-m13-egress-and-module-seams.md`

## Outcome

Ferrum2 preserves every M12 operator、wire、routing、DNS、resource and lifecycle behavior while replacing
duplicate plan identities and composition-root helper coupling with deeper modules。Core owns one
allocation-preserving egress-plan snapshot，DNS owns a config-independent runtime model，and one private
client egress module executes already selected plans for SOCKS and DNS consumers。

The words MUST、MUST NOT、SHOULD and MAY are normative。

## Requirements

### M13-MUST-01 — exact M12 compatibility

- Schema version 1、all accepted legacy/tagged config shapes、defaults、limits、field errors and redaction
  MUST remain exact。`--check-config` MUST still create zero runtime/network resources。
- CLI flags/output、public listener behavior、SIP022 TCP/UDP wire、crypto、replay/binding、first-match
  routing、manual selector control and fixed-chain order/credentials MUST remain exact。
- Ordinary route action and DNS action namespaces MUST remain independent。A selected plan/server failure
  MUST NOT retry、fallback、try a sibling/later rule/final or mutate selector policy。
- Missing `[dns]` MUST retain system resolution。Configured UDP/TCP/DoT/DoH、numeric bootstrap、TLS/HTTP
  validation、no cache/retry and direct/detoured behavior MUST remain M12-exact。
- M13 MUST add no config field、CLI option、public listener、runtime action、metric label or operator-visible
  error category。

### M13-MUST-02 — one owned egress-plan snapshot

- `ferrum2-core::route` MUST expose `EgressPlanSnapshot` as an owned、immutable、`Clone + Eq + Hash`
  concrete-plan value with `hops(&self) -> &[usize]` and fixed redacted `Debug` output。
- Validated graph compilation MUST allocate each immutable hop slice once。Owned selection and cloning
  MUST share that allocation；selecting or cloning MUST NOT copy the hop slice。No validated or public
  constructor path may produce an empty plan。
- Direct plans MUST contain one concrete outbound；fixed chains MUST retain `2..=8` unique ordered hops。
  Equality/hash MUST represent the exact ordered concrete plan and be suitable for UDP reuse identity。
- `EgressPlanHandle::snapshot_owned`、`RouteTable::select_plan_snapshot` and
  `RouteTable::final_plan_snapshot` MUST return owned values。Every product route and DNS-detour data-plane
  call site MUST use them before any await or mutable selector observation。
- Existing `EgressPlan<'_>`、`EgressPlanHandle::snapshot`、`RouteTable::select_plan` and
  `RouteTable::final_plan` MUST remain source-compatible views with identical hop results。
- One snapshot MUST remain fixed after selector switches；only a later selection may observe the new
  member。Static、routed、final、direct、chain and nested-selector actions MUST retain current selection
  granularity。
- `ferrum2_dns::PlanSnapshot` MUST be removed，and no product adapter may rebuild a plan with
  `Arc::from(hops)`、`to_vec()` or equivalent copying。

### M13-MUST-03 — DNS runtime-model dependency inversion

- `ferrum2-dns` MUST own a closed runtime transport type and `DnsUpstreamSpec` containing only validated
  runtime values：transport、numeric address、optional required TLS name/path and optional core
  `EgressPlanHandle` detour。
- `TaggedResolver::{direct,new}` and its owner/runtime implementation MUST accept DNS runtime specs and
  MUST NOT import、store or expose `DnsConfig`、`DnsServerConfig` or `DnsTransport`。
- The only normal workspace-internal dependency allowed from `ferrum2-dns` is `ferrum2-core`。
  `ferrum2-dns -> ferrum2-config`、`ferrum2-config -> ferrum2-dns` and any dependency on a binary are
  forbidden。Existing Hickory/Tokio dependencies and feature/provider identities remain exact。
- Client and server composition MUST each convert already validated config DTOs to runtime specs through
  a small pure function before listener bind、root creation、socket、runtime thread or task work。
- Conversion MUST only map validated fields；it MUST NOT parse tags/source text、read files、resolve names、
  open sockets or alter error provenance/order。Client/server focused tables MUST prove identical mapping
  for UDP、TCP、DoT、DoH、direct and detoured servers。
- DNS selection MUST snapshot one optional core `EgressPlanSnapshot` at the existing M12 selection point。
  Direct egress receives no plan；detoured TCP/UDP and UDP TC upgrade receive the same selected plan。
- Hickory MUST continue to own DNS messages/framing and upstream UDP/TCP/DoT/DoH behavior。M13 MUST NOT
  add a DNS gateway、parser、framer、cache、retry or transport implementation。

### M13-MUST-04 — one private client TCP egress module

- The client binary MUST own one concrete private `ClientEgressEngine` interface that opens TCP through
  a supplied `EgressPlanSnapshot` and application `TargetAddr` using the existing connector、clock、
  randomness、credentials and phase deadlines。
- The module MUST own the current concrete outbound preparation、ordered chain loop and nested flow
  lifetime。It MUST NOT own `RouteTable`、read/switch a selector、select policy or depend on
  `Socks5Inbound`。
- SOCKS CONNECT and detoured DNS TCP/DoT/DoH MUST call the same chain executor。DNS direct traffic MAY
  continue through `SystemDnsEgress`。
- Per-hop method/PSK、target nesting、connect/handshake deadlines、initial write、half-close、abortive
  terminal、cancellation、buffer owners and zeroization MUST remain exact。
- Any hop failure MUST terminate the selected plan with no retry/fallback/application success and must
  release every opened layer。An already opened flow MUST retain its snapshot across selector switches。
- The client DNS adapter MUST hold only the existing DNS egress seam and `Arc<ClientEgressEngine>`；it
  MUST NOT hold the SOCKS/process context or import chain implementation helpers。

### M13-MUST-05 — one bounded client UDP association

- The client egress module MUST own the current UDP association/plan/session implementation，including
  prepare、plan activation、reservation、nested encode、authenticated response acceptance、commit、cancel、
  drop and idle reaping。
- SOCKS UDP and detoured DNS UDP MUST consume this one implementation。Internal DNS UDP MUST remain
  independent from public SOCKS `UDP ASSOCIATE` opt-in and MUST NOT create another manager、codec、live-ID
  registry or capacity domain。
- Selection grain、all-layer authenticate/validate-before-mutate ordering、wire-size composition、session
  binding、replay and generation semantics MUST remain exact。
- DNS idle reuse MUST use an explicit key containing the numeric first-hop server and
  `EgressPlanSnapshot`。Same server/different plan，selector switch to a new plan，authentication/I/O
  failure、cancellation or partial state MUST NOT reuse an old association。
- Only a successfully relayed、fully reusable association MAY return to the bounded idle pool。The
  existing `UdpSessionManager` and DNS admission remain the owners of session/task/queue/buffer ceilings；
  M13 MUST NOT raise them。
- UDP TC upgrade MUST retain the same DNS server、numeric address and owned plan snapshot within the
  original deadline。Failure MUST NOT cause another DNS/route/selector selection。

### M13-MUST-06 — ownership-oriented source modules

- Client source MUST separate process composition、process context、SOCKS ingress、TCP/UDP egress、DNS
  adapter/root、Tokio I/O and observation mapping。`run.rs` may initialize validated contexts/roots，run
  `ProcessSupervisor` and map its report；it MUST NOT contain a TCP chain loop、UDP plan/session mutation、
  `DnsEgress` implementation or SIP022/DNS codec work。
- Server source MUST separate process、TCP、UDP mapping/response、DNS、Tokio I/O and observation ownership。
  It MUST NOT add a server outbound abstraction。UDP protocol capability、runtime reservation and commit
  MUST remain in one reviewable ordering seam。
- Core MUST move route/selector ownership behind `ferrum2_core::route::*` and
  `ferrum2_core::selector::*` without changing those public paths。Core remains free of config、DNS、
  protocol and async-runtime types。
- Config MUST separate public validated model/error/load/raw validation ownership while preserving all
  existing `ferrum2_config::{load_client, load_server, ...}` paths、error kind/field/display、bounded
  source reading and secret zeroization。
- Tests MUST move with their true module and exercise agreed interfaces。No test may copy a private
  product path merely to preserve access，and no independent M10～M12 negative/lifecycle evidence may be
  deleted solely to improve footprint numbers。

### M13-MUST-07 — security、resources、lifecycle and observability

- Complete configuration and DNS runtime conversion MUST finish before runtime/network side effects。
- Peer lengths/addresses、SIP022 authentication、DNS response identity and UDP state MUST continue to be
  validated before target work、accepted mutation or allocation beyond existing bounds。
- Aggregate connection/query/session/task/queue/buffer/live-ID ceilings、absolute deadlines and idle
  lifetimes MUST remain no greater than M12。No Tokio worker may block and no task may become detached。
- Prepare/rollback/activate/quiesce/drain/forced-stop semantics、primary-cause arbitration、owner counters
  and exact listener/upstream/hop rebind MUST remain exact for client and server roots。
- Trace/metric role、stage、reason and outcome identities MUST remain low-cardinality。Tags、targets、DNS
  names、plan hops、credentials and secrets MUST NOT enter errors、Debug/Display、logs、traces or labels。
- Workspace product code MUST remain unsafe-free。

### M13-MUST-08 — architecture and scope closure

- The workspace member set、normal third-party package identities、Hickory provider/features and existing
  real-process/interop/performance harnesses MUST remain unchanged。
- Architecture evidence MUST fail if DNS again depends on config，config depends on DNS，a second plan
  snapshot appears，client DNS reaches through process/SOCKS context，or composition roots regain TCP/UDP
  protocol execution。
- M13 MUST add no workspace crate、third-party dependency、fixture、second helper implementation、second
  harness、DNS/SIP022 data plane、public trait/factory/registry or unsafe exception。
- Test-footprint integrity is blocking。Numeric `WARN`/`REVIEW_REQUIRED` is advisory and MUST be accepted、
  reduced or reforecast explicitly without weakening evidence。

### M13-MUST-09 — exact qualification

- One accepted exact SHA MUST pass all T01～T06 focused evidence，repository Full，Rust 1.88 check/build/
  test，100+ lifecycle，Windows MSVC、Linux GNU and Linux musl，SIP022 TCP/UDP `12/12` each plus cleanup，
  CoreDNS/BIND DNS matrix，schema 3 footprint and blocking Architect/QA review。
- Performance/resource evidence is required because implementation ownership changes transport hot paths、
  UDP reuse identity and lifecycle composition。The existing M4 and M12 direct/detoured DNS profiles MUST
  pass on the same exact SHA；M13 defines no throughput threshold or improvement claim。
- Hosted push and manual dispatch require separate explicit authorization。Evidence MUST be exact-SHA/
  run/attempt bound；missing、skipped、spliced、unauthorized or failed evidence blocks close。
- No PR、tag、package、release or publication is implied。

## Non-goals

- New matcher/action semantics，automatic upstream policy，retry/fallback or dynamic graph rebuild。
- New DNS product behavior，transparent/TUN ingress，Fake-IP，hot reload or management interface。
- Global identifier/type redesign，new crypto/protocol core，new crate/dependency/harness or release work。

## Implementation freedom

- Internal file names MAY vary from the architecture sketch when ownership and the `run.rs` exclusions
  above remain evident；public paths and ticket ownership must be updated before editing。
- The owned snapshot MAY wrap `Arc<[usize]>` directly or an equivalent immutable shared allocation，
  provided equality/hash/redaction/no-copy behavior is proven through the interface。
- `ClientEgressEngine` MAY internally contain TCP/UDP structs and test-only internal seams，but its caller
  interface remains concrete and does not expose implementation helpers。
