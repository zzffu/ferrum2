# SPEC-0011 — M10 manual outbound selector

- **Status:** Approved
- **Milestone:** M10
- **Baseline:** `99bd62e9673f8743a0ea6597962fbfc22b3e3ce7`
- **Decision:** `docs/adr/ADR-0029-manual-outbound-selector.md`
- **Test plan:** `docs/test-plans/TEST-0011-m10-manual-outbound-selector.md`

## Scope

Additive tagged schema v1 compiles fixed-member manual outbound selectors into the shared route
selection path。Static inbound bindings、route rules and route final may name a selector；a public
process-local Rust interface queries and atomically changes its current immediate member。Later
selection calls observe the new member，while traffic that already captured a concrete outbound
identity remains unchanged。

## Current baseline

- `ferrum2-core::route::RouteTable` is the one total static/routed selection module and currently
  returns concrete `usize` identities。
- Its public concrete-only constructors and `final_outbound()` expose concrete indexes；client config
  also projects that final index into the public `ValidatedClientConfig.server` compatibility field。
- `ferrum2-config::{validate_client_graph,validate_server_graph,validate_route}` validates every
  tag/action before returning，but accepts only role-specific concrete outbounds。
- Client/server TCP select once after target authentication/validation；client routed and server UDP
  select per validated/authenticated datagram，while client static UDP selects at association setup。
- Public loaders are zero-resource Rust interfaces；there is no public selector/control type or
  HTTP/IPC/CLI control plane。

## Requirements

### M10-MUST-01 — compatible additive selector shape

- Every legacy、M7 static and M8 routed document accepted at baseline MUST remain accepted without
  edits and retain exact normalized values、defaults、concrete route results、CLI behavior and resource
  choices when `selectors` is absent。
- Existing public `RouteRule::new`、`RouteTable::static_bindings`、`RouteTable::routed`、`is_routed`
  and selector-free `final_outbound` behavior MUST remain source-compatible and concrete-only。
- `[[selectors]]` MUST be accepted only with tagged `[[inbounds]]` and concrete `[[outbounds]]`。
  Legacy/selector mixing、a present empty selector collection or partial tagged shapes MUST fail as
  redacted `config.semantic` before subscriber、runtime、socket、buffer、channel or task creation。
- Selector tags MUST share the existing inbound/outbound global case-sensitive namespace and
  `1..=64` ASCII grammar。The collection MUST contain `1..=64` selector entries。
- New binaries MUST reject malformed selector data；old binaries MAY reject the additive root field。
  No loader may silently ignore accepted selector state。

### M10-MUST-02 — complete bounded acyclic graph

- Each selector MUST contain `1..=64` unique immediate `outbounds` member tags and one explicit
  `default` tag。Default MUST be one immediate member；member order MUST NOT imply another default。
- A member MAY name one concrete outbound or one selector。Every member/default MUST exact-resolve in
  the outbound-target namespace；inbound、unknown、case-mismatched or duplicate members MUST fail。
- All selector edges MUST be checked，including edges not selected by defaults。Self、two-node and
  indirect cycles MUST fail closed。A validated graph MUST resolve every legal current-member state to
  one concrete role-valid outbound in at most 64 selector hops。
- Every concrete outbound and selector MUST be transitively reachable from at least one
  `inbounds[].outbound`、`route.rules[].outbound` or `route.final` root。No inert graph is accepted。
- Collection/mixing/count、tag、member and default failures MUST use only `selectors`、
  `selectors.tag`、`selectors.outbounds` and `selectors.default` as defined by ADR-0029。Errors MUST
  contain no index、tag、endpoint、PSK or source text。

### M10-MUST-03 — public manual control interface

- Both validated config roles MUST expose one cloneable `Send + Sync` public Rust control handle that
  shares state with the route table consumed by composition。This MUST be an additive accessor，not a
  new public config field that duplicates selector state。
- One public core compile entry MUST accept identity-safe tagged concrete、selector and action inputs，
  validate every member/default/action，and return a route table plus control handle sharing one state or
  return neither。Existing concrete-only constructors remain separate；no raw logical selector ID may be
  supplied through them or returned as a concrete outbound ID。
- `selected(selector_tag)` MUST return the current immediate member tag。For a nested selector it MUST
  return the selected selector tag，not the concrete leaf。
- `switch(selector_tag, member_tag)` MUST atomically replace current state only when `member_tag` is an
  immediate member。Selecting the already-current member MUST succeed without another effect。
- An unknown tag or concrete outbound used as selector MUST return closed `UnknownSelector`；an
  unknown、case-mismatched、non-member or descendant-only member MUST return closed `UnknownMember`。
  All failed operations MUST leave every selector unchanged。
- Control errors and Debug/Display MUST be value-free。No public private-index/atomic mutation hook is
  permitted，including under `cfg(test)`。

### M10-MUST-04 — atomic concurrent behavior

- Every query and switch on one selector MUST be linearizable。A racing query MUST observe one complete
  configured old or new member and MUST never observe an invalid/torn identity。
- A successful switch MUST be visible to later synchronized queries and route selections。Concurrent
  valid writers are last-writer-wins；M10 MUST NOT claim writer ordering beyond atomic linearization。
- Nested resolution MUST terminate and load each visited selector at most once。M10 does not require a
  graph-wide snapshot、CAS revision or multi-selector transaction。
- Query/switch MUST remain bounded in-memory operations with no I/O、async task、lock wait、DNS、retry
  or peer-sized allocation。

### M10-MUST-05 — selector actions and flow snapshots

- Static `inbounds[].outbound`、`route.rules[].outbound` and `route.final` MUST accept concrete or
  selector tags and compile before side effects。Binaries MUST NOT retain/parse operator strings。
- One route/static query MUST resolve through current selector members to exactly one concrete index。
  Selected connect/resolve/send/protocol failure MUST NOT modify selection or try a sibling、later rule
  or final。
- For selector-valued `route.final`，`select` MUST resolve the live current leaf，while public
  `final_outbound()` MUST remain the concrete configured-default leaf captured at compilation and never
  expose a logical selector identity。`ValidatedClientConfig.server` MUST remain that same immutable
  configured-default compatibility snapshot；runtime composition MUST NOT use it for route selection。
- Existing call-site granularity MUST remain：client/server TCP once per accepted/authenticated flow；
  client static UDP once at association setup；client routed UDP and server UDP once per validated/
  authenticated datagram before existing outbound mutation points。
- Once a caller receives a concrete identity，its endpoint、socket、protocol leg、direct handle and
  in-flight response MUST remain fixed despite later switches。Only a later selection call may observe
  the new member。

### M10-MUST-06 — both role compositions

- Client selector members MUST resolve only to configured Shadowsocks server outbounds。TCP and UDP
  MUST share the same process-local selection state without multiplying sockets、buffers、session IDs or
  admission limits at config/startup time。
- Server selector members MUST resolve only to configured direct outbounds。TCP and UDP MUST consume the
  selected direct identity at their existing post-auth/pre-mutation seams even though current direct
  adapters are behaviorally equivalent。
- Nested selectors、shared members and multiple binding/route references MUST share one current state
  per selector tag；they MUST NOT create per-inbound copies。

### M10-MUST-07 — preserved security, lifecycle and observability

- Existing authentication、replay、source/inbound binding、reserve-before-materialize/commit、aggregate
  TCP/UDP owners/bytes/IDs、deadlines、cancellation、shutdown and exact rebind MUST remain。
- Selector/member tags and current/default choices MUST NOT enter config errors、panic text、traces or
  metric labels。No selector-specific metric/trace family is added。
- Restart MUST reconstruct configured defaults。M10 MUST NOT persist selection、interrupt/migrate
  existing connections or rebuild membership at runtime。
- No new dependency、unsafe code、protocol wire change、schema successor or generic endpoint/adapter
  interface is allowed。

### M10-MUST-08 — qualification

- Public integration tests MUST verify query、switch、concurrency and control errors only through the
  public Rust compile/control/route interfaces；they MUST NOT inspect atomics、private IDs or private
  state。
- Existing config tables MUST cover both roles、static/route selector roots、nested resolution and every
  required empty/unknown/duplicate/default/cycle/reachability negative with redaction。
- Existing binary composition tests MUST drive switches only through the public handle and prove
  new-selection/old-snapshot behavior for client/server TCP/UDP without a test-only routing function。
- One accepted exact SHA MUST pass Full、Rust 1.85、100+ lifecycle、three native targets、existing
  TCP/UDP interop `12/12` each、schema 3 footprint and blocking review。Missing or skipped required
  evidence MUST block close。

## Non-goals

- HTTP、IPC、CLI/Clash API、management endpoint、persistence、hot reload or selector discovery/listing。
- Auto-select/URL test、retry、fallback/failover、health check、load balancing、chaining or interruption。
- Dynamic member mutation、CAS/version、multi-selector transaction、new adapter kind or control watcher。
- DNS/Geo/sniff/user rules、per-entry credentials/quotas、SIP023/multi-user、transparent/TUN、package、
  release or publication。

## Implementation freedom

- Core may store resolved logical/concrete newtypes or bounded indexes privately as long as the public
  selector-aware compile entry accepts distinct tagged identity domains，binaries only receive concrete
  identities and public errors expose no index/value。
- Core may use any standard-library atomic ordering that proves the required linearization/visibility；
  no exact ordering enum is a public contract。
- Config may validate graph topology before or inside the core constructor as long as one shared
  implementation covers both roles and ConfigField mapping remains exact。
- Existing tests may be extended or table-driven；a third equivalent helper or new process control
  harness is outside the plan。
