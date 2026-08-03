# ADR-0028 — M8 shared first-match routing

- **Status:** Accepted
- **Date:** 2026-08-03
- **Related:** `SPEC-0009`、`TEST-0009`、M8-T01～T04；extends ADR-0027 and
  partially supersedes ADR-0026 only for routed tagged client UDP

## Context

M7 validates a bounded tagged graph but captures one outbound before a target is known。
`ClientInboundConfig::outbound`、`ServerInboundConfig::outbound` and both binary
composition roots therefore implement static inbound→outbound binding。A TCP target becomes
available only after SOCKS parsing or authenticated SIP022 acceptance；a UDP target is carried by
each validated datagram and can change inside one association/session。

M8 needs one decision with identical ordering in both binaries and both networks。The decision
must not move routing into protocol modules、repeat match logic in four callers、add speculative
endpoint kinds or weaken the existing authenticate/validate/reserve/commit order。

## Decision

### Additive routed tagged mode

`schema_version = 1` gains one optional root `[route]` table only for tagged documents。
Existing legacy documents and M7 tagged documents without `[route]` retain their exact static
binding behavior。Both compatibility modes normalize into the same total selection module；
static bindings select only by inbound ID and do not acquire network/target semantics。

In routed tagged mode every `inbounds[].outbound` is omitted；mixing any static inbound binding
with `[route]` is rejected。`route.final` is mandatory and resolves one configured outbound。
`route.rules` contains `0..=64` ordered rules；every rule resolves one outbound and contains at
least one of `inbound`、`network` or `target`。

Example client document：

```toml
schema_version = 1

[[inbounds]]
tag = "socks-a"
listen = "127.0.0.1:1080"

[[outbounds]]
tag = "ss-default"
server = "127.0.0.1:8388"

[[outbounds]]
tag = "ss-special"
server = "127.0.0.1:8389"

[route]
final = "ss-default"

[[route.rules]]
inbound = "socks-a"
network = "tcp"
target = { host = "example.test", port = 443 }
outbound = "ss-special"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
```

Server uses the same `[route]` shape；its configured outbound identities remain concrete direct
outbounds。Route mode is total：every valid query selects the first matching rule or
`route.final`。`final` is a no-match default，not connect/send failure fallback。

Every inbound/outbound reference resolves before `load_client`/`load_server` returns。All
configured outbounds must be referenced by a rule or `final`。Route mode with legacy tables、
missing/dangling/wrong-namespace references、too many rules、an empty-predicate rule or any
`inbounds[].outbound` fails closed as redacted `config.semantic` before runtime side effects。

### Match semantics

Rules remain in document order。Present matchers are conjunctive；an omitted matcher is a
wildcard：

- `inbound` matches one configuration tag with existing case-sensitive exact tag semantics；
- `network` is exactly `tcp` or `udp`；
- `target` is one structured host plus non-zero port。IPv4/IPv6 literals compare exactly；
  1..=255-byte ASCII domains compare without ASCII case，while a trailing dot remains distinct。

Target matching uses the already validated pre-resolution `TargetAddr`。It does not resolve a
domain and then match its answers。There is no list、negation、CIDR、port range、domain suffix/
keyword/regex、GeoIP、Geosite、sniffed name or user identity matcher。Operators repeat a rule
when they need another exact value。

### One deep route module

`ferrum2-core` owns one runtime-neutral in-process route module because it already owns
`TargetAddr` and must remain free of TOML、Tokio and concrete protocols。Its interface is one
total selection operation equivalent to：

```rust
route.select(inbound_id, network, &target) -> outbound_id
```

`ferrum2-config` parses and fully resolves operator tags into bounded IDs and constructs this
module。Binaries know only ordered inbound/outbound collections and the selection interface；
they do not retain or look up operator strings after validation。

The implementation is an O(n) scan over at most 64 rules。No route trait、adapter registry、
new crate or dependency is added。The linear ceiling is deliberate；an indexed implementation is
only justified by measured route-selection cost or a separately approved larger rule bound。

### TCP and UDP decision points

- Client TCP selects once after SOCKS CONNECT returns a valid target and before any Shadowsocks
  server connect/write；the selected outbound remains fixed for that flow。
- Server TCP selects once after authenticated SIP022 acceptance/replay admission returns a valid
  target and before direct connect/initial-payload forwarding。
- Client UDP selects each source-authorized、`FRAG=0`、bounded decoded datagram before
  outbound-specific protocol state、endpoint pin、accepted activity or send mutation。
- Server UDP selects each authenticated bounded pending request before replay/activity/session/
  queue/target mutation or direct send。DNS resolution，when needed by direct runtime，occurs
  after selection and cannot change it。

A selected outbound failure affects only the flow/association/datagram according to existing
failure rules and never retries a later rule or `final`。Responses do not run the request router
again；they return through the request's selected outbound leg and the owning inbound。

### Routed client UDP ownership

ADR-0026's static/legacy one-association/one-connected-upstream behavior remains unchanged when
`[route]` is absent。Routed mode retains one SOCKS association manager handle、one
application-facing socket、one upstream socket and the existing fixed reusable buffers。

The routed upstream socket uses exact `send_to`/`recv_from` endpoints。Each unique configured
Shadowsocks server endpoint actually selected by that association lazily owns one
`UdpClientSession` and one process-global collision-checked live ID；multiple tags for the same
server endpoint share that leg。A response source must identify an already activated endpoint
before protocol preparation，and cryptographic response binding/replay then uses only that
endpoint's leg。

No leg、ID or outbound-sized buffer is created at config load、listener start or association
setup。Leg count is bounded by the existing 64-outbound graph cap，so the process-wide ceiling is
`udp.max_sessions * 64` protocol legs while `udp.max_sessions` keeps its existing public SOCKS
association meaning。All payload/scratch/queue capacity remains charged to the existing aggregate
byte budget；all legs and IDs die with the control-owned association。A separate leg-limit setting
is deferred until this fixed ceiling is shown inadequate。

### Preserved security and operator behavior

One method/PSK、aggregate TCP admission、server replay、UDP association/session/byte ownership、
deadlines、source authorization、cross-inbound server UDP binding、process transaction and
shutdown/reap behavior remain exact。Route evaluation is pure and cannot connect、resolve、
allocate peer-sized storage、log a destination or mutate accepted protocol/runtime state。

Existing CLI exits/config/run codes、trace keys and metric family/label identities remain。
Inbound/outbound tags、route targets and selected identities never appear in errors、traces or
metric labels。No tag metric or route decision metric is added。

## Rejected options

### Duplicate matchers in each binary/network path

Four shallow implementations would drift on ordering、domain comparison and mutation timing。
One core module gives the same interface to every caller and one direct test surface。

### Route trait、Endpoint interface or generic graph

The decision is pure in-process data and has no varying adapter。A trait/factory would be a
hypothetical seam and would prematurely choose future Tailscale、transparent/TUN or chained
outbound architecture。

### Pin a UDP association to its first target

It is smaller internally but violates per-datagram target rules when one legal SOCKS/SIP022
session carries multiple targets。Rejected。

### CIDR/domain-pattern/DNS-result matching now

These require additional grammar、normalization and evidence without a current rule requirement。
Exact validated targets cover the requested minimum and leave those additions explicit。

### Failover to later rules or final

It changes deterministic first-match selection into health/fallback policy and can duplicate
non-idempotent connection or datagram side effects。Rejected。

## Consequences and rollback

- Positive：one small selection interface hides ordering、wildcards、target equality and default
  behavior from four callers。
- Positive：legacy/static configuration and all wire/protocol state machines remain unchanged。
- Negative：exact targets are intentionally verbose；CIDR/suffix cases require repeated rules or
  a later additive matcher。
- Negative：routed client UDP may hold up to one protocol leg per distinct configured server
  endpoint，but sockets and reusable buffers do not multiply by outbound count。

Rollback removes routed tagged parsing and the route selection path while restoring M7 static
bindings。It must reject `[route]` rather than leave accepted inert rules。No remote action、
release or publication is part of this decision。
