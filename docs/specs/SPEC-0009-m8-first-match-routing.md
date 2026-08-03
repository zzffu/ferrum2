# SPEC-0009 — M8 shared minimal TCP/UDP first-match routing

- **Status:** Approved
- **Milestone:** M8
- **Baseline:** `404b62758a191fe879243c755c75bcf8b300040d`
- **Decision:** `docs/adr/ADR-0028-m8-first-match-routing.md`
- **Test plan:** `docs/test-plans/TEST-0009-m8-first-match-routing.md`

## Scope

Additive routed tagged schema v1 compiles one bounded first-match table shared by client/server
TCP/UDP composition。Rules match inbound identity、network and one exact validated target，return
one outbound identity，and use a mandatory final identity when none matches。Legacy and M7 static
tagged documents preserve exact behavior。

## Current baseline

- `ferrum2-config::{validate_client_graph,validate_server_graph}` resolves one outbound for every
  inbound and discards operator tags after validation。
- `bins/ferrum2-client/src/run.rs` captures one outbound context at listener admission；its UDP
  association connects one upstream socket before reading a target datagram。
- `bins/ferrum2-server/src/run.rs` captures one direct outbound in each TCP context；its UDP
  pending request exposes an authenticated target before runtime/protocol commit。
- `ferrum2-core::TargetAddr` is the existing bounded runtime-neutral target value。No shared route
  or network value exists。

## Requirements

### M8-MUST-01 — compatible configuration modes

- Every legacy and M7 tagged static document accepted at baseline MUST remain accepted without
  edits and retain exact normalized values、defaults、TCP/UDP enablement、CLI/check behavior、
  static mapping and resource choices。
- Legacy/static bindings MUST normalize into the same total selection interface while remaining
  invariant across network and target；binaries MUST NOT keep a second static dispatch path。
- `[route]` MUST be accepted only with tagged `[[inbounds]]`/`[[outbounds]]`。Without
  `[route]` every inbound MUST retain its required M7 `outbound` field。With `[route]` every
  inbound MUST omit `outbound` and `route.final` MUST be present。
- Legacy/route mixing、static/route mixing or partial inbound binding MUST fail as redacted
  `config.semantic` before subscriber、runtime、socket、table、channel、buffer or task creation。
- Old binaries MAY reject the additive fields；new binaries MUST NOT heuristically reinterpret
  malformed routed documents or silently ignore an accepted route table。

### M8-MUST-02 — bounded complete route graph

- `route.rules` MUST contain `0..=64` entries in document order。Each rule MUST contain at least
  one matcher and exactly one outbound action。`network` MUST be exactly `tcp` or `udp`。
- Rule `inbound`、rule `outbound` and `route.final` MUST exact-resolve in the existing global
  case-sensitive tag namespace。Every configured outbound MUST be referenced by at least one rule
  or final。
- `target` MUST be an inline `{ host, port }` value。Host MUST be an IPv4/IPv6 literal or
  1..=255-byte ASCII domain accepted by `TargetAddr`；port MUST be `1..=65535`。
- Invalid/missing/too-many/empty-predicate/dangling/wrong-namespace/unreferenced route data MUST
  use only non-indexed fields `route`、`route.rules`、`route.rules.inbound`、
  `route.rules.network`、`route.rules.target`、`route.rules.outbound` and `route.final`。
  Display/Debug MUST expose no tag、target、endpoint、PSK or source text。

### M8-MUST-03 — total first-match semantics

- Present matchers in one rule MUST be conjunctive and omitted matchers MUST be wildcards。Rules
  MUST be evaluated in document order and the first matching rule MUST be final for that request。
- Inbound tags MUST compare with existing exact case-sensitive semantics。IP targets and non-zero
  ports MUST compare exactly；ASCII domain hosts MUST compare case-insensitively。A trailing dot
  MUST remain distinct。
- If no rule matches，`route.final` MUST select one outbound。No runtime query may return
  no-route，and connect/resolve/send/protocol failure MUST NOT retry a later rule or final。
- Matching MUST use the pre-resolution `TargetAddr`。Resolved DNS answers、payload-sniffed names
  and response targets MUST NOT enter request route selection。

### M8-MUST-04 — shared module and mutation ordering

- One runtime-neutral route module MUST own matching/order/final behavior behind one total
  selection interface consumed by all four client/server TCP/UDP paths。Config MUST resolve
  operator strings to bounded IDs；binaries MUST NOT perform runtime string lookup。
- The implementation MUST remain bounded by 64 rules and MUST NOT add a route trait、generic
  graph、adapter factory/registry、new crate or dependency。
- Client routing MUST occur only after complete SOCKS source/wire/target validation；server
  routing MUST occur only after SIP022 authentication、timestamp/type/address/binding checks。
- Selection MUST precede outbound connect、DNS resolution、peer-sized allocation、endpoint pin、
  protocol replay/activity/session/queue commit、forwarding and send，except for existing
  authentication/replay admission required to yield a valid server TCP session。

### M8-MUST-05 — client TCP and UDP behavior

- Each SOCKS CONNECT flow MUST select one Shadowsocks outbound from its inbound/network/target and
  retain it for the flow。A failed selected server MUST produce the existing closed SOCKS/run
  outcome without trying any sibling outbound。
- Each valid SOCKS UDP request datagram MUST select independently；one association MUST be able to
  send target A through server A and target B through server B and receive both responses。
- Routed UDP MUST retain one application socket、one upstream socket、one manager handle and the
  existing fixed buffer/queue accounting per association。Each actually selected unique server
  endpoint MAY lazily own one `UdpClientSession`/live ID；duplicate tags for one endpoint MUST
  share the leg and inactive outbounds MUST own no leg。
- A response MUST come from an activated exact configured server endpoint and pass only that
  endpoint leg's SIP022 binding/replay state before it can reserve/materialize/commit or reach the
  SOCKS endpoint。The association MUST own and reap every leg/ID on all terminal paths。

### M8-MUST-06 — server TCP and UDP behavior

- Each authenticated TCP request MUST select one configured direct outbound identity before
  direct connect and initial-payload forwarding。The selected identity MUST remain fixed for the
  flow。
- Each authenticated UDP request datagram MUST select independently before runtime reservation or
  protocol commit。Current server outbound adapters are all direct，so distinct tags MAY have
  equivalent external egress but their resolved selection MUST be consumed rather than ignored。
- Server UDP session-to-local-inbound binding、same-inbound peer roaming、replay/generation order
  and response egress through the owning inbound MUST remain exact when consecutive datagrams
  choose different direct identities。
- Direct connect/resolve/send failure MUST remain affected-flow/session behavior and MUST NOT
  select another route。

### M8-MUST-07 — preserved bounds, lifecycle and observability

- One process-wide method/PSK、aggregate TCP admission/server replay、client live-ID registry and
  both roles' UDP association/session/allocated-byte bounds MUST remain。Route rules MUST NOT
  multiply configured listeners、process roots or eager outbound resources。
- Routed client protocol legs MUST be lazy and bounded by configured outbounds，for a hard maximum
  of `udp.max_sessions * 64` live legs。All variable receive/protocol/output/queue capacities
  MUST remain charged once to the existing aggregate byte budget。
- Existing absolute handshake/connect/idle/shutdown deadlines、prepare-before-poll transaction、
  reverse rollback、fatal arbitration and bounded reap MUST not reset or split at selection。
- Existing CLI flags、0/1/2 exits、four config codes、eight run codes、trace keys and fourteen
  metric family identities MUST remain。Tags、targets and selected route identities MUST NOT
  become errors、trace fields or metric labels。

### M8-MUST-08 — local acceptance and exact-SHA qualification

- A bounded real-process matrix MUST exercise rule order、AND/wildcard、final、two client upstreams、
  both networks and at least two inbounds without a cross product。One UDP association MUST route
  two exact targets to two servers。
- Focused negatives MUST cover selected outbound unavailable/no fallback、unmatched final、
  same-domain different case、different port、DNS target before resolution、invalid response source、
  resource saturation、control/root cancellation and restart/rebind。
- Existing legacy/static local TCP、server UDP、SOCKS UDP and 100+ lifecycle suites MUST remain
  regression gates。Existing external TCP/UDP `12/12`+cleanup remain same-SHA regression evidence；
  M8 adds no external wire cases。
- One accepted integration SHA MUST pass repository Full、Rust 1.85、Windows MSVC、Linux GNU/
  musl、M8 test envelope and blocking review。Missing、failed、skipped、unavailable、wrong-SHA
  or unauthorized evidence MUST block close。

## Non-goals

- GeoIP、Geosite、DNS policy/cache/resolver、sniffing、user/multi-user rules or resolved-IP match。
- CIDR/range、domain suffix/keyword/regex、port lists/ranges、negation、rule groups or rule tags。
- Reject actions、fallback/failover、health checks、load balancing、groups or chaining。
- Per-entry credentials、SIP023、new adapter kind、`Endpoint` interface、transparent/TUN、
  hot reload、management API or route/tag telemetry。
- New dependency/provider/workflow job、performance threshold、package、release or publication。

## Implementation freedom

- Config may use compact IDs/indexes/newtypes as long as every reference is prevalidated and
  callers cannot observe operator strings。
- The core route module may store exact target matchers separately from `TargetAddr` if needed for
  ASCII-case-insensitive domain comparison；its interface and behavior above remain the test seam。
- Routed client UDP may choose any one-socket demultiplexing implementation with equivalent exact
  source+cryptographic binding and fixed accounting；it MUST NOT pin the whole association to the
  first route or create one socket/buffer set per configured outbound。
- Server direct identities need no duplicate runtime owner while all adapters remain direct；
  adding a distinct outbound kind requires a new contract。
