# ADR-0033 — M14 ordered routing、bounded sniffing and DNS hijack seams

- **Status:** Accepted
- **Date:** 2026-08-08
- **Related:** `SPEC-0015`、`TEST-0015`、M14-T01～T09；preserves ADR-0024、ADR-0031 and
  ADR-0032；supersedes ADR-0023 only for schema-v1 client routed UDP admission，and supersedes
  the client routed SOCKS UDP selection granularity/multi-plan shape in ADR-0028、ADR-0029 and ADR-0030

## Context

The current core route module performs one exact-target first-match selection and immediately returns an
egress action。M14 needs a matched `sniff` rule to enrich metadata and resume only after that rule，while
keeping terminal route/reject/hijack decisions、selector snapshots and no-fallback behavior exact。

The source also constrains seam placement。SOCKS TCP has no pre-route application payload，server TCP owns
authenticated prefix bytes，and UDP already has a complete authenticated/decoded datagram at its policy
point。Core must remain runtime-neutral and free of concrete protocols。The DNS crate already exposes a
listener-independent `DnsProxy::answer` implementation，so adding a second `DnsService` wrapper would be
a shallow duplicate rather than a new capability。

M8、M10 and M11 made routed client UDP select per validated datagram。The pinned
[sing-box baseline](../research/M14-sing-box-socks-forwarding-baseline.md) instead caches the first SOCKS
UDP datagram，uses its destination to route the packet connection once and then preserves later
per-packet destinations through the selected outbound。RFC 1928 leaves internal route/outbound lifetime
unspecified，so [the standards review](../research/M14-socks5-udp-semantics.md) permits either model。M14
chooses the sing-box selection granularity for schema-v2 client routing without pinning the association
to the first destination。No per-datagram routed client implementation remains in M14。

## Decision

### Core owns one protocol-neutral ordered program

`ferrum2-core::route` owns matcher primitives、immutable original-target context、private monotonic cursor
and an `OrderedRouteProgram<P, A>`-shaped value generic over a caller-owned protocol key and action value。
The exact Rust spelling may vary，but its interface advances evaluation state internally and returns the
next matched action or mandatory final action；callers cannot jump、restart or mutate the original target。

Core does not name DNS、TLS、HTTP、sniff or hijack。Config owns the closed operator action/protocol
spellings，`ferrum2-sniff` owns detected protocol values，and the client/server composition adapters map
them exhaustively。This preserves a one-way dependency graph without a dynamic registry or a one-
implementation trait。

Legacy `RouteTable` paths remain compatibility views over the same matcher/egress implementation；M14
does not keep a second single-pass rule engine。The selector/plan graph is reusable independently of
program evaluation so a terminal route resolves its member only at that moment。

### Actions and failure semantics are explicit at composition

The compiled action set is closed：

```text
sniff        non-terminal；execute at most once，then resume after the matched rule
route        terminal；resolve one immutable egress plan
hijack-dns   terminal；client only
reject       terminal；TCP deny/close，UDP drop
```

Unknown、invalid、timeout and byte-limit sniff outcomes update fixed metadata and continue。Cancellation
or real I/O failure terminates the flow。A terminal action prevents later rules and final from running；
failure after terminal selection never returns to policy。

Selector resolution occurs at terminal route。Client TCP retains one owned `EgressPlanSnapshot` per
flow；routed client SOCKS UDP retains one per association after its first valid datagram。Server actions
may retain the validated one-hop scalar identity to avoid per-datagram shared-owner work。ADR-0032/
SPEC-0014 are clarified accordingly，and an architecture guard forbids using the scalar path for a
multi-hop graph。

### The breaking client UDP change uses schema version 2 without a dual data path

Changing an accepted schema-v1 routed client from per-datagram selection to one association selection
would reinterpret operator input，so ADR-0023 requires explicit `schema_version = 2`。Keeping routed UDP
operational under version 1 would in turn require the second per-datagram data path the owner explicitly
rejected；ADR-0033 therefore narrowly supersedes ADR-0023 admission for that combination。Version 1
remains accepted for every other M13 shape，but a client document combining routed mode with enabled UDP
fails closed during configuration validation with a redacted migration error。It cannot reach a
per-datagram runtime path。Version 2 uses the same bounded role shapes plus M14 fields，with
association-routed client UDP as the documented breaking semantic。There is no heuristic fallback、
automatic rewrite or compatibility implementation hidden behind the version。

Migration is an operator edit from version 1 to version 2 after reviewing this UDP difference。Rollback
of an association-routed deployment requires the previous product/config pair；the M14 binary does not
reinterpret version 1 or emulate its former per-datagram route。All other schema-v1 compatibility and
the existing support/deprecation window remain governed by ADR-0023。

### One deep pure sniff module owns parser behavior

M14 adds `ferrum2-sniff` with one small byte-slice interface returning
`Matched | NeedMore | NoMatch | Invalid` plus closed detected metadata。Its implementation delegates DNS
wire parsing to exact Hickory `0.26.1`，TLS ClientHello parsing to exact rustls `0.23.43`
`server::Acceptor` and HTTP/1 request parsing to exact no-default httparse `1.10.1`。

The module owns no socket、Tokio task、route table、egress、DNS query or telemetry sink。Runtime owns one
bounded TCP prefix collector；UDP callers pass borrowed datagrams。Parsers are attempted in configured
order and cannot allocate or read beyond the validated aggregate limits。

### Match metadata never changes the target

The original target remains immutable。Exact IP/CIDR always matches only an original IP literal；port
always matches the original non-zero port；legacy `target` remains original exact host+port。New domain
matchers use sniffed domain when present，otherwise the original domain，with ASCII case folding、
terminal-dot normalization and label-boundary suffix matching。Sniffed names never trigger resolution or
replace the connect/forward target。

Rule/list/value counts、CIDR canonical form、port ranges and sniff byte/time bounds are validated before
runtime side effects。Matcher fields are AND；values inside one field are OR；ordered linear scanning is
kept for the hard maximum of 64 rules。

### Reuse the existing DNS answering module

`DnsProxy::answer` remains the single parse/select/query/encode interface and is deepened only where an
ordinary SOCKS ingress needs to call it。`DnsProxyListeners` remains the dedicated UDP/TCP socket adapter。
No pass-through `DnsService` type、second parser/framer or second resolver is added。

Client DNS policy gains a collision-free listener/ordinary inbound identity plus query transport、
qname exact/suffix and a closed qtype set。Server application-domain resolution gains exact/suffix
domain and port/range matching but not qtype。Both preserve M12 server selection、detour snapshot、UDP
TC same-server/address/plan and no-fallback semantics。Ordinary hijack never re-enters ordinary routing。

### Preserve ownership and trust ordering

Client SOCKS TCP may route、reject or hijack from known request fields but cannot sniff。`UDP ASSOCIATE`
keeps the existing behavior of returning one relay endpoint before application data。A private
`SocksUdpEndpoint` owns the application socket、source authorization and SOCKS wire state。Wrong-source、
nonzero-fragment or malformed datagrams are dropped without classifying or fixing the association。

The first source-authorized、`FRAG=0`、bounded decoded datagram is cached，its target becomes the immutable
association route target and its payload may be borrow-inspected for DNS。The ordered route program runs
once and transitions the endpoint once：

- `route` resolves one owned `EgressPlanSnapshot`，lazy-creates one private `ClientUdpAssociation` and
  forwards the cached first datagram exactly once。Every later valid datagram retains its own SOCKS target
  but uses that same plan；ordinary rules、final and selector state are never read again。
- `hijack-dns` keeps the whole association in the existing DNS answering path。Each later datagram may
  run DNS query policy，but cannot return to ordinary routing and creates no Shadowsocks state。
- `reject` silently drops the classification datagram and terminates the association without a UDP error。

A selected route failure also terminates the association without policy re-entry。One private concrete
transition is sufficient；no endpoint trait、factory or plan-keyed association map is added。Static/
legacy client UDP keeps its association-setup snapshot，schema-v1 routed+UDP is rejected before runtime，
and server UDP remains independently selected per authenticated datagram。

Server TCP sniffs only after SIP022 authentication and before direct connect，then replays the exact
prefix once。Server UDP sniffs after authenticated preparation and before target reservation；reject
commits only the replay/binding state required for an authenticated rejected packet。Unauthenticated
input cannot create sniff/policy telemetry or accepted mutation。

## Consequences

- Core routing stays reusable and protocol-neutral while config and parser modules keep their own closed
  vocabulary。
- Callers learn one stateful ordered-program interface and one pure sniff interface；parser、cursor and
  DNS answering complexity remains local。
- The current DNS implementation is reused rather than wrapped；the cost is retaining the historical
  `DnsProxy` name for a module that now also serves hijacked ingress。
- Schema-v2 routed client SOCKS UDP can no longer mix ordinary actions or outbounds inside one
  association。It may still carry different per-datagram destinations through the first selected
  outbound；there is no legacy client routed UDP data plane in the M14 binary。
- One routed association owns at most one selected plan instead of the current plan-keyed set of lazy
  legs；invalid datagrams cannot claim that plan or terminal mode。
- M14 adds one workspace crate、one new exact package identity and one direct edge to an already locked
  package，all subject to T01 dependency review。
- Hot-path and lifecycle changes require exact-SHA performance/resource evidence but define no minimum
  throughput or improvement claim。

## Rejected alternatives

- **Concrete DNS/TLS/HTTP enum in core:** violates the repository's runtime-neutral core contract。
- **A new `DnsService` delegating to `DnsProxy`:** shallow duplication；the existing answering interface
  already has the required depth。
- **Keep `ActionTable` beside a second ordered engine:** duplicates matching semantics and invites legacy
  drift。
- **Client SOCKS TCP pre-route sniff:** impossible without delaying CONNECT success for payload the
  current inbound does not own。
- **Keep routed client UDP selection per datagram:** RFC 1928 permits it，but it diverges from the pinned
  sing-box forwarding shape and retains unnecessary mixed-plan association state。
- **Pin every datagram to the first destination:** confuses route metadata with SOCKS wire semantics；the
  outbound is fixed，but every later datagram still carries and forwards its own destination。
- **Handwritten DNS/TLS/HTTP/QUIC parsing or a plugin registry:** expands security surface and scope
  without a second implementation need。
- **Trie、regex or dynamic matcher index:** unnecessary under the fixed 64-rule ceiling；ordered linear
  evaluation is simpler and preserves configuration order。
