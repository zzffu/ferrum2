# SPEC-0015 — M14 bounded protocol sniffing and ordered route/DNS rules

- **Status:** Approved
- **Milestone:** M14
- **Baseline:** `cc8a0c2946788c16e5d7af2658a7d80bac0a844b`
- **Qualified behavior source:** `1af1bbf44b37a81c2ae03c562288b2a6e09694b5`
- **Decision:** `docs/adr/ADR-0033-m14-ordered-route-program-and-protocol-sniffing.md`

## Outcome

Ferrum2 adds bounded metadata-aware first-match routing without changing SIP022 wire/security。Because
association-level client UDP selection deliberately changes an accepted routing semantic，M14 adds
explicit schema version 2 and removes the per-datagram routed client UDP data path。Schema-v1
routed+UDP client input is rejected before side effects rather than silently reinterpreted。A non-terminal
sniff action may enrich one evaluation unit once，then ordered evaluation resumes；terminal route、DNS
hijack and reject actions end policy evaluation。

The words MUST、MUST NOT、SHOULD and MAY are normative。

## Requirements

### M14-MUST-01 — exact compatibility and bounded scope

- Every accepted schema-v1 document other than a client document combining routed mode with enabled UDP
  MUST remain accepted without edits and preserve every M0～M13 normalized value、default、error/
  redaction、CLI、wire、crypto、replay、routing、selector、chain、DNS transport/detour、resource and
  lifecycle behavior。
- Schema-v1 client routed+UDP MUST fail closed on the redacted `schema_version` migration field before
  listener、socket、resolver、task or root creation。The M14 product MUST contain no per-datagram client
  routed UDP implementation or version-selected compatibility branch。
- M14-only ordinary action/matcher/sniff and DNS-policy fields MUST require explicit
  `schema_version = 2`。Version 2 MUST accept the same bounded role shapes and existing fields；its only
  deliberate routing change is client SOCKS UDP selection once per association as specified by
  M14-MUST-08。Static client UDP and server UDP selection granularity MUST remain unchanged。
- Parsers MUST select only the declared version。There MUST be no heuristic fallback、silent rewrite、
  automatic migration or old selection engine。Rollback of routed client UDP requires the previous
  product/config pair；all other schema-v1 support remains under ADR-0023。
- Complete validation MUST finish before listener、socket、resolver、task、root or other runtime side
  effects。
- M14 MUST add no retry/fallback/failover、health/load balancing、target override、TUN/transparent/Fake-IP、
  QUIC/HTTP3、cache、dynamic registry、unsafe exception or second protocol data plane。

### M14-MUST-02 — ordered route program and action semantics

- One core-owned program MUST evaluate rules in configured order from a private monotonic cursor and MUST
  inspect at most 64 rules per evaluation unit：one TCP flow、one authenticated server UDP datagram，or
  one schema-v2 client SOCKS UDP association。It MUST NOT jump、restart or recursively evaluate。
- `sniff` MUST be non-terminal and MUST resume after its matched rule。Actual sniff work MUST occur at
  most once；a later sniff action continues without consuming another byte/time budget。
- `route`、`hijack-dns` and `reject` MUST be terminal。After any terminal selection，later rules and
  `route.final` MUST NOT execute，including when the selected operation fails。
- `route.final` MUST remain a mandatory egress action used only when evaluation exhausts all rules。
- Legacy `RouteTable` selection MUST delegate to the same implementation and retain exact-target
  first-match/final behavior；ordinary product routing MUST NOT retain a parallel `ActionTable` engine。
- Core MUST be generic over caller-owned action/protocol values and MUST NOT name DNS、TLS、HTTP、sniff、
  hijack、config or async-runtime types。

### M14-MUST-03 — ordinary matcher semantics

- Ordinary rules MAY match inbound、network、protocol、exact domain、domain suffix、exact IP、canonical
  CIDR、port、inclusive port range or legacy exact `target = { host, port }`。
- Different fields MUST combine with AND；multiple values inside one field MUST combine with OR。
  Scalar and non-empty list spelling MUST be accepted for every new matcher and `sniffers`。
- The original target MUST remain immutable。IP/CIDR and port match only the original target；a domain
  target MUST NOT match a resolved address。Legacy `target` matches only the original exact host+port。
- New domain fields match sniffed domain when present，otherwise original domain。Comparison is ASCII
  case-insensitive and ignores one terminal dot；suffix comparison MUST honor label boundaries。
  Sniffed metadata MUST NOT replace or resolve the original target。
- `protocol` MUST match only a successfully recognized closed value。TLS without SNI still sets protocol
  TLS and no domain；unknown、invalid、timeout、limit or unavailable does not match a protocol rule。
- A route document MUST contain at most 64 rules and one rule at most 64 total matcher values。Empty or
  duplicate lists、zero/reversed/overflow port ranges、noncanonical CIDR and incompatible legacy/new
  target fields MUST fail validation。

### M14-MUST-04 — pure bounded sniff behavior

- The only supported sniff protocols are strict DNS query、TLS ClientHello over TCP and HTTP/1 request。
  `ferrum2-sniff` MUST parse only supplied bounded bytes and MUST own no socket、task、route、egress、DNS
  network operation or destination telemetry。
- DNS parsing MUST use Hickory `0.26.1`。UDP consumes one complete datagram；TCP honors the two-byte
  frame。Only Query/standard opcode/one IN question recognizes DNS；responses、multiple questions、
  invalid class and malformed wire MUST NOT set DNS metadata。
- TLS parsing MUST use rustls `0.23.43` `server::Acceptor` only through ClientHello，including fragmented
  and multi-record input。It MUST NOT create a server config or complete a handshake。ECH/no SNI yields
  TLS with no domain；raw rustls errors MUST NOT escape。
- HTTP parsing MUST use exact no-default httparse `1.10.1` with at most 64 headers。Only requests are
  recognized；Host is case-insensitive，CONNECT authority is preferred，body is not consumed，IP literals
  do not become domains and duplicate/invalid Host yields HTTP with no domain。
- Configured sniffer order MUST be honored and first match wins。An invalid parser does not block later
  parsers。Incomplete DNS on non-53 ports MUST NOT delay TLS/HTTP；TLS/HTTP return NeedMore only for a
  plausible prefix。

### M14-MUST-05 — configuration and ingress capabilities

- In schema version 2，ordinary action spelling is closed to `route`、`sniff`、`hijack-dns` and
  `reject`。Absent `action` is legal only for the legacy `outbound` route shape。Schema version 1 MUST
  reject M14-only fields before side effects and retain its existing action shape。
- Route requires `outbound` and forbids `sniffers`；sniff forbids `outbound`；hijack/reject forbid both。
  An unconditional terminal rule and every rule after an unconditional terminal rule MUST fail as
  unreachable；an unconditional sniff MAY be valid。
- A protocol rule MUST have an earlier conservatively covering sniff rule for its inbound/network/
  protocol。Client TCP sniff、client UDP TLS/HTTP sniff、server UDP-only TLS/HTTP sniff、server
  `hijack-dns` and client hijack without `[dns]` MUST fail during config compilation。
- Client SOCKS supports route/reject/hijack for TCP and route/DNS-sniff/reject/hijack for UDP。Server
  Shadowsocks supports route/sniff/reject，with DNS/TLS/HTTP on TCP and DNS only on UDP。
- Defaults are `route.sniff.timeout_ms = 300` and `max_bytes = 8192`；valid ranges are
  `10..=2000` ms and `512..=16384` bytes。Checked multiplication of
  `runtime.max_connections * max_bytes` MUST succeed before runtime work。

### M14-MUST-06 — sniff resources and failure behavior

- One TCP flow MUST use one absolute sniff deadline and one lazily grown prefix capped by `max_bytes`；
  the prefix MUST count against existing buffer ownership/accounting。No max-sized eager allocation is
  allowed。
- UDP MUST inspect the already validated borrowed datagram without a payload copy or extra UDP buffer
  reservation。Schema-v2 client UDP sniffs only its cached first valid datagram；server UDP retains its
  per-authenticated-datagram policy point。
- Unknown、invalid、timeout and limit MUST record a fixed outcome and continue later rules/final。
  Cancellation and true I/O failure MUST terminate the flow and MUST NOT continue policy。
- When terminal route follows TCP sniff，the entire prefix MUST be written to the original target exactly
  once and in order before relay。No byte may be dropped、duplicated or rewritten。

### M14-MUST-07 — egress selection and no fallback

- Selector state MUST be resolved only when a terminal route action materializes。A switch during sniff
  is visible to that later selection；a switch after terminal selection MUST NOT change the current TCP
  flow、server datagram or schema-v2 client UDP association。
- Client direct/chain/selector actions MUST use one owned `EgressPlanSnapshot` with exact hop order and
  credentials。Server MAY use a validated one-hop scalar identity；multi-hop use of that path MUST be
  rejected by compilation and architecture evidence。
- Open、handshake、authentication、I/O or DNS-detour failure after terminal selection MUST NOT evaluate a
  later rule、route final、sibling selector member、other DNS server or retry。

### M14-MUST-08 — client TCP/UDP behavior

- SOCKS TCP MUST select using only known request context and MUST NOT wait for application payload。
  Route uses the existing `ClientEgressEngine`；reject returns SOCKS5 reply `0x02` through a closed
  policy-denied error kind；other protocol adapters map that kind to a closed generic failure without
  rule/tag disclosure。Hijack returns success then serves multiple framed DNS queries。
- `UDP ASSOCIATE` MUST return the existing success reply containing its one actual relay endpoint before
  reading application data。Its TCP-control lifetime、TCP-peer-IP authority、fixed/first-valid source
  port、fragment policy and bounds MUST remain exact。
- In schema version 2，wrong-source、nonzero `RSV`、`FRAG != 0`、malformed、zero-target or over-limit
  datagrams MUST be silently dropped without route metadata、terminal-mode、selector、plan、session、
  accepted-activity or send mutation。The first source/wire-valid datagram MUST become the association
  classification datagram：its target fills immutable ordinary-route metadata，its payload may be
  borrow-sniffed once，and the complete datagram is cached while the ordered program runs exactly once。
  An unknown/invalid DNS sniff outcome continues to later rules/final and the resulting terminal action
  still fixes the association。
- A terminal `route` MUST resolve one owned `EgressPlanSnapshot` once，lazy-create one private
  `ClientUdpAssociation` and forward the cached classification datagram exactly once。Every later valid
  datagram MUST preserve its own SOCKS target while using the same selected plan/session path；it MUST
  NOT re-enter ordinary rules/final or read selector state。Selected open/encode/send failure terminates
  the association without fallback。
- A terminal `hijack-dns` MUST keep the whole association in the existing DNS answering path and MUST
  create no Shadowsocks plan、socket、session or live ID。Each later valid datagram may run DNS query
  policy and its generated response uses that request's target；malformed/non-DNS data is dropped and
  MUST NOT re-enter ordinary routing。A terminal `reject` MUST silently drop the classification datagram
  and terminate the association without a UDP error。
- `SocksUdpEndpoint` MUST privately own application socket、source binding、SOCKS wire buffers and the
  one unclassified-to-terminal transition。`ClientUdpAssociation` MUST privately own exactly one selected
  Shadowsocks plan/upstream、session IDs、runtime handle and upstream buffers；a plan-keyed multi-leg map、
  public endpoint trait or factory is forbidden。
- Schema-v1 client routed+UDP MUST be rejected as required by M14-MUST-01；static/legacy UDP MUST retain
  its association-setup snapshot。Exact plan/server DNS UDP reuse、all-layer validation-before-mutation、
  capacity、idle/cancel/shutdown and exact rebind behavior MUST remain exact for supported paths。

### M14-MUST-09 — server TCP/UDP behavior

- Server TCP MUST authenticate and parse the SIP022 request before route/sniff metadata or target work。
  It may combine authenticated initial payload with bounded decrypted reads，then route/reject before
  opening direct outbound。
- Reject MUST perform an abortive closed failure without opening a direct socket and MUST NOT reveal
  rule/tag/target data。Route MUST replay the exact prefix before ordinary relay。
- Server UDP MUST prepare/authenticate before sniff and MUST sniff/route before target-side mapping or
  socket reservation。Invalid unauthenticated input MUST NOT mutate route metadata or emit sniff outcome。
- Rejected authenticated UDP MUST commit only replay/source/binding state required to prevent replay and
  MUST forward nothing。Existing prepare/reserve/commit atomicity and generation ownership remain exact。

### M14-MUST-10 — DNS policy and answering

- Existing `DnsProxy::answer` MUST remain the single Hickory parse/select/query/encode implementation；
  dedicated listeners and ordinary hijack adapters MUST call it。No delegating `DnsService` wrapper、
  second framer、second resolver or copied DNS codec is allowed。
- Client DNS policy MUST distinguish dedicated-listener and ordinary-inbound identities without
  collision and match inbound、UDP/TCP query transport、exact qname、label suffix and qtype。
- DNS matcher fields MUST accept scalar or non-empty list with fields AND/list values OR and the same
  per-rule 64-value ceiling。Qname/domain exact and suffix matching use the ordinary ASCII case、
  terminal-dot and label-boundary rules。
- Accepted qtypes are case-insensitive `A AAAA CNAME MX NS PTR SOA SRV TXT CAA SVCB HTTPS ANY` and compile
  to stable closed values；unknown、empty or duplicate values MUST fail。
- Server application-domain resolution policy MUST match inbound、application TCP/UDP、exact/suffix
  domain and port/range but MUST NOT expose qtype。Its selected server performs the existing A then AAAA
  lookup under one deadline。
- Legacy DNS `target = { host, port }` MUST remain exact：client query policy uses the current qname:53
  target and server resolution uses the original application target。It MUST NOT be mixed with new
  qname/domain/port fields。
- DNS policy remains separate from ordinary routing。No match uses `dns.route.final`；selected upstream
  busy/timeout/failure retains existing SERVFAIL/closed behavior and never re-enters ordinary routing or
  selects another server。
- UDP truncation upgrade MUST retain the same DNS server、numeric address and detour plan snapshot；
  direct/detoured UDP/TCP/DoT/DoH validation and shutdown remain M12-exact。

### M14-MUST-11 — security、lifecycle and observability

- Every peer-controlled length/address and parsed name MUST be authenticated/validated before target
  connection、forwarding、accepted mutation or allocation beyond fixed bounds。All failures are per-flow
  fail closed and must leave owners reusable or reaped as specified。
- Existing connection/query/session/task/queue/buffer/live-ID ceilings、absolute deadlines、
  `ProcessRoot`/`ProcessSupervisor` cancellation、grace/force/reap and exact listener/upstream rebind MUST
  remain authoritative。
- New observations are fixed low-cardinality values only：stage `sniff`；outcome
  `matched|unknown|timeout|limit|invalid|unavailable`；protocol `dns|tls|http|none`。
  SNI、Host、qname、destination、rule identity and tags MUST NOT enter errors、Debug/Display、logs、traces
  or metric labels。
- Workspace product code MUST remain unsafe-free and no Tokio worker may block or own a detached task。

### M14-MUST-12 — architecture and exact qualification

- `ferrum2-sniff` MAY depend on core and exact parser packages but MUST NOT depend on config、runtime or
  binaries。Core MUST remain free of parser/config/runtime edges。DNS MUST remain free of config/binary
  edges。Composition owns role mapping and network policy。
- Exact direct workspace dependencies MUST pin `ipnet` to `=2.12.1` and `httparse` to `=1.10.1`
  after T01 license/MSRV/feature review；no other new package/provider identity is allowed without
  contract amendment。
- Architecture evidence MUST reject a second ordinary engine、second DNS/SIP022 implementation、
  concrete protocol in core、dynamic registry、public one-adapter trait、client UDP field reach-through
  and server scalar selection of a multi-hop plan。
- One accepted exact SHA MUST pass all focused gates、repository Full、Rust 1.88 check/build/test、100+
  lifecycle、Windows MSVC、Linux GNU/musl、SIP022 TCP/UDP interop、CoreDNS/BIND、schema 3 footprint and
  bounded Architect/QA review with zero blocking findings。
- The same SHA MUST pass the separately authorized independent performance/resource job covering the v1
  migration rejection、schema-v2 association-routed UDP、legacy no-sniff、64-rule、server TLS/HTTP
  sniff、client TCP/UDP DNS hijack、RSS/owners/drain/rebind。Results are diagnostic；M14 makes no
  performance threshold or improvement claim。
- Push and manual dispatch require separate explicit authorization。No PR、tag、package、release or
  publication is implied。

## Non-goals

- QUIC/HTTP3、TUN/transparent/Fake-IP、process/Geo/rule-set policy、target rewriting、resolver cache or
  automatic upstream policy。
- New public plugin/Endpoint interface、generic parser registry、second harness or opaque protocol fixture。
- SIP022 wire/state-machine replacement、MSRV increase、hot reload、management or release work。
- Automatic schema migration、a second per-datagram client route engine or early retirement of other
  schema-version-1 shapes。

## Implementation freedom

- Exact internal filenames MAY differ when module ownership、public compatibility paths and ticket
  ownership are updated before editing。
- The core protocol/action generic spelling MAY differ from ADR-0033's sketch，provided core stays
  concrete-protocol-free and callers cannot restart or regress the cursor。
- Existing `DnsProxy` MAY gain a framing/helper method for the second ordinary-ingress adapter；it MUST
  not gain route/egress ownership or delegate to a duplicate answering implementation。
- Schema-v2 client UDP MAY use one private concrete enum or equivalent state representation；it MUST NOT
  introduce a public endpoint abstraction or retain a multi-plan routed association for future use。
