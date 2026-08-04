# SPEC-0012 — M11 fixed client proxy chains

- **Status:** Approved
- **Milestone:** M11
- **Baseline:** `7a3c876681255b88492b3608af4fa52497435efc`
- **Decision:** `docs/adr/ADR-0030-m11-fixed-client-proxy-chains.md`
- **Test plan:** `docs/test-plans/TEST-0012-m11-fixed-client-proxy-chains.md`

## Scope

Additive schema v1 lets each concrete client Shadowsocks outbound inherit the global method/PSK or
declare its own complete pair，and lets a tagged client define fixed ordered chains of those concrete
outbounds。Static binding、first-match routing and manual selectors may choose a complete direct or
chained plan。TCP and UDP traverse every hop in order with hop-local credentials and no retry/fallback。

## Current baseline

- `ValidatedClientConfig` stores one global `MethodPsk` and endpoint-only
  `ClientOutboundConfig` values (`crates/ferrum2-config/src/lib.rs:42-65`)；
  `validate_client` parses the global credential only after the graph (`:366-395`)。
- `RawClientOutbound` has only `tag/server` and `RawShadowsocks` owns the only method/PSK
  (`crates/ferrum2-config/src/lib.rs:1160-1164,1215-1219`)。
- `RouteTable::select` resolves static/route/selector state to one `usize`
  (`crates/ferrum2-core/src/lib.rs:458-522`)。
- Client composition builds one process-wide key provider and endpoint-only outbound contexts
  (`bins/ferrum2-client/src/run.rs:132-166,313-321,449-469`)。
- TCP opens one `ClientTcpOutbound` after route selection (`bins/ferrum2-client/src/run.rs:471-579`)；
  UDP keeps endpoint-keyed protocol legs and one-method bounds (`:658-844,897-1000,1205-1218`)。
- `ClientTcpOutbound` can connect then write one request，and `UdpClientSession` already owns one
  method-bound request/response association (`crates/ferrum2-shadowsocks/src/lib.rs:544-699`；
  `crates/ferrum2-shadowsocks/src/udp.rs:271-383`)。

## Requirements

### M11-MUST-01 — compatible per-outbound credentials

- Every schema v1 client/server document accepted at the baseline MUST remain accepted without edits
  and retain its normalized values、effective method/PSK、route results、CLI exit and startup behavior
  when `chains` and outbound credential fields are absent。
- Root `[shadowsocks].method/psk` MUST remain mandatory and exact for both roles。A tagged client
  outbound with neither credential field MUST inherit that pair；a tagged client outbound with both
  fields MUST use only its own validated pair for TCP and UDP。
- Exactly one of `outbounds.method` / `outbounds.psk` MUST fail closed before side effects。Unsupported
  method、non-canonical base64 and wrong method/key width MUST use the closed fields defined by
  ADR-0030 and MUST expose no source value or secret。
- Server inbound/outbound shapes MUST remain global-credential/direct-only；method/PSK on a server
  outbound or inbound MUST be rejected as unknown configuration，not ignored。

### M11-MUST-02 — bounded fixed chain graph

- `[[chains]]` MUST be client tagged-only，contain `1..=64` entries when present，and reject legacy、
  server、missing-inbound or missing-outbound mixing before runtime side effects。
- Chain tags MUST share the existing global tag grammar/namespace。Each chain MUST contain `2..=8`
  ordered unique `hops` and every hop MUST exact-resolve to one concrete client outbound。
- A chain hop MUST NOT name an inbound、selector、chain、unknown or case-mismatched tag。Duplicate hop、
  duplicate/colliding chain tag and all count violations MUST return the closed redacted field from
  ADR-0030。
- Every selector and chain MUST be action-reachable；every concrete outbound MUST be reachable directly
  or through a reachable chain，following all selector members。No inert chain、credential or outbound
  may survive validation。

### M11-MUST-03 — one selected immutable plan

- Client static bindings、route rules and route final MUST accept concrete outbound、chain or selector
  tags；client selector members MUST accept concrete outbound、chain or selector tags with their existing
  explicit-default/DAG/control semantics。Server actions remain unchanged。
- One selection call MUST return or resolve one complete immutable ordered plan。A direct outbound is a
  one-hop plan；a chain is its configured concrete hop sequence。Operator tags MUST NOT reach binaries。
- Existing direct-only route constructors/results MUST remain exact。Stock client composition MUST use
  the path-aware result and MUST NOT silently reduce a chain to its first or last hop。
- A selector switch after selection MUST NOT change an open TCP stack、static UDP association、already
  selected routed UDP datagram or in-flight response。A later selection may observe the new complete
  plan。
- Any selected-plan failure MUST NOT change selector state、try another selector member、continue to a
  later route rule or use route final as fallback。

### M11-MUST-04 — ordered TCP composition

- For `[A, B, ..., N]` the client MUST raw-dial only A，request B through A，continue in configured
  order，and request the application target through N。Each request MUST use that hop's effective
  method/PSK and the existing SIP022 request/response-binding state machine。
- Reordering、skipping、duplicating or applying one hop's credential to another hop MUST fail focused
  evidence。At least one two-hop flow MUST use different methods and different PSKs。
- A connect、write、read、authentication、timestamp、binding、nonce or cancellation failure at any
  layer MUST terminate the whole flow as soon as observed。No retry、alternate dial、fallback or partial
  application forwarding is permitted。
- One connection owner MUST own the raw socket and all nested layers；each layer's buffers stay at the
  existing protocol cap and all layers are awaited/dropped/zeroized on terminal exit。

### M11-MUST-05 — ordered UDP composition and response binding

- For `[A, B, ..., N]` one application request MUST be encoded N-to-A，with each outer target equal to
  the next concrete server；only the A packet may be sent to A。The response MUST open A-to-N before its
  final target/payload reaches SOCKS。
- Each layer MUST use the corresponding outbound's effective method/PSK、fresh client session lineage
  and existing response association/replay rules。At least one two-hop exchange MUST use different
  methods and different PSKs。
- Every authenticated intermediate response target MUST exactly match the configured next server。
  Wrong source/target、cross-plan response、wrong credential、outer/inner tamper、replay or binding
  mismatch MUST be dropped/terminated without application forwarding。
- Static UDP MUST snapshot the selected plan at association setup。Routed UDP MUST select once per
  validated application datagram；all per-hop state and its response remain bound to that plan。

### M11-MUST-06 — UDP length and mutation ordering

- Before reservation、session creation、counter mutation or send，the client MUST calculate the exact
  nested request bound for every hop method and target width。A payload that would make any layer exceed
  `MAX_UDP_WIRE_LEN` MUST be rejected；the exact maximum MUST succeed and maximum+1 MUST fail。
- Response handling MUST authenticate and semantically validate every layer，including intermediate
  target and final SOCKS output length，before forwarding or accepted replay/association mutation。
  Invalid inner data MUST NOT poison otherwise-valid outer state；a following valid packet remains
  acceptable。
- Encoding/decoding MUST use a bounded reusable-buffer strategy。It MUST NOT allocate a maximum-size
  wire buffer per hop、trust a peer length for allocation or bypass existing aggregate byte admission。

### M11-MUST-07 — resource and failure closure

- Chain count/hop count and any lazy per-plan TCP/UDP owner、session、socket、task or lookup collection
  MUST have a derivable fixed ceiling。No chain resource is created eagerly for an unselected action。
- Existing global TCP admission、SOCKS UDP association/session count、buffer-byte、idle、shutdown-grace
  and live-ID limits remain authoritative。M11 MUST NOT create an unowned per-hop task or unbounded queue。
- Success、hop-1 failure、later-hop failure、wrong credential、tamper、idle、control close、graceful and
  forced cancellation MUST release every client owner and permit exact listener/socket rebind under the
  existing lifecycle deadline。

### M11-MUST-08 — secrets and low-cardinality observability

- Global and per-outbound PSKs、derived keys、salts、nonces、wire/session IDs and source TOML MUST NOT
  appear in ConfigError、RunError、Debug/Display、panic、stdout/stderr、trace or metrics。
- Chain/hop/outbound/selector tags and endpoints MUST NOT become trace fields or metric labels。No new
  per-hop/per-chain metric family is added；existing closed role/stage/reason/outcome identities remain。
- Errors MUST identify only the closed configuration field or existing low-cardinality runtime reason；
  they MUST NOT reveal which secret failed authentication。

### M11-MUST-09 — preserved seams and excluded behavior

- `ferrum2-crypto` public types/traits、the exact patched `shadowsocks-crypto 0.7.0` backend and SIP022
  wire/state machines MUST remain。M11 MUST compose them rather than add a cipher/KDF/protocol fallback。
- Core MUST remain free of concrete protocol、secret、config and Tokio types；protocol modules MUST NOT
  own route/selector/chain policy or process-global state。No unsafe code、new crate or dependency is
  required。
- M11 MUST NOT add dynamic chain edits、selector-in-hop expansion、health checks、load balancing、retry/
  failover、SIP023、multi-user、server per-inbound credentials、DNS policy、hot reload or management API。

### M11-MUST-10 — exact qualification

- Public config/core tests MUST cover inheritance/override pairing、all bounds/references/reachability、
  static/route/selector chain actions and redaction before side effects。
- Focused client/protocol tests MUST cover mixed-credential two-hop TCP/UDP、outer and inner tamper、
  wrong credentials、exact UDP limit/+1、snapshot/no-fallback、no partial mutation and cleanup。
- Real-process tests MUST prove mixed-method/PSK two-hop TCP and UDP through actual client plus two
  server processes，including later-hop failure and exact resource rebind，without a second harness。
- One accepted exact SHA MUST pass Full、Rust 1.85、100+ lifecycle、three native targets、existing TCP/
  UDP interoperability `12/12` each、schema 3 footprint、blocking Architect/QA review and the separately
  authorized manual performance/resource job。Missing、skipped、wrong-SHA or unauthorized evidence
  MUST block close。

## Non-goals

- Runtime chain membership/order mutation、selector hop、nested chain、graph transaction or connection
  migration/interruption。
- Retry、fallback/failover、health probe、automatic choice、load balancing or upstream group policy。
- SIP023、多用户、server per-inbound/outbound credentials、quota or external identity lookup。
- DNS/Geo/sniff/user/CIDR/domain-pattern policy、new endpoint kind、transparent/TUN、hot reload、
  management API、package、release or publication。

## Implementation freedom

- Core/config may use bounded plan indexes、borrowed slices or a small newtype as long as direct-only
  results remain exact and the stock client cannot consume a chain as one hop。
- Client may choose bounded authenticated UDP response dispatch or lazy per-plan sockets as long as
  cross-plan acceptance is impossible and the accepted resource/cleanup ceiling is tested。
- TCP nesting may use a recursive enum or one necessary erased transport owner；it must not expose raw
  keys、duplicate the state machine or create one relay task per hop。
- Tests may extend existing tables/helpers。A third equivalent config/process harness or copied SIP022
  encoder is not allowed without explicit Architect/QA `REVIEW_REQUIRED` disposition。
