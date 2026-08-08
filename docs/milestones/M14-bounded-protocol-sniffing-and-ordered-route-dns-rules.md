# M14 — bounded protocol sniffing and ordered route/DNS rules

- **Status:** executing
- **Qualified M13 product baseline:** `1af1bbf44b37a81c2ae03c562288b2a6e09694b5`
- **Qualified product tree:** `172870c4ca0dffb6c474f2137399d553e827b1e4`
- **Planning baseline:** `cc8a0c2946788c16e5d7af2658a7d80bac0a844b`
- **Planning tree / parent:** `7eccfc66c80263e3d949c5b6aded63b0436540ce` /
  `f4dcebca3c9b56f903496d91048c3660ee60ed52`
- **T01 ticket base:** `5c2c7ab4818cfcddd9b2cd0a45adc5880a74869b` / tree
  `1794b60c6c8b0d3ca65dd5f32cb82f2504ba07cd` / parent `cc8a0c2946788c16e5d7af2658a7d80bac0a844b`
- **Strategy:** drain；all tickets integrate serially
- **Owner:** primary thread
- **MSRV:** Rust `1.88.0`
- **Performance:** required — ordered matching、bounded TCP prefix reads、UDP inspection、DNS hijack and
  UDP owner changes touch transport hot paths and resource/lifecycle ownership

## Outcome

交付一套有界、确定、可继续执行的 ordinary route program：`sniff` 是最多执行一次的
non-terminal action，`route`、`hijack-dns`、`reject` 是 terminal actions。Server 在
SIP022 认证后可识别 DNS、TLS ClientHello 和 HTTP/1 request；client SOCKS UDP 只识别 DNS，
client SOCKS TCP 不做 pre-route sniff。Client TCP/UDP DNS hijack 复用现有 Hickory answering
interface 和 tagged resolver，不创建第二套 DNS parser、resolver 或 Shadowsocks data plane。
`schema_version = 2` 明确承载 breaking client UDP 语义：首个合法 SOCKS UDP 数据报填充
association 路由元数据并只选择一次 terminal action/outbound；后续数据报保留各自 target，
但不重新执行 ordinary route。Schema-v1 client routed+UDP 启动前拒绝，不保留逐包实现。

Planning input is `C:\project\ferrum2-M14-final-plan-v1.0.md`。It is owner-approved design input，not
Git evidence；all baseline、source、dependency and validation claims below were rechecked against the
repository。

## Baseline evidence and source corrections

- `master` was clean at planning baseline `cc8a0c2…`。The diff from qualified product `1af1bbf…` to the
  planning baseline changes only tracked Markdown/status files，not Rust product、tests、manifests or
  lock state。The docs-only M14 planning commit `5c2c7ab…` is T01's ticket base，not the schema-3
  measurement baseline。
- At the planning baseline core had one exact-target `ActionTable`/`RouteTable` in
  `crates/ferrum2-core/src/route.rs`；T02 now delegates legacy `RouteTable` behavior to the single
  protocol-neutral ordered program while retaining `ActionTable` only for the separate DNS namespace。
- SOCKS CONNECT returns an empty `Session.initial_payload` and selects before application bytes exist；
  server TCP already owns authenticated `initial_payload` and an exact prefix-write seam；server UDP
  already exposes the required `prepare -> reserve -> commit` ordering。
- `DnsProxy::answer` already parses、selects、queries and encodes without owning a listener；
  `DnsProxyListeners` is the socket adapter。M14 therefore deepens that existing module instead of adding
  a pass-through `DnsService` wrapper。
- `ClientUdpAssociation` currently exposes SOCKS application socket/buffers and Shadowsocks
  plan/session/upstream state together through `pub(in crate::run)` fields，selects per valid datagram and
  can retain a plan-keyed set of lazy legs。M14 separates the application endpoint，removes that multi-plan
  shape and makes one association own at most one selected plan。
- Pinned sing-box `v1.13.14` source caches the first SOCKS UDP datagram、runs packet-connection routing
  once and preserves later per-packet destinations through the selected outbound。RFC 1928 defines each
  datagram target but does not prescribe internal outbound-selection lifetime；both findings are captured
  in `docs/research/M14-sing-box-socks-forwarding-baseline.md` and
  `docs/research/M14-socks5-udp-semantics.md`。
- Hickory `0.26.1` and rustls `0.23.43` remain exact workspace dependencies。T01's TEST-0015 review
  records locked `ipnet 2.12.1` as a later exact no-default direct edge and no-default
  `httparse 1.10.1` as the only new package identity，with its internal external-package unsafe recorded。
  T01 activates neither dependency；T02 now activates only the reviewed exact no-default `ipnet` edge
  without a new package identity，and T04 activates the reviewed `httparse` edge without changing exact
  Hickory/rustls identities or features。
- Exact planning footprint is code/tests `21814/39632`、ratio `1.816815` and
  case/support/fixture `33883/5152/597`。The current M13 numeric status is
  `REVIEW_REQUIRED` only for moved owner-file size；integrity is `PASS`。
- Repository instructions keep core free of concrete protocols。The route program is therefore generic
  over a caller-owned closed protocol key；config owns operator spellings，the sniff module owns detected
  protocol values，and binary adapters map them exhaustively。DNS/TLS/HTTP types do not enter core。

## Non-goals

- Windows TUN、Linux transparent inbound、Fake-IP、process rules、rule sets or target override。
- QUIC/HTTP3、DoQ/DoH3、DNS cache、DNSSEC、mDNS or a handwritten DNS/TLS/HTTP parser。
- `resolve`、`set-options`、retry、fallback、failover、health、load balancing or upstream groups。
- Dynamic parser/plugin registry、public Endpoint factory、second route engine、second DNS answering
  implementation、second SIP022 path or unsafe code。
- A schema-v1 client routed UDP compatibility engine、automatic config migration or first-target pinning。
- MSRV increase、unrelated crypto/wire rewrite、hot reload、management interface、package、release or
  publication。

## Exit criteria

- [ ] Qualified M13 product and exact planning HEAD/tree/parent remain reproducible；SPEC-0014's
      client-owned/server-one-hop snapshot wording is corrected without changing M13 product evidence。
- [ ] One core-owned ordered program advances a private monotonic cursor，evaluates at most 64 rules and
      preserves legacy exact-target `RouteTable` behavior through the same implementation。
- [ ] Core remains free of DNS/TLS/HTTP/config/runtime types；`ferrum2-sniff` is one deep pure parsing
      module using only exact Hickory、rustls and httparse adapters。
- [ ] Ordinary route supports bounded scalar-or-list inbound/network/protocol/domain/suffix/IP/CIDR/
      port/range/legacy-target matchers with fields AND、list values OR and immutable original target。
- [ ] Config rejects unsupported role/network/action combinations、empty/duplicate/overflow values、
      noncanonical CIDR、unreachable rules and protocol rules without an earlier covering sniff。
- [ ] Schema version 2 accepts the bounded M14 shape；schema-v1 client routed+UDP fails on a redacted
      migration error before side effects，and no per-datagram client route path remains in product。
- [ ] Sniff runs at most once per TCP flow、authenticated server datagram or schema-v2 client association；
      TCP reads use one absolute deadline and bounded lazy prefix，UDP inspects borrowed bytes；timeout/
      limit/unknown/invalid continue while cancellation/I/O failure terminates。
- [ ] Selector resolution occurs only at terminal route；selected plan/order/credentials remain fixed and
      failure never evaluates a later rule、final、sibling or retry。A schema-v2 client UDP selector is
      read once for the association and ignores later switches。
- [ ] Server TCP replays every sniffed prefix byte exactly once；server UDP sniffs/routes before target
      reservation while authenticated replay/binding commit remains atomic。
- [ ] Client TCP never waits for application bytes；reject maps to SOCKS policy-denied；TCP/UDP hijack
      never creates a Shadowsocks flow/session or falls back to ordinary routing。
- [ ] `UDP ASSOCIATE` returns one relay endpoint before payload；invalid source/wire packets cannot classify
      the endpoint；the first valid packet is cached、routes once and is forwarded exactly once。Later
      targets use the fixed route plan，while hijack/reject remain association-terminal。
- [ ] Existing `DnsProxy::answer` is the single reusable DNS answering interface；listener and ordinary
      inbound identities cannot collide；client qname/qtype and server target suffix/port policy preserve
      M12 server/detour/TC/no-fallback semantics。
- [ ] `SocksUdpEndpoint` owns SOCKS wire/source state；`ClientUdpAssociation` owns private lazy
      Shadowsocks upstream/plan/session state for exactly one selected plan，with no plan-keyed map、new
      trait/factory or change to existing ceilings、shutdown and exact response binding。
- [ ] No destination、SNI、Host、qname、rule or tag enters errors、logs、traces or metric labels；new
      telemetry dimensions are fixed enums only。
- [ ] All M0～M13 behavior outside the explicit schema-v1 client routed+UDP migration rejection remains
      green，including CLI、SIP022 wire/crypto/replay、DNS transports、server routing、selector、chain、
      resource and lifecycle evidence。
- [ ] One exact integration SHA passes focused、Full、Rust 1.88、100+ lifecycle、three-platform、
      SIP022/CoreDNS/BIND interop、footprint and bounded Architect/QA review with zero blocking findings。
- [ ] After separate explicit authorization，the same exact SHA passes the extended independent
      performance/resource job；no performance threshold or improvement claim is implied。

## Tickets

| Ticket | Outcome | Depends on | Status |
|---|---|---|---|
| M14-T01 | Freeze contracts、dependency review、M13 wording and M14 footprint control | M13 closed | done |
| M14-T02 | Build the protocol-neutral ordered route program and reusable egress graph | M14-T01 | done |
| M14-T03 | Compile schema v2、migration rejection、matchers/actions and role capabilities | M14-T02 | done |
| M14-T04 | Add the pure bounded DNS/TLS/HTTP sniff module and parser evidence | M14-T03 | done |
| M14-T05 | Compose server TCP/UDP route、sniff、reject and exact prefix replay | M14-T04 | done |
| M14-T06 | Extend DNS policy through the existing answering/resolver module | M14-T05 | done |
| M14-T07 | Compose client route/reject/hijack and one-plan association UDP ownership | M14-T06 | done |
| M14-T08 | Close real-process、security、lifecycle、architecture and qualification-tool evidence | M14-T07 | ready |
| M14-T09 | Qualify and close one exact M14 integration SHA | M14-T08 | todo |

```text
M14-T01 contract/dependency/control
  -> M14-T02 core program/egress graph
  -> M14-T03 config compiler
  -> M14-T04 parser adapters
  -> M14-T05 server vertical slice
  -> M14-T06 DNS policy/answering
  -> M14-T07 client hijack/UDP ownership
  -> M14-T08 integrated evidence/tooling
  -> M14-T09 exact-SHA qualification
```

The graph drains serially。T05～T07 intentionally overlap route metadata、DNS answering、client UDP
ownership and shutdown semantics；they must not be assigned concurrently。Each ticket receives one
writer、branch and worktree from its accepted exact base。

## Test-footprint and remote boundary

T01 resets schema 3 at planning baseline `cc8a0c2…` with code/tests `21814/39632` and
case/support/fixture `33883/5152/597`，unchanged thresholds and `TEST-0015` as `reforecast_ref`。
`TEST-0015` forecasts `2360/560/0` case/support/fixture growth，so milestone numeric
`REVIEW_REQUIRED` is expected and must be dispositioned without deleting independent security、
parser or lifecycle evidence。No new fixture or second harness is planned。

The plan itself authorized no remote action。The 2026-08-09 execute continuation now authorizes all
required remote actions through M14 close，including the exact-SHA non-force push and manual
performance/resource dispatch。The workflow still forbids force-push、unchanged-SHA rerun、PR、tag、
package、release and publication。

## Blocker / next action

No blocker。T07 is accepted at exact integration `1e29a5edbc82bd3ec7fa01aa3723331e6c54fab3`。
The bounded repair closed pre-bound owner mutation and evidence gaps but incorrectly delayed schema-v1
static capacity admission until the first packet。Two required independent `gpt-5.6-sol/xhigh`
read-only analyses both selected one split-phase association：setup owns session/buffers/upstream，while
only plan/live-ID activation remains first-valid-packet lazy。Final targeted Architect/QA both returned
`PASS` with all findings closed。Focused、Rust 1.88 and integration Quick pass；footprint integrity and
ratio pass and the accepted ticket advisory is `+161/0/0` case/support/fixture。T08 is ready on this exact
accepted integration base。
