# M14 sing-box SOCKS TCP/UDP 转发基线

- **Status:** Planning research baseline
- **Date:** 2026-08-08
- **Milestone:** M14
- **Ferrum2 planning baseline:** `cc8a0c2946788c16e5d7af2658a7d80bac0a844b`

## 结论

sing-box `v1.13.14` 的 SOCKS inbound 只有一个 TCP listener，但在 SOCKS 请求后分成两条
数据面：`CONNECT` 把一个 lazy TCP stream 交给统一 router；`UDP ASSOCIATE` 为每条控制连接
绑定一个临时 UDP socket，先读一个 SOCKS UDP datagram，再把整个 packet connection 交给同一
router。两条路径共享 inbound/user/source/destination metadata、顺序 rule engine 和 outbound
dispatcher，但路由粒度、成功回复时机、目标稳定性和生命周期明显不同。

两个需要直接约束 M14 的观察是：

1. **TCP route-time sniff 会先发 SOCKS success。** `CONNECT` 使用 `LazyConn`；sniff 的第一次
   payload read 会触发 `LazyConn.Read` 先写成功回复。若后续规则 reject 或 outbound open 失败，
   只能关闭已经成功的 stream，不能再回复 M14 计划的 `REP=0x02`。
2. **[源码推断] 普通 SOCKS UDP 是首包为 association 选一次 outbound，而不是逐包重选。**
   首包 target 写入 route metadata，`routePacketConnection` 只执行一次 rule/outbound selection；
   之后同一 copy loop 仍逐包保留各自 SOCKS target header，并通过已选 packet outbound 转发。
   因而“outbound 固定”与“逐包 destination 可变”同时成立。

M14 复用 sing-box 的“non-final sniff 后继续、terminal action 停止、缓存前缀再转发、DNS
hijack 进入独立 DNS policy”和 association 级 UDP outbound selection；不复制 client TCP
pre-route sniff、target override/resolve 或其较宽松的 SOCKS UDP source/header/lifetime 行为。

## 固定来源身份

| Source | Exact identity | Usage |
|---|---|---|
| sing-box | [`v1.13.14` / `25a600db24f7680ad9806ce5427bd0ab8afe1114`](https://github.com/SagerNet/sing-box/tree/25a600db24f7680ad9806ce5427bd0ab8afe1114) | inbound adapter、route engine、dispatch、sniff、DNS hijack |
| Official docs | [SOCKS](https://sing-box.sagernet.org/configuration/inbound/socks/)、[Listen Fields](https://sing-box.sagernet.org/configuration/shared/listen/)、[Rule Action](https://sing-box.sagernet.org/configuration/route/rule_action/)、[Protocol Sniff](https://sing-box.sagernet.org/configuration/route/sniff/) | Operator-facing behavior；exact text is pinned by the matching [`v1.13.14` docs tree](https://github.com/SagerNet/sing-box/tree/25a600db24f7680ad9806ce5427bd0ab8afe1114/docs/configuration) |
| `sagernet/sing` | [`v0.8.11` / `c7c09c5f3f58410965b0a97cbc82d4d4e8323b9b`](https://github.com/SagerNet/sing/tree/c7c09c5f3f58410965b0a97cbc82d4d4e8323b9b) | Exact first-party SOCKS codec/handler dependency pinned by sing-box [`go.mod`](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/go.mod#L36) |

Live documentation can move; implementation conclusions below use only the two exact commits.

## Shared ingress and metadata handoff

The SOCKS inbound configures only `NetworkTCP`; the generic listener accepts a TCP connection and seeds
`Source` from the peer plus `OriginDestination` from the local socket. `NewConnectionEx` delegates SOCKS
version/auth/request parsing to the pinned `sing` handler, then its two callbacks set inbound tag/type and
optional authenticated user before calling `RouteConnectionEx` or `RoutePacketConnectionEx`.
Sources: [`protocol/socks/inbound.go`](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/protocol/socks/inbound.go#L38-L118),
[`common/listener/listener_tcp.go`](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/common/listener/listener_tcp.go#L85-L110),
[`adapter/upstream.go`](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/adapter/upstream.go#L36-L55).

After method negotiation and optional username/password auth, the exact handler parses one request and
branches on command:

| Area | TCP `CONNECT` | UDP `ASSOCIATE` |
|---|---|---|
| SOCKS request target | Passed directly as route destination | Parsed but not used as the datagram target or source authority |
| Data-plane object | Accepted TCP wrapped in `LazyConn` | New ephemeral UDP socket wrapped as `AssociatePacketConn` |
| Metadata destination | Request destination | Destination decoded from the first UDP datagram |
| Initial SOCKS reply | Deferred by `LazyConn` | Success with actual UDP bind address before first datagram/route selection |

The branch is explicit in [`HandleConnectionEx`](https://github.com/SagerNet/sing/blob/c7c09c5f3f58410965b0a97cbc82d4d4e8323b9b/protocol/socks/handshake.go#L126-L284).
The request codec reads the reserved byte without validating it, and the UDP wrapper skips all first three
bytes (`RSV[2] + FRAG`) without validation; these are implementation observations, not behavior for M14 to
adopt. Sources: [`socks5.ReadRequest`](https://github.com/SagerNet/sing/blob/c7c09c5f3f58410965b0a97cbc82d4d4e8323b9b/protocol/socks/socks5/protocol.go#L221-L244),
[`AssociatePacketConn`](https://github.com/SagerNet/sing/blob/c7c09c5f3f58410965b0a97cbc82d4d4e8323b9b/protocol/socks/packet.go#L39-L100).

## Ordered route selection and outbound dispatch

Both route entry points set `metadata.Network`, call `matchRule` once, look up the terminal route's outbound
tag (or the default), check TCP/UDP support, restore any sniffed buffers, then dispatch either to an
outbound-specific handler or the shared connection manager. Sources:
[`routeConnection`](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/route/route.go#L60-L160),
[`routePacketConnection`](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/route/route.go#L195-L289).

`matchRule` scans configured rules in order. `sniff` and `resolve` mutate metadata and continue from the
following rule; `route`, `reject` and `hijack-dns` select and stop. Route options may also override target
address/port. This is close to M14's ordered cursor shape, but sing-box has more non-final mutations and
does not enforce M14's immutable original target. Source:
[`matchRule`](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/route/route.go#L403-L562),
[official Rule Action docs](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/docs/configuration/route/rule_action.md#L19-L311).

For ordinary dialer outbounds, the shared manager behaves as follows:

- TCP dials the selected outbound to metadata destination, reports handshake success, then starts two
  stream-copy directions. Cached sniff bytes are written before ordinary upload.
- UDP opens one packet connection through the selected outbound (or one connected UDP flow when
  `udp_connect` is set), then starts two packet-copy directions.

Sources: [`ConnectionManager.NewConnection`](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/route/conn.go#L94-L143),
[`ConnectionManager.NewPacketConnection`](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/route/conn.go#L144-L259),
[`connectionCopy` / `packetConnectionCopy`](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/route/conn.go#L261-L382).

### Verified nuance: TCP sniff commits SOCKS success before policy completes

Without sniff, outbound dial occurs before `ReportConnHandshakeSuccess`, so dial failure can still invoke
the lazy SOCKS failure response. With route-time sniff, the sequence changes:

1. `CONNECT` hands the router a `LazyConn` with no response written.
2. `actionSniff` calls `PeekStream`, whose first operation reads from that connection.
3. `LazyConn.Read` first calls `ConnHandshakeSuccess`, writes SOCKS success, then reads application bytes.
4. A later reject/open error reaches `CloseOnHandshakeFailure`; `LazyConn.HandshakeFailure` refuses to
   write another reply once `responseWritten` is true, so the path closes the stream.

Sources: [`actionSniff`](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/route/route.go#L564-L629),
[`PeekStream`](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/common/sniff/sniff.go#L41-L75),
[`LazyConn`](https://github.com/SagerNet/sing/blob/c7c09c5f3f58410965b0a97cbc82d4d4e8323b9b/protocol/socks/lazy.go#L14-L88),
[`CloseOnHandshakeFailure`](https://github.com/SagerNet/sing/blob/c7c09c5f3f58410965b0a97cbc82d4d4e8323b9b/common/network/handshake.go#L36-L79).

Therefore a reject after sniff cannot return any new SOCKS status, specifically not M14's planned policy
denial `0x02`. M14's “client TCP selects from request fields only and never waits for payload” is not a
missing feature relative to this reference; it preserves a stronger and simpler reply contract.

### Source-derived inference: UDP route once, targets remain per-packet

This behavior is not stated in the official docs, so it is recorded as an inference from the exact call
chain:

1. `UDP ASSOCIATE` reads exactly one packet, obtains its destination, caches that packet and invokes the
   packet handler once.
2. The inbound callback invokes `RoutePacketConnectionEx` once; `routePacketConnection` runs one
   `matchRule` and resolves one `selectedOutbound` before starting the relay.
3. The packet copy loop repeatedly reads `(buffer, destinationAddress)` and writes that same destination
   through the already-created packet writer. Thus later SOCKS datagrams can name different targets, but
   do not re-enter the ordinary route program.

Sources: [`UDP ASSOCIATE` first-packet handoff](https://github.com/SagerNet/sing/blob/c7c09c5f3f58410965b0a97cbc82d4d4e8323b9b/protocol/socks/handshake.go#L230-L269),
[`SOCKS packet callback`](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/protocol/socks/inbound.go#L99-L118),
[`routePacketConnection`](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/route/route.go#L195-L289),
[`CopyPacketWithPool`](https://github.com/SagerNet/sing/blob/c7c09c5f3f58410965b0a97cbc82d4d4e8323b9b/common/bufio/copy.go#L260-L364).

For a Shadowsocks outbound, the selected object's `ListenPacket` creates one connected UDP transport to
the configured Shadowsocks server and returns a packet codec that still accepts per-packet destinations.
That is concrete confirmation of the same association-level upstream shape for ferrum2's relevant
interop path. Source: [`protocol/shadowsocks/outbound.go`](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/protocol/shadowsocks/outbound.go#L108-L121),
[`shadowsocksDialer.ListenPacket`](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/protocol/shadowsocks/outbound.go#L169-L177).

M14 deliberately aligns with this granularity under schema version 2：the first valid SOCKS datagram
fixes the association's terminal ordinary-route action，and `route` resolves one Shadowsocks plan once。
The M14 product does not retain ferrum2's former per-datagram routed-client implementation。A schema-v1
client configuration that combines routed mode with enabled UDP is rejected before runtime and must be
explicitly migrated；later datagrams still keep their own SOCKS destinations。

## UDP association lifecycle

The handler binds a UDP socket on the accepted TCP connection's local address with port zero, sends the
actual bind endpoint, waits for the first packet under inbound `udp_timeout`, then wraps the packet
connection in an idle canceler and replays the cached first packet into routing. The documented default
is five minutes; route options/protocol detection may shorten it, but a larger route timeout cannot exceed
the inbound timeout. Sources: [`HandleConnectionEx`](https://github.com/SagerNet/sing/blob/c7c09c5f3f58410965b0a97cbc82d4d4e8323b9b/protocol/socks/handshake.go#L230-L269),
[`canceler.NewPacketConn`](https://github.com/SagerNet/sing/blob/c7c09c5f3f58410965b0a97cbc82d4d4e8323b9b/common/canceler/packet.go#L24-L75),
[`Listen Fields / udp_timeout`](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/docs/configuration/shared/listen.md#L134-L142),
[`route-options / udp_timeout`](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/docs/configuration/route/rule_action.md#L188-L212).

Closing `AssociatePacketConn` closes both UDP and the held TCP control connection. **[源码推断]** The
reverse direction is not immediate: after the success reply, this path does not read the TCP control
stream again, so remote TCP EOF is not actively observed; cleanup is instead reached through UDP
idle/error/context/relay closure. Also, the request hint is not used to authorize the UDP sender, and the
server packet wrapper replies to the most recently read UDP source. Sources:
[`AssociatePacketConn.Close`](https://github.com/SagerNet/sing/blob/c7c09c5f3f58410965b0a97cbc82d4d4e8323b9b/protocol/socks/packet.go#L119-L128),
[`serverPacketConn`](https://github.com/SagerNet/sing/blob/c7c09c5f3f58410965b0a97cbc82d4d4e8323b9b/common/bufio/bind.go#L114-L163).

The upstream sing-box test proves UDP echo followed by idle expiry, but does not prove request-hint/source
isolation, reserved/fragment rejection, mixed-target routing or TCP-EOF causality. Source:
[`TestSOCKSUDPTimeout`](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/test/socks_test.go#L22-L128).

## DNS and sniff interaction

`sniff` is a non-final rule action. TCP defaults include TLS, HTTP and framed DNS; UDP defaults include
DNS, QUIC and other packet protocols. TCP uses one absolute deadline and caches every consumed prefix for
later dispatch. UDP consumes/caches packet(s), with additional reads used for fragmented QUIC detection.
Sources: [`actionSniff`](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/route/route.go#L564-L760),
[`PeekStream` / `PeekPacket`](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/common/sniff/sniff.go#L41-L87),
[official protocol matrix](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/docs/configuration/route/sniff.md#L10-L29).

The sing-box DNS sniffer sets `Protocol=dns` but does not extract qname into ordinary route metadata.
When terminal `hijack-dns` runs, TCP serves repeated framed queries and UDP sends each response using that
packet's original destination value; the DNS router then derives qname/qtype and independently selects a
DNS rule/transport. Sources: [`common/sniff/dns.go`](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/common/sniff/dns.go#L17-L57),
[`route/dns.go`](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/route/dns.go#L23-L108),
[`DNS Router.Exchange`](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/dns/router.go#L210-L325).

**[源码推断]** Because SOCKS UDP chooses `hijack-dns` once for the packet connection, all later packets
in that association stay in the DNS handler; malformed later data closes that DNS packet connection
rather than returning to ordinary routing. Source:
[`NewDNSPacketConnection`](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/protocol/dns/handle.go#L65-L169).

## TCP/UDP comparison for M14

| Dimension | sing-box SOCKS TCP | sing-box SOCKS UDP | Ferrum2 M14 consequence |
|---|---|---|---|
| Route unit | One stream/request | **[inferred]** one association, keyed initially by first datagram | Keep TCP per-flow；schema-v2 client UDP selects once per association |
| Destination | Fixed request destination; may later be overridden/resolved | First target seeds rules; later packet targets remain variable | Preserve immutable original target; do not import override/resolve |
| Success timing | Normal route: after outbound open; sniff/hijack read: before payload processing | Before first packet and before outbound selection | Client TCP must not sniff; pre-success reject can map exactly to `0x02` |
| Sniff | Can wait for TCP payload and replay cached prefix | Inspects cached datagrams and may read more for QUIC | Client capability stays TCP=no sniff, UDP=borrowed DNS only; server owns bounded TCP prefix |
| Terminal DNS | Entire stream becomes multi-query DNS service | **[inferred]** entire association becomes DNS packet service | Make hijack association-terminal and reuse `DnsProxy::answer` |
| Relay | One dialed stream, bidirectional byte copy | One selected packet outbound, per-packet destination copy | Lazy-create exactly one selected Shadowsocks UDP plan and replay the cached first packet once |
| Lifetime | Stream copy/half-close/error | UDP idle/error/context; association close also closes TCP | Retain ferrum2 TCP-control causality, source pin, bounds and awaited ownership |

## M14 decision boundary

- **Reuse the shape:** ordered monotonic scanning; non-terminal metadata enrichment; terminal
  route/reject/hijack; cached TCP prefix replay; first-datagram association routing; separate DNS rule
  selection after hijack.
- **Keep ferrum2's narrower client contract:** no client TCP payload wait; exact policy-denied reply before
  success; strict first-valid source/wire classification; hijack-only traffic must not instantiate
  upstream state; TCP control EOF remains authoritative.
- **Do not copy reference shortcuts:** ignored request/UDP reserved fields, absent FRAG validation, last-sender
  reply behavior, inactive TCP-EOF observation, target replacement or general resolve action.
- **Retain M14 bounds:** one at-most-once sniff budget, explicit byte/deadline ceilings, borrowed UDP
  inspection, immutable classification target、variable later packet destinations and no fallback after
  any terminal selection.

These conclusions support the association-level amendment in
[`SPEC-0015`](../specs/SPEC-0015-m14-bounded-protocol-sniffing-and-ordered-route-dns-rules.md)。
