# ferrum2

This context names the contracts used to distinguish ferrum2 product guarantees
from the evidence and mechanics used to prove them.

## Language

**Normative invariant**:
A product, wire, security, API, platform, or release outcome that must remain true
regardless of implementation or test mechanism.
_Avoid_: Test requirement, implementation detail

**Selected conformance profile**:
The currently approved, reproducible combination of tests, probes, dependency
edges, and evidence used to prove one or more normative invariants.
_Avoid_: Immutable architecture, sole possible proof

**Equivalent evidence substitution**:
A reviewed replacement for part of a selected conformance profile that proves the
same claims and failure modes without weakening any normative invariant.
_Avoid_: Waiver, skip, test relaxation

**Mechanical realization**:
The non-normative spelling or platform plumbing of an approved conformance profile,
such as line-ending handling, exact test selection, or linker discovery.
_Avoid_: Product contract, architectural decision

**v0 preview**:
The first externally evaluable v0 artifact. Protocol correctness, security, resource
stability, interoperability, and platform qualification remain blocking, but no
minimum throughput ratio or production-readiness claim is implied.
_Avoid_: Production release, performance-certified release

**Performance baseline**:
A reproducible ferrum2/reference measurement and comparison ratio recorded for
diagnosis and later optimization; its value does not block the v0 preview.
_Avoid_: Performance gate, performance guarantee

**Bounded 10k-idle qualification**:
The single M4 preview resource gate for owner, task, and RSS stability while 10,000
TCP sessions remain established on the pinned performance host.
_Avoid_: Long soak, all-platform soak, open-ended soak

**SOCKS UDP association**:
The public client-side UDP relay lifetime established by one SOCKS5 `UDP ASSOCIATE`
control connection.
_Avoid_: SIP022 UDP session, route

**Association-routed UDP**:
The schema-v2 client mode where the first valid SOCKS UDP request fixes one
terminal action and, for `route`, one outbound while later requests retain their own targets.
_Avoid_: First-target pinning, per-datagram client route

**Client UDP endpoint**:
The application-side source address authorized to send datagrams for one SOCKS UDP
association.
_Avoid_: Target, destination, Shadowsocks server

**SIP022 UDP client session**:
A Shadowsocks wire identity for one selected server endpoint, with its outbound
packet lineage and inbound response association/replay state.
_Avoid_: SOCKS UDP association, public UDP listener

**Configuration tag**:
An operator-chosen name that uniquely identifies one configured inbound or outbound
inside a process configuration.
_Avoid_: AEAD tag, metric label, endpoint

**Inbound**:
A named traffic-entry identity supplied to static binding or route selection.
_Avoid_: Listener, route, endpoint

**Outbound**:
A named egress action accepted by static binding or route selection. It resolves to one immutable
direct or chained egress plan before network work.
_Avoid_: Route, upstream group, endpoint, retry candidate

**Concrete Shadowsocks outbound**:
A tagged client `[[outbounds]]` entry with one server endpoint and one effective method/PSK pair. The
pair is either declared together on that outbound or inherited together from global `[shadowsocks]`.
_Avoid_: Chain, selector, server direct outbound, multi-user identity

**Egress plan**:
The owned, immutable ordered concrete-outbound snapshot returned by one client selection call. A direct
action has one hop; a proxy chain has two or more，and later selector switches never change that snapshot.
_Avoid_: Route, selector current state, retry sequence

**Fixed proxy chain**:
A tagged client egress plan containing `2..=8` ordered, unique concrete Shadowsocks outbound hops. Its
membership and order never change at runtime.
_Avoid_: Upstream group, selector, dynamic chain, fallback list

**Chain hop**:
One concrete Shadowsocks outbound at one fixed position in a proxy chain, including that outbound's
effective endpoint and credential.
_Avoid_: Selector member, retry candidate, server inbound

**Outbound selector**:
A tagged logical outbound with a fixed non-empty member set and one manually chosen current
member. It never chooses, retries, checks, or balances members on its own.
_Avoid_: Upstream group, load balancer, failover policy

**Selector member**:
One immediate concrete-outbound、fixed-chain or outbound-selector tag admitted by an outbound selector.
_Avoid_: Fallback, candidate retry, resolved leaf

**Default selector member**:
The explicit selector member that becomes current whenever a validated process graph is created.
_Avoid_: Route final, automatic choice, persisted choice

**Current selector member**:
The selector's atomically replaceable immediate member; a nested selector remains the current
member even when it ultimately resolves to a concrete outbound.
_Avoid_: Healthiest member, fastest member, concrete leaf

**Multi-upstream capability**:
A client process with multiple concrete Shadowsocks-server outbounds that static binding
or routing can select independently; selection never implies automatic retry.
_Avoid_: Upstream group, load balancing, failover

**Upstream group**:
A logical candidate set whose policy automatically chooses, balances, checks, retries, or
fails over among member upstreams; ferrum2 does not currently provide this policy identity.
_Avoid_: Multiple tagged outbounds, multi-upstream capability, outbound selector

**Static outbound binding**:
The M7-compatible configuration relation used when no route table exists; one inbound
always selects one outbound and cannot vary by flow or datagram.
_Avoid_: Routing rule, fallback, load balancing

**Route rule**:
One ordered conjunction of matchers whose action is non-terminal `sniff` or terminal
`route`、`hijack-dns`、`reject`. A matching sniff resumes after that rule; the first
matching terminal action decides the request.
_Avoid_: Fallback, load-balancing policy, static outbound binding

**Final outbound**:
The mandatory route-mode outbound selected when ordered evaluation exhausts without a
terminal action.
_Avoid_: Failure fallback, default retry

**Route network**:
The `tcp` or `udp` traffic class evaluated by a route rule. Its evaluation unit is fixed
by the ingress contract: a flow, a server datagram, or one association-routed UDP lifetime.
_Avoid_: Protocol implementation, transport adapter

**Exact route target**:
The validated pre-resolution host and non-zero port matched by a route rule; it is not a
DNS answer, sniffed name, CIDR, or domain pattern.
_Avoid_: Destination label, resolved target

**DNS server**:
A tagged upstream DNS service with one numeric bootstrap address and one fixed UDP, TCP, DoT, or DoH
transport. A DNS action selects the server independently from the optional egress plan used to reach
it，and it is never a retry group.
_Avoid_: Outbound, upstream group, system resolver

**DNS action**:
The result of DNS first-match selection naming exactly one DNS server. Failure of that server does not
evaluate another rule, the DNS final action, or another server tag.
_Avoid_: Outbound action, fallback list, retry policy

**DNS detour**:
An optional DNS-server reference to one existing egress action whose immutable plan carries traffic to
that server's bootstrap address. Absence means direct egress；it never selects another DNS server.
_Avoid_: DNS action, DNS server tag, fallback, ordinary route

**DNS bootstrap address**:
The operator-validated numeric socket used as a DNS server's direct or detoured target. A DoT/DoH
server name is an authenticated TLS/HTTP identity and is never resolved through ferrum2.
_Avoid_: Search domain, fallback resolver, DNS answer

**DNS proxy inbound**:
A tagged client listener exposing DNS queries on both UDP and TCP at one socket address. Its tag and
received transport participate in DNS action selection.
_Avoid_: SOCKS inbound, authoritative zone, DNS server
