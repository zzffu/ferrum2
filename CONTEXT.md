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
A named egress identity returned by static binding or route selection.
_Avoid_: Route, upstream group, endpoint

**Static outbound binding**:
The M7-compatible configuration relation used when no route table exists; one inbound
always selects one outbound and cannot vary by flow or datagram.
_Avoid_: Routing rule, fallback, load balancing

**Route rule**:
One ordered conjunction of optional inbound, network, and exact-target matchers whose
action is one outbound; the first matching rule decides the request.
_Avoid_: Fallback, load-balancing policy, static outbound binding

**Final outbound**:
The mandatory route-mode outbound selected when no route rule matches.
_Avoid_: Failure fallback, default retry

**Route network**:
The `tcp` or `udp` traffic class evaluated by a route rule; UDP means each validated
datagram, not its SOCKS TCP control connection.
_Avoid_: Protocol implementation, transport adapter

**Exact route target**:
The validated pre-resolution host and non-zero port matched by a route rule; it is not a
DNS answer, sniffed name, CIDR, or domain pattern.
_Avoid_: Destination label, resolved target
