# SPEC-0017 — M16 Windows managed TUN routing, DNS and direct egress

- **Status:** Draft
- **Milestone:** M16
- **Baseline:** `fcef80dcc7e62bbca63ffbf7832df369dd418abd`
- **Related:** ADR-0034、ADR-0035、ADR-0036、TEST-0017

## Outcome

On Windows 10 build 19041+ and Windows 11 AMD64，an opt-in schema-v2 TUN client can transactionally capture
configured prefixes，steer the Windows resolver through its Wintun interface，and send each selected TUN
TCP flow or UDP mapping either through its existing Shadowsocks plan or through a new client direct
outbound。Every physical client socket is pinned before network use so product-owned capture cannot recurse。

The words MUST、MUST NOT、SHOULD and MAY are normative。

## Illustrative configuration

```toml
schema_version = 2

[tun]
tag = "tun-in"
adapter_name = "Ferrum2"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00:46:6572:7275::2/126"
mtu = 1420
auto_route = true
route_address = ["0.0.0.0/0", "::/0"]
route_exclude_address = ["10.0.0.0/8", "fc00::/7"]
auto_dns = true
ipv4_dns_address = "198.18.0.1"
ipv6_dns_address = "fd00:46:6572:7275::1"

[[outbounds]]
tag = "proxy"
server = "192.0.2.10:8388"

[[outbounds]]
tag = "direct"
type = "direct"

[route]
final = "proxy"

[[route.rules]]
network = "tcp"
target = { host = "192.0.2.80", port = 443 }
outbound = "direct"

[dns]
final = "system-upstream"

[[dns.servers]]
tag = "system-upstream"
address = "192.0.2.53:53"
transport = "udp"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw==" # documentation-only test key
```

The route example is exact-target syntax，not an internet recommendation。A prefix in
`route_exclude_address` never enters TUN；a route selecting `direct` has already entered TUN and then leaves
through the frozen physical default interface。These are different policies。

## Requirements

### M16-MUST-01 — compatibility and platform boundary

- Every M15-accepted document that omits all M16 fields MUST preserve normalized config、`--check-config`、
  route/sniff/DNS action、wire、resource and lifecycle behavior。`auto_route` and `auto_dns` default to false。
- Client direct outbound is additive schema-v2 behavior and MUST work through the shared SOCKS/TUN/DNS
  client egress on every existing build target。Managed route/DNS mutation MUST run only for Windows NT
  10.0 build 19041+ AMD64；unsupported runtime targets fail before public service and without OS mutation。
- `--check-config` MUST perform no DLL load、adapter access、route/interface/DNS query or mutation、socket
  creation、thread spawn or privilege check。
- M16 MUST keep exact Rust `1.97.1` and existing dependency identities unless a ticket records an explicit
  disposition。No new crate or package identity is planned；locked `ipnet` and `windows-sys` plus the existing
  `ferrum2-wintun` boundary are reused。

### M16-MUST-02 — closed direct outbound configuration

- Client `[[outbounds]].type` MUST be absent、`"shadowsocks"` or `"direct"`。Absence means Shadowsocks and
  preserves all existing documents。The field remains unknown for server outbounds。
- Direct MUST require `tag` and MUST reject `server`、`method` and `psk`。Shadowsocks MUST require `server`
  and retain the existing credential both-or-neither/inheritance rules。No sentinel or partially populated
  validated outbound may exist。
- A direct-only tagged client MAY omit `[shadowsocks]`。A legacy client or any client graph containing a
  Shadowsocks outbound MUST retain the M11 global credential requirement。
- Static inbound binding、route rule、route final、selector member and DNS detour MAY resolve to direct。
  A direct outbound MUST NOT appear in any fixed chain hop。Empty、mixed or multi-hop-direct plans MUST fail
  validation or the defensive runtime boundary before socket creation。
- Direct tags use the existing count、length、uniqueness、reachability and namespace rules；the spelling
  `direct` is not reserved and multiple direct entries are not given distinct runtime behavior。

### M16-MUST-03 — immutable selection and direct TCP

- One terminal selection MUST produce the existing owned egress snapshot。A direct plan contains exactly one
  direct identity；a proxy plan retains exact M11 hop order and credentials。Later selector switches MUST NOT
  change an active flow。
- TUN direct TCP MUST connect the immutable original numeric target。SOCKS direct TCP domain targets MUST use
  the existing bounded system resolver、candidate ceiling and one absolute deadline。Sniffed metadata MUST
  never replace or resolve the target。
- Auto-route MUST NOT silently replace SOCKS domain resolution with the optional Ferrum DNS graph。With
  auto-DNS，Windows resolver traffic may reach the synthetic `DnsProxy` path。Without auto-DNS，captured
  resolver packets are ordinary numeric TUN traffic subject to configured route/direct/proxy/reject policy；
  terminal physical sockets remain pinned，and failure terminates the original lookup without fallback。
- Direct TCP MUST carry raw application bytes and half-close through the existing relay lifecycle，and MUST
  create no SIP022 flow、cipher、nonce、salt or server connection。Selected resolution/connect/I/O failure
  MUST end the flow without selector、rule、final or proxy fallback。
- SOCKS and TUN callers MUST use the same client egress dispatch and MUST NOT inspect outbound kind or create
  a raw physical socket themselves。
- A Windows graph containing TUN plus a reachable direct outbound MUST freeze/publish its physical-default
  binder before TUN Ready even when auto-route is false。An external manual-route controller MUST add capture
  only after Ready。SOCKS-only and non-Windows direct retain normal system routing。

### M16-MUST-04 — immutable selection and direct UDP

- One TUN five-tuple or schema-v2 SOCKS association selection MUST retain its existing plan lifetime。A direct
  UDP mapping sends and receives raw payloads for the original target and creates no SIP022 packet/session/
  replay state。It MUST retain existing byte、session、queue、idle、generation and cancellation ceilings。
- Numeric targets MUST not invoke a resolver。SOCKS domain targets MUST use the existing bounded system UDP
  resolver with the same auto-route/auto-DNS treatment as TCP；a resolution or send failure MUST not try
  another outbound。Only responses admitted by the direct socket/mapping owner may reach TUN or SOCKS。
- Direct payload admission MUST use raw transport limits rather than subtracting Shadowsocks overhead。The
  existing first-classification-eligible-datagram commit、over-limit-no-state and expiry/reselection rules
  remain unchanged。

### M16-MUST-05 — managed TUN configuration

- `[tun].auto_route` MUST be boolean default false。When true，`route_address` is an optional non-empty list
  of at most 64 canonical IPv4/IPv6 prefixes，defaulting to both `/0` prefixes；
  `route_exclude_address` is an optional list of at most 64 canonical prefixes，default empty。Either list
  MUST be rejected when auto-route is false。
- `[tun].auto_dns` MUST be boolean default false and MUST require `auto_route = true` plus an existing client
  `[dns]` graph。When true，`ipv4_dns_address` and `ipv6_dns_address` are both required；otherwise they are
  forbidden。Each MUST be a usable unicast address inside the corresponding TUN prefix，distinct from the
  local interface address and from each other。
- M16 fields MUST be rejected for schema v1、server configuration、missing TUN or unsupported address
  families。All prefix/address/count/result bounds and cross-field constraints MUST validate before runtime
  side effects。

### M16-MUST-06 — bounded capture-prefix compilation

- The compiler MUST compute canonical disjoint `route_address − route_exclude_address` by address family。
  Overlapping input may collapse，but output MUST be independent of input order。An exclusion outside all
  includes has no effect。
- Every remaining `/0` MUST split into its two canonical `/1` children；the product MUST create no `/0`
  capture row。The final combined row count MUST be `1..=256` or validation fails。
- The compiler MUST create no physical bypass/exclude row and MUST not enumerate third-party routes as owned。
  Existing more-specific routes remain untouched and win by longest prefix；an exact owned-key conflict
  fails before the first create rather than being modified or adopted。

### M16-MUST-07 — physical underlay snapshot and socket pinning

- Before any capture row exists，the product MUST identify eligible up、non-loopback、non-Wintun physical
  interfaces and route state。For each numeric fixed Shadowsocks first-hop and each DNS bootstrap reached by
  absent/direct detour，it MUST call `GetBestInterfaceEx(destination)`，validate/convert the interface identity，
  then call interface-constrained `GetBestRoute2` and freeze its route/source fingerprint。For a proxy-detoured
  DNS server，the physical endpoint is the selected plan's first concrete Shadowsocks server；the logical DNS
  bootstrap MUST NOT be pinned as a separate physical endpoint。
- Dynamic direct targets MUST bind to one unambiguous capture-before physical default interface per family。
  Missing or ambiguous policy MUST fail prepare before capture。This policy does not preserve target-specific
  non-default LAN/VPN routing；operators MUST exclude those prefixes when that fidelity is required。
- IPv4 sockets MUST set `IP_UNICAST_IF` with the required network-byte-order index；IPv6 sockets MUST set
  `IPV6_UNICAST_IF` with the required host-byte-order index。The setting MUST precede TCP connect or UDP first
  send。Failure MUST close the socket and MUST NOT retry unpinned。
- Every TUN-capable Windows direct socket MUST cross this binding boundary regardless of capture ownership。
  While auto-route is active，every proxy and actual DNS physical first hop MUST also cross it。No caller-local
  `TcpStream::connect` or `UdpSocket::bind` may bypass the applicable boundary。

### M16-MUST-08 — exact route ownership

- M16-T01 MUST freeze one next-hop derivation、route-metric and interface-metric disposition that passes
  independent Windows 10 and Windows 11 positive/negative readback。Until that amendment is accepted，M16-T02
  and later product tickets remain blocked。These values MUST NOT become operator knobs merely to avoid the
  probe。
- Every route row MUST begin with `InitializeIpForwardEntry` and then explicitly set every field required by
  the accepted contract，including fields whose initializer value is true or illegal。Create success alone
  is insufficient：ActiveStore readback MUST exactly match the owned identity and allowed system-derived
  fields before admission。
- Only successfully read-back rows enter a private reverse-order journal。Rollback MUST remove capture rows
  before DNS/interface/adapter teardown，must delete only still-matching owned rows，and MUST surface a fixed
  cleanup-conflict outcome without deleting a third-party replacement。
- Address-derived connected/local rows remain OS-managed and MUST never be recorded as product capture rows。
- If T01 proves no interface-metric mutation is needed，product source and VM sentinels MUST prove none occurs。
  If T01 selects a Wintun-only metric lease，that lease MUST snapshot、apply、read back and conditionally restore
  each family；partial failure and an external replacement MUST preserve third-party state and report a fixed
  cleanup conflict。It MUST enter every setup/rollback/residue matrix below。

### M16-MUST-09 — Wintun DNS steering and synthetic fast path

- Auto-DNS MUST snapshot、apply and read back DNS settings only on the newly created Wintun interface for
  both families。It MUST NOT modify any physical interface or claim global resolver exclusivity。
- Exact TUN TCP/UDP destination `(ipv4_dns_address|ipv6_dns_address):53` MUST enter the existing `DnsProxy`
  before ordinary route evaluation。No other destination or port is synthetic-hijacked。`auto_dns = false`
  MUST preserve existing explicit route `hijack-dns` behavior and add no synthetic fast path。
- An upstream with no detour and one whose detour resolves to direct MUST use the same pinned physical direct
  implementation；a proxy detour retains its selected plan。UDP、TCP、DoT and DoH keep existing validation、
  authentication、deadline、admission and no-fallback behavior。
- Cleanup MUST restore the previous Wintun DNS value only when current settings still equal the owned applied
  value。External mutation MUST not be overwritten。Other-interface DNS、browser DoH/DoQ and port-53 blocking
  are explicitly outside the claim。

### M16-MUST-10 — preparation, rollback and network change

- All non-TUN roots MUST prepare before the managed TUN root。Before its underlay snapshot，the existing owner
  thread MUST establish route/interface/address notifications and record an invalidation generation。It MUST
  then perform Wintun setup、optional DNS apply and capture-row transaction；capture rows are the last host
  mutation。After exact readback it MUST revalidate the frozen physical fingerprint while excluding its own
  Wintun rows/settings；an intervening relevant event or mismatch rolls back before ready。Synchronous activate
  MUST remain a non-blocking admission gate and `ProcessSupervisor` MUST not change。
- M16-T01 MUST prove the capture-before-admission interval cannot overflow the Wintun ring or expose public
  service；failure stops the plan for a lifecycle amendment。
- Every setup failure ordinal、later composition failure、graceful stop and forced supervised stop MUST run one
  reverse transaction and await the owner thread before completion。One hundred cycles MUST return adapter、
  address、route、DNS、handle、callback、thread、flow、mapping and protocol owners to baseline。
- Route、interface and address notifications MUST only signal owner-thread revalidation。A change affecting
  frozen underlay or owned route identity MUST stop new sockets，remove capture/DNS steering and terminate
  the process through the existing supervisor。No live flow migration or uninterrupted fail-closed claim is
  made。
- T01 MUST prove external `TerminateProcess` produces process absence and zero adapter/address/route/DNS
  residue on both supported Windows baselines before controller remediation。It MUST NOT claim process-private
  flow/mapping/protocol drain from an unobservable killed process。If OS residue remains，M16 stops for
  replanning；normal RAII is not accepted as hard-kill proof。

### M16-MUST-11 — ownership, safety and observability

- `ferrum2-wintun` remains the only Windows unsafe Adapter and owns all raw route、DNS、socket-option and
  notification ABI details under its existing audited exception。No raw pointer、union、callback context or
  Windows handle crosses into async client code。
- Client egress remains binary-private；`ferrum2-core` keeps runtime-neutral plan/selector values and MUST NOT
  gain direct、Windows、TUN、DNS or async dependencies。No second route、DNS、UDP-session or process-lifecycle
  implementation is permitted。
- Errors、logs、traces and metric labels MUST NOT contain application target、proxy/DNS endpoint、route/prefix、
  interface index/LUID/GUID/name、adapter identity、DNS name、outbound tag、packet data or secret。New outcomes
  are fixed low-cardinality enums only。

### M16-MUST-12 — qualification boundary

- One exact integration SHA MUST pass focused config/core/runtime/client tests，repository Full，exact MSRV，
  Windows/GNU/musl non-driver gates，existing SIP022/DNS interoperability，test-footprint integrity，and
  bounded Architect/QA review with zero blocking findings。
- The same SHA MUST pass fresh isolated Windows 10 and Windows 11 privileged full profiles with pinned and
  unpinned TCP/UDP controls、resolver steering、network invalidation、100 cycles、hard kill and exact residue
  snapshots。On each baseline，network invalidation MUST include distinct real route、interface、IPv4
  unicast-address and IPv6 unicast-address mutations through the corresponding Windows callbacks；each row
  revokes admission/capture/DNS and terminates cleanly。Unavailable required VM evidence is BLOCKED，not waived。
- An independent same-SHA Windows performance/resource profile is required because socket creation and TUN
  lifecycle hot paths change。It is regression evidence only and creates no throughput threshold or
  improvement claim。Remote push/dispatch still requires explicit authorization。

## Non-goals

- WFP strict-route、kill switch、off-TUN DNS blocking、global DNS ownership or anti-leak claims。
- Per-target multihomed direct fidelity、live default-interface migration、hot reload or active-flow migration。
- Physical bypass routes、third-party route deletion/adoption、opening an existing Wintun adapter or modifying
  physical-interface DNS。
- Linux/macOS managed TUN、Windows ARM64/x86、service/watchdog/installer/UAC automation、Fake-IP、ICMP、
  fragments/extensions、process/Geo/rule-set routing、DoQ/DoH3 or QUIC sniffing。
- A new public endpoint abstraction、new Windows-network crate、new dependency identity、performance gain
  claim、Wintun redistribution、package、release or publication。
