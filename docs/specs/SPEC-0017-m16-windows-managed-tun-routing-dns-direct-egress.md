# SPEC-0017 — M16 Windows managed TUN routing, DNS and direct egress

- **Status:** Approved
- **Milestone:** M16
- **Baseline:** `fcef80dcc7e62bbca63ffbf7832df369dd418abd`
- **Related:** ADR-0034、ADR-0035、ADR-0036、TEST-0017

## Outcome

On Windows NT 10.0 build 19041+ AMD64，an opt-in schema-v2 TUN client can transactionally capture configured
IPv4 prefixes，steer the Windows IPv4 resolver path through its Wintun interface，and send selected IPv4 TUN
TCP flows or UDP mappings either through an existing Shadowsocks plan or through a new client direct outbound。
Every applicable IPv4 physical client socket is pinned before network use so product-owned capture cannot
recurse。M16-new managed capture、DNS、pinning、change and privileged evidence is IPv4-only because exact
restored-VM preflight found no usable IPv6 physical-default/off-link evidence boundary；that preflight is not
PASS evidence。Existing M15 manual-route IPv6 TUN behavior、SIP022 IPv6 and non-managed/SOCKS direct IPv6
remain unchanged。M16 privileged evidence is intentionally limited to the exact current VM/checkpoint named
by TEST-0017 and does not establish independent Windows-release coverage。

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
route_address = ["0.0.0.0/0"]
route_exclude_address = ["10.0.0.0/8"]
auto_dns = true
ipv4_dns_address = "198.18.0.1"

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

The retained `ipv6_address` is the existing M15 adapter address；M16 does not use it for managed capture、DNS
or physical pinning。The route example is exact-target syntax，not an internet recommendation。A prefix in
`route_exclude_address` never enters TUN；a route selecting `direct` has already entered TUN and then leaves
through the frozen IPv4 physical default interface。These are different policies。

## Requirements

### M16-MUST-01 — compatibility and platform boundary

- Every M15-accepted document that omits all M16 fields MUST preserve normalized config、`--check-config`、
  route/sniff/DNS action、wire、resource and lifecycle behavior。`auto_route` and `auto_dns` default to false。
- M15 manual-route IPv6 TUN adapter/data-plane behavior and its `16/16` transport regression evidence，plus
  existing SIP022 IPv6 and non-managed/SOCKS direct IPv6，MUST remain unchanged。M16 MUST NOT credit those
  preserved rows as proof of managed IPv6 capture、DNS、binding or physical-network change handling。
- With `auto_route = false` or omitted，an M15-compatible Windows TUN graph that omits M16 managed fields and
  has no TUN-origin client-direct operation MUST retain existing IPv6 proxy and absent/direct-detour DNS
  physical egress with no new managed-network state query or mutation。
- Client direct outbound is additive schema-v2 behavior and MUST work through the shared SOCKS/TUN/DNS
  client egress on every existing build target。Managed route/DNS mutation MUST run only for Windows NT
  10.0 build 19041+ AMD64；unsupported runtime targets fail before public service and without OS mutation。
- M16 privileged qualification MUST use only VM `Windows 10 MSIX packaging environment` restored from
  checkpoint `M15-T04-before-2b0c25b-20260810`。The runner MUST record actual guest edition、build and
  architecture after restore；the asset label MUST NOT be used as OS-version evidence。
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
- The existing `ClientEgressEngine` boundary MUST accept one closed binary-private request origin with exactly
  SOCKS、TUN and DNS cases，plus the selected plan and original target，for both TCP and UDP。Callers MUST remain
  outbound-kind agnostic and MUST NOT resolve、bind or create a raw physical socket themselves。The engine，
  not a process-wide TUN-presence check，MUST use TUN origin to reject selected direct IPv6 before resolver/
  socket creation，MUST preserve SOCKS-origin direct IPv6，and MUST apply the DNS-origin physical-first-hop
  restriction only while auto-route is active。No public trait、core variant、second dispatcher or fallback is
  permitted。
- A Windows graph containing TUN plus a reachable direct outbound MUST freeze/publish its IPv4 physical-
  default binder before TUN Ready even when auto-route is false。An external manual-route controller MUST add
  capture only after Ready。If that TUN-selected direct plan's immutable original target is IPv6，the product
  MUST fail before physical socket creation for both auto-route states and MUST NOT retry unpinned。SOCKS
  and non-Windows direct retain normal IPv4/IPv6 system routing。

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
- A Windows TUN-selected direct UDP mapping whose original target is IPv6 MUST fail before physical socket
  creation for both `auto_route = false` and `auto_route = true`；M15 proxy/reject/DNS-hijack IPv6 mappings and
  non-managed/SOCKS direct IPv6 remain unchanged。

### M16-MUST-05 — managed TUN configuration

- `[tun].auto_route` MUST be boolean default false。When true，`route_address` is an optional non-empty list
  of at most 64 canonical IPv4 prefixes，defaulting to `0.0.0.0/0`；`route_exclude_address` is an optional list
  of at most 64 canonical IPv4 prefixes，default empty。Either list MUST reject every IPv6 prefix and MUST be
  rejected when auto-route is false。
- `[tun].auto_dns` MUST be boolean default false and MUST require `auto_route = true` plus an existing client
  `[dns]` graph。When true，`ipv4_dns_address` is required and MUST be a usable unicast address inside the TUN
  IPv4 prefix and distinct from the local IPv4 interface address；otherwise it is forbidden。
  `ipv6_dns_address` MUST be rejected and is not part of the M16 schema。The existing M15 `ipv6_address`
  adapter field remains valid and unchanged。
- M16 fields MUST be rejected for schema v1、server configuration、missing TUN or unsupported managed IPv4
  shape。All prefix/address/count/result bounds and cross-field constraints MUST validate before runtime side
  effects。

### M16-MUST-06 — bounded capture-prefix compilation

- The compiler MUST compute canonical disjoint IPv4 `route_address − route_exclude_address`。Overlapping input
  may collapse，but output MUST be independent of input order。An exclusion outside all includes has no
  effect；any IPv6 input is a validation error。
- Every remaining `0.0.0.0/0` MUST split into its two canonical IPv4 `/1` children；the product MUST create no
  `/0` capture row。The final IPv4 row count MUST be `1..=256` or validation fails。
- The compiler MUST create no physical bypass/exclude row and MUST not enumerate third-party routes as owned。
  Existing more-specific routes remain untouched and win by longest prefix；an exact owned-key conflict
  fails before the first create rather than being modified or adopted。

### M16-MUST-07 — physical underlay snapshot and socket pinning

- Only when auto-route is active，before any capture row exists，the product MUST identify eligible up、non-
  loopback、non-Wintun IPv4 physical interfaces and route state。Each reachable fixed Shadowsocks first hop and
  each DNS bootstrap reached by absent/direct detour MUST resolve to IPv4，then call
  `GetBestInterfaceEx(destination)`，validate/convert the interface identity，call interface-constrained
  `GetBestRoute2` and freeze its route/source fingerprint。Under managed capture，an IPv6 concrete proxy
  endpoint or IPv6 direct/no-detour DNS physical endpoint MUST fail validation or prepare before mutation。
  For a proxy-detoured DNS server，the physical endpoint is the selected plan's first concrete Shadowsocks
  server；a logical IPv6 DNS bootstrap behind an IPv4 proxy first hop remains allowed and MUST NOT be pinned as
  a separate physical endpoint。
- Dynamic direct IPv4 targets MUST bind to one unambiguous capture-before IPv4 physical default interface。
  Missing or ambiguous policy MUST fail prepare before capture。This policy does not preserve target-specific
  non-default LAN/VPN routing；operators MUST exclude those IPv4 prefixes when that fidelity is required。
- The accepted fixed-first-hop formula is `GetBestInterfaceEx(destination)` → validated physical index →
  interface-constrained `GetBestRoute2` → frozen preferred source/route fingerprint。The accepted dynamic
  formula is the one unique capture-before IPv4 physical default。On the qualified asset，both underlay rows
  had prefix length `0`、row metric `0` and the same physical interface/source/next-hop identity；the raw
  identity remains local evidence and MUST NOT enter product telemetry。
- Applicable IPv4 sockets MUST set `IP_UNICAST_IF` with the required network-byte-order index before TCP
  connect or UDP first send。Failure MUST close the socket and MUST NOT retry unpinned。M16 MUST NOT publish an
  IPv6 binder；Windows TUN-selected direct IPv6 fails before socket creation instead。
- Every TUN-origin IPv4 Windows direct socket MUST cross this binding boundary regardless of capture
  ownership。While auto-route is active，every applicable SOCKS-origin IPv4 direct socket and every IPv4 proxy
  or actual DNS physical first hop MUST also cross it。No caller-local `TcpStream::connect` or
  `UdpSocket::bind` may bypass the applicable boundary。

### M16-MUST-08 — exact route ownership

- The accepted M16-T01 route contract creates exactly `0.0.0.0/1` and `128.0.0.0/1` with unspecified IPv4
  next hop `0.0.0.0` and row metric `1`。It leaves the Wintun IPv4 interface metric unchanged and therefore
  creates no interface-metric lease。This disposition passed positive/negative readback on the exact current
  qualification VM/checkpoint and MUST NOT become an operator knob or a cross-build inference。
- Every route row MUST begin with `InitializeIpForwardEntry` and then explicitly set every field required by
  the accepted contract，including fields whose initializer value is true or illegal。Create success alone
  is insufficient：ActiveStore readback MUST exactly match the owned identity and allowed system-derived
  fields before admission。
- Only successfully read-back rows enter a private reverse-order journal。Rollback MUST remove capture rows
  before DNS/interface/adapter teardown，must delete only still-matching owned rows，and MUST surface a fixed
  cleanup-conflict outcome without deleting a third-party replacement。
- Address-derived connected/local rows remain OS-managed and MUST never be recorded as product capture rows。
- If T01 proves no interface-metric mutation is needed，product source and VM sentinels MUST prove none occurs。
  If T01 selects a Wintun-only IPv4 metric lease，that lease MUST snapshot、apply、read back and conditionally
  restore IPv4 state；partial failure and an external replacement MUST preserve third-party state and report
  a fixed cleanup conflict。It MUST enter every setup/rollback/residue matrix below。

### M16-MUST-09 — Wintun DNS steering and synthetic fast path

- Auto-DNS MUST snapshot、apply and read back only IPv4 DNS settings on the newly created Wintun interface。
  It MUST NOT modify any physical interface、remove/change the M15 IPv6 adapter address or claim global
  resolver exclusivity。
- Exact TUN TCP/UDP destination `ipv4_dns_address:53` MUST enter the existing `DnsProxy` before ordinary route
  evaluation。No other destination or port is synthetic-hijacked。`auto_dns = false` MUST preserve existing
  explicit route `hijack-dns` behavior and add no synthetic fast path。
- An upstream with no detour and one whose detour resolves to direct MUST use the same pinned physical direct
  implementation；a proxy detour retains its selected plan。UDP、TCP、DoT and DoH keep existing validation、
  authentication、deadline、admission and no-fallback behavior。
- Cleanup MUST restore the previous Wintun DNS value only when current settings still equal the owned applied
  value。External mutation MUST not be overwritten。Other-interface DNS、browser DoH/DoQ and port-53 blocking
  are explicitly outside the claim。

### M16-MUST-10 — preparation, rollback and network change

- All non-TUN roots MUST prepare before the managed TUN root。Before its underlay snapshot，the existing owner
  thread MUST establish IPv4 route/interface/address notifications and record an invalidation generation。It MUST
  then perform Wintun setup、optional DNS apply and capture-row transaction；capture rows are the last host
  mutation。After exact readback it MUST revalidate the frozen physical fingerprint while excluding its own
  Wintun rows/settings；an intervening relevant event or mismatch rolls back before ready。Synchronous activate
  MUST remain a non-blocking admission gate and `ProcessSupervisor` MUST not change。
- M16-T01 MUST prove the capture-before-admission interval cannot overflow the Wintun ring or expose public
  service；failure stops the plan for a lifecycle amendment。
- Every setup failure ordinal、later composition failure、graceful stop and forced supervised stop MUST run one
  reverse transaction and await the owner thread before completion。One hundred cycles MUST return adapter、
  address、route、DNS、handle、callback、thread、flow、mapping and protocol owners to baseline。
- IPv4 route、interface and unicast-address notifications MUST only signal owner-thread revalidation。A change affecting
  frozen underlay or owned route identity MUST stop new sockets，remove capture/DNS steering and terminate
  the process through the existing supervisor。No live flow migration or uninterrupted fail-closed claim is
  made。
- T01 MUST prove external `TerminateProcess` produces process absence and zero adapter/address/route/DNS
  residue on the exact current qualification VM before controller remediation。It MUST NOT claim process-private
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
- The same SHA MUST pass fresh-restore privileged full and hard-kill profiles on the exact current
  qualification VM/checkpoint；the identity-bound full marker MUST itself include `cycles=100/100` alongside
  pinned and unpinned TCP/UDP controls、resolver steering、network invalidation and exact residue snapshots。
  Network invalidation MUST include distinct real IPv4 route、physical interface and IPv4 unicast-address
  mutations through the corresponding Windows callbacks；each row revokes admission/capture/DNS and
  terminates cleanly。The existing M15 IPv6 transport rows remain required regression evidence but are not
  credited as M16 managed-change proof。An unavailable or mismatched asset is BLOCKED，not replaced by a
  second VM or waived。
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
- Independent Windows 10/11、release-to-release or multi-build privileged qualification；hosted Windows jobs
  remain regression gates and MUST NOT be credited as a second OS compatibility baseline。
- M16-managed IPv6 capture、DNS steering、physical pinning or physical-network change qualification。This
  non-goal does not weaken M15 manual-route IPv6 TUN behavior、existing SIP022 IPv6 or non-managed/SOCKS
  direct IPv6。
