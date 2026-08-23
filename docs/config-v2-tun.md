# Managed TUN configuration (schema v2)

Ferrum2's managed Windows TUN supports IPv4-only, IPv6-only, and dual-stack sessions. The two
interface-address fields are optional individually, but at least one must be present.

Privileged Windows acceptance is restricted to the approved Hyper-V guest and is documented in the
[`M17 Windows TUN qualification runbook`](windows-tun-m17-qualification.md).

A complete dual-stack direct-egress example is available at
[`docs/examples/client-v2-tun.toml`](examples/client-v2-tun.toml).
Deployments upgrading from the removed compatibility model should follow the
[`network model v2 breaking migration`](network-model-v2-migration.md).

```toml
schema_version = 2

[tun]
tag = "tun-in"
adapter_name = "Ferrum2"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00:f2::2/126"
mtu = 1420
ring_capacity = 8388608
ready_timeout_ms = 10000
max_tcp_flows = 256
tcp_buffer_bytes = 32768
max_udp_mappings = 1024
udp_filtering = "endpoint_independent"
auto_route = true
strict_route = false
route_address = ["0.0.0.0/0", "::/0"]
route_exclude_address = ["192.168.0.0/16", "fc00::/7"]
auto_dns = true
ipv4_dns_address = "198.18.0.1"
ipv6_dns_address = "fd00:f2::1"
outbound = "proxy"
```

Use only the fields for enabled address families. An IPv4-only session must not contain IPv6
capture routes or an IPv6 synthetic DNS address, and the inverse applies to IPv6-only sessions.
When `route_address` is omitted with `auto_route = true`, Ferrum2 installs the two `/1` capture
routes for each enabled family. Excludes are subtracted from those captures before any Windows
route is installed.

`auto_dns` retains its existing exact-endpoint semantics. It requires `auto_route = true` and at
least one synthetic DNS address belonging to an enabled TUN subnet. Only TCP or UDP traffic whose
destination exactly equals that configured address on port 53 is handled as synthetic DNS;
Ferrum2 does not capture every port-53 destination and does not alter DoH or DoT traffic.

## UDP mapping and filtering

TUN UDP mapping is always endpoint-independent: one local source IP and port owns one logical
association even when it sends to several destinations. The first ordinary datagram is routed
exactly once; that route, terminal, outbound/chain, interface policy, and route generation remain
frozen until the association expires or is reset. Later destinations reuse the same multi-target
egress and never invoke the router again.

`udp_filtering` accepts exactly two values:

- `endpoint_independent` (default) accepts responses from any valid, same-family unicast endpoint.
- `address_dependent` accepts responses only from a remote IP to which the association
  successfully sent an accepted datagram. The remote port is not part of this check.

Capacity remains drop-new. A new source association is dropped when `max_udp_mappings` is full;
Ferrum2 does not evict an active association.

The shared `[udp].max_buffered_bytes` limit continues to meter ordinary SOCKS, DNS, and RuleSet UDP
request/response buffers. Managed-TUN association buffers are intentionally outside that byte
budget: both Direct and Shadowsocks TUN requests and responses use fixed-capacity unmetered
reservations, so an exhausted shared budget does not reject them with `buffer_limit` and does not
change its `reserved_bytes`. This is not an unbounded queue contract. TUN association count,
packet queues, payload length, session capacity, timeouts, and generation checks still apply.

The first ordinary datagram from a local UDP source is routed exactly once. A successful terminal,
outbound/chain, interface policy, and route generation are frozen for that source association. All
later targets reuse the same multi-target Direct socket or proxy packet connection and never invoke
the router again. For example, the rule below affects a socket only when `198.51.100.10:3478` is
that socket's first ordinary target:

```toml
[[outbounds]]
tag = "proxy"
server = "192.0.2.10:8388"

[[outbounds]]
tag = "direct"
type = "direct"

[route]
final = "proxy"

[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "198.51.100.10"
port = 3478
action = "route"
outbound = "direct"
```

Applications that need different target-level routing must use different local UDP sources or wait
for association expiry/network reset. A rejected first terminal is frozen and drained under the
same rule, rather than rerouting every later datagram. Synthetic DNS is handled before this ordinary
association freeze, so an initial query to the configured synthetic address does not choose the
Internet outbound. Address-dependent filtering authorizes a remote IP only after a successful send;
endpoint-independent filtering accepts any otherwise-valid same-family response source.

The privileged `udp-policy` qualification sends parsed DNS, fixed-structure 1,200-byte QUIC v1
Initial, STUN multi-server, WebRTC ICE-candidate, and sequenced game-style datagrams through the
live TUN. It also proves one frozen Direct or Shadowsocks multi-target association, IPv4/IPv6
coverage, live capacity drop-new without eviction, congested queues, and stale generations.

## Automatic and strict routing

`auto_route` controls automatic TUN route installation. It does not detect external overlapping
routes, prove that every packet is captured, or provide a kill switch.

`strict_route` is a separate request and defaults to `false`. Its effective configuration value is
exactly `auto_route && strict_route`. A configuration with `strict_route = true` and
`auto_route = false` remains valid so startup diagnostics can report the retained request and an
effective value of `false`; it must not claim that strict routing is enabled.

On Windows, an effective strict route owns one dynamic WFP session. A single-stack TUN installs an
unsupported-address-family connect guard; a dual-stack TUN installs no family guard. When managed
DNS is also enabled, the session blocks traditional TCP and UDP port 53 on non-TUN paths while
allowing Ferrum2's own controlled traffic and the managed TUN path. Filter installation is
fail-closed and ordinary `ResetNetwork` keeps the same WFP session and filters. This is not an
external route-overlap detector, general physical-interface blocker, DoH or DoT detector, or
complete kill switch.

### Route-level interface selection

Schema v2 also accepts the following route-level interface contract:

```toml
[route]
auto_detect_interface = true
default_interface = "Ethernet"
```

`auto_detect_interface` defaults to `false`, while `default_interface` defaults to absent. Both may
be configured together. Every physical TCP and UDP socket uses the same family-aware resolver, with
the fixed order outbound `bind_interface`, automatically detected interface, route-level default,
then the system best route for the actual destination. IPv4 and IPv6 are resolved independently;
the managed TUN, loopback, unavailable interfaces, and interfaces without the requested family are
not automatic candidates.

`default_interface` is preserved exactly without trimming. It must contain 1 through 256 UTF-16
code units and no control characters. Invalid names fail with the closed
`route.default_interface` configuration field and are not included in the error text.

### Outbound-level dial constraints

Every socket-owning client Direct or Shadowsocks outbound, and every server Direct outbound,
accepts the same optional constraints:

```toml
[[outbounds]]
tag = "proxy"
server = "192.0.2.10:8388"
bind_interface = "Ethernet"
inet4_bind_address = "192.0.2.20"
inet6_bind_address = "2001:db8::20"
```

`bind_interface` uses the same exact 1-through-256 UTF-16-unit name contract as
`route.default_interface`. The two address fields are strict IPv4 and IPv6 literals respectively;
putting an address in the wrong family is an error. Selectors and chains are composition nodes, not
socket owners, and reject these fields. An explicit interface error is terminal for that dial and
never falls through to a lower-priority source. A configured source address must still belong to the
resolved interface. Sockets are bound against one network generation, discarded on a stale bind,
and the complete resolve/create/bind/admit operation is retried at most once.

## Network changes

A route, interface, address, best-route, DHCP, VPN, or metric notification performs a lightweight
`ResetNetwork`. Ferrum2 closes generation-bound TCP connections and UDP associations, clears the
TUN stack's provisional UDP, pending response, and fragment state, captures a fresh dual-stack
interface snapshot, runs the stack/router/outbound/inbound hooks, and resumes only after every hook
accepts the same generation. Notification bursts are coalesced and resets are serialized.

An ordinary reset preserves the Wintun adapter and device session, GUID/LUID/index, managed
addresses, managed routes, managed DNS, strict-route WFP dynamic session and filters, and the
transaction ownership ledger. A full rebuild is reserved for confirmed damage to one of those
owned objects, an unrecoverable Wintun session failure, or an untrustworthy ownership ledger. It
keeps admission closed, cancels the current generation, cleans up only ledger-owned state in reverse
order, reconstructs the managed plane, performs readback, publishes exactly one new generation, and
then reopens admission. Other VPN or LAN routes, default-route metric changes, link handovers, and
temporary loss of an automatically detected interface are never full-rebuild reasons.

## Fragmentation, MTU, and ping

Accepted IPv4 and IPv6 fragments are reassembled under bounded entry, fragment-count, protocol-size,
and timeout limits before transport checks, DNS matching, or routing. Overlapping fragments are
dropped. Ferrum2 may generate local IPv4 Fragmentation Needed, IPv6 Packet Too Big, and appropriate
Unreachable errors.

ICMP Echo is not proxied to a remote endpoint. `ping` therefore does not measure Ferrum2 tunnel
connectivity; use a TCP or UDP health check.

When the Wintun send ring is full, the complete outgoing packet is dropped immediately and counted
as a ring-full drop. It is not retried and does not trigger ResetNetwork or a full rebuild.

## Operational metrics

The managed path exports fixed-cardinality metrics for network reset/full rebuild and generation,
ingress/egress/reject outcomes, Wintun ring-full drops, active TCP flows, UDP candidates and
associations, fragment reassembly, strict-route installation, interface selection, and stale
generation handling. IP addresses, ports, adapter names, and route prefixes are never metric labels.

Wintun ring-full drops, managed-state damage, strict-route state, and interface resolution emit
closed structured diagnostics. Those records contain only fixed reasons, results, selection source,
and `ipv4`/`ipv6` family where applicable; they never contain packet endpoints, adapter names, or
route prefixes.

The principal counters and gauges are `ferrum2_network_reset_total{reason,result}`,
`ferrum2_network_full_rebuild_total{reason,result}`, `ferrum2_network_generation`,
`ferrum2_tun_session_generation`, `ferrum2_tun_session_active`,
`ferrum2_tun_packets_ingress_total`,
`ferrum2_tun_packets_egress_total`, `ferrum2_tun_packets_rejected_total`,
`ferrum2_tun_internal_egress_backpressured_total`, `ferrum2_tun_pending_udp_responses`,
`ferrum2_tun_udp_response_dropped_total{reason}`, `ferrum2_tun_wintun_ring_full_dropped_total`,
`ferrum2_tun_tcp_flows_active`, `ferrum2_tun_udp_associations_active`,
`ferrum2_tun_udp_candidates_active`, `ferrum2_tun_reassembly_entries_active`,
`ferrum2_tun_strict_route_requested`, `ferrum2_tun_strict_route_effective`,
`ferrum2_tun_strict_route_filter_install_total{result}`, and
`ferrum2_outbound_interface_resolution_total{source,result}`. There are no route-detection,
route-conflict, or aggregate TUN memory-budget metrics.

Internal egress backpressure is lossless: the owner retains the pending response and retries it
after the occupied output is flushed. Its dedicated counter records retry observations, not
permanent packet drops. The pending-response gauge is one while that response awaits retry and
returns to zero after injection or terminal removal. A deferred response does not increment the
general packet-rejection counter.

Terminal UDP response removal increments both the general rejection counter and exactly one
`ferrum2_tun_udp_response_dropped_total` series. Its closed reason set is
`stale_generation`, `association_closed`, `queue_full`, `malformed_response`, `filtered`,
`injection_rejected`, `session_reset`, `shutdown`, and `owner_fatal`; no endpoint, association,
route, outbound, or adapter identity is exposed as a label.

## Breaking migration

- This release accepts `schema_version = 2` only. Version 1, a missing version, and future versions
  fail before a partially validated configuration can be produced; there is no automatic migration.
- Replace legacy composite matchers with the flat schema-v2 matcher fields documented in the
  breaking migration guide.
- Remove the deleted aggregate TUN UDP memory field. It has no replacement or deprecated no-op;
  the breaking migration guide names the rejected legacy spelling explicitly.
- Existing dual-stack address fields and IPv4 synthetic DNS remain valid.
- `strict_route` is new and defaults to `false`. Its requested value is retained, but it is
  effective only with `auto_route = true`; requesting it without automatic routing requires a
  fixed startup warning and installs no WFP rules.
- `[route].auto_detect_interface` and `[route].default_interface` are new and default to `false`
  and absent respectively. They may coexist; automatic detection has priority over the named
  fallback.
- `udp_filtering` now defaults to `endpoint_independent` when omitted. Set it to
  `address_dependent` explicitly to retain source-address filtering.
- Ferrum2 no longer estimates or rejects aggregate TUN-owned memory. Flow, association, queue,
  fragment, timeout, and protocol-length bounds still apply; extreme combinations can therefore be
  limited by the operating system's available memory. This does not remove the shared runtime UDP
  byte budget for ordinary SOCKS, DNS, or RuleSet traffic.
- There are intentionally no `route_guard`, `on_network_change`, `dns_mode`, or `udp_mapping`
  settings.
