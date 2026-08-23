# Managed TUN configuration (schema v2)

Ferrum2's managed Windows TUN supports IPv4-only, IPv6-only, and dual-stack sessions. The two
interface-address fields are optional individually, but at least one must be present.

Privileged Windows acceptance is restricted to the approved Hyper-V guest and is documented in the
[`M17 Windows TUN qualification runbook`](windows-tun-m17-qualification.md).

A complete dual-stack direct-egress example is available at
[`docs/examples/client-v2-tun.toml`](examples/client-v2-tun.toml).

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
udp_filtering = "address_dependent"
auto_route = true
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
association even when it sends to several destinations. Each destination still receives its own
route and outbound decision.

`udp_filtering` accepts exactly two values:

- `address_dependent` (default) accepts responses only from a remote IP to which the association
  successfully sent an accepted datagram. The remote port is not part of this check.
- `endpoint_independent` accepts responses from any valid, same-family unicast endpoint.

Capacity remains drop-new. A new source association is dropped when `max_udp_mappings` is full;
Ferrum2 does not evict an active association.

The shared `[udp].max_buffered_bytes` limit continues to meter ordinary SOCKS, DNS, and RuleSet UDP
request/response buffers. Managed-TUN target children are intentionally outside that byte budget:
both Direct and Shadowsocks TUN requests and responses use unmetered reservations, so an exhausted
shared budget does not reject them with `buffer_limit` and does not change its `reserved_bytes`.
This is not an unbounded queue contract. TUN association count, per-child packet queues, payload
length, session capacity, timeouts, and session-generation checks still apply.

Ordinary route selection remains per destination even though association ownership is EIM. A
single IPv4 source socket can therefore keep one association while one target uses Direct and a
second target uses Shadowsocks:

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

The privileged `udp-policy` qualification sends parsed DNS, fixed-structure 1,200-byte QUIC v1
Initial, STUN multi-server, WebRTC ICE-candidate, and sequenced game-style datagrams through the
live TUN. It also proves mixed Direct/Shadowsocks and IPv4/IPv6 target children, live capacity
drop-new without eviction, and binds deterministic candidate tests to congested queues and stale
restart generations.

## Route integrity and network changes

Managed routing always detects conflicting external routes. A more-specific route inside a capture
prefix, or an equal prefix with a winning or indeterminate metric, prevents admission. Loopback,
link-local, control ranges, and Ferrum2-owned rows are exempt; private LAN, ULA, container, Hyper-V,
and other VPN routes are not implicitly exempt. Add every intentionally bypassed LAN prefix to
`route_exclude_address`.

Detection is fail-closed but is not a kernel WFP kill switch. A small user-space notification race
can exist between an operating-system route change and Ferrum2's response.

A semantic route, interface, address, DNS-lease, or underlay change rebuilds the managed TUN session
inside the same Ferrum2 process. Existing TCP flows are reset and UDP associations are closed; new
traffic is admitted after cleanup, route verification, and reconstruction complete. Rebuilds retry
with bounded backoff. A cleanup-integrity failure remains terminal because continuing could corrupt
system network state.

## Fragmentation, MTU, and ping

Accepted IPv4 and IPv6 fragments are reassembled under bounded entry, fragment-count, protocol-size,
and timeout limits before transport checks, DNS matching, or routing. Overlapping fragments are
dropped. Ferrum2 may generate local IPv4 Fragmentation Needed, IPv6 Packet Too Big, and appropriate
Unreachable errors.

ICMP Echo is not proxied to a remote endpoint. `ping` therefore does not measure Ferrum2 tunnel
connectivity; use a TCP or UDP health check.

When the Wintun send ring is full, the complete outgoing packet is dropped immediately and counted
as a ring-full drop. It is not retried and does not restart the session.

## Operational metrics

The managed path exports fixed-cardinality metrics for session starts/restarts and generation,
ingress/egress/reject outcomes, Wintun ring-full drops, active TCP flows, UDP candidates and
associations, fragment reassembly, network changes, route detection, and stale underlay binds.
Packet rejection and route-conflict labels use closed reason enums. IP addresses, ports, adapter
names, and route prefixes are never metric labels.

Wintun ring-full drops and route conflicts also emit closed structured diagnostics. Those records
contain only the fixed reason and `ipv4`/`ipv6` family; they never contain packet endpoints,
adapter names, or route prefixes.

The principal counters and gauges are `ferrum2_tun_session_started_total`,
`ferrum2_tun_session_restart_started_total`, `ferrum2_tun_session_restart_succeeded_total`,
`ferrum2_tun_session_restart_failed_total`, `ferrum2_tun_session_generation`,
`ferrum2_tun_session_active`, `ferrum2_tun_packets_ingress_total`,
`ferrum2_tun_packets_egress_total`, `ferrum2_tun_packets_rejected_total`,
`ferrum2_tun_internal_egress_backpressured_total`, `ferrum2_tun_pending_udp_responses`,
`ferrum2_tun_udp_response_dropped_total{reason}`, `ferrum2_tun_wintun_ring_full_dropped_total`,
`ferrum2_tun_tcp_flows_active`, `ferrum2_tun_udp_associations_active`,
`ferrum2_tun_udp_candidates_active`, `ferrum2_tun_reassembly_entries_active`,
`ferrum2_tun_network_change_total`, `ferrum2_tun_route_detect_total`,
`ferrum2_tun_route_conflict_total`, and `ferrum2_tun_underlay_bind_stale_total`. There is no
aggregate TUN memory budget gauge.

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

## Migration from earlier schema-v2 TUN configuration

- Existing dual-stack address fields and IPv4 synthetic DNS remain valid.
- `udp_filtering` defaults to `address_dependent` when omitted.
- `max_udp_buffered_bytes` is accepted for one compatibility period but is ignored, is not range
  checked, and does not contribute to any runtime or startup memory calculation. A normal startup
  emits the fixed `warning[config.deprecated] tun.max_udp_buffered_bytes` warning once. Remove it
  from new configurations.
- Ferrum2 no longer estimates or rejects aggregate TUN-owned memory. Flow, association, queue,
  fragment, timeout, and protocol-length bounds still apply; extreme combinations can therefore be
  limited by the operating system's available memory. This does not remove the shared runtime UDP
  byte budget for ordinary SOCKS, DNS, or RuleSet traffic.
- There are intentionally no `route_guard`, `on_network_change`, `dns_mode`, or `udp_mapping`
  settings.
