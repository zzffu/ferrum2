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
association even when it sends to several destinations. Each destination still receives its own
route and outbound decision.

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

This change establishes only that configuration and diagnostic contract. The current runtime does
not yet install WFP rules from the effective value, so setting `strict_route = true` is not yet a
traffic-leak guarantee. The planned Windows enforcement is limited to unsupported-address-family
unreachable handling and traditional TCP/UDP port-53 protection on non-TUN paths when managed DNS
is enabled. It is not an external route-overlap detector, general physical-interface blocker, DoH
or DoT detector, or complete kill switch.

### Route-level interface selection

Schema v2 also accepts the following route-level interface contract:

```toml
[route]
auto_detect_interface = true
default_interface = "Ethernet"
```

`auto_detect_interface` defaults to `false`, while `default_interface` defaults to absent. Both may
be configured together: a runtime consumer must prefer a usable family-aware automatically detected
interface and use `default_interface` only as its route-level fallback. This change preserves those
values through configuration preparation and finishing but does not connect them to socket creation.

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
socket owners, and reject these fields. The values survive configuration preparation and finishing.
Runtime socket binding and interface/address membership checks land with the unified interface
resolver; until then these fields do not change socket creation.

## Network changes

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
- `strict_route` is new and defaults to `false`. Its requested value is retained, but it is
  effective only with `auto_route = true`; requesting it without automatic routing requires a
  fixed startup warning from the eventual runtime consumer. This configuration-only change does
  not install WFP rules.
- `[route].auto_detect_interface` and `[route].default_interface` are new and default to `false`
  and absent respectively. They may coexist; automatic detection has priority over the named
  fallback. This configuration-only change does not yet alter runtime socket binding.
- `udp_filtering` now defaults to `endpoint_independent` when omitted. Set it to
  `address_dependent` explicitly to retain source-address filtering.
- Ferrum2 no longer estimates or rejects aggregate TUN-owned memory. Flow, association, queue,
  fragment, timeout, and protocol-length bounds still apply; extreme combinations can therefore be
  limited by the operating system's available memory. This does not remove the shared runtime UDP
  byte budget for ordinary SOCKS, DNS, or RuleSet traffic.
- There are intentionally no `route_guard`, `on_network_change`, `dns_mode`, or `udp_mapping`
  settings.
