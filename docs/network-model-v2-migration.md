# Network model v2 breaking migration

Ferrum2 does not provide an automatic converter or a legacy runtime branch for this release. Update
the configuration before starting the new binaries; `--check-config` remains offline and is the
recommended pre-deployment gate.

## Required schema changes

Set the root version explicitly:

```toml
schema_version = 2
```

`schema_version = 1`, a missing version, zero, and unknown future versions all fail. The error is
reported at the root `schema_version` field and no partially validated configuration is returned.

Flatten legacy composite matchers. For example, replace:

```toml
target = { host = "example.com", port = 443 }
```

with the canonical schema-v2 fields:

```toml
host = "example.com"
port = 443
```

Delete `max_udp_buffered_bytes` from `[tun]`. It has no replacement, alias, warning-only mode, or
deprecated no-op. TUN UDP remains bounded by association count, packet queues, fragment limits,
protocol datagram length, deadlines, and idle expiry rather than an aggregate estimated byte budget.

## UDP behavior change

TUN UDP now always uses endpoint-independent mapping. The default filter is
`endpoint_independent`; set `udp_filtering = "address_dependent"` only when responses must come from
an IP to which the association successfully sent a datagram. Ports are not part of ADF authorization.

The first ordinary datagram from a local UDP source is routed once. Its terminal, outbound or chain,
interface policy, and generation remain frozen for that association, including later datagrams sent
to different destinations. Applications that require target-specific routing must use distinct
local UDP sources or wait for association expiry or `ResetNetwork`. Synthetic DNS is recognized
before the ordinary association is created.

## Route and dial policy

The optional route policy is:

```toml
[route]
auto_detect_interface = true
default_interface = "Ethernet"
```

Socket-owning Direct and Shadowsocks outbounds accept:

```toml
bind_interface = "Ethernet"
inet4_bind_address = "192.0.2.10"
inet6_bind_address = "2001:db8::10"
```

Interface selection is fixed as outbound explicit, family-aware automatic detection, route default,
then the system best route for the actual destination. An invalid explicit interface or source
address fails that dial without fallback.

## Windows TUN lifecycle and strict route

`auto_route` installs and owns only Ferrum2's managed TUN routes. It no longer scans other VPN, LAN,
or more-specific routes and is not proof that all traffic is captured.

`strict_route` is effective only when `auto_route` is true. On Windows it provides a dynamic WFP
unsupported-family guard for single-stack TUN and, with `auto_dns`, traditional TCP/UDP port-53 leak
protection on non-TUN paths. It does not cover DoH, DoT, arbitrary physical-interface traffic, or a
complete kill switch. Filter installation failure is fatal; requesting strict route without
automatic routing emits a warning and remains ineffective.

Ordinary interface, address, route-metric, DHCP, VPN, or best-route changes use lightweight
`ResetNetwork`: connections and generation-bound runtime state are replaced while adapter identity,
managed addresses/routes/DNS, WFP session, and ownership ledger stay intact. Only confirmed damage
to those Ferrum2-owned objects or an unrecoverable Wintun device session permits a full rebuild.

