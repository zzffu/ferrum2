# ADR-0035 — M16 client direct outbound

- **Status:** Accepted
- **Date:** 2026-08-10
- **Related:** `ADR-0029`、`ADR-0030`、`ADR-0032`、`SPEC-0017`、`TEST-0017`、M16-T01～T07

## Context

The client graph currently assumes every concrete `[[outbounds]]` entry is one Shadowsocks server，and the
client egress engine interprets every selected plan as one or more SIP022 hops。The existing core route and
selector layers already return an immutable list of concrete outbound indices，so adding a second route
action or target-specific TUN router would duplicate a seam that is already deep enough。

M16 must let an ordinary route select an outbound that reaches the original application target without
Shadowsocks。This is different from the historical phrase “direct action”，which meant a one-hop
Shadowsocks plan，and different again from excluding a prefix before it enters TUN。The distinction must be
closed in the domain model before implementation。

## Decision

### Closed client outbound algebra

Client schema-v2 accepts an optional outbound discriminator：

```toml
[[outbounds]]
tag = "direct"
type = "direct"
```

Omitted `type` preserves the existing Shadowsocks meaning；explicit `type = "shadowsocks"` has the same
meaning。A direct outbound has no `server`、`method` or `psk`，and any such field is a validation error。A
Shadowsocks outbound retains the M11 server and both-or-neither credential rules。A direct-only tagged
client graph may omit global `[shadowsocks]`；any legacy client or graph containing a Shadowsocks outbound
continues to satisfy the existing global credential contract。Server outbound syntax is unchanged。

The validated client model is a closed sum of `Shadowsocks { endpoint, credentials }` and `Direct`，not
parallel optional server/key vectors。No sentinel endpoint represents direct。

### Existing plan and selector identity remains authoritative

`EgressPlanSnapshot` remains the single owned route result and continues to store concrete outbound
indices。A direct plan is exactly one direct index。A one-hop proxy plan is exactly one Shadowsocks index；a
fixed chain is `2..=8` Shadowsocks indices。Configuration rejects direct anywhere inside a fixed chain，and
the egress boundary defensively rejects empty、mixed or multi-hop-direct plans。

Static binding、ordinary route rule/final、outbound selector and DNS detour may resolve to a direct plan。
Selector switching retains the existing snapshot lifetime：already selected TCP flows and UDP mappings do
not migrate。An absent DNS detour and a detour resolving to direct share the same physical direct socket
path。Any selected direct open/send/resolve failure ends that flow or mapping；there is no member、rule、final
or proxy fallback。

### One client egress boundary

`ClientEgressEngine` remains the sole client physical-egress dispatcher。Its private outbound context becomes
the closed Direct/Shadowsocks sum，and its existing binary-private request boundary gains one closed
`ClientRequestOrigin::{Socks,Tun,Dns}` value。TUN、SOCKS and DNS callers pass that origin plus the selected plan
and original target；they remain outbound-kind agnostic and never create a raw physical socket。The engine，
not a process-wide “TUN exists” check，dispatches outbound kind and applies the binding obligation for that
request origin。No public trait、core variant or second dispatcher is added。

TCP direct reuses the existing dialer/resolver boundary and returns a raw relay stream through a small
client-local flow sum。UDP direct reuses the existing bounded resolver、direct socket factory、session
capacity、idle/cancellation and owner machinery；callers no longer create raw product sockets themselves。
No public factory、new crate or core protocol variant is added。

TUN always connects its immutable original numeric destination；sniffed metadata never replaces it。SOCKS
domain direct uses the existing bounded system resolver and one existing deadline。Direct creates no
SIP022 owner、cipher、nonce、session or wire overhead。Observability records only fixed direct/proxy outcome
categories and never a target、tag、interface identity or DNS name。

When auto-route is active，SOCKS domain lookup still uses the Windows system resolver rather than silently
switching to the optional Ferrum DNS graph。With auto-DNS，the steered synthetic query enters the existing
`DnsProxy`。Without auto-DNS，any resolver packet captured by the `/1` rows is ordinary TUN traffic and follows
the configured route/direct/proxy/reject policy；its terminal physical socket is pinned，so this bounded nested
lookup does not create an unpinned fallback。Resolution failure ends the selected flow under the existing
deadline。

On Windows，when a client graph contains both TUN and a reachable direct outbound，the TUN root freezes and
publishes the IPv4 physical-default binding before Ready even if `auto_route = false`。A manual-route controller
must retain M15 ordering and add external capture only after Ready；the resulting IPv4 direct socket is pinned
and does not depend on the controller enumerating arbitrary target bypass routes。A Windows TUN-selected
direct plan whose immutable original target is IPv6 fails before physical socket creation for both
`auto_route = false` and `auto_route = true`；the engine rejects only `Tun` origin before resolver/socket and
there is no unpinned fallback。`Socks` origin using the same direct tag retains IPv6 system routing，including
in a mixed Windows TUN graph；non-Windows direct clients also retain normal IPv4/IPv6 routing。Only while
auto-route is active，`Socks`-origin IPv4 direct，`Dns` origin and reachable proxy physical first hops use the
binding boundary，and the latter two physical-first-hop classes must resolve to IPv4；a logical IPv6 DNS
bootstrap behind an IPv4 concrete proxy first hop remains valid because the bootstrap is not a separate
physical socket endpoint。With auto-route off，IPv6 absent/direct-detour DNS physical egress retains its
existing behavior。

## Consequences

- Ordinary routing can deliberately bypass Shadowsocks after traffic has entered TUN，without a second
  route engine or changes to the core plan representation。
- The central egress dispatch makes SOCKS、TUN and DNS behavior consistent and prevents caller-local raw
  socket paths from bypassing Windows underlay binding。
- The closed request origin prevents a process-wide TUN-presence check from rejecting SOCKS IPv6 or applying
  managed first-hop policy to DNS when auto-route is off。
- Direct-only tagged clients no longer need meaningless Shadowsocks credentials；legacy and proxy-bearing
  graphs retain their existing credential requirements。
- Allowing direct through a selector or DNS detour costs no second semantic path；both resolve to the same
  singleton plan and retain no-fallback behavior。
- The Windows TUN composition deliberately rejects selected direct IPv6 before a socket，without weakening
  SOCKS/non-Windows direct IPv6、existing SIP022 IPv6 or M15 manual-route IPv6 regression evidence。

## Rejected alternatives

- **Add `RouteAction::Direct`:** route actions select named egress plans already；a second action would split
  static、route、selector and DNS behavior。
- **Represent direct as `0.0.0.0:0` or optional parallel fields:** permits invalid states and pushes trust-
  boundary checks into runtime。
- **Make direct TUN-only:** SOCKS and TUN use the same routing graph；a caller restriction would require
  extra reachability analysis and duplicate dispatch。
- **Permit direct as a chain hop:** its meaning after or before a proxy is undefined and is not needed to
  reach an application target。
- **Add a generic endpoint registry or public egress trait:** there are only two concrete client modes and
  one existing private composition boundary。
