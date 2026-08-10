# ADR-0036 — M16 Windows managed TUN policy

- **Status:** Proposed
- **Date:** 2026-08-10
- **Related:** `ADR-0034`、`ADR-0035`、`SPEC-0017`、`TEST-0017`、M16-T01～T07

## Context

M15 owns a Wintun adapter and bounded TCP/UDP data plane but deliberately leaves capture routes and Windows
DNS outside the product。M16 must add an opt-in compatible capture policy while preventing the client's own
proxy、direct and DNS sockets from re-entering Wintun。The new direct outbound makes the destination set
unbounded at startup，so endpoint host routes alone cannot solve recursion。

Windows route、DNS and process-termination APIs also impose non-obvious ownership limits：ActiveStore rows
are not process-scoped，per-interface DNS is not globally exclusive，and `TerminateProcess` does not run
Rust cleanup。The milestone needs a capability probe before it can promise lifecycle cleanup。

An exact restored-VM preflight found one usable IPv4 physical default but no IPv6 physical default，no
non-link-local physical IPv6 address and no owned off-link dual-stack endpoint。That preflight is a planning
input，not PASS evidence。M16 therefore narrows only its new managed-network contract to IPv4 instead of
inventing another VM、endpoint or configuration knob；the accepted M15 manual-route IPv6 data plane remains。

## Decision

### Compatible and opt-in ownership

`[tun].auto_route` and `[tun].auto_dns` default to `false`。With both false or absent，M15 route/DNS host
state remains unchanged。A graph combining TUN with a reachable client direct outbound still takes a
read-only capture-before IPv4 physical-default snapshot and publishes its socket binder before Ready；this is
required direct-egress behavior，not product route ownership，and an external controller adds capture only
after Ready。`auto_route = true` makes the existing Wintun owner additionally own its compiled IPv4 capture
rows、IPv4 binding for SOCKS-origin direct and every reachable proxy/DNS physical first hop、IPv4 underlay
notifications and rollback journal。`auto_dns = true` additionally owns only IPv4 DNS settings on that newly
created Wintun interface and exact synthetic IPv4 DNS handling；it requires auto-route and the existing `[dns]`
graph。The existing
M15 `ipv6_address` adapter address and manual-route IPv6 behavior are preserved rather than managed by M16。

This is compatible routing，not strict routing：Ferrum2 does not delete or rewrite third-party routes，does
not add physical bypass routes，does not modify physical-interface DNS，and does not add WFP filters or a
kill switch。More-specific LAN、VPN and operator routes retain Windows longest-prefix precedence unless the
operator explicitly includes an equally or more specific prefix。

### Capture plan and exact journal

The capture compiler produces a bounded canonical IPv4 set from
`route_address − route_exclude_address`，then splits any remaining `0.0.0.0/0` into its two `/1` rows。
Both input lists reject IPv6 prefixes。It never creates a `/0`，never creates an exclude/bypass row，and
rejects an empty or over-limit result。Each intended row is absent before create，has every mutable
`MIB_IPFORWARD_ROW2` field explicitly initialized，is read back from ActiveStore，and enters the journal only
after an exact match。Rollback deletes journaled rows in reverse order only while their owned identity still
matches；Windows address-derived connected/local rows are never journaled。

Route next-hop derivation、row metric and any need for Wintun interface-metric mutation are physical-world
values。M16-T01 must freeze them from positive/negative readback on the current approved Hyper-V asset，VM
`Windows 10 MSIX packaging environment` restored from checkpoint
`M15-T04-before-2b0c25b-20260810`，before product implementation。The guest's actual product、edition、
architecture and full version/build are recorded after restore；the VM label is not treated as OS-version
evidence。If one bounded rule does not work on that exact asset，the contract stops for replanning rather than
exposing an unproved operator knob。

### Immutable physical underlay policy

Only when `auto_route = true`，before any capture row exists，M16 snapshots eligible up、non-loopback、non-
Wintun IPv4 physical interfaces and routes。Each reachable fixed Shadowsocks first hop and direct/no-detour
DNS bootstrap must resolve to IPv4，then uses `GetBestInterfaceEx` followed by interface-constrained
`GetBestRoute2`。Under managed capture，an IPv6 concrete proxy endpoint or IPv6 DNS bootstrap reached
physically through absent/direct detour fails validation or prepare before mutation。A logical IPv6 DNS
bootstrap behind an IPv4 concrete proxy first hop remains allowed because only the proxy first hop is a
physical endpoint。While managed capture is active，dynamic direct targets use one unambiguous frozen IPv4
physical default interface，and every applicable TCP/UDP socket is bound before connect/first send。

Independently，a Windows graph with TUN-origin client direct selects and publishes that IPv4 physical-default
binder before Ready for both auto-route states；with auto-route off，only TUN-origin direct uses it。

Missing、ambiguous、changed or failed applicable IPv4 binding rejects the selected socket；there is no unpinned fallback
and no per-flow bypass route。A Windows TUN-selected direct IPv6 target fails before physical socket creation
whether auto-route is on or off。This bounded policy deliberately does not preserve arbitrary target-specific
multi-interface routing。IPv4 prefixes that must continue through a non-default LAN、enterprise VPN or other
interface belong in `route_exclude_address`。Per-target route fidelity、managed IPv6 and live underlay
migration are deferred。

With `auto_route = false`，the managed physical-first-hop restriction does not run。An M15-compatible TUN graph
that omits M16 managed fields and has no TUN-origin client-direct operation retains existing IPv6 proxy and
absent/direct-detour DNS physical egress without a new managed-network state query or mutation。The separate
TUN-origin client-direct rule still rejects an original IPv6 target before resolver/socket for both auto-route states；
SOCKS origin using the same direct tag remains allowed。

### DNS steering, not DNS exclusivity

Auto-DNS snapshots、sets and reads back only the new Wintun interface's IPv4 DNS settings，using the
validated synthetic IPv4 address。TUN TCP/UDP whose exact destination is that address on port 53 enters the
existing `DnsProxy` before ordinary routing；other port-53 traffic follows ordinary policy。The existing M15
IPv6 adapter address remains configured but is not a managed DNS address。While auto-route is active，direct
and detoured UDP/TCP/DoT/DoH upstreams use the same IPv4 binding boundary at their actual physical first hop。

Cleanup restores the prior Wintun DNS state only if current state still equals the owned applied value；an
external mutation is reported and never overwritten。The product makes no claim about other interfaces、
browser DoH/DoQ or global DNS anti-leak behavior。No WFP enforcement is added。

### Existing lifecycle, final preparation and change handling

No async activation interface or new process supervisor is introduced。All non-TUN roots are prepared first；
the managed TUN root is last。Its owner establishes notifications before the physical snapshot，records a
generation，performs Win32 mutation/readback during async prepare，and adds capture rows as the last host
mutation。It then revalidates the frozen physical fingerprint while excluding its own exact Wintun state；
any intervening relevant generation change or mismatch rolls the transaction back。Synchronous activation
only opens admission。M16-T01 must prove that the bounded capture-before-admission interval is acceptable；
otherwise the plan stops for a lifecycle amendment。

IPv4 route、interface and unicast-address notifications are treated as invalidation signals。If revalidation
changes any frozen underlay or owned-row invariant，the process rejects new sockets、removes capture/DNS
steering and
terminates through the existing supervised shutdown。Existing flows are not migrated and the milestone does
not claim fail-closed behavior during the transition。

M16-T01 must also prove that `TerminateProcess` leaves process absence and no adapter、address、capture-route
or Wintun-DNS residue on the same restored qualification VM before controller remediation。This external row
does not claim in-process owner drain。If adapter teardown does not provide the OS-state cascade，M16 stops
and replans；a service、watchdog or persistent recovery ledger is not silently added。

M16 deliberately qualifies privileged managed-network behavior on this one current VM/checkpoint only。It
does not claim independent Windows 10-versus-Windows 11、release-to-release or multi-build coverage；adding
another build later requires a separate evidence amendment，not a hidden expansion of this milestone。

## Consequences

- Socket pinning，not target host routes，solves recursion for both fixed proxy endpoints and arbitrary
  direct targets。
- One adapter lifetime continues to own all Wintun Win32 state；the existing audited `ferrum2-wintun`
  boundary may deepen instead of adding a second shallow Windows-network crate。
- Compatible routing preserves third-party more-specific routes but cannot promise strict capture、DNS
  anti-leak or per-target multi-interface fidelity。
- M16's new capture、pinning、DNS and physical-change contract is IPv4-only；M15 manual-route IPv6 adapter and
  transport evidence and existing non-managed IPv6 egress guarantees remain separate and unchanged。
- Real capability and hard-kill cleanup on the exact current VM/checkpoint are entry gates。Other Windows
  builds remain unqualified by M16 rather than being inferred from that single result。

## Rejected alternatives

- **Physical `/32`/`/128` bypass rows:** cannot enumerate arbitrary direct destinations and adds route-table
  ownership for every flow。
- **Choose best interface after capture:** the capture route can make Wintun the answer and reintroduce the
  loop。
- **Copy sing-box `/0` plus metric-zero behavior:** upstream behavior is evidence，not Ferrum2's readback and
  ownership contract。
- **WFP strict route or DNS block filters:** materially different security、interop and cleanup scope。
- **Live underlay recomputation/migration:** changes established-flow semantics and is not required for a
  first compatible mode。
- **A new `ferrum2-windows-net` crate:** route/DNS/pinning share the owned Wintun lifetime and currently have
  no second consumer；split only if implementation evidence proves the existing Adapter cannot remain deep。
