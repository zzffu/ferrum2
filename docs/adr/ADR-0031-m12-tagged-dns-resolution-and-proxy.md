# ADR-0031 — M12 tagged DNS resolution and proxy

- **Status:** Accepted
- **Date:** 2026-08-05
- **Related:** `SPEC-0013`、`TEST-0013`、M12-T01～T06；extends ADR-0019、ADR-0024 and ADR-0028

## Context

Ferrum2 currently has two deliberately small DNS behaviors. Server direct TCP/UDP resolves an
authenticated domain target through Tokio's system resolver, consumes at most 16 socket candidates and
shares one absolute connect deadline. Client SOCKS domain targets remain names on the SIP022 wire and
are not resolved locally. There is no public DNS listener、tagged DNS-server graph or operator choice of
UDP、TCP、DoT or DoH.

M8 already owns the only ordered rule matcher: optional inbound、`tcp|udp` and pre-resolution exact
target are ANDed，the first match wins and a mandatory final action closes selection. M12 needs the same
conditions and ordering for DNS-server choice，but a DNS server is neither a Shadowsocks outbound nor a
retry candidate. Duplicating that matcher or adding DNS policy to Hickory would create a second rule
engine and blur two action domains.

The latest stable Hickory release is
[0.26.1](https://github.com/hickory-dns/hickory-dns/releases/tag/v0.26.1). Its resolver and protocol
packages declare Rust 1.88，while this workspace still declares Rust 1.85.0. Therefore the original M12
draft phrase “MSRV 1.85” cannot coexist with the requested latest Hickory versions. M12 treats latest
Hickory as authoritative and raises the workspace MSRV to 1.88.0.

Hickory already provides DNS messages、name/record validation、UDP/TCP framing、upstream connection
management and DoT/DoH transports. Ferrum2 only needs validated composition、tag selection、bounded
listener ownership and adaptation to the existing process lifecycle. It must not fork those protocols
or transports.

The requested “upstream tag” follows sing-box's
[detour dial-field](https://sing-box.sagernet.org/configuration/shared/dial/) meaning：it names the
existing outbound used to connect to a DNS server，not the DNS server selected by a DNS rule. M12 must
therefore preserve two distinct choices：`dns.route` chooses a DNS server tag，then that server's optional
`detour` chooses an egress action. Collapsing them would either route DNS through the wrong policy or
make encrypted DNS impossible to carry over an existing Shadowsocks plan.

## Decision

### Exact dependency and toolchain contract

M12 adds one `ferrum2-dns` crate and pins the current release line exactly:

~~~toml
hickory-resolver = { version = "=0.26.1", default-features = false, features = [
    "tokio", "tls-ring", "https-ring", "webpki-roots"
] }
hickory-proto = { version = "=0.26.1", default-features = false, features = ["std"] }
hickory-server = { version = "=0.26.1", default-features = false }
~~~

`hickory-server` is used only for its request/response server types and bounded message encoding.
Ferrum2 does not use its stock plain-TCP accept loop because 0.26.1 does not expose connection
admission there. Accepted TCP streams instead use Hickory's `hickory-net` framing through the resolver
re-export，under ferrum2's existing bounded supervisor. This keeps protocol/framing in Hickory while
preserving ferrum2's connection ceiling and awaited shutdown.

The workspace `rust-version` and explicit MSRV CI/tooling checks become `1.88.0`. The selected build
toolchain remains `1.97.1`；M12 does not lower or otherwise repin it. All workspace packages continue to
inherit one MSRV. Exact Cargo metadata、feature and lockfile checks prevent a second Hickory version、
`system-config`、DNSSEC、DoQ/DoH3 or AWS-LC provider from entering the product graph.

`ring` is the TLS crypto provider because it avoids the native AWS-LC build surface and already supports
the three required release targets. Product DoT/DoH trusts `webpki-roots` and always verifies the
configured server name. There is no insecure verifier. A test-only ephemeral trust root may be injected
by the selected interoperability profile；custom operator CA configuration is deferred.

### One optional DNS section

Schema version 1 gains an additive optional `[dns]` section. If it is absent，client behavior is
unchanged and server direct resolution remains the existing system resolver. A present section has
`1..=64` tagged servers、one mandatory DNS route，and role-specific consumers:

- Client may declare `1..=64` `[[dns.inbounds]]`. Each tag binds one socket address as a public DNS
  proxy on both UDP and TCP.
- Server does not accept `dns.inbounds`. Its authenticated domain-target TCP/UDP paths use the selected
  tagged DNS server instead of the system resolver.
- A client `[dns]` without a DNS inbound is inert and rejected. A server `[dns]` is consumed by direct
  domain resolution and needs no DNS listener.

Every `dns.servers` entry accepts an optional `detour` naming an existing outbound action in the same
process configuration. If absent，the DNS server uses direct egress. In a tagged client document it may
name a concrete outbound、fixed chain or selector，using the same compiled egress plan and snapshot
semantics as existing traffic. In a server document it may name one of the currently supported tagged
direct outbounds；M12 does not add a new server-side proxy-outbound type. Legacy documents have no named
outbound action and therefore reject `detour` while still allowing direct DNS servers.

DNS inbound tags join the existing case-sensitive global configuration-tag namespace. A collision with
an inbound、outbound、selector or chain fails before side effects. Server tags are local to
`dns.servers` and may not duplicate each other. Every detour reference is resolved before side effects
and counts as an outbound-graph reachability root；unknown、inbound、DNS-server or role-invalid tag
references fail at `dns.servers.detour` without exposing the supplied value.

The operator shape is:

~~~toml
[dns]
timeout_ms = 5000
max_inflight = 256

[[dns.inbounds]]
tag = "local-dns"
listen = "127.0.0.1:5353"

[[dns.servers]]
tag = "lan"
transport = "udp"
address = "192.0.2.53:53"

[[dns.servers]]
tag = "secure"
transport = "doh"
address = "192.0.2.54:443"
server_name = "resolver.example"
path = "/dns-query"
# Existing client outbound、chain or selector action.
detour = "example"

[dns.route]
final = "secure"

[[dns.route.rules]]
inbound = "local-dns"
network = "udp"
target = { host = "internal.example.", port = 53 }
server = "lan"
~~~

Here `example` is an existing outbound、chain or selector tag in the client document. `secure` is the
DNS server tag selected by `dns.route`；the two identities are intentionally different.

The server uses the same field against its existing direct-outbound tags:

~~~toml
[[outbounds]]
tag = "dns-direct"

[[dns.servers]]
tag = "secure"
transport = "dot"
address = "192.0.2.54:853"
server_name = "resolver.example"
detour = "dns-direct"
~~~

`transport` is closed to `udp`、`tcp`、`dot` and `doh`. `address` is always a numeric, non-zero
`SocketAddr`. `server_name` is required for DoT/DoH and forbidden for UDP/TCP；`path` is optional for
DoH with exact default `/dns-query` and forbidden otherwise. DoH is HTTP/2 POST as implemented by
Hickory. `detour` is transport-independent and applies to UDP、TCP、DoT and DoH. No proxy URL、headers、
HTTP/3 or opportunistic encryption are added.

### Explicit bootstrap and loop boundary

The numeric `address` is the bootstrap target. Ferrum2 never resolves it through the system resolver or
configured DNS graph. Without `detour` it is dialed directly；with `detour` it is preserved as the
application target passed to one snapshotted egress plan. For a client Shadowsocks plan，the configured
Shadowsocks hop endpoints remain numeric and the DNS bootstrap target travels inside existing SIP022
TCP or UDP semantics. For DoT/DoH，`server_name` remains only the authenticated TLS/HTTP identity；it is
never a bootstrap lookup input.

Validation rejects a directly dialed upstream bootstrap socket that aliases any client DNS proxy
socket，including same-family wildcard listener overlap. A client detour is not classified as that
direct local edge because the numeric target is presented at the final remote egress hop；its concrete
first-hop endpoints and all visible listener collisions still use existing graph validation. The
detour graph cannot point back to DNS：outbound endpoints are numeric，chains/selectors are already an
acyclic validated graph，and no outbound action may reference a DNS server.

An external DNS service can still be misconfigured to forward back to ferrum2 through another address.
Such an indirect topology cannot be proven from local config. It is contained by one absolute query
deadline、one global in-flight admission ceiling、no cross-server retry and `SERVFAIL` on exhaustion or
timeout. M12 does not add a private EDNS hop marker or modify query wire data to detect that external
cycle.

### Reuse one first-match engine with a separate action

Core extracts the existing runtime-neutral match predicate and ordered first-match table into one
small generic action table. Existing outbound routes continue to wrap it and return immutable egress
plans. DNS config compiles the same table with a numeric DNS-server identity as its action. Core learns
neither DNS、Hickory、TOML nor Tokio types.

`dns.route.rules` accepts exactly the existing conditions:

- optional `inbound`;
- optional `network = "tcp"|"udp"`;
- optional exact `target = { host, port }`.

Its only action field is `server`. `outbound` is rejected in a DNS rule and `server` is rejected in an
ordinary route rule. The mandatory `dns.route.final` is a server tag. All action tags are resolved and
all servers are reachable from a rule or final action before runtime work.

`detour` is not a DNS-rule condition or action and does not run ordinary `[route]` against the bootstrap
address. After one DNS action selects a server，that server's resolved detour action supplies only the
egress plan for its transport. A DNS detour therefore cannot alter application outbound selection or
select a different DNS server.

For server direct resolution，the match input is the authenticated Shadowsocks inbound、application
TCP/UDP network and original pre-resolution `TargetAddr` including its application port. Ordinary
outbound route selection and DNS-server selection are independent first-match calls over the same
input.

For a client DNS proxy request，the match input is the DNS inbound tag、received UDP/TCP transport and
the Hickory-validated absolute query name with synthetic port 53. DNS names are compared with the
existing ASCII case-insensitive exact-host rule；the absolute terminal dot remains significant.

Once selected，a DNS-server failure never evaluates a later DNS rule or `dns.route.final` and never
tries another server tag. A UDP-tagged server may repeat the same query to TCP at the same bootstrap
address only when Hickory reports a truncated UDP response；it retains the same detour-plan snapshot.
That standards-defined same-server transport upgrade is not policy fallback.

### DNS behavior stays inside Hickory

`ferrum2-dns` delegates message decoding/encoding、query and record structures、UDP/TCP DNS framing、
response truncation and upstream UDP/TCP/DoT/DoH connections to Hickory. Ferrum2 supplies only validated
configuration、selection context、admission/deadline ownership and low-cardinality error mapping.

A narrow Hickory `RuntimeProvider` adapter is the egress seam. Its direct mode delegates TCP/UDP to the
existing runtime；its detoured mode delegates TCP streams and UDP datagrams to the already selected
ferrum2 egress plan. Hickory still owns DNS framing、TLS and HTTP/2. Client detoured UDP reuses the
existing SIP022 UDP state machine and bounded owners independently from whether public SOCKS5
`UDP ASSOCIATE` is enabled；configuring internal DNS egress must not expose that public command.

The public proxy accepts a standard `QUERY` with exactly one `IN` question. It forwards the Hickory
request and returns the selected upstream response with the client transaction identity. Malformed
messages fail without upstream work；zero/multiple questions return `FORMERR`；non-`QUERY` opcodes
return `NOTIMP`；unsupported classes return `REFUSED`. Upstream timeout、busy admission、TLS/HTTP or
transport failure returns `SERVFAIL` when a response can safely be formed.

Server direct resolution uses Hickory A/AAAA lookup results，preserves the existing maximum of 16
ordered socket candidates and shares the caller's absolute connect deadline. Route selection remains
pre-resolution. An IP target bypasses DNS exactly as before.

M12 sets Hickory retries to zero and response-cache capacity to zero. One selected request therefore
has no hidden cross-timeout retry，and separate server tags cannot share stale answers. Bounded caching
and configurable retry policy are future behavior，not preparatory M12 abstractions.

### Resource ownership and lifecycle

`dns.timeout_ms` defaults to 5,000 and is bounded to `100..=30,000`. It is one end-to-end absolute
deadline covering admission、detour selection、egress connect/SIP022 handshake、TLS/HTTP、query and
response. No existing per-stage timeout may extend it. `dns.max_inflight` defaults to 256 and is bounded
to `1..=4096`；one shared semaphore covers proxy and server-resolution requests across all server tags.

The existing runtime `max_connections`、`listen_backlog`、`idle_timeout` and shutdown grace apply to
the aggregate client DNS TCP listener set. UDP receives into Hickory's 4,096-byte maximum buffer. DNS
TCP length framing has the protocol's 65,535-byte ceiling and a bounded per-connection response queue.
No peer length controls an allocation above that ceiling.

Tagged resolver connections are lazy. Their count is derivable from the maximum server count and each
server's fixed transport set. A ferrum2-owned Hickory runtime handle tracks every upstream background
task and every bounded detour bridge/UDP owner. Detoured work also consumes the existing egress
connection、session and byte budgets instead of creating parallel unaccounted limits. On process
shutdown the resolver graph is dropped，remaining tasks are aborted if necessary and all joins are
awaited within the existing `ProcessSupervisor` grace. DNS listener prepare/rollback、graceful drain、
forced stop and exact UDP/TCP rebind use existing process roots.

Query names、record data、DNS server/inbound/detour tags、bootstrap endpoints and TLS identities never
become trace fields or metric labels. Existing closed stage/reason/outcome identities are extended only
with low-cardinality DNS values such as transport class and terminal reason.

## Consequences

- Latest Hickory security fixes and all required transports are used without a ferrum2 DNS wire or
  connection implementation.
- The MSRV rises from 1.85.0 to 1.88.0. Users building ferrum2 must update even when `[dns]` is absent，
  because Cargo's workspace package contract is global.
- Core gains one deeper reusable first-match action table because two real action domains now consume
  it；ordinary route behavior remains exact.
- `detour` makes DNS-server selection and DNS-server egress independently configurable. Client DNS can
  use an existing direct、concrete、chain or selector plan without another proxy stack；server detours
  remain limited to its existing direct-outbound surface.
- Product TLS trusts public WebPKI roots only. Private-CA and OS-store policy require a later explicit
  operator contract.
- Disabling cache and general retry is deliberately minimal. It avoids multiplying memory by tagged
  servers and keeps failure timing exact for the first release.

## Rejected alternatives

- **Keep Rust 1.85 with Hickory 0.25.x:** rejected because the user explicitly chose the latest stable
  resolver/protocol release，and 0.26.1 also contains current security fixes.
- **Use system resolver for bootstrap hostnames:** rejected because it creates split policy、hidden
  environmental behavior and direct loop ambiguity.
- **Use Hickory server's stock plain-TCP listener:** rejected because its 0.26.1 accept path does not
  expose ferrum2's required connection admission boundary.
- **Copy the existing route matcher into the DNS crate:** rejected because two first-match engines would
  drift on case、terminal-dot、network or final semantics.
- **Model a DNS server as an outbound/selector member:** rejected because transport failure must not
  trigger outbound policy，and server tags are not proxy egress plans.
- **Run ordinary outbound rules for the DNS bootstrap target:** rejected because `detour` is an explicit
  stable reference；re-routing bootstrap traffic would add recursion、post-selection policy drift and a
  second failure fallback surface.
- **Add cache、DNSSEC、DoQ/DoH3、custom CA or external loop markers now:** rejected as unrequested
  policy and resource surface.

## Non-goals

- Recursive authoritative DNS、zone service、dynamic update、transfer、DNSSEC validation、mDNS、DoQ or
  DoH3.
- DNS response based proxy routing、domain suffix/wildcard/regex、CIDR、GeoIP/Geosite、qtype/client-IP
  conditions or multi-question routing.
- Cross-server retry、fallback/failover、health checks、load balancing、DNS-server selectors or upstream
  groups.
- Resolving a DNS server hostname or rewriting EDNS/ECS/DNS payloads.
- New server-side proxy outbound types. A server `detour` may use only the direct outbound actions that
  already exist for that role；adding Shadowsocks/SOCKS/Tailscale server egress is a separate feature.
- Product custom CA、insecure TLS、DoH authentication/header policy、system root-store selection or TLS
  server endpoints.
- Replacing SIP022 target names with resolved IPs on the client，changing route selection order，new
  standalone binary，hot reload、management API、package、release or publication.
