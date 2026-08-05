# SPEC-0013 — M12 tagged DNS resolution and proxy

- **Status:** Approved
- **Milestone:** M12
- **Decision:** `docs/adr/ADR-0031-m12-tagged-dns-resolution-and-proxy.md`

## Outcome

Ferrum2 provides an additive tagged DNS graph backed by Hickory 0.26.1. Client can expose bounded local
UDP/TCP DNS proxy inbounds，and server can resolve authenticated domain targets through a selected
UDP、TCP、DoT or DoH server. Both use the existing match conditions and first-match implementation with
an independent DNS `server` action. Each selected server may independently name an existing egress
action through optional `detour`，allowing both client-proxy and server-resolution paths to control how
the DNS upstream is reached. Existing configurations and system-resolution behavior remain exact when
`[dns]` is absent.

The words MUST、MUST NOT、SHOULD and MAY are normative.

## Requirements

### M12-MUST-01 — exact Hickory graph and Rust contract

- Workspace dependencies MUST pin `hickory-resolver =0.26.1`、`hickory-proto =0.26.1` and
  `hickory-server =0.26.1` exactly. Resolver MUST disable default and `system-config` features and enable
  only Tokio、ring-backed DoT/DoH and WebPKI roots required by ADR-0031.
- The resolved normal product graph MUST contain one 0.26.1 Hickory family and MUST NOT enable DNSSEC、
  recursor、DoQ、DoH3、AWS-LC、system resolver config or Hickory metrics.
- Workspace `rust-version` and every explicit MSRV check MUST be `1.88.0`. `rust-toolchain.toml` MUST
  remain `1.97.1` unless an independent toolchain requirement is approved.
- Cargo metadata、license/provenance and `Cargo.lock` MUST be committed and checked. Hickory's
  MIT/Apache-2.0 terms and transitive licenses MUST be compatible with GPL-3.0-only distribution.

### M12-MUST-02 — additive validated configuration

- A schema v1 document without `[dns]` MUST produce the same validated values and effective client/
  server behavior as baseline `c733e0dd03e711c045c0b7a4ee189277fbe37698`.
- A present `[dns]` MUST contain `1..=64` `[[dns.servers]]` and one `[dns.route]` with a mandatory
  `final`. It accepts `timeout_ms` in `100..=30000`，default 5000，and `max_inflight` in `1..=4096`，
  default 256. Unknown fields fail closed.
- Client `[dns]` MUST contain `1..=64` `[[dns.inbounds]]`. Each inbound has one globally unique
  configuration tag and one non-zero IPv4 or IPv6 listen socket. It exposes both UDP and TCP on that
  socket. Server config MUST reject `dns.inbounds`.
- Every server has a unique DNS-local tag，a closed transport and an address. Every server MUST be
  referenced by `dns.route.final` or at least one rule action. Duplicate、unknown、unreachable or
  role-inert identities fail before side effects.
- `dns.servers[].detour` is optional. If absent，that server MUST use direct egress. If present，it MUST
  resolve to an existing outbound action in the same tagged document and count as a reachability root.
  A client detour MAY name a concrete outbound、fixed chain or selector；a server detour MAY name only
  an existing server direct outbound. Legacy documents MUST reject `detour` because they have no named
  outbound actions.
- A detour MUST reject an unknown、inbound、DNS-server、cross-role or otherwise invalid tag at
  `dns.servers.detour` before side effects. It MUST NOT make a DNS server into an outbound、run ordinary
  route rules or create a fallback edge.
- A client UDP DNS detour MUST NOT change the validated public `[udp].enabled` value. Internal DNS UDP
  capability and public SOCKS5 UDP admission are independently configured consumers of the same
  bounded SIP022 implementation.
- DNS inbound tags MUST not collide with existing inbound、outbound、chain or selector tags. Config
  errors identify only closed fields such as `dns.inbounds.tag`、`dns.servers.address` or
  `dns.route.rules.server`；they MUST NOT include the supplied tag、host、path or endpoint.
- Root `[shadowsocks]`、legacy/tagged mutual exclusion and all existing config limits remain
  authoritative. M12 does not create a DNS-only config role or standalone binary.

### M12-MUST-03 — server transport and bootstrap validation

- `dns.servers[].transport` MUST be one of `udp`、`tcp`、`dot` or `doh`.
- `address` MUST parse as a numeric non-zero `SocketAddr`. Hostnames、URLs、zero ports and missing IPv6
  brackets fail at `dns.servers.address`. No runtime path may resolve this address.
- UDP/TCP MUST reject `server_name` and `path`. DoT/DoH MUST require a validated ASCII
  `server_name` and use it for certificate verification. DoT MUST reject `path`.
- DoH `path` MUST be an absolute path without scheme、authority、query or fragment，MUST be no longer
  than 1,024 bytes and defaults exactly to `/dns-query`. Hickory's HTTP/2 POST transport is the only
  supported DoH spelling.
- DoT/DoH MUST verify time、chain and configured identity against WebPKI roots. Expired、not-yet-valid、
  untrusted or wrong-name certificates fail closed. Product config MUST NOT expose skip-verification or
  custom-root fields in M12.
- A numeric server address MUST be the direct socket target when `detour` is absent and the final
  application target carried by the selected egress plan when `detour` is present. Neither spelling may
  perform system or configured-DNS bootstrap.
- Validation MUST reject a directly dialed server address that aliases a client DNS inbound socket，
  including an explicit address covered by a same-family wildcard listener on the same port. Existing
  concrete-hop/listener and visible listener/metrics collisions remain authoritative for detoured
  servers and MUST fail or roll back atomically before Active state.

### M12-MUST-04 — one matcher and independent DNS action

- Core MUST contain exactly one runtime-neutral implementation of the optional inbound、optional
  network、optional exact-target conjunction and ordered first-match/final selection. Existing
  `RouteTable` and DNS routing MUST consume it；neither config nor DNS may copy its matching loop.
- Ordinary route rule behavior、public selection results、selector snapshots and failure semantics MUST
  remain exact. Core MUST remain free of DNS、Hickory、Serde/TOML and async runtime types.
- `dns.route.rules` MUST accept only existing condition fields `inbound`、`network` and `target` plus
  action `server`. At most 64 rules are accepted. A conditionless rule is allowed and shadows following
  rules exactly as in ordinary routing.
- DNS rules MUST reject `outbound`；ordinary route rules MUST reject `server`. A selected server failure
  MUST NOT evaluate a later rule or final and MUST NOT alter ordinary outbound selection.
- `detour` MUST be resolved only as the DNS server's configured outbound reference；the DNS bootstrap
  target MUST NOT be submitted to ordinary first-match routing. DNS action selection and detour-plan
  resolution are distinct calls and neither may mutate the other.
- On server resolution the input is authenticated inbound identity、application TCP/UDP and original
  pre-resolution target/port. On client proxy the input is DNS inbound identity、received UDP/TCP and
  Hickory's validated absolute question name at synthetic port 53.
- Domain equality remains ASCII case-insensitive and otherwise exact. IP、port and terminal-dot
  differences remain significant. Client proxy rule examples and tests MUST use the absolute terminal
  dot.

### M12-MUST-05 — client UDP/TCP DNS proxy

- Each configured client DNS inbound MUST prepare one UDP and one TCP listener on the same address.
  Failure to prepare either listener MUST roll back both and all other newly prepared roots.
- DNS wire parsing、name/record representation、TCP length framing、response encoding and UDP response
  truncation MUST use Hickory. Ferrum2 MUST NOT add another DNS parser、serializer or hand-written TCP
  frame codec.
- A valid request is message type Query、opcode QUERY、exactly one IN-class question. Its record type may
  be any type Hickory 0.26.1 can represent without an M12-specific matcher.
- A valid request MUST be forwarded only to the first selected server and its response code、answer、
  authority、additional and EDNS data returned subject to safe Hickory encoding and the client
  transaction identity.
- For each selected server，the client MUST use direct egress when `detour` is absent and the referenced
  client egress action when it is present. UDP、TCP、DoT and DoH MUST all work over a concrete outbound、
  fixed chain and selector where the transport applies；Hickory retains DNS/TLS/HTTP ownership.
- Internal SIP022 UDP created for a DNS detour MUST reuse the existing bounded UDP state machine but
  MUST NOT enable or accept public SOCKS5 `UDP ASSOCIATE` when the public `[udp]` opt-in is disabled.
- Zero or multiple questions return FORMERR；unsupported opcode returns NOTIMP；unsupported class returns
  REFUSED. A malformed UDP message with no safely recoverable identity is dropped；a malformed TCP frame
  closes that connection. None performs upstream I/O.
- Admission exhaustion、deadline、selected-upstream connection/TLS/HTTP/protocol failure returns SERVFAIL
  if a safe response can be encoded. NXDOMAIN and NODATA from the selected server MUST remain
  distinguishable and MUST NOT become generic transport errors.
- TCP MUST accept multiple complete framed queries during one connection while applying the global
  in-flight ceiling and idle deadline. EOF、half frame、oversized/zero-length frame、idle、cancel and
  shutdown MUST release its permit、buffer and task.

### M12-MUST-06 — server direct domain resolution

- A server config with `[dns]` MUST use the independently selected DNS server for every authenticated
  TCP/UDP domain target. IP targets MUST bypass DNS. A config without `[dns]` MUST retain
  `SystemTcpResolver`/`SystemUdpResolver`.
- The selected DNS server's absent/present detour MUST use direct egress or its referenced server direct
  outbound respectively. The application's ordinary outbound plan and the DNS server's detour plan are
  independent even when their tags differ；the DNS answer MUST NOT replace either selection.
- Outbound route selection MUST remain before resolution and MUST see the original target. DNS answers
  MUST NOT be fed back into ordinary route matching.
- Hickory A/AAAA handling MUST return at most the existing 16 ordered `SocketAddr` candidates with the
  application target port. Empty answers、invalid RDATA and resolution errors fail before target
  connection or datagram forwarding.
- Resolution、candidate iteration and target connect/send MUST share the caller's absolute phase
  deadline. A DNS query timeout MUST NOT grant a fresh connect timeout.
- TCP and UDP paths MUST snapshot one DNS-server action per target selection. A later request or
  datagram may select another server，but an in-flight resolution never changes server.
- Client SOCKS domain targets MUST remain domain targets on the SIP022 wire. M12 MUST NOT resolve or
  replace them before Shadowsocks authentication.

### M12-MUST-07 — exact transport failure semantics

- Each tagged server has exactly one Hickory logical name-server configuration. There is no pool across
  tags，parallel race、health ordering、retry or fallback. Hickory general retry count and response cache
  capacity MUST be zero.
- A detour action MUST snapshot with existing egress semantics：UDP selects per logical query/datagram；
  a newly opened TCP/DoT/DoH flow snapshots once and a reused flow retains that concrete plan. A
  selector switch affects only later snapshots and never interrupts or migrates an existing flow.
- A UDP server MUST query its numeric address over UDP. On a valid truncated response it MAY use TCP at
  the same address、same DNS tag and same detour-plan snapshot within the original deadline. No other
  error permits transport upgrade.
- TCP、DoT and DoH use only their configured transport. DoT/DoH MUST NOT silently downgrade to plaintext.
- Hickory MUST validate upstream response source、transaction identity and protocol structure before
  response data or candidate addresses are accepted. Spoofed source、wrong ID、malformed body、unexpected
  HTTP status/content type、TLS alert and early EOF fail closed.
- One failed direct or detoured server MUST NOT update a selector、ordinary route、DNS action or
  application accepted state and MUST NOT try a different detour/member/tag. A following independent
  valid query remains acceptable.

### M12-MUST-08 — timeout、memory and admission bounds

- `dns.max_inflight` is one aggregate logical-query semaphore shared by all client DNS inbounds、server
  resolver calls and tagged servers. A query acquires before upstream work and releases on every
  terminal path.
- `dns.timeout_ms` is one monotonic absolute deadline from accepted query/resolution through final
  response/candidate result. Queue、detour selection、SIP022 connect/handshake、TLS/HTTP and target time
  all count. No nested existing timeout、retry or backoff may extend it.
- The aggregate client DNS TCP connection count MUST be capped by existing
  `runtime.max_connections`，not multiplied by listener count. Backlog、idle timeout and shutdown grace
  reuse existing validated runtime values.
- Inbound UDP allocation MUST be at most Hickory's 4,096-byte receive bound per active operation. TCP
  message allocation MUST be at most 65,535 bytes and response queues MUST have an explicit fixed depth.
  Peer lengths are validated before allocation or spawn beyond those bounds.
- Upstream connections/tasks MUST be lazy and derivably bounded by server count、fixed transport count
  and aggregate in-flight work. No task、socket、queue、cache or maximum message buffer is eagerly
  allocated per possible query.
- Detoured DNS work MUST consume existing outbound connection、UDP session、buffer-byte and live-ID
  owners in addition to DNS admission. Internal DNS UDP MUST NOT create a second unbounded session
  manager or duplicate SIP022 packet implementation.
- Saturation tests MUST prove stable owner/task/socket/buffer counts，bounded memory and recovery after
  pressure. Numeric bounds cannot be weakened by Hickory defaults.

### M12-MUST-09 — process lifecycle ownership

- Complete DNS config、rule graph、TLS identity/path and loop validation MUST finish before subscriber、
  listener、socket、upstream connection or task side effects.
- Client DNS listeners and server resolver ownership MUST be composed as existing `ProcessRoot` values
  in the same prepare/rollback/activate/quiesce/drain/stop transaction as existing roots.
- Hickory background work MUST use a ferrum2-owned runtime handle whose tasks can be counted、closed and
  awaited. Merely dropping Tokio join handles or relying on process exit is insufficient.
- Any bounded stream bridge or UDP adapter needed to satisfy Hickory's runtime interface over an egress
  plan MUST have one registered owner、fixed queue/buffer ceilings and an awaited cancellation path.
- Success、parse failure、timeout、busy、TLS/HTTP failure、TCP idle/half-frame、listener error、graceful
  shutdown and forced shutdown MUST reach zero DNS owners/tasks and permit exact UDP/TCP listener plus
  upstream endpoint rebind within the existing lifecycle deadline.
- A terminal DNS-root failure participates in existing process cause arbitration and shutdown. It MUST
  NOT leave ordinary SOCKS/Shadowsocks roots active past the supervisor outcome.

### M12-MUST-10 — bootstrap、loop and privacy closure

- No server tag、detour tag、TLS identity or DoH path may trigger system or configured DNS bootstrap.
  Every upstream uses the validated numeric address either as a direct socket target or as the final
  target carried through one selected egress plan.
- The validated graph MUST remain one-way from DNS server to outbound action. Outbound、chain and
  selector nodes MUST NOT reference DNS servers；their existing numeric endpoints and DAG validation
  MUST prevent an in-process detour cycle.
- Direct-egress self-address/wildcard alias loops and concrete first-hop listener collisions MUST fail
  config. Indirect external cycles MUST terminate by the absolute deadline and admission bound with no
  retry storm、unbounded task growth or application forwarding.
- Query names、record data、client addresses、DNS inbound/server/detour tags、bootstrap endpoints、TLS
  names、DoH paths and response payloads MUST NOT appear in metric labels. Query/answer payloads MUST
  NOT be logged.
- Runtime errors expose only closed low-cardinality role、transport、stage、reason and outcome. Debug/
  Display/panic/stderr/trace/metrics tests use sentinels to prove no operator DNS value leaks.
- DNS config values are not secrets，but they remain destination identity and cardinality-sensitive
  data under the existing observability policy.

### M12-MUST-11 — interoperability and negative evidence

- The selected external upstream profile MUST pin CoreDNS 1.14.6 plus artifact hashes/provenance and
  serve one deterministic synthetic zone over UDP、TCP、DoT and DoH. Each transport must prove positive
  A/AAAA and NXDOMAIN/NODATA handling without public-network dependency.
- The selected external client profile MUST pin BIND `dig` 9.20.26 or record an approved equivalent
  substitution. It must query ferrum2's public proxy over UDP and `+tcp`，including EDNS response-size/
  truncation behavior and cleanup.
- A real server process MUST resolve a synthetic domain through at least plaintext and encrypted tagged
  servers before actual TCP and UDP direct forwarding. Distinct answers must prove first-match rule and
  final action choice，not merely query success.
- A real client DNS proxy MUST reach CoreDNS over direct plus detoured UDP/TCP/DoT/DoH paths. At least
  one concrete、multi-hop and selector detour witness MUST prove use of the configured outbound plan，
  while a real server resolver MUST prove an explicit server-direct detour distinct from its application
  outbound action.
- Negative coverage MUST include every config bound/field pairing、unknown/wrong-role detour、direct
  loop、unknown action、first match/no fallback、detour failure/no fallback、malformed query/response、
  UDP spoof、TCP half-frame、DoT trust/name failure、DoH path/status/body failure、timeout、saturation、
  cancellation and exact rebind.
- External artifacts、test certificates/keys and zone data MUST be synthetic、reviewed and non-production.
  Unavailable artifact、provider or trust setup is BLOCKED，not PASS.

### M12-MUST-12 — exact qualification

- One accepted exact SHA MUST pass all focused config/core/DNS/client/server/process tests，repository
  Full，Rust 1.88.0，100+ lifecycle，Windows MSVC、Linux GNU and Linux musl builds，existing SIP022
  TCP/UDP `12/12` each plus cleanup，direct/detoured DNS interoperability，schema 3 footprint and
  blocking Architect/QA review.
- Performance/resource evidence is required because DNS adds UDP/TCP hot paths、TLS/HTTP connection
  ownership and process roots. It is a reproducible regression/resource result only；M12 defines no
  throughput threshold or performance claim.
- Hosted push and manual performance dispatch each require separate explicit authorization. Evidence
  MUST be bound to exact SHA/run/attempt；missing、skipped、wrong-SHA、spliced or unauthorized evidence
  blocks close.
- No PR、tag、package、release or publication is implied by M12 qualification.

## Non-goals

- Recursive or authoritative DNS、zones、updates/transfers、DNSSEC validation、mDNS、DoQ/DoH3.
- Cache、general retry、DNS-server groups/selectors、health、load balancing or fallback/failover.
- Domain suffix/wildcard/regex、CIDR、qtype、source-IP、GeoIP/Geosite、sniffing or response-based routing.
- Custom CA/insecure TLS、system roots、DoH auth/custom headers or hostname bootstrap.
- New server-side proxy outbound types；server `detour` is limited to the direct outbound actions
  already supported by that role.
- Client-side resolution of SOCKS targets、SIP022 wire changes、rule-engine replacement or new standalone
  binary.
- Hot reload、management API、transparent/TUN、package、release or publication.

## Implementation freedom

- Core may spell the shared matcher as a generic table、predicate plus selector function or equivalent
  small deep interface，provided one implementation serves outbound and DNS actions and current public
  route behavior remains exact.
- `ferrum2-dns` may use Hickory `Resolver`、`NameServerPool` and/or `CachingClient` public handles as
  needed，provided protocol/transport is not copied，cache/retry remain disabled and one tagged server
  cannot invoke another.
- A narrow Hickory runtime adapter may wrap its Tokio provider to register/await background tasks and
  delegate TCP/UDP creation to a resolved direct or existing egress-plan adapter. It must not fork
  Hickory DNS、TLS/HTTP or SIP022 code.
- Tests may inject an ephemeral TLS root and deterministic clock/transport at existing test seams. Such
  injection is selected conformance evidence and must not create an insecure product configuration.
