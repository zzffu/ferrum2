# SPEC-0007 — M6 SOCKS5 UDP ASSOCIATE

- **Status:** Approved
- **Milestone:** M6
- **Baseline:** `35354f274847d2608a2009e04aaa3b17fb4fa8f4`
- **Decision:** `docs/adr/ADR-0026-m6-opt-in-socks5-udp-association.md`
- **Test plan:** `docs/test-plans/TEST-0007-m6-socks5-udp-associate.md`

## Scope

显式启用 client UDP 时，将一个 no-auth SOCKS5 UDP association 经 configured
Shadowsocks server 的现有 SIP022 UDP path 转发到 server direct outbound；保留
schema v1 cohort、TCP `CONNECT`、three methods、wire/security 和 operator identity。

## Requirements

### M6-MUST-01 — schema v1 opt-in compatibility

- Existing client v1 documents MUST keep the same normalized TCP values、UDP-disabled
  command behavior and zero UDP startup resources。
- Client MAY add `[udp]` with existing fields/ranges。Absent section MUST disable UDP；
  an explicit section MUST default to `enabled=true`、4096 sessions、16 MiB allocated
  bytes and 300s idle；`enabled=false` MUST create no UDP socket/session/buffer。
- `--check-config` MUST validate the complete section before listeners/tasks and preserve
  stable redacted config errors。No schema v2 or heuristic fallback is introduced。

### M6-MUST-02 — control command and lifetime

- Greeting/no-auth and `CONNECT` bytes/behavior MUST remain unchanged；`BIND` remains
  `REP=07`。The existing generic core `Inbound` seam remains CONNECT-only。
- The client composition MUST recognize `CMD=03`, parse its request source hint, bind
  both association sockets and reserve bounded state before returning one success reply
  containing the actual application-facing IPv4 endpoint。
- Before reply commitment, the command path MUST use this exact closed mapping and send at
  most one request reply：

  | Condition | Observable action |
  |---|---|
  | UDP absent/disabled, or `BIND` | `REP=07` |
  | Parsed request has unsupported `ATYP` | `REP=08` |
  | Complete `CMD=03` has an invalid hint, or session/byte/random/key/socket setup fails | `REP=01` |
  | Request is truncated, control I/O fails, or handshake deadline expires before a complete request | close without a request reply |
  | Complete setup | exactly one `REP=00` with the actual relay endpoint |

  Failure while writing the selected reply MUST roll back setup and close without attempting
  a second reply。No UDP resource or success state survives a failed success-reply write。
- The association MUST terminate when its TCP control connection terminates；idle、I/O、
  cancellation and process shutdown MAY terminate it earlier and MUST close the control。

### M6-MUST-03 — standalone SOCKS UDP wire

- Request/response datagrams MUST use RFC 1928 `RSV[2]=0`、`FRAG=0`、ATYP、address、
  non-zero port and DATA；IPv4、IPv6 and 1..=255-byte ASCII domain targets MUST round-trip。
- Malformed/truncated RSV/address/port/domain、zero target port、unsupported ATYP and
  `FRAG!=0` MUST be silently dropped with no UDP reply or accepted-state mutation。
- Complete receives、SOCKS overhead and SIP022 overhead MUST remain under fixed bounds；
  IPv6 interface allowance MUST use verified erratum 3198's 22-byte SOCKS header, not 20。
- Peer length/address MUST be validated before payload ownership, SIP022 encoding,
  forwarding or input-sized allocation；responses MUST encapsulate the authenticated
  target-source address and exact payload。

### M6-MUST-04 — client endpoint authorization

- Expected source IP MUST be the control TCP peer IP。A syntactically valid request address
  MUST be advisory only: it MUST NOT replace that IP or trigger resolution。
- A non-zero requested port MUST be exact。For a zero port, regardless of valid address
  encoding, only the first fully valid, `FRAG=0`, capacity-reserved datagram from the
  expected IP MAY pin the source port。
- After pinning, all other IP/port sources MUST be silently dropped。Wrong-source、invalid,
  fragmented or saturated datagrams MUST NOT pin/roam/refresh idle or consume SIP022 IDs。

### M6-MUST-05 — SIP022 and mutation ordering

- One SOCKS UDP association MUST own one existing `UdpClientSession` for the configured
  method/PSK；all live client session IDs MUST use the existing bounded eight-draw collision
  check under one serialized registry and be removed on every terminal path。
- Requests MUST reuse `core::Datagram` and existing SIP022 encode/counter semantics；
  borrowed SOCKS decode MUST reserve runtime capacity before payload ownership and encode。
- Response preparation MUST authenticate and validate timestamp/type/address/binding into
  already charged reusable scratch, returning one opaque borrowed view over validated target/
  payload offsets without target/payload ownership allocation or replay/association mutation。
  The caller MUST reserve the exact queue/byte capacity before materializing one `Datagram`；
  materialization, atomic protocol commit, activity and enqueue MUST preserve that order before
  SOCKS response emission。
- Invalid、tampered、stale、duplicate、too-old、unbound or third-association responses
  MUST be silently dropped without plaintext、activity or client-endpoint mutation。
- The connected upstream UDP socket MUST accept responses only from configured server。
  Counter/random/key/state terminal failure MUST fail closed for the affected association。

### M6-MUST-06 — bounded runtime and shutdown

- Active associations MUST consume both the existing bounded TCP child permit and one
  `udp.max_sessions` permit；active state MUST NOT be evicted to admit another association。
- The association MUST obtain idle deadlines and manager removal/cancellation through the
  existing per-handle `UdpSessionManager` state。Only those existing operations MAY become
  public；the client MUST NOT duplicate an idle registry or generalize `DirectUdpRuntime`。
- All receive/protocol/output/queued backing capacities MUST be charged once to the existing
  global allocated-capacity budget；per-direction queues remain fixed depth four。Kernel
  buffers remain OS-bounded and are not reported as user-space accounting。
- Capacity/queue pressure MUST reject setup or silently drop only the affected datagram,
  release reservations and leave replay/endpoint/activity unchanged。
- Each association owns exactly two UDP sockets inside its supervised TCP child。Control EOF、
  reset、write-half-close、idle、application-facing/upstream socket I/O failure、child cancel、
  graceful/forced process shutdown and sibling-root failure MUST each have a bounded awaited
  path and return session ID/manager entry、permits、queues、bytes、tasks and sockets to
  baseline with immediate endpoint rebind where observable。

### M6-MUST-07 — observability and secrecy

- Existing seven UDP metric families MUST represent client role using existing closed
  directions/outcomes/reasons；existing TCP families and meanings MUST not change。
- Trace/metric identity MUST NOT contain PSK/key/nonce/wire ID、client endpoint、target、
  configured server or free-form error。Malformed/wrong-source drops must not create
  peer-controlled labels。
- Offline/disabled paths MUST expose zero active UDP sessions and zero buffered bytes。

### M6-MUST-08 — acceptance and qualification

- Focused unit/public-interface tests MUST cover command bytes、codec bounds/negative rows、
  failure replies、source pin races、collision、capacity、borrow-reserve-materialize ordering、
  one-association/multi-target behavior、idle/control/I/O/root/shutdown and secret-free telemetry。
- A composed all-method × IPv4/IPv6/domain table MUST prove the exact smaller of SOCKS and
  SIP022 payload maxima succeeds and one byte over drops before allocation、encode、send or
  accepted-state mutation；IPv6 MUST use the 22-byte corrected header。
- A bounded real-process matrix MUST cover all three methods plus focused IPv6/domain target、
  wrong-source、fragment、disabled、control-close、saturation and restart/rebind rows。
- Existing external UDP `M2-UDP-INT-001..012` MUST rerun unchanged IDs；six FerrumClient
  rows MUST use explicit client `[udp]` and the composed binary instead of the protocol
  example, while six reference-client rows remain independent cross-validation。
- One accepted exact SHA MUST pass Full、Rust 1.85、Windows/GNU/musl、external UDP
  `12/12`+cleanup、test budget and blocking review。Missing/failed/skipped/unavailable or
  unauthorized required evidence MUST block M6 close and MUST NOT be spliced with old runs。

## Non-goals

- Fragment reassembly、source-port roaming、shared public UDP listener or public IPv6 bind。
- Routing、DNS proxy/custom resolver、multi-upstream、load balancing、chaining or direct
  client outbound。
- SOCKS `BIND`、new authentication、UDP-over-TCP、SIP023/multi-user/multi-PSK。
- New dependencies、UDP throughput/10k claims、package、release or publication。
