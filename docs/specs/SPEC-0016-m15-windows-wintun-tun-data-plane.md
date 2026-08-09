# SPEC-0016 — M15 Windows Wintun TUN data plane

- **Status:** Approved
- **Milestone:** M15
- **Baseline:** `bd374c6ec47470020bfcf908aa1a3475f0b3dbf0`
- **Related:** ADR-0034、TEST-0016、SPEC-0015

## Scope

This specification defines one optional Windows NT 10.0+ AMD64 client TUN inbound backed by official
Wintun `0.14.1`。It accepts externally routed、complete IPv4/IPv6 TCP and UDP packets，runs one bounded
userspace stack，and composes the existing ordered policy、DNS answering and SIP022 egress implementations。

## Configuration

The accepted shape is additive schema version 2。Illustrative routed configuration：

```toml
schema_version = 2

[tun]
tag = "tun-in"
adapter_name = "Ferrum2"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
mtu = 1420
ring_capacity = 8388608
ready_timeout_ms = 10000
max_tcp_flows = 256
tcp_buffer_bytes = 32768
max_udp_mappings = 1024
max_udp_buffered_bytes = 16777216

[[outbounds]]
tag = "proxy"
server = "192.0.2.10:8388"

[route]
final = "proxy"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw==" # documentation-only test key
```

For static binding，`[tun].outbound = "proxy"` replaces `[route]`。The existing `[udp]` limits continue
to bound the shared SIP022 UDP manager；its `enabled` field controls only public SOCKS5 UDP exposure。
When TUN needs UDP and `[udp]` is absent，the existing validated UDP defaults are materialized internally
without enabling SOCKS5 UDP。

- `[tun]` presence MUST enable exactly one TUN inbound；`enabled` and `tunnel_type` are unknown fields。
- `[tun]` MUST be accepted only for a schema-v2 client and MUST fail closed for schema v1 or the server。
- `tag`、`adapter_name`、`ipv4_address` and `ipv6_address` are required。`outbound` is required exactly when
  `[route]` is absent and forbidden when `[route]` is present。The root `[shadowsocks].method/psk` remains
  required；the example value above is a public test key and MUST NOT be reused operationally。
- TUN-only tagged graphs MUST be accepted without a dummy SOCKS listener。For `N` declared
  `[[inbounds]]`，ordinary SOCKS IDs remain declaration-order `0..N-1` and optional `[tun]` is appended as
  ordinary ID `N`；a TUN-only graph therefore uses ID `0`。Adding/removing TUN MUST NOT renumber SOCKS，and
  DNS listener IDs remain in their separate namespace。The exact context compiled for ordinary route and
  `DnsIngressId::Ordinary` is `[[inbounds]]` in declaration order followed by `[tun]`。
- TUN and SOCKS coexistence MUST preserve one global collision domain across ordinary/DNS inbounds、
  outbounds、chains and selectors。Insertion、removal、SOCKS reorder and every cross-kind tag collision MUST
  have mutation-sensitive config tests。
- The TUN tag MUST enter the existing ordinary route and `DnsIngressId::Ordinary` namespaces。Static
  binding and ordered routing MUST use the same compiled plan graph as SOCKS。
- `adapter_name` MUST satisfy the Wintun header bound and reject NUL/control input。The fixed Wintun
  `TunnelType` is internal `Ferrum2` and is not configurable。
- `ipv4_address`/`ipv6_address` are interface address plus prefix，not canonical network addresses。They
  MUST be usable unicast host addresses and MUST reject unspecified、loopback、multicast、IPv4 network/
  broadcast values and any configured concrete proxy/DNS bootstrap address inside either interface prefix。
- Optional resource fields have the following only accepted meanings and bounds：

  | Field | Default | Accepted value | Accounting meaning |
  |---|---:|---:|---|
  | `mtu` | `1420` | `1280..=1500` | one complete IP packet |
  | `ring_capacity` | `8388608` | power of two in `131072..=67108864` | bytes in each of the two Wintun rings |
  | `ready_timeout_ms` | `10000` | `1000..=60000` | one absolute owner-thread setup/DAD deadline |
  | `max_tcp_flows` | `256` | `1..=4096` | simultaneous TUN TCP flows |
  | `tcp_buffer_bytes` | `32768` | `4096..=262144` | one smoltcp TCP buffer per direction per flow |
  | `max_udp_mappings` | `1024` | `1..=8192` | live TUN five-tuple mappings including reject tombstones |
  | `max_udp_buffered_bytes` | `16777216` | `65536..=134217728` | global owned UDP payload bytes across both directions and all mappings |

- Counts and every term/product/sum MUST use checked `u64` arithmetic。The exact validated owned-buffer budget is
  `2*ring_capacity + 2*max_tcp_flows*tcp_buffer_bytes + max_udp_buffered_bytes +
  max_tcp_flows*(mtu+1024) + max_udp_mappings*(mtu+512) + 8*mtu + 1048576` bytes。The per-flow/per-mapping
  additions reserve packet staging plus fixed metadata；the final two terms reserve eight device/channel
  packet slots and the fixed owner/control pools。No payload、socket buffer、queue or hidden pool may exist
  outside these terms without first amending this contract。Defaults evaluate to exactly `53,995,616` bytes
  and MUST remain at most `67,108,864` (`64 MiB`)；every accepted combination MUST be at most `268,435,456`
  (`256 MiB`)。RSS is measured separately and is not claimed equal to this deterministic buffer budget。
- Public stack-command/event/pending-packet queue counts MUST NOT become configuration fields in M15。
- `auto_route`、route include/exclude、bypass、strict route、system/interface DNS and WFP fields MUST be
  rejected by `deny_unknown_fields`。
- `--check-config` MUST validate shape、tags、ranges、prefixes and the complete allocation plan without
  loading/probing a DLL or driver，checking elevation，creating a thread/adapter/event/socket or mutating OS
  state。The client MUST perform a pure target/architecture gate before printing `configuration valid`。

## Artifact and platform boundary

- Only official Wintun `0.14.1` AMD64 `wintun.dll` is accepted。The ingestion ZIP SHA-256 MUST equal
  `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51` and the AMD64 DLL SHA-256 MUST
  equal `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce`。
- The executable installation directory is a trusted local boundary；a principal able to rewrite it could also
  replace the executable and is outside M15。Runtime MUST nevertheless reject UNC/network paths and every
  reparse point in the complete executable-directory and DLL path。From the fixed-volume root through the
  executable directory it MUST open each component for attributes with
  `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT`、reject
  `FILE_ATTRIBUTE_REPARSE_POINT` and hold the directory handle without `FILE_SHARE_DELETE` until unload。
- Runtime MUST derive `<current executable directory>\wintun.dll` and open that exact non-reparse regular file
  read-only with `FILE_FLAG_OPEN_REPARSE_POINT` and share mode limited to `FILE_SHARE_READ`。It MUST hash the
  exact `427552` bytes through that held handle with Windows CNG SHA-256，verify the pinned DLL hash，keep all
  file/directory handles live，then call `LoadLibraryExW` on the same absolute path with System32-only
  dependency search。Under the stated trusted-directory premise，the held handles bind hash and load against
  path retarget、replacement、truncation or rename。CWD/PATH/operator-selected/network/plugin/temp search is
  forbidden；a reparse、lock or path-identity conflict is a closed startup failure before library execution。
- Runtime MUST resolve only these eleven case-sensitive exports with the reviewed `unsafe extern "system"`
  signatures，and MUST fail closed if any is absent：

  ```text
  WintunCreateAdapter
  WintunCloseAdapter
  WintunGetAdapterLUID
  WintunGetRunningDriverVersion
  WintunStartSession
  WintunEndSession
  WintunGetReadWaitEvent
  WintunReceivePacket
  WintunReleaseReceivePacket
  WintunAllocateSendPacket
  WintunSendPacket
  ```

  No other export is resolved or called；in particular `WintunOpenAdapter`、`WintunDeleteDriver` and
  `WintunSetLogger` remain outside M15。
- Qualification MUST verify PE AMD64 identity、current-trust Authenticode status、license member、DLL hash
  and exports before placing the DLL beside the candidate。No Wintun binary enters Git or a published
  artifact in M15。
- Enabled TUN MUST fail before public service on non-Windows/non-AMD64、Windows NT below 10.0、missing or
  invalid DLL/ABI、missing privilege or unavailable driver。Existing redacted startup categories are reused。

## Exact dependency graph

The `ferrum2-wintun` target-specific direct edge MUST be
`windows-sys = { version = "=0.61.2", default-features = false, ... }`，reuse the existing lock identity and
list exactly these eight features：

```text
Win32_Foundation
Win32_Storage_FileSystem
Win32_System_LibraryLoader
Win32_System_Threading
Win32_Security_Cryptography
Win32_NetworkManagement_IpHelper
Win32_NetworkManagement_Ndis
Win32_Networking_WinSock
```

The direct edge MUST be `smoltcp = { version = "=0.13.1", default-features = false, ... }`，resolve as exactly
one lock identity and list exactly this literal feature array：

```text
std
medium-ip
proto-ipv4
proto-ipv6
socket-tcp
socket-tcp-reno
socket-udp
iface-max-addr-count-2
iface-max-route-count-2
assembler-max-segment-count-4
```

The positive `auto-icmp-echo-reply` feature MUST be absent。No fragmentation/reassembly、ICMP/raw socket、
Ethernet/802.15.4、Cubic or host-device feature is accepted。
Existing workspace consumers already unify additional `windows-sys 0.61.2` features onto the same package。
Workspace policy MUST therefore prove the new direct edge's literal eight-feature/default-off declaration and
that M15 adds no resolved `windows-sys` feature outside Cargo's dependency-defined transitive closure of that
allowlist；it MUST NOT assert that the complete pre-existing workspace union contains only eight。It MUST
separately prove the exact smoltcp feature array and one `smoltcp 0.13.1` package。

Rust `1.97.1` MUST be the exact workspace `rust-version`、selected toolchain and CI MSRV selector。This is the
latest stable release verified on the 2026-08-09 planning date，not a floating Cargo/rustup channel。All
workspace-policy source and metadata assertions MUST reject `1.88.0`、the dependency-minimum `1.91`、a
different numeric version and any `stable`/`latest`/beta/nightly selector。A future Rust release MUST NOT
silently change this contract；it requires an explicit control amendment and fresh dependency/platform review。

## Lifecycle and ownership

- `prepare` MUST first start the final stack-owner thread，then await one bounded acknowledgement。Only that
  thread may verify/load the DLL，create a new adapter，obtain identity，snapshot/set IPv4 and IPv6 MTU
  separately，create the two exact addresses，wait DAD，start the session and construct smoltcp behind its
  own reverse journal。Setup failure MUST complete that journal and exit before `prepare` reports failure；
  successful setup MUST acknowledge before the same absolute `ready_timeout_ms` deadline。
- The async prepare side MUST retain a drop guard from thread spawn through successful root handoff。Timeout、
  cancellation or unwind before handoff MUST signal the same rollback command and reap the owner；a detached
  setup/owner thread is never an accepted failure result。
- Address readiness means both exact rows have `DadState == IpDadStatePreferred`。`Tentative` continues to
  wait only until the absolute deadline；`Duplicate`、`Invalid` or `Deprecated` fail immediately。Timeout or
  row disappearance fails setup and enters the same thread-owned rollback path。
- No flow or mapping may be admitted during prepare。Synchronous `activate` MUST be non-blocking and may
  only open the admission gate；it MUST NOT perform Win32 calls or wait for the owner thread。
- Readiness MUST be a fixed low-cardinality state after activation；it MUST NOT emit adapter name/index、
  address、target、route、tag or secret。External controllers may discover the configured adapter by their
  own OS query before adding owned narrow routes。
- The created adapter MUST never fall back to opening/reusing an existing adapter。Same-name collision is
  a closed startup failure and MUST leave the existing adapter unchanged。
- Quiesce MUST reject new TCP flows and UDP mapping commitments while polling existing TCP state until the
  process grace deadline。Forced stop is the only phase allowed to discard retained TCP bytes。
- Shutdown/rollback MUST signal the owner thread's separate stop event，wake it from
  `WaitForMultipleObjects`，and let that same thread stop polling/release any current RX packet before it
  ends the session。The thread then deletes only exact created addresses，conditionally restores each family
  MTU without overwriting a detected third-party change，closes the created adapter，unloads the DLL，closes
  owned control handles，reports cleanup and exits。The async root MUST join only after that exit。Cleanup
  conflict/failure MUST surface as `shutdown.cleanup` while the owner still attempts every later step。
- `WintunCloseAdapter`'s void return is not sufficient evidence of deletion。Privileged postconditions MUST
  prove adapter、address、expected OS-managed route rows、session、HANDLE、thread、flow、mapping、queue and
  buffered-byte owners return to the exact baseline and the name can be rebound。
- Product code MUST NOT call any explicit Windows route、DNS or WFP mutation API or delete an external
  route。Address-derived connected/local rows are OS-managed and MUST disappear after owned cleanup。

## Packet and stack boundary

- Exactly one synchronous owner thread MUST own Wintun library/adapter/session/read event，smoltcp
  `Interface`/`SocketSet`，clock/timers，flow/mapping tables and all packet staging for their full lifetime。
- A Wintun RX pointer MUST remain on that thread and inside one receive-token consume lifetime；it MUST NOT
  cross a channel、thread、future or await。The session read event MUST never be closed by Ferrum2。
- Before smoltcp ingress，one shared validator MUST enforce all of the following：packet length is within MTU；
  source and destination are non-unspecified unicast；IPv4 is exactly version 4/IHL 5 with declared total
  length equal to the received length，valid header checksum，reserved bit zero，`MF=0`，fragment offset zero
  and protocol directly `6` or `17`；IPv6 is exactly version 6 with `40 + payload_length` equal to the
  received length and base `Next Header` directly `6` or `17`。IPv4 options and every IPv6 extension header
  are therefore unsupported；the validator MUST NOT walk an extension chain。Base-header values `0`、`43`、
  `44`、`50`、`51`、`59`、`60`、`135`、`139`、`140`、`253` and `254` are explicit reject rows，regardless
  of whether the following bytes are absent、truncated、well-formed or begin another extension。
- TCP source/destination ports MUST be non-zero，data offset MUST be at least 5 and within the IP payload，
  and its checksum MUST be valid。UDP ports MUST be non-zero，length MUST equal the complete IP payload and
  be at least 8；IPv4 UDP checksum zero is accepted and any non-zero value MUST validate，while IPv6 UDP
  checksum zero is rejected and every accepted value MUST validate。Any truncation、trailing byte、fragment、
  ICMP or other protocol is dropped before flow/mapping/policy state。
- After smoltcp TX materializes an owned packet and before Wintun send，the owner MUST run the same byte-level
  validator。No IP option、IPv6 extension、fragment、ICMP or other protocol may reach Wintun TX。
- smoltcp MUST use `Medium::Ip`，two interface addresses，`set_any_ip(true)` and exactly two non-expiring
  in-memory routes：`0.0.0.0/0` via the configured IPv4 interface address and `::/0` via the configured IPv6
  interface address。The route capacity is exactly two and a third insert MUST fail。These routes only make
  original unicast destinations local to smoltcp；they are not Windows routes and invoke no OS route API。
  No Ethernet、ARP or NDISC behavior enters the stack module。
- The owner MUST use bounded `poll_ingress_single` work rather than the unbounded `Interface::poll` loop，
  processing at most eight ingress packets before checking stop/control/timers again。
- RX/TX staging、socket tables、channels and IDs MUST be prebounded by the validated memory plan。Stale IDs
  MUST contain/use a generation and fail closed without touching a reused slot。
- Wintun TX ring-full MAY drop one materialized IP packet。TCP relies on its stack retransmission；UDP records
  a fixed drop。There is no unbounded pending-TX queue。
- Fatal Wintun/session/thread/stack invariant failure MUST terminate the required process root。Malformed
  peer input、capacity rejection and per-flow selected failure remain local and MUST NOT restart policy。

## TCP behavior

- One validated IPv4/IPv6 TCP five-tuple MUST create at most one non-cloneable flow with an immutable numeric
  original target。Flow admission MUST respect `max_tcp_flows` before socket/task/buffer creation。
- The local userspace stack MUST complete the application-side handshake independently of upstream open。
  A terminal reject or selected route/DNS failure after that point MUST close/reset the local flow；it MUST
  NOT evaluate another rule、final、selector member or retry。
- Client TCP `sniff` rules MUST be accepted only when their possible inbound set contains TUN and excludes
  SOCKS inbounds。Wildcard/mixed rules that could require SOCKS pre-route bytes MUST fail configuration。
- TUN TCP sniff MUST reuse the existing pure parser and bounded absolute-deadline prefix collector。Every
  collected byte MUST enter the selected route or DNS framing path exactly once。
- `route` MUST open the one selected owned egress snapshot through existing `ClientEgressEngine::open_tcp`
  and relay through the existing lifecycle。`hijack-dns` MUST use existing bounded DNS-over-TCP framing and
  `DnsProxy::answer` without creating a Shadowsocks flow。`reject` MUST create no egress owner。
- Stack-to-Tokio saturation MUST stop consuming the smoltcp receive buffer so the advertised TCP window
  applies backpressure；Tokio-to-stack writes MUST retain unsent remainders and preserve order。FIN MUST be
  ordered after accepted bytes；half-close、reset、idle、cancel and force MUST be bounded。

## UDP behavior

- One validated IPv4/IPv6 UDP five-tuple is the mapping identity；the target is immutable。Expired mappings
  are reclaimed before admission；a full table drops a new candidate and MUST NOT evict a live mapping。
- For an absent tuple，`ferrum2-tun` MUST expose one provisional owned candidate datagram and immutable tuple
  to the client caller without inserting a mapping。The caller evaluates the existing terminal policy and
  selected-plan payload bound，keeps route/hijack/reject mode and plan state client-side，then returns either
  `commit(opaque_terminal_token, payload_bound)` or `drop without commit`。Only the owner thread applies that
  result，rechecks tuple generation/capacity and atomically inserts the token mapping before releasing the first
  datagram with that token；stale or duplicate decisions fail closed。`ferrum2-tun` MUST treat the token only as
  an opaque correlation capability and MUST NOT observe a route plan、DNS action、reject mode or credential。
- A classification candidate MUST pass source/IP/UDP/port/checksum/MTU/fragment checks and selected
  terminal-action payload bounds before committing mapping state。Temporary route/selector/plan resolution
  needed for a chain-specific bound is permitted but is not a commit。
- An over-limit、queue-full or capacity-rejected first candidate MUST create no terminal mode、accepted
  activity、association、SIP022 session/live ID、socket or send。A later valid candidate for the tuple MUST
  evaluate current route/selector state again。
- The first classification-eligible datagram MUST commit exactly one `route`、`hijack-dns` or `reject`
  mapping mode。Later datagrams MUST NOT run ordinary route or selector again；mapping expiry permits a new
  candidate and current selection。
- `route` MUST create exactly one existing `ClientUdpAssociation` with one owned plan and use one shared
  ingress-neutral request/response transition。Every response MUST satisfy the association's existing
  authenticated target/session binding and the live mapping generation before injection。
- `hijack-dns` MUST call the existing `DnsProxy::answer` for each accepted DNS request；ordinary policy does
  not re-enter，malformed DNS does not fall back，and no Shadowsocks state is created。
- `reject` MUST retain only a bounded terminal tombstone needed to prevent policy re-entry；it creates no
  egress/session/socket owner。
- Per-mapping order MUST be preserved。UDP queue/ring saturation drops a complete current datagram with a
  fixed reason and does not update accepted activity。Mapping idle uses the existing validated UDP idle
  lifetime；graceful/forced shutdown reaps every mapping and retained datagram。
- Because fragments are unsupported，the maximum TUN UDP payload is the configured MTU minus the exact IP
  and UDP headers。Larger application datagrams fail by fragment drop；M15 makes no 65,507-byte TUN claim。

## Compatibility, security and diagnostics

- TUN omission MUST preserve schema-v1/v2 acceptance、SOCKS TCP/UDP、server behavior、DNS、selectors、chains、
  SIP022 wire/crypto/replay and M0～M14 lifecycle/observability exactly。
- The existing M14 classification contract is clarified：a selected-plan payload check may read ephemeral
  selector state，but rejected over-limit candidates commit nothing and a later candidate observes the then-
  current selector。TUN and SOCKS evidence MUST prove this ordering。
- `ferrum2-wintun` is the sole documented unsafe source exception。`ferrum2-tun` MUST NOT depend on config、
  DNS、Shadowsocks or a binary；the client TUN adapter MUST call the one existing policy、DNS and egress
  implementations。No second route/DNS/SIP022 parser or codec is permitted。
- Errors MUST use existing redacted config/startup/runtime/shutdown categories。Raw Win32/Wintun strings、
  DLL paths、adapter identity、targets、packets and route rows MUST NOT enter `Display`/`Debug`/telemetry。
- Metrics/traces MAY add only closed inbound/stage/reason values and fixed counters for packet/drop/lifecycle
  outcomes。No destination、address、name、tag、rule or dynamic identity label is permitted。

## Non-goals

- Product-managed capture/default/bypass routes、system DNS、WFP、strict route、network monitoring or
  full-tunnel safety。
- ICMP、fragment reassembly、Fake-IP、process routing、QUIC/HTTP3、raw packet filters or multiple TUNs。
- Non-Windows TUN、Windows non-AMD64 qualification、driver build/delete、existing-adapter reuse、installer、
  service、auto-elevation、DLL redistribution、package、release or publication。
- Public device/flow factory、dynamic backend registry、multi-thread/sharded stack or zero-copy claim。
