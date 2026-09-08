# F2P: TCP-carried proxy protocol

## Scope and status

Implemented on 2026-09-08 and exercised through real loopback client/server binaries; this is not a claim of measured superiority. F2P supports application TCP and UDP over TCP. The only carrier is TLS 1.3 over TCP. No general Transport registry, WebSocket/gRPC carrier, TUIC implementation, TLS bypass, or native UDP listener is introduced. Existing Shadowsocks remains a separate supported protocol. Profiles are `balanced` (default) and `realtime`; they do not weaken security or change advertised UDP capability.

## Module ownership

`ferrum2-f2p` is the deep protocol module. It owns TLS configuration, authenticated handshakes, target encoding, error replies, UDP framing, session IDs, bounded queues, bidirectional profile scheduling, and owned tunnel tasks. It receives already-connected asynchronous streams and injected destination UDP operations; it never resolves application domains, selects routes, or creates physical sockets itself. It depends on the existing core address and endpoint contracts, not Shadowsocks.

The client egress engine selects F2P alongside Direct and Shadowsocks for SOCKS, TUN, DNS and RuleSet consumers. It owns one lazy UDP tunnel pool per outbound identity. Two configured outbounds never share a pool even with identical server addresses and credentials. All physical TCP connections pass through the existing network socket service and outbound dial policy. Generation changes retire old tunnels and sessions; later traffic establishes new ones, without replaying old datagrams.

Pooled connections are created on the process runtime captured during startup, including physical socket registration, TLS and the tunnel driver. They must not inherit the first SOCKS connection's shorter-lived affine reactor. A cancellable dial owner prevents an abandoned admission from detaching a connection attempt. TCP, TLS, framing and server UDP operations have separate private implementation modules; only the protocol's small interface is exported.

Process-level cleanup drains F2P pools on every platform before final ownership checks, then executes any native network cleanup. It does not depend on the Windows-only network root. `ClientTunnel::shutdown` cancels and joins the driver; concurrent shutdown waits serialize and retain join custody if a waiter is cancelled.

The server listener dispatches by configured inbound protocol, never by unauthenticated guessing. Its F2P adapter uses the existing inbound identity, rule engine, direct resolver, socket service, cancellation and connection supervisor. TCP and UDP target policy is checked before external connection/send. UDP classification has access to the first payload for existing sniff rules. Reject remains reject; no fallback to Direct. F2P target connections cannot silently bypass configured routing.

Configuration owns validated paths and options, not live TLS objects. Startup loads secrets and certificates before listener readiness. F2P-only servers do not require a dummy Shadowsocks key. Existing global Shadowsocks settings are required only when a Shadowsocks listener exists. Unknown or inapplicable protocol fields are rejected.

## Security

TLS 1.3 only, ALPN `f2p/1`, normal server-name and certificate validation. Without `ca_file`, public WebPKI roots are used; a configured CA PEM replaces that root store. There is no insecure verifier. Certificates and keys use PEM, parsed with rustls PKI types. Authentication uses a file containing one base64-encoded 32-byte random token, retained in zeroizing storage and compared with the pinned `constant_time_eq` fixed-size primitive. Credentials, peer targets and certificate contents never appear in errors or Debug output. TLS early data is disabled. Authentication completes before any target operation. Handshake/connect/write-stall deadlines and cancellation bound pre-relay work.

## Wire and lifecycle

Versioned authenticated startup identifies TCP versus UDP and the profile. Lengths and discriminants are strictly validated before allocating. IPv4, IPv6 and bounded core domain targets retain existing port-zero rejection and redacted formatting.

TCP startup includes the target and has two responses. First, the server acknowledges authenticated request admission; the client then exposes a writable stream. The server can read the first application bytes for existing sniff-before-route policy before connecting any target. Second, `respond_tcp` reports target success (including its socket endpoint) or failure. The client stream consumes this bounded response before exposing application response bytes; target failures become stream errors. This preserves existing SOCKS-over-Shadowsocks admission semantics: SOCKS success is not proof that the ultimate target connected. Waiting for target success before allowing client writes would prevent ordinary SOCKS applications from supplying the bytes required by server sniff rules, so that alternative is rejected.

After the target response, TCP is a bidirectional byte stream without per-chunk F2P frames. Normal write-half shutdown drains pending TLS bytes and sends close-notify without discarding the readable half; fatal errors terminate the connection. No cross-application TCP multiplexing.

UDP mode multiplexes fixed-target sessions. The fixed header is 8 bytes: type:u8, flags:u8 (zero), body_length:u16 big-endian, session_id:u32 big-endian. Control types are OPEN, OPEN_RESULT, DATA, CLOSE, PING, PONG. ID zero is connection control only; client session IDs increase monotonically and are never reused within a tunnel. Exhaustion requires another tunnel. Each DATA frame is exactly one complete datagram; empty payloads are valid. There is no application-layer retransmission, ACK, reordering or fragmentation. Oversized datagrams are rejected before writes.

OPEN carries a target. The client may pipeline the first DATA without waiting for OPEN_RESULT. The server may defer destination creation until that first payload, allowing existing payload-aware policy. Pending opens and payloads are bounded and time out. OPEN_RESULT reports the resolved fixed peer endpoint or a closed failure code. A successful destination uses a connected UDP socket, preserving reply/session attribution. Different local sources targeting the same endpoint remain different sessions. CLOSE releases the session and all queued ownership. Unknown, closed or late session traffic cannot create a session or reach another target; structurally invalid frames fail the tunnel. Remote target failures are session-local. A tunnel failure invalidates every contained session. Old queued datagrams are never replayed after reconnect.

The parser retains partial header/body progress across cancellation of a receive wait. Likewise a partially written frame is completed or the entire tunnel is closed; it is never skipped. Background tasks have explicit abort/drain ownership and cannot keep an otherwise dropped pool alive indefinitely.

## Profiles and resource accounting

Both profiles batch only already-ready data, never wait on a batching timer, and schedule fairly across ready UDP sessions. `balanced` allows a larger bounded write turn and more buffering for bursts. `realtime` uses smaller write turns and tighter per-session queue residence/buffer budgets. Both client requests and server responses obey the authenticated profile. Profile policy constants are initial engineering choices, not benchmark-derived optimal values; document exact implemented values with verification results.

Queues have session, tunnel and aggregate byte bounds, including pending opens and control admission. Empty datagrams also consume nonzero accounting overhead. Allocation capacity, not merely payload length, must be accounted where ownership retains larger buffers. F2P must not add an unaccounted queue beside the existing UDP runtime budget; share a budget or reserve a bounded sub-budget from it. External socket/TLS buffers are separately bounded overhead, not falsely included in an application-buffer metric.

Expired UDP data may be dropped only before commitment to TLS/TCP. Expiry cannot retract bytes already in TLS or the kernel. Overflow does not block every receiving session indefinitely, and one stalled destination cannot stop tunnel parsing. Queue policy is explicit; it does not promise freshness beyond the proxy-controlled queue. TCP flows retain byte-stream reliability and are not subject to datagram expiry.

Client pooling currently uses one lazy tunnel per outbound identity, with fixed session-to-tunnel assignment and no warm connection. Two configured profiles/outbounds remain isolated. This is a conservative implemented policy, not a claim that one tunnel is optimal. The profile is the only public tuning control; there are no worker, batch, TLS-record, socket-buffer or tunnel-count knobs.

| Initial UDP policy | balanced | realtime |
|---|---:|---:|
| Per-session queued-byte ceiling | 256 KiB | 128 KiB |
| Maximum proxy queue residence | 250 ms | 25 ms |
| Already-ready write turn | 32 frames / 256 KiB | 4 frames / 16 KiB |
| Client tunnel reservation ceiling | 262,028 bytes | 131,014 bytes |

One indivisible datagram may exceed a write turn's byte ceiling. A client tunnel's actual reservation is also capped at one quarter of the configured global budget. Logical sessions are bounded by the configured session count and 256 per client tunnel; one SOCKS association retains at most 256 fixed targets, with both original and canonical domain storage accounted. Session-local remote failure or overflow drops only the current uncommitted datagram, not other targets in the association.

Client target storage grows on demand rather than allocating and reserving all 256 entries. Growth funds the complete replacement vector while the old allocation is still charged; allocation/admission failure leaves existing sessions intact. Retained backing capacity remains charged after target removal. Original and canonical domain strings, staged replacements, and temporary OPEN clones have their own lifetime-bound reservations. Established target requests reuse the retained entry without cloning its domain strings per datagram.

Server F2P tunnels reserve up to one quarter of the same runtime byte budget used by native Shadowsocks UDP, capped at 1 MiB per tunnel. Every OPEN acquires an aggregate session reservation before allocating its worker, including the pending-first-DATA phase; successful connect transfers that reservation into the socket lease. The configured global minima remain valid for mixed-protocol servers. Pending OPEN metadata is also bounded within the reserved tunnel budget. A F2P tunnel allows at most 64 logical sessions, additionally bounded by configuration and available bytes. Exhaustion rejects admission rather than allocating outside the budget.

The protocol charges 4096 base bytes, 2048 bytes per live session, exact boxed payload length plus 256 bytes per retained packet (including empty, control and in-flight packets), and 65,764 bytes for one reusable server receive scratch per tunnel. An idle session waits for socket readiness without owning a large buffer. Ready sessions borrow the shared 65,508-byte scratch only for synchronous nonblocking receive and packet materialization; no await holds the scratch. False readiness releases it before waiting again. The extra byte detects over-limit datagrams: 65,507-byte and empty responses remain valid, while oversized responses close only their session. The scratch retains the aggregate reservation owner until its allocation and charge are destroyed. Application-buffer metrics include the server/client tunnel reservations, not a false claim of exact TLS/kernel/task memory. No profile eliminates TCP head-of-line blocking.

Both adapters move their actual aggregate byte reservations into protocol-owned shared state. Workers and surviving session handles retain that state until actual destruction; aborting a Tokio task cannot prematurely release its byte reservation. Normal server exit aborts and joins its worker set before returning. Cancellation aborts the workers while their retained reservation guards continue to cover allocations until those workers are destroyed.

## Configuration shape

Keep schema-v2 TOML and tagged inbounds/outbounds. Client F2P outbounds add `type = "f2p"`, `server`, optional `profile`, `[outbounds.auth] token_file`, and `[outbounds.tls] server_name` plus optional `ca_file`. Server F2P inbounds add `type = "f2p"`, `[inbounds.auth] token_file`, and `[inbounds.tls] certificate_file` / `private_key_file`. Existing route tags and global UDP enablement/resource ceilings remain applicable. No `transport = "tcp"` or protocol capability booleans. Global UDP enabled is administration, not capability negotiation. Illegal protocol composition must be rejected during validation, not panic at runtime; existing Shadowsocks chains remain valid and F2P is a standalone proxy hop in this implementation.

Matching examples: [client](../examples/client-v2-f2p.toml) and [server](../examples/server-v2-f2p.toml). Paths are working-directory-relative. Supply your own matching token files, certificate chain and private key before running; examples contain no usable credentials. `server_name` must match the certificate. Use `profile = "realtime"` on a separate tagged outbound to isolate latency-sensitive traffic; existing entry/target rules select that outbound, with no automatic game detection.

From the repository root:

```text
cargo build -p ferrum2-client -p ferrum2-server --bins --locked
cargo run -p ferrum2-client --locked -- --config docs/examples/client-v2-f2p.toml --check-config
cargo run -p ferrum2-server --locked -- --config docs/examples/server-v2-f2p.toml --check-config
cargo run -p ferrum2-server --locked -- --config docs/examples/server-v2-f2p.toml
cargo run -p ferrum2-client --locked -- --config docs/examples/client-v2-f2p.toml
```

Run the last two commands in separate terminals after provisioning credentials. Offline checking validates structure without reading credential files; materialization/startup loads them before listeners become ready. Mixed listeners retain global `[shadowsocks]` credentials only for Shadowsocks listeners. A F2P-only server requires no Shadowsocks key.

## Implementation interface contract

The protocol exports `Profile::{Balanced, Realtime}`; `ClientConfig::load(token_file: &Path, server_name: &str, ca_file: Option<&Path>) -> io::Result<Self>`; `ServerConfig::load(token_file: &Path, certificate_file: &Path, private_key_file: &Path) -> io::Result<Self>`. Configs are immutable and shareable. `connect_tcp(io, &ClientConfig, Profile, &TargetAddr)` returns `ClientStream<S>`, and `connect_udp(io, &ClientConfig, Profile)` returns an authenticated client stream. `accept(io, &ServerConfig)` returns `Accepted::{Tcp { stream, target, profile }, Udp { stream, profile }}`. `respond_tcp(&mut ServerStream<S>, Result<SocketAddr, ConnectErrorKind>)` completes the TCP reply. Streams implement Tokio AsyncRead/AsyncWrite and the core LocalEndpoint/AbortiveClose contracts when their input does. Protocol adapters must preserve generation fences of the supplied stream.

UDP exports `Limits { max_sessions: usize, max_buffered_bytes: usize, idle_timeout: Duration }`, fallible `ClientTunnel::start(stream, profile, limits, resources)`, asynchronous `ClientTunnel::open(target) -> io::Result<ClientSession>` (admission only, without waiting for the remote OPEN_RESULT), `is_closed`, and `close`. The `resources: Send + Sync + 'static` argument owns the caller's aggregate byte reservation. Session asynchronous send/receive are `send(&self, payload: &[u8]) -> io::Result<()>` and `receive(&mut self, destination: &mut [u8]) -> io::Result<(usize, SocketAddr)>`; `poll_receive` supports fair multi-target scanning without one task per client session. Session drop closes its ID. Tunnel drop/close cancels its owned driver.

The asynchronous `ClientTunnel::shutdown() -> io::Result<()>` is the explicit drain operation for process owners. `close`/drop remain cancellation operations; callers that require the stream to be destroyed before checking ownership must await `shutdown`.

The server entry point is `serve_udp(stream, profile, limits, backend, resources)`, with normal worker drain and cancellation-safe reservation retention. `UdpBackend: Send + Sync + 'static` has associated `Socket: UdpSocket` and `Reservation: Send + 'static`. `reserve_session` acquires aggregate capacity synchronously at OPEN; `connect(&self, reservation, target, first_payload)` applies routing and transfers that reservation into the returned socket. Reservation drop must release capacity on every rejection or cancellation path. `UdpSocket: Send + Sync + 'static` exposes fallible `peer_addr`, asynchronous `send -> io::Result<()>`, and asynchronous `receive -> io::Result<usize>`. Destination policy, session admission and physical socket generation handling belong to its implementor. The UDP driver sends the initial payload after backend connect; backends must not duplicate it.

## Verification and honest performance claims

Run real unprivileged client/server loopback forwarding through SOCKS TCP and SOCKS UDP for both profiles, including simultaneous distinct UDP sessions, zero-length data, domain targets, rejected targets, wrong credentials, certificate verification failure and clean shutdown. Keep deterministic regressions for fragmented/coalesced frames, partial-write cancellation, half-close, session isolation, bounded queues, profile fairness/expiry and tunnel failure. Ordinary client tests are compile-only per repository rules; use the actual binaries or m0 harness for execution. No privileged TUN or host-network changes are authorized by this work.

Measure TCP throughput and game-like UDP RTT under concurrent traffic with fixed payload/count and disclose loopback-only scope. These smoke measurements do not qualify lossy WAN/game performance. TCP head-of-line blocking remains inherent in UDP over TCP, including nested QUIC. Full WAN loss/RTT qualification is a separate environment requirement, not a reason to label this implementation faster without evidence.

### Local evidence, 2026-09-08

Real-binary regressions cover both profiles, TCP half-close, domain targets, distinct UDP sources sharing one destination, multiple destinations per SOCKS association, zero-length datagrams, HTTP-sniff rejection before target connect, session-local UDP rejection, token/name failures, mixed-protocol minimum resource limits, and graceful shutdown. The delayed-first-read reply regression failed before fixing timeout ordering and passed afterwards. The first real UDP shutdown run exposed the cached tunnel's incorrect affine-reactor lifetime; the process-reactor implementation passed the same graceful-shutdown check.

A throwaway, subsequently removed, mixed-load smoke used debug binaries on Windows loopback: 200 sequential 64-byte UDP echo requests after three warmups, 1 ms sleeps between requests, concurrent 32 MiB TCP upload followed by its complete echo. There was one run per profile, without WAN delay/loss injection or a Shadowsocks baseline.

These measurements preceded the final aggregate-admission and cancellation-guard refinements. They are historical development smoke observations, not a benchmark of the final revision.

| Profile | UDP p50 | UDP p99 | UDP max | TCP aggregate echo throughput |
|---|---:|---:|---:|---:|
| balanced | 0.372 ms | 0.478 ms | 1.142 ms | 135.69 MiB/s |
| realtime | 0.367 ms | 0.537 ms | 0.541 ms | 88.50 MiB/s |

TCP throughput counts 64 MiB aggregate application bytes, not 32 MiB of one-way throughput. Scheduling and warm-cache differences are uncontrolled; these observations do not establish a profile winner, performance improvement or game/WAN suitability. They prove the mixed paths execute, not that this protocol is faster than another.

### Executed verification

Windows MSVC gates completed: 458 tests across the affected protocol/config/runtime/observability/DNS/server packages, plus 38 cross-process and workspace-contract tests. Client tests were compiled with all features, not executed. The affected all-target/all-feature Clippy gate and workspace formatting check passed. Both documented example configurations passed offline validation without credential files.

```text
cargo test -p ferrum2-f2p -p ferrum2-config -p ferrum2-runtime -p ferrum2-observability -p ferrum2-dns -p ferrum2-server --locked
cargo test -p ferrum2-client --all-features --no-run --locked
cargo build -p ferrum2-shadowsocks --example udp_protocol_client --locked
cargo test -p ferrum2-m0-harness --test f2p_local_e2e --test local_e2e --test socks_udp_local_e2e --test tcp_routing_e2e --test workspace_policy --test cli_contract --locked -- --test-threads=1
cargo clippy -p ferrum2-f2p -p ferrum2-config -p ferrum2-runtime -p ferrum2-observability -p ferrum2-dns -p ferrum2-client -p ferrum2-server -p ferrum2-m0-harness --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
```

The initial Windows-hosted Linux cross-check could not reach Rust integration checking: the default build lacked `x86_64-linux-gnu-gcc`; retrying with LLVM failed building `ring` because the Linux C sysroot (`assert.h`) was missing. Native Linux verification below supersedes that coverage gap without claiming that the Windows-hosted cross compiler has been installed. No privileged TUN/host-network qualification or lossy-WAN qualification was performed.

### Native Linux verification, 2026-09-08

The existing WSL2 Debian installation already contained GCC 14.2.0 (`x86_64-linux-gnu`), `libc6-dev`, `build-essential`, and Rust 1.97.1. No compiler package reinstall was needed. Builds ran natively in Debian, with an isolated Linux target directory instead of reusing Windows artifacts.

The first real-binary run reproduced a Linux-only cleanup failure: the client retained its 262,028-byte UDP tunnel reservation because no Windows network cleanup owner existed. Client process-resource cleanup now drains F2P pools on all platforms, before optional native cleanup. The original four real-binary regressions passed after this fix; the added protocol regression verifies that concurrent shutdown calls return only after the peer observes stream closure.

Results: both Linux binaries built successfully; 17 F2P protocol tests, 4 F2P real-binary tests, and 2 Direct UDP process/support tests passed. The build still reports five TUN dead-code warnings and one server unused-import warning; it is not a warning-free Linux Clippy qualification.

Commands, from the repository root inside Debian:

```sh
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_TARGET_DIR="$HOME/.cache/ferrum2-linux-target"
cargo +1.97.1 build -p ferrum2-client -p ferrum2-server --bins --target x86_64-unknown-linux-gnu --locked
cargo +1.97.1 test -p ferrum2-f2p --target x86_64-unknown-linux-gnu --locked
cargo +1.97.1 test -p ferrum2-m0-harness --test f2p_local_e2e --test socks_udp_local_e2e --target x86_64-unknown-linux-gnu --locked -- --test-threads=1
```

### UDP capacity optimization

A before/after native WSL2 Debian loopback probe used the same synthetic TLS credentials, real client/server binaries, 8 MiB global UDP budgets, one 1 MiB server tunnel partition, and sequential four-byte datagrams to up to 64 fixed IPv4 targets. Every admitted target was exercised again before teardown, so the count does not include evicted sessions.

| Measurement | Before | After |
|---|---:|---:|
| Balanced established and rechecked targets | 15 | 64 |
| Realtime established and rechecked targets | 15 | 61 |
| Balanced client bytes, one single-target association | 472,941 | 327,615 |
| Balanced client bytes, four single-target associations | 1,105,680 | 524,376 |
| Incremental budget per single-target association | 210,913 | 65,587 |

The realtime result is bounded by its unchanged 131,014-byte client tunnel reservation: 61 live sessions charge 124,928 bytes plus the 4096-byte base, leaving less than another session's 2048-byte admission cost. Profiles and partition sizes were not enlarged for the comparison. These are budget/capacity measurements, not RSS, throughput, p99 latency, WAN, or privileged TUN performance claims.

The temporary metrics probe was removed after recording the result. Permanent regressions cover forty simultaneously live responders plus a false-ready idle socket within 1 MiB, full/empty/oversized replies, reservation destruction and cancellation, and six real SOCKS/F2P associations forwarding and rechecking domain-addressed UDP under a 1 MiB client budget in both profiles.

Post-change verification passed: Linux ran 21 F2P protocol tests, 170 runtime tests, 5 F2P real-binary tests and 2 Direct UDP process/support tests. Windows ran 253 affected-package tests and the same 5 F2P real-binary tests; the client all-feature test binary was compile-checked without executing its platform-dependent suite. Strict all-target/all-feature Clippy passed for the affected Windows packages and for F2P/runtime under Linux; workspace formatting passed. The previously noted Linux binary-build warnings remain, so this does not claim whole-workspace warning-free Linux qualification.
