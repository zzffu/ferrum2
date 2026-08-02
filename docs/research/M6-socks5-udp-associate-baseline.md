# M6 SOCKS5 UDP ASSOCIATE 规范与互操作基线

- **Status:** Planning research baseline
- **Date:** 2026-08-02
- **Milestone:** M6
- **Planning baseline:** `35354f274847d2608a2009e04aaa3b17fb4fa8f4`

## 结论

M6 应在既有 no-auth SOCKS5 profile 上增加 RFC 1928 `UDP ASSOCIATE`，每条
TCP 控制连接绑定一个独占的临时 IPv4 UDP relay socket，并通过一个连接到固定
Shadowsocks server 的 UDP socket 和一个既有 `UdpClientSession` 转发。该选择不需要
共享 UDP listener、按客户端地址做全局 demux、routing、客户端 DNS 或新依赖。
旧的 client schema-v1 配置若没有 `[udp]` 必须保持 UDP disabled；显式 `[udp]` 是唯一
启用入口，表内既有 `enabled=false` 仍可作为显式关闭开关。

必须独立于参考实现落实以下安全语义：TCP 控制连接结束即关闭 association；只接受
TCP peer IP；只向实际观察并锁定的 client UDP endpoint 回复；`RSV != 0`、
`FRAG != 0`、畸形/超界地址和 payload 静默丢弃；所有 socket、task、queue、scratch
capacity、idle lifetime 和关闭等待有界。sing-box 和 shadowsocks-rust 的固定版本
只提供成功 wire、echo、idle 和外部 SIP022 互操作证据，不能替代这些负向合同。

## 固定来源身份

| Source | Exact identity | M6 usage |
|---|---|---|
| RFC 1928 | [RFC Editor canonical HTML](https://www.rfc-editor.org/rfc/rfc1928.html) | request/reply、UDP header、FRAG、association lifetime 和 client IP 规则 |
| RFC 1928 erratum | [Verified Errata 3198](https://errata.rfc-editor.org/eid3198/) | IPv6 UDP header/headroom 是 22 bytes，不是正文误写的 20 |
| sing-box | [`v1.13.14` commit `25a600db24f7680ad9806ce5427bd0ab8afe1114`](https://github.com/SagerNet/sing-box/tree/25a600db24f7680ad9806ce5427bd0ab8afe1114) | 固定 binary/provider 与 SOCKS observable behavior |
| `sagernet/sing` used by sing-box | [`go.mod` pins `v0.8.11`](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/go.mod), exact dependency commit [`c7c09c5f3f58410965b0a97cbc82d4d4e8323b9b`](https://github.com/SagerNet/sing/tree/c7c09c5f3f58410965b0a97cbc82d4d4e8323b9b) | actual SOCKS codec/client/server behavior used by sing-box |
| shadowsocks-rust | [`v1.24.0` commit `7ee1aa9223ed8f4d34734aac919036c8ad4502c2`](https://github.com/shadowsocks/shadowsocks-rust/tree/7ee1aa9223ed8f4d34734aac919036c8ad4502c2) | fixed binary/provider 与第二个独立 implementation sample |

仓库固定 binary asset、size、SHA-256 和 version-output 仍以
`tests/interop/versions.toml` 为权威；M6 不更新 provider pin。

## RFC 1928 normative contract

| Area | Standard requirement | M6 consequence | Source |
|---|---|---|---|
| Request | request 是 `VER=05, CMD=03, RSV=00, ATYP, DST.ADDR, DST.PORT`；address/port 是客户端预期用来发送 UDP 的 endpoint。若请求时不知道，客户端必须使用全零 address 和 port；server **MAY** 用该 hint 限制 association | 不能把 request endpoint 当作普通非零 `TargetAddr`；必须接受合法的 all-zero hint，也不能把它误当 UDP target | [RFC 1928 §4](https://www.rfc-editor.org/rfc/rfc1928.html#section-4), [§6 UDP ASSOCIATE](https://www.rfc-editor.org/rfc/rfc1928.html#section-6) |
| Reply | reply 是 `VER, REP, RSV=00, ATYP, BND.ADDR, BND.PORT`；成功时 BND endpoint 是客户端必须发送 SOCKS UDP messages 的 relay endpoint | bind 和 admission 必须先成功，再回复 `REP=00` 与实际、可达、非 wildcard 的 local endpoint；失败 reply 后在 10 秒内关闭，M6 直接关闭 | [RFC 1928 §6](https://www.rfc-editor.org/rfc/rfc1928.html#section-6) |
| Lifetime | UDP association 在承载 `UDP ASSOCIATE` 的 TCP connection 终止时终止 | EOF、half-close、reset、control I/O error、process cancellation 都必须取消 UDP operations、关闭两个 UDP sockets 并等待 owner；不能留下只靠 idle timer 回收的 association | [RFC 1928 §6 UDP ASSOCIATE](https://www.rfc-editor.org/rfc/rfc1928.html#section-6) |
| UDP wire | 每个 client datagram 是 `RSV[2]=0000, FRAG[1], ATYP, DST.ADDR, DST.PORT, DATA`；UDP datagram boundary 自带总长度 | 先在固定上限内解析完整 header，再构造 `TargetAddr`/payload；不读取 peer-controlled length 之外的内容，不按声明长度做大 allocation | [RFC 1928 §7](https://www.rfc-editor.org/rfc/rfc1928.html#section-7) |
| Relay/drop | 无法或不愿 relay 的 datagram 静默丢弃；remote reply 必须用同一 UDP header 封装，header address 是 reply 的 remote source | UDP parse、policy、capacity、upstream auth/replay/size failure 都不向 client 发送 SOCKS error datagram；成功 response 使用 authenticated SIP022 `Datagram.target()` 作为 source address，`RSV/FRAG=0` | [RFC 1928 §7](https://www.rfc-editor.org/rfc/rfc1928.html#section-7) |
| Client source | UDP relay 必须从 SOCKS server 获得预期 client IP，并丢弃来自其他 source IP 的 datagram | 权威 IP 是 TCP peer IP；request hint 不是可伪造的 authority，reply 也不能直接发往尚未证明拥有的 hinted endpoint | [RFC 1928 §7](https://www.rfc-editor.org/rfc/rfc1928.html#section-7) |
| Fragmentation | fragmentation 可不实现；不实现时必须丢弃所有 `FRAG != 00` datagram | M6 不建 reassembly queue/timer；所有 nonzero `FRAG` 静默丢弃且不得锁定 endpoint、创建 SIP022 state 或发送 upstream | [RFC 1928 §7](https://www.rfc-editor.org/rfc/rfc1928.html#section-7) |
| Headroom | SOCKS-aware API 应为 IPv4/domain/IPv6 分别减去 header；verified erratum 将 IPv6 从 20 修正为 22 bytes | wire parser 按实际 10 / `7 + domain_len` / 22 bytes 计算；最终 application payload 还必须满足 method/target-specific SIP022 maximum | [RFC 1928 §7](https://www.rfc-editor.org/rfc/rfc1928.html#section-7), [Errata 3198](https://errata.rfc-editor.org/eid3198/) |

RFC 没有要求 server 使用 request address/port 做完整 endpoint authorization，也没有规定
idle expiry、session 数或 queue 深度。它只明确要求 source IP isolation 和 TCP lifetime。
后述 port locking、idle close 与 resource limits 是 M6 的安全/可靠性 profile。

### Request hint 与 source pin 的证据边界

| M6 choice | RFC 1928 | sing-box 1.13.14 / `sing` 0.8.11 | shadowsocks-rust 1.24.0 |
|---|---|---|---|
| TCP peer IP 永远是 client source IP authority | **要求** relay 从 SOCKS server 取得并记录 expected client IP、丢弃其他 source IP；没有规定该 IP 必须如何从 request/TCP peer 二者选出。选择 TCP peer 且不允许 request 覆盖它，是利用 request hint **MAY** 的 M6 policy | server packet wrapper 接受任意 source，不能支持该安全结论 | UDP relay 按完整 UDP peer 建 association，但不把它绑定到对应 TCP peer，不能支持该安全结论 |
| request port 非零时固定该 source port | server **MAY** 用 request `DST.ADDR/DST.PORT` 限制 association，因此允许；不是 RFC 的强制行为 | client helper 对 UDP 总发送 port zero；server 忽略 hint，既不验证也不反对此 profile | client 发送它已绑定的 actual nonzero UDP port，因此支持此 profile；server 自身不校验 TCP hint |
| request port zero 时忽略 bounded-valid address；首个 fully-valid datagram 锁定 port | client 在 endpoint 未知时**必须**发送全零 address/port；RFC 没有要求 server 拒绝“非零 address + zero port”，且 server **MAY** 决定是否使用 hint。M6 的宽容接收是 interoperability policy，不是 RFC 为 client 授予的新合法编码 | client helper 总把 port 置零、但可能把 address 改写为非零 loopback，因此该选择保持兼容 | client 通常发送 actual nonzero address/port，不依赖 first-packet pin，也不反对此 fallback |
| 不支持 fragmentation，`FRAG != 0` 静默 drop 且不能建立 pin/state | **要求**不支持 reassembly 的实现丢弃所有非零 `FRAG` | reader 跳过 `RSV/FRAG` 而不验证，反对此安全行为，不能作为 oracle | UDP server 显式丢弃 `frag != 0`，支持该行为；但 codec 不验证 `RSV` |

因此 M6 采用兼容性较好的规则：TCP peer 始终固定 IP；request port 非零就固定 port；
request port 为零时，IPv4/IPv6/domain address 只做 bounded syntax validation，首个
fully-valid datagram 固定 port。该宽容不会允许第三方 IP，也不会让 malformed、
`RSV != 0`、`FRAG != 0`、超界或无法进入 SIP022 的 packet 赢得 first-packet race。

## M6 selected behavior

### Control request and relay endpoint

1. 保留现有 no-auth greeting、`CONNECT` 成功/失败和 `BIND -> REP 07` 行为；仅把
   `CMD=03` 分流到 UDP association。`ferrum2-socks5` 解析 command，不把 UDP
   control request 伪装成 `ferrum2_core::Session`。
2. UDP request hint 支持 IPv4/IPv6/domain 的 bounded syntax。address 永远不能覆盖 TCP
   peer IP：若 port 非零，该 port 是固定 source-port constraint，address 仅做 bounded
   syntax validation；若 port 为零，无论 bounded-valid address 是否为零，首个
   fully-valid datagram 决定 port。后者明确兼容 `sagernet/sing` 的 rewritten hint。
3. association 的 client endpoint 只能由实际收到的 datagram 建立：source IP 必须等于
   TCP peer IP，非零 hinted port 还必须匹配；随后完整验证 `RSV/FRAG/address/port/
   payload/SIP022-fit` 并取得所需 resource reservation，最后原子锁定完整 source
   `SocketAddr`。畸形包和错误端口不能赢得 first-packet race。
4. relay UDP socket 绑定到 accepted TCP connection 的 concrete local IPv4 address 和
   ephemeral port；成功 reply 返回该 actual endpoint。M6 不新增 shared/same-port UDP
   inbound 或 dual-stack listen 配置。

### Datagram translation

- client → upstream：验证 SOCKS header 后复用 `ferrum2_core::TargetAddr` 和
  `Datagram`，再由一个 association-owned `UdpClientSession::encode_request` 生成
  SIP022 UDP。domain 保持为 domain 交给现有 server direct resolver；client 不解析
  DNS，也不选择 route。
- upstream → client：upstream socket 连接到配置中的固定 Shadowsocks server endpoint，
  只接收该 peer；`UdpClientSession::prepare_response` 完成 authentication、timestamp、
  type、request/response binding 和 replay precheck。取得 response queue/byte capacity
  后调用 `commit_response`，再编码 `RSV=0000, FRAG=00, source ATYP/address/port,
  payload` 发给已锁定 client endpoint。
- 一个 UDP association 可向多个 target 发包；TCP request hint 不是 target。IPv4、
  IPv6 和 bounded ASCII domain target 都沿用现有 `TargetAddr` 规则，target port zero
  静默丢弃。零长度 UDP DATA 不因 SOCKS 层单独拒绝。
- complete SOCKS wire 和 complete SIP022 wire 都受 65,507-byte hard ceiling；每包
  application maximum 是 SOCKS header limit 与
  `ferrum2_shadowsocks::max_udp_payload_len` 的较小者。过大包在 encode/send/state
  mutation 前丢弃。

### Bounds and shutdown

- 在 client raw schema 中把 `[udp]` 加为 optional additive schema-v1 table，并复用既有
  `UdpConfig` 的 `enabled/max_sessions/max_buffered_bytes/idle_timeout`。缺表的旧配置映射为
  UDP disabled；只有显式表且 `enabled=true` 才启用。缺表或 `enabled=false` 都保持
  `UDP ASSOCIATE -> REP 07`；不新增 routing、DNS、per-target 或 method-specific knob。
- `BoundedSupervisor` 的 TCP child ownership 继续覆盖 control connection；UDP-specific
  admission 复用 `UdpRuntimeLimits`、`UdpSessionManager`、`UdpBufferBudget`、固定
  per-direction queue depth 4、opaque generation 和 `OwnerRegistry`。server-only
  `DirectUdpRuntime` 的 plaintext direct-send loop 不可原样复用于 client upstream；只
  复用其 capacity/commit/cancellation primitives 和 shutdown pattern。
- 每个实际 allocation 按 backing capacity 计入同一 global UDP budget，包括 receive
  wire、encode output、`UdpPacketScratch` 和 queued `Datagram`。reservation 必须先于
  allocation/accepted-state mutation；等待 budget 的 future 必须同时可被 control 和
  process cancellation 终止。
- TCP EOF/reset/half-close 是立即终止条件。idle expiry 是额外有界 profile：它关闭
  control TCP 与两个 UDP sockets，使 client 不会留下看似存活但已失效的 control。
  process graceful shutdown 通过既有 `ProcessSupervisor` deadline drain，然后对剩余
  association task 做 forced abort + await；最终 owner counters 回到 baseline。

## Pinned implementation observations

### sing-box 1.13.14

- sing-box 的 SOCKS inbound 只建立 TCP listener，并把 `udp_timeout` 交给
  `sagernet/sing` 的 handler；见
  [`protocol/socks/inbound.go`: `NewInbound`, `NewConnectionEx`](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/protocol/socks/inbound.go#L38-L74)。
- exact dependency handler 对每个 `UDP ASSOCIATE` 在 TCP local address 上绑定临时 UDP
  socket、回复 actual bind endpoint、等待首包并应用 first-packet/ongoing idle timeout；
  见 [`protocol/socks/handshake.go`: `HandleConnectionEx`](https://github.com/SagerNet/sing/blob/c7c09c5f3f58410965b0a97cbc82d4d4e8323b9b/protocol/socks/handshake.go#L230-L268)。这支持
  M6 的 per-control ephemeral socket 与 idle-close 选择。
- exact client helper 在 `CMD=03` 时总把 port 改成 zero，并会按输入地址类别重写 hint
  address；server 端不使用该 hint。这支持 TCP peer 作为唯一 IP authority，并解释了
  M6 为什么对任意 bounded-valid address + zero port 都进入 first-valid pin；见
  [`ClientHandshake5`](https://github.com/SagerNet/sing/blob/c7c09c5f3f58410965b0a97cbc82d4d4e8323b9b/protocol/socks/handshake.go#L90-L106) 和
  [`Client.DialContext`](https://github.com/SagerNet/sing/blob/c7c09c5f3f58410965b0a97cbc82d4d4e8323b9b/protocol/socks/client.go#L102-L139)。
- packet writer 总写 3 个 zero bytes，但 reader 只是跳过前三字节；underlying
  `serverPacketConn` 还会接受任意 source 并把 reply 指向最近 sender。它们不能作为
  `RSV/FRAG/source` security oracle；见
  [`AssociatePacketConn.ReadPacket/WritePacket`](https://github.com/SagerNet/sing/blob/c7c09c5f3f58410965b0a97cbc82d4d4e8323b9b/protocol/socks/packet.go#L75-L104) 和
  [`NewServerPacketConn`](https://github.com/SagerNet/sing/blob/c7c09c5f3f58410965b0a97cbc82d4d4e8323b9b/common/bufio/bind.go#L114-L149)。
- upstream test `TestSOCKSUDPTimeout` 证明 SOCKS client → UDP echo 和 timeout 后不再有
  response；它不覆盖 malformed header、wrong source 或 TCP-close causality。可复用其
  observable test shape，不复制 sleep-based realization；见
  [`test/socks_test.go`](https://github.com/SagerNet/sing-box/blob/25a600db24f7680ad9806ce5427bd0ab8afe1114/test/socks_test.go#L22-L55)。

### shadowsocks-rust 1.24.0

- TCP handler 在运行 mode 禁用 UDP 时回复 `REP 07`；启用时对 `UDP ASSOCIATE` 回复
  预先配置的 UDP server address，然后读取 control connection 直到 EOF。这为“UDP 是
  显式 capability，disabled 时拒绝命令”提供实现先例，但不规定 ferrum 的 TOML 缺表
  语义；见
  [`Socks5TcpHandler::handle_udp_associate`](https://github.com/shadowsocks/shadowsocks-rust/blob/7ee1aa9223ed8f4d34734aac919036c8ad4502c2/crates/shadowsocks-service/src/local/socks/server/socks5/tcprelay.rs#L289-L307)。
- 独立 UDP server 解析 `UdpAssociateHeader`、显式 drop `frag != 0`，response 写
  `frag=0` 与 remote source address；association manager 以完整 peer `SocketAddr`
  为 key，支持 TTL、capacity 和 bounded `mpsc` send queue；见
  [`Socks5UdpServer::run` / `Socks5UdpInboundWriter::send_to`](https://github.com/shadowsocks/shadowsocks-rust/blob/7ee1aa9223ed8f4d34734aac919036c8ad4502c2/crates/shadowsocks-service/src/local/socks/server/socks5/udprelay.rs#L101-L211) 和
  [`UdpAssociationManager`](https://github.com/shadowsocks/shadowsocks-rust/blob/7ee1aa9223ed8f4d34734aac919036c8ad4502c2/crates/shadowsocks-service/src/local/net/udp/association.rs#L46-L106)。这些是 wire、peer-key、TTL/
  capacity 的 useful observations。
- exact client 先绑定 UDP socket，把 actual local address/port 放入 request，连接 reply
  BND endpoint，并保留 TCP owner；这要求 M6 支持 nonzero hinted port 和 normal
  connected-UDP client behavior。见
  [`Socks5UdpClient::associate`](https://github.com/shadowsocks/shadowsocks-rust/blob/7ee1aa9223ed8f4d34734aac919036c8ad4502c2/crates/shadowsocks-service/src/local/socks/client/socks5/udp_client.rs#L21-L60) 与
  [`Socks5TcpClient::udp_associate`](https://github.com/shadowsocks/shadowsocks-rust/blob/7ee1aa9223ed8f4d34734aac919036c8ad4502c2/crates/shadowsocks-service/src/local/socks/client/socks5/tcp_client.rs#L65-L101)。
- `UdpAssociateHeader::read_from` 读取但不验证两个 reserved bytes；更重要的是 client
  source 明确注释该版本 UDP server 没有随 broken TCP control 删除 association。因此
  此版本也不能作为 reserved/lifetime oracle；见
  [`relay/socks5.rs`: `UdpAssociateHeader`](https://github.com/shadowsocks/shadowsocks-rust/blob/7ee1aa9223ed8f4d34734aac919036c8ad4502c2/crates/shadowsocks/src/relay/socks5.rs#L780-L829) 和
  [`udp_client.rs`: `Socks5UdpClient`](https://github.com/shadowsocks/shadowsocks-rust/blob/7ee1aa9223ed8f4d34734aac919036c8ad4502c2/crates/shadowsocks-service/src/local/socks/client/socks5/udp_client.rs#L21-L60)。
- `tests/socks5.rs` 没有 UDP case；lower-level `crates/shadowsocks/tests/udp.rs` 验证
  SIP022 UDP echo（含 2022 AES/ChaCha），但不经过 SOCKS control/header。M6 必须新增
  自己的 public-path evidence；见
  [`tests/socks5.rs`](https://github.com/shadowsocks/shadowsocks-rust/blob/7ee1aa9223ed8f4d34734aac919036c8ad4502c2/tests/socks5.rs) 和
  [`crates/shadowsocks/tests/udp.rs`](https://github.com/shadowsocks/shadowsocks-rust/blob/7ee1aa9223ed8f4d34734aac919036c8ad4502c2/crates/shadowsocks/tests/udp.rs)。

## Repository reuse map at baseline

| Existing seam | Reuse | Constraint/evidence path |
|---|---|---|
| SOCKS greeting/request/reply/address codec | extend in place; preserve CONNECT tests and failure bytes | `crates/ferrum2-socks5/src/lib.rs::{Socks5Inbound::accept,read_target,SocksReplyPending}`; `crates/ferrum2-socks5/tests/{connect,negative}.rs` |
| Runtime-neutral target/datagram | use only UDP header target, not request endpoint hint | `crates/ferrum2-core/src/lib.rs::{TargetAddr,Datagram}`; `TargetAddr` correctly rejects target port zero while UDP request hint must allow zero |
| SIP022 UDP client protocol | one `UdpClientSession` per association; reuse encode, authenticated prepare/commit, replay/binding, three method profiles and payload calculation | `crates/ferrum2-shadowsocks/src/udp.rs::{UdpClientSession,UdpPacketScratch,max_udp_payload_len}` and `crates/ferrum2-shadowsocks/tests/{udp_packets,udp_replay,udp_sessions}.rs` |
| Bounded UDP state | reuse limits, byte reservations, queue depth, provisional commit, generation invalidation and owner counters | `crates/ferrum2-runtime/src/udp.rs::{UdpRuntimeLimits,UdpBufferBudget,UdpSessionManager,PendingUdpSession,PendingUdpDatagram}`; do not reuse `DirectUdpRuntime`'s direct-target send semantics |
| Process lifecycle | keep TCP association under existing bounded child and add UDP owners to the same cancellation lineage | `bins/ferrum2-client/src/run.rs::{run_with_registry,ClientTcpRoot,client_connection}`; `ferrum2_runtime::{ProcessRoot,ProcessSupervisor,BoundedSupervisor}` |
| Typed config | add existing validated `UdpConfig` to client root; preserve `schema_version = 1` and validate before bind | `crates/ferrum2-config/src/lib.rs::{ValidatedClientConfig,UdpConfig,validate_client,validate_udp}`; currently only `ValidatedServerConfig` consumes it |
| External providers | reuse exact download/hash/version/license/safe-extraction and UDP echo fixtures | `tests/interop/versions.toml`, `tests/m0-harness/src/external_support/mod.rs`, existing M2 UDP qualification code |

## Required M6 evidence and risks

| ID | Risk | Primary evidence that must fail on regression |
|---|---|---|
| M6-R01 | command/config refactor changes existing CONNECT/BIND/no-auth bytes or silently enables UDP for old client configs | existing SOCKS package suite plus table-driven UDP request success/disabled/unsupported/malformed exact replies；config tests prove omitted `[udp]` and `enabled=false` yield `REP 07`, explicit enabled table is required |
| M6-R02 | request address is trusted, wrong process steals response, compatible zero-port form regresses, or malformed first packet pins endpoint | deterministic source-address seam tests: wrong IP drop, nonzero hinted-port mismatch drop, all-zero and nonzero-address/zero-port first-valid lock, later wrong-port drop, no state/forwarding before lock |
| M6-R03 | parser accepts nonzero RSV/FRAG, truncated/unknown ATYP, empty/non-ASCII/oversize domain, target port zero, or allocates from peer length | one bounded negative table asserts silent drop, zero upstream sends, unchanged protocol/runtime state and unchanged allocated-capacity counters |
| M6-R04 | one association is incorrectly bound to one target | one control/UDP endpoint alternates at least two target addresses and receives correctly attributed response headers |
| M6-R05 | SOCKS and SIP022 overhead composition truncates or exceeds 65,507 | per method and ATYP: exact maximum succeeds, one-byte-over drops; include verified 22-byte IPv6 header and `max_udp_payload_len` cross-check |
| M6-R06 | unauthenticated/spoofed/replayed upstream response reaches client or advances state out of order | connected upstream peer test plus existing SIP022 negative vectors; public-path mutation test reserves queue/bytes before `commit_response` and sends nothing on failed prepare/reservation |
| M6-R07 | TCP close, half-close, idle expiry or process shutdown leaks association | paused-time owner test and real sockets: admitted UDP signal, control close, immediate no-forward, awaited return to baseline for sessions/sockets/tasks/queues/bytes; process graceful and forced paths |
| M6-R08 | session/buffer/queue saturation evicts active flow, overcommits memory, or blocks shutdown | exact configured limits with one-over admission/drop, queue depth 4, backing-capacity accounting including fixed scratch, cancellation while waiting for budget, deterministic expired-only replacement |
| M6-R09 | public client path only works against ferrum server or one method | six new method-major cases: ferrum client SOCKS UDP driver → sing-box server and → shadowsocks-rust server for each standard method; each case sends three distinct request/reply datagrams and verifies payload + source address + cleanup |
| M6-R10 | external cases merely replay M2's socket-free example | new driver must negotiate public TCP `UDP ASSOCIATE`, use returned BND endpoint, retain then close control TCP, and observe association teardown; reuse provider provisioning, not old PASS claims |
| M6-R11 | IPv4-only public listener accidentally expands to dual stack/DNS/routing | config and real-process tests keep configured TCP listen/upstream as IPv4 while UDP headers independently cover IPv4/IPv6/domain targets; no route decision or client DNS call exists |

The six external cases complement rather than replace the existing same-SHA SIP022 UDP matrix.
Release qualification must retain the full existing TCP/UDP gates and add the six public-path rows on
one exact SHA/run/attempt; no result may be spliced from M2/M5 runs.

## Explicit non-goals

- SOCKS UDP fragmentation/reassembly；
- shared or same-port public UDP listener、multi-inbound/outbound tags、routing、DNS policy；
- SOCKS authentication changes、BIND、SIP023/multi-user；
- copying either reference implementation's parser, global association map or lifecycle behavior；
- replacing existing SIP022 UDP state machines or `ferrum2-crypto` seam。

## Planning questions resolved by this research

- **Enablement:** old client schema-v1 configs without `[udp]` remain disabled；only an explicitly
  present table with `enabled=true` enables UDP，and disabled requests receive `REP 07`.
- **Request endpoint authority:** TCP peer supplies mandatory IP。For nonzero request port, ignore
  the bounded-valid address for authority and pin that port；for zero request port, any
  bounded-valid address form defers the port to the first fully-valid datagram。This intentionally
  accepts `sagernet/sing`'s nonzero rewritten address without weakening the TCP-peer IP pin.
- **Relay topology:** one ephemeral public UDP socket and one connected upstream UDP socket per live
  TCP control association; no shared listener/demux.
- **Fragmentation:** unsupported and silently dropped for every `FRAG != 0`.
- **Reference boundary:** reuse success/echo/idle shapes and exact provider pins only; RFC plus ferrum
  negative/lifecycle tests are authoritative for security.
- **Routing:** every accepted target is encoded unchanged into the one configured SIP022 upstream；
  routing remains deferred.
