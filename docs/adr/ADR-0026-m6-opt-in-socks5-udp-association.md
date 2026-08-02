# ADR-0026 — M6 opt-in SOCKS5 UDP association ownership

- **Status:** Accepted
- **Date:** 2026-08-02
- **Related:** `SPEC-0007`、`TEST-0007`、M6-T01～T03；extends ADR-0021～0024

## Context

M5 已有完整 SIP022 UDP client protocol owner、generic bounded UDP manager、server
direct UDP path 和 process supervisor，但 public client inbound 仍只接受 SOCKS5
`CONNECT`。M6 需要增加 `UDP ASSOCIATE`，同时保留 M3 close 时 client schema v1
cohort 的 effective behavior，并避免为尚未存在的 routing/multi-inbound 建 seam。

## Decision

### Compatible opt-in

Client schema v1 additive 接受 optional `[udp]`。Section 缺失时 UDP 保持 disabled，
因此 M3 preserved client documents 继续对 `CMD=03` 返回 command-not-supported，且不
创建 UDP resource。Section 显式出现时复用 server 已有 `enabled`、`max_sessions`、
`max_buffered_bytes`、`idle_timeout_ms` 字段、范围和数值默认值；`enabled=false` 仍为
zero-UDP-resource escape hatch。旧 binary 会拒绝新 section；回滚时删除它即可。

### Association and endpoint ownership

一个成功的 SOCKS UDP association 由收到 `UDP ASSOCIATE` 的 TCP control connection
唯一拥有；control EOF/error、idle、cancellation 或 process shutdown 都终止它。每个
association 动态绑定一个 application-facing IPv4 UDP socket 和一个连接到 configured
Shadowsocks server 的 UDP socket；成功 reply 返回实际 application-facing endpoint。
它不是 process root、共享 listener 或 route。

Expected client IP 固定为 control TCP peer IP。Request source hint 必须是语法完整的
RFC 1928 address+port，但 address 仅作 advisory，不覆盖 TCP peer IP，也不触发 DNS。
非零 port 立即固定 expected source port；port 为零时，只在首个来源 IP 正确、完整
语法有效、`FRAG=0` 且 capacity 已预留的 datagram 上固定 source port；此后 source
endpoint 不 roaming。该 profile 同时接受 RFC 的全零 unknown endpoint 和 sing-box
使用的 nonzero-address/zero-port hint。
RFC 1928 fragmentation 是 optional，M6 不实现 reassembly，所有 `FRAG!=0` datagram
静默丢弃且不刷新 state。

### Existing deep modules

每个 SOCKS UDP association 拥有一个现有 `UdpClientSession`；所有 live outbound
session IDs 在一个有界、serialized set 内执行既有八次 collision check。Datagram
仍使用 `core::Datagram`，SIP022 packet/auth/replay/binding 仍由
`ferrum2-shadowsocks` 拥有。Association capacity、allocated bytes、depth-four queues、
idle state 和 generation 复用 `UdpSessionManager`；TCP child ownership、cancellation
和 awaited shutdown 复用 `BoundedSupervisor`/`ProcessSupervisor`。

`ferrum2-socks5` 的 interface 只增加 command result 和 SOCKS UDP header decode/
encode；它不拥有 socket、runtime、upstream 或 config policy。Client binary 是唯一
composition adapter。不存在第二个 adapter，因此不新增 generic UDP relay trait。

## Consequences

- Old v1 client behavior and startup side effects remain unchanged until explicit opt-in。
- Source pin、connected upstream socket、SIP022 authentication/binding 和 bounded state
  共同避免把 no-auth SOCKS relay 变成 open/spoofable UDP relay。
- One association owns two sockets and fixed buffers；byte/session limits may reject an
  association before success reply or silently drop one datagram under pressure。
- Shared process-wide UDP port、fragment reassembly、routing、DNS proxy、multi-upstream、
  UDP-over-TCP 和 source-port roaming remain out of scope。

## Rejected alternatives

- **Default-on v1 section:** changes preserved client behavior；rejected。
- **Schema v2:** opt-in addition needs no breaking syntax/default；rejected。
- **One shared UDP listener keyed by peer:** adds demultiplexing、startup transaction and
  routing-like state without a current requirement；rejected。
- **Require only an all-zero tuple for an unknown endpoint:** rejects the pinned sing-box
  SOCKS helper's syntactically valid nonzero-address/zero-port hint without adding security；
  TCP peer IP remains the authority；rejected。
- **Generalize `DirectUdpRuntime`:** its direct-target socket semantics do not match a
  SOCKS-to-SIP022 client association；a one-adapter trait would be shallow；rejected。

## Sources

- `docs/research/M6-socks5-udp-associate-baseline.md`
- [RFC 1928 sections 6–7](https://www.rfc-editor.org/rfc/rfc1928.html#section-6)
- [RFC 1928 verified erratum 3198](https://www.rfc-editor.org/errata/eid3198)
