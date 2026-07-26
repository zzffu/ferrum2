# SPEC-0001: M0 AES-128-GCM TCP 安全纵切

- **Status:** Approved
- **Milestone:** M0
- **Related ADRs:** `ADR-0001`、`ADR-0002`、`ADR-0003`、`ADR-0004`、`ADR-0005`、`ADR-0006`
- **Test plan:** `docs/test-plans/TEST-0001-m0-aes128-tcp-vertical-slice.md`
- **Tickets:** M0-T01、M0-T02、M0-T03、M0-T04、M0-T05、M0-T06、M0-T07、M0-T08

## Objective

交付 ferrum2 的首个安全、可观察、可独立验收的产品纵切：

```text
SOCKS5 no-auth IPv4 CONNECT
  → ferrum2-client
  → SIP022 2022-blake3-aes-128-gcm TCP
  → ferrum2-server
  → direct IPv4 TCP target
```

两个独立 binary 使用 typed TOML；同一 binary 能在不创建 runtime resource 时离线
校验配置。M0 同时以安全负向、lifecycle/backpressure、最小 tracing/Prometheus、
四项双向 reference interop、MSRV 与三目标 binary smoke 证明该路径。

## Non-goals

- `2022-blake3-aes-256-gcm`、`2022-blake3-chacha20-poly1305`。
- 任何 UDP、SOCKS5 `UDP ASSOCIATE` 或公开 UDP inbound。
- SOCKS/domain/IPv6 target、DNS resolver/proxy；M0 target 仅 IPv4。
- multi-user、SIP023/EIH 产品行为或多个 PSK；只保留 key lookup seam。
- routing rules、multiple upstreams、load balancing、proxy chaining、hot reload、
  management API。
- custom executor、`io_uring`、`unsafe` exception、required task runner。
- M3 的最终 operator/platform qualification，M4 的 throughput 与 10,000 idle
  performance/resource gate。
- push、PR、release、artifact publication 或 remote issue mutation。

## User/operator-visible behavior

### Binaries and config

- `ferrum2-client` 监听一个 IPv4 SOCKS5 endpoint，连接一个 configured IPv4
  Shadowsocks server。
- `ferrum2-server` 监听一个 IPv4 Shadowsocks endpoint，认证后 direct connect
  request 中的 IPv4 target。
- `--config <PATH> --check-config` 成功输出恰好 `configuration valid\n` 且 exit 0；
  config/usage error exit 2，run fatal exit 1，graceful exit 0。
- configuration schema、defaults、ranges、secret parsing 与 error format 完全遵循
  `ADR-0003`。config file 最大 1 MiB；所有 tables 拒绝 unknown fields。
- `--check-config` 不创建 Tokio runtime、proxy/metrics listener、connector、
  tracing subscriber 或 task；OS 端口已占用不影响纯离线成功。

### SOCKS5

- 只支持 version 5、no-auth method `0x00`、command `CONNECT (0x01)`、ATYP
  IPv4 `0x01`。
- greeting 包含 `0x00` 时选择 no-auth；否则回复 `0x05 0xff` 后关闭。
- `BIND`/`UDP ASSOCIATE` 回复 `0x07`；domain/IPv6 回复 `0x08`；malformed version/
  length 关闭当前 connection。
- client 依次完成到 Shadowsocks server 的 IPv4 TCP connect、读取该 socket 的
  local IPv4 address、完整 SIP022 request first-write，随后才回复 SOCKS success。
  success reply 必须恰好为
  `05 00 00 01 <local-ipv4:4> <local-port:2-big-endian>`；这里的
  `BND.ADDR/BND.PORT` 是已建立 client→Shadowsocks-server socket 的 local endpoint。
  `local_addr` 失败或不是 IPv4 时，关闭该 SS socket，并作为 pre-success general
  failure 处理。
- 若 success 前失败，映射一次 failure：
  `network unreachable→0x03`、`host unreachable→0x04`、
  `connection refused→0x05`，timeout/其他→`0x01`。所有已发送的 request-stage
  failure reply 必须恰好为
  `05 <REP> 00 01 00 00 00 00 00 00`；no-acceptable-method 仍只回复
  greeting `05 ff`，malformed version/length 仍直接关闭。
- server target connect 发生在 SOCKS success 之后且没有 SIP022 acknowledgement；
  后续 target refusal 表现为 SOCKS stream EOF/RST，不再发送第二个 SOCKS reply。

### Observability

- run mode 输出 newline-delimited structured JSON tracing；optional loopback
  `GET /metrics` 暴露 Prometheus text。
- field、metric、label 与 redaction contract 遵循 `ADR-0005`。destination、raw
  peer input 和所有 secret material 不出现在 tracing 或 metric labels。

## Current execution path

当前仓库无 Cargo workspace 或产品 execution path；这不是部分实现。

M0 完成后的 client path：

```text
client TcpListener
 → Socks5Inbound::accept
 → Session<SocksStream, SocksReplyPending>
 → ShadowsocksTcpOutbound::open
 → request salt/header single-write
 → SocksReplyPending::succeeded(outbound.local_endpoint())
 → owned bidirectional relay
```

server path：

```text
server TcpListener
 → ShadowsocksTcpInbound::accept
 → fixed-header single-read/auth
 → variable-header auth/full semantics
 → exact replay check-and-insert
 → Session<ShadowsocksStream, NoReply>
 → DirectOutbound::open
 → authenticated initial payload
 → response header + first payload single-write
 → owned bidirectional relay
```

## Proposed architecture and ownership

| Module | Owns | Must not own |
|---|---|---|
| `ferrum2-core` | address/session types；`Inbound`/`Outbound`/`Connector`/reply contracts；closed connect errors | Tokio、TOML、cipher、concrete inbound/outbound |
| `ferrum2-crypto` | secret types；strict PSK conversion；BLAKE3 KDF；AES-128 AEAD owners；nonce；key/clock/entropy seams | socket、framing、routing、logs |
| `ferrum2-shadowsocks` | SIP022 TCP state machine、framing、replay、binding、protocol errors、single-I/O abstraction | CLI、direct policy、global runtime |
| `ferrum2-socks5` | greeting/request parse、M0 CONNECT inbound、reply mapping | DNS、routing、SS crypto |
| `ferrum2-runtime` | socket adapters、proxy/metrics listeners、semaphore、direct connector、relay、timeouts、task ownership、shutdown | config parsing、wire constants、routing policy、metrics registry internals |
| `ferrum2-config` | TOML read/parse/semantic validation、validated role configs、redacted config errors | listeners、runtime creation |
| `ferrum2-observability` | JSON tracing initialization、typed metrics registry与text encoding | Tokio、socket/listener、protocol/session policy、destination labels |
| binaries | parse CLI、load validated config、construct adapters/supervisor | protocol implementation |
| `tests/m0-harness` | metadata/filesystem policy、黑盒process E2E、external interop/platform drivers | concrete ferrum2 Cargo dependency、production behavior |

Dependency DAG、toolchain、exact dependency versions 与 manifest ownership 由
`ADR-0001` 冻结。M0-T01 独占所有 manifests/lock/toolchain/license；后续 ticket
不能修改它们。

## Configuration and validation

实现 `ADR-0003` 的两个 role-specific schemas。关键 semantic rules：

1. `schema_version = 1`。
2. method 只能是 `2022-blake3-aes-128-gcm`。
3. PSK 必须 canonical standard padded base64 且 decode 后恰好 16 bytes。
4. network endpoints 为非零端口 IPv4 literals；metrics 只准 loopback。
5. client listen 与 server endpoint 不得相同；同一进程 metrics 与 proxy listener
   不得相同。
6. runtime/replay ranges 必须在构造 validated type 前检查。
7. raw config、secret token 和 parser snippet 在返回/显示 error 前清除或丢弃。

`load_client`/`load_server` 是纯文件+CPU 操作并返回 validated types。binary 按顺序：

```text
parse CLI → read bounded file → deserialize → semantic validate
  → if check: print exact success and exit
  → else: initialize observability/runtime/listeners
```

## Types, interfaces, state transitions, and data flow

### Core and capability types

核心 traits 与 `Session<S, R>` 遵循 `ADR-0001`，使用 RPITIT/static dispatch。
`TargetAddr` 能表达 bounded future variants，但 M0 `Socks5Inbound` 与
`DirectConnector` 只产生/接受 IPv4。
`Connector::Stream` 与 `Outbound::Stream` 实现core `LocalEndpoint`，返回在任何
SIP022 first-write前取得并验证过的 `SocketAddrV4`；protocol wrapper只委托它。
`SessionReply::succeeded(self, bound)`/`failed(self, kind)`消费reply owner，从类型
层保证SOCKS response至多一次，并让composition显式提供success reply的BND值。

`Aes128Psk`、`TcpSubkey`、`TcpSealer`、`TcpOpener`、`KeyProvider`、`Clock`、
`SecureRandom` 遵循 `ADR-0002`。raw PSK 不离开 scoped provider capability；
protocol 只得到独占 AEAD+nonce owner。
该`Clock`只服务SIP022 timestamp/replay；runtime deadlines使用Tokio monotonic
timer/test-util paused time，不依赖crypto。

### Client states

```text
C0 AcceptedSocks
  → C1 Greeting
  → C2 ConnectRequestValidated(IPv4 target)
  → C3 ServerConnecting
  → C4 RequestHeaderSingleWrite
  → C5 SocksSuccessSent
  → C6 Relaying(RequestOpen, ResponseAwaiting|ResponseOpen)
  → C7 Closing
```

- C0～C2 受 handshake timeout。
- C3 受 connect timeout。
- C4 生成 16-byte salt、type 0、wall timestamp、target、`1..=900` padding；
  M0 ferrum2 client initial payload 为空。
- C4 成功定义为一次底层 write 返回整个 contiguous header 长度；short write 失败。
- C5 后 client→server data frames可发送；server→client bytes 必须等 response header/
  first payload认证及 request-salt binding 后才可见。

### Server states and side-effect order

```text
S0 AcceptedSocket
  → S1 FixedRegionSingleRead(43 bytes)
  → S2 FixedAuthenticated(type/time/length)
  → S3 VariableAuthenticated(full bounds/address/padding semantics)
  → S4 ReplayReserved(exact atomic check+insert)
  → S5 DirectConnecting
  → S6 InitialPayloadForwarded
  → S7 Relaying(ResponsePending|ResponseOpen)
  → S8 Closing
```

硬顺序：

```text
AEAD authentication
 → type/time/length bounds
 → variable AEAD authentication
 → full address/padding/header semantic validation
 → exact replay mutation
 → accepted-session/metrics mutation
 → target connect
 → forwarding
```

S0～S4 的任何 reject 断言 connector call count、forwarded bytes、accepted counter 和
replay mutation 均为 0。唯一例外是 S4 自身的成功 replay insertion；之后 target
失败仍保留 entry。

### Wire and allocation

wire constants、KDF、nonce、request/response header 与 replay algorithm 完全采用
`ADR-0004`。额外实现约束：

- initial fixed read/write 使用记录底层 operation 的 abstraction；不得以
  `read_exact`/`write_all` 多次触底。
- decrypt direction持有一个最大 `65551` bytes 的 fixed-capacity reusable scratch；
  不按 authenticated length 调用 input-sized reserve。所有 slice/length arithmetic
  用 checked operations。
- request variable header完整消费；IPv4 address 7 bytes、padding length 2 bytes、
  padding `0..=900`，其余是 initial payload。padding 与 payload 不得同时为空。
- encoder 将 application bytes 切成 `<=16384` chunks；decoder 接受最大 65535。
- response 必须绑定本连接完整 16-byte request salt，且 first response header 与
  nonempty first payload 一次 write。

### Relay data flow

direct connect 成功后：

1. server 先写 authenticated initial payload（若有）。
2. 两方向 local futures 使用 owned 16 KiB application buffers。
3. writer stalled 时对应 reader停止；无 data queue。
4. EOF 只 shutdown 对侧 writer，反方向继续。
5. fatal error/cancellation 终止本 flow 两方向并回收。

## Errors and failure semantics

内部 closed error classes：

```text
ConfigIo, ConfigTooLarge, ConfigSyntax, ConfigSemantic,
SocksProtocol, SocksUnsupported,
Authentication, InvalidType, TimestampSkew, Replay, ReplayCapacity,
FrameBounds, AddressBounds, ResponseBinding, NonceExhausted,
RandomUnavailable, ClockUnavailable,
HandshakeTimeout, ConnectTimeout, NetworkUnreachable, HostUnreachable,
ConnectionRefused, RelayIo, IdleTimeout, Cancelled, Shutdown, ListenerFailure
```

- 对外 config/CLI 输出使用 `ADR-0003` stable codes，不包含 source `Display`。
- protocol initial failure返回closed `ShadowsocksError::Detection(reason)`，并在
  返回前恰好一次调用core `AbortiveClose::mark_abortive`；调用后typed state
  terminal且owner立即drop transport。runtime只实现protocol-neutral capability，
  不反向依赖protocol，也不使用string-based判断。
- 普通 EOF、target refusal、idle/operator shutdown 不伪装成 authentication
  failure，也不得调用`mark_abortive`。
- authentication/semantic failure只关闭当前 flow；listener failure 是 process fatal。
- replay mutex/state error、entropy/clock failure、nonce overflow、capacity full 全部
  fail closed，不降级、不 retry 弱策略。
- target connect 只在 S4 后发生。client 侧 pre-success connect error 可发一次 SOCKS
  failure；server target failure发生在 success 后，只关闭 stream。
- 没有 error path 可 panic、按 peer 值无界 allocate 或 forward unauthenticated bytes。

## Security and privacy

- fixed SIP022 revision、primitive/protocol fixture provenance、exact replay 和
  detection strategy 由 ADR-0004/0006 定义。
- PSK、derived material、salt、nonce、raw config、raw frames 绝不进入 log/error/
  panic/trace/metric；destination 不进入 tracing 或 metric labels。
- config/secret/KDF buffers 使用 fixed secret newtypes 与 explicit zeroize；任何
  production entropy failure关闭 flow。
- response salt 与 request salt不同；request/response AEAD owners 和 nonce counters
  分离，checked counter 在复用前失败。
- replay store exact、monotonic TTL 60 秒、live entry 不提前 eviction；wall timestamp
  boundary为 inclusive 30 秒。
- process restart 清空 replay store 是已接受剩余风险；M0 不声称跨重启 exact
  retention。
- reference executable 先校验 SHA-256，只作为独立子进程，不 vendor/link/copy。

## Concurrency and resource lifecycle

| Resource | M0 contract |
|---|---|
| active proxy connections | semaphore default 4096，validated `1..=65535` |
| listen backlog | default 1024，validated `1..=65535` |
| application relay buffer | 每方向 16384 bytes |
| encrypt wire scratch | 每 active flow一个 reusable buffer，最多16459 bytes（覆盖first response） |
| decrypt wire scratch | 每 active decrypt direction最多 65551 bytes，一个 reusable buffer |
| data-plane queues | none |
| replay entries | default 65536，validated `1024..=1048576`，TTL 60s |
| handshake timeout | 5s default |
| connect timeout | 10s default |
| idle timeout | 300s default；forwarded byte 重置 |
| shutdown grace | 30s default |
| metrics connections | 16 permits |
| metrics header | 1024-byte cap，2s timeout |

一个 supervisor 拥有 listeners/JoinSet；每 flow 一个 owner task且不再 spawn relay
directions。shutdown、listener failure、timeout、half-close 与 cleanup 采用
`ADR-0005`。required lifecycle evidence 是 owner registry 回零、socket 可重绑、
JoinSet empty 和固定 buffer/permit counters；RSS 等间接指标不能替代。

## Compatibility and upstream divergence

- 固定 reference pins、四项 matrix、artifact checksums 和 required-job policy 见
  `ADR-0006`。
- M0 只声明 AES-128 TCP/IPv4 covered path，不声明完整 SIP022/v0 compatibility。
- reference 的 replay ordering、logging、unsafe 或 binding 偏差不进入 ferrum2。
  若互操作揭示规范 ambiguity，停止 gate并先修订 ADR/spec。
- M1 对 method/地址支持只能 additive；不得复制 transport state machine或改变已
  固定 AES-128 wire。

## Observability

实现 `ADR-0005` 的固定 JSON fields、closed enums、七项 metric names/types/labels。
额外要求：

- config validation error在 tracing 初始化前仍使用同一 redacted code taxonomy。
- accepted connection metric只在 server S4 或 client SOCKS parse+SS open 成功后增加；
  authentication/semantic rejects计为 rejection而非 accepted。
- bytes counter只增加已成功 forward 的 authenticated application bytes。
- replay entries gauge 与 exact store在同一 mutation boundary 更新。
- 多个 arbitrary destination 输入不得创建新 metric series。

## Migration and rollback

M0 是首次 schema/wire/runtime，无数据迁移。所有 replay/metric state in-memory。
rollback 为通过 supervisor shutdown 后回退 integrated commit。更改 wire、
dependency/module direction、config schema、secret seam、task topology、metrics
schema 或 reference pins 必须用新的 ADR/spec revision，不得静默编辑实现理由。

## Acceptance criteria

1. **AC-01 Workspace/toolchain:** M0-WS-001、M0-WS-002、M0-MSRV-001 通过；
   workspace members/DAG、exact direct versions、lock、license、unsafe forbid、
   Rust 1.85.0 locked graph 均有证据。
2. **AC-02 Offline config/CLI:** M0-CFG-001～003、M0-CLI-001 通过；两个 binaries
   的 valid/invalid matrix 与零 listener/connector/task 副作用直接可见。
3. **AC-03 Crypto correctness/secrets:** M0-CRYPTO-001～004 通过；primitive vectors、
   KDF/nonce fixture、redaction/clear seam、entropy failure和nonce overflow均精确。
4. **AC-04 SIP022 fail-closed ordering:** M0-PROTO-001～006 通过；有provenance的
   非官方composite wire KAT通过，且所有auth、bounds、semantic和allocation
   negative case在connector/forward/accepted/replay mutation前失败。
5. **AC-05 Replay/time:** M0-REPLAY-001～004 通过；invalid 不 poison、64-way duplicate
   恰好一个成功、±30/±31、59.999/60 秒、wall rollback 与 capacity fail-closed。
6. **AC-06 Detection/binding:** M0-DETECT-001～003、M0-BIND-001 通过；single
   underlying I/O、typed abortive-close capability、批准的统一native close class和
   full request-salt binding均有直接证据。
7. **AC-07 SOCKS/local product path:** M0-SOCKS-001～002、M0-ENDPOINT-001、
   M0-E2E-001～002 通过；两个真实 binaries 完成 IPv4 echo/half-close；
   `local_addr` error/non-IPv4 保持零 first-write并发精确general failure，同时冻结
   target/protocol failure行为。
8. **AC-08 Lifecycle/backpressure:** M0-LIFE-001～005 通过；stalled writer传播
   backpressure，timeout/cancel/listener/half-close/shutdown 与至少 100 mixed cycles
   后 owner registry/buffer/socket 回基线。
9. **AC-09 Observability:** M0-OBS-001～003 通过；JSON/metric snapshot与 sentinel
   scan证明fixed fields/labels、无secret/destination、bounded cardinality和
   supervisor-owned metrics endpoint limits。
10. **AC-10 Interoperability:** M0-INT-001～004 全部 required PASS；pin、asset
    checksum/version、双向 bytes/half-close、sanitized diagnostics齐全，缺环境不
    得 skip-pass。
11. **AC-11 Platform/repository gates:** M0-PLAT-001～003、M0-GATE-001～002
    通过；三 target release binaries 在 matching runner 完成 valid/invalid config
    smoke，quick/full 在同一 integrated commit exit 0。
12. **AC-12 Scope/provenance:** M0-SCOPE-001 通过；固定从
    `b41c6127b1834ebd97246451fd92bafea50cb205` 到 integrated `HEAD` 的完整 diff
    不含 M0 non-goals、external binaries、generated results 或真实 secrets；所有
    fixture/reference/locked dependencies有来源和license review记录。

M0 只有在 AC-01～AC-12 同一 integrated commit 证据齐全时才能进入 close。

## Open questions

没有留给 Engineer 自行决定的 M0 contract 问题。以下是执行期验证 contingency，不
扩大实现权限：

- T08 首次下载时补录 reference asset byte size 与精确 `--version` 输出；checksum/
  version 不匹配即阻塞，不自行换版本。
- 仓库尚无 CI provider；required job contract 是 provider-neutral。matching runner
  不可用会阻塞 M0 close，而非允许 skip。
- zero-linger native probe若在 Windows/Linux 无法得到一致批准的 close class，
  必须停止并提议 ADR-0004 revision。
- DEC-008（UDP）、DEC-009（M3 完整平台 qualification）、DEC-010（M4 performance/
  10k threshold）明确延期，不是 M0 实现开放项。
