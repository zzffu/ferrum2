# SPEC-0001: M0 AES-128-GCM TCP 安全纵切

- **Status:** Approved
- **ADR-0010 amendment:** Approved
- **ADR-0011/0012 amendments:** Approved
- **ADR-0013 amendment:** Approved
- **ADR-0014 amendment:** Approved
- **ADR-0015 amendment:** Approved
- **ADR-0016 amendment:** Approved
- **Milestone:** M0
- **Related ADRs:** `ADR-0001`、`ADR-0002`、`ADR-0003`、`ADR-0004`、`ADR-0005`、`ADR-0006`、`ADR-0007`、`ADR-0008`、`ADR-0009`、`ADR-0010`、`ADR-0011`、`ADR-0012`、`ADR-0013`、`ADR-0014`、`ADR-0015`、`ADR-0016`
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

当前仓库的exact integration `51fb7327af966cfc3f4a49058ea6bf2284009dcf`
已经汇合T01～T08并通过local Team Lead、Architect与QA gates，包含完整M0
end-to-end product path。该SHA的首次hosted run `30301746374`为2/11 success、
9/11 failure；ADR-0015/T07/T08正在修复Linux listener restart与evidence-script
portability，因此该SHA不是M0 close commit。

M0 完成后的 client path：

```text
client TcpListener
 → Socks5Inbound::accept
 → Session<SocksStream, SocksReplyPending>
 → ShadowsocksTcpOutbound::connect_server [configured connect timeout; default 10s]
 → ConnectedClientOpen::write_request(application_target)
     [fresh configured handshake timeout; default 5s]
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
| `tests/m0-harness` | metadata/filesystem policy、黑盒process E2E、external interop/platform drivers、primitive-only independent native request generator | concrete ferrum2 Cargo dependency、production behavior |

Dependency DAG、toolchain、production versions/sources、license与release graph由
`ADR-0001`及其修订冻结。`ADR-0009`的`aes 0.9.1`/`ghash 0.6.0` no-default
`zeroize` anchors、`ADR-0011/0015`的harness test-only edges，以及`ADR-0013`
两个binary的Tokio `test-util` dev-kind edges组成当前M0 selected conformance
profile。ADR-0016部分取代“永久由T01独占”和“这些edge是唯一合法机制”的表述：
经执行前ticket/test mapping、exact authorization、single-writer lease与完整
lock/metadata/tree/MSRV gate，可以采用同等或更强的窄替代；test-only capability
不得进入production/release graph；production manifest只能在既有package
identities与既有resolved feature outcome内调整declaration/anchor spelling。
任何version/source/API/wire/unsafe/license/product behavior变化仍需新ADR/spec。

M0-T08继续独占CI路径`.github/workflows/m0.yml`；该workflow已在`51fb7327`实现并
执行过首次hosted run。ADR-0016不创建第二个workflow、不改变ADR-0007的
job/security/exact-SHA matrix，也不把当前T07/T08 repair或旧run改成PASS。

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
  → C4 ConnectedClientOpen
  → C5 RequestHeaderSingleWrite
  → C6 SocksSuccessSent
  → C7 Relaying(RequestOpen, ResponseAwaiting|ResponseOpen)
  → C8 Closing
```

- C0～C2 受 handshake timeout。
- C3 受 connect timeout。
- C4 是不暴露transport/cipher/nonce/scratch的single-use opaque capability；
  connect成功即停止configured connect budget，随后开始新的configured handshake
  budget；默认值分别为10秒/5秒，但实现不得硬编码默认值。
- C5 生成 16-byte salt、type 0、wall timestamp、target、`1..=900` padding；
  M0 ferrum2 client initial payload 为空。
- C5 成功定义为一次底层 write 返回整个 contiguous header 长度；short write失败，
  timeout是binary-owned `Reason::HandshakeTimeout`且normal drop/abortive 0，不扩展
  `ShadowsocksError`。
- C6 后 client→server data frames可发送；server→client bytes 必须等 response header/
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
`ADR-0004`；duplex ownership与executor-neutral interface采用`ADR-0010`。额外实现
约束：

- initial fixed read/write 使用记录底层 operation 的 abstraction；不得以
  `read_exact`/`write_all` 多次触底。
- 每个receive direction以一次固定`65551` usable-limit request创建reusable decrypt
  scratch；每flow以一次固定`16459` usable-limit request创建reusable encrypt
  scratch。两者storage identity保持不变且不reserve/grow；所有slice/length
  arithmetic用checked operations。
- request variable header完整消费；IPv4 address 7 bytes、padding length 2 bytes、
  padding `0..=900`，其余是 initial payload。padding 与 payload 不得同时为空；
  完整auth/semantics后才可为core `Session.initial_payload`创建一个最大`65526`
  bytes的bounded `Bytes` owner。
- encoder 将 application bytes 切成 `<=16384` chunks；decoder 接受最大 65535。
- response 必须绑定本连接完整 16-byte request salt，且 first response header 与
  nonempty first payload 一次 write。

### Opaque duplex interface

`ferrum2-shadowsocks`提供executor-neutral `TransportIo` seam与opaque
`ClientFlow`/`ServerFlow`。flow持有未拆分transport、logical RX/TX states、当前已
实例化cipher owner、pending response direction的一次性derivation capability、
scratch与单一lifecycle/fatal latch，并通过`PlainDuplex`只暴露plaintext poll
read/write/flush/shutdown及只读`terminal()`：

- `ClientTcpOutbound`构造时持有validated configured Shadowsocks server endpoint；
  `connect_server()`连接该stored server endpoint并返回opaque
  `ConnectedClientOpen`；后者被`write_request(application_target)`消费，且只把
  application target编码进SIP022 request。两者不得混用。fused core convenience
  `open`可以内部委托，但T07必须用分相interface分别应用validated config中的
  connect/handshake durations（默认10秒/5秒）。
- client flow在request first-write后立即允许TX；RX可同时等待并认证response。
- `ShadowsocksTcpInbound::accept`返回既有
  `Session<ServerFlow, NoReply>`；validated target和authenticated initial payload
  分别位于`Session.target`/`Session.initial_payload`。server flow RX只从
  subsequent request frame开始，不重复payload。
- server first nonempty plaintext write生成并single-write response first header；
  response pending不阻塞request RX。
- fixed 43/59-byte reads及request/response first-writes维持single completed
  operation；所有post-fixed region使用checked bounded-fill/write-drain。
- 合法zero-length subsequent payload frame必须完成认证与nonce推进；面对非空
  destination不得返回伪EOF，必须self-wake/Pending并在下一次outer poll继续下一
  frame。
- `TransportIo: AbortiveClose + Send + Unpin`与
  `PlainDuplex: Send + Unpin`不全局要求`LocalEndpoint`；只有`ClientFlow`按core
  `Outbound::Stream`要求委托stored endpoint。capabilities采用borrowed
  process-owner lifetime，`Clock`额外要求`Sync`，production-shaped flow必须
  compile-time证明`Send + Unpin`。
- T07的client `TokioConnector`及两个composition root内
  `TokioTransport`/`TokioFramed`只做connector/trait delegation与closed error
  mapping；server accepted socket先用现有`RuntimeTcpStream::from_connected`
  取得stored endpoint/abortive capability。不含任何protocol transition；
  core/runtime production dependency不变；manifest exceptions由ADR-0011限定在
  harness test dependencies/唯一lock hunk，并由ADR-0013限定在两个binary
  dev-only Tokio `test-util` declarations且无lock delta。

### Relay data flow

direct connect 成功后：

1. server connection owner先用binary-private bounded loop把非空
   `Session.initial_payload`完整、恰好一次写入target；每次successful nonzero
   write重置idle deadline。cancel、idle、write-zero或write failure返回精确partial
   prefix count且不进入普通relay；`ServerFlow`不重复该payload。
2. client request-write可与response-pending read并发；server request-read可与
   response-pending write并发。
3. 两方向 local futures 使用runtime-owned 16 KiB application buffers；SS flow
   内另持有固定reusable wire scratch。
4. `poll_write_plain`可在plaintext完整进入唯一encrypt scratch后报告consumption；
   scratch未drain时不接受下一段plaintext，因此writer stalled最多保留一个bounded
   frame并让对应reader停止；无data queue。
5. 每个outer protocol poll最多触发一个underlying transport operation；
   always-ready one-byte fragmentation不得饿死反方向。
6. complete subsequent frame之间的EOF只shutdown对侧writer，反方向继续。
7. detection/protocol/transport fatal或cancellation终止本flow两方向并回收；
   只有initial Detection调用abortive。正常单向EOF/shutdown只关闭该方向，反方向
   继续。
8. `relay_lifecycle`无论success、I/O failure、idle timeout或cancellation都保留
   terminal前每方向successful nonzero application writes的`RelayStats`；binary只
   把server prefix count恰好一次加到对应方向，不统计read-ahead、ciphertext或
   protocol overhead。

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
- protocol公开error精确为`Connect(ConnectErrorKind)`、
  `Detection(DetectionReason)`、`Protocol(ProtocolReason)`与
  `Transport(TransportPhase)`；`ProtocolReason`只有`Authentication`、
  `FrameBounds`、`NonceExhausted`，`TransportPhase`只有`Read`、`Write`、
  `WriteZero`、`Flush`、`Shutdown`。`FlowTerminal`只有`Normal`及上述三个
  flow-fatal类别；`ResponseUnavailable`删除。
- 只有参与request/response first-envelope的fixed/variable/first-payload read、
  contiguous first-write、auth或semantics failure才是Detection。terminal先安装，
  再恰好一次调用`AbortiveClose::mark_abortive`；mark失败不恢复。另一方向的
  subsequent operation不因response pending而改类。first-envelope完成后的
  tag/bounds/mid-frame EOF/nonce failure为Protocol，underlying I/O为Transport；
  两者均终止两方向但不abortive。server response-pending empty flush零I/O；
  shutdown不发header且failure为`Transport(Shutdown)`。
- RX frame-boundary EOF与TX shutdown为direction-local normal close；只有两方向
  都关闭才是`Normal` terminal。仅在RX仍open时，TX shutdown后的nonempty write
  安装`Transport(Write)`；`Normal`安装后不可替换，read/write返回`Ok(0)`、
  flush/shutdown成功且全部零I/O。fatal后所有poll返回相同typed error且不再触底。
- T07按ADR-0010穷尽映射既有observability `Reason`，不得字符串判断。
  client configured-SS-server `ShadowsocksError::Connect`固定为
  `stage=shadowsocks,outcome=failed`；server direct-target core
  `ConnectErrorKind`固定为`stage=direct,outcome=failed`；Detection/Protocol固定为
  `stage=shadowsocks,outcome=rejected`；Transport固定为
  `stage=relay,outcome=failed`；Normal固定为
  `stage=relay,outcome=completed`且无reason。
  `TokioFramed`对Detection/Protocol使用
  `io::Error::from(ErrorKind::InvalidData)`，对Transport使用
  `io::Error::from(ErrorKind::Other)`；不保留underlying source。
- 普通 EOF、target refusal、idle/operator shutdown 不伪装成 authentication
  failure，也不得调用`mark_abortive`。
- authentication/semantic failure只关闭当前 flow；listener failure 是 process fatal。
- replay mutex/state error、entropy/clock failure、nonce overflow、capacity full 全部
  fail closed，不降级、不 retry 弱策略。
- target connect 只在 S4 后发生。client 侧 pre-success connect error 可发一次 SOCKS
  failure；server target failure发生在 success 后，只关闭 stream。
- client configured-server connect deadline精确映射
  `ConnectErrorKind::Timeout`/`ConnectTimeout`；connect完成后fresh configured
  handshake duration覆盖request first-write并映射binary
  `Reason::HandshakeTimeout`。两者使用validated config values（默认10秒/5秒），
  不得复用budget、硬编码默认值、扩展protocol error taxonomy或把timeout伪装成
  Detection。
- relay/prefix failure保留失败前每方向已成功写出的application byte totals；error
  reason与partial stats必须同时可用，normal与failure都不得double count。
- 没有 error path 可 panic、按 peer 值无界 allocate 或 forward unauthenticated bytes。

## Security and privacy

- fixed SIP022 revision、primitive/protocol fixture provenance、exact replay 和
  detection strategy 由 ADR-0004/0006/0008 定义；duplex/fatal ownership由
  ADR-0010定义。ADR-0008仅纠正两个
  AES-GCM primitive cases 的来源归属，不改变 numeric values 或密码/协议行为。
  ADR-0016允许bytes/result不变的后续事实性provenance勘误作为evidence amendment，
  但更换fixture bytes、expected result、reference pin或分发/license决定仍须
  architecture/scope revision。
- AEAD owner 的 dependency-review evidence 由 ADR-0002/0009 联合定义：
  `aes-gcm/zeroize`、`aes/zeroize`、`ghash/zeroize` 与
  `polyval/zeroize` 必须在同一 exact registry package instances 上启用；
  metadata feature sets、`zeroize/aarch64` induced feature 与 pre-repair 110-tuple
  lock identity baseline 必须 exact；这不改变 AES API、wire 或 physical-memory
  guarantee 边界。package identities和上述resolved feature sets是normative，
  不能以ADR-0016 equivalent substitution改变。
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
| encrypt wire scratch | 每 active flow一次固定16459 usable-limit allocation request；storage identity不变、不增长 |
| decrypt wire scratch | 每 active receive direction一次固定65551 usable-limit allocation request；storage identity不变、不增长 |
| authenticated initial payload | core `Session`中一个bounded `Bytes` owner，完整auth/semantics后创建，最大65526 bytes，forward或drop后释放 |
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
`ADR-0005`，partial relay outcome采用`ADR-0012`。required lifecycle evidence按
`ADR-0011`组合：恰好100个real-process mixed cycles证明child/port/temp cleanup；
T06 direct tests证明真实runtime counters/JoinSet；两个binary的production-used
private `run_with_registry` tests证明composition连接了同一个registry，先观察live
non-baseline再回baseline。`forced_shutdowns`只断言精确累计增量。RSS、process exit
或port rebind不能单独替代内部counter证据。ADR-0015部分取代 exact-rebind seam：
client/server各自的binary-private listener constructor只在Unix bind前启用
`SO_REUSEADDR`，Windows保持默认且所有平台禁止`SO_REUSEPORT`；harness-owned
target/foreign listeners与cleanup probe从首次bind起使用相同平台策略并完成
bind+listen。完全终止后的exact proxy/metrics/target地址必须立即可重绑，而一个
仍存活的同策略listener必须继续阻止第二个listener。

上述100-cycle、direct counter、binary-private registry与same-policy bind probe是
当前selected conformance profile。ADR-0016允许重新组织test process、private seam
或test-only依赖，但不得减少五类各20次、逐cycle cleanup/rebind、内部owner直接
证据、immediate restart或live-owner exclusion，也不得让black-box外观冒充进程内
状态。

## Compatibility and upstream divergence

- 固定 reference pins、四项 matrix、artifact checksums 和 required-job policy 见
  `ADR-0006`；GitHub Actions provider、hosted runner 和 evidence 表达见
  `ADR-0007`。
- M0 只声明 AES-128 TCP/IPv4 covered path，不声明完整 SIP022/v0 compatibility。
- reference 的 replay ordering、logging、unsafe 或 binding 偏差不进入 ferrum2。
  若互操作揭示规范 ambiguity，停止 gate并先修订 ADR/spec。
- M1 对 method/地址支持只能 additive；不得复制 transport state machine或改变已
  固定 AES-128 wire。

## M0 CI provider contract

M0 required CI 固定为公开 repository `zzffu/ferrum2` 的 GitHub Actions，
workflow path 为 `.github/workflows/m0.yml`。workflow 只允许
`pull_request`、push 到 `master`/`codex/integration/**` 和
`workflow_dispatch`；禁止 `pull_request_target` 及其他 triggers。

workflow 使用
`actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd`
（v6.0.2），设置 `ref: ${{ github.sha }}`、`fetch-depth: 0`、
`clean: true`、`persist-credentials: false`。所有 `uses:` 必须固定完整
40-hex commit SHA。顶层权限只有 `contents: read`，其余为 `none`，job 不得
提升权限。required jobs 不使用 cache，不依赖 cache hit，不使用
`continue-on-error`，不读取 `secrets.*`。

required job ID 和 displayed name、runner、timeout 精确为：

| Required job | Runner | Timeout (minutes) |
|---|---|---:|
| `m0-host-quick` | `ubuntu-24.04` | 60 |
| `m0-security` | `ubuntu-24.04` | 60 |
| `m0-lifecycle` | `ubuntu-24.04` | 60 |
| `m0-local-e2e` | `ubuntu-24.04` | 60 |
| `m0-integration-full` | `ubuntu-24.04` | 60 |
| `m0-msrv` | `ubuntu-24.04` | 60 |
| `m0-windows-msvc` | `windows-2022` | 60 |
| `m0-linux-gnu` | `ubuntu-24.04` | 60 |
| `m0-linux-musl` | `ubuntu-24.04` | 60 |
| `m0-interop-sing-box` | `ubuntu-24.04` | 60 |
| `m0-interop-shadowsocks-rust` | `ubuntu-24.04` | 60 |

`ubuntu-latest`、`windows-latest` 与任何 `*-latest` 禁止。每个 job checkout 后
断言 clean worktree 和 `git rev-parse HEAD == GITHUB_SHA`。platform/interop
job 在自己的 fresh VM 内构建当前 commit binaries，不消费其他 job/run 的
ferrum2 artifact。

`m0-linux-musl` 固定安装 `musl`/`musl-dev`/`musl-tools=1.2.4-2`，用
`musl-gcc` 为 linker 构建两个 `x86_64-unknown-linux-musl` release binaries，
原生运行各自 valid/invalid `--check-config`，并以 `file` 与
`readelf -hW/-lW/-dW` 证明两个 artifact 均无 `PT_INTERP`/`DT_NEEDED`。
`m0-linux-gnu` 构建并原生运行两个 `x86_64-unknown-linux-gnu` release
artifacts 的 valid/invalid config matrix，同时阻塞运行 M0-DETECT-002。
Windows 2022 job 同样运行两个 MSVC artifacts 的 config matrix 和
M0-DETECT-002。精确 command/test allocation 见 TEST-0001。

interop job 执行 reference binary 前必须核实 ADR-0006 既有固定
SHA-256、size/version 和 license record；只使用 ADR-0006 的 synthetic PSK，
不读取 repository secrets。每个 required job 记录 run ID/attempt、job、
`GITHUB_SHA`、`RUNNER_OS`/`RUNNER_ARCH`、`ImageOS`、`ImageVersion`、
OS/kernel、rustc/cargo/linker；CI status 链接 `Set up job` 中 exact
`Included Software` URL。platform job 另记录 artifact SHA-256 和 linkage。

GitHub-hosted VM 没有本项目可固定的 OCI image digest；上述 provider-native
runner evidence 被批准用于 M0 smoke，但不是 M3 完整平台资格。job 启动后的
setup/network/package/reference/command/timeout/evidence 错误是 FAIL；workflow、
push、provider 或 required job 不可用导致没有结果是 BLOCKED；missing、
skipped、cancelled 或 neutral 均不是 PASS。

M0 close evidence 只能来自另行授权 push 后的一次完整 GitHub Actions run：
同一 run ID/attempt 的 11 jobs 全部 success，且 `GITHUB_SHA` 精确等于批准的
integration commit。不同 SHA 的 PR/manual run 和本机/WSL2 结果不能替代。

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
schema、reference pins 或 ADR-0007 的 provider/workflow/job/runner/security/
evidence contract 必须用新的 ADR/spec revision，不得静默编辑实现理由。远程
revert、branch mutation 或 workflow rerun 仍需用户单独授权。

只改变selected conformance profile或mechanical realization、且ADR-0016的全部
equivalence条件成立时，可以使用执行前的TEST/ticket amendment而不新建产品ADR；
它仍须在新exact candidate SHA上重跑受影响gate，且不得追认旧失败证据。

## Acceptance criteria

1. **AC-01 Workspace/toolchain:** M0-WS-001、M0-WS-002、M0-MSRV-001 通过；
   workspace members/DAG、ADR-0001/0009 exact direct versions/features、lock、
   package version/source/checksum identity、license、unsafe forbid、Rust 1.85.0
   locked graph 均有证据。
2. **AC-02 Offline config/CLI:** M0-CFG-001～003、M0-CLI-001 通过；两个 binaries
   的 valid/invalid matrix 与零 listener/connector/task 副作用直接可见。
3. **AC-03 Crypto correctness/secrets:** M0-CRYPTO-001～004 通过；primitive vectors、
   KDF/nonce fixture、redaction/clear seam、entropy failure和nonce overflow均精确。
4. **AC-04 SIP022 fail-closed ordering:** M0-PROTO-001～009 通过；有provenance的
    非官方composite wire KAT通过，且所有auth、bounds、semantic和allocation
    negative case在connector/forward/accepted/replay mutation前失败；opaque flow
    在response pending时保持duplex/fair progress；对向subsequent failure不被
    pending first-envelope重分类且abortive为0；post-fixed fragmentation（含
    zero-length subsequent frame不伪装EOF）、
    scratch reuse、poll/admission边界与exact terminal matrix有直接证据。
5. **AC-05 Replay/time:** M0-REPLAY-001～004 通过；invalid 不 poison、64-way duplicate
   恰好一个成功、±30/±31、59.999/60 秒、wall rollback 与 capacity fail-closed。
6. **AC-06 Detection/binding:** M0-DETECT-001～003、M0-BIND-001 通过；single
   underlying I/O、typed abortive-close capability、full request-salt binding，
   以及ADR-0011 primitive-only generator构造的43个short prefixes加
   auth/type/time/length共47个native connections均有直接证据；全部是批准的
   reset class、非EOF，且每案target accepts为0。authenticated zero variable length
   的typed reason精确为`AddressBounds`。47-row覆盖与独立construction是不变量；
   process/helper布局只是ADR-0016 selected profile。
7. **AC-07 SOCKS/local product path:** M0-SOCKS-001～002、M0-ENDPOINT-001、
   M0-ADAPT-001～002、M0-E2E-001～002 通过；两个真实 binaries 完成 IPv4
   echo/half-close；production adapters、client configured-server
   dial/application-target wire separation、configured connect与fresh configured
   request first-write phase deadlines（默认10秒/5秒）及server
   connect-before-initial-payload-forward有focused证据，全部typed terminal/Connect
   及Normal的role/call-site observability映射穷尽；当前paused-time capability由
   ADR-0013两个binary dev edges提供。ADR-0016允许同等的package-local dev-only
   受控时间方案，但production feature tree必须不含test capability，并同时杀死
   default/non-default hardcoding与wall-clock mutation；
   `local_addr` error/non-IPv4 保持零 first-write并发精确general failure，同时冻结
   target/protocol failure行为。
8. **AC-08 Lifecycle/backpressure:** M0-LIFE-001～005 通过；stalled writer传播
   backpressure；timeout/cancel/listener/half-close/shutdown保留failure前partial
   direction stats；恰好100个五类均分black-box cycles与T06/binary-private直接证据
   共同证明owner task/buffer/permit/listener/child/port/temp cleanup；Unix真实连接
   后完全终止的proxy/metrics/target exact地址可立即bind+listen，Windows保持默认
   exclusive语义，且任一平台的live same-policy listener都阻止第二个listener。
9. **AC-09 Observability:** M0-OBS-001～003 通过；JSON/metric snapshot与 sentinel
   scan证明fixed fields/labels、无secret/destination、bounded cardinality和
   supervisor-owned metrics endpoint limits。
10. **AC-10 Interoperability:** M0-INT-001～004 全部 required PASS；pin、asset
    checksum/version、pre-FIN双向bytes、ordered clean-EOF convergence与
    sanitized diagnostics齐全，缺环境不得 skip-pass；两个 interop job 分别在
    自己的 `ubuntu-24.04` clean VM 从
    `GITHUB_SHA` 构建 ferrum2，并在执行 reference 前验证既有 pin/hash/version。
    每案先完整逐byte比较双向各16386-byte distinct payload，再依次观察application
    client write-half close后的target clean `Ok(0)`、target成功write-half close后
    的application client clean `Ok(0)`；
    byte equality前不得发送FIN。external evidence不声明peer FIN后新产生的reverse
    bytes能穿过sing-box 1.13.14，也不声明target FIN导致client EOF；该ferrum2
    行为仍由同一SHA上未修改的
    M0-E2E-001/M0-LIFE-003独立blocking。
11. **AC-11 Platform/repository/CI gates:** M0-PLAT-001～003、
    M0-GATE-001～002、M0-CI-001～006 通过；三个 target release binaries 在
    固定 hosted runner 完成 valid/invalid config smoke，GNU/Windows
    M0-DETECT-002 和 musl static proof 完整；同一 pushed exact integration
    commit 的一个 run/attempt 中 11 个固定 job 全部 success。
12. **AC-12 Scope/provenance:** M0-SCOPE-001 通过；固定从
    `b41c6127b1834ebd97246451fd92bafea50cb205` 到 integrated `HEAD` 的完整 diff
    仍被逐项枚举。仅用户明确授权的既有 skill optimization
    `d1ef4bcfb081a89c5da1185dcb7c57606f8ec77e` 中 23 个 exact out-of-band
    control-plane paths 不进入 M0 内容/provenance 扫描；该例外必须同时固定
    `d1ef4bcf` 的精确 parent、完整 commit path set、逐路径 blob identity，并要求
    `d1ef4bcf` 是 `HEAD` ancestor。任一路径、内容、rename、descendant、near-miss
    或额外 spillover 不匹配都 fail closed；不得使用目录 glob、移动 baseline 或
    缩小 diff。其余完整 M0 diff 不含 non-goals、external binaries、generated
    results 或真实 secrets；所有 fixture/reference/locked dependencies有来源和
    license review记录；dependency
    当前selected profile中production dependency surface精确等于ADR-0001经
    ADR-0009部分取代后的集合；harness direct dev dependencies与lock hunk精确等于
    ADR-0011经ADR-0015部分取代后的allowlist（两个primitive edges加一个
    rebind-evidence `socket2` edge），两个binary dev-kind Tokio declarations精确
    等于ADR-0013 allowlist且production trees不含`test-util`、lock无新增hunk，
    package identities/resolved crypto features不变。若执行前按ADR-0016批准
    equivalent substitution，则审计改为精确比较该amended profile，并另外证明
    production/release graph、安全feature、version/source/license及coverage不弱于
    本baseline；唯一批准的
    `.github` path是M0-T08拥有的`.github/workflows/m0.yml`。

M0 只有在 AC-01～AC-12 同一 integrated commit 证据齐全时才能进入 close。

## Open questions

ADR-0010～0015已批准，不留给 Engineer 自行决定的 M0 contract 问题。以下是
执行期验证 contingency，不扩大实现权限：

- T08已固定并验证reference asset byte size、checksum与精确`--version`输出；
  后续run任一不匹配仍阻塞，不自行换版本。
- GitHub Actions provider 与 required workflow contract 已由 ADR-0007 固定；
  workflow已实现，exact `51fb7327`已按一次授权push并产生失败run
  `30301746374`。Origin固定URL已验证正确；修复后的新exact
  `codex/integration/m0`必须先通过T08 local integration、Architect与QA gates，
  并获得separately authorized push，才可非force更新同名remote branch并等待新
  Actions run。master、PR、branch protection、tag/release、rerun及其他remote
  mutation均未授权。
- zero-linger native probe若在 Windows/Linux 无法得到一致批准的 close class，
  必须停止并提议 ADR-0004 revision。
- DEC-008（UDP）、DEC-009（M3 完整平台 qualification）、DEC-010（M4 performance/
  10k threshold）明确延期，不是 M0 实现开放项。
