# ADR-0010: M0 opaque SIP022 duplex flow ownership

- **Status:** Accepted
- **Date:** 2026-07-27
- **Owners:** Architect / Team Lead
- **Related milestone/spec/tickets:** M0；`SPEC-0001`；M0-T03、M0-T07；
  窄幅取代 ADR-0004 的 caller-visible TCP stream transition/`HeaderIo`
  interface；保持 ADR-0001 `Session` ownership 与 ADR-0005 owner-task lifecycle

## Context and problem

M0-T03 candidate `05605d328cc35952676cadc8ce30e6c4b91fbf7a` 的 replay、
binding、wire fixture 与部分 detection ordering 已通过现有命令，但 Architect/QA
review 发现其 caller-visible transitions 无法组成 SPEC-0001 已批准的 duplex relay：

- client 等待 response first-read 时独占整个 transport，request writer不能继续；
- transition/`into_parts` 会丢弃 request sealer 或 response sealer；
- server target transition丢弃 core `Session.initial_payload`；
- 43/59-byte fixed region之后仍只允许一次read，合法TCP fragmentation被误判；
- handshake与每帧重新分配maximum scratch，不能证明fixed reusable ownership；
- duplex开始后没有单一fatal owner来保证fatal terminal与abortive exactly once，
  同时保留正常half-close。

这些是既有M0行为的实现/接口缺口，不要求改变SIP022 wire、产品范围、core
`Session`、runtime task topology或buffer caps。用户已授权后续M0内全部本地窄
blocker修复；本ADR仍须经Product/Architect/QA批准后才能开始repair。

## Scope and non-goals

本决策只冻结M0 AES-128 SIP022 TCP flow的内部ownership、executor-neutral poll
interface、closed failures与对应证据。

明确不做：

- 不改变SIP022 revision、wire bytes、KDF、nonce progression、replay、binding、
  detection class、fixture或reference pins；
- 不新增cipher、UDP、address family、SIP023、多用户、routing、DNS、management
  或operator capability；
- 不修改`ferrum2-core`、`ferrum2-runtime`、任何manifest、`Cargo.lock`、dependency
  graph或one-owner-task/two-local-future topology；
- 不把protocol、cipher、frame或terminal classification迁入binary adapters；
- 不产生新的remote授权。本地合同/repair授权不授权push、PR、workflow rerun、
  tag/release或其他remote mutation；原T08 exact-integration-SHA条件授权保持独立。

## Decision drivers and invariants

- `ferrum2-shadowsocks`是deep module；T07不得看到或排序`TcpSealer`、
  `TcpOpener`、salt、nonce、frame phase或scratch。
- client request-write在response pending时可推进；server request-read在first
  target response pending时可推进。
- 整个SS transport由一个opaque flow持有，不physical split/reunite，不引入
  `Arc<Mutex<_>>`、direction task或data channel。
- request 43-byte、response 59-byte fixed region以及各自contiguous first-write
  使用一个completed underlying operation；`Pending` polls不计completed
  operation。之后全部bounded fill/write-drain接受任意合法fragmentation。
- server inbound继续返回core
  `Session<ServerFlow, NoReply>`：validated target与authenticated initial payload
  分别进入`Session.target`/`Session.initial_payload`；`ServerFlow` RX只从
  subsequent request frame开始，不重复payload。
- 每flow一个fixed-request reusable encrypt scratch，usable limit `16459` bytes；
  每receive direction一个fixed-request reusable decrypt scratch，usable limit
  `65551` bytes；storage identity不随frame变化且不得增长。
- initial Detection先安装fatal terminal，再恰好一次
  `AbortiveClose::mark_abortive`；mark失败也不得恢复。post-first-envelope
  Protocol/Transport fatal终止两方向但不abortive；ordinary EOF/half-close不
  abortive且不提前终止反方向。
- 保持ADR-0005的一个connection owner task、两个local futures、runtime-owned
  timeout/cancellation/backpressure/half-close。

## Options considered

### Option A：opaque fused flow + binary-local Tokio adapters

`ClientFlow`/`ServerFlow`持有未拆分transport、独立logical RX/TX state、当前已
实例化的cipher owner、pending direction的一次性derivation capability、scratch与
一个lifecycle/fatal latch。protocol暴露executor-neutral transport与plaintext
duplex interfaces；T07用薄newtype adapters映射Tokio traits。

### Option B：physical reader/writer/abort split

显式direction owners可独立驱动，但需要shared abort arbitration或reunite，
interface更宽、caller更容易丢owner，并为每flow引入额外shared synchronization。

### Option C：protocol-owned完整relay future

interface最小，但会复制runtime的idle/cancellation/accounting/half-close，或要求
runtime反向理解protocol。

### Option D：direction drivers + generic runtime coordinator

ports清晰，但扩展runtime interface并把protocol fatal token、progress与join policy
暴露给更多caller；在现有`relay_lifecycle`可复用时不具必要性。

## Decision

选择Option A。

`ferrum2-shadowsocks`提供以下executor-neutral seam；精确Rust lifetime spelling可
为borrow checker做机械调整，但interface能力、ownership与error contract不得改变：

```rust
pub trait TransportIo: AbortiveClose + Send + Unpin {
    type IoError;

    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        destination: &mut [u8],
    ) -> Poll<Result<usize, Self::IoError>>;

    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<Result<usize, Self::IoError>>;

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::IoError>>;

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::IoError>>;
}

pub trait PlainDuplex: Send + Unpin {
    fn poll_read_plain(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        destination: &mut [u8],
    ) -> Poll<Result<usize, ShadowsocksError>>;

    fn poll_write_plain(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        source: &[u8],
    ) -> Poll<Result<usize, ShadowsocksError>>;

    fn poll_flush_plain(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ShadowsocksError>>;

    fn poll_shutdown_plain(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ShadowsocksError>>;

    fn terminal(&self) -> Option<FlowTerminal>;
}
```

`TransportIo`/`PlainDuplex`不全局要求`LocalEndpoint`。只有core
`Outbound::Stream`所需的`ClientFlow`在underlying transport实现
`LocalEndpoint`时委托该trait；`ServerFlow`不暴露endpoint。

### Capability and flow ownership

M0选择borrowed process capabilities，不改为隐式global或trait object：

- `ClientFlow<'a, S, K, T>`保留`&'a K`/`&'a T`以在response salt出现后恰好一次
  创建response opener；TX从open起持有request sealer。
- `ServerFlow<'a, S, K, T, R>`保留`&'a K`/`&'a T`/`&'a R`以在首个nonempty
  target payload出现后恰好一次创建response sealer；RX从accept起持有request
  opener。
- `K: KeyProvider + Sync`、`T: Clock + Sync`、`R: SecureRandom`，transport与
  instantiated flow必须`Send + Unpin`。T03做compile-time assertions；T07
  connection future拥有这些引用的process-lifetime owners。

client `Outbound::open`在connector与request single-write成功后返回opaque
`ClientFlow`：

- `ClientTcpOutbound`在构造时接收并持有validated configured Shadowsocks server
  endpoint；`open(application_target)`只把`application_target`编码进request，
  connector必须连接stored server endpoint，绝不能dial application target；
- TX为`RequestOpen(TcpSealer)`；
- RX为`ResponseFixedPending → ResponsePayloadFill → ResponseOpen(TcpOpener)`；
- response type/time/full request-salt binding与first payload authentication完成前
  不释放任何byte。

server `ShadowsocksTcpInbound::accept`在完整request
authentication/semantics/replay reserve后返回：

```text
Session {
  target: validated target,
  stream: ServerFlow,
  initial_payload: authenticated Bytes,
  reply: NoReply,
}
```

`NoReply`实现core `SessionReply`，其consuming success/failure均为无副作用
`Infallible`完成。`ServerFlow`：

- RX为`RequestOpen(TcpOpener)`，不含也不重复交付`Session.initial_payload`；
- TX为`ResponsePending → ResponseFirstWriting → ResponseOpen(TcpSealer)`；
- empty target write不触发response；target在任何response byte前EOF时，T07只
  shutdown TX，不发送empty response header。

T07 connection owner必须先完成direct connect，再把非空`Session.initial_payload`
完整、恰好一次写入target；connect或prefix write失败即停止，不进入普通relay。
之后才把`ServerFlow`与target交给未修改的`relay_lifecycle`。

### Binary-local adapters

T07只拥有下列薄adapters：

- client `TokioConnector<C>`机械委托core `Connector`并把成功的`C::Stream`包装为
  `TokioTransport<C::Stream>`；它不选择或替换target。T03的
  `ClientTcpOutbound`把stored configured server endpoint传给该connector，并把
  application target只交给request encoder；connect error与ordering不变；
- 两个composition roots的`TokioTransport<T>`包装runtime stream，实现
  `TransportIo`；在`T`支持时机械委托`LocalEndpoint`与`AbortiveClose`；
- 两个composition roots的`TokioFramed<F>`包装`PlainDuplex`，安全地使用Tokio
  initialized `ReadBuf` slice并实现`AsyncRead + AsyncWrite`。它的只读terminal
  accessor委托inner flow的唯一latch，不保存第二份terminal；error conversion只
  执行本ADR的穷尽映射，不重新分类。

server accepted `TcpStream`先通过现有`RuntimeTcpStream::from_connected`取得
abortive capability，再包装为`TokioTransport`；direct target stream不进入protocol
adapter。adapter不得包含KDF、nonce、frame、binding、replay、buffer sizing或
transition logic。

## Poll, fairness and buffer contract

- 每次outer `PlainDuplex` poll最多执行一个underlying `TransportIo` operation。
  always-ready partial operation后若尚无user-visible完成值，调用`wake_by_ref`并
  返回`Pending`；不得在一个poll内吞完最多65551个one-byte fragments。两个logical
  directions因此在bounded poll count内均可推进。
- fixed first-read/first-write可因`Pending`被重复poll，但只能产生一个completed
  transport attempt；完成值short即Detection，不retry剩余bytes。
- request variable、response first payload、subsequent encrypted length/payload
  使用checked bounded-fill；任意`1..remaining` fragmentation均合法。
- decoder认证并接受合法的zero-length subsequent payload frame；当调用者提供非空
  destination时，该frame只推进nonce/state，不得以`Ok(0)`伪装EOF。flow必须
  self-wake并返回`Pending`，由下一次outer poll继续下一frame。
- `poll_read_plain`在live state且destination为空时返回`Ok(0)`，不poll transport、
  不改变state。frame-boundary EOF关闭RX；后续read持续返回`Ok(0)`且不触底。
- `poll_write_plain`的source为空时返回`Ok(0)`且不触发response、nonce或I/O。
  source长度`1..=16384`完整admit；长度`>16384`只admit前16384并返回16384。
- plaintext完整加密并admit到唯一encrypt scratch后即可报告consumption。scratch
  占用时先以最多一个underlying write推进drain：未drain则`Pending`；drain完成后
  才可admit当前source。不得依赖caller在`Pending`后重交旧source。
- server first response wire可在admission后pending，但仍只有一个completed
  transport write；short completion为Detection。response first-write完成前不接受
  第二段plaintext。
- server TX仍为`ResponsePending`且没有staged wire时，flush直接成功且不触底；
  shutdown不生成header，直接poll underlying shutdown，其I/O failure为
  `Transport(Shutdown)`而非Detection。
- normal shutdown先drain TX，再poll underlying shutdown；TX shutdown幂等，之后
  flush/shutdown返回成功且不触底。flow仍为`Live { tx_closed, rx_open }`时，
  TX关闭后的nonempty write返回并安装`Transport(Write)` fatal。若RX也已关闭并
  安装`Normal`，后续read/write均返回`Ok(0)`，flush/shutdown返回成功，terminal
  保持`Normal`且不触底。
- flow使用一次固定request创建encrypt/decrypt scratch。observer记录
  `BufferRole`、requested usable limit与opaque storage identity；handshake、
  minimum/maximum及subsequent frames间identity不变，不调用reserve/grow。
- authenticated initial payload在完整auth/semantics之后复制为core `Session`
  所需的单一bounded `Bytes` owner，最大`65526` bytes；它不是wire scratch，
  由T07在forward或drop后释放。

## Closed errors, terminal and observability

公开closed enums精确为：

```rust
pub enum ProtocolReason {
    Authentication,
    FrameBounds,
    NonceExhausted,
}

pub enum TransportPhase {
    Read,
    Write,
    WriteZero,
    Flush,
    Shutdown,
}

pub enum FlowTerminal {
    Normal,
    Detection(DetectionReason),
    Protocol(ProtocolReason),
    Transport(TransportPhase),
}

pub enum ShadowsocksError {
    Connect(ConnectErrorKind),
    Detection(DetectionReason),
    Protocol(ProtocolReason),
    Transport(TransportPhase),
}
```

这些类型为`Clone + Copy + Debug + Eq + PartialEq`，Display只输出固定文本，不持有
source、secret或peer text。candidate的`ResponseUnavailable`删除：target在response
pending时EOF是server TX正常shutdown；client未完成response first-envelope时看到
EOF仍为`Detection(ShortRead)`。

“first-envelope完成”按logical direction定义：client TX request first-write和
server RX request fixed+variable在flow创建前完成；client RX需完成response fixed+
first payload authentication；server TX需完成response contiguous first-write。
只有参与该first-envelope的fixed/variable/first-payload read、contiguous
first-write、auth或semantic operation失败才是Detection；另一logical direction的
subsequent operation不因response仍pending而改类，且response-pending empty
flush/shutdown遵循上一节。first-envelope完成后的规则如下：

| Event | Closed result | Abortive |
|---|---|---:|
| client configured-SS-server connector error before transport | `Connect(kind)` | 0 |
| initial request/response first-envelope failure | `Detection(reason)` | exactly 1 |
| subsequent tag/auth failure | `Protocol(Authentication)` | 0 |
| subsequent bounds or mid-frame EOF | `Protocol(FrameBounds)` | 0 |
| subsequent nonce exhaustion | `Protocol(NonceExhausted)` | 0 |
| subsequent underlying read/write/flush/shutdown error | matching `Transport(phase)` | 0 |
| nonempty pending wire gets completed write `0` | `Transport(WriteZero)` | 0 |
| frame-boundary EOF or direction shutdown | direction-local normal close | 0 |
| target EOF while server response pending | direction-local normal TX close, no header | 0 |
| timeout/cancel/operator shutdown | runtime-owned normal drop | 0 |

private lifecycle latch在`Live`内分别记录RX EOF与TX shutdown；任一正常方向关闭不
终止反方向，只有两方向都关闭后才进入`Normal` terminal。fatal transition只有
`Live → Detection`、`Live → Protocol`或`Live → Transport`一次。Detection先安装
terminal，再调用一次`mark_abortive`；Protocol/Transport/Normal不调用。fatal后
全部poll返回同一typed error，且transport/cipher/observer counts不再增长。
`Normal`同样不可替换；其重复poll使用上一节的closed success语义。

production使用no-op `FlowObserver`/`BufferObserver`。recording observer只接收closed
terminal event、buffer role/request/opaque identity；与`RecordingTransportIo`
共享sequence recorder，直接证明terminal-installed事件早于abortive调用，不记录
wire、secret或peer text。

T07到既有observability `Reason`的穷尽映射固定为：

| Source | `Reason` |
|---|---|
| `Detection(ShortRead|ShortWrite|Authentication|KeyUnavailable)` | `Authentication` |
| `Detection(InvalidType)` | `InvalidType` |
| `Detection(TimestampSkew)` | `TimestampSkew` |
| `Detection(FrameBounds|PaddingBounds|EmptyRequest)` | `FrameBounds` |
| `Detection(AddressBounds)` | `AddressBounds` |
| `Detection(ResponseBinding)` | `ResponseBinding` |
| `Detection(ClockUnavailable)` | `ClockUnavailable` |
| `Detection(RandomUnavailable)` | `RandomUnavailable` |
| `Detection(Replay)` | `Replay` |
| `Detection(ReplayCapacity)` | `ReplayCapacity` |
| `Detection(ReplayUnavailable|ReadFailed|WriteFailed)` | `RelayIo` |
| `Protocol(Authentication|FrameBounds|NonceExhausted)` | same-named `Reason` |
| any `Transport` | `RelayIo` |
| `Connect(NetworkUnreachable|HostUnreachable|ConnectionRefused|Timeout)` | corresponding reason；`Timeout`→`ConnectTimeout` |
| `Connect(Other)` | `RelayIo` |

Detection/Protocol记录`stage=shadowsocks,outcome=rejected`；Transport记录
`stage=relay,outcome=failed`；client `ShadowsocksError::Connect`记录
`stage=shadowsocks,outcome=failed`。server T07 direct-target connector的core
`ConnectErrorKind`记录`stage=direct,outcome=failed`。Normal记录
`stage=relay,outcome=completed`且无reason。两种connect按role/call-site区分，
不得从error string推断。

`TokioFramed`把Detection/Protocol用
`io::Error::from(io::ErrorKind::InvalidData)`，Transport用
`io::Error::from(io::ErrorKind::Other)`；不得把Connect交给framed adapter。此构造
固定kind/standard message且`get_ref()`为`None`，underlying source sentinel不得
出现在Debug/Display/source chain。inner flow的唯一typed terminal由adapter只读
委托，供relay结束后的typed instrumentation读取。

## Consequences and tradeoffs

### Positive

- T07看到plaintext duplex与既有core `Session`，无法丢失cipher owner、target或
  initial payload。
- 未拆分transport使fatal/abortive ownership唯一，不需要shared mutex或reunite。
- 复用现有runtime lifecycle，保持dependency DAG与task topology。
- scripted与production adapters跨相同seams；测试不触碰private cipher/phase。

### Negative

- `ferrum2-shadowsocks`需要实现executor-neutral poll state machine。
- 两个binary各有少量orphan-rule newtype delegation。
- single-scratch buffered admission比一次性codec helper具有更多显式state。
- 已认证initial payload按既有core contract占一个额外、严格有界的`Bytes` owner。

## Compatibility and upstream divergence

SIP022 revision、message types、KDF、nonce、wire bytes、timestamp/replay/binding、
detection class、reference pins与fixture bytes全部不变。sing-box与
shadowsocks-rust仍只作为独立compatibility oracle；不复制或vendor其代码。

本ADR只取代ADR-0004中caller-visible `HeaderIo`/manual `seal_*`、`open_*`、
`accept_client_response`、`write_first_response`与`into_parts` sequencing；
ADR-0004其余wire/security contract继续有效。ADR-0001 `Session`与ADR-0005
initial-payload/owner-task/backpressure/half-close contract继续有效。

## Migration and rollback

candidate未integrate，无persisted state或schema migration。repair保留既有replay
store、wire constants、fixtures与provenance，替换stream orchestration与allocation
ownership。回滚是从integration排除repair commit并保留已验证checkpoint
`5e3ddf9b1591f56b5f57983c121980af9b3aeb09`。

## Verification plan

- `tcp_duplex`：response pending时两方向进展、always-ready one-byte fairness、
  current/pending cipher ownership、`Session` target/payload与flow不重复payload。
- `tcp_fragmentation`：fixed 43/59仍single completed operation；其后每个region用
  one-byte与mixed fragmentation成功，mid-region EOF按table失败；zero-length
  subsequent payload认证后self-wake/Pending，非空destination不观察到伪EOF。
- `tcp_allocation_bounds`：每flow一个encrypt、每receive direction一个decrypt
  fixed request，storage identity在多帧与maximum frame间稳定；initial payload
  是独立bounded `Session` owner。
- `tcp_flow_contract`：0/1/16384/16385 writes、single-scratch admission、normal
  repeat polls（包括`Live { tx_closed, rx_open }`与已安装`Normal`的分离语义）、
  exact Protocol/Transport terminal matrix与source redaction；client
  response仍pending时的subsequent request-TX failure，以及server response仍pending
  时的subsequent request-RX failure，仍按Protocol/Transport分类且abortive为0。
- `detection_prevention`：pre-flow request与in-flow response Detection均terminal
  installed before exactly-one abortive；mark失败不恢复；其他类别零abortive。
- T07 focused client/server adapter tests证明delegation、initialized `ReadBuf`、
  fixed `io::Error` mapping、client configured-server dial/application-target wire
  separation及server direct-connect-before-initial-payload-forward；真实
  `local_e2e`/`half_close`通过未修改的`relay_lifecycle`。

## References

- `docs/adr/ADR-0001-m0-workspace-toolchain-and-module-topology.md`
- `docs/adr/ADR-0004-m0-sip022-tcp-security-state.md`
- `docs/adr/ADR-0005-m0-runtime-lifecycle-and-observability.md`
- `docs/specs/SPEC-0001-m0-aes128-tcp-vertical-slice.md`
- `docs/test-plans/TEST-0001-m0-aes128-tcp-vertical-slice.md`
