# Composition / protocols 最小实施设计

仅静态设计，基于 canonical composition.md 的 C1–C8、protocols.md 的 PROTO-1–5。已读取 root/client/server/observability/shadowsocks/crypto/net/sniff/socks5 AGENTS、codebase-design SKILL/DEEPENING；核对 SOCKS association/endpoint、client egress UDP association、TUN UDP association、server UDP commit、SS server、crypto outbound/seal、两端 network reset、sniff observation/routing、server listener/io/report 和 dns_egress 的实际调用。未修改产品、运行测试、编译、网络操作或动态复现。下文验证属于后续计划。

## 1. UDP 的 admission 与 source pin 是一个 caller 决策（C2）

保留 SOCKS codec 与 endpoint module 分离；codec 仅借用解析。`SocksUdpEndpoint::receive` 返回带私有 `SourceCandidate` 的有效 packet，candidate 含 source port，非 Clone/Copy；endpoint 的公开于 SOCKS 子树的 `accept(u16)` 删除。新增 `accept_admitted(candidate, observed_at)`，仅 association admission module 能调用；它同步、不可失败地 pin 并令 last_valid=max(last_valid, observed_at)。IP/预设端口检查仍在 receive，单关联串行读取保证 candidate 不跨另一次 receive；不必给每包发全局 ID。

```rust
// SOCKS 私有，Candidate payload 与 source 保持在一个值内。
struct CandidateRequest { source: SourceCandidate, target: TargetAddr, payload: BytesMut }
enum RequestDisposition { Admitted, Dropped, Terminated }
enum FirstRequestState { Awaiting, Active(EstablishedUdpRelay) }
```

最小迁移不造通用事务框架：把 `forward_udp_request -> bool` 分为同步 `prepare_owned_application_request` 的 admission/encode 结果与异步 send 结果，前者成功后立即 `endpoint.accept_admitted`，再开始 send；后者失败保留现有 terminal/drop 分类。首包 admission 的成功定义是目标/长度/route 可接受、容量/session/generation commit 成功且编码成功；不把 UDP send 成功与资源 admission 混淆。prepare 内若 encoding 失败已消耗协议 packet ID，不能倒退 nonce；首包失败关闭 provisional association，不能为了回滚 pin 回退 crypto lineage。

现有首包 `(target,payload,terminal)` 改为保留 candidate。第一包预算/队列等可恢复 rejection 必须 drop provisional egress 与未冻结候选 terminal，然后回到 Awaiting；下一合法 source 的 datagram 可重新选 route。不能继续当前 relay 并把旧 route 当作已由接受的首包冻结。已经 Active 的后续 rejection 保留既有 source/route，不刷新 endpoint activity。prepare/socket/activation 失败保留现有 terminal 语义；所有取消分支释放 candidate、pending session 和缓冲。

DNS hijack 首包也携带 candidate 到 DNS admission owner；最小可审计选择是成功得到合法答案且 response 已能编码之后、发送到应用之前 pin；失败/无答案/超限不 pin。send 需要 destination，因此不能等应用 send 后才第一次 pin。候选等待期间不刷 idle，控制 EOF、取消、generation 和 idle 仍统一选择。后续 DNS query 是否更新 activity 也使用同一接受点。

Seam 是 SOCKS admission module 的完整 first-request transition，而不是导出 pin internals 供测试跨过 interface。真实 endpoint socket 是现有本地 Adapter；纯 source/admission 逻辑直接测试，不新增测试专用公共 token。后续验证覆盖 fixed port/zero port、wire rejection、fixed-budget成功+request-budget不足、换源成功、编码失败、DNS无答案/成功、取消及 Active 下拒绝不刷新 idle。client ordinary binary 仍 compile-only；共享 pure logic 或现有 safe integration seam 验证行为。

## 2. Client Direct/Proxy 资源用 closed state 表达

当前 `ClientUdpAssociation` 的 upstream enum 外仍散落 plan/protocol/first_server/direct_wire/inner_wire/scratch 等 Option，实际 caller activate/encode/send 使用 expect。以以下私有所有权替换，外部保留 prepare、admit request、send、receive、cancellation 的少量 interface：

```rust
struct ClientUdpAssociation { lease: UdpAssociationLease, path: UdpPath }
enum UdpAccounting { Metered, TunUnmetered }
enum UdpPath { Direct(DirectAssociation), Proxy(ProxyAssociation) }
enum ProxyPhase { Prepared(ProxyPlanResources), Active(ProxyProtocolResources) }
enum DirectSocketState { Pending(ClientUdpSocketFactory), Bound(ClientDirectUdpSocket) }
enum DirectBufferState { Available(BytesMut), Received { payload: BytesMut, source: SocketAddr } }
enum SessionLease { Pending(PendingUdpSession), Active(UdpSessionHandle) }
```

`UdpAssociationLease` 拥有 manager、SessionLease、accounting、fixed reservations；Proxy 拥有 frozen plan、first_server、network generation、inner/upstream buffers、scratch、protocol legs/live ID 注册 owner。Direct 拥有 resolver、timeout、response policy/peers/hints、lazy socket、request target 与 buffer state。只保留真正生命周期可空的值，不把所有 Option 换成名字不同的 Option enum。activation 消费 Prepared resources 成为 Active；失误重复 activate 可保持幂等，但不能构建缺失 protocol 的 Active。

metering 从 `ClientRequestOrigin` 一次映射至 named accounting；只有 Tun 可产生 TunUnmetered。不得加公开 `with_unmetered(true)`。请求、响应、固定容量各沿现有 reservation owner；TUN 无 byte charge 仍有 payload/queue/session/generation 限制。Direct 首目标选定 socket/family/interface 的冻结策略保留，后续不兼容 family 明确拒绝，不随手开第二 socket。Proxy live ID 注销在 protocol owner Drop；公共 association Drop 只负责共同 lease，避免两层重复 remove。

该变更不换 sockets、缓存或队列，也不预先新增 boxing；Direct/Proxy enum 可能增加 max-variant 大小，应查看实际 type size 后再决定是否值得 box 冷资源，不能假设 box 自动降低成本。测试新 interface 的生命周期结果后删除旧针对 Option/expect 组合的结构测试。

## 3. 每个 TUN UDP datagram 先过 synthetic DNS（C3）

把 `run_udp_reject_association`、route association 和 synthetic-first 分支共同入口集中在现有 TUN UDP association module 内的一个 owned dispatch loop。冻结的 ordinary terminal 独立于 synthetic DNS：

```rust
enum OrdinaryPolicy {
    Unselected,
    Reject,
    Route { egress: ClientUdpAssociation, request_bound: usize },
    HijackDns,
}
struct TunUdpDispatch {
    association: UdpAssociation,
    ordinary: OrdinaryPolicy,
    dns: SyntheticDnsContext,
    generation: RouteGenerationGuard,
}
```

每次取得真实 target 后：检查 session/route generation → exact synthetic IP + port 53 → DNS answer path；只有非 synthetic 才读取/创建 ordinary policy。Reject 固定拒绝普通目标，不能阻止后续 exact synthetic 查询；synthetic 成功也不能把 Reject 改成 Route。Unselected 遇 synthetic 不选 ordinary；下一 ordinary 才做第一次 route。route/DNS send 的取消、ADF reservation、answer后授权、response queue/drop计数复用现有 owner，不重写 TUN parser/table。循环可以组合私有 dispatch 方法与 response select，不能复制成三个会漂移的 synthetic 检查。

删旧 reject-only reader 与多份 synthetic-first/route 分派。保留 protocol origin/MTU/queue checks。后续验证同源 ordinary Reject→synthetic、synthetic→Reject→synthetic、非 exact DNS address/port、两族、generation取消及没有答案不授权；与现有 Route 分支完整可观察结果比较。每包新增/统一一个现有 exact match，DNS context Arc 只在 association 建立时持有，不 per-packet clone。

## 4. SS 身份与时间由协议 module 负责（PROTO-1/2）

活动更新时间在持锁接受 commit 中统一 `max(previous, supplied_now)`；server、client current/old 和 batch staging 使用同一规则。duplicate 或 batch 任一失败不得改变 activity/replay/rotation。时钟输入保留注入，不增 timer，也不在 lock 外采样后直接赋值。旧关联 retention 仍以成功接受时间算完整 mandatory interval。

选择低成本 immutable instance identity，而非每包 Arc token 或密钥 equality。私有 `ServerOwnerId(NonZeroU64)` 由 SS crate 中单个 checked AtomicU64 sequence 分配；只在 `UdpServer::new` 一次 `fetch_update(Relaxed, checked_add)`，耗尽返回现有 Generation 类错误；从不 wrap、reset 或复用。不是地址 ID、随机碰撞概率 ID，也不暴露数值。进程内同一个 crate instance 构造的 server 之间唯一；能力不支持跨进程/序列化。

```rust
struct UdpServer { owner: ServerOwnerId, crypto: UdpCrypto, state: Mutex<ServerState> }
struct PendingUdpRequest { owner: ServerOwnerId, /* existing authenticated fields */ }
struct UdpRequestCommit { owner: ServerOwnerId, /* existing move-only fields */ }
struct ServerResponseCapability { owner: ServerOwnerId, generation: u64 }
```

当前 slot 与 generation 完全相等，不需保留两份；新 capability 用 owner+generation，仍 16 字节、Copy/Eq/Hash/redacted。token 增加 8 字节，无 per-packet allocation/refcount。`existing_capability`、`commit_request`、snapshot/remove/encode 的公共 capability 消费入口都在 lookup/mutation 前验证 owner；wrong owner 返回 Generation，不能先修改 replay/随机数/输出。owner 移动不变；重新构造即使同 key 必须新 owner，旧 capability 不能复活；server per-session generation checked exhaustion 仍 fail closed。

server `run/udp/commit.rs` 中 token 继续位于 runtime reservation commit closure，freeze identity 和 capability publish 继续在现有具体 commit owner。不把 key/token 绑定交给 caller。drop token不保留 server 或 key；能力仅是失效后仍可被拒绝的值，没有所有权引用环。现有 concurrent winner、frozen rejected/direct identity 跨 idle/reset 保留。

## 5. UDP crypto session 绑定创建它的 primitive owner（PROTO-3）

私有 `CryptoOwnerId` 使用 crypto crate 自己的 checked constructor sequence，`UdpCrypto` 和其创建的 `UdpOutboundSession` 各保存它。`seal` 在 profile/counter/output/random 操作之前验证 owner，相异返回新增 closed `UdpCryptoError::OwnerMismatch`（更新所有已知映射）。同一个 UdpCrypto 创建多个 session 合法；移动 crypto/session 合法；另一构造出的 UdpCrypto 即使同 method、同 PSK 也拒绝。明确选择 instance lineage，不声称会识别相等密钥；现有生产 wrapper 成对拥有不需复制或共享密钥。

选择 constructor ID 的成本是每 UdpCrypto 一次原子、8 字节/owner、8 字节/session、每 seal 一个整数比较；没有 PSK copy/compare、Arc 引用计数或 per-packet分配。nonce reserve成功后才 commit 的原规则不变。身份仅进程内私有，Debug仍 redacted；Zeroize清除 session现有敏感状态，并可清零ID存储但不重用全局计数。全局 allocator 是生产唯一性 mechanism，不是环境设置；测试不得重置进程全局值。耗尽测试在私有 allocator instance seam测试行为，不公开修改全局的 fixture constructor。

## 6. Closed telemetry 与协议映射（C1/C5/C7、PROTO-4）

C1选择把所有现有 public Outcome/Stage 纳入 grid，保留方法输入和原有 family/label意义，仅新增合法 Dropped/Tun series。删手工 OUTCOMES/STAGES 和 enum discriminant arithmetic。schema module 内一个小 macro declaration 一次给出每个维度的 variant/label，生成 enum、ALL、COUNT、index、as_str；metric family 尺寸和 labels 由该 owner 导出。只用于重复闭合 telemetry dimensions，不建立通用 schema generator。删除这些真正 closed enum 的 non_exhaustive 并更新全部 known-variant matches；io::ErrorKind 等上游 nonexhaustive 仍保留合理 else。

成本：额外 series 是固定低 cardinality，事先按实际 family cardinality列出新增数量和 histogram/counter内存；不悄悄接受无限 label。index仍 O(1)，无每次线性 search或heap。后续测试独立列出预期合法 label tuple 并验证每个只增长自己的 series，不能复刻遗漏列表后宣称完整；涵盖全部 public enum exhaustive match，渲染 determinism和 sentinel redaction。

C5在各 binary 的 observation module 使用同一形状、各自明确转换其依赖，不让零 Ferrum依赖 observability 引入 runtime/sniff：

```rust
enum SniffAttempt {
    Parsed { transport: Transport, progress: SniffProgress },
    TcpCollectionEnded(SniffPrefixOutcome),
}
fn record_sniff(metrics: &Metrics, attempt: SniffAttempt);
```

collector Complete 必须变 Parsed，Timeout→Timeout、Limit→Limit、Unavailable/ReadError/Cancelled→Unavailable（保留已有闭合 vocabulary），解析 Matched/Invalid/NoMatch/NeedMore按现有正确server mapping。UDP没有TCP collector值，避免 bool limited/Option contradictory组合。client TCP cancellation/error 分支也调用此唯一 emitter，一 attempt恰一 metrics.sniff，它已产生同tuple trace，不额外emit。两个 binary的少量 dependency mapping 不值得新跨层 crate；共享的是真正 telemetry tuple，不迁 parser metadata进observability。

C7选择兑现现有文档：在 client/server completed interface resolution observation method 内一次调用 typed metric和已有 diagnostic emitter，覆盖成功及失败、DNS/TCP/UDP/materialization caller。诊断使用 Debug/Trace level，默认Info不逐socket日志；不额外引入有状态采样/去重表。轻量 reset 在 transition完成处同样统一 emit一次；若现有 emitter固定Info，修改为适配该级别并同步文档。失败不记录 raw errors、名称、地址。明确 debug volume随socket尝试数增长，性能测量默认logging与debug分开。

PROTO-4在 SS wire 私有 interface 用 `PacketDirection::Request | Response { binding: &UdpSessionId }` 同时决定 message type、binding和长度，不再接受 response bool/u8+Option组合；response长度预算可用同样 closed direction类型的无identity视图，不能因长度计算复制session ID。crypto header operation改两个 named encrypt/decrypt方法共用内部primitive实现。net输入改 `InterfaceOperationalState`、`InterfaceLinkState`、`AutomaticInterfaceSelection`，仅映射实际boolean决策，不机械包装所有 getter。FrameError、DetectionReason和新增crypto error逐一exhaustive match，保留当前闭合分类并专门列出 OwnerMismatch→StateUnavailable/Generation的协议映射选择（此候选选择 Generation）。

## 7. Snapshot owner 与 server 报告（C4/C6/C8）

C4两端network root都要持有 snapshot工作直至完成。选择 runtime内一个小 `OwnedBlockingOperation<T>` module（仅在统一runtime设计已选同类机制时复用），interface为 start(owned closure)、wait(&mut self)、finish(self)；private Arc<Mutex<Running|Completed(result)>>+Condvar保留完成状态。worker在 unwind时也发布 Failed并notify；Drop同步等 Completed，多线程runtime用block_in_place，不能单纯drop JoinHandle。外部取消只停止等待使用结果，root清理仍finish；不持catalog锁等待，不向net crate引入Tokio。若总设计不接受共享owner，就把完整snapshot ownership放在各root的private module，不复制一个只有await的薄wrapper。

取消前已开始的OS capture可能不可中断：关闭monitor、回收snapshot后才能报告root完成，不承诺硬deadline；grace/forced不等于可以detach。最多一个snapshot in flight，无后台池、额外steady worker或polling。future取消/Drop必须保留waitable result，不以“spawn_blocking不能abort”解释已回收。测试用现有safe catalog Adapter和真实进程内线程，不进行真实网络变更；后续验证取消/完成竞争、panic、snapshot failure和root完成顺序。

C6在server的io acquisition返回 `EndpointAcquireError { stage: SocketCreate|Configure|Bind|Listen, kind: ClosedIoKind }`，丢弃原io error但保留kind。required root closures捕获 `RootDescriptor { role: UdpInbound|TcpInbound|Metrics|Network|Dns|Rules, declaration_index }`，与ProcessRootId登记在只读root列表。ProcessReport映射时生成owned closed `ServerRunFailure { primary: RootFailure, cleanup: CleanupOutcome }`；root id查descriptor，phase来自ProcessCause，stage来自error。UDP无Listen阶段；不拿endpoint值、tag或端口当identity。

终端exit code保持原分类；cleanup失败优先，但stderr同一结构保留原primary和cleanup，不在report_result先抹掉cause。诊断只输出closed fields和声明index；runner evidence parser同步迁移，删除旧扁平StartupBind-only schema，保留内部兼容返回值没有价值。此次不据过往bind失败推断哪一endpoint，不改host配置。

C8 server AcceptListener Adapter把 `poll_accept` 的 Err转换为 `io::Error::from(error.kind())`，保留Transient集合 Interrupted/WouldBlock/ConnectionAborted/ConnectionReset而不带原OS message；set_nodelay失败保持独立既有policy不混淆accept。runtime `is_transient_accept_error` 继续唯一拥有retry决策，不在server复制第二份。后续通过已有safe listener seam验证transient后下一accepted连接、terminal root failure和redaction。

## 8. 删除 server 旧 DNS runtime 与 fixture exports（PROTO-5）

实际server Direct只调用 `ServerDnsResolver::for_direct[_observed]`，选 exact tagged或system。保留这条interface与 tagged resolver/transport owner的closed安装清理状态；将 `ServerDnsState` 缩为当前 tagged resolver installation owner，或在已有 materialization handoff中直接持有它。删除 ServerProxyPolicy/ServerProxyRuntime、InstalledServerDns.proxy、configured application backend、proxy accessor、new_observed/new_inner、仅为该路径保留的observer/cache state与dead_code allowance。

DNS policy合法性仍在offline/明确materialization阶段验证：提取 `validate_server_dns_policy(blueprint, registry_snapshot) -> Result<(), ...>`，编译验证完成即可释放不用的program；不能靠构造未使用DnsProxy才间接验证，也不能把必须失败的config默默接受。此路径未真正使用的runtime cache不分配；保留仍被tagged transport或其他真实caller需要的cache。删除旧proxy行为测试，改测server实际Direct exact tagged/system选择、失败无fallback、owner shutdown和invalid policy/materialization退出码2。DNS policy元数据文档清楚区分验证的声明与真实运行匹配，不能把unused path计数当已执行。client DNS不随这次清理删除。

PROTO-5移除泛称TCP_SALT_LEN和43/59固定首读长度exports，integration caller从MethodProfile推导尺寸；reviewed wire vectors/provenance不改写。纯 fixture encoder/open_data_frame、TcpSubkey::from_bytes、独立NonceCounter测试入口迁回crate-owned单元测试；有实际跨crate qualification依赖才开显式test-support feature且默认关闭，不无条件新建。测试从生产public interface验证nonce/封包行为；删除obsolete alias。遍查in-repo uses后一次迁移，不能保留兼容constant。

## 9. 集成顺序与后续不回退证据

先落实protocol identity/time与closed error variants，随后UDP closed state/admission、TUN dispatch，再telemetry/snapshot/root report，最后删除obsolete DNS和fixture surface。每项一组可review的行为改动及其直接caller，不机械拆大文件或先加pass-through facade。预估改动不改变wire、key derivation、队列上限、route freeze或zero-copy decoder；但source rejection loop、额外series、owner ID比较以及DNS启动分配移除都必须实测，静态cost不是性能证明。

实施阶段验证时：affected crate tests和client compile-only，相关m0-harness，fmt/clippy/check及适用workspace gates。协议case包括反序时间/current+old+batch回滚、59.999/60秒、wrong owner/key/same-key新instance、move、remove/recreate、duplicate concurrent winner、输出/counter失败不变、所有profile vector。替换旧结构测试，不叠加镜像 implementation测试。普通验证不建真实TUN、不变route/DNS/WFP。

correctness通过后使用相同baseline/candidate release工具链、硬件、负载和既有qualification统计规则，比较 SOCKS/TUN UDP throughput/尾延迟/拒绝预算成本、SS existing-session和churn、startup内存/耗时、默认logging CPU及debug开销；保留样本分布/噪声，未测不能写无回退。SS outbound-ID索引、批量replay栈上staging、sniff增量parser、DNS桥减层都是之后CPU profiling假设，不混入这批正确性与owner identity修复。先用Qualification完成无采样的性能不回退验收，之后才获取CPU样本并选择优化。
