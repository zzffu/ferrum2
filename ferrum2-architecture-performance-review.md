# Ferrum2 全 workspace 架构与性能审查

审查对象：`current.tar(20260907-203603).gz`。归档 SHA-256：`a91eeec09e5d2bde0a8c628c4da5ac8fbf6bea96a29c0f03009ca8f60c1196e9`。

## 当前工作区复核与实施（2026-09-08）

以下是对当前源码的复核和本轮落地结果；后面的归档审查正文保留其原始证据范围。
成本路径基本属实，但“存在额外成本”不等于“已证明业务吞吐下降”。本轮没有合并
crate、替换密码实现或运行会修改宿主机网络的资格测试。

| ID | 复核与处置 |
|---|---|
| PERF-01 | 确认并实施。监听器只负责快速分派；新会话 DNS/socket 工作由根持有的有界 future 集合执行。按已认证身份合并准备工作，保留有界逐包 FIFO；提交前重新检查冻结路由和 generation。 |
| PERF-02 | 确认并实施。每个共享字节域至多缓存一个 65,507 字节 Direct 接收 buffer；缓存仍计费，预算压力可回收。`Bytes` 切片和独立 reservation 都能保留物理 owner，reset 防止旧 lease 重新进入缓存。成功回包仍有小型 owner 元数据分配，不是零分配。 |
| PERF-03 | 确认并实施。单跳固定容量从 196,521 降到 131,014 字节，无 inner buffer 和提交 Vec；2–8 跳保留三块 buffer 和原子批提交。未改多跳 replay 状态结构。 |
| ARCH-01 | 确认分域设计并增加独立 TUN 字节预算。`tun.udp_buffered_bytes_limit` 默认 64 MiB，范围 1 MiB–1 GiB；固定 egress、候选/队列 payload、物化与延迟响应共享该域。删除普通 runtime 的 unmetered 准入接口；保留普通 UDP 与 TUN 隔离。没有把它描述为整个进程 RSS 上限。 |
| PERF-04 | 确认并实施。稳定 slot、O(1) FIFO 链和可更新 expiry heap 取代线性顺序删除及全 map retain。每个保留 entry 只有一个 deadline。插入最多额外清理一个到期 entry；精确 `entry_count` 仍需处理所有到期项。 |
| PERF-05 | 确认并实施。出站 session ID 用反向 HashSet 查重，与会话插入/删除保持同锁原子维护。网络 reset 原本保留协议重放状态，因此不能清掉仍有效的 ID 集合。 |
| PERF-06 | 确认并实施最终完整解析结果复用。保留 DNS/TLS/HTTP 顺序、严格字节界限与额外收集 horizon 的差异。没有改成简化 SNI parser；每连接增量 TLS 状态仍未引入。 |
| PERF-07 | 成本属实，本轮不改提交协议。每项 refresh 先构造完整 successor，再原子替换自己的磁盘 cache；简单批量发布会破坏这条失败原子性。match set 已共享；全局候选索引拆成每资源索引会改变读侧成本，尚无支持该取舍的测量。 |
| PERF-08 | 删除编译后不变的空 mask 扫描，预先记录 active fields；新增 63/64/65、稀疏/密集、多次 Continue 测量。保留每次 metadata 变化后重新评估；未凭静态推测引入自适应 bitmap 或 continuation 缓存。 |
| ARCH-02 | 提取 `ferrum2-runtime::RetainedMonitorOwner`，两个 binary 保留 Windows adapter 和角色错误映射。取消 waiter 不丢失实际 blocking join。没有为了消除相似文本而移动 observation/endpoint/RuleSet 编排或增加 common crate。 |
| PERF-09 | 线程实验确认低连接上限仍创建全部 shard。默认数量现为 `min(available_parallelism, max_connections)`；主 Tokio worker 数与全进程配置接口不改，吞吐/公平性仍需负载测量。 |
| PERF-10 | 锁确实存在。两轮合成 ready-poll 实验仅见约 1.5 ns/poll 增量；没有真实 relay profile 支持更改握手/ready ownership，因此保持现有 exactly-once 和 control lifetime 契约。 |

### 已取得的容量与测量证据

- 单跳每关联少预留 **65,507 字节**；1,024 个关联对应 **63.9717 MiB** 的容量差，
  不是 RSS 或吞吐结果。默认 TUN 64 MiB 在完全忽略 payload 时最多容纳 512 组单跳
  固定 buffer 或 341 组多跳固定 buffer；实际可准入数会更低，mapping 上限不是保证值。
- `OwnerSnapshot`、客户端 shutdown JSON 和
  `ferrum2_tun_udp_buffered_bytes{role="client"}` 暴露独立域。普通
  `udp.max_buffered_bytes` 加 TUN 上限构成被计量 UDP 容量包络；TCP、内核 socket、
  Wintun ring、重组及 allocator 元数据不包含在这个包络内。
- PERF-01 在准备阶段保守地同时保留首包字节 lease 与 provisional 队列 reservation，
  因而需要瞬时准入余量；这是预算上界，不是两份物理 payload。后续同身份报文各自
  计费，队列满才丢新报文，不把“合并工作”实现为丢弃所有后续首批数据。
- 线程 probe 通过真实 `AffineConnectionExecutor` 和 Windows 进程线程计数观察：
  16 个可用逻辑核，连接上限 1/4/16，修改前均增加 16 个线程，修改后增加 **1/4/16**
  个线程；每轮结束从活动线程数回到原来的 4 个线程，活跃 owner 全为零。
  这是空闲执行器资源实验，不是 TCP 负载吞吐比较。
- SOCKS release probe 使用真实公开握手和消耗后的 reply，底层为无系统调用的受控
  ready IO。两轮 raw p50 为 2.976/2.977 ns，SOCKS 为 4.533/4.523 ns。
  每轮交错采集 31 个计时 batch；这些不是请求级 p99，也不包含网络、拷贝或调度成本。
- 优化后的 rule qualification runner 执行 **423 个场景**，其中新增 bitmap 场景
  **84 个**均为零 query allocation/reallocation；correctness、allocation 和本地
  parity/threshold gate 通过。命令为：

  ```text
  target/release/ferrum2-rule-qualification.exe --profile qualification --samples 5 --iterations-per-sample 256 --workspace-root . --output target/review-rule-qualification.json
  ```

  runner SHA-256：
  `13798c9b88e29fd6b1eef94a2582630288ac05161f3affc1e4e91153bfb58d05`。
  10,000 规则 late-match 的单次观察 p50：sparse 367 ns、dense 6,895 ns、
  sparse + Continue 1,899 ns、dense + Continue 53,967 ns。候选访问数说明密集负载仍有
  明显工作量。这是仅 5 个样本的当前版本测量，不是 parent/candidate A/B，
  不据此声称优化百分比，也不替代正式 A/A 校准和尾延迟资格。

### 验证边界

已执行真实 release binaries 的无特权 loopback native contract，结果
`m3_local_native_contract status=PASS`；它覆盖 TCP/UDP 分流往返、启动回滚、信号退出和
端口回收。文档 TUN 配置的 `--check-config` 通过，仅做离线验证。
普通客户端测试 binary 保持只编译；TUN/Windows 使用无默认特性的纯内存/injected 测试。
本轮没有执行管理员 Wintun/WFP 操作、ETW、真实 TUN 性能测试或 Linux sanitizer fuzz。

新增回归重点为：慢 resolver 下既有会话分派、同身份 FIFO/duplicate、截止时间与 reset、
保留 Bytes 的计费、false readiness、大 UDP 报文、独立预算回收、FIFO/TTL churn、ID 碰撞、
嗅探边界及 retained worker join。删除了两个只扫描源码/文档字样的 compatibility 测试；
旧配置拒绝仍由真实解析和 CLI 负例验证，不以“文档不能提到旧字段”代替行为合同。

最终门禁结果（没有把编译-only 项记成已执行测试）：

| 门禁 | 结果 |
|---|---|
| `cargo build --workspace --bins --locked` | 通过 |
| 普通 workspace 测试，排除 client、TUN、Windows 平台和 rule qualification 四包 | 787 passed，5 ignored |
| TUN `--lib --no-default-features --features fuzzing` | 139 passed |
| Windows 平台 `--lib --no-default-features --features fuzzing` | 75 passed |
| client `--all-features --no-run`；rule qualification `--no-run` | 均通过，仅编译 |
| DNS `--features __interop-test-root` | 91 passed |
| TUN/Windows `--all-features` check | 通过 |
| TUN `--features fuzzing --target x86_64-unknown-linux-gnu` check | 通过；有 packet/TCP 未使用代码警告，不是 GNU 严格 lint 通过声明 |
| 全 workspace `clippy --all-targets --all-features -- -D warnings` | 通过 |
| `cargo fmt --all -- --check`；`cargo doc --workspace --all-features --no-deps --locked` | 均通过 |
| Python performance_candidate / performance_rule / CI / platform controller | 144 / 66 / 80 / 9 tests 成功；CI 项有 12 个平台相关 skipped |
| Windows 非变更 qualification script contract | PASS |
| 目标专用 release binaries 的 `qualify_native.py --local-contract` | PASS |
| `m4-qualification self-check` | PASS，mutations=56 |

普通 workspace 命令：

```text
cargo test --workspace --exclude ferrum2-client --exclude ferrum2-tun --exclude ferrum2-platform-windows --exclude ferrum2-rule-qualification --locked
```

黑盒预算回归改为持续真实准入直到出现拒绝，并验证随后换源、冻结路由及清理；
不再绑定旧的每关联固定 buffer 字节常量。服务器回收检查使用启动时实际观测的
root baseline，仍要求 session 归零、容量回到 baseline、端口可重新绑定。
临时 thread/poll probe 源码和未启动的 listener 配置已删除；原始规则测量保存在
忽略的 `target/review-rule-qualification.json`，不作为可移植性能提升承诺。

## 原归档审查：范围与证据强度

扫描了根 workspace 全部 **19 个成员**的 manifest、内部依赖和源码结构/成本模式，共 **651 个 Rust 文件、201,067 行物理文本**（含测试、注释和空行，不等于生产代码行数）。重点跟踪了 UDP 准入与回包、DNS 缓存、规则评估与刷新、TCP relay/sniff、TUN、Windows owner 以及两个 binary 的 materialization/lifecycle。静态 manifest 普通/构建依赖图无环；不是 cargo 完整 feature-resolved 图。额外查看独立 TUN fuzz crate 和 vendored crypto 补丁边界，它们不计入这 19 个根成员。

原审查环境没有 rustc/cargo，**未编译、未执行 Rust 测试、未跑实际基准/Windows ETW，也没有修改产品源码**。以下原审查正文的全部性能数字只在明确标为公式推算时给出；不承诺吞吐提升百分比。全量结构扫描不等于逐行正式审计；对第三方加密实现没有作密码学正确性证明。

## 总体结论

现有 crate 分层值得保留，最优先的不是合并 crate、重写 runtime 或更换密码库。第一批建议是：单跳 UDP 按需配置资源、Direct UDP 回包 buffer 复用、服务端新会话慢路径隔离。第二批是 DNS/会话索引维护、TUN 独立字节包络、重复 owner 消重及嗅探结果复用。规则索引/线程预算/SOCKS 锁需要针对实际负载验证。

P1 表示优先实施验证，不表示已证实漏洞；P2 是第二批，P3 是 profile 后再决定。代码路径与成本存在性已确认，但对业务性能的实际影响未测量。

## 保留的架构性质

保持 core/net 中立契约、protocol 与 host composition 分离、runtime 实际工作所有权、Windows FFI 的局部隔离；保持认证准备→预算准入→状态提交，及 generation fence/retire/join 顺序。当前已有 DNS 最早到期下界、规则索引/scratch、协议 in-place/scratch、响应 codec 池、TUN/reassembly deadline 管理等优化，不能重复当成“完全没有”。各项结论以当前源码为准，不把历史 smoltcp profile 当当前系统 TCP 的测试结果。

## 优先级概览

| ID | 优先级 | 建议 |
|---|---|---|
| PERF-01 | P1 | 服务端 UDP 新会话慢路径阻塞同一监听器接收 |
| PERF-02 | P1 | Direct UDP 回包每次申请最大报文容量 |
| PERF-03 | P1 | 单跳 Proxy UDP 可省一个完整 buffer 与临时提交 Vec |
| ARCH-01 | P2 | 资源上限是分域的，缺少直观的整体内存包络 |
| PERF-04 | P2 | DNS cache 的全局锁内仍有线性删除与批量清理 |
| PERF-05 | P2 | SS UDP 新会话 ID 查重在全局锁内扫描所有会话 |
| PERF-06 | P2 | TCP 嗅探重复解析累计前缀，完成后还会再解析 |
| PERF-07 | P2（大规则集） | 规则热更新可批量构建或共享索引 |
| PERF-08 | P2/P3（先测） | 规则匹配候选 bitmap 仍有全宽操作 |
| ARCH-02 | P2 | binary composition 中重复 owner 和 materialization 流程 |
| PERF-09 | P3（先测） | Affine shards 与 Tokio 主 runtime 缺乏统一线程预算 |
| PERF-10 | P3（先测） | SOCKS5 CONNECT 握手后仍保留共享 IO mutex |


## 逐项发现

### PERF-01 · 服务端 UDP 新会话慢路径阻塞同一监听器接收

**优先级：P1；静态源码确认；收益未实测。**

**源码事实。** 同一个 packets 循环执行 recv、prepare、会话选择、DNS 候选解析和 provisional socket 打开。新 Direct 会话在 resolve_udp_selection_candidates 和 reserve_session_with_initial_candidates 上等待；等待期间该监听循环不会继续收下一包。admission_guard 已在等待前释放，不是持锁跨 DNS 的问题。

**影响范围。** 冷 DNS、慢接口选择或建 socket 会干扰同监听器已有会话的上行尾延迟；其他监听器和已经独立运行的响应任务不等同于全部阻塞。

**建议改法。** 把“已建立会话投递”和“新会话准备”分开。后者进入有并发数、总字节数和截止时间限制的工作集合；对同一已认证身份做 in-flight 合并。完成后回到受控提交点重查 frozen route 与 generation。

**风险与不变量。** 中高：不能每包无界 spawn；不能为了并发提前提交 replay/peer/activity；不能在失败时遗留 provisional socket/队列；shutdown 必须拥有并 join 实际工作。

**验证方式。** 注入可控慢 resolver：A 已有 IP 会话持续传输，B 新域名会话等待。检验 B 等待时 A 仍可被分派，同时覆盖同身份并发首包、取消、reset、队列满。端到端记录 p50/p99、丢包、owner 数。

**定位。** `bins/ferrum2-server/src/run/udp/run_loop.rs:140–181`；`bins/ferrum2-server/src/run/udp/run_loop.rs:248–305`；`bins/ferrum2-server/src/run/udp/run_loop.rs:310–385`。

### PERF-02 · Direct UDP 回包每次申请最大报文容量

**优先级：P1；静态源码确认；收益未实测。**

**源码事实。** receive_target 每次等待 readable 后，预留 MAX_UDP_WIRE_DATAGRAM_BYTES 并新建 BytesMut::with_capacity。常量为 65,507 字节。成功时 buffer 转移给 Datagram；WouldBlock 时本次 allocation/reservation 被丢弃。上层同步等待响应 handler 完成后才接下一响应。

**影响范围。** 小报文高 PPS 下会产生与包数对应的大容量分配请求；这不是测得的 RSS 或实际内存写带宽，也不是 buffer 泄漏。

**建议改法。** 使用有上限、可回收的 buffer lease/pool；或在确认下游不保留 Datagram 的接口上显式归还 buffer。把物理 buffer 和预算所有权一起复用。已有 response_codec 的池化模式可作为参考，但其存在不代表本接收路径已复用。

**风险与不变量。** 中：不能仅把 65,507 改为 MTU 而截断合法大报文；不能提前释放仍被 Bytes/Datagram 持有的预算；避免为每个空闲会话永久缓存完整 buffer 从而放大驻留容量。

**验证方式。** 同包长/并发/速率下记录 allocations/datagram、requested bytes/datagram、PPS、p99 和所有 buffer 生命周期。覆盖 false readiness、接收取消、handler 错误、预算耗尽、大报文。

**定位。** `crates/ferrum2-runtime/src/udp/direct.rs:596–654`；`crates/ferrum2-runtime/src/udp/limits.rs:1–22`；`bins/ferrum2-server/src/run/udp/response_codec.rs:1–75`。

### PERF-03 · 单跳 Proxy UDP 可省一个完整 buffer 与临时提交 Vec

**优先级：P1；静态源码确认；收益未实测。**

**源码事实。** prepare 对所有 Proxy 分配 inner_wire、upstream_wire、scratch.body，均为 65,507 字节。encode_request 单跳只走 upstream_wire；accept_response 在访问多跳 inner_wire 前返回。然而 commits 的 Vec::with_capacity 在单跳判断之前创建；final commit 又 push/pop 一次。多跳批提交还创建若干短 Vec。

**影响范围。** 单跳每会话可省 65,507 B（约 63.972 KiB）的预留容量；1,024 个单跳代理关联对应约 63.972 MiB，不包含分配器元数据。可以删除单跳提交 Vec 的分配点，但不能宣称整个 UDP 回包零分配。

**建议改法。** 按 frozen plan 的 hop 数准备资源：单跳不创建 inner_wire，且普通 UDP 的 fixed_buffer_count 同步由 3 调为 2；单跳直接提交 token，不经过 Vec。多跳最多 8 跳，可先对轻量描述符/令牌采用定长容器或复用 scratch，减少链式 collect/unzip；较大的 replay 状态副本不要盲目全部搬到栈上。

**风险与不变量。** 单跳改动低至中；多跳中。必须保留借用认证、预算准入后 materialize、重放提交失败原子性，以及跨 session 的确定性锁顺序。不要用未经检查的数组容量或放宽 hop 限制。

**验证方式。** 1/2/4/8 跳分别测固定 buffer 容量与每包分配；断言单跳无 inner buffer、无 commit-vector allocation point；验证多跳任一层失败不会局部推进 replay/association。

**定位。** `bins/ferrum2-client/src/run/egress/udp/prepare.rs:53–97`；`bins/ferrum2-client/src/run/egress/udp/proxy.rs:110–164`；`bins/ferrum2-client/src/run/egress/udp/proxy.rs:197–214`；`bins/ferrum2-client/src/run/egress/udp/response.rs:61–95`；`crates/ferrum2-shadowsocks/src/udp/mod.rs:25–51`；`crates/ferrum2-shadowsocks/src/udp/client.rs:216–253`。

### ARCH-01 · 资源上限是分域的，缺少直观的整体内存包络

**优先级：P2；静态源码确认；收益未实测。**

**源码事实。** TUN 的 TunUnmetered 是明确设计：不占普通 udp.max_buffered_bytes，并非遗漏的预算检查。关联数、队列深度、payload、session 和 generation 仍有限制。当前 Proxy 固定三块 buffer 容量共 196,521 B；默认允许 1,024 个 TUN UDP mappings。TCP relay 每方向 32,768 B，普通连接默认上限 4,096。

**影响范围。** 假设 1,024 个 TUN mappings 全部已准备为 Proxy，三块固定 buffer 合计约 191.915 MiB；假设 4,096 个连接同时处于双向 relay，仅双向 relay buffer 合计 256 MiB。两者都是容量推算，不是实际峰值 RSS，也不能据此断言默认应用一定同时达到这些状态。

**建议改法。** 新增独立 TUN byte budget/有界 arena，保持与普通 SOCKS/DNS/RuleSet UDP 的隔离；在配置准备阶段计算资源包络，暴露分域 owned/reserved bytes 和单独采样的进程 RSS。优先按 hop 数与实际路径惰性配置 buffer。

**风险与不变量。** 中高：不能无说明把 TUN 塞回共享普通 UDP 预算，破坏明确产品语义；池中缓存容量也必须计入所属域；字节准入必须先于 allocation/materialization。

**验证方式。** 以 Direct/Proxy、1/2/8 hops、空闲/活跃、mapping/flow count、满队列为轴验证理论容量和观测值；关闭/reset 后 pool 与 owner 收敛；测试普通 UDP 预算耗尽不意外影响 TUN 的现有隔离契约。

**定位。** `bins/ferrum2-client/src/run/egress/udp/lease.rs:1–25`；`docs/config-v2-tun.md:89–97`；`crates/ferrum2-config/src/lib.rs:6–24`；`crates/ferrum2-runtime/src/relay.rs:14–38`。

### PERF-04 · DNS cache 的全局锁内仍有线性删除与批量清理

**优先级：P2；静态源码确认；收益未实测。**

**源码事实。** DnsCacheState 使用 HashMap 和保存完整 key 的 VecDeque。remove 先删 map，然后在线性队列 position 查找并 remove；insert 和 entry_count 可在锁内 purge_expired，后者 retain 全 map 和整个顺序队列。expiry_lower_bound 已避免每次访问全表扫描，成功 answer 的地址数组是 Arc，不是每次复制完整 IP 向量。

**影响范围。** 大缓存、频繁更新同 key、TTL 成批到期时，锁持有时间可能出现尖峰；无充分依据说小缓存普通 hit 已经成为瓶颈。

**建议改法。** 用稳定 entry ID/slab + O(1) 顺序链维护 FIFO；deadline 使用有界可更新 heap 或 timer wheel，增量清理并限制单次工作。出现实测跨线程争用后再考虑 sharding。另可评估 borrowed cache key，减少 canonical domain 在 hit 路径的复制。

**风险与不变量。** 中：必须保持 FIFO 而非擅自改 LRU、TTL=0 删除、server/A/AAAA/generation 隔离。使用惰性过期 heap 时必须限制 stale entries 的积累。std HashMap retain 当前实现为 O(capacity)，不是只与 live len 有关。

**验证方式。** 不同容量下测试稳态 hits、随机到期、同批 TTL 到期、同 key 更新、多线程混合访问；报告锁持有时间与 p99/p999，不能只测无竞争 hit 吞吐。

**定位。** `crates/ferrum2-dns/src/cache.rs:134–144`；`crates/ferrum2-dns/src/cache.rs:215–255`；`crates/ferrum2-dns/src/cache.rs:333–363`；`crates/ferrum2-dns/src/cache.rs:390–421`。

### PERF-05 · SS UDP 新会话 ID 查重在全局锁内扫描所有会话

**优先级：P2；静态源码确认；收益未实测。**

**源码事实。** 新 session 的 generate_distinct_outbound_session 闭包同时查 sessions.contains_key 与 sessions.values().any(outbound_session_id)。正常已存在会话先走 get 分支，不会每个数据包扫描。

**影响范围。** 大量存量 session 叠加新会话 churn 时，新会话准入成本随表容量/规模增长，并占用共享 mutex。

**建议改法。** 增加 outbound_session_ids 反向 HashSet/index，使两个命名空间的查重都走直接查询；和 session/capability 的插入、淘汰、reset 一起原子维护。

**风险与不变量。** 中：随机 ID 生成、入站与出站 ID 不冲突、旧 generation capability 失效规则不得削弱；不能靠删除查重提升速度。

**验证方式。** 分别固定存量 session 数与新建率，测 admission 延迟/锁时间；用受控随机源产生重复 candidate，验证删除/reset 后反向集合准确。

**定位。** `crates/ferrum2-shadowsocks/src/udp/server.rs:235–291`。

### PERF-06 · TCP 嗅探重复解析累计前缀，完成后还会再解析

**优先级：P2；静态源码确认；收益未实测。**

**源码事实。** client 的 collect_sniff_prefix 回调对累计 bytes 调 sniff；完成后再次 sniff 同一个 collected prefix。TLS sniff 每次新建 rustls Acceptor 并从 Cursor(bytes) 开始。server 同样存在 collect/parse 路径。

**影响范围。** 分片 ClientHello/HTTP header、较高连接建立率下，累计前缀重复解析和临时状态重建可能放大成本；不是长期已建立 TCP relay 的每包成本。输入已受 bytes/timeout/aggregate 限制，不能把它描述为无界解析。

**建议改法。** 先让 collector 保存最终完整解析结果，消除完成后的重复解析；进一步针对 TLS 保留每连接 acceptor/增量状态。保持 DNS/TLS/HTTP 顺序、max_bytes 与 horizon=max_bytes+1 的边界差异一致。

**风险与不变量。** 中：不能为提速用不验证长度/结构的简化 SNI parser；不能把需要继续收集的 partial 结果缓存为最终结果；保留超时及原字节透明转发。

**验证方式。** ClientHello/HTTP 分成 1/2/4/16 段以及小碎片，记录 parser 调用次数、processed prefix bytes、分配、建连 p99；测试 max_bytes 边界和 timeout/cancel。

**定位。** `bins/ferrum2-client/src/run/routing.rs:202–259`；`crates/ferrum2-sniff/src/lib.rs:171–196`；`bins/ferrum2-server/src/run/tcp/selection.rs:89–149`。

### PERF-07 · 规则热更新可批量构建或共享索引

**优先级：P2（大规则集）；静态源码确认；收益未实测。**

**源码事实。** RuleSet 刷新一个资源时 builder_for_generation 共享旧 match_sets，replace 后调用 builder.build；build 仍遍历所有 descriptors 构建候选索引。due 资源依次 refresh，多个到期变化可造成多次完整 index build。不是未变 match_set 深拷贝。

**影响范围。** 大量/大型规则集且频繁更新时会增加控制面 CPU、分配与峰值内存；小规则集低频刷新收益可能有限。

**建议改法。** 优先同一轮已准备且确实变化的更新合并一次 successor build/publish；长期考虑每资源不可变候选索引的结构共享。保留单次 evaluation 固定 snapshot。

**风险与不变量。** 中高：磁盘 cache commit、校验、快照发布、失败保持旧状态之间的顺序不能破坏；不要无界并行编译所有资源使峰值内存更高。

**验证方式。** 固定总规则数，分别更新 1 个与多个资源，测 build 次数、build duration、allocations、峰值活跃字节、读侧延迟；故障注入校验/磁盘 commit/取消/发布失败。

**定位。** `crates/ferrum2-ruleset/src/cache_work/session.rs:144–184`；`crates/ferrum2-rule/src/registry.rs:135–164`；`crates/ferrum2-rule/src/registry.rs:358–411`；`crates/ferrum2-ruleset/src/refresh.rs:113–139`。

### PERF-08 · 规则匹配候选 bitmap 仍有全宽操作

**优先级：P2/P3（先测）；静态源码确认；收益未实测。**

**源码事实。** 大程序路径每次 find_next 都 fill_candidates，遍历 FieldKind::ALL，扫描 mask 是否为空，清 matched，再全宽 zip candidates/mask/matched 和判空。小程序 <=64 已有线性专用模式，规则匹配也已有索引与复用 scratch。

**影响范围。** 超大稀疏规则程序、多个 Continue/metadata 更新时，全宽扫描可能抵消部分索引收益；不能称当前系统是全量逐条匹配。

**建议改法。** 编译时记录 active field kinds，考虑 dirty-word reset 与稀疏 postings/密集 bitmap 自适应。只有证明语义安全后才复用 continuation 候选，元数据更新必须正确失效。

**风险与不变量。** 中：规则顺序、Continue、Sniff 后的 metadata 和 snapshot generation 都是正确性契约；不能简单缓存第一次候选集合。

**验证方式。** 规则数量覆盖 64 附近以及大程序；early/late/no match、稀疏/密集、多个 Continue 分开测 cycles/lookup、候选数和分配，避免仅比较纳秒均值。

**定位。** `crates/ferrum2-rule/src/program/index.rs:32–89`；`crates/ferrum2-rule/src/compiled_program.rs:1–30`。

### ARCH-02 · binary composition 中重复 owner 和 materialization 流程

**优先级：P2；静态源码确认；收益未实测。**

**源码事实。** client/server 的 run/network_wait.rs 各 272 行中有 269 行为顺序文本匹配；run/observation/sniff.rs 各 141 行中 139 行匹配，计数含空行与 inline tests。endpoint/ruleset materialization 也有相似编排。client 普通门禁仅编译测试 binary，不能把所有 runtime 状态逻辑长期绑在不可普通运行的 host shell 中。

**影响范围。** 重复的 stop/join/retire/error mapping 容易产生修复不同步。该问题主要影响维护成本和可测试性，不应捏造直接吞吐收益。

**建议改法。** 以职责抽取：通用 retained work/stop/join owner 放 runtime；Windows 同步原语留 platform-windows；网络中立 outcome/trait 放合适的中立边界；DNS/RuleSet work 保留各自 crate。binary 留 role、策略和错误映射。可在 client 包增加可安全执行的 library test target，隔离纯路由/lease/状态机与 host shell。

**风险与不变量。** 中：不建议建 common 大杂烩，不给 runtime 反向依赖 Windows/DNS/config；不以合并文件为目标；不能取消现有 privileged/timed 测试保护。

**验证方式。** 共享 owner 使用 injected monitor 和可控制 worker，证明 shutdown、取消、重复 wait、drop 等时序；两个 binaries 保留角色特定契约。安全库测试进入普通 CI，host Windows 场景仍只在专用 runner。

**定位。** `bins/ferrum2-client/src/run/network_wait.rs:35–153`；`bins/ferrum2-server/src/run/network_wait.rs:35–153`；`bins/ferrum2-client/src/run/observation/sniff.rs:15–65`；`bins/ferrum2-server/src/run/observation/sniff.rs:15–65`；`AGENTS.md:43–60`；`AGENTS.md:91–99`。

### PERF-09 · Affine shards 与 Tokio 主 runtime 缺乏统一线程预算

**优先级：P3（先测）；静态源码确认；收益未实测。**

**源码事实。** AffineConnectionExecutor::new 按 available_parallelism 创建 shard_count，with_shard_count 私有，不随 max_connections 收缩。两个 binaries 又各自创建默认 multi-thread Tokio runtime。并不是每个 inbound 创建一套 executor。

**影响范围。** 高逻辑核、低连接上限时可能过度配置线程/空闲 runtime；不能静态断言 shard 架构慢于工作窃取。

**建议改法。** 允许 composition/config 给出 process-level worker/shard 预算，至少评估 min(available_parallelism, max_connections) 和按负载选择的 shard 上限；保留 affine 局部所有权，不先重写 executor。

**风险与不变量。** 中：吞吐、调度公平性、CPU 利用率、局部性和尾延迟要一起看；主 runtime 与连接 shard 的工作职责不同，不能机械平均分核。

**验证方式。** 1/4/16 等 shard 数与不同主 runtime workers 交叉测试，在相同 affinity/CPU/负载下记录 thread count、context switches、CPU/有效吞吐和 p99。

**定位。** `crates/ferrum2-runtime/src/connection_executor.rs:73–108`；`crates/ferrum2-runtime/src/connection_executor.rs:155–199`；`bins/ferrum2-client/src/run.rs:218–230`；`bins/ferrum2-server/src/run.rs:94–108`。

### PERF-10 · SOCKS5 CONNECT 握手后仍保留共享 IO mutex

**优先级：P3（先测）；静态源码确认；收益未实测。**

**源码事实。** SocksStream 与一次性 SocksReplyPending 共享 Arc<Mutex<IO>>；CONNECT 生成时即引入共享 owner。SocksStream 的 poll_read/poll_write 每次锁住 IO，reply 消费后没有所有权还原接口。

**影响范围。** 这是每次 socket poll 的无争用锁成本候选，而不是全局锁或 async deadlock。高吞吐/小块传输是否可见需要 profile。

**建议改法。** 评估握手 phase 与 ready stream 的类型转换：只有在 reply 完成且没有其他共享持有者后回收独占 IO；若通用 SessionReply 契约阻碍转移，先设计局部 ready transition，而不是仓促改变整个 core Session 模型。

**风险与不变量。** 中：必须保留成功/失败回复的 exactly-once、sniff 期间的读流量、失败清理和 UDP control lifetime；不可在不复核 Send/Sync 契约的情况下把 Mutex 简单替换为 RefCell。

**验证方式。** 相同 relay buffer 和 socket 配置下对比大流与小块负载；测试回复失败、握手取消、半关闭和 UDP ASSOCIATE 独立生命周期。

**定位。** `crates/ferrum2-socks5/src/lib.rs:93–120`；`crates/ferrum2-socks5/src/lib.rs:321–350`；`crates/ferrum2-socks5/src/lib.rs:435–447`。

## 19 个成员覆盖矩阵

| Crate | 源码文件数 / 物理行数 | 结论 | 代表性定位 |
|---|---:|---|---|

| `ferrum2-client` | 96 / 27,552 | UDP 单跳资源与临时容器（PERF-03）；TUN 分域预算（ARCH-01）；嗅探（PERF-06）；薄化 host composition（ARCH-02）。 | `bins/ferrum2-client/src/run/egress/udp/prepare.rs` |

| `ferrum2-server` | 57 / 14,591 | 监听器新会话慢路径隔离（PERF-01）；保持 frozen route、provisional recheck 与提交原子性。 | `bins/ferrum2-server/src/run/udp/run_loop.rs` |

| `ferrum2-core` | 6 / 1,865 | 保持中立目标/流量/选择器契约；Datagram 已使用 Bytes，避免把 host 工作与预算策略堆入 core。 | `crates/ferrum2-core/src/lib.rs` |

| `ferrum2-rule` | 29 / 6,827 | 保持 small-linear/indexed 双路径与 snapshot；优化 active fields/bitmap（PERF-08）及 build（PERF-07）。 | `crates/ferrum2-rule/src/program/index.rs` |

| `ferrum2-ruleset` | 19 / 5,118 | 批量 successor 或不可变 index 共享（PERF-07）；保留下载、解压、缓存提交和 shutdown 的有界 owner。 | `crates/ferrum2-ruleset/src/cache_work/session.rs` |

| `ferrum2-crypto` | 15 / 3,276 | 已有 provider、in-place 操作与 UDP open cache；先测密钥缓存命中/会话 churn，不优先换加密后端或每包 spawn_blocking。 | `crates/ferrum2-crypto/src/udp/aead.rs` |

| `ferrum2-shadowsocks` | 35 / 12,590 | 新会话反向 ID index（PERF-05），多跳短容器（PERF-03）；保留认证/重放/失败原子性。 | `crates/ferrum2-shadowsocks/src/udp/server.rs` |

| `ferrum2-socks5` | 3 / 1,212 | UDP 已有 borrowed parser；CONNECT ready 后恢复独占 IO 属 profile 候选（PERF-10）。 | `crates/ferrum2-socks5/src/lib.rs` |

| `ferrum2-net` | 6 / 1,849 | 维持网络策略/能力的中立接口及 generation 缓存身份；接口解析缓存优化先测，不去掉 reset fence。 | `crates/ferrum2-net/src/resolver.rs` |

| `ferrum2-runtime` | 61 / 19,992 | 优先 Direct UDP buffer lease（PERF-02）；通用 owned-work 消重（ARCH-02）；线程预算后测（PERF-09）。 | `crates/ferrum2-runtime/src/udp/direct.rs` |

| `ferrum2-config` | 50 / 14,882 | 在现有准备/验证层输出配置资源包络（ARCH-01）；不把 config load 误当数据面热路径。 | `crates/ferrum2-config/src/lib.rs` |

| `ferrum2-dns` | 48 / 15,172 | 缓存维护算法（PERF-04）；保留实际 native lookup 工作被 parent 持有/join 的模型。 | `crates/ferrum2-dns/src/cache.rs` |

| `ferrum2-observability` | 17 / 5,267 | 指标族已固定；仅在 profile 证实原子竞争时评估 per-shard 累积，禁止无界标签和逐包日志。 | `crates/ferrum2-observability/src/metrics/family.rs` |

| `ferrum2-sniff` | 2 / 1,052 | 复用最终解析结果和增量状态（PERF-06）；保持 bytes/timeout/order 和完整协议验证。 | `crates/ferrum2-sniff/src/lib.rs` |

| `ferrum2-tun` | 59 / 18,920 | 当前系统 TCP＋原生 UDP；优先独立字节预算与 mapping buffer（ARCH-01），不沿用旧 smoltcp 调优结论。 | `crates/ferrum2-tun/src/system_tcp/mod.rs` |

| `ferrum2-platform-windows` | 42 / 12,630 | 保持 FFI、Wintun buffer lifetime、路由安装/回滚和 reset ownership 隔离；不为减少拷贝跳过安全边界。 | `crates/ferrum2-platform-windows/src/lib.rs` |

| `ferrum2-m0-harness` | 47 / 18,867 | 给新增池/索引/异步准入补并发取消与生命周期回归；现有 workspace/feature 契约继续保留。 | `tests/m0-harness/tests/workspace_policy.rs` |

| `ferrum2-m4-qualification` | 44 / 15,539 | 复用当前身份绑定、负载、资源采样基础；新增 cold admission、UDP allocations 与 mapping 容量场景，不新建大而重复的 benchmark 框架。 | `tools/ferrum2-m4-qualification/src/m4_support/throughput.rs` |

| `ferrum2-rule-qualification` | 15 / 3,866 | 已有 stats_alloc 与 timed 证据；新增 TTL 批到期、更新风暴、sparse/dense/Continue 场景；继续隔离 timed gates。 | `tools/ferrum2-rule-qualification/src/measurement/allocation.rs` |


补充：`ferrum2-tun-fuzz` 是独立 workspace，继续保持 sanitizer/fuzzing features 不泄露到普通产物，并把 pool lease/准入重排后的 reset/cancel 场景纳入 fuzz。`vendor/shadowsocks-crypto` 保留明确 patch provenance 和零化失败卫生，优先保持补丁小而可复核，不以删重放/随机/零化成本作为优化方案。来源：`crates/ferrum2-tun/fuzz/Cargo.toml`、`vendor/shadowsocks-crypto/FERRUM_PATCH.md`。

## 建议落地与验收

第一批分成独立变更，便于定位回归：PERF-03 单跳资源和提交 fast path → PERF-02 有界 buffer lease → PERF-05 反向 ID index。PERF-01 的慢路径隔离并行设计但独立交付，因为它改变时序与取消所有权。第二批处理 DNS cache、TUN 独立字节预算、嗅探复用和 owner 抽取。规则索引结构共享、worker 预算和 ready IO 类型转换放在 profile 数据之后。

性能验收既要有 `allocations/op`、申请容量、吞吐，也要有 p99/p999、丢包、实际 RSS、各域活跃/保留 bytes、shutdown/reset 后 owner 收敛。固定同源码身份、构建 profile、CPU/affinity、包长、并发数和负载；A/A 控噪后做交错 A/B，不把消除 allocation point 自动换算成吞吐提升百分比。

可复用现有 m0/m4/rule qualification。按 `AGENTS.md:43–60,91–99` 的 gate 分类运行：普通 workspace 测试排除 host/timed targets；client 与 rule qualification 普通门禁仅编译；TUN/Windows 只运行明确的纯/injected 路径；真实路由改写和管理员 Wintun 验证留专用 Windows runner。本报告没有执行这些命令。

## 不建议第一步做的改动

不把所有 Mutex 替换成 DashMap/ArcSwap；先减少临界区工作、修正数据结构，再证明读锁/原子争用。不要为了省分配把有界 budget 或真实 worker join 去掉。不要以全局 `target-cpu=native` 作为可移植发行包默认；LTO/CGU/编译 feature 精简只作独立构建实验。没有当前 profile 证据，不优先替换加密 provider、引入每包 spawn_blocking、重写 TCP relay 或基于旧 smoltcp 数字改现在的 TUN 数据面。

## 外部语义核验

Rust 官方 HashMap 文档：retain 与全量 values 遍历的当前复杂度按 capacity 而不是 live len 计；Tokio UdpSocket 文档：readable 可以 false-positive，try_recv 后必须处理 WouldBlock；Tokio copy_bidirectional_with_sizes 文档：两个方向各使用指定大小 buffer；Tokio runtime Builder 文档：默认 multi-thread worker 数按系统可用核心数选择，且可以通过显式配置覆盖。这些语义仅支持 API 行为解释，不能代替项目的实测。

资料地址（查询于 2026-09-08）：
```text
https://doc.rust-lang.org/std/collections/struct.HashMap.html#method.retain
https://docs.rs/tokio/latest/tokio/net/struct.UdpSocket.html#method.readable
https://docs.rs/tokio/latest/tokio/io/fn.copy_bidirectional_with_sizes.html
https://docs.rs/tokio/latest/tokio/runtime/struct.Builder.html#method.worker_threads
```

## 附件说明

`ferrum2-review-evidence.md` 保存上述发现的原文件行号摘录；`ferrum2-workspace-inventory.json` 保存逐成员依赖/文件物理行数/源码 SHA-256 与结构模式计数；`ferrum2-review-findings.json` 保存机器可读的问题清单。正则模式计数不代表问题数量或自动证明。
