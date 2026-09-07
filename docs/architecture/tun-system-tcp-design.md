# TUN 系统 TCP 转换设计

## 状态与范围

设计基线：`e1f103015d38892a62b184511b1e596e2e55b8d3`。
系统 TCP 已完成原子切换，Windows IPv4 宿主机正确性资格已通过；本文件保留设计基线与验收合同，并在末节记录实施证据。尚未进行新旧实现的性能对比。

已确认需求：

- 保留 Windows x86_64 Wintun 入口。
- TCP 不再由 smoltcp 终结；由 Windows TCP 栈完成入口 L3→L4 转换。
- UDP 保留现有 Ferrum2 原生解析、重组、association、过滤和响应组包路径。
- 原始目标继续交给现有规则、DNS 和 Direct／代理出口；不绕过路由决策。
- 分阶段提交；不保留 smoltcp TCP fallback，也不新增 stack 选择配置。
- 不引入 gVisor、Go 运行时、新 WFP 透明代理入口或本轮 UDP 性能优化。

**决策已确认：方案 B，产品管理最小临时入站放行。**
用户同时明确授权通过受管 runner 执行 `-AcknowledgeHostNetworkMutation`，
替代此前仅无特权验证的限制。授权不包含默认路由、宿主机 DNS、物理接口或无关状态变更。
实施必须同步更新资格与零残留合同；新增放行只覆盖受管 TUN 的内部 TCP listener 路径。

## 设计基线与替换边界

设计基线的 `stack/mod.rs::enqueue_complete` 对 UDP 提取 payload 后直接调用 `UdpTable::admit`，
随后返回。UDP 没有进入 smoltcp 的 UDP socket 状态机；切换后仍保留这条原生路径。

基线 TCP 在 `stack/tcp.rs` 创建 smoltcp socket，`tcp/owner.rs` 驱动双向内存桥，
`lifecycle/live/session.rs` 负责轮询和生命周期。上述 socket、内存桥与轮询实现现已删除。
当前 `system_tcp` 私有模块拥有 tuple 转换、映射、listener 和隔离；
`tcp/mod.rs::TcpFlow` 以真实系统 socket 保留 `AsyncRead + AsyncWrite` 和不可变 `target()`：

```text
应用 TCP socket
  → Windows 生成原始 IP/TCP 包
  → Wintun receive
  → Ferrum2 校验 + TCP 双向 tuple 改写
  → Wintun send，作为入站包交还 Windows
  → 绑定 TUN 本地地址的 TCP listener
  → 已认证映射对应的 TcpFlow / Windows TcpStream
  → 现有规则、DNS、Direct 或代理出口
```

反方向由 listener 对应的 Windows socket 生成 TCP 包，发往合成 peer，经 Wintun 读出，
恢复原始 tuple 后注入回应用。Windows 负责入口 TCP 的握手、排序、重传、拥塞控制和关闭；
Ferrum2 仍负责数据路径上的地址转换、映射所有权、包校验和生命周期隔离。

UDP 与 TCP 仍共享受管 adapter、包入口、输出背压及重组设施，不为此复制第二套 UDP 实现。

## D1：每地址族一个受管 listener，显式维护双向映射

记应用原始源端点为 `S:s`，原始目标为 `D:d`，TUN 已分配本地地址为 `L`，
listener 端口为 `l`，同族合成 peer 为 `P`，分配的转换端口为 `p`：

| 方向 | 原始包 | 重写后 |
|---|---|---|
| 应用发起／后续应用段 | `S:s → D:d` | `P:p → L:l` |
| listener 产生的返回段 | `L:l → P:p` | `D:d → S:s` |

- listener 绑定精确 TUN 本地地址，不绑定 wildcard、物理地址或公网地址。
- IPv4 与 IPv6 分开创建；IPv6 listener 为 V6ONLY，不通过 mapped IPv4 隐式合并。
- 使用系统分配的 listener 端口；不公开固定监听端口，不在配置中暴露实现细节。
- 只允许已验证的初始 SYN 创建映射；非 SYN 的未知 tuple 不创建连接。
- 正向索引包含完整原始四元组；反向索引包含地址族、listener 身份和合成端点。
- accept 必须同时匹配精确 peer 地址、端口、listener epoch 和当前 session generation；
  查不到、过期、重复 accept 或已 fenced 的连接立即关闭，不能交给规则系统。
- 不能仅以 `remote_port` 恢复原始目标；不能仅凭源地址或源端口判断反向报文。
- accept 后仍使用保存的原始 `D:d`，绝不把内部 listener 或 peer 地址当作路由目标。
- 应用直连内部 listener 不具备已准入映射，因此不会获得任意目标代理能力。

映射在有界 owner 内管理，不把可变 NAT 表公开给 client 或 outbound。
新连接达到 `max_tcp_flows` 时拒绝新建，不驱逐活跃 TCP。
容量必须包括半开连接和待发布连接，不能只计算已经 accept 的流。

## D2：合成 peer、路由与配置

合成 peer 是重写包使用的地址，**不是新增本机接口地址**。
它必须属于 TUN 的同族前缀、不同于已分配本地地址，并能通过该 TUN 路由回来。

选定推导策略：

- IPv4 常规前缀优先选择子网中最小可用单播主机地址；若它是本地地址，则选择下一个。
  不选网络地址或广播地址，保留当前 IPv4 `/31`、`/32` 的配置拒绝行为。
- IPv6 选择前缀内最小非全零 host 地址；若它是本地地址，则选择下一个。
  本次将可准入前缀收紧为 `/126` 或更宽；当前可通过的 `/127` 不再准入，
  避免依赖尚未验证的 Windows 合成 subnet-router-anycast peer 行为。
- 当前 `/128` 已被配置验证拒绝，继续拒绝；不暗中占用外部地址，
  不偷偷扩大前缀或安装新的外部捕获路由。
- 示例 `198.18.0.2/30` 可使用 `.1`；示例 IPv6 `::2/126` 可使用 `::1`。
- peer 可以与现有未分配到本机的 synthetic DNS 地址重合：DNS 按原始目标识别，
  TCP 反向识别按完整内部 tuple 和映射，不按“出现该 IP”进行劫持。
  必须测试 DNS TCP、DNS UDP 与普通 TCP 共存，不能靠文档假设无冲突。
- 启动与网络重置检查 peer 的实际路由属于受管 TUN；如果被更具体路由抢占，启动／恢复失败。
  不修复或删除不属于本次运行的路由；`auto_route=false` 也不绕过内部路径检查。

`max_tcp_flows` 保留为入口准入限制。`tcp_buffer_bytes` 随用户态桥删除，不能悄悄改成
SO_RCVBUF／SO_SNDBUF；Windows 的缓冲与自动调优由系统负责。
全部仓内配置、fixture、CLI 映射、错误变体和普通测试同步迁移，不留兼容别名。
现有 TCP timeout 来自 client composition 的 `context.runtime.idle_timeout`，不是独立 TUN 字段。
切换后继续显式执行该期限：半开映射从初始 SYN 起固定计时，SYN 重传不延长期限；
已建立映射以有效、已映射的双向 TCP 报文刷新空闲期限。超时 fence／关闭实际流并退役映射，
不能只清 NAT 表而留下 socket，也不能无声改成 Windows 默认无限等待。

## D3：包改写只拥有地址转换，不重新实现 TCP

复用现有 PacketParser 和 ReassemblyTable；只有通过现有长度、地址族、options、
扩展头和 checksum 验证的完整 TCP 包才能访问传输头。

- 使用解析结果中的 transport offset，不能假定 IPv4 固定 20 字节或 IPv6 固定 40 字节头。
- 重写 IPv4／IPv6 地址和 TCP 端口，更新 IPv4 header checksum 与 TCP pseudo-header checksum。
- 优先使用经过验证的增量 checksum 更新，不因 tuple 改写再次扫描整个 payload。
- 保留 sequence、acknowledgment、flags、window、options 和 payload；不自己处理重传／拥塞控制。
- 已有分片重组与 MTU 拒绝语义继续有效；不能把未完整重组的片段当作完整 TCP 首部处理。
- 输出仍由现有 owner 统一写入 Wintun；内部输出槽忙时保留待处理包，不增加并发 adapter writer。
- 外部不可信包继续校验；本轮不顺带删除 UDP 的响应复核或改变其队列／复制策略。

Windows 实际输出的 options、checksum 和分段形式必须在真实 TUN 上验证。
纯内存包改写通过不等于 Windows 能正确 accept。

## D4：TcpFlow 直接封装系统流及 generation lease

保留 `TcpFlow::target()`、`AsyncRead`、`AsyncWrite`，底层改为 Tokio Windows TcpStream。
删除 ByteQueue、FlowOwner 和 smoltcp socket pump，不在系统 socket 外再套旧的两级字节桥。

Interface 的行为合同：

- read、write、flush、shutdown 在 generation fence 后返回既有类别的连接重置错误。
- fence 必须唤醒已经 Pending 的读写；不能只在下一次主动调用时检查 atomic 标志。
- 普通读写由 Tokio 的 `poll_read`／`poll_write` 驱动就绪循环；虚假就绪后的 `WouldBlock`
  必须重新注册 reactor 唤醒，不能仅保存 generation fence waker 后返回 `Pending`。
- peer FIN 产生 read EOF，但仍允许写入；本地 shutdown 只关闭写半边，继续允许读取。
- shutdown 成功表示 Windows 接受写半关闭，不再承诺“FIN 已经被 Ferrum2 写入 Wintun”。
  原来依赖 smoltcp FIN 发包时刻的测试不应重新钉到另一个实现时刻。
- drop、timeout、reset 和 owner 退出都释放实际 socket；仅释放计数器不算关闭。
- 连接数／OwnerRegistry lease 跟随真实资源生命周期，不因 pending publish 提前归零。
- 保留原始目标和现有路由身份；不引入与用户需求无关的进程识别或新匹配字段。

监听接受使用 Tokio readiness，不采用 native owner 周期性 `accept + sleep` 轮询。
listen/accept 工作必须有明确 owner、取消和 join；不使用脱离生命周期的裸 spawn。
native owner 和异步任务之间仅传递有界 accept／retire 事件及不可变 lease，不能在持有共享锁时 await。

## D5：关闭、端口复用与网络重置

TCP 映射不能照搬 UDP 的 idle-only 回收。

- 半开连接有固定准入截止时间；过期不能继续 accept／发布。
- 正常 EOF 不能立即删除反向映射，否则最后 ACK、另一方向数据和 FIN 重传无法回到应用。
- RST／双向关闭进入退役；映射身份在安全回收前不得指向另一原始目标。
- 明确保留有界的退役／隔离状态；保守按 240 秒（2 × 120 秒 MSL）隔离已释放内部 tuple。
  隔离表和可用端口空间满时拒绝新建，不提前复用，不无界累积。
  240 秒是本设计的保守隔离选择，不是本机 TIME_WAIT 的测量值；可用转换端口限为
  1..=65535，每族活跃与隔离端口合计不超过该空间。隔离状态由长于 session 的生命周期
  owner 持有，reset 重建映射表时不能顺便清空；到期回收使用有界 deadline 索引。
- 不把 generation 整数当作线上的身份：旧包中没有 generation。
  新 session 使用新的 listener epoch；内部 tuple 的隔离覆盖跨 reset 的旧包与迟到 accept。
- 原始 tuple 在旧连接存活时出现不同 ISN 的新 SYN，不覆盖原映射；合法重传不得重复占用容量。
- 高连接周转会消耗转换端口隔离空间，这是该保守方案的明确代价，必须单独验证，
  不能只测长连接吞吐就宣布系统转换全面更快。

ResetNetwork 顺序：

1. 停止新准入、暂停正常包轮询，fence 当前 generation 及所有公开／待发布流。
2. 取消 listener accept 工作；通过既有 reset barrier 取消／排空 TCP handlers，
   关闭旧 socket，join 实际工作，退役旧映射与输出。只 abort task 而未 join 不算完成。
3. 按既有合同清理 UDP／分片 generation 状态；保持 adapter、受管路由和 strict-route WFP 身份。
4. 刷新接口快照，重新验证内部 peer 路由，准备新 epoch 的 listeners 和映射表。
5. 现有 stack/router/outbound/inbound hooks 全部接受新 generation 后恢复准入。

listener 创建、第二地址族绑定或任务启动失败必须回滚已经拥有的资源；
不发布半初始化 session。最终退出和 full rebuild 同样先关闭／join socket 工作，再清理 adapter。

## D6：Windows 防火墙是独立的实施决策

参考实现不是“只改包就没有宿主机策略成本”。
[sing-tun Windows 源码（固定版本）](https://github.com/SagerNet/sing-tun/blob/3760753c251bbe03dd8286446f90463c22f0dbc9/stack_system_windows.go)
会给当前可执行文件添加所有 profile 的入站 TCP allow 规则。
Ferrum2 不照搬这种应用级宽泛放行，也不关闭防火墙、不修改默认 action。

[Windows TUN 资格合同](../windows-tun-qualification.md#safety-boundary)将随实施更新，
只增加受管 TCP listener 所需的临时入站放行授权，不允许任意持久防火墙规则。
现有 strict_route 不能被当作已具备 listener 入站放行能力；
listener 绑定成功不证明 Wintun 注入的连接能够通过实际入站过滤。

已比较以下两种策略，用户选择第二种：

1. **不自动修改防火墙。** 使用宿主机现有策略；部署者自行提供所需的最小放行。
   受策略阻止时明确报告连接失败，不降级回 smoltcp，不自动放开应用。
   优点是不扩大当前权限合同；代价是某些默认阻断入站的宿主机不能即装即用。
2. **允许产品管理严格限定的临时入站放行。** 独立于 strict_route，限定本程序、TCP、
   受管 TUN 接口、本地 listener 地址／端口及合成 peer；生命周期内创建、验证、撤销。
   需要先验证 Windows 实际提供的条件表达与策略优先级，再选择平台实现；
   不假设加一条普通 WFP permit 就能覆盖所有系统／第三方 block。
   同步扩展资格／恢复合同和零残留读回；用户已明确授权实现与受管宿主机执行。

两种策略都不允许物理接口／公网 listener 暴露，不允许以跳过 BFE／防火墙检查掩盖失败。
平台实现优先使用独立、进程拥有的动态 WFP session：精确条件与实际分配的 sublayer
weight 必须读回，进程终止自动释放，正常退出显式关闭。针对该精确路径的 hard permit
不能绕过更高优先级阻断、callout veto 或其他层策略；受策略阻止必须报告真实失败，
不得扩大匹配范围或关闭防火墙。详见
[Windows WFP action arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration)。

## 模块所有权与 clean cutover

| 所有者 | 实施责任 |
|---|---|
| `ferrum2-tun` 私有 TCP 转换模块 | tuple 改写、双向映射、准入、关闭及隔离、原始目标恢复 |
| `ferrum2-tun::tcp` | 系统 TcpFlow、generation fence、真实 socket 生命周期 |
| `ferrum2-tun` native lifecycle | listener epoch 创建／回滚／join、现有公平调度和 adapter 生命周期 |
| `ferrum2-platform-windows` | Windows socket／接口能力、已授权的最小动态入站放行及完整读回 |
| `ferrum2-config` 与 client composition | peer 可推导性准入、删除旧缓冲字段、传递新已准入配置 |
| 现有 tests/platform 与 qualification 工具 | 真实 TCP、UDP 不回退、网络重置、崩溃恢复、零残留证据 |

不新增通用 stack trait：只有一个生产实现时，额外动态 backend seam 没有收益。
模块 Interface 隐藏映射、Windows accept 和回收细节；测试通过包输入／输出、实际流和生命周期结果断言。
移除失效的 smoltcp Interface、SocketSet、MemoryRx/MemoryTx、TCP pump、旧桥指标及仅证明旧形状的测试。
是否还需保留 smoltcp 的非 TCP 类型由引用审计决定；只因测试构包而保留生产依赖不可接受。
UDP 相关行为测试保留，调用方仅做公共构造和时钟类型迁移，不重写 UDP 算法。

## 分阶段提交与验收

### 阶段一：本设计和决策记录

提交架构、需求／非目标、风险、调用方迁移范围、验证顺序；不改产品运行行为。
防火墙策略 B 和受管宿主机验证授权已确定；后续提交开始产品实施与安全合同迁移。

### 阶段二：原子产品切换

实现 packet rewrite + NAT owner + 系统 TcpFlow + listener 生命周期；同步迁移 config、client、
指标、fixture、现有测试和配置说明，删除 smoltcp TCP 及旧桥，不让默认入口指向未完成实现。
相关包 format、clippy、普通安全测试和 client compile-only 门禁通过后提交。
不提交仅有配置开关、空实现、fallback 或运行时尚未接通的“基础框架”。

### 阶段三：资格工具与实证

按已批准的安全合同更新现有 qualification，不新建绕过公开 runner 的 privileged 测试入口。
验证目标：

- IPv4／IPv6 完整 tuple 往返、TCP options、分片与 checksum 的确定性包测试。
- 真正 OS socket 的传输、半关闭、取消唤醒和关闭，使用无特权 loopback smoke。
- 同源端口不同目标、未知反向包、伪造／迟到 accept、SYN 重传、映射满、隔离空间满、
  关闭与 reset 竞争的行为测试。
- DNS TCP／UDP、现有 UDP filtering／mapping、队列背压和 generation 行为保持。
- Windows 真实 Wintun 的 TCP 双向数据、UDP、策略隔离、重置、强杀恢复和零残留。
- 现有 host 正确性 runner 只证明其实际覆盖的 IPv4 场景；IPv6 真实验证如需扩展地址与路由
  授权，必须显式评审合同，不能用纯包测试冒充 IPv6 宿主机已通过。
- TCP 长流、多流、短连接周转与 CPU 需要实际成对测量；正确性通过不等于提速。

真实宿主机执行仍要求已有提升权限 shell 和明确的 `-AcknowledgeHostNetworkMutation` 授权。
普通测试不得创建真实 adapter、修改路由、DNS、WFP 或防火墙。
没有真实执行的项目必须明确标记未验证，不能写成已完成资格。

## 实施与验证结果

2026-09-07 完成以下分阶段提交：

| 提交 | 内容 |
|---|---|
| `c97b6ef2`、`22d1db48` | 设计、方案 B 与受管宿主机授权 |
| `3416def6` | 原子系统 TCP 切换；移除 smoltcp、旧 byte bridge、tcp_buffer_bytes 和失效指标 |
| `400e12c6` | 精确 TCP ingress WFP 资格、重置与零残留合同 |
| `8d799fe1`、`3fedbbcf` | 使用真实出口指纹变化触发重置，并按 Windows 约束先撤销受管测试路由再创建替代项 |

最终实际执行候选：`3fedbbcf4c57d3cc8ff3bbf694ae6d23d5ff7400`。
资格 source bundle：`39fc258a8c0794d3ac94fe27a825767659f4dd0644c2056544ee3f3d4398af5b`。
run ID：`01c2cc163c94`；`qualification.json` SHA-256：
`31a7090e5adb0533c5eec5af3af1ea95a24de851b2e10081c1e91bd78372c2c7`。
原始本机证据保留在仓库外的 `ferrum2-evidence/system-tcp-3fedbbcf`，不提交二进制或运行日志。

**最终 verdict 为 `QUALIFIED`，八项全部 PASS，总耗时 112.1404339 秒：**

- 真实 Wintun 创建／删除、系统 TCP 双向传输及原生 UDP。
- run-owned `/32` 隔离与精确六条件、hard-permit TCP ingress WFP 读回。
- 真实语义网络重置：session generation `2 → 4`，strict-route filter IDs 与实际权重保持；
  TCP listener `62894 → 65006`，filter ID `203595 → 203597`，旧 filter 已不存在。
- 重置后再次通过 TCP／UDP；强杀进程树后恢复通过。
- 最终 adapter、route、address、process、port、strict-route WFP、TCP-ingress WFP 残留均为 0。

此前两次失败分别是无关 loopback 路由未触发语义重置、Windows 拒绝同接口同前缀并存路由；
均保留失败证据且清理 PASS，不被最终成功覆盖或算作通过。

普通验证已通过：

```text
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test -p ferrum2-tun -p ferrum2-platform-windows --lib --no-default-features --features fuzzing --locked
cargo build --workspace --bins --locked
cargo test --workspace --exclude ferrum2-client --exclude ferrum2-tun --exclude ferrum2-platform-windows --exclude ferrum2-rule-qualification --locked
cargo test -p ferrum2-client --all-features --no-run --locked
cargo fmt --all -- --check
cargo doc --workspace --all-features --no-deps --locked
python -B -m unittest discover -s tests/performance_candidate -p test_*.py -v
python -B -m unittest discover -s tests/platform -p test_qualify_native.py -v
pwsh -NoProfile -File tests/platform/test_windows_tun_host_qualification.ps1
```

TUN／Windows platform 两个安全 library suite 共 211 passed；普通 workspace gate
768 passed、5 ignored；client 仅编译测试。Python 分别 144／9 passed。
生成的 reset selector 配置也已通过真实 client 的 `--check-config`，该检查不创建网络资源。

边界仍然成立：IPv6 仅有确定性包／状态覆盖，未作真实宿主机资格；没有吞吐、CPU 或延迟
成对测量，不宣称提速。本机包含操作员手动允许的防火墙应用规则，runner 未创建或修改这些
持久规则，不承诺其他宿主策略下没有首次弹窗。未引入固定路径安装器、安装状态文件或新的
二进制路径参数；最终使用原有公开 runner。
