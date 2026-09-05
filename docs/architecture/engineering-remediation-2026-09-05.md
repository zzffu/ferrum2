# Engineering remediation — 2026-09-05

**[全量生产静态审查](engineering-audit-2026-09-05.md)已完成，后续采用
[统一架构设计](engineering-design-2026-09-05.md)按所有权分批实施；先修 Qualification
证据契约，完成架构与性能无回退验收后才进行 CPU profiling 驱动优化。
本文下列修改和覆盖表保留为先前阶段的候选历史，不代表当前架构已实现或验收。**

这是持续整改记录，不是生产资格声明。起点 `9bbcea22d0373ff60932f929d93d265c98c0a711`，
开始时工作区干净。根目录和全部 51 份 scoped `AGENTS.md`、
README、文档索引、workspace manifests、架构台账和 CI 入口为审查输入。
以本地规则为准；不迁入 Codex 专属流程。不修改 vendor、fixture、网络权限或 lint 强度。

## 架构设计后的实施

统一设计里程碑为 `1b40da27`；以下工具修复属于 M1，尚未开始 M2–4 产品架构修改。
产品源码仍为 `2fb0dd4a`。详细命令和 red/green 见[逐批证据](engineering-remediation-evidence-2026-09-05.md)。

| 批次 / 审查项 | 已落实行为 | 实际验证 |
|---|---|---|
| M1a / RTL-05 | 普通 workspace 排除 timed Rule qualification；强制保留独立 no-run gate | workspace policy 20、完整 m0 93 passed/5 ignored、CI Python 55；rule test compile-only、m0严格clippy、fmt通过 |

## 环境与暂定验收

- Windows 11 Pro `10.0.26200`，AMD Ryzen 7 7700，8 核 / 16 逻辑处理器，
  49,373,096 KiB 可见内存；Rust/Cargo 1.97.1，MSVC x86_64，锁定依赖。
- WSL2 Debian：Linux `6.18.33.2-microsoft-standard-WSL2`，Rust 1.97.1 GNU x86_64，
  23,567 MiB 内存。WSL 不能代替真实 Windows 驱动资格或原生 Linux 性能环境。
- 用户尚未提供生产负载和 SLO。暂定工程验收：故障测试先在旧代码失败；修复后通过，
  所有相关 owner、permit、queue 和 buffer 回到测试基线；正常协议和关闭行为不退化；
  受影响包格式、严格 lint、测试及相关 workspace 门禁通过。
- 性能验收复用现有测量器与 reviewed policy；必须保留成功工作量、错误、清理、CPU、
  内存及适用延迟分位数。同条件交错重复 A/B，保留范围；没有覆盖的分位数不得推算。
  闭环测量不代表过载排队延迟，微基准不代表端到端生产收益。
- 原始证据已复制到 Git 忽略的 `profiles/remediation-20260905T075656Z/`，含四次真实 host
  运行及检查日志。`manifest.json` 记录 316 个文件的长度和 SHA-256；manifest 自身 SHA-256
  为 `36a737fe8808a844ca6bb1b6d3b90406a7107e8c117d52fff042f21bf55daaee`。
  这是本机留存索引，不是新的测量器或验收策略。不提交 target、profiles 或测试凭据。

## 先前阶段 Workspace 覆盖清单

当前19个package的生产静态审查状态及逐文件哈希见[全量审查](engineering-audit-2026-09-05.md)。
本节保留最初阶段的覆盖粒度，便于解释下列历史测试证据。

每项适用根指南及该目录 `AGENTS.md`；测试和工具还继承 `tests/AGENTS.md` 或
`tools/AGENTS.md` 及更近的 scoped 指南。下表区分静态筛查、具体路径审查和执行验证；
“筛查”不代表逐行审查所有实现。文件数 / 行数为起点附近 `src/**/*.rs` 物理计数，含测试，
只用于导航，不按行数机械拆分。

| Package（目录） | src 文件 / 行 | 已查看的职责或路径 | 状态 / 验证入口 |
|---|---:|---|---|
| client（bins） | 83 / 25967 | prepare/materialize → SOCKS/TUN → egress；DNS、network、shutdown composition | 约束/调用链筛查；R11 已修复；仅编译测试，m0 进程验证 |
| server（bins） | 51 / 13491 | materialize → SS TCP/UDP → Direct；共享网络和冻结路由 | 约束/调用链筛查；package + m0 |
| core | 4 / 1649 | target、Datagram、trait、selector/plan | 约束/接口筛查；package |
| rule | 19 / 4672 | 编译、候选索引、scratch、registry | 约束/依赖筛查；package + config |
| ruleset | 9 / 2326 | 下载、blocking owner、原子快照、refresh | R4 已修复验证；其余下载/刷新路径仍为定向审查 |
| crypto | 11 / 1950 | typed keys、nonce、AEAD、entropy | typed owners/entropy/nonce/AEAD 定向审查；vectors/entropy |
| shadowsocks | 18 / 4785 | TCP authenticate/replay/flow；UDP prepare/commit | 约束/调用链筛查；协议与 tokio adapter |
| socks5 | 1 / 574 | no-auth command、retained control、borrowed UDP codec | 握手/codec/one-shot reply 定向审查；command/udp |
| net | 4 / 909 | immutable selection、256-entry interface cache、binder | 快照、选择优先级、cache 与 binding 定向审查；network contracts |
| runtime | 28 / 9634 | metrics、supervisor、affine executor、UDP owner/queues、shutdown | R1/R3/R6/R7/A2 已修复验证；其余路径仍需深入审查 |
| config | 25 / 8923 | prepare/finish、资源计划、验证边界 | bounded load/draft/finish/graph 定向审查；config/v2 contracts |
| dns | 26 / 7193 | proxy TCP/UDP、cache、tagged owner/admission | R2 / Perf1 已修复验证；并发 cache 性能尚未覆盖 |
| observability | 11 / 3937 | closed schema、composition renderer、手动 gauge | 约束/接口筛查；metrics/tracing contracts |
| sniff | 1 / 267 | transport strictness、bounded parser seam | 完整 parser 实现/边界定向审查；sniff contract |
| tun | 48 / 16981 | packet/stack/association → caller policy；live/hosted 选择 | R8 生命周期已修复验证；其余平台边界定向审查；safe lib + host qualification |
| platform-windows | 35 / 10528 | injected core/live FFI、managed transaction | 约束/平台边界筛查；hosted-safe lib + all-features check |
| m0-harness（tests） | 18 / 5836 | 黑盒进程、workspace policy、lifecycle | 约束/门禁筛查；先 build bins 再 package |
| m4-qualification（tools） | 34 / 13763 | profile contract、TCP/UDP/DNS、host identity | 测量能力审查；self-check |
| rule-qualification（tools） | 14 / 3760 | 单一 allocation owner、timing/报告 | 约束/测量入口筛查；compile-only，显式测量另列 |

关键非 Cargo 项：`tests/{ci,platform,performance_candidate,performance_rule}` 对应四组
Python unittest；`tools/{ci,performance_candidate,performance_rule}` 是对应控制器；
PowerShell correctness/performance runner 分离，需静态 contract、源清单重建及显式 host
qualification。共享 fixtures 保持原样。CI 包括 `m0.yml`（quality/platform/qualification）、
`lifecycle-stress.yml`、`tun-fuzz-deterministic.yml`、`performance-candidate.yml`；provider identity、
fuzz sanitizer 和原生 musl 的执行证据必须单列，不能由本地 Windows 测试替代。

## 真实所有权与数据路径

配置先 prepare，再由 binary materialize DNS、RuleSet 和固定端点，再激活 process roots；
失败逆序回滚。core/net 提供协议中立契约；runtime 只依赖 core/net，不能吸收 DNS 或遥测 schema。
SOCKS command 和 SS authenticated flow 把已验证目标交给路由和 connector，TCP relay 保留
half-close / 固定缓冲 / 背压；UDP 先 reserve runtime 容量，再 commit 协议身份及一次性路由。
DNS listener 的 JoinSet 拥有请求任务，TaggedResolver 的独立 owner 拥有 upstream 和 shutdown；
RuleSet refresh 在完整编译成功后发布 generation。TUN 负责 packet/stack 和 generation-bound
association，Windows crate 才能触及真实 adapter、route、WFP；普通测试关闭 live-backend。

## 当前整改结果

完整的逐批复现、命令、失败、性能表和撤回记录见
[验证证据](engineering-remediation-evidence-2026-09-05.md)。下表是当前保留的行为；
每项位置、触发条件和契约均已通过代码路径或失败测试确认。没有将静态性能假设当作瓶颈。

| 项 / 优先级 | 位置与被破坏的契约；触发及影响 | 当前修复与验证 |
|---|---|---|
| R1 / P1 | runtime `metrics.rs::serve_metrics_connection`：慢读响应/永不结束 shutdown 可永久占据 admission | 整体 I/O 4 秒 deadline；慢读、错误响应、shutdown、满载后 admission 恢复测试。同步 renderer 仍须非阻塞 |
| R2 / P1 | DNS `proxy/loops.rs::tcp_loop`：子任务 panic 被吞，accept 早退遗漏显式 join | 优先消费完成/取消；所有退出 abort + join；旧 panic 测试失败，新实现释放 TCP/UDP listener 后可重绑定 |
| R3 / P1 | runtime `udp/direct.rs`：panic/首次 poll 前 abort 跳过 manager.remove，滞留 session/queue/owner slot | 生命周期 guard 先移除准确 generation，再释放容量；共享 manager 下 abort/panic 两项 owner 全基线测试 |
| R4 / P1 | RuleSet `loader.rs` 原 blocking owner：取消 shutdown 后 join handles detach；无 worker admission | 独立私有 `blocking.rs`，每 loader 最多 2 workers/2 handles；permit 随 closure，取消/并发 shutdown 可重试且 join；故障测试通过 |
| R5 / P2 | `HostExecution.ps1` 原 product startup：runtime 未返回就报错，启动日志被最终清理删除 | 私有 `HostProduct.ps1` 统一启动、关闭与失败导出；注入 client/server/export 失败测试；闭合源 bundle 同步更新 |
| R6 / P1 | runtime `run_direct_session`：有限队列可被持续补入，while-drain 饿死已就绪应答 | 每请求轮询一次应答、显式 cooperative budget；保留通知合并下排空和取消前已接纳请求；旧实现 64 次发送后才响应，新公平性测试通过 |
| R7 / P2 | runtime `udp/{session,manager}.rs`：反序提交采样时间缩短 idle deadline | 三条 activity 更新均单调；queued/immediate 反序提交旧实现失败，修复后 deadline 与完整 owner 基线正确 |
| R8 / P1 | TUN `OwnerThread::reap`：取消 await 后 native cleanup 尚未结束但 owner 提前返回 | 私有 `runtime/thread.rs` 保留 join 所有权，锁保持到 native join 完成；运行中/阻塞池已满两种取消测试通过；Windows/WSL safe lib 各 128 项 |
| R9 / P2 | performance `Invoke-Ferrum2HostTrial`：失败丢失 before metrics/产品日志，无法区分等待阶段；导出失败替换原错误 | 提前保存 before，失败保存 phase 与全部产品/workload 日志；保留原始错误；同一注入测试在旧源有 3 处失败，新 104 项 controller suite 通过 |
| R10 / P2 | qualification `Invoke-Ferrum2HostQualificationChecks`：probe 失败立即关闭产品，缺少数据面状态 | probe 前保存两端 metrics，失败保存产品日志与 failure metrics；外层指向持久 evidence 目录；7 项平台 Python tests 和真实八项资格通过 |
| R11 / P1 | client `render_client_metrics` 重复声明基础 TUN flow family，违反 OpenMetrics 唯一性，严格采集器可拒绝 scrape | owner gauge 单独命名；旧产品 HTTP 黑盒测试失败，新两端通过；client compile-only 与严格 lint 通过 |
| Perf1 / P2 | DNS `cache.rs::insert`：未过期状态仍每写全表 + FIFO 扫描；测量确认成本随容量显著增长 | 到可能过期时间之前跳过扫描，key 不存在时跳过 FIFO 查找；TTL/FIFO/observer 语义保留；六对测量见下 |

R4 和 R8 仍不能强制中断卡住的系统文件操作或 native cleanup；它们保留和等待所有权，
不承诺底层 OS 操作的绝对时限。R8 取消后的 shutdown 可能等待更久，这个代价不能隐藏。

## 架构与规则适配

- 规则符合性以根和 scoped AGENTS 为准；保持 native future/Send、精确依赖、closed errors、
  reserve-before-protocol-commit、无新 unsafe。没有改 vendor 或削弱 lint/限制。
- RuleSet blocking admission/join 从 loader 流程分离；Direct UDP socket/factory/双栈归一化
  从会话 owner 分离到私有 `udp/socket.rs`；TUN native thread 的退出不变量由一个 owner 实现。
  调用方无需分别处理正常、panic、abort 三种清理路径。代价为少量内部模块和 shutdown 同步。
- 私有 Windows `latency.rs` 统一有界采样和 nearest-rank；workload 由 1021 降至 989 行，
  解决工具的 1000 行硬性规则。不是按行数搬移无关逻辑。其他大 owner 仍列为待审。
- 测量工具没有第二套 CLI；startup 与 active failure 共用 product 日志导出。所有 source
  bundle 按字节数和 SHA-256 更新；旧证据用其原提交读取，不添加兼容 reader。
- 低影响 API 偏好仍有余项：部分 bool 构造参数、宽泛公开面与大模块尚需逐调用方确认。
  不把这些与已复现的资源/生命周期缺陷混列为同级风险。

## 性能结论与测量边界

没有证明整体 TCP/UDP/TUN 吞吐或尾延迟改善，也没有通过完整生产性能验收。

**DNS cache 稳态单线程写入已获得可复现局部收益。** 基线 `3ad88718...`、候选
`bd9f9fcb...`，release/锁定依赖，同一个 rule producer、1/100/1000 容量，60 秒 TTL，
预建输入、固定 clock；六对 AB/BA 交错、每次 31 个自校准批次、5 批预热。
12/12 次 311 场景 correctness/allocation/parity 全通过，完整样本和每次实际迭代数保留。

| 容量/操作 | baseline p50 ns/op，中位数 [范围] | candidate，同单位 | 配对成本 B/C |
|---|---|---|---|
| 1 / FIFO write | 192.63 [191.72,193.54] | 161.79 [157.95,168.34] | 1.187 [1.144,1.223] |
| 100 / FIFO write | 3469.74 [3455.26,3516.22] | 168.98 [163.84,175.82] | 20.662 [19.653,21.170] |
| 1000 / FIFO write | 32020 [31660,32240] | 159.77 [157.77,162.40] | 200.117 [197.844,202.193] |
| 1000 / refresh | 29590 [29320,29820] | 139.99 [137.29,144.68] | 211.731 [204.312,216.181] |

读命中约 61 ns/op；每次写入仍 2 allocations。这个结果不是网络 DNS QPS，也不是逐请求
p99。任意中间 key 刷新与到期扫描仍可能线性；并发争用和 TTL 突发尚缺测量。
raw 同时保存 p50/p95/p99 批次分布、完整进程 CPU 与 peak working set；整体 311 场景 CPU
约 34 秒，不归因于 cache 子场景。不存在通过少做工作或删校验得到该结果的路径。

**Windows TUN 的所有尝试均保留。** Quick 每场景 3 对，预热 2 秒/active 10 秒；TCP
单流 64 KiB、延迟 1 KiB、UDP 1200 B/batch 1、分片 1440 B/batch 4。新增 workload schema 4 /
host trial schema 3 保留 p50/p95/p99 与最多 2,000,000 样本。延迟从发送前至完整回显验证后，
包括重试；不含连接建立。闭环与单流数据不代表开放负载或 256 流逐请求排队 SLO。

- 两次早期 A/B 分别只有 16/24、23/24；就绪超时和分片重传耗尽未被删去。
- R6 同代码 A/A 24/24 功能成功，但 UDP 倍率范围约 -9.9% 到 +10.4%，同代码也被策略判
  REGRESSION。保留 2% 策略，没有调宽门槛。
- 原始 9bb → 4e 的完整 Quick 24/24：分片配对中位数约 -4.90%，总体 REGRESSION。
- 315 → 7e 的 timer 复用尝试也是 24/24 / REGRESSION，未证实收益，已在 `79ecb468`
  撤回 timer 复用；保留 R7 单调性修复。没有将该候选数据归给撤回后的代码。
- 首次 Confirm 仅 1/50，workload TCP 10054；事后 server 有 network reset/relay_io 各 1，
  因缺少当时 before 数据，不能确定事件先后或归因。已补齐诊断。
- 第二轮 Confirm：baseline `5b46b03e...` 是原始 9bb 产品加同一当前 harness；
  candidate `8d3ecf7e...`。五对、5 秒预热/30 秒 active，增加 256-flow fairness；46/50 后在服务端 startup.bind 失败，validator exit 2，不能作完整比较。

所有已结束的 host 运行的 runner JSON 均报告五类残留为 0；全量审查 HT2 发现部分删除后读回缺口，不能扩大为每类独立验证。“执行退出 0”与“性能策略通过”明确分开。
R5/R9/R10 的工具修复解决取证缺口，没有证明原始 TCP/UDP 故障已被消除。

## 已执行验证与当前资格

完整命令、执行日志和 commit 对应关系见证据文件；这里不把未运行项记为通过。

| 门禁 | 实际证据 |
|---|---|
| locked workspace bins build；SOCKS/SS 跨进程测试 | 已执行；完整 workspace gate（排除 client/TUN/platform）最新 675 passed / 0 failed / 5 ignored |
| runtime / DNS | 最新 125 / 74 passed；WSL 同两包共 199 passed |
| RuleSet | 25 passed；故障边界/HTTPS/loader 与严格 lint 已验证 |
| client all-features test | 仅 `--no-run` 编译；从未执行 client test binary |
| TUN/platform safe lib | Windows TUN 128、platform 59；WSL TUN 128；均 no-default-features + fuzzing，不创建 adapter |
| 格式、workspace all-targets/all-features clippy -D、docs | 已通过；R8 后重新验证 client compile-only、全 workspace lint/docs |
| M4 self-check | PASS，56 mutations；新的量化算法与空输入拒绝也在 self-check 内 |
| Python controller / platform | performance 104、rule 19、CI 55、platform native/注入资格 7；对应 PowerShell 非变更合同通过 |
| Windows unprivileged native contract | 早期 target-specific release PASS；后续真实 host 使用各自 commit 独立 release 构建 |
| 真实 Windows TUN 当前工具/产品 | `8d3ecf7e...` 八项 QUALIFIED，源 bundle `b105cdac...`，五类残留全零 |

675 项完整 gate 位于 R7 时点；后续 timer 撤回重跑 runtime 125，R8 重跑 TUN/WSL/client
及全 lint/docs；R9/R10 只改工具与测试，Rust 产品源码与 d6 一致。MSVC 仅有生成 import lib
的 informational stdout warning，没有放宽 lint。一次 q TCP probe timeout 单独保留，
其后成功没有覆盖失败历史。

## 未解决项与可直接继续的工作

| 项 / 优先级 | 事实、假设或环境限制 | 下一步与验收 |
|---|---|---|
| 长负载 TCP/UDP 故障 / P1 | Confirm TCP reset、一次资格 TCP connect timeout、早期分片缺 ACK；根因未确认 | 使用补齐的 before/failure metrics、phase、产品日志定位；禁止忽略网络事件、重传失败或补单个试次 |
| 性能 / P1 | 已有负向信号且当前主机同代码波动超过策略门槛 | 当前 Confirm 46/50，不完整；仍需查清 bind 失败、新 bundle A/A、开放负载与长时 CPU/内存斜率；不足时使用隔离原生 runner |
| System resolver / P1 待验证 | runtime/DNS/RuleSet/binary bootstrap 有 `lookup_host`；锁定 Tokio 的实现使用 spawn_blocking，取消 waiter 不等于取消 OS lookup | 注入阻塞底层，验证超时后的实际工作 admission/join；不能把异步超时当 native 操作上限；尚未确认生产积压规模 |
| UDP 可观测性 / P2 | Direct owner 的终止 result 仍有被丢弃路径 | 对照 binary 的 closed reason 指标补缺口，避免重复 schema 或 peer 数据 |
| Cache 后续 / P2 | 此次只有固定 TTL 单线程写入测量 | 大容量/并发/过期突发/随机刷新、网络 DNS 请求与尾延迟；保留正确性和成功工作量 |
| 架构 / P2 | runtime reset、observability metrics、TUN live owner 仍约 800 行以上；部分 crate 仅定向审查 | 围绕 owner 不变量和 caller 负担审查，禁止按行数机械拆分；无逐行覆盖声明 |
| 生产验收信息 | 未给生产流量、连接分布、DNS/RuleSet 规模、SLO | 现有工程标准暂定，不用自造 SLO 宣布生产可用 |

未执行或不适用于本地的门禁：完整 lifecycle ignored qualification、Linux IPv6-only
ignored 用例、原生 GNU/musl 全 workspace/linkage、外部 interop provider、专用 Linux CI
sanitizer/fuzz 一小时 campaign。WSL targeted tests 不能代替这些证据。命令、限制与入口保留
在证据文件的“未完成项与下次直接入口”；客户端始终 compile-only。

所有变更均按独立问题本地提交，未推送/部署。开始时无用户未提交修改，未覆盖无关工作。
当前不能宣称全项目生产可用；结论仅限记录的平台、配置、注入故障及工作负载。
