# Engineering remediation — 2026-09-05

这是持续整改记录，不是生产资格声明。起点 `9bbcea22d0373ff60932f929d93d265c98c0a711`，
开始时工作区干净。根目录和全部 51 份 scoped `AGENTS.md`、
README、文档索引、workspace manifests、架构台账和 CI 入口为审查输入。
以本地规则为准；不迁入 Codex 专属流程。不修改 vendor、fixture、网络权限或 lint 强度。

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
- 原始日志暂存在 Git 忽略的 `target/remediation-*.log`；每批在本文记录命令与结果。
  不将 target、profiles 或测试凭据提交。

## Workspace 覆盖清单

每项适用根指南及该目录 `AGENTS.md`；测试和工具还继承 `tests/AGENTS.md` 或
`tools/AGENTS.md` 及更近的 scoped 指南。下表区分静态筛查、具体路径审查和执行验证；
“筛查”不代表逐行审查所有实现。文件数 / 行数为起点附近 `src/**/*.rs` 物理计数，含测试，
只用于导航，不按行数机械拆分。

| Package（目录） | src 文件 / 行 | 已查看的职责或路径 | 状态 / 验证入口 |
|---|---:|---|---|
| client（bins） | 83 / 25967 | prepare/materialize → SOCKS/TUN → egress；DNS、network、shutdown composition | 约束/调用链筛查；仅编译测试，m0 进程验证 |
| server（bins） | 51 / 13491 | materialize → SS TCP/UDP → Direct；共享网络和冻结路由 | 约束/调用链筛查；package + m0 |
| core | 4 / 1649 | target、Datagram、trait、selector/plan | 约束/接口筛查；package |
| rule | 19 / 4672 | 编译、候选索引、scratch、registry | 约束/依赖筛查；package + config |
| ruleset | 9 / 2326 | 下载、blocking owner、原子快照、refresh | 生命周期路径审查中；loader/https |
| crypto | 11 / 1950 | typed keys、nonce、AEAD、entropy | 约束/接口筛查；vectors/entropy |
| shadowsocks | 18 / 4785 | TCP authenticate/replay/flow；UDP prepare/commit | 约束/调用链筛查；协议与 tokio adapter |
| socks5 | 1 / 574 | no-auth command、retained control、borrowed UDP codec | 约束/接口筛查；command/udp |
| net | 4 / 909 | immutable selection、256-entry interface cache、binder | 约束/接口筛查；network contracts |
| runtime | 28 / 9634 | metrics、supervisor、affine executor、UDP owner/queues、shutdown | 重点审查/整改中；完整 package |
| config | 25 / 8923 | prepare/finish、资源计划、验证边界 | 约束/依赖筛查；config/v2 contracts |
| dns | 26 / 7193 | proxy TCP/UDP、cache、tagged owner/admission | 重点审查/整改中；interop-root 完整 package |
| observability | 11 / 3937 | closed schema、composition renderer、手动 gauge | 约束/接口筛查；metrics/tracing contracts |
| sniff | 1 / 267 | transport strictness、bounded parser seam | 约束/接口筛查；sniff contract |
| tun | 48 / 16981 | packet/stack/association → caller policy；live/hosted 选择 | 约束/平台边界筛查；hosted-safe lib + all-features check |
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

## 发现与批次

### R1 — P1：metrics 慢读端永久占用 admission（已修复）

- 位置：`crates/ferrum2-runtime/src/metrics.rs::serve_metrics_connection`；违反 runtime
  bounded metrics / resource ownership 契约。
- 触发：客户端完成请求后不读取响应，或 transport shutdown 始终 Pending；读头超时的
  408 写出同样可能挂起。16 个请求即可占满 endpoint，阻断后续监控采集。
- 已确认：旧实现两项 paused-time 故障测试失败，超过测试的 5 秒外部保护时间仍不结束。
  不是吞吐假设，也不依赖真实网卡。
- 修改：保留原 2 秒 header deadline，为所有状态、body 和 shutdown 增加总计 4 秒的
  request I/O deadline，返回红化 TimedOut 错误。同步 renderer 必须 bounded/nonblocking；
  Tokio timeout 不能抢占同步回调，此限制已写入公开契约。
- 验证：`cargo test -p ferrum2-runtime --locked` 通过；新增 response/shutdown 停滞和
  饱和后恢复 admission、完整 OwnerSnapshot 回基线测试。删除相关只比较常量的断言。
- 代价：读头耗时会消耗同一请求预算；极慢的合法 scrape 会断开，客户端可重试。

### R2 — P1：DNS TCP 子任务失败被吞掉（已修复）

- 位置：`crates/ferrum2-dns/src/proxy/loops.rs::tcp_loop`；违反所有任务 joined/reported
  及 required listener failure 契约。
- 触发与影响：请求 handler/observer panic，join 结果被忽略，故障不能传播到进程 root；
  accept 错误使用 `?` 返回，绕过显式 abort-and-join。
- 已确认：注入 observer panic 的 loopback 测试在旧实现超过 2 秒仍不报告失败。
- 修改：检查 JoinError，以封闭错误报告；取消和完成回收优先于新 accept；所有退出分支
  汇合到 abort-and-join。保持已有达到连接容量时拒绝新流的语义。
- 验证：新增公共 listener 故障测试检查 sibling owner 释放、resolver shutdown 和 TCP/UDP
  重绑；`cargo test -p ferrum2-dns --features __interop-test-root --locked` 和 package
  all-targets/all-features clippy `-D warnings` 均通过。
- 代价：内部 panic 将触发已有进程级故障处理；普通错误请求仍只结束自身连接。

### R3 — P1：Direct UDP 异常退出遗漏会话清理（已修复）

`runtime/src/udp/direct.rs::commit_session_with_resolver_arc` 在任务末尾调用 remove；panic
会跳过该语句，违反 exact ownership 和 generation removal 契约。注入 handler panic 后，
旧实现的 UDP owner 无法回到基线，已复现。共享 manager 下，一个 runtime 在任务首次
poll 前被 Drop，也不能依赖“最后一个 runtime 退出”的全局清理。影响是 session/queue
容量滞留，旧 handle 仍显得存活，可用容量无法及时恢复。

修复把 generation-bound session 放进已有 `DirectOwnerLifetime`；Drop 先 remove/publish
removal，再释放 task/socket accounting 与 owner permit。正常完成、panic、abort 共用同一
清理路径，无新公开接口、依赖或堆分配；每个 owner 多保留 manager handle 和 session ID。
现有 manager 的 generation 检查防止旧 owner 删除复用后的 slot。

验证：`cargo test -p ferrum2-runtime --locked` 及该包 all-targets/all-features clippy
`-D warnings` 通过。新增 panic 后 removal event / admission 恢复、未 poll 任务取消时
共享 runtime 继续工作，两项测试比较完整 OwnerSnapshot；现有 reset/queue/drain 测试保留。

### R4 — P1：RuleSet shutdown 取消丢失 join 所有权（已修复）

- 原位置 `ruleset/src/loader.rs::BlockingTaskOwner::shutdown`：`mem::take(tasks)` 后 await，
  shutdown 被取消会 Drop JoinHandle 并 detach worker；重试/并发 shutdown 可提前报成功。
  违反 scoped guide 的 blocking cache/compiler 必须 joined 契约。取消重试测试已在旧实现
  失败：worker 尚被 gate 阻塞，第二次 shutdown 就返回。
- `ruleset/src/blocking.rs` 现在独立拥有 admission、task handles、sticky failure 和 joins；
  使用异步 mutex 串行 join，await 期间句柄仍留在 owner 内，取消可重试。loader 只描述
  cache/download/compile 流程，不再同时实现阻塞工作调度。
- 每个 loader 最多两个阻塞操作及两个 retained handles；permit 移入 blocking closure，
  取消等待者不会提前释放容量；shutdown 关闭 admission。普通 materialization/refresh 本来
  顺序执行，公开并发调用现在受到背压。代价为异步 admission 和至多两个操作并行。
- package tests、loader/HTTPS tests、all-targets/all-features 严格 clippy 通过。新增取消
  shutdown 重试和取消 waiter 后容量保持测试；旧 panic/remaining-work 测试随 owner 迁移。
- 仍需限定：Rust 不能强制中断已经开始的 `spawn_blocking`；本改动保证保留并等待所有权，
  不保证损坏文件系统操作的绝对完成时限。调用方仍须调用 shutdown，不能仅 Drop loader。

### A2 — P2：Direct UDP 的 socket 与会话 owner 分离（已完成）

`runtime/src/udp/direct.rs` 同时拥有双栈 socket 创建/IPv4-mapped 地址归一化和 session
admission/relay/lifetime，超过约 800 行生产 owner 的导航阈值。将 socket trait、factory、
具体系统实现及归一化移至私有 `udp/socket.rs`，让该 owner 封装平台 socket 细节；direct
只消费协议中立 socket 契约。保留 curated re-export，不保留旧模块转发 shim，也不增加
公共接口或动态分发。代价是一个内部模块；原有 runtime 完整行为测试和严格 clippy 通过。
这是职责分离，不是性能优化；余下大模块仍按 A1 跟进。

### R5 — P2：主机测量启动失败丢失取证日志（已修复）

第一轮真实 Quick/EndToEnd A/B 在第 17 次（baseline，UDP 场景第 3 对）启动时等待服务端
`ferrum2_network_generation` 超时，只有 16/24 次完整记录，不能作为有效性能比较。
事务 `3daa2d9ce9f4` 清理 PASS、五类残留全零，`benchmark_succeeded=false`；失败运行保留在
`%TEMP%/ferrum2-remediation-performance-20260905T071858Z`，不可与重跑拼接。

原 `HostExecution.ps1::Start-Ferrum2ProductTrial` 抛错前未返回 runtime，外层 catch 无法导出
product logs，外层事务随后删除临时树。已经观察到 trial 017 目录没有日志；因此目前无法
判断原始就绪超时的根因，不能宣称是候选回归或已修复的启动错误。

新增私有 `HostProduct.ps1` 统一拥有产品启动、关闭和启动失败诊断；所有已启动产品在失败
退出前导出 stdout/stderr，导出失败保留原始错误并发出封闭 warning。网络变更和最终回收仍
属于原事务。`HostExecution.ps1` 从 1032 行降至 921 行，新 owner 134 行；不是创建第二个
runner。两个 PowerShell module、两个闭合 source bundle、qualification 源检查、performance
入口和 Python recipe 同步更新，没有旧路径 shim。

注入测试覆盖 client/server 两个失败点及诊断导出自身失败，比较完整导出文件内容，不启动
真实进程或网络。新的源 bundle 需要全新测量；旧 A/A 校准不能自动适用。
101 项 performance controller、55 项 CI controller、PowerShell source/plan 静态合同和
19 项 workspace policy 均通过。

### 后续审查项（不等于已确认故障）

| ID / 优先级 | 位置、事实或假设 | 下一步与验收 |
|---|---|---|
| A1 / P2 | runtime reset、observability metrics、TUN live owner 有约 800 行以上生产 owner；m4 windows_tun/workload 1021 行违反工具 1000 行要求 | 按实际职责拆分并保持 invariant/消费者；禁止纯行数搬移；UDP direct 已按 A2 处理 |
| P1 / P2 假设 | DNS cache 每次 insert 扫描 entries + FIFO，满缓存更新可能拉长持锁时间 | 先测不同容量、TTL/更新比例与并发；保持过期、FIFO、generation 和 telemetry 语义 |
| L1 / 已解决 | ruleset blocking admission、取消及重试 join | 见 R4；全 loader 网络下载并发仍由 composition 拥有 |
| L2 / P2 待审 | affine executor 的 unbounded event channel 是否有结构性上界 | 核对每 shard 发事件次数、thread join 和启动失败路径；不能仅凭 unbounded 命名判定失控 |
| O1 / P2 待审 | 部分 UDP task result 被丢弃，低基数故障定位覆盖待逐一映射 | 对照 binary observation 和现有指标，避免添加重复 schema 或泄漏 peer |

## 证据与未完成项

里程碑：`5438c615` 修复 R1；`f20ade19` 修复 R2；`6fc90a96` 修复 R3；`5d3e791c`
修复 R4；A2 独立提交包含 UDP socket 职责分离及本记录。
R1 饱和恢复测试开发时曾误把主动强制关闭计数当作零资源快照；已改为等待最后一个请求
自行超时回收后才停止监听，验证完整快照（包括强制关闭计数）回到基线，再跑完整 package。

修改前：`cargo fmt --all -- --check`、workspace all-targets/all-features clippy `-D warnings`、
runtime 完整 package 测试均通过。说明已有静态门禁没有证明本次故障边界正确。
新增 R1 两项测试和 R2 一项测试在旧实现失败；日志保留于 `target/remediation-*-red.log`。

性能：尚无本次 A/B 数据，不能宣称吞吐或尾延迟改善。现有 Windows Confirm/CPU 文档是
历史 A/A；Linux profile producer 的正式 raw evidence 限定 ubuntu-24.04，不能伪造 WSL 的
环境身份。当前 host 已提升权限，用户已授权专用 runner 的 acknowledgement；执行前仍须
确认 exact committed candidate、源 bundle、Wintun 和 transaction 前提。

仍未逐行覆盖所有 crate；表中“筛查”项的完整生产审查仍欠缺。最终必须补充每项实际执行
门禁、失败、未运行原因、测量工作负载及生产 SLO/耐久性/跨平台证据缺口。
