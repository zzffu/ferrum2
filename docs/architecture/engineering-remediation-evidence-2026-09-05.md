# Engineering remediation evidence — 2026-09-05

[当前整改记录](engineering-remediation-2026-09-05.md) 汇总当前行为。本文件保留各批次的复现、失败、撤回和测量历史；早期状态不是当前资格。

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
- 原始证据已复制到 Git 忽略的 `profiles/remediation-20260905T075656Z/`，含四次真实 host
  运行及检查日志。`manifest.json` 记录 316 个文件的长度和 SHA-256；manifest 自身 SHA-256
  为 `36a737fe8808a844ca6bb1b6d3b90406a7107e8c117d52fff042f21bf55daaee`。
  这是本机留存索引，不是新的测量器或验收策略。不提交 target、profiles 或测试凭据。

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
| ruleset | 9 / 2326 | 下载、blocking owner、原子快照、refresh | R4 已修复验证；其余下载/刷新路径仍为定向审查 |
| crypto | 11 / 1950 | typed keys、nonce、AEAD、entropy | 约束/接口筛查；vectors/entropy |
| shadowsocks | 18 / 4785 | TCP authenticate/replay/flow；UDP prepare/commit | 约束/调用链筛查；协议与 tokio adapter |
| socks5 | 1 / 574 | no-auth command、retained control、borrowed UDP codec | 约束/接口筛查；command/udp |
| net | 4 / 909 | immutable selection、256-entry interface cache、binder | 约束/接口筛查；network contracts |
| runtime | 28 / 9634 | metrics、supervisor、affine executor、UDP owner/queues、shutdown | R1/R3/R6/A2 已修复验证；其余路径仍需深入审查 |
| config | 25 / 8923 | prepare/finish、资源计划、验证边界 | 约束/依赖筛查；config/v2 contracts |
| dns | 26 / 7193 | proxy TCP/UDP、cache、tagged owner/admission | R2 已修复验证；cache 性能仍是假设 |
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
  request I/O deadline，返回脱敏 TimedOut 错误。同步 renderer 必须 bounded/nonblocking；
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
产品进程或触及主机网络。新的源 bundle 需要全新测量；旧 A/A 校准不能自动适用。
101 项 performance controller、55 项 CI controller、PowerShell source/plan 静态合同和
19 项 workspace policy 均通过。

### R6 — P1：持续补入的 Direct UDP 请求饿死应答（已修复）

位置 `runtime/src/udp/direct.rs::run_direct_session`。原代码用 `while pop(request)` 排空请求
后才轮询应答；4 条队列上限不能约束持续补入情况下的一轮发送量。注入 socket 让每次发送
都补入一个请求且应答始终 ready，旧实现直到 64 次发送后才处理应答，回归测试明确失败。
这确认了调度饥饿，但尚不能据此认定它就是前述真实分片故障或 TCP 负向信号的根因。

改为每发送一条请求就轮询一次应答，保留已接纳请求的有限排空，并显式消耗 Tokio cooperative
budget，让一直 ready 的适配器也给控制任务执行机会。发送有进展时继续非阻塞轮询队列，
不依赖 Notify 为每条报文保存通知；不改 queue depth、字节预算、协议 commit 或重传规则。
代价是每条请求更多一次调度/状态检查，真实吞吐和延迟需同条件复测。

新增四项行为测试：就绪应答不被持续补入请求饿死；合并通知仍排空无应答的请求批次；
一直 ready 的 I/O 允许另一任务取消；首次 poll 前关闭仍发送全部已接纳请求并回收全部 owner。
开发中最后一项检测到草稿只排空一条请求的回归，已修正，未将该草稿提交或用于性能测量。
Windows/WSL runtime 各 123 项、server 56 项、四个跨进程 UDP target 共 17 项通过（4 项按
平台约束 ignored），client all-features compile-only、workspace 严格 clippy、格式、文档
构建通过。首次 m0 命令误写了两个不存在的 target 名称，未执行测试；已使用实际
`udp_local_e2e`、`socks_udp_local_e2e`、`socks_udp_routing_e2e`、`socks_udp_lifecycle_e2e`
完整重跑。真实 host 测量和此前 TCP 退化信号继续定位，尚未给本批性能结论。

### 后续审查项（不等于已确认故障）

| ID / 优先级 | 位置、事实或假设 | 下一步与验收 |
|---|---|---|
| A1 / P2 | runtime reset、observability metrics、TUN live owner 有约 800 行以上生产 owner；m4 windows_tun/workload 1021 行违反工具 1000 行要求 | 按实际职责拆分并保持 invariant/消费者；禁止纯行数搬移；UDP direct 已按 A2 处理 |
| P1 / P2 假设 | DNS cache 每次 insert 扫描 entries + FIFO，满缓存更新可能拉长持锁时间 | 先测不同容量、TTL/更新比例与并发；保持过期、FIFO、generation 和 telemetry 语义 |
| L1 / 已解决 | ruleset blocking admission、取消及重试 join | 见 R4；全 loader 网络下载并发仍由 composition 拥有 |
| L2 / 已排除该假设 | affine executor 每个 shard 退出时恰好发送一次终止事件，通道由 shard 数结构性限界 | 不将 unbounded 命名误报为无限增长；长期调度/停顿性能仍需测量 |
| O1 / P2 待审 | 部分 UDP task result 被丢弃，低基数故障定位覆盖待逐一映射 | 对照 binary observation 和现有指标，避免添加重复 schema 或泄漏 peer |

## 证据与未完成项

里程碑：`5438c615` 修复 R1；`f20ade19` 修复 R2；`6fc90a96` 修复 R3；`5d3e791c`
修复 R4；`0f897381` 完成 A2；`25edd40a` 修复 R5。全部为本机独立提交，未推送。

修改前：`cargo fmt --all -- --check`、workspace all-targets/all-features clippy `-D warnings`、
runtime 完整 package 测试均通过。说明已有静态门禁没有证明本次故障边界正确。
新增 R1 两项测试和 R2 一项测试在旧实现失败；日志保留于 `target/remediation-*-red.log`。

### 首阶段已执行门禁

Rust 完整门禁绑定 `0f897381`；后续 `25edd40a` 仅改变 host 工具、对应 Python 测试和文档，
未改变 Rust 产品代码。后续工具门禁及真实 host 运行绑定 `25edd40a`。以下命令均从仓库根
目录执行，非零退出没有被当作成功。

| 命令 | 实际结果 |
|---|---|
| `cargo build --workspace --bins --locked` | PASS；MSVC 有生成 import lib 的 informational linker stdout warning |
| `cargo build -p ferrum2-shadowsocks --example udp_protocol_client --locked` | PASS |
| `cargo test --workspace --exclude ferrum2-client --exclude ferrum2-tun --exclude ferrum2-platform-windows --locked` | 666 passed，0 failed，5 按平台/工作流规则 ignored |
| `cargo test -p ferrum2-client --all-features --no-run --locked` | PASS，仅编译 |
| `cargo test -p ferrum2-runtime --locked` | 119 passed；包括本次五项 metrics/UDP 新故障测试 |
| `cargo test -p ferrum2-dns --features __interop-test-root --locked` | 71 passed |
| `cargo test -p ferrum2-ruleset --locked` | 25 passed |
| `cargo test -p ferrum2-tun --lib --no-default-features --features fuzzing --locked` | 126 passed |
| `cargo test -p ferrum2-platform-windows --lib --no-default-features --features fuzzing --locked` | 59 passed |
| `cargo check -p ferrum2-tun -p ferrum2-platform-windows --all-features --locked` | PASS |
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | PASS |
| `cargo run -p ferrum2-m4-qualification --bin m4-qualification --locked -- self-check` | PASS，56 mutations |
| `cargo doc --workspace --all-features --no-deps --locked` | PASS |
| `cargo test -p ferrum2-m0-harness --test workspace_policy --locked`（工具更新后） | 19 passed |
| `python -B -m unittest discover -s tests/performance_candidate -p 'test_*.py' -v` | 最终 101 passed |
| 同一 unittest 命令，目录 `tests/performance_rule` / `tests/ci` | 19 / 55 passed |
| `python -B -m unittest discover -s tests/platform -p 'test_qualify_native.py' -v` | 6 passed |
| `pwsh -NoProfile -File tests/platform/test_windows_tun_host_qualification.ps1` | PASS，最新 bundle；六个变更的 PowerShell 文件额外全部 ParseFile 通过 |

WSL Debian GNU，独立 `CARGO_TARGET_DIR=/home/zzffu/.cache/ferrum2-remediation-target`：

```text
cargo test -p ferrum2-runtime -p ferrum2-ruleset -p ferrum2-dns --features ferrum2-dns/__interop-test-root --locked
cargo check -p ferrum2-tun --features fuzzing --target x86_64-unknown-linux-gnu --locked
```

分别 215 passed / PASS。Windows target-specific release 构建和以下非特权 native contract
也通过，输出 `m3_local_native_contract status=PASS`：

```text
cargo build -p ferrum2-client -p ferrum2-server --bins --release --locked --target x86_64-pc-windows-msvc
python -X utf8 tests/platform/qualify_native.py --local-contract --profile windows-msvc --target x86_64-pc-windows-msvc --client target/x86_64-pc-windows-msvc/release/ferrum2-client.exe --server target/x86_64-pc-windows-msvc/release/ferrum2-server.exe
```

### 真实 Windows TUN 正确性

专用 runner 在已提升权限的 shell 中执行，显式传入用户已授权的
`-AcknowledgeHostNetworkMutation`。`0f897381` 为 QUALIFIED / 104.456 秒；更新共享工具后，
`25edd40a43dc7d4f9c8893a002a51be3ce36ddb0` 再次 QUALIFIED / 107.206 秒。两次八项检查全部
PASS，两次 adapter/route/address/process/port 残留均为 0。最新 qualification bundle 为
`b7c5729c4b2e01ca957e73a97966972b2c6f4425bb6a50f1e01d196c93636796`。
留存 `correctness-final/qualification.json` 的 SHA-256 为
`b944f4abf66341d59a5c1653970ee9b4d935a1deafcbb4316d7632dd252e9014`。

实际命令（两次替换各自完整 SHA 和新的外部 evidence 目录）：

```text
pwsh -NoProfile -File tests/platform/run_windows_tun_qualification_host.ps1 -CandidateSha <sha> -EvidenceDirectory <new-directory> -AcknowledgeHostNetworkMutation
```

### 性能实测：两次不完整运行，验收未通过

没有有效的完整 A/B 结论，不宣称性能提升。第一轮见 R5；第二轮绑定同一基线
`9bbcea22d0373ff60932f929d93d265c98c0a711` 和候选 `25edd40a...`，使用新的 performance bundle
`142262e4bac798ab69ffd11c59d753a7b2038d1547dbeb34a733f9eae8951912`。
两侧独立 release 构建，使用同一 harness / workload source，工具链、硬件和系统见本文开头。
无其他 Codex 编译、测试或 benchmark 与有效负载阶段并发执行；不声称控制了所有外部主机噪声。

```text
pwsh -NoProfile -File tools/windows-tun/performance/run_windows_tun_performance_host.ps1 -Mode Quick -Topology EndToEnd -BaselineSha 9bbcea22d0373ff60932f929d93d265c98c0a711 -CandidateSha 25edd40a43dc7d4f9c8893a002a51be3ce36ddb0 -EvidenceDirectory <new-directory> -AcknowledgeHostNetworkMutation
```

Quick 固定每场景三对，AB/BA/AB，预热 2 秒、active 10 秒，每次新建进程和 adapter：
TCP 单流 65,536 字节回显；TCP 延迟为单连接 1,024 字节往返；UDP 为单 association、
1,200 字节、batch=1；分片负载 1,440 字节、batch=4。延迟从请求发送前到完整回显验证完成，
包含期间重试/排队，不含连接建立和初次 admission。闭环发送不证明过载时开放负载排队 SLO。
现有 producer 只保留 p99，没有 p50/p95；不可从 p99 推算。CPU 的 100% 表示一个逻辑核。

第二轮 23/24 完成；trial 24（candidate，分片第 3 对）在预热阶段因重传预算耗尽失败。
错误定位到一个 missing ACK；server 有一次 `queue_full`，client 重组 completed=56469，
重组 limit/malformed/overlap/timeout 以及 ring-full drop 均为 0。已导出 workload stderr 和
client/server failure metrics；没有提高重传预算、扩大队列或替换失败试次。
`453c82f58a8c` 事务清理 PASS，五类残留全零，`benchmark_succeeded=false`。

独立 validator 实际退出 **2**：`unable to read Windows TUN trial 24`：

```text
python -B -m tools.performance_candidate windows-tun-validate-host-evidence --evidence-root <second-run-directory> --baseline-sha 9bbcea22d0373ff60932f929d93d265c98c0a711 --candidate-sha 25edd40a43dc7d4f9c8893a002a51be3ce36ddb0 --mode Quick --topology EndToEnd --policy tools/windows_tun_performance_policy.json
```

以下保留第二轮所有已完成的对应场景记录，**仅作诊断，不是通过验收的比较，也未合并首轮**。
值为中位数 [最小值, 最大值]；比较倍率为配对中位数 [范围]，大于 1 才是该指标改善。

| 场景 | baseline | candidate | 比较倍率 / 完整性 |
|---|---|---|---|
| TCP 单流，MB/s（10^6 B/s） | 129.166 [100.948, 132.679] | 122.005 [85.010, 130.566] | C/B=0.9196 [0.8421, 1.0108]，三对 |
| TCP 1 KiB p99，µs | 160.2 [159.6, 163.8] | 162.1 [160.9, 163.5] | B/C=0.9956 [0.9846, 1.0018]，三对 |
| UDP，packet/s | 9828 [9446, 10054] | 9467 [9145, 9971] | C/B=0.9917 [0.9305, 1.0022]，三对 |
| UDP p99，µs | 174.6 [170.9, 182.4] | 175.1 [170.9, 175.5] | 同上三对的附属观测 |
| 分片，MB/s | 41.053 [40.523, 41.127]，n=3 | 40.861 [40.845, 40.877]，n=2 | 第三对缺失，不计算比较倍率 |

| 场景 | client CPU%，B → C | server CPU%，B → C | client 峰值 MiB，B → C | server 峰值 MiB，B → C |
|---|---:|---:|---:|---:|
| TCP 单流 | 82.09 → 86.23 | 53.74 → 50.44 | 146.54 → 146.54 | 12.59 → 12.57 |
| TCP 1 KiB | 35.72 → 26.24 | 28.46 → 21.58 | 146.56 → 146.57 | 12.59 → 12.56 |
| UDP | 42.67 → 46.63 | 42.65 → 44.18 | 152.42 → 153.79 | 12.60 → 12.84 |

已完成试次的 client/server failure counter delta 都为 0；不能因此把包括失败试次的整体
错误率说成 0。每次的 checked_units、I/O completions、CPU 窗口、failure counters 和 payload
检查均在原始 trial.json 中。TCP 延迟场景完成事务数中位数从 65172 降至 45341，说明较稳定的
p99 不能掩盖工作量下降；更低的 CPU 百分比也不等于每单位工作成本降低。
TCP 吞吐存在退化信号，具体因果尚未证实，不能以“只是噪声”排除，也不把它归因于某一修复。

### 未完成项与下次直接入口

1. **P1，实测故障待归因**：保留第二轮 trial 024 的 stderr / failure metrics。
   `runtime/src/udp/limits.rs::UDP_SESSION_QUEUE_DEPTH` 固定为 4，workload fragment batch 也为 4；
   `server/src/run/udp/run_loop.rs` 在 reserve 失败时计数并拒绝，未提交协议 replay/activity。
   这是已确认的容量边界，不是已确认的根因。下一批应复现 ACK 延迟/重传与队列占用的交错，
   用现有 UDP diagnostic 和 injected socket seam 分清原始丢失点，再决定是否改调度/背压。
   不修改资源限制或减少有效工作量来通过测试。就绪超时的原始基线故障也仍未归因。
2. **P1，性能验收**：TCP 吞吐负向信号、延迟场景工作量下降和分片失败未消除。先定位，再
   使用同一测量契约完整重跑；不要追加试次补洞或重新定义阈值。新 bundle 还缺新 A/A 噪声
   校准及 Confirm/256-flow、p50/p95、开放负载/过载、长时资源斜率证据。
3. **P2，覆盖**：仍未逐行审查所有 crate；表中筛查项及 A1/P1/O1 后续项仍开放。R4 的
   并发 compiler admission 没有实际 RuleSet 刷新负载性能对比。本轮五个确认问题的修复和
   有限 host qualification 不能替代其余模块审查。
4. 未执行的五个 ordinary ignored 测试：一次完整 lifecycle qualification、三个 Linux
   IPv6-only UDP 用例、一个 Windows 会归一化地址的 127/8 wildcard 用例。没有将 ignored 算作
   通过。完整 Linux lifecycle 需先构建本机产品，再按 `lifecycle-stress.yml` 的 30 分钟外部
   bound 执行 `cargo test -p ferrum2-m0-harness --test lifecycle_cycles full_qualification_runs_twenty_cycles_per_category_and_at_least_100_per_binary --locked -- --ignored --exact --nocapture`。
   IPv6 专项命令见根指南 / m0 工作流，在有 IPv6 loopback 的 Linux release 环境执行。
5. 原生 GNU/musl 全 workspace 与 linkage、外部协议 interop provider、nightly sanitizer/fuzz
   一小时 campaign 以及 hosted identity 闭环未执行。它们需相应原生工具链、reviewed provider
   或专用 Linux CI；本机 WSL affected tests 不替代这些证据，也没有伪造 ubuntu-24.04 identity。
   客户端测试始终 compile-only；fuzz 按仓库约束只通过对应有界 Linux CI workflow。
6. 尚缺真实生产负载、连接分布、DNS/RuleSet 大小及 SLO。当前结论仅限本文 Windows/WSL 配置、
   注入故障及所列工作负载；**整个项目尚未达到经证据确认的生产可用状态**。

## 续行证据：R6 与测量完整性

`4e0fbd752ac14694bde0dd452e65257336c13c39` 为 R6 独立里程碑。该版本真实 Windows TUN
正确性资格为 QUALIFIED：八项 PASS，105.45419 秒，事务 `ae17b476df78` 五类残留全零。
证据目录 `%TEMP%/ferrum2-fairness-correctness-20260905T083540Z`。

同一提交两侧的 Quick / EndToEnd A/A，使用与前两轮相同的 performance bundle `142262e4...`、
预热 2 秒 / active 10 秒 / 三对 AB/BA/AB，共 **24/24 完整试次**。事务 `ee73bf8b8d12`，
执行 600.386 秒，总计 717.793 秒，产品 failure counter 增量为 0，清理 PASS / 五类全零。
证据目录 `%TEMP%/ferrum2-fairness-aa-20260905T083927Z`，独立 validator 返回结构有效的
**REGRESSION** 决策；runner 退出 0 只表示执行和清理完成，不能当作性能门禁通过。

| 同代码 A/A 场景 | 配对改善倍率，中位数 [最小, 最大] | 现有策略结果 |
|---|---|---|
| TCP 单流 | 0.9772 [0.9655, 1.0330] | regression |
| TCP 1 KiB p99 | 1.0079 [0.9993, 1.0280] | regression（还有 CPU/work guard） |
| UDP packet rate | 0.9804 [0.9010, 1.1043] | regression |
| 分片吞吐 | 0.9817 [0.9411, 0.9858] | within-noise-band |

同代码 UDP 倍率范围约 -9.9% 到 +10.4%，当前主机不能可靠区分 2% 量级的变化。
没有放宽策略，也没有据此消除此前真实 A/B 的负向信号。A/A 的完整成功只说明本轮未重现
启动/分片故障，不证明 R6 已消除其根因。继续原始 `9bbcea22...` 与 `4e0fbd75...` 的完整 A/B。

### Cache 写入测量准备

现有 rule qualification 只测 cache hit/miss，不能验证 insert 全表扫描假设。新增私有
`dns_cache` owner，承接已有缓存读场景并加入满容量 FIFO 写入与刷新；维持同一 CLI、
JSON schema、单一计时/分配 owner、所有旧场景和门禁。新场景仍使用既有 1 / 100 / 1000
规模，预建查询 identity、固定单调时间、60 秒 TTL，计时包含 lock/维护/淘汰；错误粘滞记录，
计时外核对完整答案、容量与 FIFO 淘汰。分配统计仍位于计时外。

当前只是测量器和 TTL/FIFO 行为测试准备，尚未修改 cache 生产算法，不能先声称性能瓶颈
或改善。读/写所有场景均需同条件前后测量；批量 ns/op 的 p99 不是逐请求尾延迟。

### R6 完整 A/B：功能完成，性能门禁仍拒绝

原始 `9bbcea22d0373ff60932f929d93d265c98c0a711` 对 `4e0fbd75...` 的 Quick / EndToEnd
已完成 24/24，事务 `4250fa981c44`，总计 724.181 秒、active 执行链 608.448 秒。
同样的 bundle / 工作负载 / 顺序；所有 trial 产品 failure counter 增量为 0，清理 PASS、
五类残留全零。原始证据 `%TEMP%/ferrum2-fairness-ab-20260905T085310Z`。
独立 validator 实际退出 **3 / REGRESSION**。四场景都未满足完整策略，不能把部分主指标
的正向差值当作通过。A/A 的 validator 同样为退出 3；当前策略保持不变。

| 场景 | baseline 中位数 [范围] | candidate 中位数 [范围] | 配对改善倍率 [范围] |
|---|---|---|---|
| TCP 单流 MB/s | 132.620 [129.869, 136.960] | 137.734 [129.112, 138.122] | 1.0056 [0.9736, 1.0636] |
| TCP 1 KiB p99 µs | 139.6 [139.1, 143.4] | 139.3 [136.3, 140.1] | 1.0205 [1.0022, 1.0236] |
| UDP packet/s | 9116 [8912, 10152] | 9574 [9439, 9690] | 1.0502 [0.9545, 1.0591] |
| 分片 MB/s | 42.011 [41.982, 43.683] | 39.954 [39.804, 40.666] | 0.9510 [0.9112, 0.9686] |

CPU 中位数 client/server：TCP 单流 72.13/46.38 → 67.07/45.58%；TCP 延迟
25.84/20.00 → 34.15/27.14%；UDP 45.63/41.28 → 46.69/43.26%；分片
78.28/78.69 → 80.26/76.37%。成功工作量、逐 trial working-set 与 CPU 窗口保留于原始数据；
CPU guard 按工作量归一化，不能直接比较这些百分比宣称效率改善。

分片三对均下降，是需要定位的持续负向信号；此前不完整 A/B 和本轮都保留。R6 修复了
已复现的饥饿契约，代价尚未被性能验收接受；继续调整同一调度问题，而非删除回归测试、
加大队列、提高重传预算或挑选成功场景。此前启动失败/丢 ACK 本轮未重现，仍未确认根因。

Cache 测量准备已验证：新增三项 TTL/FIFO 测试在原生产实现全部通过；rule 工具
all-targets/all-features check、compile-only test、DNS + 工具严格 clippy、19 项 Python
controller 测试通过。显式执行 release `--profile qualification --samples 31
--iterations-per-sample 256`，311 个场景的 correctness/allocation/parity 门禁均通过。
该 pilot 的缓存 FIFO 写入 p50 批量成本：1 / 100 / 1000 条为 193.51 / 3505.41 /
31680.00 ns/op；refresh 为 164.77 / 3192.50 / 29440.00 ns/op，读命中约 62–68 ns/op。
这是全表维护成本随容量增长的测量证据，仍不是网络 DNS 吞吐或逐请求 p99。
原始文件 `target/remediation-cache-baseline-pilot.json`，重复前后比较继续执行。

### P1（性能假设）验证与 cache 优化

`dns/src/cache.rs::DnsCacheState` 新增一个可能过期时间的下界；到期前省去 entries/FIFO
全量扫描，到期后在原过期删除过程中重算。删除不存在的 key 直接返回。删除/淘汰最早条目
可能留下偏早下界，最多产生一次额外扫描，不会延长 TTL。保留过期优先于 FIFO、刷新移动到
队尾、lookup 不刷新顺序、零 TTL 删除、qtype/generation 隔离、observer 在锁外调用。
无公共 API/依赖变化，无新每次操作分配；每个 cache 多一个 Option<Instant>。
任意中间 key 刷新/单 key 过期删除仍有 FIFO 线性成本，过期扫描仍为 O(n)，不声称所有写入
变成常数时间。工作负载当前是单线程非过期稳态，并未证明并发尾延迟或 TTL 突发成本。

DNS authoritative gate 74 项、严格 clippy 通过；release 候选 pilot 同参数 311 场景的
correctness/allocation/parity 均通过。1000 条 FIFO 写入 p50 为 160.46 ns/op，refresh
137.02 ns/op；两侧每次写入仍为 2 allocations，读命中没有相同比例变化。
先记录本批实现与 pilot；同条件重复和全部相关门禁继续执行，未给整个 DNS 服务生产资格。

### Cache 六对重复结果

基线 `3ad88718c7f3f6b22f89b1a8d201b8a7c272cfaa`、候选
`bd9f9fcb19d72796841eb88741f2104fc673a35c`，各自干净的独立 checkout 与固定 release
可执行文件。完整命令仍为 Rust producer `--profile qualification --samples 31
--iterations-per-sample 256 --workspace-root <对应快照> --output <每次独立 JSON>`；六对
AB/BA 交错，12/12 exit 0，全部 311 场景保留并通过现有 runner-report validator。
计时使用现有 5 批预热、自校准至至少 100 µs 的样本窗口；每次 31 样本，实际迭代数、
完整样本、分配和 fixture hash 在 raw JSON。没有把不同操作数的自校准批次误写成固定 QPS。
无并行编译、测试或其他 Codex benchmark；主机仍有未控制的其他用户进程。

| 单线程缓存容量/操作 | baseline p50 ns/op，中位数 [范围] | candidate，同单位 | 配对成本 B/C 中位数 [范围] |
|---|---|---|---|
| 1 / FIFO insert | 192.63 [191.72,193.54] | 161.79 [157.95,168.34] | 1.187 [1.144,1.223] |
| 100 / FIFO insert | 3469.74 [3455.26,3516.22] | 168.98 [163.84,175.82] | 20.662 [19.653,21.170] |
| 1000 / FIFO insert | 32020 [31660,32240] | 159.77 [157.77,162.40] | 200.117 [197.844,202.193] |
| 1000 / refresh | 29590 [29320,29820] | 139.99 [137.29,144.68] | 211.731 [204.312,216.181] |

1000 条读命中为 61.29 → 60.88 ns/op，未显示同级收益。写入每操作仍为 2 allocations，
没有靠减少输入检查、容量或工作量制造结果。完整 `cache-observations.json` 保留全部
12 个 cache 场景的 p50/p95/p99 批次观测与范围；这些分位数是批量 ns/op 的分布，不能充当
网络请求尾延迟。整个 311 场景进程的 CPU 时间 B 33.84–34.13 秒、C 33.83–34.13 秒，峰值
工作集 B 27.88–29.98 MiB、C 27.97–29.79 MiB；该整体 CPU 数字不归因于 cache 子场景。
原始资料及采集参数在 `target/remediation-cache/`。没有把本批观察包装为独立 reviewed
Rule controller calibration/adoption verdict；没有运行新的对外测量入口。

### p50/p95 测量契约补齐

Windows workload schema 4 / host trial schema 3 增加 TCP/UDP p50、p95 和 reservoir 样本数，
三种分位数来自同一批样本、同一 nearest-rank 算法，保留原 2,000,000 上限与成功工作量。
新的私有 `latency.rs` 统一采样与统计，`workload.rs` 从 1021 降至 989 行，解决 A1 中工具的
硬性体积偏差；没有移走无关业务或新增公共 API。控制器拒绝旧版本、缺失字段、分位数
乱序和样本计数不符；p99 策略、重试和负载配方不变，旧证据按对应提交读取。

102 项 Python performance controller、M4 严格 clippy、self-check 56 mutations、
PowerShell 非变更合同通过。M4 bundle `4febaee81d3e04463d622a8613181bc22b23b36dace7ab0a4c6223b8bedf6681`；
performance bundle `64231e1089363cea93d85fa78004f3b835cbdb99fabcb55d7f52c9bfcbde6e4f`；
qualification bundle `09b155f17e074f726686ff11e9099ac3e4050245f938c5ab19476e6e32204b52`。
这些是新测量身份，先前 24 次 A/A 和 A/B 没有被改成新 schema，也不自动变成新工具的资格。

### R7 — P2：乱序提交缩短 UDP idle deadline；复用会话 timer

`runtime/src/udp/{session,manager}.rs` 原先把捕获的 `now` 直接覆盖 last_activity；并发调用
先采样时间后竞争锁时，较早时间可能后提交。queued/immediate 公共 seam 的反序提交测试
在旧实现失败，deadline 被缩短 20 秒。三条 accepted activity 更新路径现在保持单调最大值，
不改协议 replay 提交时机或更新失败时的行为。

在这一不变量上，`run_direct_session` 保留一个已注册 idle timer，只在它到期时重新检查
会话 deadline 并 reset；此前每轮 I/O 都查询共享状态、构造/注册/丢弃 timer。R6 的一请求/
一次应答机会、cooperative budget、队列上限及关闭排空保持。资源代价为每会话持有原本就在
等待中的同一个 timer；省去逐报文管理 timer 的收益仍需同配方实测，尚未声称吞吐改善。

新增测试覆盖乱序 queued/immediate 提交、timer 注册后的 activity 延长与精确到期、最终
完整 owner 基线。旧 response-handler 后刷新/失败不刷新、持续补入公平性和首次 poll 前
关闭测试全部保留。Windows runtime 125 项、WSL runtime + DNS 199 项、runtime 严格 clippy
通过；完整 workspace、client compile-only 与新的 host 资格继续执行。

TUN `OwnerThread::reap` 在 await 前转移 native join 句柄的取消窗口仍是待验证审查项：
`process/shutdown.rs::abort_and_reap_remaining` 能在 watchdog 下取消该 future。尚未把静态
窗口当作已复现真实 adapter 残留；后续应通过不创建适配器的 gated native thread 验证。

R7 之后的完整 Windows 门禁已完成：workspace（按根命令排除 client/TUN/platform）
675 passed / 0 failed / 5 ignored；client all-features 仅编译；workspace bins build、
all-targets/all-features clippy `-D warnings`、workspace docs 全部通过。TUN safe lib
126 项、platform-windows safe lib 59 项及两个包 all-features check 通过。MSVC linker
仍只有生成 import lib 的 informational stdout warning，没有放宽 lint 或跳过失败测试。

### R7 timer 尝试的验收与撤回

`7e8ad6414e0a177f0d6f3b821ce86ad3a36561a6` 真实 TUN 八项资格再次 QUALIFIED，事务
`c3c9f3418631` 五类残留全零，证据 `%TEMP%/ferrum2-timer-correctness-20260905T093714Z`。
随后以 `3158694617c9d8ca29f4050f0911e02808299c41` 为基线、`7e8ad641...` 为候选进行
同一新版 harness 的 Quick/EndToEnd 三对比较，24/24 完成，事务 `b0cc0c079929` 产品
failure delta 全零且 cleanup PASS / 五类全零。证据 `%TEMP%/ferrum2-timer-ab-20260905T094207Z`，
独立 validator 退出 **3 / REGRESSION**。

配对改善倍率中位数 [范围]：TCP throughput 0.9301 [0.8624,1.0061]；TCP p99
1.0294 [1.0000,1.1689]；UDP packet rate 0.9770 [0.9107,1.0365]；分片 throughput
0.9883 [0.9577,1.0523]。无 confirmed timer 性能收益。TCP 路径未修改也出现较大负向差值，
不能据此指认 timer 为 TCP 根因；也不能用这个理由忽略 gate 失败。

因此撤回持久 idle timer 的性能尝试，恢复逐轮 timer 行为，保留已复现的 monotonic
activity 修复与全部新测试。没有撤回 R6 的公平性与资源限制，也没有挑选通过的试次。
p50/p95/p99 和 checked sample count 已有实际数据；这些记录仍完整保留，不能把候选
试验的结果归给撤回后的提交。接下来验证最终 TUN join 修复和当前候选的完整资格。

### R8 — P1：取消 TUN reap 时 native cleanup 脱离 owner（已修复，待 host 资格）

原 `tun/src/runtime.rs::OwnerThread::reap` 取走 native JoinHandle 后直接 await
spawn_blocking。取消 future 时，OwnerThread::Drop 已看不到句柄，root 可以在 native
cleanup 尚未完成时返回。gated 假线程测试已在旧实现失败；这证实 owner 契约破坏，
并不等于已经观测到真实 adapter 残留。生产 watchdog 可取消 root，因此不能只依赖 Tokio
Runtime 最后 Drop 时可能等待其 blocking pool。

新的私有 `runtime/thread.rs` 统一拥有 native owner 的 signal、async join 和 Drop。
PendingThreadJoin 在 await 期间保留 join 状态，互斥锁一直持有到 native join 完成；
取消方要么接手尚未开始的 join，要么等现有 worker 完成。Drop 在产品多线程 Tokio
runtime 上先 block_in_place 让出 worker。无新外部 API、trait、依赖、unsafe 或平台调用；
普通 Drop 和显式 reap 共享同一所有权规则。

代价是每次 reaping 的一个 Arc/Mutex，以及取消后仍等待 native cleanup 的关闭延迟。
不能强制终止卡住的 OS cleanup；本改动保证不提前丢掉所有权，不把该等待宣称为绝对
有界的 native 操作。专用 host runner 的外部时限和 recovery 仍须独立验证。

Windows safe lib 128 项、TUN all-features check / 严格 clippy 已通过。新测试覆盖
已开始的 join 和 blocking pool 已满、join worker 尚未执行的窗口；全部使用假 native
线程，未创建适配器或修改网络。旧正常退出、panic、启动回滚和清理失败用例保留。

R8 追加门禁：WSL 同一 safe lib 128 项通过；client all-features compile-only、
workspace all-targets/all-features 严格 clippy、workspace docs 再次通过。R7 timer
撤回后的 runtime 125 项通过。最终 Confirm 使用 `5b46b03e`（原始 9bb 产品代码，
只覆盖当前 M4 harness 的六个源/manifest 文件）作为基线；M4 bundle 与候选逐字节一致。
该 detached baseline 留在 `profiles/remediation-confirm-baseline`，只用于本机验证，未推送。

### 首次 Confirm 失败与 R9 取证整改

最终 Rust 候选 `d6c6fab81f39bdaac75f44a8fcabed93012721d1` 的真实 host 八项资格为 QUALIFIED，
来源 `%TEMP%/ferrum2-final-correctness-20260905T100230Z`，五类残留全零。
随后 baseline `5b46b03e053efc41c4023ed39853489c112e15af` 对 d6 的 Confirm/EndToEnd 在
trial 2 失败，仅 1/50 完整记录；不能作为比较。事务 `009b952f3519`，cleanup PASS、
benchmark_succeeded=false、五类残留全零。所有资料保留于
`%TEMP%/ferrum2-remediation-confirm-20260905T100513Z`。

workload stderr 是 TCP read 的 Windows 10054 reset。服务端累计每方向 2,938,503,168 字节，
relay_io=1、network_generation=2、network_reset started/succeeded 各 1；客户端 TUN
session_active=1、restart reset=0、foundation/reassembly/ring-full drop=0。不能依据
事后计数判定 network reset 与 RST 的因果/先后。泛用 readiness 超时同时用于 active-complete，
不能把错误文本直接称为预热失败；先前 commentary 的阶段判断已纠正。启动前 3 秒采样
DWM 约 101.27%（一个逻辑核），仅为环境背景，不是性能波动的归因证据。

**R9 / P2，HostExecution.ps1::Invoke-Ferrum2HostTrial**：确认失败时丢失 metrics-before
和已启动产品 stdout/stderr；计数是在 workload 之前采集，但文件直到成功才写，外层 catch
也只导出 workload 日志。工具错误无法区分 warmup-readiness 与 active-completion。
现在立即持久化两端 before metrics；失败导出闭合 phase 和所有产品日志；抽取已有
HostProduct 的私有共享 helper，让 startup 与 active failure 共享导出规则。导出异常
不再覆盖原始 workload 错误。没有延长 timeout、过滤网络通知、扩大队列或更改工作负载。

新注入测试覆盖两个阶段和导出自身失败；在不可变旧 owner 源上出现 3 项断言失败，
修复后通过。完整 performance controller 104 项、PowerShell 静态合同、workspace policy
19 项通过。performance bundle 为 `00bcf65a7a07becce520c41e83f2653a80aa3aa7fcddb1c9f6c94a4059278dce`；
qualification bundle 为 `2fbb37e4e0ff0aed8cf3d4fc3668869418a143dbc633309c95f1aff34237904b`。
M4 source bundle 和全部 Rust 产品代码不变；下一轮使用新的完整证据目录，不补洞拼接。

### R10 — P2：资格 probe 失败也需保存数据面状态

工具提交 `6a4e000f...` 的真实资格运行在 `qualification-probe-before-notification` 失败：
TCP connect timeout。其 Rust 产品代码与先前通过的 d6 相同，不能直接归为产品代码回归。
外层临时 stderr 路径已清理，但文件确实复制为 evidence 的 `supervisor.stderr.log`；
不是丢失全部 supervisor 日志。事务 `1e0a3cf5c5d7` cleanup PASS / 五类残留全零，
86.763 秒，未产生 qualification verdict。证据
`%TEMP%/ferrum2-current-correctness-20260905T103203Z` 保留失败，不能记 PASS。

`HostQualification.ps1::Invoke-Ferrum2HostQualificationChecks` 原 smoke probe 的 finally
直接关闭产品，未导出前后 metrics 和产品日志。现在在 probe 前保留两端 metrics，失败时
复用私有日志导出 helper 并捕获故障 metrics，再保留原始异常并执行原有 cleanup。外层错误
指向持久 evidence 目录，避免提示已删除的临时 stderr 路径。八项判定、deadline、网络动作
和产品源码均不变。新的 fully injected 平台测试检查两端前后数据、完整日志和两次 stop；
普通平台 Python suite 7 项通过，没有调用真实适配器/路由/WFP 操作。

### R10 更新后实际资格

候选 `8d3ecf7ec51fe2b7649136fcb92e9c91d2519175`，资格 source bundle `b105cdac8997609cac43f231bf29f8fa19fa10a3b61767914a3f0c84312a8dfc`，
八项检查全部 PASS / QUALIFIED，99.321093 秒，cleanup 五类全零。
证据 `C:\Users\ZZZ\AppData\Local\Temp\ferrum2-verified-correctness-20260905T104831Z`。此前 6a 的失败记录仍保留，不由这次成功覆盖。
第二轮 Confirm 的目录为 `C:\Users\ZZZ\AppData\Local\Temp\ferrum2-remediation-confirm2-20260905T105011Z`，
当前仍在运行，尚无最终 verdict。

### Confirm 等待期间的补充路径审查

以下是明确的代码边界核对，不是新的性能结论或全 crate 逐行覆盖：

- `socks5/src/lib.rs` 的借用 UDP decoder 在 materialize 前验证非空 ASCII、完整端口和长度，
  与 `core::DomainName/TargetAddr` 的实际协议契约一致；root-only 是协议允许值，不误报为
  panic。one-shot reply 消费 owner，流锁只覆盖单次 poll；client `run/socks/tcp_command.rs`
  的 accept_command 由 cancellation + 配置 handshake_timeout 包裹。不能把协议 crate
  没有自行创建 timer 误报为真实调用链无超时。
- `sniff/src/lib.rs` 全部 parser 路径：输入绝对上限、TCP DNS 长度、UDP 完整性、DNS
  Header 最小长度预检、TLS/HTTP 仅 TCP、HTTP 单一 Host/CONNECT 和 metadata redaction。
  该模块无 transport I/O 或任务。fragmentation/limit/ordering 行为由既有 sniff_contract
  在完整门禁内验证；未建立 sniffer 性能基线。
- `net/src/{model,resolver,capability}.rs`：256 个成功决策的 generation cache、旧 generation
  不回写、系统 catalog 查询位于 cache mutex 外、family/source/stable identity 校验，以及
  binder 不再查路由的契约。Snapshot 不包含所有目标路由细节，因此不能通过简单内容相等
  忽略全部系统 route notifications。尚无该同步平台查询的竞争/延迟实测。
- `crypto/src/{random,tcp/aead,tcp/nonce,udp/session,udp/aead}.rs`：entropy 重试有界、计数
  耗尽在操作前拒绝、成功才 commit、typed owner 和错误 redaction。TCP authentication
  失败的清理依赖已锁定 vendor `v2/tcp/mod.rs::decrypt_packet`，该实现确实 zeroizes
  supplied packet；没有误把 wrapper 未重复 zeroize 认作泄露，也没有修改 vendor。
  密码学 primitive 没有重新设计；已有 vector/entropy gates 不能替代独立密码分析。
- `config/src/{load,dependency,prepared/prepare/draft,prepared/resources,prepared/finish}.rs`：
  metadata 检查后仍 take(MAX+1) 防增长，source zeroizing、UTF-8/TOML 错误转 closed kinds；
  不保留原 parser 诊断；draft 将每个 outbound 与 endpoint/resolver 绑定，finish 消费
  prepared plan 并检查 materialized resources。依赖 cycle traversal 有显式 stack。
  已核对相关 TUN/DNS 数值上限；未声称读过全部 schema 组合或测过配置编译尾延迟。


### R11 — P1：客户端指标 family 元数据冲突

`bins/ferrum2-client/src/run/observation.rs::render_client_metrics` 在共享 registry 输出后
再次声明 `ferrum2_tun_tcp_flows_active` 的 HELP/TYPE，且帮助文本不同。实际 host metrics
中同名 HELP/TYPE 各有两条；即使 SOCKS-only，registry 也会声明基础 TUN family。
这违反 [OpenMetrics 1.0 的 family 唯一性与文本格式契约](https://prometheus.io/docs/specs/om/open_metrics_spec/)，
会使严格采集器拒绝整次 scrape；此前 qualification 的自有文本读取器不检查这项格式。

保留 observability registry 原有的无标签 foundation gauge，把客户端追加的 owner gauge
改为 `ferrum2_tun_tcp_flow_owners_active{role="client"}`，明确计数是 runtime 持有的 flow
owner。同步更新仓内调用测试，不保留冲突别名。新黑盒测试通过既有 m0 process/readiness
门面启动两端 SOCKS/SS loopback 产品，检查实际 HTTP body 的 metadata 唯一性、两种 gauge
和单一 EOF；回收子进程后才断言。普通测试不启用 TUN，不执行 client test binary。
验证：旧 debug 产品的 m0 测试在两项重复 metadata 上失败；重建两端后同一测试通过。
`cargo build -p ferrum2-client -p ferrum2-server --bins --locked`、client all-features
`--no-run`、client/m0 all-targets/all-features clippy `-D warnings`、fmt all check 均通过。
测试编写时先修正了 harness 的 path-module 引用及已有 spawn mutex 的使用；这两处属于
测试自身问题，不计为产品缺陷。性能测量发生于 R11 之前的不可变 8d 提交，不归给此修复。


### 第二轮 Confirm 的完整失败记录

`5b46b03e...` → `8d3ecf7e...`，run `adffe47ea2ce`，EndToEnd/Confirm，完成 46/50。
第 47 次是 candidate、256-flow fairness、第四对；`failure-phase.txt` 为 `product-startup`。
服务端 stderr 为 `error[startup.bind] process: unable to prepare required endpoint`；客户端
仅正常 TUN lifecycle 日志，尚未启动 workload。外层等待 server network_generation 超时。
runner exit 1；独立 `windows-tun-validate-host-evidence` exit 2，拒绝缺失 trial 47。

build 117.505 秒、execution 2202.645 秒、cleanup 6.142 秒、总计 2326.608 秒。
cleanup PASS / benchmark_succeeded=false，adapter/routes/addresses/processes/ports 全 0。
来源为前述 confirm2 evidence 目录，不补跑、拼接或将前四场景完整配对称为整轮通过。
端口通过先 bind/close 预检，server 直到 client TUN 就绪后才启动，存在 TOCTOU 窗口；
证据没有失败时的端点占用快照，无法确定是临时端口复用、其他进程竞争或其他 bind 原因。
这与首次 Confirm 的 active TCP reset 是不同故障，不能混为一个已确认根因。

### M1a — RTL-05：普通门禁不执行 Rule qualification 计时工作负载

基于统一设计 `1b40da27`。先将既有结构化 workflow contract 补全 scoped compile-only
要求，旧工作流在 `hosted_execution_mutations_fail_closed` 返回明确错误，exit 101；没有执行
Rule benchmark。之后 root AGENTS、m0 workflow 与 gate ledger 同步排除该包并加独立
`cargo test -p ferrum2-rule-qualification --no-run --locked`。新增六种工作流 mutation，
覆盖误纳入 workspace、直接执行、遗漏、条件跳过、压制失败及 shell wrapper。

实际 Windows/MSVC/Rust1.97.1 检查：

- `cargo test -p ferrum2-m0-harness --test workspace_policy --locked`：20通过。
- `cargo test -p ferrum2-m0-harness --locked`：93通过、0失败、5个已有ignored；不含真实TUN。
- `cargo test -p ferrum2-rule-qualification --no-run --locked`：两个test executable编译通过，未执行。
- `cargo clippy -p ferrum2-m0-harness --all-targets --all-features --locked -- -D warnings`、
  `cargo fmt --all -- --check`通过。
- `python -B -m unittest discover -s tests/ci -p 'test_*.py' -v`：55通过；输出中的拒绝诊断属于预期negative cases。

日志在 `target/remediation-rule-compile-only-{red,green,m0,build,clippy,ci}.log`。
5个ignored的provider/lifecycle/Linux IPv6条件未在本批执行，未改为通过；客户端test binary
未执行。root指南仅修正命令与说明以遵守既有作用域规则，未放宽测试/平台/lint契约。

### M1b — CT-01 / HT1：CPU/work 使用实际测量窗口

Windows producer 以 `cpu_sample_seconds` 将 CPU delta 化为百分比，旧 PS/Python reducer
却只比较 percent/work，丢失窗口因子。改为每个 trial 先恢复 CPU seconds，再按 checked
units 做 pair ratio。保留现有2% guard、median/majority、零CPU处理及primary direction；
未改性能阈值或原始schema。公开指南同步公式，并修正已过时的raw trial版本说明。

新增 `test_windows_tun_cpu_window.py` 用完整PS `New-Ferrum2HostSummary` 和Python
host evidence validator，覆盖ClientDirect/client、EndToEnd/client/server × 相同/增加真实成本
× 两种实现，遍历Quick含lower-is-better场景。使用合法10/20秒窗口、candidate双倍checked
work的合成证据，不运行工作负载。旧实现有6个PS不符、6个Python判定不符；新实现2项测试
全部组合通过，完整summary对象一致。另有既有host evidence9、source capture8通过。

root整合检查：`python -B -m unittest discover -s tests/performance_candidate -p 'test_*.py' -v`
115通过（同时覆盖下一批IO修复）；CLI/summary import通过；PS parser通过；
`pwsh -NoProfile -File tests/platform/test_windows_tun_host_qualification.ps1`通过，nonmutating。
该资格bundle仍为 `b105cdac...`，未把PS静态检查写作真实host资格。
日志 `target/remediation-audit/ct01-*.log`、`target/remediation-m1-candidate-full.log`、
`target/remediation-m1-powershell-contract.log`。

仅performance bundle的HostProfiles行更新：21940 bytes，SHA-256
`7ee17c346631df87216a5b045bb46a3972e6cefae26dfe3db70952291b7ac52e`；完整bundle为
`33182ceee547176d35020b775a84401da55abad87e50a0b0674a1f2eac0f7776`。
没有新性能测量；旧bundle结果不升级为当前验收。marker窗口偏差、host清理读回等其余M1问题仍待修复。

### M1c — CT-03/04/06：读取、身份和输出的文件所有权

Linux `_read_trial` 复用共享 bounded closed JSON reader，一次读出解析值、原始bytes的
SHA-256和内容字节数；summary不再重新打开文件计算digest。单行、UTF-8、重复键、
nonfinite及各场景byte cap保留。共享reader只多存一个长度，不让所有调用者保留raw buffer。
即使stat后文件增长，read最多达到outer cap+probe；普通行仍按原16KiB限界。

发现 `islice(Path.glob(...))` 仍会由本机Python3.11 pathlib先构建全部目录项，review后改为
`with os.scandir`逐项处理，按host原有大小写匹配保留至计划文件数+1即拒绝并关闭迭代器。
匹配列表内存有界；不声称含大量非证据文件的目录扫描具有固定墙钟时限。
输出临时路径在创建后、write前登记，write/flush/fsync/replace失败都保留原目的文件并清临时文件。

新增 `test_linux_evidence_io.py` 与 `test_output.py`：紧凑输入/注入I/O，覆盖增长文件、
同读哈希（validation后文件被更换）、准确行与byte边界、首个超额提前关闭枚举器、平台
大小写、输出各阶段失败与成功。初始5项有5 failures/1个新接口error；额外数量及惰性枚举
测试各在旧实现失败。最终相关64项通过；root整合full candidate115通过，包含更新后的scale
直接caller。日志 `target/remediation-ct-io-{red,green,count-red,enumeration-red,regression}.log`
和 `target/remediation-m1-candidate-full.log`。未更改schema、source bundle或性能policy。

### M1d — RTL-01/02：Rule证据从原始观测重算并绑定工作负载

将报告验证从bounded subprocess owner移入私有`validated_report.py`；一个返回对象携带
完整报告、scenario suites和workload SHA，删除仅比较id→suite的旧入口，迁移CLI及calibration
读取调用方。验证实际duration/operations→ns/op、nearest-rank p50/p99、DNS QPS、五个单操作
allocation region、compiled bytes/entry、配对关系与适用parity/allocation gates。
数学容差为普通f64计算的8 ULP，不使用性能阈值容忍矛盾数据。

workload包含fixture bytes/hash、报告配置、policy、可用environment和输入scenario元数据，
12份报告及hash-bound calibration source必须一致。无需新schema字段：现有v6/v2已保留完整
source reports，由这些已绑定bytes重建identity。engine的`rule_program_mode`是实现输出，
review后移出跨版本identity并删除controller的64条索引阈值硬编码；保留闭合合法值和观测。
Rust Route场景ID仍含模式名，未来改阈值须先协调稳定输入ID，不能私下归一化现有场景。

离线red为4项测试14种原本未拒绝的矛盾；mode review另有3个red subcase，均修正。
`python -B -m unittest discover -s tests/performance_rule -p 'test_*.py' -v`最终37通过；
20个Python模块AST解析、差异检查通过。仅修紧凑synthetic fixture内部数学/status矛盾，
未改共享协议向量或外部release archives。日志`target/remediation-audit/rtl12-*.log`及
`target/remediation-rtl12-root-green.log`。

root另只读校验已有cache实验12份报告，每份311场景，全部通过，无新runner调用/benchmark，
结果`target/remediation-rtl12-retained-validation.json`；这是parser/math回验，不是adoption或
校准批准。mode排除前的共同workload digest只属于当时validator版本，不作为当前身份常量。
仍缺：完整calibration启动前验证（RTL-03）、CLI请求与报告配置的显式关联、闭合错误输出、
run-wide证据预算、异目录calibration引用（RTL-06/07/08）。生产者未提供CPU model时比较的
是None，不能声称已补采真实硬件身份；合成build证据归属RTL-04仍需后续Rust修正。

### M1e — M4-01/02：资格工具部分启动失败仍完整回收线程

`resource_sampling::establish_sessions` 在spawn失败时先drop结果receiver，再join，避免等待
阻塞在已无人消费的有界结果队列上的worker；primary与cleanup错误同时保留。
`ProfileDnsResponder` 在下一次clone/configure/spawn前已拥有所有已启动线程，任何setup错误
通过同一个finish；finish保存首错但遍历所有join，成功仍核对完整observed计数。
只抽取两个具体的worker setup seam，未新增通用executor或变更网络/测量路径。

5个有限进程内线程/通道测试覆盖满队列取消、setup三类错误、worker错误/panic/计数溢出
后仍等待后续线程、成功计数及不一致报告。测试内用有限deadline保证脚本工作能够结束，
不打开socket，不调用产品或计时负载。没有旧源动态red运行，不把静态等待环写成已实测挂死。

- `cargo test -p ferrum2-m4-qualification --bin m4-qualification --locked worker_lifetime -- --test-threads=1`：5通过；root独立重复同一命令通过。
- `cargo run -p ferrum2-m4-qualification --bin m4-qualification --locked -- self-check`：PASS，56 mutations。
- M4 all-targets/all-features clippy `-D warnings`、fmt check及M4 bundle exact-source单测试通过。
  首次clippy指出测试module位置，移至各文件末尾后通过；root MSVC test link输出创建lib/exp
  的`linker_messages` warning，5项测试仍通过，未抑制lint。
- root将同一safe filter加入M4/root指南和m0 self-check step，防`test=false`令新契约在CI中
  没有执行；workspace policy20再验通过。普通Rule/client的compile-only规则保持。

日志`target/remediation-m4-workers/{validation.txt,root-tests.log,workspace-policy.log}`。
M4 closed bundle更新两份源码行，完整digest
`4f0782957b29718a827c9b5f7c045ecd26b65aafa02315a26953dca6ff9242a5`。
此源码身份下尚未运行真实host/性能测量；其他M4计量/探测边界仍待后续批次。

### M1f — CT-02 / CW-01：完整矩阵重建与最终工作流结果

aggregate要求四个canonical group目录，各自带plan、summary及完整AB raw trials。复用
`validate_plan`和`summarize_evidence`重建全部schema、scenario closure、数值/状态/identity，
以canonical typed JSON比较，跨组完整build与environment必须一致。删除summary-only输入。
aggregate schema2记录producing job结果、common identities、同读plan digest和raw manifest
digest。新增`--producer-result`来自workflow `needs.paired-profile.result`，复用唯一typed
`tools.ci.required_gate` owner；非success及未知值输出INVALID，不能接受先前上传的成功摘要。

workflow改为stage raw → 完整cleanup → 仅profile/stage/cleanup均成功时summary → always
upload，失败raw仍可保留。full aggregate额外看包括upload结果在内的producer job终态。
同批补齐此workflow里另一处普通workspace Rule qualification遗漏：exclude并单独no-run，
与M1a的root/m0规则一致。新增CI依赖源码及initializer纳入Linux controller source identity。

6种原本错误接受的summary mutation先red；相关78项及plan scalar5项通过。root第一次
共享工作树整合123项有1项失败：下一批M4新增measurement.rs尚未登记bundle，校验器正确
拒绝半批源码。没有跳过该项。随后以`25bdc735`建独立worktree
`target/remediation-m1-integration-20260905`，复制27个已完成CT/HT文件；逐项哈希记录在
`target/remediation-m1-integration-files.json`，完成后与主工作树核对无变化。

该独立快照full candidate123项全部通过（33.958s），包括M4完整source-bundle检查；PS
nonmutating qualification contract通过。主工作树CI Python56项通过。
日志`target/remediation-ct02-*.log`、`target/remediation-ct02-cw01-*.log`、
`target/remediation-m1-{evidence-full,isolated-candidate,isolated-ps,aggregate-ci}.log`。
这些是offline/parser/流程契约证据，未执行GitHub workflow、benchmark或host网络操作。
完整矩阵重建增加有限raw文件读取/归约成本；阈值与A/A校准规则不变，新source identity须重新取基线。

### M1g — HT2/HT3：清理证明及 supervisor 最终证据

共享私有 `HostCleanup.ps1` 保留历史 expected identities，独立枚举五类资源并归约残留；
读取失败、PID身份替换、GUID或名称仍占用均不能输出零。recovery schema 2 在产品启动前
记录最多4096个唯一有效adapter GUID；未完成创建计划只有在最终无新GUID且名称无冲突时
才能收尾，避免创建前取消永久卡住。未知新GUID只阻止成功，绝不授权删除。已有created
身份仍用GUID和名称检查。baseline是有界保留数据，不宣称Windows cmdlet枚举本身有硬内存上限。

`SupervisorEvidence.ps1` 统一四份worker/recovery日志和phase/primary/cleanup/timeout/exit
数据的保留。最终发布移到close、导出、临时目录删除之后，900秒涵盖这些步骤。删除前验证
TEMP直属目录、严格随机名称、非reparse目录、证据目录不在其下；失败保留证据与原错误。
正确性与性能仅共享身份/回收原语，不共享runner或verdict。

普通验证只执行注入inventory和实际supervisor AST的finally/tail，替换process group与删除
操作；覆盖历史账本退休、读取失败、各类残留、GUID改名/替换、创建前取消、未知新GUID、
close/export/remove失败与超时，均不运行worker try或任何真实host查询/变更。
最终隔离快照full candidate 123项通过（30.940s），主树PS nonmutating资格contract通过；
PS parser、两source bundle重建及diff检查通过。日志 `target/remediation-ht23-final-candidate.log`、
`target/remediation-ht23-root-static.log` 和 `target/remediation-audit/ht*-*.log`。
一次root同步使用了错误工作目录，复制失败后的旧快照测试不作为最终证据；修正绝对路径
更新27文件manifest后完整重跑，未跳过失败。manifest仍在 `target/remediation-m1-integration-files.json`。

本批performance bundle `ce0b52d0ca851f0ffd698fa4c0c1d81dcb0b729771cbe9d6915775f988172c23`；
qualification bundle `dc6349c9a6cd6d40c6f933f5fa710b05c361ec01173b40473cbea4595bb58d95`。
增加一次启动前adapter枚举及最终五类状态读取的成本，尚无live测量；实际cmdlet空枚举、
真实回收、900秒完成仍需专用host runner验证，旧五零报告不升级为新readback证据。

自动审批另拒绝过一次包含静态文件重写的Python shell命令，工具仅给出 `blocked by policy`，
未指出具体内容。没有重试该命令；改用专用apply_patch完成静态编辑，不执行文本里的host
命令。完整范围见 `target/remediation-audit/ht2-ht3-execution-notes.md`；这与先前两组动态
审查agent turn被内容审查阻止是不同事件，后两组仍未执行或绕行。

### M1h — RTL-03/07/08：先验证校准，统一证据预算

`ReviewedCalibration` 在任何A/B runner启动前完成hash-bound source、raw数学、派生策略、
runner身份、完整argv、execution policy和scenario catalog验证，并给每份新报告提供同一
workload identity。私有 `RunnerRequest` 对应当前Rust CLI的六种测量参数、两个profile及
完整报告configuration；拒绝重复、未知/缩写参数和越界数值。紧凑fixture原先写501 samples
却报告5，现同步请求5 samples/10 base iterations/真实Smoke Route scales，不削弱validator。

私有 `output.py` 统一reader/capture/emitter的64MiB编码预算。每份报告连同外层metadata、
trace和catalog先计费再保留；超限输出INVALID并保留此前已接纳raw，完整summary额外超限
也保留全部raw。半pair只能是失败证据，不能review成calibration。该预算不是RSS保证，
多次精确编码检查增加有限controller CPU成本。review输出必须与source同resolved目录、
不能覆盖source；不隐式复制、不保留旧接口。

输出先精确量算再原子替换。root复核另发现继承的fdopen失败泄漏：现在raw fd包装成功后
转交stream，包装失败仍关闭；write/flush/fsync/close失败不替换原目标。primary与cleanup
分别保留，temp清理失败不掩盖原错误。普通注入测试先在旧实现复现Windows unlink遮蔽
fdopen错误、cleanup遮蔽replace错误；修后fstat证明fd关闭、目标bytes不变、临时文件无残留。

`python -B -m unittest discover -s tests/performance_rule -p 'test_*.py' -v` 最终51通过，
root独立复跑51通过（0.931s）；AST/import/diff检查通过。日志
`target/remediation-audit/rtl378-{red,green,output-red,output-green}.log`、
`target/remediation-rtl378-final-root.log`。新controller README已链接两个文档入口。
所有runner均mock，未运行Rust test binary、benchmark、A/A/A/B或批准校准。
RTL-04独立SRS build evidence与RTL-06闭合诊断仍是后续项，运行时git/rustc不等于build
provenance的审查观察也未被本批解决。schema v6/calibration v2保持，修正既有契约执行。

### M1i — RTL-04：synthetic SRS 构建证据归属

`match_set/srs.rs` 的私有 `SyntheticSrsReference` 将独立构造的snapshot owner与BuildEvidence
同存；generated `synthetic_srs` 行用它的build时间、分配、重分配和内存字段，不再丢弃后
用binary decode + timing wrapper冒名替换。独立构造的正确性对照贯穿全部probe；性能计时
仍由另一个timing owner共享binary compiled matcher，并保留ptr::eq检查以控制layout噪声。
唯一调用方同步，helper公开范围缩小。真实仓内SRS无独立generated输入，保留并明确它的
decode+wrapper构建语义；README逐列说明。未改schema、Python或历史归档数值。

Windows Rust1.97.1下 `cargo check -p ferrum2-rule-qualification --all-targets --all-features --locked`、
`cargo test -p ferrum2-rule-qualification --no-run --locked`、该包all-targets/all-features
clippy `-D warnings` 及fmt check均通过。初次fmt一处换行不符，修正后通过；未运行任何
Rule test binary或benchmark，未添加冻结代码形状的测试。命令/exit/toolchain详见
`target/remediation-audit/rtl04-validation.md`；原输出在agent工具记录，没有伪称独立log文件。
这是静态归属修正与编译验证，后续显式qualification仍须检查实际输出；没有性能改善结论。
运行时repository/rustc与真实build provenance不一致的独立观察保持未解决。

### M1j — M4-06/07：准入窗口、完整尾部与数值证据

Windows五个性能场景用私有ActiveWorkWindow停止截止后的新准入，完整验证最后已准入的
transaction/batch并保留计数、延迟和完成耗时；最低64MiB/1024请求/4096 datagrams/256非零
flow要求保持，缺样失败，不延长准入凑数。fairness全部worker完成最后预热回复、报告并
释放sender后才发布统一active start；失败关闭consumer/cancel并join全部worker。原有额外
轮询只是tool协调实现，本批没有把它误记为产品热点或性能优化。

raw workload schema5 / host trial4同批迁移；新增actual elapsed和tail checked units，计量
单位随各场景为bytes、transaction或unique datagrams。PS/Python校验uint64、原minimum、
payload/batch/I/O、tail上限及窗口关系，并从checked/elapsed重算所有可推导throughput/rate。
首次review补齐原遗漏的tcp-single-flow；warmup总bytes仅作总量、不进入active分子。
CPU时长>=actual elapsed只是必要一致性条件，不证明端点完全对齐；顺序读client/server
及marker观察的采集偏差仍明确记录。没有原始latency reservoir/per-flow计数，摘要无法
独立重建quantiles/Jain，不把该限制隐藏成已验真。

performance-only `HostTrial.ps1` 拥有trial执行和数值验证，原共享HostExecution仅保留执行
原语；qualification不导入HostTrial或性能策略。正负向fixtures同步真实数学，CPU/work
比较因果保持，未调threshold。bundle和recipe完整刷新，不支持旧schema兼容读取。

独立worktree `target/remediation-profile-files-20260905` 实际用于本批window快照，基于
`014c7e18`，22文件清单/hash在 `target/remediation-m4-window/{owned-paths.txt,snapshot.json}`。
它不含下一批主树deadline I/O半成品、HT4 red测试或CPU工具实现；文档只保留window段。
第一次fullcandidate126有3个故障场景失败：旧trial测试漏加载新HostTrial；补齐加载，原
断言未改，最终126全过（40.903s）。自定义target-dir令self-check现有路径契约拒绝，改回
默认隔离target后PASS（56 mutations及新增内存窗口/预热checks），没有放宽路径规则。
主树曾因并行deadline模块未完成编译失败，也不作本批通过证据。隔离strict M4 all-targets/
all-features clippy `-D warnings`、fmt all、PS nonmutating资格contract通过。

日志 `target/remediation-m4-window/root-isolated-{candidate,candidate-final,self-check,self-check-final,clippy,fmt,ps}.log`；
agent针对性检查见同目录validation.txt。MSVC链接创建lib/exp提示仍存在，无lint抑制。
本批M4 bundle `e07950bedd00f0ce3bb416da8df21aa44ad39e38609fcbe7d92f604530717d55`；
performance `c6e802e73baa97e49ff16c964cef17b4affe1bd874c5d6369523a277dec08c0c`；
qualification `c5c6163efdb5397d9168c3702f2c40dc4f756ba34abb935235e9e464c9763191`。
未执行真实workload/adapter/benchmark/profiler；新增少量计时/计数和预热同步的成本尚未测量。
旧基线不可直接与新分母比较，两成员必须用同版harness重采。

### M1k — RTL-06：闭合诊断与失败清理

Rule controller以固定Stage/Category代替原异常、路径、argv和runner stderr回显；正常help
保持，非法argv与非.json输出在启动runner前拒绝。失败时继续保留已接纳raw的v6 partial，
有--output则同目录写content-addressed failure.v1，绑定request/runner/pair/order/role和
已写partial hash，复用唯一atomic文件owner。额外诊断只有有界前缀bytes/SHA/truncated、
合法exit/errno和闭合secondary，不保存原文或Base64；无output不另写文件。代价是不能从
失败artifact恢复外部原始错误内容。前缀hash不冒充完整未读输出的hash。

root复核补齐child/reader事务：Thread构造/start、执行wait与失败路径均有owner；kill后
wait及全部reader join共用5秒清理deadline，所有wait带剩余timeout。kill/reap/join失败
保留primary并附cleanup_unconfirmed；只读取确认结束的reader发布的immutable bytes。
Python不能强停继承pipe的reader，未结束就明确unconfirmed，不声称reap或生产可恢复。
自有output cleanup group在有/无primary时都保持output阶段；只识别自有marker，不递归
转发外部异常链。KeyboardInterrupt/SystemExit保持原退出语义。

旧cli内存加载的synthetic sentinel红测证明直接泄漏；旧capture owner的四个有限mock
红测以keyword-only wait立即拒绝无参wait，不实际挂死。修后覆盖第二reader启动失败、
kill失败、重复wait timeout、未结束join、atomic primary/cleanup、多异常组、路径错误及
失败证据写入失败。终端和全部新产物逐byte检索明文与Base64 sentinel均无泄漏。
最终 `python -B -m unittest discover -s tests/performance_rule -p 'test_*.py' -v` 66通过；
root独立复跑66通过（0.984s），diff检查通过。日志 `target/remediation-audit/rtl6-*.log`、
`target/remediation-rtl6-final-root.log`；实现/限制在同目录rtl6-implementation.md。
生命周期新case仅fake child/thread和内存stream，不执行真实runner、产品或benchmark；
本批未改变v6/v2校准或性能阈值，未补真实build provenance。

### M1l — HT4：保留所有失败标签观察

`Get-Ferrum2FailureCounterTotal` 迁入performance-only HostTrial，HTTP metrics获取仍为shared
原语。保留原name matcher和两项已声明TUN reason豁免，同时闭合校验reset、full rebuild、
RuleSet load/refresh、DNS resolve、strict-route install、outbound-interface resolve、UDP
association route八类result family的完整keys/合法值；缺失、重复或未知label拒绝证据。
每sample最多计一次，started/succeeded和association正常reset回收不计失败；UDP route的
stale_generation按未成功工作保守计入。不同family仍可能记录同一根因，不称独立事故数
或错误率，也不新增吞掉drop的环境豁免。

初始focused7 tests有5项red；新增future failure-name case证明未收窄原matcher，最终8绿。
主树fullcandidate134有1项失败：并行M4 profile_files未登记完整source bundle。随后以
当时HEAD archive构造 `target/remediation-audit/ht4-head-snapshot`，仅覆盖两PS、两bundle和
新test，完整134通过（34.622s）。五个文件与当前源码逐字节hash核对一致，archive保留。
PS parser、module exports、两完整source closures、nonmutating资格contract和diff检查通过。
证据 `target/remediation-audit/ht4-{metrics-red,metrics-green,candidate-full,isolated-candidate-full,powershell-parser,qualification-static}.log`，
范围/逐family来源在ht4-metric-contract.md。未执行产品、live host或benchmark。

performance bundle `b6c2d5d94b941c8969ba6f576852f6c9b374bab05c99cac8ceae231c4256d165`；
qualification `dcbcbe9686b4c4ac63679dbdbfd6fa370bb7c6c4933dc0b38ea8faaada87531f`。
新增解析在测量前后执行，不在包转发路径；成本尚未测量，新failure guard可能使此前漏计
的异常run拒绝，不能用旧零delta报告替代新baseline。

### M1m — CPU helper 执行边界，完整采样资格后置

保留唯一 `tools/profile-cpu.sh` attach入口和六参数，私有Python process/evidence/record
owner集中所有helper的POSIX session、selectors双pipe上限、INT/KILL/reap与deadline。
waitid(WNOWAIT)在最后group signal前保留leader身份；primary触发和cleanup状态分开，
不可读/proc或未确认退出拒绝成功。不signal Ferrum/M4 target，不改perf权限或安装工具。
原无界Rust fake-tool测试迁到既有tests/ci发现体系，不新建测试系统。

旧无schema metadata.txt删除，改schema1 metadata.json。正常exit0仅COLLECTED/unverified，
analysis_qualified/adoption_claim均false；失败invalid。仅观察PID/start/exe hash/ELF build ID，
controller checkout不是binary build证明。保留缺build/workload/window/final-result及counter/
sample/loss/symbol schema的明确原因；没有猜测Samply schema。gzip/JSON解析有32MiB压缩/
128MiB解压上限，helper双流各64KiB，均不是硬文件配额/RSS或CPU采样质量保证。
以后真正profiling分析仍需补M4绑定和reviewed采样格式，但不再阻塞产品架构实施。

root复核补了fdopen失败原fd关闭；输出路径在mkdir/chmod前验证，以持有的Linux目录fd和
O_NOFOLLOW逐级检查；非法路径、相对dangling link、外部redirect不能制造前置副作用。
root内absolute output保持可用。新目录0700、文件0600；实际采样环境须支持这些权限。

WSL Debian最终专项24/24、完整tests/ci80/80通过，无skip；测试仅finite fake helpers及
注入collector。早期Windows17项有7个Linux-only skip如实保留，未用skip冒充执行。
bash -n及scope diff检查通过。root按M0指南先locked build两产品bins，再完整
`cargo test -p ferrum2-m0-harness --locked`：93 passed/0 failed/5原ignored；m0 all-targets/
all-features clippy `-D warnings`通过。产品client test binary未运行。
日志 `target/remediation-cpu-{linux-tests,linux-ci-regression,output-red,m0-build,m0-tests,m0-clippy}.log`；
完整范围/限制在target/remediation-cpu-diagnostic-report.txt。本批没有真实perf/Samply、
benchmark、host adapter操作或性能提升证据；新增Python调度/验证成本尚未测量。

### M1n — 收尾已完成的 Qualification 资源与协议边界

schema rejection probe改用现有ProcessGuard，stdout/stderr各64KiB和既有redaction规则，
两capture均join后再报错；读取错误不再当EOF。SOCKS的partial I/O从tcp_scale迁入一个私有
deadline owner，connect/握手共享绝对期限，最后成功byte也检查截止；resource TCP/DNS
事务同时限制write/read及响应长度。返回blocking socket保留有限timeout，仅实际Tokio
handoff清除timeout；未改变throughput payload loop的原测量语义。

ReadyFile与路径处理移至profile_files，字段私有；任何mkdir/chmod前检查relative normal
profiles子路径与完整已有parent链，不follow symlink/reparse到外部新建目录，再逐级创建/
readback。原ready发布、碰撞、remove/drop测试跟随owner；Unix0700/0600保持。
Windows下8个finite脚本IO/fake child/Cursor/temp-file契约通过；不宣称实际Unix redirect
或Windows reparse变更已执行，也不宣称抵抗同权限并发FS替换。

DNS profile/resource两个客户端共享完整响应oracle：ID/flags/question/class/唯一answer/
TTL和空额外sections匹配，允许wire compression，拒trailing/reserved bits。Hickory Record
相等性忽略TTL，测试发现后增加明确TTL比较。DnsLoad保留sent/verified/unfinished，停止
之后的最后request失败也不能吞掉；finish遍历全部worker并保留计数/首错。

DNS resource schema2改为OBSERVATION_COMPLETE，明确process bounds/stability、最终
shutdown/join/rebind的真实结果；query_drain始终UNVERIFIED，production_recovery_qualified
为false。删drained阶段及虚假active=0证明，不移除真实资源上限。exit0仅表示上述观测和
cleanup完成，不代表产品查询owner回收合格。实际产品query/inbound/pool观察留M2。
相关文档和workflow描述/纯测试filter同步，普通suite没有新增性能或特权工作负载。

收尾验证：root边界filter8/8、dns_contract_tests6/6、M4 self-check PASS（56 mutations）、
M4/config严格all-targets/all-features clippy、fmt all、workspace policy20通过；完整
candidate134通过（38.129s），Windows CI Python80发现中68通过/12个Linux-only skip。
这些skip不能代替Unix filesystem用例；CPU专属Linux覆盖另见M1m。总self-check包含已有
有限loopback/DNS行为，不称整个self-check是纯内存；新两个filter不启动socket或产品。
日志 `target/remediation-audit/m4-final-{boundary-tests,dns-tests,self-check}.log`、
`target/remediation-m4-{final-candidate,final-policy,final-ci,config-final-clippy,config-final-fmt}.log`，
agent早期失败/修正见m4-03-04-validation.md、m4-05-validation.md、remediation-dns-contract/validation.txt。

M4 bundle44 rows，SHA `4fc39effe4b51c3306777d1a8b1d93ed9afeb56efa12861097d4c96f12c1c9d3`。
5个本批Rust文件只做CRLF→LF规范化；44 rows都与Git clean filter bytes一致，Python/PS
完整source closure通过。当前hash清单与限制在target/remediation-audit/m4-final-handoff.md。
现有ProcessGuard Drop、kill后Child.wait及capture join仍依赖OS/EOF，**没有OS强制硬期限**；
本批只消除probe绕开已有owner，不能称全部进程生命周期已闭合。这项与其他未完成工具
问题后置，不再串为产品架构前置条件。没有新benchmark/profile或privileged host运行。

### M2a — 配置图先准入，再共享派生结果

固定修改前基准 `cba03a4488935a4d40cfd22f8cd658c74f4365cf`。本批仅改变 config
准备/验证及对应契约、文档；没有修改运行时 relay、core/rule 公开编译器或性能工具。
FND-01 的共享路径重复展开为已确认静态复杂度问题；FND-02 的结构限额晚于递归派生
为已确认顺序问题，栈耗尽没有动态复现。本批没有重试先前被拦截的动态压力组。

`validation/egress_graph` 成为私有准入 owner：原有各 cohort 64、selector members 64、
chain 2–8 hop 限制先于 DNS/endpoint drafts；optional TUN 只计入 inbound 身份。
名称只解析为现有 PreparedEgressRef；具体 chain 不允许 Direct、selector 或重复 hop。
闭合 VisitState 的迭代 DFS 先检查环，再按依赖顺序计算 domain capability 和 u64 首跳集合。
删除旧 capability evaluator、重复字符串 resolve 和 client 首跳路径枚举；调用者只消费
typed 边与摘要。343 行的新模块含 341 行生产区（含空行/注释），测试随 owner 放置。

准入 egress 图 V≤192，selector/chain 边 E≤4,608；HashMap/HashSet 解析预期 O(V+E)，
摘要计算 O(V+E)，typed 拓扑 O(V+E)，摘要/遍历状态 O(V)。根集合的首跳消费为 bitset
union 与升序 outbound 扫描。保留代价是一次临时 typed 拓扑及最终 config/core 独立校验；
core 公开接口仍有线性 tag 查找，resolver/RuleSet 依赖图仍有排序/去重成本，**不是整个
prepare 都为线性**。下游 core 的 cycle/reachability 有完成/到达标记，不枚举共享路径；
运行时 selector 只走当前选中路径。没有新增 crate 依赖、公开 schema 或兼容 fallback。

六个新增测试使用小 diamond、两节点环、64th bit、65 member/cohort 和非法 chain；验证
摘要、闭合脱敏错误与结构拒绝先于非法 endpoint，不构造深递归或资源耗尽工作负载。
旧契约首次运行暴露错误优先级变化：缺 outbounds、缺 DNS servers、身份碰撞以及同时
含非法 hops 的伪 cycle fixture。保留输入、更新适用字段与完整错误；真正 selector cycle
仍检查闭合索引路径。缺 hops 却报 Chains 的实现错误被修为 ChainsHops，没有迁就错误改断言。

受影响包最终 `cargo test -p ferrum2-config --locked`：86 passed、0 failed、0 ignored；
config/M4 all-targets/all-features clippy `--locked -- -D warnings` 与 fmt all 通过。
初始失败及最终日志：`target/remediation-audit/m2a-{config-initial,prepare-initial,
config-root-tests,config-next,config-final-tests,graph-unit}.log`；scope/downstream 复核记录
在 `target/remediation-audit/m2a-config-implementation.md`。

下游 Windows MSVC 门禁：先 locked build workspace bins（16.62s），再普通 workspace
673 passed/0 failed/5 原有 ignored；5项分别是权威20-cycle资格、三个Linux IPv6进程契约、
Windows会归一化127/8的wildcard契约。没有运行 client 或 Rule qualification test binary。
随后 example build、client all-features no-run、Rule no-run、安全 TUN128/platform59、
platform all-feature check、GNU target check、DNS interop74、全workspace严格clippy、fmt、
doc均通过。`target/remediation-audit/m2a-gates.json`保留每条确切命令、exit和日志。
GNU check只是Windows上的cross-target编译，不是原生Linux运行或链接资格。

M4 self-check PASS56；有限 worker/io/DNS filter分别5/8/6通过；非变更PowerShell资格合同
通过。日志均为`target/remediation-audit/m2a-<gate>.log`。MSVC build/test有链接器正常创建
lib/exp的linker_messages warning；strict clippy未放宽且通过。Python工具源本批未变，沿用
M1逐批离线验证，不把它们重新称为M2测试。host Quick A/A PlanOnly通过，当前shell已提升；
实际host运行与同条件性能对比待执行，尚未宣称无性能回退、吞吐提升或生产就绪。

#### M2a 固定提交性能测量（完整，但未通过无回退验收）

产品候选提交 `804f0dc04e8af354d727deff89f727bec3b23a9e`；controller 同提交，Windows
EndToEnd Quick，release/locked/offline/x86_64-pc-windows-msvc；public runner 显式传入
`-AcknowledgeHostNetworkMutation`，执行前确认 shell 已提升。每轮4场景×3交错pair×2成员，
每trial 2s预热/10s active；288s为标称负载窗，实际还包含CPU采样、启动与停止，不能称总耗时。
测量期间没有其他cargo/test/benchmark；后续SRS源码工作不在本次产品提交中。

A/A 两成员均 `cba03a4488935a4d40cfd22f8cd658c74f4365cf`，RunId `34f185756c1b`，
外部证据 `C:\Users\ZZZ\AppData\Local\Temp\ferrum2-m2a-aa-20260905T174744Z`。
24/24 trial完成，产品失败计数delta全部0；独立readback清理adapter/route/address/process/
port全部0。build119.457s、execution609.944s、cleanup4.266s，总734.438s。
runner exit0/执行PASS；Python独立校验 exit3、**REGRESSION**，三组CPU/work等护栏未过。
这两个状态含义不同，执行完成不能冒充采用通过。

| A/A场景 | 配对收益中位数 | 全部pair范围 | 独立判定 |
|---|---:|---:|---|
| TCP单流吞吐 | -0.486% | -27.944%..+1.656% | regression |
| TCP 1KiB p99（反向成本比） | -0.498% | -3.471%..+1.958% | regression |
| UDP packet rate | -0.313% | -0.744%..+1.730% | regression |
| fragment reassembly rate | -0.307% | -0.761%..+0.697% | within-noise-band |

相同源码的TCP单对差异近28%，本轮噪声不能忽略；未删除被标记outlier的pair，未放宽2%
政策。A/B使用同版harness比较基准与804f0dc0；没有配置准备专用timing场景，此Quick只能
观察所测数据面，不能证明配置派生CPU/分配或开放负载尾延迟。日志与启动身份在
`target/remediation-audit/m2a-{aa,ab}-{run.json,host.log}`，A/A独立结论在aa-validation.log。

A/B RunId `9f4f3eb5041c`，证据目录
`C:\Users\ZZZ\AppData\Local\Temp\ferrum2-m2a-ab-20260905T180113Z`。
24/24完成、两产品所有failure delta为0、五类资源readback全零；build115.760s、
execution612.099s、cleanup2.205s，总730.507s。runner exit0/执行PASS，独立validator
exit3/**REGRESSION**。吞吐和延迟的主指标都在原2%中位护栏内，但CPU/work护栏未过：
TCP单流server配对成本中位+3.103%，TCP请求server+4.110%，UDP client/server
+3.849%/+5.745%。这些是现有计量边界内的观测，未补齐CPU窗口起止对齐的资格证明。

下表单位MB/s为十进制、µs为微秒；每个成员3次观测，中括号保留全部范围。收益对p99采用
baseline/candidate反向成本比；配对收益中位数不等于两列各自中位数的比值。

| A/B场景 | baseline 中位数 [范围] | candidate 中位数 [范围] | 配对收益中位数 [范围] |
|---|---|---|---|
| TCP单流，64KiB/次 | 137.951 [136.253,141.145] MB/s | 139.406 [139.161,139.995] MB/s | +1.055% [-0.815,+2.134] |
| TCP请求，1KiB，p99 | 157.3 [157.2,158.2] µs | 159.4 [156.5,159.4] µs | -0.753% [-1.380,+0.511] |
| UDP，1200B，batch1 | 7752 [7647,7769] packets/s | 7792 [7715,7829] packets/s | +0.772% [-0.477,+1.896] |
| UDP分片，1440B，batch4 | 31.488 [31.300,31.601] MB/s | 31.632 [31.364,31.829] MB/s | +0.456% [-0.752,+1.690] |

TCP请求p50/p95中位为115.8/126.4→115.3/126.0µs，UDP为124.2/154.5→123.8/154.0µs，
UDP p99为191.1→189.7µs；所有每次分位数及范围留在raw和m2a-observation-summary.json。
TCP请求3次实际完成量合计148,595→114,052，不能用接近的p99掩盖完成工作减少；未丢弃
请求/错误或删改时间窗来提高结果。该闭环负载不提供开放到达队列的p99/过载错误率，
Quick也没有256-flow公平性；批量TCP/fragment未提供逐请求p99，不能推算。

各场景client/server CPU百分比中位（100%=一个核心）：TCP96.01/55.51→93.08/57.84；
请求28.94/19.60→27.96/20.19；UDP46.48/41.65→49.17/44.66；fragment84.92/79.47→82.09/76.62。
client peak working set中位TCP153,747,456→153,845,760B；请求154,066,944→153,755,648B；
UDP212,348,928→211,251,200B；fragment153,653,248→153,583,616B。server各值也保留raw及
归约JSON。这里的CPU与内存是整个进程观测，不能归因给配置准备模块。

两轮harness源码bundle均`4fc39effe4b51c3306777d1a8b1d93ed9afeb56efa12861097d4c96f12c1c9d3`，
performance bundle均`b6c2d5d94b941c8969ba6f576852f6c9b374bab05c99cac8ceae231c4256d165`。
builds.json逐成员记录commit、client/server/harness/DLL哈希。事后只读环境复核仍为Win11
26200、Ryzen7700 8c/16t、49,373,096KiB，rustc1.97.1 commit8bab26f4f68e0e26f0bb7960be334d5b520ea452、
LLVM22.1.6、Cargo1.97.1、pwsh7.6.4；RUSTFLAGS/CARGO_ENCODED_RUSTFLAGS均未设置。
`m2a-environment.json`是事后身份记录，不能替代采样期间的系统时间序列；未采集真实CPU堆栈。

只读归约不构成第二套资格框架。完整两轮raw+相关门禁归档为
`profiles/remediation-m2a-20260905T181728Z`，337 files/2,361,640B，manifest SHA-256
`2dd84f902a390ec84ef53361c095a109e8ad0f1194ee7ea4464595df306c4fe0`；归档不再修改，
较晚的事后环境记录单独保留。候选功能修复继续保留为可审查提交，**性能验收保持未通过**；
A/A本身不稳定，现有证据不足以将上述变化归因给代码或宣称无回退。继续产品架构整改，
不进入性能优化，不通过再修工具、删outlier或提高门槛来制造采用结论。

### M2b — SRS 解码的输入、展开与工作准入

本批产品基准 `804f0dc0`，独立于其已完成的Quick测量。`ferrum2-rule::srs`公开入口改为
`decode_srs(reader, limits)`，旧无限签名删除；ruleset/cache两处、config真实fixture以及
Rule qualification三处调用同步传入显式默认策略。没有改Windows/M4/Python工具行为或bundle。
工具中的变更仅是被修改产品接口的必要调用迁移。普通qualification测试仍只编译。

私有`limits`集中闭合维度、穷尽默认值和只能收紧的构造；`decode/context`统一累计预算。
encoded/decoded分别在source buffering下、zlib上且payload buffering下设64/128MiB边界，
各自最多一次独立1-byte EOF probe；超量标记先于IO/Compression映射，真实truncated/IO、
strict stream end、trailing payload/file、unsupported分类保持。声明长度及最小wire需求
先准入，数据实际读到后才增量保留；未知声明不能先触发整块reserve/resize。unsupported
字符串在固定8KiB scratch中验证UTF-8后丢弃。

每文件100k规则尝试、1m发射entry、8m累计collection与8m succinct nodes相互独立；重复项
在dedup前收费。domain wire depth258、logical100；展开64MiB、keyword每条255B/总2MiB。
原暂定1MiB因现有100k Keyword需1,188,890B而在实现前改为2MiB，未删fixture或设无限例外。
512Mi work units按请求字节、声明元素、rule/entry及bitmap/rank/遍历/展开收费；失败读可
保守消耗请求量，最终sort和compile不逐比较收费，所以不是整个API的CPU或时间硬上限。

LOUDS保留已验证compact arrays与有界frame/current key，逐key交collector，删除
`Vec<Vec<u8>>`完整重建集合；node/bitmap均前进、最终visited闭合，复制前累计entry/bytes。
IPv6 block覆盖inclusive end后立即成功，避免先加后继在u128::MAX误报overflow，/0不做
shift128。调用者不再各自选择解码预算或解释尺寸声明；代价是读取/解析计数检查与有限
额外状态。保留fallible reserve，未扩大unsafe、依赖或lint例外。

验证由实现owner与独立静态review交叉进行。8个新增普通用例使用小fixture和低限额，涵盖
cap/EOF、CountingRead实际读量cap或cap+1、duplicate entry/bytes、规则/work、unsupported
UTF8、tiny LOUDS和IPv6 /128、/127、/0。初次唯一失败是新测试成功分支漏SRS framing，
修正测试构造后通过；没有伪称旧生产代码动态复现失败，也未重试被拦的压力组。

实际执行：rule39/config86/ruleset25通过，四份pinned SRS完成decode/compile；qualification
no-run及all-targets/all-features check、四包strictclippy/格式通过。root重新locked build
workspace bins（14.74s），完整普通workspace **681 passed/0 failed/5原ignored**；client
all-features compile-only，safe TUN128/platform59、platform all-features、GNU cross-target
check、DNS interop74、全workspace strictclippy/fmt/doc、M4 self-check均通过。普通测试没有
新增adapter、route/DNS/WFP/interface操作。与M2a相同的Linux/hosted资格缺口仍然存在。
每条命令、退出码、日志在`target/remediation-audit/m2b-gates.json`；owner首次/最终日志为
`m2b-{rule-initial,rule-green,integration,qualification-compile,final-rule,final-clippy,final-fmt}.log`。
完整scope、计费定义和限制在`m2b-srs-implementation.md`，静态fixture基准在
`m2-srs-fixture-census.md`。Root普通M4 filters/PS/Python在M2a/M1通过，源未变，不重算新覆盖。

未运行timed 100k matrix或SRS前后性能对比；100k keyword限额依据仍是确定的静态字节计算。
四份pinned通过证明当前默认计数允许这些输入，不是每个预算维度的精确用量/RSS census。
matcher/automaton、snapshot总量、下载/cache事务与实际工作生命周期仍需独立落实，不能
把本批称为整个RuleSet生产可用或性能已改善。此候选保留进入后续集成，性能验收单列。

M2b验证归档：`profiles/remediation-m2b-20260905T184218Z`，26 files/170,701B，manifest
SHA-256 `df1c598527cbb9c8d0d940d956601dde31c34a8a4fe3f6ff58479438604a8a93`，含较晚的M2a
事后环境记录。该副本不再修改。

### M3a — 通知订阅 rollback owner 与不可抹除的 cleanup 失败

产品基准`07939e2d`。部分订阅失败继续逆序取消全部已完成handle；任何取消失败保留仍可
被callback引用的context，并返回Cleanup。完整订阅在snapshot_underlay前即交Adapter
pending槽；生产与injected测试共享同一prepare/cleanup所有权操作，成功take到ManagedState
之间没有fallible步骤。私有命名NotificationStages及闭合Absent/Cleaned/Failed归约同时
处理pending/committed；仅在已有CleanupOperations边界映射原返回类型。

finish_setup_transaction总执行outer cleanup，再粘住inner/outer失败，strict-route标志
不擦除cleanup位。TUN创建失败先处理cleanup-integrity，随后才处理stop/deadline/retry；
root复核补回提前return路径的underlay.invalidate，避免顺序修复跳过原停止分支的失效动作。
没有新增公共API、unsafe许可、平台职责或host操作。

32组合覆盖snapshot/commit后失败、普通/cleanup内错、通知取消/后续cleanup成败、
strict-route标志；比较完整CreateError、逆序事件、pending/committed持有关系与context
释放/安全保留。原订阅测试覆盖每个失败ordinal×各前序取消失败，outer cleanup仍执行。
平台safe suite62、TUN safe128均通过；两包live all-features check、all-targets/all-features
strictclippy与owned格式通过。root最后失效修正后重跑TUN check/clippy/fmt通过。
确切命令、owned hashes及日志在`target/remediation-audit/m3a-platform-rollback.md`和
`m3a-platform-ownedpaths.json`，原始日志为`m3a-*.log`。

普通测试排除live backend，未调用实际Adapter::create或操作网络状态。live Adapter字段
接入与native owner_main取消竞态只有静态/编译证据；不能把shared helper测试冒充实际
Win32故障注入。整合workspace/client compile-only及专用host资格待其他当前批次冻结后
执行。既有cleanup_inner在失败时不clear catalog的行为尚需结合残留隔离契约审查，未在
本批标为新确认缺陷。握手/join、health/MTU等平台余项仍未修复，没有性能无回退结论。

### M3b — DLL 读取边界与验证失败的目录 handle 回收

基准`21bcb96b`。live verify_artifact先读取已持有File的metadata，错误长度在body分配、
seek/read/hash之前拒绝。生产共用的core reader随后从同一File的offset0固定读取427,552B，
仅再读1byte核实EOF；短文件、增长文件、seek/read错误都闭合拒绝，再将完整有界slice
交私有CNG hash。删除clone File及无界read_to_end路径；SHA-256/ABI/System32/pin与持有
身份规则保持。CreateFileW成功后先构造既有DirectoryHandle，再进行可能失败的目录属性
验证；失败时当前handle与已有ancestor集合一并RAII回收。

4个纯reader测试验证错误metadata零IO、非零初始offset和partial read、短/长文件最多
pin+1读取，以及seek/body/EOF异常的完整闭合Error。platform安全suite66/66、生产
all-features check、all-targets/all-features strictclippy与owned格式全部通过；命令/
hash清单在`target/remediation-audit/m3b-loader-bounds.md`、m3b-loader-ownedpaths.json，
日志m3b-*.log。没有新unsafe、依赖、公开API或通用FS抽象。

实际CNG、Win32目录验证失败的CloseHandle次数只有静态/编译证据；没有真实DLL篡改、
大文件、adapter或网络操作，也没有启动性能测量。该读取上限不是OS调用的硬期限或
整体启动RSS/延迟改善声明。整合检查及专用host资格仍待当前DNS/cache源码收口。
