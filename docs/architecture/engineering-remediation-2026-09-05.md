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
| runtime | 28 / 9634 | metrics、supervisor、affine executor、UDP owner/queues、shutdown | R1/R3/A2 已修复验证；其余路径仍需深入审查 |
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

### R6 — P1：持续补入的 Direct UDP 请求饿死应答（续行整改）

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

### 最终已执行门禁

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
