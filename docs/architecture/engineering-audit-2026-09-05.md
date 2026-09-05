# 全量工程审查 — 2026-09-05

## 执行顺序与审查基线

用户明确纠正执行顺序：**全 workspace 按最新 AGENTS 审查 → 统一架构设计及实现 →
正确性与性能无回退验收 → Qualification CPU profiling 驱动的性能优化**。
第一阶段生产模块静态审查已完成，正在进入统一架构设计。既有整改提交是历史候选，不能代表全量审查或架构验收完成。
不继续产品修改，不根据静态热点猜测实施优化。审查可以运行安全、有界的行为复现。

代码基线 `2fb0dd4a`；本轮开始工作树干净。现有 52 份指南（根 + 51 scoped）与原始
`9bbcea22` 间无修改，仍以当前磁盘内容为准。指南逐文件 SHA-256 清单位于
`target/remediation-audit-guides.json`，索引 SHA-256
`99310a8265bfb4bfd4d670b03056fd7a85284b2309040e81278a5343f26f5ccd`。
Rust 1.97.1，workspace 19 packages。成员、targets、features、直接依赖已从 locked
`cargo metadata --no-deps --format-version 1` 重新登记。

未完成的 SRS 候选已暂停，完整文件和 tracked patch 保存于 Git 忽略目录
`profiles/remediation-paused-srs-20260905T114301Z`；manifest SHA-256
`1274f969377465b48664cfb00f5d9652f5d1ba2f5521d8d9ff02934ae40f2ca9`。
该补丁未提交、未接受，活动源码已恢复到基线。红测试证据仍保留；它不等于完整修复。

## 覆盖与完成定义

“已审”必须包括生产模块实现、公开接口、真实调用方、关键测试契约和作用域规则；
仅枚举、搜索或跑测试不足以标记完成。测试模块按其验证契约登记，不把 test binary
编译当作测试执行。每项发现分开记录事实、待复现假设和平台限制，给出位置、规则、
触发/影响、优先级、后续修复与验证方向。500/800 行只作职责检查线索。

| 审查组 | Packages / 支撑范围 | 当前状态 |
|---|---|---|
| Foundations | core、rule、config | 生产静态审查完成 |
| Runtime/DNS | runtime、dns、ruleset | 生产静态审查完成 |
| Platform | tun、platform-windows | 生产静态审查完成；safe-only 验证 |
| Protocols | crypto、shadowsocks、socks5、sniff、net | 生产静态审查完成 |
| Composition | client、server、observability | 生产静态审查完成；client test compile-only |
| Qualification/工具 | m0-harness、m4-qualification、rule-qualification、Python/PowerShell/CI | 源码静态审查完成；root 汇总 |

用户已授权五个审查代理，统一使用 gpt-6-astra / medium；root 汇总跨 crate 问题。
19 packages 的全部 446 个 `src/**/*.rs` 路径均已登记；生产模块由对应审查组逐文件阅读。
独立 test-only 文件的 pending/部分阅读状态明确保留，不能称所有测试源码或平台场景全覆盖。
[逐文件覆盖与源码哈希](engineering-audit-2026-09-05/coverage.json)保存审查基线，
[跨组独立核对](engineering-audit-2026-09-05/cross-check.md)收窄了部分并发条件和生产可达性。
分组报告已经进入仓内文档，原始日志仍在 Git 忽略的 target 目录。
本阶段没有产品修改；分组消息经报告和跨组核对后才纳入结论，没有并行性能测量。

## 性能工具路线的核对

仓库已有 `tools/profile-cpu.sh`（Linux attach-only，依次运行 perf stat 与 Samply）、
`profile.profiling`（release + debug=1、strip=none）及 M4
`profile-workload`，应复用 producer/controller、现有 source identity 和工作负载。
Windows TUN workload 只能由指定 correctness/performance runner 的 job children 执行。
历史 CPU report 的 WPR/xperf + 对应 EXE/PDB 是可复用方法，但其 mixed-scene trace、
未解析内核 symbols 和 profiler observer effect 不能直接作为当前热点结论。
wrapper 本身不启动 Qualification，也不等待 ready；它的两段 duration 要分别落在同一
Qualification 的有效负载窗口内。当前只支持 tcp-bulk/udp-small-high，不得冒用场景名。
阶段三先获取短时、场景明确、符号可解析的 CPU 样本；无 profiler 的前后测量独立执行。
此处只是工具能力与约束核对，尚未选择优化或开始新的 profiling 运行。

## 审查结论与设计输入

| 优先级 / 问题组 | 已确认代码事实、触发与影响 | 详细位置、规则、验证方向 |
|---|---|---|
| P1 配置图资源 | 共享 selector DAG 重复展开路径；部分递归在结构数量校验之前执行 | [Foundations FND-01/02](engineering-audit-2026-09-05/foundations.md)；复杂度静态确认，未运行耗尽复现 |
| P1 外部资源体积 | SRS声明长度预分配、解压/展开未全限界；下载/metadata/hash没有独立字节预算 | [FND-03](engineering-audit-2026-09-05/foundations.md)、[RD-02](engineering-audit-2026-09-05/runtime-dns.md)；旧小输入分配红测试单独留存 |
| P1 查询/本地工作归属 | tagged query异常可绕过子任务清理；Tokio内部FS/系统lookup工作不属于现有join owner | [RD-01/03/04](engineering-audit-2026-09-05/runtime-dns.md)；native积压规模、OS时限未测 |
| P1 TUN退出握手 | 尚在队列中的completion sender由准备/root保留，同时root先join等待该sender的native线程 | [PLAT-01/02](engineering-audit-2026-09-05/platform.md)、[独立核对](engineering-audit-2026-09-05/cross-check.md)；已dequeue取消路径可以解除等待，不能泛称每次退出死锁 |
| P1 清理错误完整性 | cancellation优先掩盖CreateError cleanup；notification逆序清理失败丢分类 | [PLAT-03/04](engineering-audit-2026-09-05/platform.md)；静态错误优先级/所有权确认 |
| P1 测量可信度 | CPU百分比/工作量缺实际窗口因子；Rule report派生值未重算；场景/fixture/校准及矩阵闭合不足 | [CT-01/02](engineering-audit-2026-09-05/candidate-tooling.md)、[RTL-01/02](engineering-audit-2026-09-05/rule-tooling.md)；数学/数据流事实，未伪造证据执行 |
| P1 qualification回收 | setup spawn失败可持接收端join已阻塞sender | [M4-01](engineering-audit-2026-09-05/m4-tooling.md)；有条件的静态等待环 |
| P2 UDP接纳/策略 | SOCKS预算拒绝前pin；TUN冻结Reject后吞后续synthetic DNS；SS activity可倒退，token缺owner绑定 | [C2/3](engineering-audit-2026-09-05/composition.md)、[PROTO-1/2](engineering-audit-2026-09-05/protocols.md)；真实caller与纯内存API证据分开 |
| P2 观测/错误 | metric合法enum与series网格不同步；TCP sniff错标UDP；Direct UDP终态丢弃；server accept丢可恢复kind | [C1/5/6/8](engineering-audit-2026-09-05/composition.md)、[RD-05](engineering-audit-2026-09-05/runtime-dns.md) |
| P2 恢复与平台状态 | 两文件缓存提交非原子；snapshot/monitor未join；readback失败当damage；MTU漏health、DLL先读后限、handle验证早退 | [RD-06/08](engineering-audit-2026-09-05/runtime-dns.md)、[PLAT-05..10](engineering-audit-2026-09-05/platform.md) |
| P2 资格证据强度 | cleanup部分计数为字面0，缺删除后读回；失败标签漏计；恢复日志仍有丢失路径；活动窗/采样/捕获边界不完整 | [Host](engineering-audit-2026-09-05/host-tooling.md)、[M4](engineering-audit-2026-09-05/m4-tooling.md)、[Harness](engineering-audit-2026-09-05/harness.md)、[CPU wrapper](engineering-audit-2026-09-05/cpu-profiler.md) |
| P2/P3 接口与规则 | 失效selector错误/fixture API、mutable validated fields、trait义务、known-enum wildcard、普通gate误执行qualification benchmark | 各组报告；[CI/workflows](engineering-audit-2026-09-05/ci-workflows.md)、[Rule工具](engineering-audit-2026-09-05/rule-tooling.md) |

所有发现的完整文件/行、契约、触发/影响、事实与假设、修复方向和验证方式在对应报告。
同一CPU窗口问题CT-01/HT1只算一项；系统lookup、listener alias、SRS跨组项同样合并。
未被确立为当前生产caller缺陷的公开能力问题、嵌套selector线性一致性，保持较低优先级或待定。

**纠正历史资格证据的强度：** 此前各次host JSON确实报告cleanup PASS/五类0，
但HT2审查发现route/address删除后读回及提前退役port ledger存在缺口。
因此这些JSON不能单独证明每一类状态均已独立读回为零；本次没有发现或声称实际残留。
过去记录的结果保留，不用新解释改写原始证据，也不把它们作为当前完整生产资格。

## 本阶段实际验证与限制

- Protocols五包：138个既有测试、严格all-targets/all-features clippy通过；纯内存API probe
  验证server跨owner能力/反序时间行为，未证明生产远程可达性。
- TUN/platform safe lib：128/59通过；m0 qualification_contract：16通过。
- runtime/dns/ruleset日志：224 passed / 0 failed；foundations三包日志结尾各组通过。
  两者原工具session最终exit未收取，保留这一限制，不伪称取得了完整命令退出证据。
- 基础层与runtime/DNS两个代理轮次被自动内容审查中断，系统仅称“可能存在网络安全风险”，
  未标明具体子操作。新动态复现已停止；DNS scratch未进入目标故障路径，不计成功。
  随后静态补读和报告保存完成。没有借其他代理重试被拦截操作。
- 客户端test binary仍未执行；没有运行真实adapter/route/DNS/WFP变更、provider、fuzz或新profiling。
  Test-only源文件未全读、平台故障交错和生产规模负载未全验证；详见coverage与报告。

## 下一阶段

在以上全量生产静态审查上形成统一架构设计。先修资格/清理/测量契约建立可信基线，
再按模块所有权分批实现并验证正确性与同条件性能无回退；未完成这一验收前不进入性能优化。
历史候选与测量见[整改记录](engineering-remediation-2026-09-05.md)及
[逐批证据](engineering-remediation-evidence-2026-09-05.md)，暂停SRS补丁不会自动恢复。
