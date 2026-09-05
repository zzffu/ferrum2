# Qualification 证据与执行所有权设计

设计基线：生产 `2fb0dd4a`，全量生产静态审查 `fc6180b2`。本文件仅设计。
复用现有 M4、Rule runner、Python controller、PowerShell host modules、CPU wrapper；
correctness 与 performance 保持不同 public runner、计划、source bundle 和 verdict。

## 1. 原始观测到 verdict 只有一个可信转换

Windows trial 已有 CPU 百分比、实际 CPU 窗口和 checked_units。修正两套现有 reducer：

`CPU seconds / checked work = cpu_percent / 100 * cpu_sample_seconds / checked_units`。

按 pair 比较该量，保留现有 median+majority 与 2% guard；不把 primary latency improvement
当 work ratio。采样百分比由同一窗口推导时窗口因子会消去分母，恢复实际进程 CPU delta。
这一步可保留 trial schema；同步修改 PS/Python、严格校验以及完整 bundle identity。
现有采样含 marker 接收开销，不能声称恰好等于 packet active 窗口。
需保留 CPU 起止和 active 起止观测，分别报告窗口覆盖与偏差，禁止由名义 active 替代实际窗口。
零 baseline CPU 仍不能证明无限精度的 CPU 不回退；保留明确零值/不可比较语义。

Linux trial 用已有 bounded closed JSON owner 一次读出 bytes/value/digest，删二次读取；
aggregation 按 catalog 重建 group/scenario closure，检查完整 schema、nested decision、
统一 build/recipe/environment identity。汇总若只消费上游摘要，必须显式绑定摘要生产 job
与 raw manifest，不将自报 mandatory 列表当外部标准。
workflow 最后清理完成后才发布最终可接受证据；失败仍发布原始日志和失败状态。
aggregate 必须要求每个生产 job 与最终 cleanup 成功，`always()` 仅保证失败证据能汇总。
A/A 保留噪声观测，但机器结果明确不具备 adoption eligibility，不能产生代码优化 WIN。
schema 变化在 producer/controller/fixture/docs 同批更新，不读旧 schema 兜底。

Rule controller 新建私有 `validated_report` 行为 owner：输入 bounded report 与预期 runner
identity，输出已核对 report 与 workload identity。它按实际 operations/duration 重算 ns/op、
nearest-rank quantiles、五次单操作 allocation 汇总、compiled bytes/entry、同进程 parity 与
适用 gates，容差以 producer 的浮点编码为依据，不能用性能阈值充当数学一致性容差。
workload identity 包含 fixture bytes/hash、scenario 元数据、配置、measurement policy、
相关 host/toolchain/build profile；排除有意不同的产品/runner hash 与时间戳。
完整 calibration applicability 在启动任何 runner 前校验；每次返回核对相同 workload。
synthetic SRS 的 independent build 证据与 shared-object timing 明确分别归属。

保留单一现行 aggregate artifact。设 coherent run-wide encoded evidence 预算，在保留每份
report 时扣减，序列化后写出前再校验现有 reader cap，避免 12×64MiB 隐式膨胀；不另建归档
格式。超过预算返回闭合错误并保留已拥有证据。review-calibration 要求 source/output 共目录，
在写出前验证，避免成功生成不可解析引用。错误类别与 stage 闭合；不得直接转发 runner stderr。

## 2. 执行拥有者负责完成清理，证据拥有者负责证明

M4 resource/DNS responder setup 用现有 concrete worker owner 立即收管已启动线程；
任何 setup/finish 失败先关闭所有阻塞依赖，再遍历全部 join，收集首要错误但不提前退出。
命令捕获复用已有 bounded process owner，加入绝对 deadline、stdout/stderr cap、drain
与 reap；移除 Command.output 裸调用。临时输出路径先验证 containment 再 mkdir。
SOCKS setup 使用一条 absolute deadline；返回 socket 的后续 I/O timeout 由对应 workload
明确设置，不依赖 helper 清除后偶然沿用。

计量修正留在相应 scenario owner：Windows fairness 的实际 flow completion/elapsed；
TCP/UDP 不为凑最小样本而暗自扩 active，证据记录实际负载窗口与缺样状态；DNS 检查完整
查询/响应语义，resource drain 与测试前基线比较。保留失败请求、超时、丢弃计数。
这些修正改变 recipe/source identity，必须用同一新版 harness 重采 baseline 与 candidate。

Windows private host ownership 维护两类信息：仍需清理的可恢复资源，以及直到最终 readback
都保留的 run-owned expected identities。每次删除后读回 exact adapter/route/address；process
按 PID+creation identity 验证结束；ports 在产品退出后读回占用，不能只把 ledger 删掉就记0。
未知/读回错误是 cleanup failure，不转为0；不清理发现的非本 RunId 资源。
五类结果由读回构造。恢复失败的日志在 transient tree 删除前导出到指定 evidence directory。
closed failure metrics parser 同时看 family 和合法 result labels，reset/full-rebuild failed
不得遗漏。保持 rollback deadline 与现有900秒正确性上限，不动默认路由/DNS/物理接口。

## 3. 普通测试门禁与明确测量入口

root workspace test 排除 rule-qualification，并显式保留该包 --no-run；同步 m0 workflow、
现有 workflow contract 和 gate ledger。原有 timed tests 由明确 qualification 入口执行，
不删测试、不加 ignored 来制造普通 gate 通过。client compile-only 与 hosted TUN features
维持原约束。先 offline Python/PS contract 与 M4 self-check，工具通过后才建立新基线。

## 4. 架构验收和之后的 CPU profiling

无生产 SLO 时，暂定验收是：契约正确、资源上限可解释、错误无掩盖、关闭全部回收，且
现有 reviewed policy 下同条件 A/B 未观察到回退。记录每个 pair 和 range/MAD，噪声过大
则结论为不确定。primary gate 通过仍须一起审阅 tail、错误率、CPU/work、峰值和残留；
不为未 gate 的 metric 自创可接受退化比例。缺失的 open-loop 排队/长期内存证据单列。

代表负载从真实变更路径选：非TUN TCP bulk+UDP小包，DNS cache hit/miss与规则更新，
Windows EndToEnd TCP/UDP/fairness/fragment，TUN lifecycle；仅在区分TUN/加密归因时补
ClientDirect。不机械跑所有拓扑×协议。先 A/A 量噪声，再同harness A/B交错完整pairs；
失败trial整组不可接受，不删离群、不拼补旧run。单请求tail与batch ns/op明确分开。

CPU采样在架构实现和对应无回退验收之后，使用 `tools/profile-cpu.sh` attach 到 M4
`profile-workload` ready 所指的实际进程。保留现有CLI与tcp-bulk/udp-small-high场景；
wrapper 输出绑定实际 executable hash、PID start、binary build/symbol、ready identity、
sampling起止与 active overlap。perf stat与Samply依次运行，两段必须均位于有效负载窗。
新增整次deadline与helper cleanup；PASS必须验证gzip/JSON有效样本、目标进程/线程、
可解析符号、丢失/缺失样本，不能只检非空文件。fake-tool tests验证这些contract但不计
真实采样。实际工具不具备所需能力则明确失败，无perf fallback或伪造metadata。

Linux/WSl与Windows分别保留host/toolchain/kernel/profile/flags/CPU/RAM/environment。
Windows ETL须用已有专用runner工作负载与对应EXE/PDB；混场景、缺symbol不作精确热点。
profiler运行与无采样的性能比较独立，热点只产生下一批优化假设；优化后再重复对应A/B。
