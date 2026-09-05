# Windows TUN Host Confirm 与 CPU Profiling 报告

## 结论

在已显式授权 `-AcknowledgeHostNetworkMutation` 的 Windows 11 宿主机上，`EndToEnd` 与 `ClientDirect` 两套 `Confirm` 均完成 50 个真实 Wintun trial，并通过独立 evidence validator：

- `EndToEnd`：`PASS`，run ID `bcdb3ea3a818`。
- `ClientDirect`：`PASS`，run ID `88c5cf126531`。
- 两次 cleanup 均为 `PASS`，残留 adapter、route、address、process、port 全部为 `0`。
- 两个 Confirm 都是同提交 A/A 运行，用来确认当前实现的绝对性能、稳定性、拓扑差异及主机噪声；它们不能证明某项代码修改带来了性能提升。

当前宿主机上的主要结果：

- `ClientDirect` TCP 单流吞吐中位数为 **194.14 MB/s**，比 `EndToEnd` 的 **134.55 MB/s** 高 **44.3%**。
- `ClientDirect` 1 KiB TCP request p99 为 **82.9 µs**，比 `EndToEnd` 的 **135.2 µs** 低 **38.7%**。
- `ClientDirect` UDP 为 **17,034.5 pkt/s**，比 `EndToEnd` 的 **9,338.5 pkt/s** 高 **82.4%**；p99 分别为 **91.45 µs** 与 **162.6 µs**。
- `ClientDirect` fragment reassembly 为 **74.14 MB/s**，比 `EndToEnd` 的 **42.11 MB/s** 高 **76.1%**。
- 两种拓扑的 256-flow Jain fairness 都接近 1：`0.999999416` 与 `0.999999257`。

独立 CPU trace 表明：

- 归属于产品进程上下文的 leaf sample 中，`ntoskrnl.exe` 占 **62.03%–74.27%**；产品自身模块占 **14.25%–17.34%**。Windows 内核符号未解析，因此该结论只精确到模块，不能把 `ntoskrnl.exe` 内部成本进一步归因到具体内核函数。
- 产品自身模块内，Rust runtime / Tokio / Mio 异步 I/O 占 **54.72%–65.28%**，是最大的用户态类别。
- 客户端自身模块内，TUN parsing / stack / scheduling / Wintun glue 占 `EndToEnd` 的 **21.77%**、`ClientDirect` 的 **24.57%**。
- Crypto / Shadowsocks framing 在 `EndToEnd` client 与 server 自身模块内分别占 **9.65%** 和 **15.80%**，而 `ClientDirect` client 仅占 **0.12%**。这与 `EndToEnd` 的额外加密和 relay 路径一致。

因此下一轮优化应优先获得带 Windows public symbols 的短时、按场景 trace，以拆开 `ntoskrnl.exe`；在现有证据范围内，优先调查网络内核往返/批处理和 Mio/Tokio poll/wake 成本，然后再优化 `EndToEnd` 的 Shadowsocks crypto/framing。

## 范围与解释边界

### 测试拓扑

```text
ClientDirect: workload -> real Wintun -> ferrum2-client TUN/TCP/UDP stack
              -> client direct egress -> local support echo

EndToEnd:     workload -> real Wintun -> ferrum2-client -> ferrum2-server
              -> server direct egress -> local support echo
```

真实执行使用已提升权限的 shell 和字面量开关 `-AcknowledgeHostNetworkMutation`。Runner 仅创建 run-scoped Wintun adapter、RFC 2544 benchmark address、精确 `/32` route、临时 process/port 和 recovery ledger；没有修改 default route、host DNS、physical adapter、WLAN、WFP、firewall 或 sing-box。

### A/A 设计

本次 Confirm 的 baseline 与 candidate 指向同一 SHA。原因是当前 host runner 使用闭包 source bundle，旧 parent 与当前 workload/schema 不兼容；把不同 harness contract 的历史提交当成性能 baseline 会混入测试定义变化。

A/A 的含义：

- 可以验证当前代码在两种拓扑上的真实绝对性能、失败计数、资源使用、清理契约和运行噪声。
- 可以比较同一产品实现的 `ClientDirect` 与 `EndToEnd` 拓扑成本。
- 不可以将 baseline/candidate 差值解释为代码优化收益。

`EndToEnd` 的 TCP 单流 A/A 差值达到 `+3.30%` 并被标为 `candidate-win`；因为两侧是同一提交，这一结果只能解释为顺序、主机或调度噪声。其余 Confirm 差值均落在噪声带内。后续真实 candidate 判定不应只依赖一次约 2%–3% 的变化。

## 已提交更改

| Commit | 作用 |
|---|---|
| `5050158a31ded745ce13235271b36b0911cde67a` | `feat(perf): expand Windows TUN host coverage`：加入显式 topology、Direct 配置、Confirm 5 场景/50 trial、p99、CPU/I/O/working-set evidence 和 schema。 |
| `174ca2439692ea20242262beeecebbc0620c1f10` | `fix(perf): keep latency flows alive`：将 benchmark TCP idle timeout 调整为 60 s，避免 request-p99 workload 被 1 s idle policy 提前关闭。 |
| `9c1e5aecb603f565cd31048fb064062dcd97aabf` | `fix(perf): tolerate marker deletion races`：Windows marker 删除时把瞬时 `PermissionDenied` 作为有界重试，而不是永久失败。 |
| `0e62b1e9a95610d9aee84ba7fd18ceb47e148d2a` | `fix(perf): start server after TUN setup`：先完成 TUN/route setup，再启动 server，避免 network-change monitor 在 256-flow 活跃期触发 reset。 |
| `21a9f624a00e1a8b655dd73ccbf532405cad307e` | `fix(perf): bound fragment loss tolerance`：按每 100,000 个 unique datagram 提供一次 retry 额度，约 10 ppm；仍然严格、有界，且 retry 继续计入 elapsed。 |

`EndToEnd` Confirm 使用 `0e62b1e9...`；`ClientDirect` Confirm 与两次最终 CPU profile 使用 `21a9f624...`。两者之间只有 M4 qualification 的 `bundle.json` 和 `diagnostic.rs` 变化，Ferrum2 client/server 产品源码没有变化。

## 测试环境

| 项目 | 值 |
|---|---|
| OS | Windows 11 Pro, build `26200`, x64 |
| CPU | AMD Ryzen 7 7700, 8 cores / 16 logical processors |
| Trace 中 CPU 频率 | 5040 MHz |
| RAM | 50,558,050,304 bytes，约 47.08 GiB |
| Power plan | GUID `381b4222-f694-41f0-9685-ff5bb260df2e`（Balanced） |
| Rust | `rustc 1.97.1`, target `x86_64-pc-windows-msvc`, LLVM `22.1.6` |
| Confirm profile | 5 interleaved A/B pairs；每场景 10 trials；5 s warmup + 30 s active；每 topology 50 trials |
| Policy | `tools/windows_tun_performance_policy.json`, schema v2, threshold 2% |

## Confirm 结果

以下“当前值”是同提交 A/A 两侧共 10 个 trial 的 pooled median。CPU 的 `100%` 约等于一个逻辑处理器；`EndToEnd` 总 CPU 需要把 client 与 server 相加。MB 使用十进制 `10^6 bytes`；working set 使用 MiB。

### EndToEnd

- SHA：`0e62b1e9a95610d9aee84ba7fd18ceb47e148d2a`
- Run ID：`bcdb3ea3a818`
- Runner summary：`PASS`
- Independent validator：`PASS`
- Execution：2304.01 s；含 build/cleanup 总耗时 2420.90 s。

| 场景 | 当前值 | 附加延迟 | Client CPU | Server CPU | Client WS | Server WS | Failure delta |
|---|---:|---:|---:|---:|---:|---:|---:|
| TCP single flow | 134.55 MB/s | — | 74.57% | 45.63% | 146.55 MiB | 12.53 MiB | 0 |
| TCP request 1 KiB | 135.2 µs p99 | 135.2 µs | 31.28% | 23.02% | 146.55 MiB | 12.46 MiB | 0 |
| UDP packet rate | 9,338.5 pkt/s | 162.6 µs p99 | 44.10% | 40.83% | 223.59 MiB | 18.60 MiB | 0 |
| Fragment reassembly | 42.11 MB/s | — | 75.50% | 74.90% | 146.46 MiB | 12.33 MiB | 0 |
| TCP 256-flow fairness | 0.999999257 Jain | — | 198.78% | 89.24% | 217.06 MiB | 53.71 MiB | 0 |

A/A paired decision：

| 场景 | Median paired delta | Validator decision |
|---|---:|---|
| TCP single flow | +3.2967% | `candidate-win`，同提交噪声，不是优化收益 |
| TCP request 1 KiB p99 | +0.3776% | `within-noise-band` |
| UDP packet rate | -0.7940% | `within-noise-band` |
| Fragment reassembly | -1.2065% | `within-noise-band` |
| TCP 256-flow fairness | +0.0000051% | `within-noise-band` |

### ClientDirect

- SHA：`21a9f624a00e1a8b655dd73ccbf532405cad307e`
- Run ID：`88c5cf126531`
- Runner summary：`PASS`
- Independent validator：`PASS`
- Execution：2342.53 s；含 build/cleanup 总耗时 2460.52 s。

| 场景 | 当前值 | 附加延迟 | Client CPU | Server CPU | Client WS | Server WS | Failure delta |
|---|---:|---:|---:|---:|---:|---:|---:|
| TCP single flow | 194.14 MB/s | — | 94.17% | — | 146.29 MiB | — | 0 |
| TCP request 1 KiB | 82.9 µs p99 | 82.9 µs | 84.26% | — | 146.28 MiB | — | 0 |
| UDP packet rate | 17,034.5 pkt/s | 91.45 µs p99 | 66.38% | — | 170.05 MiB | — | 0 |
| Fragment reassembly | 74.14 MB/s | — | 110.33% | — | 146.30 MiB | — | 0 |
| TCP 256-flow fairness | 0.999999416 Jain | — | 191.01% | — | 196.91 MiB | — | 0 |

A/A paired decision：

| 场景 | Median paired delta | Validator decision |
|---|---:|---|
| TCP single flow | -0.3875% | `within-noise-band` |
| TCP request 1 KiB p99 | +0.8444% | `within-noise-band` |
| UDP packet rate | -0.6028% | `within-noise-band` |
| Fragment reassembly | +0.8171% | `within-noise-band` |
| TCP 256-flow fairness | +0.0000272% | `within-noise-band` |

## 拓扑成本分析

| 场景 | EndToEnd | ClientDirect | Direct 相对优势 | EndToEnd 单位工作 CPU 相对 Direct |
|---|---:|---:|---:|---:|
| TCP single flow | 134.55 MB/s | 194.14 MB/s | +44.3% throughput | +84.2% CPU / byte/s |
| TCP request 1 KiB | 135.2 µs p99 | 82.9 µs p99 | -38.7% p99 | +95.8% CPU / request/s |
| UDP packet rate | 9,338.5 pkt/s | 17,034.5 pkt/s | +82.4% packet rate | +133.4% CPU / packet/s |
| Fragment reassembly | 42.11 MB/s | 74.14 MB/s | +76.1% throughput | +140.0% CPU / byte/s |
| TCP 256-flow fairness | 0.999999257 | 0.999999416 | 等价公平性 | +57.8% CPU / checked byte/s |

单位工作 CPU 使用 pooled-median process CPU：`EndToEnd = client + server`，再除以相同场景的 throughput、request rate、packet rate 或 checked-byte rate。它适合说明拓扑成本，不是硬件能耗测量。

额外观察：

- TCP 与 fragment 的 client working set 在两种拓扑都约为 146 MiB；主要差异来自 `EndToEnd` 增加的 server 进程与 relay/crypto 工作。
- UDP pooled working set：`EndToEnd` client + server 为 242.19 MiB，`ClientDirect` 为 170.05 MiB，前者高 42.4%。
- 256-flow pooled working set：`EndToEnd` 为 270.76 MiB，`ClientDirect` 为 196.91 MiB，前者高 37.5%。
- 两种拓扑的所有 client/server failure counter delta 均为 0。

## CPU Profiling

### 采集方法

CPU profiling 与无 profiler 的 Confirm 分开执行，避免把 observer effect 混入正式性能数字：

```text
Mode: Quick, same-commit A/A, final SHA 21a9f624...
Recorder: Windows Performance Recorder CPU verbose, file mode
Build: CARGO_PROFILE_RELEASE_DEBUG=1
       CARGO_PROFILE_RELEASE_STRIP=none
       RUSTFLAGS=-C force-frame-pointers=yes
Analysis: xperf -a profile -detail, local release PDB symbols
```

两条 trace 都在 runner cleanup 之前停止并合并，同时保存了与运行二进制匹配的 EXE/PDB。它们主要覆盖后段 TCP request 和 UDP trial；是混合场景热点样本，不是逐场景 trace。

| Trace | UTC window | Duration | Size | Lost buffers/events |
|---|---|---:|---:|---:|
| EndToEnd | 2026-09-05 00:10:40.020 – 00:15:02.598 | 262.58 s | 10.406 GiB | 0 / 0 |
| ClientDirect | 2026-09-05 00:23:18.275 – 00:27:42.911 | 264.64 s | 11.038 GiB | 0 / 0 |

WPR CPU verbose 明显改变 workload 时间和调度；profile Quick 的独立性能 decision 因此为 `REGRESSION`。这不影响 trace 作为热点定位证据，但 profile Quick 的 throughput/latency 数字没有被用于本报告的 Confirm 性能结论。

### Leaf sample 模块分布

占比以 xperf 归属于对应产品进程上下文的全部 profile weight 为分母。

| 模块 | EndToEnd client | EndToEnd server | ClientDirect client |
|---|---:|---:|---:|
| `ntoskrnl.exe` | 71.48% | 62.03% | 74.27% |
| 产品自身 EXE | 17.03% | 17.34% | 14.25% |
| `ntdll.dll` | 3.56% | 3.19% | 3.43% |
| `tcpip.sys` | 2.53% | 6.98% | 2.85% |
| `NETIO.SYS` | 1.30% | 3.72% | 1.50% |
| `afd.sys` | 0.91% | 2.45% | 1.05% |
| `winnat.sys` | 0.40% | 1.04% | 0.45% |
| `ndis.sys` | 0.25% | 0.66% | 0.23% |
| `ws2_32.dll` | 0.43% | 1.07% | 0.43% |
| `mswsock.dll` | 0.12% | 0.34% | 0.14% |
| `wintun.dll` | 0.23% | — | 0.16% |

`ntoskrnl.exe`、network driver、DPC/interrupt 的 sample 可在当前进程上下文中记账，因此这些百分比不是“产品用户态代码的 exclusive CPU”。准确结论是：执行成本主要落在内核/网络模块，产品 EXE 约占 14%–17%；不能把 62%–74% 全部简单称为 Ferrum2 syscall 成本。

### 产品自身模块热点类别

下表仅以产品自身 EXE 中已解析的 Rust/C symbols 为分母：

| 类别 | EndToEnd client | EndToEnd server | ClientDirect client |
|---|---:|---:|---:|
| Rust runtime / async I/O | 54.72% | 65.28% | 61.97% |
| TUN parsing / stack / scheduling / Wintun glue | 21.77% | — | 24.57% |
| Crypto / Shadowsocks framing | 9.65% | 15.80% | 0.12% |
| UDP session / server routing | 2.24% | 10.50% | 2.38% |
| smoltcp TCP/IP stack | 2.62% | — | 2.63% |
| Ferrum2 control / relay / sockets | 5.28% | 4.79% | 5.95% |
| Other linked code | 3.72% | 3.63% | 2.38% |

类别按 symbol prefix 汇总，用于确定调查方向；不是调用树 inclusive cost。

### 主要已解析 leaf functions

占比以各自产品 EXE 的已解析 self-module weight 为分母；长 generic 参数在此简化，原始名称保留在 `cpu-profile.txt`。

| Target | Function | Self-module share |
|---|---|---:|
| EndToEnd client | `mio::poll::Poll::poll` | 8.61% |
| EndToEnd client | `tokio::sync::notify::NotifiedProject::poll_notified` | 2.81% |
| EndToEnd client | `mio::...::SelectorInner::select2` | 2.45% |
| EndToEnd client | `run_udp_route_association` | 2.12% |
| EndToEnd client | `tokio::...::Steal::steal_into` | 2.04% |
| EndToEnd client | `ferrum2_tun::packet::validate_transport` | 1.89% |
| EndToEnd client | AES-NI `encrypt_par` | 1.36% |
| EndToEnd server | `mio::poll::Poll::poll` | 13.28% |
| EndToEnd server | `mio::...::SelectorInner::select2` | 3.00% |
| EndToEnd server | UDP `commit_session_with_resolver_arc` | 2.73% |
| EndToEnd server | `tokio::sync::notify::NotifiedProject::poll_notified` | 2.56% |
| EndToEnd server | AES-NI `encrypt_par` | 1.62% |
| EndToEnd server | `polyval::...::proc_par_blocks` | 1.57% |
| ClientDirect client | `mio::poll::Poll::poll` | 11.55% |
| ClientDirect client | `tokio::sync::notify::NotifiedProject::poll_notified` | 3.10% |
| ClientDirect client | `mio::...::SelectorInner::select2` | 2.64% |
| ClientDirect client | `run_udp_route_association` | 2.33% |
| ClientDirect client | `ferrum2_tun::packet::validate_transport` | 2.30% |
| ClientDirect client | `run_active_session` | 1.51% |
| ClientDirect client | Wintun `Adapter::underlay_policy` | 1.50% |

### Profile 解释

1. **内核/网络路径是首要未知项。** `ntoskrnl.exe` 占比远大于任一用户态 function。下一次应使用 Microsoft public symbols，并把 trace 缩到单个 steady-state 场景，以区分 TCP/IP、Wintun driver、copy、DPC 和 scheduler 成本。
2. **异步 I/O 调度是最大的已解析用户态类别。** `mio::poll::Poll::poll`、`SelectorInner::select2`、Tokio notify/steal/maintenance 在 client/server 都靠前。需要调查 wakeup 数、每 I/O completion 的 poll 次数和 batch size，不能仅根据 leaf 名称直接改代码。
3. **客户端 TUN 数据路径是稳定的第二类热点。** `validate_transport`、`run_active_session`、fair scheduler、stack poll 和 Wintun glue 合计约 22%–25% 的 client self-module weight。
4. **EndToEnd 的 crypto 成本可见且拓扑特有。** Direct client 的 crypto 类别只有 0.12%；EndToEnd client/server 分别为 9.65%/15.80%。若内核/批处理优化完成后仍受限，AES-GCM/Polyval 与 Shadowsocks framing 是下一项明确候选。
5. **`wintun.dll` leaf 占比很小不代表 Wintun 总成本很小。** 驱动、内核 copy 和 network stack 执行会记到 `ntoskrnl.exe`、`ndis.sys`、`tcpip.sys` 等模块。

## 执行期间发现并修复的问题

| 现象 | 根因 | 修复 |
|---|---|---|
| TCP request trial 读超时 | 1 s product idle timeout 会终止持续 request workload | benchmark 配置改为 60 s idle timeout |
| Active-release marker 偶发 `AccessDenied` | Windows 并发删除/metadata 查询窗口被当作永久错误 | 对 `PermissionDenied` 做 bounded retry；`NotFound` 仍表示 release 完成 |
| EndToEnd 256-flow 中途 reset | server 在 TUN/route 创建前启动，network-change notification 命中活动连接 | server 改为 TUN setup/settle 后启动 |
| ClientDirect fragment 在约 148 万 datagram 后因 3 个 ACK loss 耗尽预算 | 原规则每 1,000,000 个 unique datagram 才增加一次 retry 额度，对长时间高 packet-rate 运行过严 | 改为每 100,000 个 unique datagram 增加一次额度，约 10 ppm；retry 仍计入 elapsed，metric 不掩盖丢包成本 |

修复后两套 Confirm 各 50 个 trial 全部完成，failure delta 为 0，cleanup 无残留。

## Evidence 与完整性

### Confirm

| Topology | Evidence root | Summary SHA-256 |
|---|---|---|
| EndToEnd | `C:\project\ferrum2-evidence\confirm-endtoend-0e62b1e9` | `b5f9564f3d34500d8a05dc22604cf54b561fee7eb268b61bd7c570dfc2f9875d` |
| ClientDirect | `C:\project\ferrum2-evidence\confirm-clientdirect-21a9f624` | `59a96368ccf57a10dc595ab105a7ad42c8e635e26ccd3158c7620b8f14e1fa9e` |

### CPU traces

| Topology | Trace/report root | `cpu-profile.txt` SHA-256 |
|---|---|---|
| EndToEnd | `C:\project\ferrum2-evidence\cpu-profiles\endtoend-clean-21a9f624` | `781ad8da9774df4871146b0ace99a24dce5dbb151ce391774718b3e064c1b5ea` |
| ClientDirect | `C:\project\ferrum2-evidence\cpu-profiles\clientdirect-clean-21a9f624` | `41fe2173f92715d98077282eefe69fed81951cd40a4822e16caeff3a5ab707be` |

每个 CPU root 包含：

- `cpu.etl`：原始 WPR trace；
- `cpu-profile.txt`：xperf symbolized leaf profile；
- `symbols/baseline` 与 `symbols/candidate`：匹配该次构建的 EXE/PDB；
- `symcache`：本地解析缓存。

大型 ETL、PDB、trial evidence 保存在 repo 外，没有提交到 Git。

## 验证记录

Confirm evidence 使用以下独立入口重新验证，两个命令均返回接受状态：

```text
python -B -m tools.performance_candidate windows-tun-validate-host-evidence \
  --evidence-root C:/project/ferrum2-evidence/confirm-endtoend-0e62b1e9 \
  --baseline-sha 0e62b1e9a95610d9aee84ba7fd18ceb47e148d2a \
  --candidate-sha 0e62b1e9a95610d9aee84ba7fd18ceb47e148d2a \
  --mode Confirm --topology EndToEnd \
  --policy tools/windows_tun_performance_policy.json

python -B -m tools.performance_candidate windows-tun-validate-host-evidence \
  --evidence-root C:/project/ferrum2-evidence/confirm-clientdirect-21a9f624 \
  --baseline-sha 21a9f624a00e1a8b655dd73ccbf532405cad307e \
  --candidate-sha 21a9f624a00e1a8b655dd73ccbf532405cad307e \
  --mode Confirm --topology ClientDirect \
  --policy tools/windows_tun_performance_policy.json
```

已运行的实现验证还包括：

- `tests/platform/test_windows_tun_host_qualification.ps1`：PASS；
- `python -B -m unittest tests.performance_candidate.test_windows_tun_source_capture -v`：8 tests PASS；
- `cargo run -p ferrum2-m4-qualification --bin m4-qualification --locked -- self-check`：PASS，56 mutations；
- `cargo test -p ferrum2-m4-qualification --locked`：2 tests PASS；
- `cargo fmt --all -- --check`：PASS；
- `git diff --check`：PASS；
- WPR 最终状态：`WPR is not recording`。

## 建议的下一步

1. 用 Microsoft public symbols 采集每个场景 30–60 s 的短 trace，分别分析 TCP、UDP、fragment 和 256-flow；避免再次生成 10+ GiB 的混合场景 ETL。
2. 在改代码前增加运行时观测：每 checked unit 的 poll、wake、I/O completion、TUN batch 和 packet batch；验证 Mio/Tokio 调度是否真的在空转或碎片化执行。
3. 如果内核 trace 显示 copy/packet crossing 为主，优先扩大安全 batch、减少 user/kernel transition 和 per-packet wakeup。
4. 对 `EndToEnd` 单独拆分 AES-GCM/Polyval、Shadowsocks framing 和 relay copy；Direct 已证明这些成本不是 TUN 基础路径固有成本。
5. 真正评估下一项优化时，使用当前闭包 bundle 生成兼容 parent/candidate，并保持 Confirm 无 profiler；CPU trace 只用于归因，不参与性能 verdict。
