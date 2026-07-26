# ferrum2 v0 差距分析

## 基线与 M0 plan 处置

调查基线为 2026-07-27 的
`master@b41c6127b1834ebd97246451fd92bafea50cb205`。仓库只有
`AGENTS.md`、`workflow.toml`、milestone workflow 技能和文档模板；bootstrap
调查时：

- `rg --files` 未发现 `Cargo.toml`、`Cargo.lock`、Rust 产品源码、benchmark
  或 CI workflow；
- 只存在 template spec/test plan/ticket，没有 approved contract 或 non-template
  ticket；
- `workflow.py doctor` 和 `validate` 通过，但都警告
  `No non-template tickets found`；
- `workflow.toml` 的三条 quick Cargo 命令均已实测非零退出，直接原因是根目录
  没有 `Cargo.toml`；
- 当前不存在产品行为、产品测试或互操作证据。工作流结构校验通过不能解释为产品
  能力已部分实现。

M0 plan 当前新增、尚未实现的控制面：

- `ADR-0001`～`ADR-0006` Accepted，关闭 roadmap DEC-001～DEC-007；
- `SPEC-0001` 与 `TEST-0001` Approved；
- M0-T01～M0-T08 均为 `ready`，依赖/ownership 已冻结，唯一执行 frontier 是 T01；
- `docs/research/M0-upstream-baseline.md` 固定规范、工具链/依赖、reference 与平台
  provenance。

这些文档把下表 M0 项从“未决设计”推进为“有批准 contract、待实现”；产品代码、
测试执行、互操作/平台证据仍然全部不存在，不能标为 completed。

## 正确性与安全差距

| ID | 当前行为与证据 | 目标行为 | 严重度 | 依赖 | 拟议里程碑 | 不确定性/所需研究 |
|---|---|---|---|---|---|---|
| GAP-C001 | 无 secret type、KDF 或 AEAD 代码 | 精确 key 长度、BLAKE3 derivation、三个指定 AEAD、zeroize boundary 和无泄密错误 | P0 | workspace 与 crypto boundary | M0（AES-128），M1（全部） | KAT 来源、依赖版本与 license/provenance |
| GAP-C002 | 无 SIP022 TCP framing/state machine | message type、bounds、request/response binding、detection-prevention 和 nonce/salt 规则严格符合 SIP022 | P0 | GAP-C001 | M0/M1 | 规范快照和与参考实现的显式差异处理 |
| GAP-C003 | 无 TCP replay state | 超过 30 秒时间戳拒绝；server exact salt set 至少保留 60 秒且无 false positive | P0 | clock seam、bounded exact store | M0 | clock rollback、容量与 eviction 策略 |
| GAP-C004 | 无 UDP state/session/replay 实现 | per-direction monotonic packet ID、sliding window、nonce 唯一；仅在认证和完整语义校验后更新 | P0 | shared crypto/wire boundary | M2 | window/session API、迁移与并发回收语义 |
| GAP-C005 | 无认证前置或 input-bound 测试 seam | target connect、peer-sized allocation、forwarding 和 accepted state mutation 均晚于认证与 bounds/header 校验 | P0 | connector/runtime seam | M0-M2 | 如何确定性观测“没有发生副作用” |
| GAP-C006 | 无 task、queue、buffer 或 session 生命周期 | 全部资源有 owner、limit 和 termination path；failure 仅终止受影响 flow | P0 | runtime/cancellation design | M0-M3 | timeout、half-close、listener failure 和 shutdown 模型 |
| GAP-C007 | 无日志、错误或指标实现 | secrets 不进入日志/错误/panic/trace/labels；destinations 不成为 metric labels；labels 固定且低基数 | P0 | config/observability contract | M0/M3 | redaction/zeroization 可测试边界与 exposition 策略 |

## 功能与兼容性差距

| ID | 当前行为与证据 | 目标行为 | 优先级 | 依赖 | 拟议里程碑 | 不确定性/所需研究 |
|---|---|---|---|---|---|---|
| GAP-F101 | 无 Cargo workspace 或 planned crates | 建立单向依赖的 core/crypto/shadowsocks/socks5/runtime/config/observability crates 和两个 composition roots | P0 | ADR、MSRV/dependency decisions | M0 | trait seam 的精确所有权与 static/dynamic dispatch 边界 |
| GAP-F102 | 无二进制或配置入口 | 独立 client/server；typed TOML 完整语义校验可在不绑定 listener 时运行 | P0 | GAP-F101 | M0 | CLI 名称/退出码、schema、secret input 与默认值 |
| GAP-F103 | 无用户可见数据路径 | SOCKS5 TCP `CONNECT` → SIP022 TCP → server direct outbound 可完成 local echo | P0 | GAP-C001-C003、GAP-F101-F102 | M0 | domain/DNS 已延期；IPv4 reply mapping/BND contract 已在 M0 冻结 |
| GAP-F104 | 无 cipher 支持 | 三个且仅三个指定方法共享经过验证的 TCP state machine | P0 | M0 AES-128 seam | M1 | 方法无关抽象是否保持 hot path 深度 |
| GAP-F105 | 无 UDP 协议 API | 三个方法的 client/server UDP protocol path 与 direct UDP echo；不新增 public UDP inbound | P0 | M1 shared boundary | M2 | public protocol API 与 session ownership |
| GAP-F106 | 无外部互操作 harness | 完成 24 个必需组合；固定 reference version/checksum、方向、fixture 和诊断证据 | P0 | runnable paths、external runners | M0 subset，M1/M2 full | 参考版本、CI 可用性、端口隔离和网络依赖策略 |

## 运维、平台与性能差距

| ID | 当前行为与证据 | 目标行为 | 优先级 | 依赖 | 拟议里程碑 | 不确定性/所需研究 |
|---|---|---|---|---|---|---|
| GAP-O201 | 无 Cargo manifest/CI；三条 quick gate 因缺 manifest 失败 | committed lockfile 下 quick/full gate 可运行且 required jobs 不被静默跳过 | P0 | GAP-F101 | M0 | CI provider/runner、job timeout 与 artifact policy |
| GAP-O202 | 本机仅安装 Windows Rust targets；无 target build 证据 | Linux x86_64 glibc、Linux x86_64 musl、Windows locked build 和 artifact config smoke 通过 | P0 | portable implementation/toolchain setup | M0 smoke，M3 qualification | 精确 triples、linker、native runner 与 cross strategy |
| GAP-O203 | 无 stable config/log/metrics contract | 最终 schema、error/exit semantics、tracing fields、Prometheus exposition 和 label set 可兼容验证 | P1 | M0 minimal contract、TCP/UDP runtime | M3 | metrics listener 默认策略与兼容性承诺 |
| GAP-O204 | 无外部 fixture/provenance 管理 | KAT、interop fixture、synthetic secret 均记录来源、checksum、license 与 expected result | P0 | protocol test plans | M0-M2 | 可提交 fixture 的许可边界 |
| GAP-P201 | 无 benchmark harness 或 reference baseline | pinned comparable shadowsocks-rust loopback TCP 基线；ferrum2 aggregate throughput ≥90% | P0 release gate | feature/platform freeze | M4 | 硬件、版本、连接数、预热/重复和统计方法 |
| GAP-P202 | 无 10,000 idle session 资源测量 | 预先定义采样窗口内 task/memory 不持续增长，且结果可复现 | P0 release gate | stable runtime/observability | M4 | “稳定”的数值阈值、FD/socket 观测和 soak 时长 |

## 决策与剩余研究/原型需求

M0 plan 已处置：

1. **Resolved：**SIP022 official-site commit/blob、Rust 1.97.1、MSRV 1.85.0、
   exact dependencies 与 GPL metadata，见 ADR-0001/upstream baseline。
2. **Resolved：**workspace DAG、core RPITIT ownership 与 T01 manifest lock，
   见 ADR-0001/SPEC-0001。
3. **Resolved：**secret/key-provider、clock/CSPRNG seam，见 ADR-0002。
4. **Resolved：**typed TOML schema、`--check-config`、defaults/ranges、0/1/2 exits
   与 redacted error taxonomy，见 ADR-0003。
5. **Resolved：**exact replay capacity/TTL/order、single I/O、zero-linger、response
   binding，见 ADR-0004。
6. **Resolved：**task ownership、timeouts/buffers、half-close/backpressure、
   tracing/metrics，见 ADR-0005。
7. **Resolved：**reference versions/checksums、fixture provenance、unavailable policy
   与三个 M0 target smoke，见 ADR-0006/TEST-0001。

后续里程碑仍须决定：

1. **M2 plan：**UDP protocol API、session/window size、buffer/queue/idle limits
   和并发回收策略。
2. **M3 plan：**M0 三 target build/config smoke 之外的 full native lifecycle、
   packaging 和最终 operator compatibility qualification。
3. **M4 plan：**benchmark 主机、reference config、warm-up、repetition、
   aggregation、稳定阈值和结果归档契约。

## 优先级结论

所有产品差距当前仍是未开始，但 M0 已完成 pre-implementation contract gate。
最小可执行 frontier 是 M0-T01（locked workspace/core），完成后开放
T02/T05/T06 的 non-overlapping wave；T02完成后再开放T03/T04。其余方法、UDP、
完整平台与性能门保持在后续里程碑，不得从 v0 范围移除。
