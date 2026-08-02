# ferrum2 v0 preview 产品愿景

## 问题与目标用户

Shadowsocks 2022 的部署者需要一个高性能、可审计、可运维的 Rust
实现：它应严格遵守 SIP022，而不是以“能够连接”代替协议正确性；它还应在资源受限、
连接数很高和恶意输入存在时保持边界清晰、失败关闭且不会泄露秘密。

v0 面向两类用户：

- 通过 SOCKS5 TCP `CONNECT` 使用自托管代理的运维者；
- 需要嵌入、互操作验证或继续扩展 Shadowsocks 2022 TCP/UDP 协议层的维护者。

## 期望结果与成功度量

v0 只有在以下结果都有直接证据时才算完成：

1. 独立的 `ferrum2-client` 和 `ferrum2-server` 能把 SOCKS5 TCP
   `CONNECT` 经 Shadowsocks 2022 TCP 转发到 server 的 direct outbound。
2. TCP 和 UDP 协议层均支持且仅支持
   `2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm` 和
   `2022-blake3-chacha20-poly1305`。
3. 三种方法、两种 transport、两个参考实现和两个通信方向组成的 24 个必需互操作项
   全部通过；UDP 在 v0 可通过协议 API 测试，不暗示存在公开 UDP inbound。
4. 两个二进制都能在不创建 listener 的情况下完成 typed TOML
   配置的完整语义校验，并提供不泄密的结构化 `tracing` 日志和低基数
   Prometheus 兼容指标。
5. Linux x86_64 glibc、Linux x86_64 musl 和 Windows 的 locked
   构建及约定的 artifact smoke test 均通过。
6. 在固定、同机、可复现的配置下记录 ferrum2 与可比 shadowsocks-rust 的
   loopback aggregate TCP throughput、比值和差距；该比值不阻塞 v0 preview。
   10,000 个空闲 TCP session 通过 M4 定义的单主机、有界资源资格；不另设
   多平台或开放时长的 long soak。
7. 安全、重放防护、边界检查、背压、取消、半关闭和优雅关闭的负向测试通过；
   skipped 或缺失的 required gate 不算通过。

## 产品原则

- **协议正确性先于覆盖面和性能。** SIP022 是 wire contract；认证、重放和
  detection-prevention 行为不得为 benchmark 让步。
- **先认证和校验，再产生副作用。** target connect、peer-controlled allocation、
  forwarding 和 accepted-session 状态变更都发生在认证及完整语义校验之后。
- **秘密默认不可观察。** PSK、派生 key、salt、nonce 和 secret-bearing config
  不进入日志、错误、panic、trace 或 metric labels；destination 不成为
  metric label。
- **资源必须有界且生命周期可证明。** 队列、buffer、UDP session、idle lifetime
  和任务终止路径都有明确上限或 owner。
- **用纵向切片降低不确定性。** 每个里程碑交付可执行、可观察、可独立验收的行为，
  并尽早使用参考实现和目标平台验证边界。
- **声明必须可复现。** 互操作版本、fixture 来源、toolchain、target、benchmark
  配置和验证命令均需固定并留存证据。

## v0 范围

- SIP022 TCP 与 UDP framing、codec、认证、重放防护和 transport state machine；
- 三个指定密码套件及其精确 key 长度、key derivation 和 audited AEAD boundary；
- SOCKS5 TCP `CONNECT` client inbound；
- 独立 client/server 二进制和 server minimal direct outbound；
- 单 PSK，同时保留无需重写 transport state machine 的 key lookup seam；
- Serde-backed typed TOML、listener 启动前完整校验；
- Tokio multi-thread runtime、owned/reusable buffers、必要时使用 `socket2`；
- structured `tracing`、Prometheus-compatible bounded-cardinality metrics；
- sing-box 与 shadowsocks-rust 的双向 TCP/UDP 互操作；
- Linux x86_64 glibc、Linux x86_64 musl、Windows 构建；
- 可复现吞吐、任务数和内存基线。

## 明确非目标

- SOCKS5 `UDP ASSOCIATE` 或其他公开 UDP inbound；
- SIP023 Extensible Identity Headers、多用户或多 PSK 产品行为；
- multi-inbound、multi-outbound、routing rules、DNS proxy/resolver、多个
  upstream、load balancing、proxy chaining、hot reload 和 management API；
- Linux transparent inbound、Windows TUN 或其他设备/内核流量入口；
- reduced-round ChaCha、custom executor 和 `io_uring`；
- 没有独立 ADR、安全论证和 benchmark 证据的 `unsafe`；
- v0 路线图之外的部署编排、远程控制面或发布自动化。

## 兼容性与上游关系

[SIP022](https://shadowsocks.org/doc/sip022.html) 是规范性 wire contract。
ferrum2 独立实现协议核心，不依赖其他代理项目的 Shadowsocks protocol core。
sing-box 和 shadowsocks-rust 仅作为兼容性研究、互操作和性能比较对象；任何参考
代码或 fixture 都必须记录 provenance 并经过 license review。实现差异不能通过
静默偏离 SIP022 来解决，必须进入显式 ADR/spec 决策。

M3 close 时由对应 binary 接受的所有 `schema_version = 1` 配置构成 preserved
cohort：它们在全部 v0.x 中继续有效；successor schema stable 发布后，移除支持
还必须同时等待至少 12 个月和至少两个 stable minor releases，并提前一个
stable release 发出 deprecation notice。后续 v1 可以添加 optional sections/
fields或安全放宽 endpoint domain，但省略新增项时必须保留 cohort 的 effective
behavior；breaking change 使用显式新 schema version，不使用 heuristic
fallback、静默 reinterpret 或自动重写。当前单 listen、单 server、IPv4
operator endpoint、两个 binary roots 和 workspace member 数量是现状而非永久
拓扑。

## 约束

- 使用 stable Rust Cargo workspace；MSRV 和依赖版本在 authoritative
  manifests 中固定，应用仓库提交 `Cargo.lock`。
- workspace 级 `unsafe_code = "forbid"`；例外只能位于隔离的性能 crate，
  并经过既定 ADR 和 focused review。
- dependency direction 是 binaries/runtime 指向 protocol/core；
  `ferrum2-core` 不依赖 concrete protocol、cipher、config format 或 async
  runtime implementation。
- crypto crate 不拥有 socket 或 policy；protocol crate 不拥有 routing policy、
  process-global runtime state 或 CLI concerns。
- host-local quick/full 命令以 `docs/agents/milestone-workflow.md` 为准；外部
  互操作、target matrix、security 和 performance gates 是其补充而不是替代。
- 许可证为 `GPL-3.0-only`；examples、tests 和 fixtures 只能使用明确的 synthetic
  secrets。
- M0 规划前仓库基线
  `master@b41c6127b1834ebd97246451fd92bafea50cb205` 只有工作流控制面，
  没有 Cargo workspace 或产品实现；M0 的集成与资格证据由 roadmap、CI status
  和 milestone handoff 记录。

## 里程碑地图

| 里程碑 | 可独立验收的结果 | 状态 |
|---|---|---|
| M0 | AES-128-GCM TCP 安全纵切：离线配置、SOCKS5、独立两端、direct outbound、最小观测、互操作与平台冒烟 | closed |
| M1 | 三种方法的完整 TCP 行为和完整 TCP 互操作矩阵 | closed |
| M2 | 三种方法的 UDP 协议 API、bounded session/replay state 和完整 UDP 互操作矩阵 | closed |
| M3 | 稳定运维契约、生命周期证明和三目标平台资格 | closed |
| M4 | 可复现性能基线、资源门与 v0 preview integrated qualification | closed |

这些状态是证据状态。M0 已由同一集成 SHA 的本地、互操作与三平台证据关闭；
M1 已由 exact `874c83d0ee71054bd702d6ecac55e88d9e2fbcef` 的本地 full、
Rust 1.85、三平台和 12/12 TCP 互操作证据关闭。M2 已由 exact
`7907cda05a56e1c3b85af2dd8faeb85a385154b7` 的本地 full、Rust 1.85、
Windows/Linux GNU/Linux musl、TCP 与 UDP 各 12/12，以及 IPv4
Shadowsocks UDP ingress 到 IPv6-only direct target 的三报文 real-process
证据关闭。M2 的 ADR-0020～0022、SPEC/TEST-0003 和 M2-T01～T06 均保持
accepted/approved/done。

M3 已由 remotely qualified product SHA
`d9e59d787c3fe78dfca778ee8a36668a45387368` 关闭产品与 release 结果：
GitHub Actions run `30494736004` attempt `1` 在同一 SHA 上通过 quality、
MSRV、Windows MSVC、Linux GNU、Linux musl、TCP/UDP interop 和 final
qualification。Local integrated/evidence source
`d784b06171723bb93fd467cea1a799f58f7d60b0` 仅增加执行证据文档；M3-T01～T03、
T05～T08 为 `done`，T04 保持诚实 `deferred` 并由 fresh-review T06 replacement
交付其产品结果。Close Product/Architect/QA verdicts 分别为
`PASS_WITH_NOTES`、`PASS_WITH_NOTES`、`PASS`，无 blocker/major；完整状态见
M3 handoff。M4 由 exact `9b379a426853d86a184464f6fd8c73081b464535`
automatic push run `30730883667/1` 关闭：performance、Full/security/process、
MSRV、TCP/UDP `24/24`、三平台、test budget 与 final qualification 在同一 SHA
全部通过。Ferrum2/reference medians 为 `50860305/476470749` bytes/s，ratio
`0.106743814` 仅作诊断；selected THP apply/restore、exact 10k、`180/180`、
`6/6`、drain 与 cleanup 通过。M4 qualified but did not package or publish the v0
preview；remote scope 已消费撤销。
