# ADR-0001: M0 workspace、工具链与模块拓扑

- **Status:** Accepted
- **Date:** 2026-07-27
- **Owners:** Architect / Team Lead
- **Related milestone/spec/tickets:** M0；`docs/specs/SPEC-0001-m0-aes128-tcp-vertical-slice.md`；M0-T01～M0-T08；关闭 DEC-001、DEC-002；direct dependency baseline 与 manifest ownership 条款被 ADR-0009、ADR-0011、ADR-0013 部分取代

## Context and problem

仓库目前只有工作流控制面。M0 必须在不扩大 v0 范围的前提下建立首个 Rust
workspace，并使 AES-128-GCM TCP 纵切可以按非重叠 ownership 并行实现。若工具链、
依赖版本、crate 方向或核心接口留给 Engineer 临场决定，`Cargo.lock` 会成为并行
写热点，协议、runtime 和 composition seam 也无法独立验收。

规范及上游事实的完整来源记录在
`docs/research/M0-upstream-baseline.md`。本 ADR 接受其中 2026-07-27 的固定基线。

## Decision drivers and invariants

- 使用 stable Rust、Tokio 多线程 runtime、owned/reusable buffers，且 workspace
  `unsafe_code = "forbid"`。
- `ferrum2-core` 不依赖 Tokio、配置格式、具体 protocol/cipher 或 composition root。
- crypto 不拥有 socket、路由或进程级策略；protocol 不拥有 CLI 或全局 runtime。
- per-frame/per-packet hot path 优先 static dispatch；trait object 仅能出现在进程组合
  seam，且 M0 不需要它。
- 所有应用 crate 采用 `GPL-3.0-only`、`publish = false`；提交 `Cargo.lock`。
- 三个目标是 `x86_64-pc-windows-msvc`、`x86_64-unknown-linux-gnu`、
  `x86_64-unknown-linux-musl`。

## Options considered

### Option A：七个 deep crates、两个 composition roots 和一个测试 harness

核心契约、密码、协议、SOCKS5、runtime、配置、可观测性各有单一 ownership，
二进制只负责组合，外部进程测试由独立的非发布 workspace member 驱动。

### Option B：先在两个二进制内完成纵切，再抽取 crates

文件较少，但会复制 wire、错误、lifecycle 和 secret 知识；M1/M2 必须大规模迁移，
且无法在 M0 证明未来方法/UDP 不会重写状态机。

### Option C：先横向创建所有 v0 cipher/transport 抽象

会在没有端到端行为和互操作反馈时扩大范围，产生无法独立验收的脚手架。

## Decision

### 规范、Rust 与 workspace policy

- SIP022 固定到官方站点仓库 commit
  `34598d65054dad975d330ff9d7317b0d41cf1efd`，文件
  `docs/doc/sip022.md` 的 Git blob 为
  `f6b203facf219fe47bfe2913c2e576240d2bf1f9`。live 页面只作导航，固定文件才是
  M0 wire contract。
- `rust-toolchain.toml` 固定 Rust `1.97.1`、`profile = "minimal"`、
  `rustfmt`/`clippy`，并列出三个目标。它是可复现开发/构建 compiler。
- workspace `edition = "2024"`、`resolver = "3"`、
  `rust-version = "1.85.0"`。1.85.0 是 MSRV，必须用真实 locked graph 编译验证，
  不得使用 `--ignore-rust-version`。
- root workspace metadata 统一 `license = "GPL-3.0-only"`、
  `publish = false`；T01 增加 GPL-3.0-only `LICENSE`，所有本项目 package 继承。
- `[workspace.lints.rust] unsafe_code = "forbid"`，所有 members 以
  `[lints] workspace = true` 继承。
- `[workspace.dependencies]` 使用 exact requirements，完整 transitive graph 由
  committed `Cargo.lock` 固定。禁止 `full` feature、OpenSSL/native TLS、
  `async-trait`、`io_uring` 和未使用 optional dependency。

M0 原始批准的 direct dependency baseline 如下；member 只声明实际使用的条目。
ADR-0009 部分取代本段：在不改变既有版本/feature 的前提下，额外增加 exact
`aes 0.9.1` 与 `ghash 0.6.0` no-default `zeroize` direct feature anchors，并只对
这两个不直接导入 Rust symbols 的安全 anchors 建立窄例外。当前规范性 dependency
surface 必须联合读取本表与 ADR-0009：

| Crate | Exact version | Feature contract |
|---|---:|---|
| `tokio` | `1.53.1` | production no-default；`rt-multi-thread,macros,net,io-util,sync,time,signal`；`ferrum2-runtime`及ADR-0013限定的两个T07 binary dev-dependency可额外启用`test-util` |
| `bytes` | `1.12.1` | default `std` |
| `socket2` | `0.6.5` | default；不启用 `all` |
| `serde` | `1.0.229` | no-default；`std,derive` |
| `toml` | `1.1.3+spec-1.1.0` | Cargo requirement `=1.1.3`；no-default；`std,serde,parse` |
| `tracing` | `0.1.44` | no-default；`std` |
| `tracing-subscriber` | `0.3.23` | no-default；`fmt,json,env-filter` |
| `prometheus-client` | `0.25.0` | no-default；不启用 protobuf |
| `aes-gcm` | `0.11.0` | no-default；`aes,bytes,zeroize` |
| `blake3` | `1.8.5` | no-default；`std,zeroize` |
| `base64` | `0.23.0` | no-default；`std` |
| `zeroize` | `1.9.0` | no-default；`alloc,derive` |
| `getrandom` | `0.4.3` | no-default；`std` |
| `clap` | `4.6.4` | no-default；`std,derive,help,usage,error-context` |
| `thiserror` | `2.0.19` | default `std` |

Test-only exact dependencies 为 `hex = 0.4.3`、`serde_json = 1.0.151`、
`tempfile = 3.27.0`。M0 不直接引入 `rand`、`secrecy`、`subtle`、
`metrics`/`metrics-exporter-prometheus`、Hyper 或另一个任务运行器。

### Workspace members 与依赖方向

workspace members 固定为：

- `bins/ferrum2-client`
- `bins/ferrum2-server`
- `crates/ferrum2-core`
- `crates/ferrum2-crypto`
- `crates/ferrum2-shadowsocks`
- `crates/ferrum2-socks5`
- `crates/ferrum2-runtime`
- `crates/ferrum2-config`
- `crates/ferrum2-observability`
- `tests/m0-harness`

依赖方向为：

```text
bins ───────────────→ config, observability, runtime, socks5/shadowsocks
tests/m0-harness ───→ metadata/filesystem/process artifacts；无concrete crate Cargo dependency
config ─────────────→ core, crypto
socks5 ─────────────→ core
shadowsocks ────────→ core, crypto
runtime ────────────→ core（metrics socket接收generic renderer，不反向依赖observability）
observability ──────→ tracing, tracing-subscriber, prometheus-client
crypto ─────────────→ cryptographic/secret dependencies only
core ───────────────→ std, bytes
```

concrete protocol 与 Tokio I/O 的适配通过 binary composition 的泛型实例化完成；
不得令 `core` 反向依赖 concrete crate。`socket2` 只由 runtime 的 socket adapter
使用。

`tests/m0-harness`始终是黑盒/metadata harness：其Cargo manifest不得对任何
`ferrum2-*` library/binary package声明path dependency或dev-dependency。T01 static
tests因此可在future target source缺失时编译。T07/T08 required jobs先显式build
binary artifacts，再由harness根据workspace target directory与platform executable
suffix定位并spawn；路径缺失直接失败。

### Core contract

T01 在 `ferrum2-core` 冻结以下语义；精确 Rust 定义可按借用检查器调整，但不得改变
ownership 或 dependency direction：

```rust
pub struct Session<S, R> {
    pub target: TargetAddr,
    pub stream: S,
    pub initial_payload: Bytes,
    pub reply: R,
}

pub trait Inbound<IO>: Send + Sync {
    type Stream;
    type Reply: SessionReply;
    type Error;
    fn accept(&self, io: IO)
        -> impl Future<Output = Result<Session<Self::Stream, Self::Reply>, Self::Error>>
             + Send;
}

pub trait Outbound: Send + Sync {
    type Stream: LocalEndpoint;
    type Error;
    fn open(&self, target: &TargetAddr)
        -> impl Future<Output = Result<Self::Stream, Self::Error>> + Send;
}

pub trait Connector: Send + Sync {
    type Stream: LocalEndpoint;
    fn connect(&self, target: &TargetAddr)
        -> impl Future<Output = Result<Self::Stream, ConnectError>> + Send;
}

pub trait LocalEndpoint {
    fn local_endpoint(&self) -> std::net::SocketAddrV4;
}

pub trait AbortiveClose {
    type Error;
    fn mark_abortive(&mut self) -> Result<(), Self::Error>;
}
```

`SessionReply` 以 consuming self保证至多一次回复：

```rust
pub trait SessionReply: Sized {
    type Error;
    fn succeeded(self, bound: std::net::SocketAddrV4)
        -> impl Future<Output = Result<(), Self::Error>> + Send;
    fn failed(self, kind: ConnectErrorKind)
        -> impl Future<Output = Result<(), Self::Error>> + Send;
}
```

`TargetAddr` 能表达 IP 与 bounded domain，且不实现会泄露原值的 `Display`；
M0 的 SOCKS 和 connector 行为只接受 IPv4。runtime connector 必须在返回 stream
前读取并验证 socket local endpoint 为 IPv4，将其存入实现 `LocalEndpoint` 的
owned wrapper；读取失败或结果非 IPv4 时 connect 失败，因此任何 SIP022 first-write
尚未发生。协议 stream wrapper 逐层委托该 capability。composition 在 outbound
open 成功后把存储的 endpoint 传给 consuming `SessionReply::succeeded`，SOCKS crate
无需依赖 runtime/socket type。traits 使用 RPITIT/static dispatch，不使用
`async-trait`。

`AbortiveClose`是protocol-neutral transport capability：它只把owned transport标记
为drop时执行abortive close，不引用Shadowsocks error/reason。protocol一旦调用成功
或失败都必须立刻进入terminal state并返回，不能继续复用transport。runtime的safe
socket adapter实现它，fake transport记录调用；core不依赖socket2或Tokio。

### Manifest ownership 与 transient workspace state

M0-T01 独占 root manifest、lockfile、toolchain、license、全部初始 member manifests
和 `ferrum2-core`。每个后续 member manifest用explicit `[lib]`/`[[bin]]` path声明
最终owner将创建的target source；T01不创建、format或compile这些尚未实现的source。
Cargo metadata与lock resolution不要求explicit target path已经存在，因此T01可以
独立验证完整member/DAG/locked dependency graph，同时不越过下游ownership。

这是有意的transient state：T01只要求metadata、core和architecture-policy tests
通过，workspace quick gate要到T07汇合全部source后才应通过。后续integration tests
使用Cargo auto-discovery，不需改manifest。

后续并行 ticket 不得修改T01拥有的manifest/lock路径。若实现发现遗漏dependency或
target，当前wave必须停止，由Team Lead先修订contract并安排一个独占manifest变更；
不得由多个Engineer竞争`Cargo.lock`。ADR-0009 是该流程的首次窄执行：仅授权一个
T01 writer 增加两个 fixed-version zeroize feature anchors、更新 lock representation
与 workspace-policy evidence。ADR-0011 随后只把harness manifest、对应policy与
唯一two-edge lock hunk转交T07；ADR-0013再只把两个binary manifests的exact
Tokio `test-util` dev edges转交同一个T07 writer，且不允许新增lock hunk。

## Consequences and tradeoffs

### Positive

- 每个后续 ticket 有独立 crate/source ownership，首个依赖 wave 可安全并行。
- MSRV、当前 compiler、release targets 和依赖供应链各有独立、可复现的 gate。
- M1 增加 cipher、M2 增加 UDP 时保留 core 和 composition seam。

### Negative

- T01 必须在任何产品行为前一次性建立所有 manifests 与 dependency lock。
- exact pins 需要显式升级流程；`prometheus-client`/`blake3` 未声明的 MSRV 必须靠
  实际 1.85.0 gate 证明。
- RPITIT/static dispatch 会增加泛型类型复杂度，但避免 hot path trait-object 成本。

## Compatibility and upstream divergence

参考实现只用于黑盒互操作，不能决定模块边界。ferrum2 不复制其 protocol core。
依赖的 source license/provenance 必须在 T01 对完整 locked graph 审核；本 ADR
记录上游声明，不替代法律审查。

## Migration and rollback

仓库没有现存 Cargo 或持久数据，首次建立无需迁移。回滚是回退 M0 integration
commit；之后调整成员、MSRV、direct dependency 或 dependency direction 必须用
新 ADR supersede 本记录。

## Verification plan

- M0-WS-001、M0-WS-002：workspace member/DAG/policy 静态测试。
- M0-MSRV-001：Rust 1.85.0 对 locked graph 的 check 和 test。
- M0-PLAT-001～003：Rust 1.97.1 三目标 release binary build/artifact smoke。
- `workflow.toml` quick/full commands 在同一 integration commit 通过。

## References

- `AGENTS.md`
- `workflow.toml`
- `docs/research/M0-upstream-baseline.md`
- [固定 SIP022 文件](https://github.com/shadowsocks/shadowsocks-org/blob/34598d65054dad975d330ff9d7317b0d41cf1efd/docs/doc/sip022.md)
- [Cargo `rust-version`](https://doc.rust-lang.org/cargo/reference/rust-version.html)
- [Rust platform support](https://doc.rust-lang.org/rustc/platform-support.html)
