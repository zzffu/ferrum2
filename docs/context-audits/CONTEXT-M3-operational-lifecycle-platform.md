+++
milestone = "M3"
goal = "稳定 v0 运维合同、资源生命周期和 Linux GNU、Linux musl、Windows 三目标平台资格，同时保留未来拓扑演进空间"
status = "approved"
baseline_commit = "3a877b6beeb955b5237ab4048f8dec02a92f06b6"
verified_commit = ""
before_context_sha256 = "b58311d6db1eaffb4188ff5885aaf92169d9a8e62a79acba544b37f814483ea1"
after_context_sha256 = "aa9bd4cb87d19ca5dd134e9eb6435f45e51ae422a691903a4107bebcc9bdac86"
entries = [
  "Product purpose",
  "Primary languages/frameworks",
  "Architecture entry points",
  "Critical invariants",
  "Generated files",
  "Local development setup",
  "Active planned changes",
]
reviewers = ["product_manager", "architect", "qa"]
+++

# Context audit: M3 — operational lifecycle and platform qualification

本审计证明：在批准 M3 计划前，Team Lead 已把 `## Project-specific context`
的每个顶层条目与仓库证据逐项比较，并将未实现的 M3 意图仅放入
`Active planned changes`。

## Feature request

- Requested outcome：稳定现有 schema v1 运维合同，建立可复用的事务式资源
  生命周期，并完成三目标平台资格。
- User/operator value：已有合法配置可继续升级；启动、失败、取消与关闭可诊断且
  不泄漏资源；release artifacts 在三个目标上具有可复现证据。
- Scope boundary：保留 multi-inbound/outbound、routing、DNS、Linux transparent
  inbound 和 Windows TUN 的演进路径，但 M3 不实现这些能力。
- Milestone：M3。

## Repository baseline

- Exact baseline commit：
  `3a877b6beeb955b5237ab4048f8dec02a92f06b6` on `master`。
- Manifests/build：`Cargo.toml`、`Cargo.lock`、`rust-toolchain.toml`、
  `workflow.toml`、`.github/workflows/m0.yml`。
- Entry points：`bins/ferrum2-client`、`bins/ferrum2-server`、
  `crates/ferrum2-config`、`crates/ferrum2-observability`、
  `crates/ferrum2-runtime`。
- Evidence：config/CLI、tracing/metrics、runtime lifecycle/process lifecycle
  suites，platform fixtures，以及 M2 exact-SHA handoff/CI status。

## Entry-by-entry audit

| Entry | Classification before update | Repository evidence | Required update | Result after update |
|---|---|---|---|---|
| Product purpose | confirmed | workspace manifests、两 binary composition roots、TCP/UDP crates、M2 handoff | 无；M3 不冒充已交付能力 | shipped purpose 与 v0 non-goals 保持不变 |
| Primary languages/frameworks | confirmed | pinned Rust toolchain、Cargo graph、Tokio/Serde/tracing/Prometheus dependencies、workspace lint | 无 | authoritative framework facts 保持不变 |
| Architecture entry points | confirmed | 十个当前 members、core contracts、runtime owners、binary `run.rs` | 无；当前 member/binary 数量不升级为永久拓扑 | 仅描述当前已实现入口和 dependency direction |
| Critical invariants | confirmed | ADR-0002/0004/0005/0020～0022、security/replay/runtime tests | 无；M3 细化 lifecycle outcome，不改 wire/security | 既有安全、资源与 release invariants 保持约束 |
| Generated files | confirmed | `.gitignore`、Cargo `target/`、committed fixture provenance、无 generated source tree | 无；M3 platform logs/hashes 是 generated qualification artifacts | source/fixture 与 disposable evidence 边界保持清晰 |
| Local development setup | confirmed | `workflow.toml` quick/full、toolchain targets、Cargo-only workflow | 无 | host-local 与 hosted qualification 边界保持不变 |
| Active planned changes | missing | M3 在 roadmap 为 proposed，但该条目为 `None` | 增加一个 M3 planned 项并写清 topology non-freeze/non-goals | M3 仅作为 planned intent 记录 |

## Planned-feature placement

M3 请求仅写在 `Active planned changes`。现有单 listen、单 server、IPv4 operator
endpoint 和两个 composition roots 是当前 adapter；本审计不把 supervisor、
兼容期或平台资格写成 shipped fact。M3 close 时必须回到 exact integrated SHA
复核本表，把已证明事实移入当前状态条目并清除或推进 planned item。

## Context update summary

- Stale claims removed or corrected：无。
- Current facts added：无；现状条目已经与仓库一致。
- Planned-only statements added：M3 运维合同、事务式 supervisor、三目标资格及
  topology non-freeze 边界。
- Statements deliberately unchanged：产品范围、技术栈、模块入口、安全不变量、
  generated artifacts 和本地开发命令。

## Plan implications

- Product/roadmap：旧 v1 cohort 继续有效；未来拓扑通过兼容扩展或显式新 schema
  引入，M3 不提前实现。
- Architecture/ownership：config、observability、runtime、binary composition、
  platform qualification 五个 non-overlapping tickets。
- Invariants：semantic validation before resources；prepare/activate/rollback；
  single transitive ownership；monotonic cancellation/deadlines；grace/force/reap。
- Generated/tooling：native release binaries、hashes、linkage 与 lifecycle logs
  是不提交的 qualification artifacts；无需 archive/installer/publication。
- Validation：复用既有表格和 process seams；同一 exact SHA 运行 full、安全、
  TCP/UDP interop 与三目标 gates。

## Review verdicts

- Product Manager：PASS；范围、用户价值、五票依赖图与兼容期建议可执行。
- Architect：PASS；需要两个 ADR，禁止冻结当前拓扑，并识别 startup partial
  activation 风险。
- QA：PASS；现有 focused suites 全部通过，无 blocker/major；记录六项
  nonblocking planning notes。
- Team Lead：APPROVED；采用两 ADR、一个 spec/test plan、五票计划，并保持
  M4 performance/long-soak 与未来 topology features 明确延期。
