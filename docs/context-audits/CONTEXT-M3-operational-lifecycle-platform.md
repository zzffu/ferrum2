+++
milestone = "M3"
goal = "稳定 v0 运维合同、资源生命周期和 Linux GNU、Linux musl、Windows 三目标平台资格，同时保留未来拓扑演进空间"
status = "verified"
baseline_commit = "3a877b6beeb955b5237ab4048f8dec02a92f06b6"
verified_commit = "d784b06171723bb93fd467cea1a799f58f7d60b0"
before_context_sha256 = "b58311d6db1eaffb4188ff5885aaf92169d9a8e62a79acba544b37f814483ea1"
after_context_sha256 = "ce9f3efc9040bf81dcbe8fabf6f1ece1a4dddd34667841d5cd4d292ea65ecd04"
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

本审计保留 planning 时的逐项清点，并在 M3 close 时把全部七个
`## Project-specific context` 顶层条目重新绑定到 exact repository evidence。
关闭源是本地 integrated/evidence commit
`d784b06171723bb93fd467cea1a799f58f7d60b0`；其直接父提交
`d9e59d787c3fe78dfca778ee8a36668a45387368` 是 remotely qualified product
SHA，GitHub Actions run `30494736004` attempt `1` 在同一 SHA 上完成全部七个
required jobs。两提交之间仅有五份执行证据文档变化，没有 product、test 或 CI
source delta。

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

## Planning entry-by-entry audit

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

Planning 时 M3 请求仅写在 `Active planned changes`。现有单 listen、单 server、
IPv4 operator endpoint 和两个 composition roots 被明确视为 current adapters，
没有被冻结为永久拓扑。Close 复核现已证明 supervisor、兼容合同和三目标资格，
因此这些事实进入当前条目，M3 planned item 被清除；M4 仍只是 roadmap
`proposed`，尚不是 active planned change。

## Close entry-by-entry verification

| Entry | Close classification | Exact evidence | Close result |
|---|---|---|---|
| Product purpose | missing current fact | ADR-0023；client/server CLI/config/observability contracts；`d9e59d78...` run `30494736004/1` | 增加 schema-v1/operator identity compatibility 与三目标 native qualification；publication 仍分离 |
| Primary languages/frameworks | confirmed | `Cargo.toml`、`Cargo.lock`、`rust-toolchain.toml`、workspace lints | 无修改；stable Rust/Cargo、Tokio、Serde、tracing、Prometheus、pure-Rust crypto 与 `unsafe_code = "forbid"` 保持准确 |
| Architecture entry points | missing current fact | `crates/ferrum2-runtime/src/process.rs`；两 binary `run.rs`；architecture tests | 增加 topology-neutral `ProcessRoot`/`PreparedProcessRoot`/`ProcessSupervisor` seam 与 current-adapter 边界 |
| Critical invariants | missing current fact | ADR-0023/0024、SPEC-0004、T01/T03/T06 evidence | 增加 preserved cohort/evolution、pre-resource validation、closed identities、prepare/rollback/ownership/cancel/grace/force/reap invariants |
| Generated files | stale/incomplete | `.gitignore`、`tests/platform/qualify_native.py`、run `30494736004/1` | “planned source tree”改为 current fact；native artifacts、hash/linkage/logs明确为不提交的 generated evidence |
| Local development setup | stale | `workflow.toml`、`.github/workflows/m0.yml`、`tests/platform/**` | 去除“harness 尚不存在”；hosted native/interop 补充但不替代 local quick/full |
| Active planned changes | stale | roadmap M3 ready-to-close evidence；M4 status `proposed` | 删除已完成 M3，设为 `None` |

## Close evidence and implications

- Product/operator：M3 close 时 parser-accepted 合法 v1 cohort 继续受
  ADR-0023 的 v0.x 与 successor window 保护；future topology 通过兼容扩展或
  explicit new schema 演进。
- Architecture/ownership：`ProcessSupervisor` 是 topology-neutral deep seam；
  所有 roots prepare-before-poll，失败 reverse rollback，active work 只有一条
  transitive owner/cancellation lineage，并使用一个 absolute grace deadline。
- Validation/observability：完整 semantic validation 先于 subscriber/runtime
  与任何资源；CLI exit、closed diagnostics/traces 和十四 metric families 保持
  redacted、bounded-cardinality identity。
- Qualification：exact `d9e59d78...` run `30494736004/1` 的 quality、MSRV、
  Windows MSVC、Linux GNU、Linux musl、TCP/UDP interop 与 final qualification
  全部 success；failed runs `30472227257/1` 和 `30476271774/1` 不参与拼接。
- Generated/tooling：native binaries、SHA-256、linkage 与 lifecycle logs 是不提交
  的 qualification artifacts；archive、installer、signing、upload、release 和
  publication 均未执行。

## Close review verdicts

- Product Manager：`PASS_WITH_NOTES`；八项 exit criteria 全部 PASS，close
  context/docs/baseline 同步为非阻塞动作。
- Architect：`PASS_WITH_NOTES`；无 blocker/major；唯一 note
  `ARCH-M3-CLOSE-N01` 是 T06 completion evidence 中一个 SHA 字符的机械勘误。
- QA：`PASS`；十项 MUST、same-SHA hosted convergence、ticket/review/root、
  milestone budget 与七项 context inventory 均通过。
- Team Lead：接受三方结论，修正 note，更新全部七项 context，并将 audit
  `approved` → `verified`。关闭后 hash 为
  `ce9f3efc9040bf81dcbe8fabf6f1ece1a4dddd34667841d5cd4d292ea65ecd04`。
