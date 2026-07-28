# ADR-0013: M0 binary paused-time test boundary

- **Status:** Accepted
- **Date:** 2026-07-27
- **Owners:** Product / Architect / Team Lead
- **Related milestone/spec/tickets:** M0；`SPEC-0001`；M0-T01、M0-T07；
  部分取代 ADR-0001 的 Tokio test/manifest baseline、ADR-0011 的
  “root/other member manifests unchanged”审查边界，以及 ADR-0012 的
  manifest/dependency non-goal；ADR-0016将两个exact dev edges定义为当前selected
  conformance profile而非永久唯一机制；不改变 ADR-0012 的 deadline/accounting
  semantics

## Context and problem

ADR-0012 与 TEST-0001 要求 T07 在两个 binary package 内用 Tokio paused time
确定性证明 configured connect deadline 与 fresh request-first-write deadline：
既要覆盖默认 10 秒/5 秒，也要用 non-default values 杀死 hardcoding。server
prefix idle/progress/cancel evidence 同样需要 paused time。

实现 preflight 发现：

- root workspace Tokio `1.53.1` 的 normal features 不含 `test-util`；
- 两个 binary 只有 normal `tokio.workspace = true`；
- `ferrum2-runtime` 虽有 Tokio `test-util` dev-dependency，但 Cargo dev edges
  是 package-local，targeted `cargo test -p ferrum2-client`/`ferrum2-server`
  不会继承另一个 package 的 dev edge；
- T07 当前不拥有 binary manifests，ADR-0001/0011/0012 又禁止相应修改。

因此批准的 paused-time test 无法编译，而把 `test-util` 加到 root 或 normal
dependency 会不必要地扩大 production feature graph。

## Decision drivers and invariants

- 必须保留 TEST-0001 的 deterministic paused-time evidence；不得改成 wall-clock
  sleep、借用 runtime package dev graph，或降低 default/non-default assertions。
- production Tokio version、source、checksum、root features、两个 binary normal
  declarations 与 release graph必须不变。
- T03 production code/dependency继续executor-neutral且不依赖Tokio time；
  既有T03 test-only Tokio edge不变且不得增加`test-util`。T06 source、manifest、
  relay topology 与 production feature graph不变。
- 不新增 package identity、dependency version、lock hunk、wire/config/API/metric/
  operator behavior或产品范围。
- 只允许一个 T07 manifest writer，且只能修改两个明确列出的 binary manifests。

## Options considered

### Option A: two binary-local Tokio dev edges

两个 binary 各自继承同一个 workspace Tokio，只在 dev dependency 上额外请求
`test-util`。resolver 3 使该 edge只参与该 package 的 test/dev-target graph。

### Option B: add `test-util` to root workspace Tokio features

会把 test-only capability传播到每个 normal inheritor和release graph，范围过宽。

### Option C: add `test-util` to binary normal dependencies

会直接扩大 production binary feature graph，不满足本决策的隔离目标。

### Option D: rely on runtime dev-dependency or move tests

Cargo 不会把 dependency package 的 dev edges传播给 targeted binary tests；把测试
移到 runtime 也不能证明 binary-local configured phase composition。

### Option E: wall-clock tests or a new injectable timer seam

wall-clock 会引入 flake 与长等待；新的 production timer abstraction 比两个
test-only manifest edges更广，并改变已批准的 composition seam。

## Decision

选择 Option A。M0-T07 获得以下两个路径的独占、一次性 ownership：

- `bins/ferrum2-client/Cargo.toml`
- `bins/ferrum2-server/Cargo.toml`

每个文件必须保留现有 normal declaration：

```toml
[dependencies]
tokio.workspace = true
```

并且只新增以下 test-only declaration：

```toml
[dev-dependencies]
tokio = { workspace = true, features = ["test-util"] }
```

约束为：

- member manifest不得写 Tokio version、source/path/git、rename、optional、
  target condition、`default-features` override、`full` 或除 `test-util` 外的
  member-only feature；
- root `Cargo.toml`、其他 member manifests、既有 normal dependency 与
  workspace Tokio features不得改变；
- `Cargo.lock` 不为本决策产生任何额外 hunk。T07 最终 lock diff仍只能是
  ADR-0011 批准的 `ferrum2-m0-harness` 两条 direct edge；package count与全部
  `(name, version, source, checksum)` identity tuples不变；
- manifest declaration policy、locked metadata dependency kind、production/test
  feature trees 与 LF/CRLF fixtures必须共同证明边界。仅观察 unified resolved
  test graph不足以证明 production 隔离。

resolver 3 下的数据流为：

```text
production build:
binary normal edge → workspace Tokio normal features → release binary

binary package test:
binary normal edge + same-package dev edge
  → same Tokio 1.53.1 identity + test-util
  → paused-time binary-private tests
```

## Consequences and tradeoffs

### Positive

- default/non-default deadlines与prefix idle semantics可用零wall-sleep的确定性测试。
- test capability位于消费 Tokio timer 的binary composition seam，不进入protocol。
- production dependency graph、package identities与lock representation不变。
- 形状与既有 `ferrum2-runtime` normal-plus-dev Tokio pattern一致。

### Negative

- 两个 member manifests各增加一个 intentional dev-kind metadata edge。
- test graph内 Cargo feature unification会让同一 Tokio package的`test-util`
  对该 test build可见；隔离证据必须查看排除dev edges的production tree。
- workspace-policy需要同时解析 dependency kind、manifest原文语义与feature tree，
  不能只看最终 unified node feature set。

## Compatibility and upstream divergence

本决策不改变 SIP022 wire、crypto/replay/detection/binding、SOCKS behavior、
timeout默认值/范围、error/observability mapping、task/buffer topology、metrics、
CLI/config、reference pins、platform matrix或remote authorization。

Tokio version与normal features保持原批准值。新增能力只用于本仓库 binary unit
tests，不构成对 sing-box、shadowsocks-rust 或 upstream Tokio behavior 的产品
compatibility claim。

## Migration and rollback

无 persisted-state、wire 或operator migration。回滚时删除两个 exact
`[dev-dependencies]` declarations及其 workspace-policy assertions；`Cargo.lock`
不得变化。若 paused-time evidence仍是M0 gate，则回滚同时恢复本合同矛盾并阻塞T07，
不得以real-time tests替代。

## Verification plan

候选实现必须同时满足：

```bash
cargo metadata --locked --format-version 1
cargo test -p ferrum2-m0-harness --test workspace_policy --locked
cargo tree -p ferrum2-client --locked -e normal,build,features -i tokio
cargo tree -p ferrum2-server --locked -e normal,build,features -i tokio
cargo tree -p ferrum2-client --locked -e all,features -i tokio
cargo tree -p ferrum2-server --locked -e all,features -i tokio
cargo build -p ferrum2-client --bin ferrum2-client --release --locked
cargo build -p ferrum2-server --bin ferrum2-server --release --locked
cargo test -p ferrum2-client --locked phase_deadline_contract
cargo test -p ferrum2-server --locked lifecycle_composition_contract
cargo check --workspace --all-targets --locked
cargo test --workspace --locked
```

Review还必须以 ADR-0013 Accepted commit 为固定base确认：

- production trees不含 `tokio feature "test-util"`，包含dev edges的两个 test
  trees各有该feature；
- 两个 manifests只有 exact dev declaration，normal declarations未变；
- root/其他 manifests不变；
- 除 ADR-0011 harness two-edge hunk外 `Cargo.lock` 无新增delta，110 identity
  tuples不变；
- `workspace_policy` 对两个 manifests 的 LF/CRLF positive fixtures给出相同PASS，
  并对缺失任一edge、extra/missing feature、normal/root移动、`full`、version/
  default/source/path/git/rename/optional/target/duplicate-table mutation给出相同FAIL。

## References

- `ADR-0001`：workspace Tokio baseline、resolver与manifest ownership。
- `ADR-0011`：T07 harness manifest/lock exception与LF/CRLF policy evidence。
- `ADR-0012`：binary configured phase deadlines与server prefix semantics。
- `SPEC-0001`、`TEST-0001`、M0-T01、M0-T07。
