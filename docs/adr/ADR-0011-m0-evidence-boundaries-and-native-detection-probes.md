# ADR-0011: M0 evidence boundaries and native detection probes

- **Status:** Accepted
- **Date:** 2026-07-27
- **Owners:** Product / Architect / Team Lead
- **Related milestone/spec/tickets:** M0；`SPEC-0001`；M0-T01、M0-T03、
  M0-T06、M0-T07；部分取代 ADR-0001 的 harness dependency/manifest ownership、
  ADR-0004 的 native probe construction，以及 ADR-0005 的 lifecycle evidence
  allocation；ADR-0010 的 production protocol interface 不变；本ADR关于
  root/其他member manifests不变的审查边界被ADR-0013的exact binary dev edges
  部分取代；本ADR的M0-LIFE-005 exact-rebind probe与harness dependency/lock
  allowlist被ADR-0015部分取代；ADR-0016再将具体evidence mechanism和test-only
  allowlist降为selected conformance profile，其余结果性决定继续规范；
  ADR-0017删除whole-workflow/snapshot scope self-audit，并将external
  qualification改为Cargo-managed、普通workspace test不执行、仅hosted运行的
  non-test binary；结果性security/lifecycle/native detection决定不变

## Context and problem

T07 composition preflight 暴露两个不可由现有合同诚实证明的要求：

1. 黑盒 child-process harness 能证明 process exit、端口可重绑和临时目录清理，
   但不能观察进程内 owner task、buffer、permit、listener 或 `JoinSet` 状态。
2. 已提交的固定 SIP022 fixture 使用历史 timestamp。只截断或翻转它的密文只能
   可靠触发 short/authentication；不可能在不重新认证的情况下证明 current-time
   invalid type、stale timestamp 或 authenticated length semantic branch。

把内部 counters 暴露为 CLI、metric、HTTP、environment variable 或 test IPC 会扩大
operator/security surface；让 harness 链接 `ferrum2-*` production crate 则会破坏
ADR-0001 的黑盒边界并使 native protocol evidence 循环依赖被测实现。

这些是 M0 evidence seam 的窄缺口，不改变产品、wire、密码、error taxonomy、API、
runtime topology 或平台范围。用户已授权 M0 内后续本地窄 blocker 修复；远程授权
仍只适用于 T08 全部门禁通过后的 exact integration SHA。

## Decision drivers and invariants

- evidence只能声称test seam真实观察到的状态；黑盒外观不能替代进程内直接证据。
- native probe必须对authenticated branch有独立construction proof，不能循环调用
  被测production encoder。
- 不新增operator/public binary surface或`ferrum2-*` harness dependency。
- production package identity、resolved crypto features、wire、API与task topology不变。
- test dependency/lock exception必须exact、可机器拒绝任何额外edge或line-ending绕过。

## Options considered

### Option A：compositional lifecycle evidence + primitive-only generator

由黑盒process、T06 direct runtime和binary-private production composition三段证据
共同覆盖lifecycle；harness只用已锁定primitive独立构造current-time probes。

### Option B：公开内部counters或test control surface

拒绝。CLI、HTTP、metric、environment variable或test IPC会增加operator/security
surface，且baseline-only counter容易形成未接入production path的假阳性。

### Option C：harness链接production crate或复用stale fixture

拒绝。前者使证据循环并改变workspace dependency topology；后者无法认证
type/time/length semantic branches。新增manifest dependency但宣称lock
byte-identical同样不可实现。

## Decision

### Compositional lifecycle evidence

M0-LIFE-005 是三组直接证据的合取，任何一组都不能替代另一组：

1. `lifecycle_cycles` 运行恰好 100 个 deterministic real-process cycles：
   success、authentication reject、connect failure、cooperative cancellation、
   forced termination 各 20 个。每个 child 都有 deadline、被显式 wait/reap；
   proxy、metrics、target 三类原地址均能精确重绑，temporary path 已不存在，
   harness 自身 child registry 回到起始值。
2. T06 的 production runtime tests 直接检查真实 `OwnerRegistry`、relay buffer、
   semaphore permit、listener、supervisor child 与 `JoinSet` cleanup。
3. 两个 binary 的 private composition tests 通过 production `run` 实际调用的同一
   `run_with_registry` 路径，把同一个 registry 传入真实
   `BoundedSupervisor`、connection handler 与 `relay_lifecycle`。测试必须先观察
   对应 counter 的 non-baseline live witness，再在每个 terminal path 完成并等待
   supervisor reaping 后回到 baseline。`forced_shutdowns` 是 cumulative counter，
   断言精确 `+1`，不得要求回零。

`run_with_registry` 不得有 `cfg(test)` 替代实现；production 与 test 必须走同一
composition path。现有 runtime `OwnerRegistry` interface 保持不变；本 ADR 不新增
binary/public observation seam、metric、label 或 management capability。

### Independent native request generation

M0-T07 获得一次严格限定的 harness manifest/lock ownership：

- `tests/m0-harness/Cargo.toml` 新增且只新增
  `aes-gcm.workspace = true` 与 `blake3.workspace = true` 两个
  `[dev-dependencies]`；
- harness direct dev-dependency 集合精确为
  `aes-gcm`、`blake3`、`hex`、`serde_json`、`tempfile`；
- 不得依赖任何 `ferrum2-*` package，不得复用 production KDF、framing 或 parser；
- `Cargo.lock` 只允许 `ferrum2-m0-harness` package dependency list 增加
  `"aes-gcm"` 与 `"blake3"` 两条 edge。package 数仍为 110；所有
  `(name, version, source, checksum)` identity tuples 以及既有 resolved crypto
  feature sets不变，不能出现其他 lock hunk。

`detection_probe` 用 synthetic PSK、独立 salt 和当前系统时间独立实现 test-only
BLAKE3 derive-mode KDF 与 AES-128-GCM sealing。它不输出 key、salt、nonce、raw
packet 或 destination。

每个平台精确运行 47 个 native connections：

| Cases | Authenticated construction | Required typed branch evidence | Native observation |
|---|---|---|---|
| 43 short | 从一个有效 current-time 43-byte fixed region 发送前缀 `n=0..42` | `ShortRead` | `ConnectionReset`，不得接受 EOF |
| 1 auth | 先生成完整有效 current-time request，再只翻转 fixed ciphertext/tag 一位 | `Authentication` | same reset |
| 1 type | 独立 seal `type=1`、current timestamp、valid declared length | `InvalidType` | same reset |
| 1 time | 独立 seal `type=0`、至少 120 秒 stale timestamp、valid length | `TimestampSkew` | same reset |
| 1 length | 独立 seal current-time `type=0`、declared variable length `0`，并追加 nonce 1 的 valid empty-variable AEAD tag | `AddressBounds` | same reset |

typed branch identity 由 T03 direct protocol tests 与 generator precondition tests
证明；native process test 证明这些 wire-triggerable rows 的批准 close 外观一致。
每个 case 后 target accept count 必须仍为 0，不能只在整组结束后做 aggregate
assertion。

### Policy guards

`workspace_policy` 对 LF 与 CRLF positive fixture 给出相同 verdict，对 bare CR、
dependency addition/removal、显式 version、feature override、normal dependency、
任何 `ferrum2-*` edge、lock identity/edge mutation 给出失败。focused
`cargo metadata --locked`、package identities 与 crypto feature trees共同证明
这次 exception 没有改变 production dependency graph。

## Consequences and tradeoffs

### Positive

- 每项cleanup/native claim都有与其visibility匹配的direct evidence。
- 不增加production surface即可关闭生命周期counter与authenticated native branch
  缺口。
- exact manifest/lock policy使test-only exception可审计、可回滚。

### Negative

- required native matrix每个平台增加47个real connections，lifecycle增加100个
  process cycles，CI成本上升。
- harness维护一份独立test-only KDF/sealing implementation及其precondition tests。
- lifecycle verdict需要组合三组evidence，不能由单一命令概括。

## Compatibility and upstream divergence

本决策只重分配 evidence ownership，并增加两个已锁定 primitive 的 test-only
direct edges。除ADR-0013随后批准的两个binary-local Tokio dev edges外，
production member/graph、wire bytes、key/nonce semantics、error taxonomy、API、
config、task topology、metric schema、reference pin和 target matrix均不变。

ADR-0001 的“后续票不得修改 manifest/lock”仅被本 ADR 对 M0-T07 上述三个精确路径/
hunk 取代。ADR-0004 的 detection classification 与 ADR-0005 的 runtime lifecycle
仍是规范；只有 evidence construction/allocation 被本 ADR 窄幅取代。

## Migration and rollback

无 persisted state 或 wire migration。回滚时删除两个 harness dev-dependency edge、
对应唯一 lock hunk和独立 generator/probes，并恢复旧 evidence assignment；不得保留
无法由黑盒观察的内部-counter claim。

本决策不采纳sing-box或shadowsocks-rust的implementation detail；reference pins与
interop role保持ADR-0006不变。

## Verification plan

```bash
cargo metadata --locked --format-version 1
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo test -p ferrum2-m0-harness --test workspace_policy --locked
cargo test -p ferrum2-runtime --test lifecycle --locked
cargo test -p ferrum2-runtime --test shutdown --locked
cargo test -p ferrum2-client --locked lifecycle_composition_contract
cargo test -p ferrum2-server --locked lifecycle_composition_contract
cargo test -p ferrum2-m0-harness --test lifecycle_cycles --locked
cargo test -p ferrum2-m0-harness --test detection_probe --locked
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --locked
```

Review还必须确认 root/其他 member manifests除ADR-0013两个exact binary dev
declarations外不变、lock diff 只有两个 harness edges、110 identity tuples/crypto
features不变、matched tests 非零且符合 TEST-0001 的 exact matrix。

## References

- `ADR-0001`：workspace topology、manifest/lock baseline与harness black-box seam。
- `ADR-0004`：SIP022 detection classification与native close requirement。
- `ADR-0005`：runtime ownership、lifecycle与observability contract。
- `ADR-0010`：opaque SIP022 flow；本ADR不改变其production interface。
- `SPEC-0001`、`TEST-0001`、M0-T01/M0-T03/M0-T06/M0-T07。
