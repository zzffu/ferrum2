# ADR-0024: M3 transactional process lifecycle and reusable supervisor

- **Status:** Accepted
- **Date:** 2026-07-29
- **Owners:** Architect / Team Lead
- **Related milestone/spec/tickets:** M3；`SPEC-0004`；`TEST-0004`；
  M3-T03、M3-T04、M3-T05；amends the process-lifecycle portions of
  ADR-0005 and ADR-0022

## Context and decision boundary

`ferrum2-runtime` 已有 bounded connection supervisor、owner registry、absolute
deadlines 和 UDP session runtime；两个 binary 仍分别协调 Tokio runtime、TCP/
UDP/metrics roots 和 shutdown。当前 server 的 fallible root preparation 可在
root polling 期间发生，因此一个 root 已可服务而另一个 root 随后失败的 partial
activation 仍缺少统一 transaction 证明。

M3 需要一个 topology-neutral process lifecycle，使未来 inbound/outbound roots
可复用相同 ownership/cancellation/rollback/shutdown invariants。本 ADR 不创建
routing graph、DNS policy、transparent proxy 或 TUN，也不固定 root、listener、
binary 或 workspace member 数量。

## Outcome invariants

- 完整 config semantic validation 发生在 subscriber、runtime、listener、
  metrics endpoint、session table、socket、channel 或 task 创建之前。
- 所有会阻止 process activation 的 fallible root resources 先 prepare；所有
  required roots prepared 后才进入 active polling。
- Preparation/activation 失败以逆 ownership order rollback；未留下 listener、
  socket、task、buffer、session、registry count 或 installed process-global
  state。
- 每个 root 与 child resource 有唯一 transitive owner、一个 termination path
  和可观测的 reap outcome；owner drop 不是未证明的 shutdown protocol。
- Cancellation 单调传播；同一 flow 的 protocol/target failure 只终止该 flow，
  required root terminal failure 则取消整个 process。
- Phase timeout 使用 monotonic absolute deadline；重试、candidate 或方向切换
  不得重新获得完整 budget。
- Graceful shutdown 先 quiesce admission，再 drain 到一个 deadline，随后
  force-cancel 并 reap 所有 owners；正常返回前 owner snapshot 回到 baseline。

## Options considered

### Option A：继续在两个 binary 内复制 root selection

局部修改较小，但 startup ordering、fatal arbitration 和 cleanup 很容易分叉，
未来 roots 会重复相同缺陷。拒绝。

### Option B：runtime 提供 topology-neutral process supervisor outcome

把 lifecycle policy 封装在 deep module，binary 只提供已验证 config、root
adapters 与 OS shutdown signal。接受。

### Option C：M3 同时建立通用 routing/service graph

超出当前目标，会提前决定未来 routing/DNS/TUN policy 和 topology。拒绝。

## Decision

### Lifecycle outcome model

Normative state sequence 是：

```text
Validated -> Preparing -> Prepared -> Active -> Quiescing -> Draining -> Stopped
                |            |          |            |
                +---------- Rollback     +---------- Forced -> Stopped
                                         +---------- Fatal  -> Quiescing
```

这些是可观察 outcome，不要求同名 public enum 或固定 helper layout。

- **Validated:** typed config 已完整通过，无 runtime resource。
- **Preparing:** 顺序/并行准备实现可选，但 dependency 与 rollback order 必须
  deterministic；尚不 poll public service loops。
- **Prepared:** required roots 的 fallible bind/setup 已完成，尚未接收业务。
- **Active:** roots 开始 polling；activation 要么全部成为 active transaction
  的成员，要么 process 失败并 cleanup。
- **Quiescing:** 停止新 admission，发出一个 process cancellation lineage。
- **Draining:** 已接受工作在 absolute shutdown deadline 内完成。
- **Forced:** deadline 到期后取消剩余工作并记录 closed forced-shutdown
  outcome。
- **Stopped:** roots/children 全部 joined/reaped，owned resource snapshot 回到
  pre-run baseline。

### Preparation, activation, and rollback

Config loading remains outside the process supervisor。Validated config 转换成
root adapters 时：

1. observability value/endpoint、Tokio runtime、TCP/UDP listeners、metrics
   listener、protocol/runtime tables等 required roots全部完成 fallible prepare；
2. prepare 不得 spawn detached polling task 或接受业务；
3. 任一步失败时，已准备 resources 逆序释放并返回 `startup.*` closed cause；
4. 只有全部 roots prepared 才 activation；
5. activation 期间的同步失败同样 rollback；active 后的 terminal root failure
   使用 `runtime.*` cause并进入统一 quiesce/reap。

Implementation 可以使用 owned futures、prepared handles 或其他等价 boundary，
但不得靠 background task 隐藏 fallible startup。

### Ownership and failure arbitration

- Process supervisor 唯一拥有 required roots 和 process cancellation source。
- Root owner 唯一拥有其 child supervisor/session table/listener/socket；child
  owner负责per-flow task与buffer/channel。
- Child completion/rejection更新 owner state exactly once；late completion必须
  被 generation/cancellation lineage 拒绝，不能 resurrect state。
- Per-flow auth、parse、target、queue、idle 或 relay failure 不升级为 root fatal，
  除非同一错误证明 required root 已不能继续服务。
- Required TCP/UDP/metrics listener terminal failure、root panic/join failure 或
  supervisor invariant violation 是 process fatal；多个同时失败由一个
  deterministic first-cause outcome表示，其他结果仍被 reap。

### Cancellation, timeout, and shutdown

External shutdown signal、process fatal、startup rollback 都触发同一 monotonic
cancellation lineage；取消不可撤销。Handshake、connect/resolve、idle 与
shutdown 使用各自 configured absolute deadline；内部阶段不得 reset budget。

Graceful shutdown：

1. stop accept/receive/admission；
2. cancel pending but unaccepted preparation/handshake according to existing
   phase semantics；
3. drain accepted TCP half-closes and admitted UDP work until
   `runtime.shutdown_grace_ms` absolute deadline；
4. force-cancel remainder，close sockets/channels，join/reap roots and children；
5. emit bounded closed outcomes；return only after baseline owner proof or return
   `shutdown.cleanup`。

### Future-root neutrality

Future multi-inbound/outbound、routing、DNS、transparent/TUN adapters may become
new prepared roots/children without changing lifecycle invariants。Supervisor 不拥有
route selection、DNS answer policy、packet capture、device configuration 或 protocol
semantics；这些功能需要各自后续 contract。

## Consequences and tradeoffs

- Positive：startup partial activation、listener fatal 和 shutdown cleanup 使用
  一个可复用 outcome，而不是两个 binary 的近似实现。
- Positive：future roots 复用 owner/cancel/deadline/rollback，不迫使 M3 决定
  future topology。
- Negative：准备资源与 poll service 需要显式分离，部分现有 binary-local code
  会迁移到 runtime seam。
- Negative：process return 可能等待完整 reap 到 deadline；cleanup failure必须
  显式上报，不能假装 graceful success。

## Compatibility, migration, and rollback

Wire、config values、listener addresses、existing per-flow behavior和public core
traits不因本 ADR 改变。Operator-visible变化仅是 exit-1 run failures获得
ADR-0023 的稳定、脱敏分类，以及 startup/shutdown 结果更确定。若实现回滚，必须
保留 validation-before-resource、atomic preparation 和 no-leak outcomes；不能
回到 partial activation。

## Verification seam

- Paused-time supervisor state table覆盖prepare failure at each root、activation
  failure、simultaneous fatal causes、graceful/forced shutdown、late child
  completion和owner snapshots。
- Existing runtime lifecycle/half-close/UDP tables验证per-flow isolation、
  absolute deadlines、bounded resources与child cleanup。
- 一个 production-used real-process adapter table 对 client/server 各执行
  startup rollback、signal shutdown、fatal root、restart/rebind，并在每次退出
  后验证资源可重新取得。
- 三目标 native release binaries复用同一 bounded process lifecycle seam；不为
  每个平台复制 product semantics。

## References

- `docs/adr/ADR-0005-m0-runtime-lifecycle-and-observability.md`
- `docs/adr/ADR-0012-m0-phase-deadlines-and-partial-relay-accounting.md`
- `docs/adr/ADR-0022-m2-bounded-direct-udp-runtime-and-server-composition.md`
