# ADR-0023: M3 schema v1 operator compatibility and evolvable topology

- **Status:** Accepted
- **Date:** 2026-07-29
- **Owners:** Architect / Team Lead
- **Related milestone/spec/tickets:** M3；`SPEC-0004`；`TEST-0004`；
  M3-T01、M3-T02、M3-T04、M3-T05；amends ADR-0003 and narrows the
  topology interpretation of ADR-0001

## Context and decision boundary

M0～M2 已经形成可用的 `schema_version = 1` 配置、CLI、错误文本、closed trace
fields 和十四个 metric families。M3 需要把这些现有 operator-facing outcomes
变成升级合同，同时避免把今天的单 listen、单 server、IPv4-only operator
endpoint、十个 workspace members 或两个 binary composition roots误当成永久
产品拓扑。

本 ADR 只决定兼容、版本、诊断和 observable identity。它不设计或实现
multi-inbound、multi-outbound、routing、DNS、Linux transparent inbound、
Windows TUN 或新的 public UDP inbound。

## Outcome invariants

- M3 close 时每份对对应 binary 合法的 v1 配置都属于 preserved cohort；在约定
  窗口内，后续 binary 必须不经修改地接受并保留同一 effective behavior。
- v1 可以向后兼容地增加 optional fields/sections、放宽当前非安全性语法限制或
  扩大 endpoint/address domain；省略新增项时必须保留 preserved cohort 的
  effective values。
- breaking syntax、default 或语义变化使用显式新 schema version；不得 heuristic
  fallback、静默 reinterpret、自动重写或按失败顺序猜测版本。
- 当前 binary 继续对自己未知的字段 fail closed；本合同不要求旧 binary
  forward-read 未来新增字段。
- CLI names、exit classes、stable diagnostic codes、trace field identity 和
  metric family/type/label semantics 在兼容期内不可删除或重新解释。
- PSK、derived keys、salt、nonce、raw config、source/peer/target/destination 和
  free-form errors 不得进入 operator diagnostics、trace fields 或 metric labels。

## Options considered

### Option A：永久冻结当前 v1 shape 和 composition

最容易做 byte-for-byte regression，但会把历史 adapter 变成 routing、TUN、
transparent inbound 等未来工作的结构障碍。拒绝。

### Option B：保留 v1 cohort，允许兼容扩展，breaking change 使用新 schema

保护现有部署，同时把 compatibility outcome 与当前 topology 解耦。接受。

### Option C：M3 立即跳到 schema v2

没有当前行为必须 breaking change 的证据，只会制造迁移而不增加用户价值。拒绝。

## Decision

### Compatibility window and cohort

Preserved cohort 是 M3 exact integrated commit 上由 `ferrum2-client` 或
`ferrum2-server` 完整 semantic validation 接受的全部 v1 文档。它们必须：

1. 在所有 v0.x releases 中不经修改继续有效；
2. 若 successor schema 发布，在 successor 首个 stable release 后至少
   **12 个月**且至少跨越 **2 个 stable minor releases** 继续有效；
3. 只有同时满足两个下限且此前至少一个 stable release 已发出明确 deprecation
   notice，才可按新的 ADR/spec 结束支持。

这是持续的 release obligation。M3 close 证明 policy 与 preserved cohort
regression guard；时间本身只能由后续 release evidence 证明。若旧行为被证实
不安全或不可能维持，必须以具体证据重新开启 contract 并由用户批准，不能静默
缩窄 cohort。

### Allowed v1 evolution

v1 后续变化只在下列条件下兼容：

- 新字段/section 是 optional，且缺省时 preserved cohort 的 normalized values
  与副作用保持不变；
- 新 enum/endpoint/address 只让以前无效的输入变有效，不改变既有值；
- multi-inbound/outbound、routing、DNS、transparent inbound 或 TUN 可在满足
  上述条件时作为 additive v1 shape 引入，否则使用新 schema；
- 新版本仍以一个显式 parser/validator path 处理所声明版本；不尝试其他版本；
- 旧 binary 拒绝由新 binary 才认识的字段是允许的，文档必须说明 direction。

Changing a required field、removing/renaming a field、changing an existing default、
reinterpreting an accepted value、or changing failure-closed behavior is breaking
and requires a new schema version plus explicit migration/rollback policy。

### Stable CLI, exits, and diagnostics

两个现有 binary 保留：

- `--config <PATH>`、`--check-config`、`--help`、`--version`；
- exit `0`：help/version、valid check、normal/graceful termination；
- exit `2`：CLI usage 或 configuration failure；
- exit `1`：validated configuration 进入 process startup/runtime 后的失败。

Config stable codes 保持
`config.io`、`config.too_large`、`config.syntax`、`config.semantic`。
M3 为 exit 1 引入以下 closed run codes：

- `startup.observability`
- `startup.runtime`
- `startup.bind`
- `startup.protocol`
- `runtime.listener`
- `runtime.child`
- `runtime.root`
- `shutdown.cleanup`

非 usage failure 向 stderr 输出一行以 stable code 与 redacted summary 组成的
diagnostic。Field path 仅在不含值/秘密时出现。Clap 的 help/usage prose 不是
byte-stable API，但 flags、exit class 和不泄密要求是合同。

### Stable traces and metrics

Closed trace event 的 operator field identity 是
`timestamp`、`level`、`event`、`role`、`transport`、`stage`、`outcome`、
optional `reason`、`session_id`、`duration_ms`、`bytes`。`session_id` 仅为
process-local bounded correlation value，不是 wire/session identity。

当前十四个 metric families 的 base name、counter/gauge type、label keys 与
语义保持稳定；Prometheus counter samples 按 exposition convention 带
`_total`。可以 additive 增加新的 closed event categories/families，但不得
复用现有 identity 表示不同概念，也不得加入 secret、identity 或 destination
cardinality。

### Topology boundary

当前两 binary、单 listen/server 配置、IPv4 operator endpoints 和 workspace
member list 是 preserved cohort 的当前 adapter/profile，不是 schema family 或
永久 product topology。Architecture tests 应保护 dependency direction、
deep-module boundaries 和已承诺 adapter compatibility，而非断言所有未来
members/targets 已穷尽。

## Consequences and tradeoffs

- Positive：现有部署获得明确升级窗口，未来拓扑无需破坏 transport state
  machines 或伪装成 M3 工作。
- Positive：observable identity 与 prose/layout 分离，既可稳定 dashboards/
  automation，又允许实现与文档改善。
- Negative：每个后续 config change 都要维护 preserved cohort fixture/table，
  并明确 old-to-new 与 new-to-old compatibility direction。
- Negative：结束 v1 支持需要时间、release count、notice 与新 contract，不能仅
  由代码合并决定。

## Compatibility, migration, and rollback

M3 不迁移配置、不重写文件、不改变 `schema_version`。Rollback 到 M3 之前的
binary 只保证读取当时已认识的 v1 fields；使用后续 additive fields 前，operator
必须参考对应版本文档。Metric/trace additions可由旧 consumer忽略，已有
family/field不得被删除或 repurpose。

## Verification seam

- 一个 preserved v1 fixture/value table 同时覆盖 client/server defaults、
  explicit values、three methods、UDP enabled/disabled 与 redacted invalid rows；
- CLI process table覆盖 flags、0/1/2 exits、stable config/run codes 和
  zero-resource check；
- observability contract tables覆盖 exact fields、十四 family identity/type/
  labels/semantics 和 secret/destination sentinels；
- architecture contract只验证 dependency/boundary，显式证明它不枚举未来
  topology。

## References

- `docs/adr/ADR-0001-m0-workspace-toolchain-and-module-topology.md`
- `docs/adr/ADR-0003-m0-configuration-and-cli-contract.md`
- `docs/adr/ADR-0005-m0-runtime-lifecycle-and-observability.md`
- `docs/adr/ADR-0022-m2-bounded-direct-udp-runtime-and-server-composition.md`
