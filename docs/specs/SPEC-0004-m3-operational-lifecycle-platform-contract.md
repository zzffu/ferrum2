# SPEC-0004: M3 operational, lifecycle, and platform contract

- **Status:** Approved
- **Milestone:** M3
- **Related ADRs:** ADR-0023、ADR-0024；extends ADR-0003、ADR-0005、
  ADR-0006、ADR-0016、ADR-0017、ADR-0022
- **Test plan:** `docs/test-plans/TEST-0004-m3-operational-lifecycle-platform-contract.md`
- **Tickets:** M3-T01、M3-T02、M3-T03、M3-T04、M3-T05

## Objective and non-goals

M3 使当前 v0 产品可稳定运维和资格复现：

1. 保留 M3 close 时所有合法 schema v1 配置及其 effective behavior；
2. 稳定 CLI、exit/error classes、redacted structured logs 和 metric identity；
3. 用一个 topology-neutral process supervisor 证明 prepare、ownership、
   cancellation、absolute timeouts、rollback 和 graceful/forced shutdown；
4. 在 Windows MSVC、Linux GNU、Linux musl 的 native release artifacts 上完成
   同一 exact SHA 的 bounded qualification。

M3 明确不实现 multi-inbound/outbound、routing、DNS proxy/resolver、Linux
transparent inbound、Windows TUN、SOCKS5 UDP ASSOCIATE、SIP023/multi-user、
hot reload、management API、archives/installers/publication。M4 才拥有 throughput
baseline和单主机bounded 10,000-idle resource qualification。

## User/operator-visible behavior

- 当前合法 client/server v1 文件升级后无需编辑；defaults 与 explicit values
  归一化成与 M3 相同的行为。
- `--check-config` 在创建任何 runtime resource 前完整验证并以 exit 0/2 返回；
  正常 process failure 用 exit 1 和一个 stable redacted run code。
- JSON tracing 只有 closed fields/categories；Prometheus exposition 保持十四个
  family 的 name/type/labels/meaning。
- Startup 是 all-required-roots transaction。任一 prepare/bind/setup failure
  回滚全部已取得资源；active root terminal failure 统一取消并 reap process。
- SIGINT/Ctrl-C 或平台等价 signal 先停止 admission、bounded drain、必要时
  force-cancel，随后退出；退出后同地址可立即 restart/rebind。

## Existing execution path and ownership

- `bins/ferrum2-{client,server}/src/main.rs` 解析 Clap、调用
  `ferrum2_config::load_*`，check mode 后才进入 `run::run`。
- `crates/ferrum2-config/src/lib.rs` 以 Serde typed roots、closed errors 和
  secret wrappers 完成 load/semantic validation。
- `crates/ferrum2-observability/src/lib.rs` 拥有 closed `TraceRecord` 与 isolated
  fourteen-family `Metrics` registry；不安装 process-global recorder。
- `crates/ferrum2-runtime/src/supervisor.rs`、`owner.rs`、`relay.rs`、`udp.rs`
  已拥有 bounded children、owner counters、deadlines、relay/UDP shutdown。
- 两个 binary 的 `run.rs` 目前分别准备/轮询 TCP、UDP、metrics roots；M3 将
  process coordination 收敛到 production-used reusable runtime seam。
- `.github/workflows/m0.yml` 已构建三个 exact targets；M3 增加 native
  release-artifact lifecycle/linkage/hash evidence，不改变 provider authority。

## Required contract

### M3-MUST-01 — preserved schema v1 cohort

M3 integrated close commit 上分别被 current client/server parser 与 semantic
validator 接受的每个 `schema_version = 1` document 构成 preserved cohort。
后续版本必须按 ADR-0023 的 v0.x + successor 后至少 12 个月且至少 2 个 stable
minor releases + prior notice 窗口，不经修改地接受它并保留相同 normalized
values与side-effect choices。

当前 cohort 的角色 shape：

| Role | Required sections/fields | Optional/defaulted sections |
|---|---|---|
| client | `schema_version=1`；`[client].listen/server`；`[shadowsocks].method/psk` | `[runtime]`、`[logging]`、`[metrics]` |
| server | `schema_version=1`；`[server].listen`；`[shadowsocks].method/psk` | `[runtime]`、`[replay]`、`[udp]`、`[logging]`、`[metrics]` |

Current parser accepts IPv4 `address:port` operator endpoints；future versions may
also accept IPv6 or richer endpoint forms under MUST-02，so current rejection of those
forms is not a permanent product invariant。Config is at most 1,048,576 bytes；
unknown fields fail closed for the binary reading them。Metrics endpoint, when
present, is IPv4 loopback and distinct from the proxy listener。

Current defaults/ranges：

| Field | Default | Accepted range/category |
|---|---:|---|
| `runtime.max_connections` | 4096 | 1..=65535 |
| `runtime.listen_backlog` | 1024 | 1..=65535 |
| `runtime.handshake_timeout_ms` | 5000 | 100..=60000 |
| `runtime.connect_timeout_ms` | 10000 | 100..=120000 |
| `runtime.idle_timeout_ms` | 300000 | 1000..=86400000 |
| `runtime.shutdown_grace_ms` | 30000 | 0..=300000 |
| `replay.capacity` server-only | 65536 | 1024..=1048576 |
| `udp.enabled` server-only | true | boolean |
| `udp.max_sessions` | 4096 | 1..=65535 |
| `udp.max_buffered_bytes` | 16777216 | 1048576..=268435456 |
| `udp.idle_timeout_ms` | 300000 | 60000..=86400000 |
| `logging.level` | `info` | `error|warn|info|debug|trace` |
| `[metrics]` | absent | explicit loopback `listen` |

Supported methods remain exactly the three v0 methods。Canonical Base64 PSK decodes
to 16 bytes for AES-128 and 32 bytes for AES-256/ChaCha20-Poly1305；secret text,
decoded/derived material and raw configuration are never retained in errors。

### M3-MUST-02 — compatible evolution without topology freeze

- Future v1 additions are optional and omission preserves every MUST-01 effective
  value/behavior；widening may make previously invalid endpoints/values valid。
- Removing/renaming/reinterpreting accepted input, changing an existing default or
  narrowing safe input requires an explicit successor schema and migration contract。
- Parser selects only the declared schema；no heuristic fallback, silent rewrite or
  automatic migration。Old binaries need not accept fields introduced later。
- Current single listen/server, IPv4 validated types, two binaries, ten workspace
  members and current direct composition are current adapters, not exhaustive topology。
- Architecture evidence protects dependency direction and deep-module seams rather
  than an exact forever member/target list。

### M3-MUST-03 — CLI, diagnostics, and validation before resources

Both binaries preserve `--config`、`--check-config`、`--help`、`--version` and
exit classes 0/2/1 defined by ADR-0023。Config codes remain
`config.io|config.too_large|config.syntax|config.semantic`；run codes are exactly：

```text
startup.observability  startup.runtime  startup.bind  startup.protocol
runtime.listener       runtime.child    runtime.root  shutdown.cleanup
```

Non-usage failure emits one redacted stderr diagnostic；Clap prose is not byte-stable。
Complete config validation precedes subscriber/global state、Tokio runtime、listener、
socket、metrics registry/endpoint、replay/session table、channel、buffer reservation
or task creation。`--check-config` creates none of those resources。

### M3-MUST-04 — stable redacted tracing contract

Accepted JSON record keys are:

```text
timestamp level event role transport stage outcome reason?
session_id? duration_ms? bytes?
```

`event/role/transport/stage/outcome/reason` use closed categories；new categories may
be additive。`session_id` is a process-local numeric correlation value only。
PSK/key/salt/nonce/raw config/free message/error、wire IDs、source/peer/target/
destination never appear。Configured level filtering remains closed and does not
require a process-global subscriber in library tests。

### M3-MUST-05 — stable metric identity and meaning

The following base families, Prometheus type and label keys are stable。Counter sample
names use `_total` according to exposition format；base HELP/TYPE names do not。

| Family | Type | Label keys | Meaning |
|---|---|---|---|
| `ferrum2_tcp_connections` | counter | `role,inbound,outcome` | TCP admission/outcome |
| `ferrum2_tcp_connections_active` | gauge | `role,inbound` | active TCP flows |
| `ferrum2_tcp_failures` | counter | `role,stage,reason` | closed TCP failures |
| `ferrum2_tcp_bytes` | counter | `role,direction` | authenticated app bytes |
| `ferrum2_tcp_replay_entries` | gauge | none | exact replay-set entries |
| `ferrum2_tcp_replay_rejections` | counter | `reason` | TCP replay rejects |
| `ferrum2_tcp_forced_shutdown` | counter | `role` | forced TCP flows |
| `ferrum2_udp_sessions_active` | gauge | `role` | active bounded UDP sessions |
| `ferrum2_udp_datagrams` | counter | `role,direction,outcome` | UDP datagram outcomes |
| `ferrum2_udp_failures` | counter | `role,stage,reason` | closed UDP failures |
| `ferrum2_udp_bytes` | counter | `role,direction` | authenticated app bytes |
| `ferrum2_udp_buffered_bytes` | gauge | `role` | allocated user-space bytes |
| `ferrum2_udp_replay_rejections` | counter | `role,direction,reason` | UDP replay rejects |
| `ferrum2_udp_forced_shutdown` | counter | `role` | forced UDP sessions |

Families/categories may be added but existing identity/type/keys/meaning cannot be
removed or repurposed during the compatibility window。No label accepts method、PSK、
key material、wire/session/packet identity、source/peer/target/destination or
free-form text。

### M3-MUST-06 — transactional supervisor and ownership

Validated process follows ADR-0024:

```text
Validated -> Preparing -> Prepared -> Active -> Quiescing -> Draining -> Stopped
                \-> Rollback             \-> Fatal/Forced -> Stopped
```

All required fallible roots prepare before public polling；failure rolls back prepared
resources in deterministic ownership order。Process/root/child each have one transitive
owner and exactly-once completion/reap accounting。No detached task or unowned socket/
buffer/session/channel survives rollback or stopped。

### M3-MUST-07 — cancellation, deadlines, isolation, and shutdown

External signal、fatal root and rollback trigger monotonic cancellation；all phase
budgets are monotonic absolute deadlines and cannot reset inside retries/candidates。
Auth/semantic/target/queue/idle failures remain affected-flow/session scoped；required
root terminal failure cancels the process。Shutdown quiesces admission, drains accepted
work to one configured grace deadline, force-cancels the remainder, joins/reaps every
owner and returns baseline snapshots；cleanup failure uses `shutdown.cleanup`。

### M3-MUST-08 — current binary composition evidence

Production-used client/server adapters compose config, observability, TCP, server UDP,
optional metrics and OS signal with MUST-06/07。A deterministic local process matrix
executes at least 100 bounded startup/failure/shutdown/restart cycles per binary path,
including partial bind/metrics failure、root fatal、TCP half-close、UDP enabled/disabled、
graceful and forced shutdown。Each cycle proves termination and immediate rebind with
no product owner growth；it is bounded lifecycle evidence, not M4's bounded
10,000-idle resource qualification。

### M3-MUST-09 — three-target native release qualification

One exact candidate SHA produces locked release artifacts for:

- `x86_64-pc-windows-msvc`
- `x86_64-unknown-linux-gnu`
- `x86_64-unknown-linux-musl`

On each native runner both release binaries execute help/version、valid/invalid
offline config、startup rollback and signal shutdown/rebind rows using synthetic
configs。Evidence records exact SHA、Rust/toolchain/runner identity、artifact SHA-256
and bounded lifecycle markers。Windows records PE headers/dependents；GNU records
ELF/file/readelf/objdump and GLIBC requirements；musl proves native execution and
static/static-PIE with no `PT_INTERP` or `DT_NEEDED`。Unavailable native setup is
release `BLOCKED`, never PASS。

### M3-MUST-10 — exact-SHA integrated qualification

M3 closes only when the same exact integrated SHA has:

- authoritative `workflow.toml` full gate；
- security/config/observability/runtime/process suites；
- fixed TCP 12/12 and UDP 12/12 interop with cleanup；
- all MUST-09 platform rows and artifact hashes；
- test-budget milestone gate；
- zero open blocker/major review finding。

Evidence from another SHA/run/attempt, skipped required row or self-test-only platform
helper cannot be spliced into PASS。Provider/setup unavailable blocks release evidence
but does not reopen a product ticket unless it reveals a product defect。

## Acceptance criteria

1. M3-MUST-01/02 are implemented as a preserved-cohort/effective-value table and
   topology-neutral architecture guard.
2. M3-MUST-03/04/05 exact CLI、diagnostic、trace and metric contracts pass without
   secret/destination leakage or resource creation during offline validation.
3. M3-MUST-06/07 supervisor state/owner tests pass for rollback、fatal、graceful、
   forced、late completion and deadline paths.
4. M3-MUST-08 current binary process matrix completes its bounded cycles and returns
   all owned resources/rebindability to baseline.
5. M3-MUST-09 native release artifacts and linkage/hash records pass on all three
   targets without skipped required rows.
6. M3-MUST-10 same-SHA product/integration/release gates and milestone test budget pass
   with zero blocking review root.

## Implementation freedom

- Internal supervisor type names、state representation、prepared-root trait shape、
  root storage/order and testing adapters are Engineer choices if outcomes remain。
- Tables may extend existing files rather than create new harnesses；equivalent
  evidence is allowed only under ADR-0016 before execution/review。
- Compatible endpoint/parser widening is not required in M3；M3 only removes tests/
  contracts that incorrectly declare current rejections/topology permanent。
- Platform scripts may use native shell idioms，but markers and evidence semantics
  remain cross-platform and fail closed。

## Open decisions

None。Schema compatibility、lifecycle state、ticket ownership、target triples、
native artifact evidence and M4 deferral are approved for execution。
