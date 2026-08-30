# Ferrum2 非 TUN 性能优化：全部未完成项清单

> 审查对象：`current.tar(10).gz`  
> 审查日期：2026-08-29  
> 范围：TCP、SOCKS5、Shadowsocks TCP/UDP、Direct UDP、DNS、规则引擎、运行时、Linux 网络路径、Windows 非 TUN 物理网络路径、性能验证与构建实验  
> 明确排除：`crates/ferrum2-tun/**`、`bins/ferrum2-client/src/run/tun/**`、Wintun/TUN 专属路径及其性能实验  
> 结论性质：源码静态审查和仓库证据审查；不代表已经完成 Rust 编译或真实性能验收

---

## 1. 总结

最新版本中，原计划的主要 P0/P1 数据面改造已经完成，但仍不能标记为“全部性能优化完成”。本次重新核对后，未完成工作分为三类：

| 类别 | 数量 | 含义 |
|---|---:|---|
| 原计划部分完成 | 11 | 已有接口、候选实现或部分生产集成，但最后一段代码、默认采纳或实验结果缺失 |
| 原计划未开始 | 4 | 尚无生产实现或正式实验结果；其中多项应继续保持 profile 驱动 |
| 新发现的具体代码残留 | 6 | 未在原计划状态表中单列，但最新源码仍存在明确的锁、分配、复制或派生成本 |
| 共享验证与采纳门禁 | 7 | 不属于新的算法实现，但任何“完成”或“更快”结论都必须补齐 |

因此，当前有：

- **21 个唯一工程待办项**；
- **7 个共享验证/采纳门禁**。

### 1.1 最高优先级剩余项

1. 客户端 Shadowsocks UDP 按最大 65,507 bytes 扩展和清零 wire，尚未改成 exact-size。
2. 服务端 UDP established-session 路径每包仍先进入进程级 `admission` mutex，多 receive worker 的关键部分仍会串行。
3. `UdpServer` protocol maps 和 `UdpMappings` 仍有全局 mutex；`UdpMappings` 还使用全局 `notify_waiters()`。
4. AES UDP body cipher 每包执行 BLAKE3 派生、临时 Vec 构造和 cipher 初始化。
5. TCP read state 仍有强制 self-wake；zero-copy relay 的 trait 已实现但生产 relay 未接通。
6. copy/zero/wakeup/lock wait 等结构指标仍未连接到生产热路径。
7. 当前源码尚无本版本对应的 Rust 构建、全量测试和真实 candidate-vs-parent ABBA 证据。

---

## 2. 状态定义

- **🟡 部分完成**：基础实现存在，但生产默认路径、关键集成、性能证据或采纳决策尚未完成。
- **⬜ 未开始**：没有对应生产实现或正式实验结果。
- **🆕 新发现**：本次重新检查最新源码后发现的明确残留，不在原 46 项完成度统计中。
- **🔒 门禁未完成**：代码可能已存在，但尚不能证明可编译、正确、稳定或更快。
- **条件性任务**：只有 profile 证明相关成本仍占主导时才应实施，不应为了清单完成率盲目改造。

---

## 3. 全部工程待办总表

| ID | 状态 | 优先级 | 工作项 | 下一步结论 |
|---|---|---:|---|---|
| M0-02 | 🟡 | P0 | 分配、清零、复制、唤醒和锁等待指标接线 | 必须完成，是后续微优化的证据基础 |
| TCP-06 | 🟡 | P1 | TCP read 状态在单次 poll 内有界推进 | 消除读取成功后的无条件 self-wake |
| TCP-07 | 🟡 | P2 | 协议感知 zero-copy relay | trait 已有，生产 relay 尚未消费 borrowed plaintext |
| UDP-06 | 🟡 | P0 | 客户端 SS UDP exact-size wire growth | 当前仍按最大 wire resize/清零 |
| RULE-01 | 🟡 | P2 | domain suffix hybrid trie 默认采纳 | 候选实现已存在，缺 qualification 与采纳证据 |
| RULE-02 | 🟡 | P2 | CIDR radix/Patricia trie 默认采纳 | 候选实现已存在，缺 qualification 与采纳证据 |
| RULE-04 | 🟡 | P2 | ArcSwap 原子 snapshot 默认采纳 | 候选实现已存在，默认关闭 |
| WIN-01 | 🟡 | P1 | Windows 动态 UDP generation wrapper 去双锁 | TCP 已简化，UDP 仍有 resource/closed 两把 mutex |
| BUILD-01 | 🟡 | P2 | ThinLTO + codegen-units=1 实验与采纳 | 只有工具和 profile，无真实结果 |
| BUILD-02 | 🟡 | P2 | PGO 训练、验证与采纳 | 只有流程工具，无 profraw/profdata/result |
| BUILD-03 | 🟡 | P2 | 固定 CPU `target-cpu` 实验与发布决策 | 只有控制器，无真实结果和发布策略 |
| UDP-14 | ⬜ | P3/条件性 | `recvmmsg`/`sendmmsg` 批量系统调用 | 仅在 syscall 已成为主要瓶颈后实施 |
| OBS-01 | ⬜ | P3/条件性 | metrics per-worker aggregation | 仅在共享 counter contention 被证实后实施 |
| BUILD-04 | ⬜ | P3/条件性 | allocator 对照实验 | 先消除剩余结构分配，再重新 profile |
| BUILD-05 | ⬜ | P3/条件性 | Tokio worker/affinity 对照 | 先处理共享锁和 self-wake，再调 worker |
| NEW-UDP-01 | 🆕 | P0 | 移除 established-session 每包进程级 admission gate | 当前多 receive worker 仍先在共享 gate 排队 |
| NEW-UDP-02 | 🆕 | P0/P1 | 分片 `UdpServer`/`UdpMappings`，消除全局通知惊群 | protocol/mapping lookup 仍有共享 mutex 和 `notify_waiters()` |
| NEW-UDP-03 | 🆕 | P1 | 缓存 AES UDP session-derived body cipher | 当前逐包 BLAKE3 derive + Vec + cipher init |
| NEW-SOCKS-01 | 🆕 | P1/P2 | SOCKS UDP owned-buffer path | 当前每 association 预零最大 wire，且请求 payload 逐包 `to_vec()` |
| NEW-DNS-01 | 🆕 | P2 | DNS egress channel 使用 buffer lease/`Bytes`，减少逐包 Vec 复制 | `ChannelDnsDatagram` send/recv 边界仍有多次复制 |
| NEW-UDP-04 | 🆕 | P3 | borrowed UDP API 的 scratch 延迟分配 | 主生产路径已 owned/in-place，但公开 fallback scratch 仍预留最大容量 |

---

# 4. 原计划中仍部分完成的 11 项

## 4.1 M0-02：结构性性能指标尚未完整接线

### 当前状态

`tools/ferrum2-m4-qualification/src/m4_support/profile_structural.rs` 已定义：

```text
allocations
copy_bytes
zero_bytes
wakeups
lock_wait_nanoseconds
```

但当前多个字段仍以 `not_exposed` 关闭；allocation 依赖外部 artifact。

### 尚需完成

至少接入：

- TCP decrypt prepare bytes、zeroized bytes。
- TCP AEAD/frame encode copy bytes。
- TCP read self-wake、poll budget exhaustion。
- relay activity notify 次数。
- UDP request wire resize/zero bytes。
- replay cleared words/bits。
- `admission`、`UdpServer.state`、`UdpMappings.state`、session shard、response codec 的 lock wait/hold。
- AES body cipher constructions/datagram。
- SOCKS/DNS UDP per-datagram allocations/copy bytes。

### 实施要求

- 使用 feature-gated 或 benchmark-only instrumentation。
- 生产默认关闭时，不产生稳定可测的热路径回退。
- 高频计数优先 worker-local 或 sampling，避免观测自身制造共享 cache-line contention。

### 完成标准

- `copy_bytes`、`zero_bytes`、`wakeups`、`lock_wait_nanoseconds` 不再统一返回 `not_exposed`。
- 每个 P0/P1 剩余优化至少有一个结构性指标直接证明成本被消除。
- 指标单位、范围和 aggregation 方式写入 schema/文档。

---

## 4.2 TCP-06：TCP read path 尚未完全在单次 poll 内推进

### 当前证据

目标文件：

```text
crates/ferrum2-shadowsocks/src/tcp/flow/io.rs
crates/ferrum2-shadowsocks/src/tcp/flow/client.rs
```

已有 `PollBudget`，但 read fill 路径仍多处：

```rust
cx.waker().wake_by_ref();
return Poll::Pending;
```

当前源码中的相关位置包括 `flow/io.rs` 约 56、116、145、172、182 行。

### 尚需完成

- 将 length read → length open → payload read → payload open → plaintext-ready 放入一个有界循环。
- 底层返回 `Pending` 时才正常返回 `Pending`。
- budget 用尽时才 self-wake。
- 对 read、write、flush 和 first-response 状态使用一致的公平性预算。

### 风险

- 永远 Ready 的 mock transport 导致单任务独占 executor。
- 状态迁移时重复 consume 或漏唤醒。
- EOF/认证失败路径发生二次 poll。

### 完成标准

- 成功读取小 frame 时不再固定发生多轮 self-wake。
- `wakeups/frame`、context switches/request 下降。
- partial-read、EOF、认证失败、最大 frame、budget exhaustion 测试全部通过。

---

## 4.3 TCP-07：`PlainBufferedDuplex` 尚未接入生产 relay

### 当前状态

Shadowsocks flow 已实现 `PlainBufferedDuplex`/`AsyncBufRead` 类能力，但：

```text
crates/ferrum2-runtime/src/relay.rs
```

仍使用：

```rust
tokio::io::copy_bidirectional_with_sizes(...)
```

因此典型路径仍是：

```text
socket -> decrypt scratch -> relay 32 KiB buffer -> target socket
```

### 尚需完成

- 新增 specialized buffered relay，只对支持 `PlainBufferedDuplex` 的一侧启用。
- 直接将已认证 plaintext slice 写到目标 socket。
- partial write 后保存未消费 range。
- 目标产生 backpressure 时不得覆盖 decrypt scratch。
- generic `AsyncRead + AsyncWrite` 保留现有 fallback。

### 完成标准

- decrypt scratch → relay buffer 的 payload copy 为 0。
- 可删除或缩小至少一个方向的 32 KiB 中间 buffer。
- `tcp-bulk`、`tcp-stream-64k` 不回退；`tcp-scale-10k` RSS/connection 下降。

---

## 4.4 UDP-06：客户端 Shadowsocks UDP 尚未 exact-size growth

### 当前证据

目标文件：

```text
bins/ferrum2-client/src/run/egress/udp/association.rs
```

当前仍存在：

```rust
upstream.resize(MAX_UDP_WIRE_LEN, 0);
inner.resize(MAX_UDP_WIRE_LEN, 0);
```

单 hop 每轮可能清零一块 65,507-byte wire，多 hop 可能清零两块。

### 尚需完成

1. 在编码前通过 layout calculator 得到 exact final wire length。
2. 只将 `BytesMut.len()` 扩展到该 exact length。
3. capacity 可以保留，不要 shrink；但不能每轮把逻辑长度扩到最大。
4. 单 hop 和多 hop 分别计算每层准确长度。
5. 错误和取消后只清理实际写入范围。

### 测试矩阵

- payload：0、128、1200、1472、1500、8192、最大 wire。
- target：IPv4、IPv6、domain。
- hop：1、2、4、8。
- 小包→大包→小包，验证 capacity 复用且 zero bytes 不回到最大值。

### 完成标准

- 128/1200/1500-byte datagram 的 `zero_bytes/datagram` 接近实际 wire length。
- association 仍保持 1-wire/2-wire 结构和容量预算守恒。
- `udp-small-high`、MTU 场景改善，max-wire 无回退。

---

## 4.5 RULE-01：domain suffix hybrid trie 未生产采纳

### 当前状态

`crates/ferrum2-rule/src/hybrid_index.rs` 已实现 suffix trie 和阈值，但：

```toml
candidate-domain-suffix-trie = []
```

默认 feature 为空。

### 尚需完成

- 完成 rule qualification 的有效 calibration artifact。
- 对 8/32/64/128/1k/10k domain rules 运行 baseline-vs-candidate。
- 覆盖 exact、suffix、无匹配、深 label、IDNA/规范化边界。
- 验证小规则集不因 pointer chasing 回退。
- 决定默认启用、自动阈值启用或保留 opt-in。

### 完成标准

- qualification 状态不是 `CALIBRATION_REQUIRED`。
- 有 source-hash-bound candidate result。
- 默认 feature/内部自动选择策略有明确决议。

---

## 4.6 RULE-02：CIDR radix/Patricia trie 未生产采纳

### 当前状态

IPv4/IPv6 radix 候选已实现，但：

```toml
candidate-cidr-radix = []
```

默认关闭。

### 尚需完成

- 对不同 prefix 数量和 prefix-length 分布 qualification。
- 覆盖 `/0`、`/32`、`/128`、重叠前缀、随机 IP、IPv4/IPv6 混合集。
- 与当前 sorted groups + binary search 比较 CPU、allocation 和 compiled bytes。
- 确定自动阈值。

### 完成标准

- 大 CIDR 集稳定改善，小集不回退。
- 语义 property test 与参考模型一致。
- feature/default 采纳决议完成。

---

## 4.7 RULE-04：ArcSwap snapshot 未生产采纳

### 当前状态

原子 snapshot store 已实现，但依赖：

```toml
candidate-atomic-snapshot = ["dep:arc-swap"]
```

默认关闭。

### 尚需完成

- 测量当前 `RwLock` read contention 和 reload 频率。
- 对高 route churn、规则 reload、并发 route-once 场景做对照。
- 验证旧 snapshot 的峰值内存和释放延迟。
- 决定是否默认使用 ArcSwap。

### 完成标准

- 有真实 lock contention 证据和 ABBA 结果。
- reload 原子语义、内存峰值和 shutdown 生命周期通过测试。
- 默认策略有明确决议。

---

## 4.8 WIN-01：Windows 动态 UDP generation wrapper 尚未完成去锁

### 当前证据

目标文件：

```text
crates/ferrum2-runtime/src/network_socket/generation.rs
```

动态 TCP 已使用合并 state mutex + `AtomicU8` closed；动态 UDP 仍有：

```text
resource: Arc<StdMutex<Option<Arc<...>>>>
closed:   Arc<StdMutex<Option<Cancellation>>>
```

每次 `closed()`、`live_resource()`、close/reset 可能分别进入不同 mutex。

### 尚需完成

可选设计：

- 将 resource 和 terminal cancellation 合并到一个 state mutex；或
- resource 仍用 mutex，closed 改为 atomic terminal state，并将详细 cancellation 保存在只写一次的 side storage；或
- 使用原子 generation/closed fast check，只有状态变化时进入 mutex。

### 完成标准

- 动态 UDP send/recv/closed fast path 的锁次数下降。
- reset、close、drop、concurrent send/recv 不产生 deadlock 或 stale socket 使用。
- Windows 非 TUN loopback 和 generation-reset 测试通过。

---

## 4.9 BUILD-01：ThinLTO/CU=1 尚未运行和采纳

### 当前状态

已有 `[profile.performance-thin-lto]` 和实验控制器，但没有结果 artifact。

### 尚需完成

- 在稳定机器构建 baseline 与 ThinLTO candidate。
- 记录构建时间、二进制大小、RSS、所有关键性能场景。
- 运行独立 ABBA，不能与源代码优化混在同一候选中。
- 决定是否用于 release，还是只用于特定发布产物。

### 完成标准

- 存在 hash-bound build record 和 candidate result。
- 多场景总体有益，构建成本可接受。
- release profile 决策已落地。

---

## 4.10 BUILD-02：PGO 尚未实际训练、验证和采纳

### 当前状态

工具支持 generate、训练、`llvm-profdata merge`、profile-use 和独立验证，但仓库无 `.profraw`、`.profdata` 或正式结果。

### 尚需完成

- 建立训练 workload，覆盖 TCP request/bulk、UDP small/MTU、DNS、规则六类。
- 验证 workload 与训练 workload 分离，覆盖 cold/error/different-CPU。
- 生成并哈希 raw profile 和 merged profile。
- 比较 baseline vs profile-use。
- 建立 profile 失效和重建策略。

### 完成标准

- 独立 validation 多场景改善，无明显过拟合。
- profile provenance、编译器版本和源码 digest 完整。
- release/CI 的 profile 生成策略明确。

---

## 4.11 BUILD-03：固定 CPU target feature 尚未实测和发布采纳

### 当前状态

控制器要求显式 CPU 名称、deployment ID 和 nonportable acknowledgement；暂无实际结果。

### 尚需完成

- 定义生产 CPU baseline，而不是使用不可复现的 `native`。
- 为每个支持 CPU class 构建候选。
- 验证目标 CPU、最低兼容 CPU 和 fallback artifact。
- 对 AES/BLAKE3、copy、branch-heavy rule workloads 做对照。

### 完成标准

- 发布矩阵和 fallback 明确。
- 不兼容 CPU 能 fail closed 或获得通用 artifact。
- 有 ABBA 结果和 artifact identity。

---

# 5. 原计划中尚未开始的 4 项

这些项目不是遗漏，而是应继续保持证据驱动。只有满足前置条件时才实施。

## 5.1 UDP-14：`recvmmsg`/`sendmmsg`

### 当前状态

未发现 batch recv/send 实现。

### 实施前置条件

- UDP-06 exact-size 已完成。
- NEW-UDP-01/02 的共享锁问题已处理。
- profile 显示 syscalls/datagram 仍是主导成本。
- 有安全、已审查的封装；workspace 不得新增普通业务代码 unsafe。

### 可能设计

- 固定 batch 上限。
- buffer 全部来自有界 pool。
- partial send、单消息错误、fairness 和 shutdown 有完整语义。

### 完成标准

- syscalls/datagram 明显下降。
- 低流量 p99 不因等待成批而恶化。

---

## 5.2 OBS-01：metrics per-worker aggregation

### 当前状态

未发现 worker-local counter/周期聚合生产实现。

### 实施前置条件

- `perf c2c`、cache-line bounce 或 counter contention 证明共享 atomics 是显著热点。
- M0-02 已接入正确的观测。

### 完成标准

- counter contention 下降。
- 指标总量和 label 语义保持正确。
- 聚合延迟和 shutdown flush 明确。

---

## 5.3 BUILD-04：allocator 对照实验

### 当前状态

没有 allocator candidate feature、依赖或正式结果。

### 实施前置条件

- TCP/UDP/DNS/SOCKS 剩余可直接消除的分配已经处理。
- allocation hotspot 重新 profile 后，allocator CPU/lock 仍然显著。

### 完成标准

- 比较 system allocator 与候选 allocator 的 CPU、lock、RSS、fragmentation、long-run growth。
- Linux/Windows 分平台决策，不允许只看短时吞吐。

---

## 5.4 BUILD-05：Tokio worker/affinity 对照

### 当前状态

只有实验矩阵能力，没有正式运行结果或生产配置。

### 实施前置条件

- NEW-UDP-01/02 全局锁问题已处理或量化。
- TCP self-wake 和 DNS/codec 串行问题已处理。

### 完成标准

- 比较 default、physical-core、reduced worker variants。
- 记录 throughput、p99、context switches、CPU utilization。
- 不把增加 worker 当作共享锁问题的替代方案。

---

# 6. 新发现的 6 个具体代码残留

## 6.1 NEW-UDP-01：established-session 每包仍经过进程级 admission gate

### 严重性

**P0。** 这是本次重新核对后最重要的新发现。

### 当前证据

目标文件：

```text
bins/ferrum2-server/src/run/udp/run_loop.rs
```

每个认证成功的请求在约 153–157 行先执行：

```rust
guard = admission.lock() => guard
```

随后才执行：

- `protocol.existing_capability(&pending)`；
- `mappings.identity(capability)`；
- established Direct binding lookup。

对于 live Direct session，代码在约 245 行才释放 gate。也就是说，即使后续 runtime session state 已分片，多个 `SO_REUSEPORT` receive worker 的 established packet 仍会在这段 process-wide gate 上排队。

### 尚需完成

#### 方案一：established fast path 无全局 gate

1. 从 authenticated session ID 得到稳定 shard。
2. 在 shard 中读取 capability、frozen identity 和 runtime handle。
3. 通过 runtime generation reservation 完成 stale-handle recheck。
4. 在 reservation commit 中提交 per-session protocol replay/peer/activity。
5. 只对 new/rejected/orphan identity 使用全局 admission gate。

#### 方案二：worker-affine ownership

- session ID 稳定映射到 owner worker。
- 非 owner worker 将 packet 投递到有界 channel。
- owner 串行维护 protocol state，无跨 worker mutex。

### 不变量

- 并发 first packet 只能有一个 winner。
- route-once identity freeze 不改变。
- stale runtime generation 在 protocol mutation 前失败。
- rejected/orphan pruning 不与 established commit 竞态。

### 完成标准

- established Direct packet 不获取 process-wide `admission` mutex。
- `receive_workers=1/2/4/8` 在多 session workload 下具备可观察扩展性。
- lock wait/hold 指标证明该 gate 不再是主瓶颈。

---

## 6.2 NEW-UDP-02：`UdpServer`/`UdpMappings` 仍有全局 mutex 和通知惊群

### 当前证据

#### `UdpServer`

```text
crates/ferrum2-shadowsocks/src/udp/server.rs
```

仍包含：

```rust
state: Mutex<ServerState>
```

其中有：

```text
sessions
capability_sessions
outbound_sessions
```

lookup/create/remove 会进入该共享 map lock；每 session protocol 虽然有独立 mutex，但索引仍全局。

#### `UdpMappings`

```text
bins/ferrum2-server/src/run/udp/identity.rs
```

仍包含：

```rust
state: Mutex<UdpMappingState>
published: tokio::sync::Notify
```

`capability(handle)` 在全局 Notify 上等待；每次 publish/invalidate/reset 使用：

```rust
published.notify_waiters()
```

并发等待很多 handle 时，一次 publish 会唤醒全部 waiter，再让大部分重新争用同一个 mutex。

### 尚需完成

- `UdpServer` maps 按 session ID/capability hash 分 shard。
- 每个 shard 维护 session map 和 per-session protocol Arc。
- `UdpMappings` 改为 generational slot/shard，或复用 runtime handle index。
- capability publication 使用 per-handle oneshot/watch/Notify，不使用 process-wide notify-all。
- maintenance reconcile/prune 不复制全量 key 后逐项重新加锁；改为增量或 shard-local sweep。

### 完成标准

- 不同 session lookup/create/commit 可并行。
- 发布一个 capability 不唤醒无关 handle waiter。
- 1/2/4/8 worker benchmark 中 map-lock contention 明显下降。

---

## 6.3 NEW-UDP-03：AES UDP body cipher 逐包派生和构造

### 当前证据

目标文件：

```text
crates/ferrum2-crypto/src/udp/aead.rs
vendor/shadowsocks-crypto/src/v2/udp/aes_gcm.rs
```

多个 seal/open 路径调用：

```rust
crypto.aes_body_cipher(session_id)
UdpCipher::try_new(...)
```

vendored `try_new` 每次会：

1. `Vec::with_capacity(key_len + session_id.len())`；
2. 拼接 PSK + session ID；
3. 执行 BLAKE3 `derive_key`；
4. 构造 AES-GCM cipher。

这是确定的逐包分配、哈希派生和 cipher 初始化，不只是理论风险。

### 尚需完成

- outbound session 创建时缓存 derived body cipher。
- inbound 已接受 session 在 `ServerSession`/client association state 中缓存 cipher。
- 未知新 session 的第一包仍可临时派生；认证成功并提交 session 后才缓存。
- 明确 cipher clone 能力；若 cipher 不可安全 clone，则使用 Arc 或把 crypto operation 放在 per-session state 内。
- session expiry/drop 时完成 key material zeroization。

### 安全要求

- 未认证 session ID 不得污染长期 cache。
- cache key 必须绑定 profile、PSK generation 和 session ID。
- key reload 后旧 cipher 不得跨 generation 使用。
- cache 不得无界增长。

### 完成标准

- established AES session 的 `aes_body_cipher_constructions/datagram` 接近 0。
- 顺序小包 workload 不再逐包分配 derive material Vec。
- AES 与 ChaCha 分场景 benchmark；认证失败和 key reload 测试通过。

---

## 6.4 NEW-SOCKS-01：SOCKS UDP 仍有最大 buffer 预零和逐包 payload copy

### 当前证据

目标文件：

```text
bins/ferrum2-client/src/run/socks/endpoint.rs
bins/ferrum2-client/src/run/socks/association.rs
bins/ferrum2-client/src/run/socks/dns_hijack.rs
```

每个 `SocksUdpEndpoint` bind 时：

```rust
wire: vec![0; MAX_SOCKS_UDP_DATAGRAM_BYTES]
```

这会立即分配并清零最大 UDP wire。

接收后，多个路径执行：

```rust
let payload = decoded.payload().to_vec();
```

因此每个 application datagram 至少产生一次实际 payload allocation/copy。

### 尚需完成

推荐引入 owned-buffer endpoint：

- receive wire 使用 `BytesMut::with_capacity` + `recv_buf_from`，避免预零整个最大范围。
- decode 返回 target/payload ranges。
- 将 owned wire 或精确 payload buffer移交给 association。
- endpoint 使用第二块有界 buffer 或 buffer lease 继续收发；association 当前串行时也可在请求完成后回收原 wire。
- response encode 使用独立、延迟分配的 send wire，避免 receive borrow 迫使 payload `to_vec()`。

### 完成标准

- endpoint 创建不触碰整个最大 buffer。
- 主 SOCKS UDP request path 不再固定 `payload.to_vec()`。
- 每 association buffer 数量和总预算有硬上限。
- source pinning、invalid wire、DNS hijack、idle timeout 和最大包测试通过。

---

## 6.5 NEW-DNS-01：DNS egress channel 仍逐包分配和复制

### 当前证据

目标文件：

```text
crates/ferrum2-dns/src/channel_datagram.rs
bins/ferrum2-server/src/dns_egress.rs
bins/ferrum2-client/src/dns_egress.rs
```

`ChannelDnsDatagram` 的 packet 类型仍是：

```rust
type Packet = Vec<u8>;
```

发送时：

```rust
permit.send(buffer.to_vec());
```

接收时又：

```rust
buffer[..packet.len()].copy_from_slice(&packet);
```

服务端 DNS egress 接收 physical UDP response 后还执行：

```rust
response[..length].to_vec()
```

因此一次 DNS datagram 可能在 runtime ↔ channel ↔ physical socket 边界经历多次分配和复制。

### 尚需完成

可选设计：

1. channel packet 改为 `Bytes`/`BytesMut`。
2. 使用 bounded buffer lease pool，mpsc 传递 lease ownership。
3. `DnsDatagramIo` 若必须写入 caller slice，至少让 producer→channel 边界零额外复制。
4. 服务端 response 直接把 `BytesMut` 精确 split/freeze 后送入 channel。
5. 保持 channel depth=1 和最大 datagram bytes 的有界语义。

### 完成标准

- `poll_send` 不再每次 `buffer.to_vec()`。
- physical response 不再 `response[..length].to_vec()`。
- allocations/query 和 copy bytes/query 下降。
- DNS timeout、cancel、channel close、oversize 测试通过。

---

## 6.6 NEW-UDP-04：公开 borrowed UDP scratch 仍预留最大容量

### 当前证据

目标文件：

```text
crates/ferrum2-shadowsocks/src/udp/mod.rs
crates/ferrum2-shadowsocks/src/udp/wire.rs
```

`UdpPacketScratch::new()` 当前使用：

```rust
BytesMut::with_capacity(MAX_UDP_WIRE_LEN)
```

borrowed `open_packet` 还会把完整 wire 复制到 scratch。主 client/server 生产路径已迁移到 owned/in-place，因此这不是当前主数据面瓶颈，但公开 API、examples 或外部调用方仍承担最大容量预留和完整复制。

### 尚需完成

- `UdpPacketScratch::new()` 初始为空或使用小容量。
- 收到 wire 后按 `wire.len()` exact reserve/grow。
- 增加 `with_capacity` 或显式 preallocate API，让高性能调用方自主选择。
- 文档明确 owned/in-place API 是推荐生产路径。

### 完成标准

- 创建 scratch 不自动保留 65,507 bytes。
- borrowed path 行为和错误语义保持兼容。
- 不影响 owned/in-place 主路径。

---

# 7. 共享验证与采纳门禁

这些项目不应与工程待办重复计数，但在完成前不能声称“优化全部完成”或给出性能提升百分比。

## 7.1 GATE-01：Rust 构建、格式、Clippy 和测试门禁

当前审查环境没有 `cargo`/`rustc`，需在 Rust 1.97.1 环境运行：

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace \
  --exclude ferrum2-client \
  --exclude ferrum2-tun \
  --exclude ferrum2-platform-windows \
  --locked
cargo test -p ferrum2-client --all-features --no-run --locked
cargo test -p ferrum2-dns --features __interop-test-root --locked
```

还应增加：

```bash
cargo test -p ferrum2-shadowsocks --all-features --locked
cargo test -p ferrum2-runtime --all-features --locked
cargo test -p ferrum2-rule --all-features --locked
```

完成标准：所有命令在干净 checkout 和 locked dependencies 下通过。

---

## 7.2 GATE-02：本版本真实 candidate-vs-parent ABBA 结果

压缩包中没有发现与本轮源码对应的真实 result JSON。

必须补充：

- 六对预注册 ABBA。
- parent/candidate artifact hash。
- environment identity。
- raw trial JSONL、summary、controller digest。
- correctness status。
- TCP、UDP、DNS、规则和高连接数关键场景。

完成标准：关键候选状态为 `CANDIDATE_WIN` 或 `WITHIN_CALIBRATED_BAND`，而不是只通过控制器单测。

---

## 7.3 GATE-03：高噪声场景稳定裸机复校

当前以下 hosted-runner calibration 几乎无法识别常见优化：

| 场景 | noise band | adoption threshold |
|---|---:|---:|
| `dns-cache-size-4096` | 208.9% | 261.2% |
| `dns-cache-size-65536` | 67.8% | 84.8% |
| `tcp-bulk` | 29.2% | 36.5% |
| `tcp-stream-64k` | 97.4% | 121.8% |

需在稳定自托管/裸机环境固定：

- CPU affinity。
- NUMA。
- governor/frequency。
- SMT policy。
- client/server/runner 进程布局。
- 背景服务和热身时长。

完成标准：A/A 噪声可支持识别预期的个位数到二十个百分点改进。

---

## 7.4 GATE-04：规则 qualification calibration 与默认采纳

`ferrum2-rule-qualification` 文档仍要求单独审查、source-hash-bound calibration artifact。RULE-01/02/04 的实现存在不等于可以默认启用。

完成标准：

- rule calibration 不再是 `CALIBRATION_REQUIRED`。
- 小/中/大规则集和构建内存均有证据。
- 默认 feature 决议记录在代码、Cargo feature 和文档中。

---

## 7.5 GATE-05：Linux 多 receive worker 扩展性和默认值决策

当前 `udp.receive_workers` 默认仍为 1。实现支持 1..32 不代表 2/4/8 能扩展。

必须测试：

```text
receive_workers = 1 / 2 / 4 / 8
```

同时记录：

- `admission` wait/hold。
- `UdpServer.state` wait/hold。
- `UdpMappings.state` wait/hold。
- packets/s、p99、CPU/core、context switches。
- 同 session 与多 session 两种 workload。

完成标准：在 NEW-UDP-01/02 处理后，确定文档化的推荐值；默认值是否改变必须由实测决定。

---

## 7.6 GATE-06：Windows 非 TUN 动态 UDP 验证

WIN-01 完成前后都需在 Windows 运行：

- compile/all-features。
- static fast path vs dynamic wrapper loopback。
- generation reset concurrent send/recv。
- 1k/10k socket scale。
- locks/operation、tasks/socket、RSS、p99。

仅验证物理 TCP/UDP generation path，不包含 TUN/Wintun。

---

## 7.7 GATE-07：性能证据持久化

当前 workflow artifact retention 为 30 天，仓库 invariant 已标记“不是 durable provenance”。

尚需完成：

- 将 raw evidence、summary、calibration、artifact manifest 保存到长期不可变存储。
- 以 digest 在仓库或发布记录中引用。
- 定义 retention、访问控制、删除策略和恢复验证。
- 不能只保留 screenshot、compact fixture 或 policy 文档。

完成标准：任何采纳决策都能通过 digest 找回原始 evidence。

---

# 8. 推荐执行顺序

## Wave 0：先补可信门禁

1. GATE-01 Rust build/test。
2. M0-02 结构指标接线。
3. 为 NEW-UDP-01/02/03 和 UDP-06 增加定向 microbenchmark。
4. GATE-03 稳定环境复校。

## Wave 1：解决 UDP 当前最明确瓶颈

1. UDP-06 exact-size wire growth。
2. NEW-UDP-01 established fast path 去 process-wide gate。
3. NEW-UDP-02 protocol/mapping sharding和 per-handle publication。
4. NEW-UDP-03 AES body cipher session cache。
5. GATE-05 运行 1/2/4/8 worker scale。

## Wave 2：完成 TCP 和应用边界精修

1. TCP-06 read poll 有界推进。
2. TCP-07 specialized zero-copy relay。
3. NEW-SOCKS-01 owned-buffer path。
4. NEW-DNS-01 channel buffer lease。
5. WIN-01 动态 UDP wrapper 去锁。

## Wave 3：候选特性采纳

1. GATE-04 rule calibration。
2. RULE-01 domain trie。
3. RULE-02 CIDR radix。
4. RULE-04 ArcSwap。
5. BUILD-01 ThinLTO。
6. BUILD-02 PGO。
7. BUILD-03 target-cpu。

## Wave 4：仅在 profile 证明后执行

1. UDP-14 batch syscalls。
2. OBS-01 metrics aggregation。
3. BUILD-04 allocator。
4. BUILD-05 Tokio worker/affinity。
5. NEW-UDP-04 borrowed scratch 优化。

---

# 9. 依赖关系

```text
GATE-01 + M0-02
├── UDP-06
├── NEW-UDP-01
│   └── NEW-UDP-02
│       └── GATE-05
├── NEW-UDP-03
├── TCP-06
│   └── TCP-07
├── NEW-SOCKS-01
├── NEW-DNS-01
└── WIN-01
    └── GATE-06

GATE-03 + GATE-02
├── RULE-01 / RULE-02 / RULE-04 + GATE-04
├── BUILD-01
├── BUILD-02
└── BUILD-03

完成主要结构热点并重新 profile 后
├── UDP-14
├── OBS-01
├── BUILD-04
└── BUILD-05
```

---

# 10. 建议新增的定向场景

## UDP server scaling

- `udp-server-workers-1`
- `udp-server-workers-2`
- `udp-server-workers-4`
- `udp-server-workers-8`
- 每个场景分为：单 session 高 PPS、多 session 高 PPS、新 session churn。

## AES cipher construction

- `udp-aes-established-small-128`
- `udp-aes-new-session-small-128`
- `udp-chacha-established-small-128` 作为对照。

## SOCKS UDP

- 10k dormant associations RSS。
- 128-byte sequential request/response。
- allocation/copy per datagram。
- max packet 和 DNS hijack。

## DNS channel

- physical UDP egress 1/64/256 concurrent。
- allocations/query。
- channel depth=1 backpressure。

## TCP scheduling/relay

- 1-byte fragmented reads。
- 1 KiB request。
- 64 KiB stream。
- wakeups/frame、copy bytes/frame、RSS/connection。

---

# 11. 不应误判为“未完成”的项目

以下实现目前是有界且符合既定设计，不应仅因为存在最大容量 buffer 就自动重写：

- 服务端 response codec 的固定、预算内 multi-wire pool。
- Direct UDP 每 session 一块持久 receive scratch。
- DNS listener 的固定并发 request/response slots。
- 每 session protocol mutex：同一 session 的 replay/counter 本身需要串行；真正问题是跨 session 的全局 gate/map lock。
- `udp.receive_workers` 默认 1：在扩展性证据完成前，保守默认并非缺陷。

以下实验也不应为了完成率立即做：

- allocator 替换。
- Tokio worker 数增加。
- metrics aggregation。
- `recvmmsg/sendmmsg`。

它们必须由 profile 证明是剩余主导成本。

另外，build experiment 工具还支持 `panic-abort-strip`，但该项主要涉及二进制体积、panic/backtrace 和故障诊断语义，不属于本清单的核心性能完成标准；可作为独立发布实验处理。

---

# 12. 最终完成定义

只有同时满足以下条件，才能将非 TUN 性能优化标记为“完成”：

## 代码层面

- [ ] 上表所有 P0/P1 必做项完成。
- [ ] UDP established fast path 不经过 process-wide admission gate。
- [ ] 客户端 SS UDP 小包不按最大 wire 清零。
- [ ] established AES session 不逐包派生 body cipher。
- [ ] TCP read 状态不进行无必要 self-wake。
- [ ] zero-copy relay 已在生产 specialized path 生效，或有证据证明不采纳。
- [ ] Windows 动态 UDP fast path 完成去锁或有证据证明当前锁成本可忽略。

## 正确性层面

- [ ] Rust 1.97.1 下 fmt、Clippy、workspace tests 和 all-features compile 全部通过。
- [ ] nonce、认证失败、replay、route-once、generation、budget、cancel 和 shutdown 不变量全部覆盖。
- [ ] Linux/Windows 非 TUN 平台测试通过。

## 性能证据层面

- [ ] 结构指标能够直接报告 copy/zero/wakeup/lock wait。
- [ ] 本版本有真实六对 ABBA artifact。
- [ ] 高噪声场景已在稳定裸机复校。
- [ ] 1/2/4/8 UDP worker 扩展性已验证。
- [ ] 规则和 build candidates 有正式采纳或拒绝决议。
- [ ] 原始 evidence 可长期按 digest 恢复。

## 状态结论

在上述门禁完成之前，推荐版本状态仍为：

> **非 TUN 性能优化主要结构已完成，但仍处于最后热点收敛、候选采纳和真实性能验收阶段。**

