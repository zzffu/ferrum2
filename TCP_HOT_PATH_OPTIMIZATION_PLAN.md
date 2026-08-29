# Ferrum2 TCP 热路径优化计划

状态：待实施

基线提交：`1e08868c8c3d523f1275cd6f8d3b63f4d42453e6`

范围：Shadowsocks 2022 TCP、公共双向 relay、Windows 物理 TCP、TUN TCP

## 1. 目标

按风险从低到高消除当前 TCP 热路径中已经由源码确认的成本：

1. 消除 Shadowsocks 稳态解密的每帧堆分配。
2. 消除解密状态切换时对 65,551 字节 scratch 的重复清零。
3. 消除发送编码时为插入 18 字节长度头而执行的整帧 `copy_within`。
4. 正确处理所有合法 partial read/write，并减少主动 self-wake。
5. 利用 SIP022 initial payload，减少 TLS/HTTP 首包的额外 frame 和 write。
6. 移除 Windows 与 SOCKS 数据阶段的每-poll 同步锁。
7. 将 TUN TCP 从“扫描全部 live flow”改为“只驱动 ready flow”，减少跨线程锁、复制和唤醒。

所有优化必须保持：

- SIP022 wire compatibility；认证失败仍 fail closed 且不提交 nonce，但不再保证输入 buffer 不变；
- nonce exhaustion 仍必须在 primitive 执行前失败，且不得修改 buffer 或 counter；
- 有界背压、双向公平性、TCP half-close 和取消语义；
- workspace `unsafe` 策略不变；
- 日志和错误不暴露密钥、nonce 或 peer payload；
- 无兼容 shim：接口变更时同步更新仓库内全部调用者和测试。

## 2. 非目标

- 不把普通加密代理改造成 Linux transparent relay；需要加解密的 endpoint 不能使用 socket-to-socket `splice` 绕过用户态。
- 第一轮不调整 32 KiB record 大小。sing-box 当前选择接近 32 KiB，而 shadowsocks-rust 的 64 KiB 是 framing、内存和帧内 HOL 延迟之间的另一种权衡。
- 第一轮不引入全局 buffer pool、TFO、MPTCP、socket buffer 配置或替换 allocator；这些只在前述确定性成本消除后按 profile 证据决定。
- 不在同一个变更中混合 codec、Windows stream 和 TUN scheduler 重构。

## 3. 模块与 seam

### 3.1 Shadowsocks TCP frame module

外部 interface 继续是 `ClientFlow`/`ServerFlow` 的 `AsyncRead + AsyncWrite`。调用者不需要知道 nonce、tag、headroom、scratch 大小或 RX/TX 状态。

实现内部形成一个深 module，集中拥有：

- cipher 和 nonce 状态；
- 固定 encrypt/decrypt backing storage；
- encrypted-length、payload、ready-plaintext 和 staged-write 状态；
- partial I/O、认证失败、EOF 和 shutdown 处理。

内部 crypto seam 使用可变 slice 和逻辑长度进行原位 seal/open。它不得为每个 packet 分配，也不得要求调用者通过 `BytesMut::clear/resize` 表达状态。

测试只通过 frame/flow interface 断言 wire bytes、明文、错误、allocation、背压和 half-close，不再用 scratch 指针稳定性代替真实 allocation 约束。

#### 认证失败 buffer 契约决策

删除“AEAD 认证失败后输入 ciphertext buffer 原样不变”的旧契约。该契约目前由 `crates/ferrum2-crypto/tests/sip022_vectors.rs` 的 corrupted-buffer 相等断言固定，并迫使 `TcpOpener::open_in_place` 在每次尝试前复制完整 body。生产调用者在认证失败后都会终止握手或把 flow 置为 poison，不会重用失败 buffer，因此保留原 ciphertext 没有调用者价值，却让每个成功 frame 都承担 allocation、两次复制和临时清零成本。

新的 interface 契约为：

| 结果 | 输入 buffer | nonce |
| --- | --- | --- |
| 成功 | 同一 backing storage 中得到已认证明文 | 提交一次 |
| `AuthenticationFailed` | buffer 内容未指定且调用者不得再读取或复用；实际进入 primitive 的 body 会被清零，过短输入也必须整体丢弃 | 不提交 |
| `NonceExhausted` | 保持不变 | 保持不变 |

认证失败仍必须满足：不释放未经认证的明文、安装 fatal terminal、丢弃整个 frame/flow。测试应断言这些可观察结果和 nonce rollback，不再断言失败 ciphertext 的逐字节保留。

### 3.2 Generation-bound TCP module

`GenerationBoundTcpStream` 应由连接任务独占底层 stream 和 cancellation state。`poll_read`/`poll_write` 使用 `&mut self` 的独占性直接 poll，不再把 stream、future 和 closed 状态分别放在 `std::sync::Mutex` 后。

generation invalidation 仍封装在该 module 内；调用者只观察普通 `AsyncRead/AsyncWrite` 成功、EOF 或关闭错误。

### 3.3 TUN TCP bridge module

外部 interface 保持：应用侧是 `TcpFlow: AsyncRead + AsyncWrite`，stack 侧是 owner handle。

stack 侧不再暴露多个浅查询方法。由一个深的 `drive` 操作在一次 bridge 获取中完成：

- abort/close 状态判断；
- application/stack capacity 计算；
- 两方向传输；
- FIN/RST 状态推进；
- waker 和 ready 状态更新。

ready-flow queue/bitset 使用 slot generation 防止陈旧唤醒，并使用 per-flow 去重标志防止同一 flow 被重复入队。

## 4. 实施阶段

### 阶段 0：建立可重复基线

改动：仅测试/测量工具，不改变生产行为。

1. 在本地保存当前提交的 paired parent/candidate 基线：
   - `tcp-bulk`：吞吐主指标；
   - `tcp-stream-64k`：连续流 guard；
   - `tcp-request-1k`：小请求 p99 guard；
   - `tcp-scale-10k`：连接规模和 RSS guard。
2. 分别记录 client/server CPU profile；Windows TUN 另记录 owner thread 和 Tokio worker。
3. 为 `ferrum2-shadowsocks` 准备串行、current-thread 的 `stats_alloc` 测量：warm-up 后连续处理 1 B、1 KiB、32 KiB payload，统计 allocation、reallocation 和 allocated bytes。
4. 准备 scripted transport，使每次 read/write 只前进 1 字节或 7 字节；新断言与对应修复在同一提交落地，避免主分支保留预期失败测试。
5. 增加 TUN 诊断基准：1/256/4096 个 idle flow，以及 1/16/256 个 ready flow，记录一次 `drive_tcp` 的耗时、flow visits、bridge 获取和 wake 次数。

退出条件：基线环境、命令、配置、日志级别、样本和 profile 均可复现；没有生产代码变化。

### 阶段 1：原位解密并删除全 scratch 清零

主要文件：

- `crates/ferrum2-crypto/src/tcp/aead.rs`
- `crates/ferrum2-shadowsocks/src/tcp/flow/mod.rs`
- `crates/ferrum2-shadowsocks/src/tcp/flow/io.rs`

步骤：

1. 将 `TcpOpener` 改为直接认证并解密调用者提供的可变 slice；成功时提交 nonce，认证失败时由 primitive 破坏性清理 body，并返回现有 closed error。
2. 正式删除“认证失败后输入 buffer 不变”的 interface 契约，同时删除 `buffer[..tag_start].to_vec()`、明文拷回和临时 Vec 销毁路径。
3. 引入一次分配、固定长度的 decrypt backing storage；状态机只维护 `filled`、`wire_len` 和 ready plaintext range。
4. 删除稳态 `clear()+resize(MAX_DECRYPT_WIRE_LEN, 0)`；只覆盖实际接收范围。
5. 更新 `sip022_vectors.rs`：删除 corrupted buffer 原样相等断言，保留“失败不推进 nonce，随后合法 frame 仍可在同一 opener 上成功”的断言。
6. 同步处理握手和数据帧，避免保留第二套旧 open 路径。

验收：

- warm-up 后稳态数据 frame 为 `0 allocation / 0 reallocation`；
- 1 B 与 32 KiB frame 都满足同一 allocation gate；
- tampered/短 tag 不释放明文、终止 flow、失败 body 不可观察且 nonce 不推进；
- nonce exhaustion 保持 buffer 和 counter 不变；
- CPU profile 中不再出现每帧临时 Vec 分配/释放和 65,551 字节 memset；
- wire fixtures 与客户端/服务端互通结果不变。

建议提交：`perf(shadowsocks): decrypt TCP frames in place`

### 阶段 2：无 memmove 发送编码

主要文件：

- `crates/ferrum2-crypto/src/tcp/aead.rs`
- `crates/ferrum2-shadowsocks/src/tcp/wire.rs`
- `crates/ferrum2-shadowsocks/src/tcp/flow/io.rs`

步骤：

1. 在 encrypt backing storage 中预留 encrypted-length 所需的 18 字节 headroom。
2. 直接在最终位置写入并加密 2 字节长度和 payload，各自追加 tag。
3. 删除数据 frame 的 `resize + copy_within`。
4. 同样检查 request/response first-write 的移动路径；能使用相同内部 module 时统一实现，不保留平行编码器。
5. 暂不重写 Tokio relay 的 buffer ownership；本阶段目标是删除确定冗余的第二次整帧移动。

验收：

- 所有 method profile 的现有 wire vector 完全一致；
- 0 B、1 B、32 KiB 和超限 payload 行为保持正确；
- 稳态 write 不产生新 allocation；
- `tcp-bulk` 吞吐和 CPU 按仓库 paired performance policy 判定通过，`tcp-request-1k` 不回退。

建议提交：`perf(shadowsocks): encode TCP frames with headroom`

### 阶段 3：修正 partial I/O 并压缩调度轮次

主要文件：

- `crates/ferrum2-shadowsocks/src/tcp/handshake.rs`
- `crates/ferrum2-shadowsocks/src/tcp/flow/client.rs`
- `crates/ferrum2-shadowsocks/src/tcp/flow/server.rs`
- `crates/ferrum2-shadowsocks/src/tcp/flow/io.rs`

步骤：

1. request first-write、request first-read、response first-read 和 response first-write 全部保留 position，直到完整、底层 Pending 或错误。
2. 合法 short I/O 不再映射为 detection failure。
3. 状态转换在同一次 poll 内循环推进，只有底层真实 Pending、向调用者交付数据或达到 cooperative budget 时才返回。
4. 删除用于继续内部状态转换的 `wake_by_ref()`。
5. 为循环设置明确的 bytes/frames budget，防止 always-ready 大流独占 Tokio worker。

验收：

- 1 字节和 7 字节 scripted read/write 完成完整握手及双向 relay；
- 每个 partial I/O 测试同时覆盖 flush、shutdown 和反向继续传输；
- frame length → payload 不再强制产生一个额外 scheduler turn；
- backpressure、half-close 和取消测试全部通过。

建议提交：`fix(shadowsocks): support partial TCP frame IO`

### 阶段 4：合并 initial payload

主要文件：

- `crates/ferrum2-shadowsocks/src/tcp/handshake.rs`
- `bins/ferrum2-client/src/run/egress/tcp.rs`
- `bins/ferrum2-client/src/run/tun/tcp.rs`
- `bins/ferrum2-client/src/run/routing.rs`
- SOCKS TCP 调用路径

步骤：

1. 用新的当前接口替换 `write_request(target)`：明确接收 target 与有界 initial payload。
2. TUN route sniff 已取得的 prefix 在代理 route 中直接进入 SIP022 request first-write，不再由 `ReplayIo` 重复发送。
3. direct route 仍把 prefix 原样交付目标，确保每个 prefix 恰好消费一次。
4. SOCKS 已缓存业务数据时走同一接口；server-first 协议继续允许空 initial payload，不引入固定等待时间。
5. 如果 payload 超出首包协议容量，由 Shadowsocks module 自己顺序发送剩余 frame，不把切分规则暴露给调用者。

验收：

- TLS ClientHello、HTTP request、空 payload 和最大 sniff prefix 都只交付一次；
- 代理首包包含 target、padding 和 initial payload；
- 小请求少一个后续 SS frame 和 write；
- `tcp-request-1k` p99 按 paired policy 通过，server-first TTFB 不回退。

建议提交：`perf(client): coalesce TCP initial payload`

### 阶段 5：移除 Windows 与 SOCKS 每-poll 锁

主要文件：

- `crates/ferrum2-runtime/src/network_socket/generation.rs`
- `crates/ferrum2-runtime/src/network_socket/service.rs`
- `crates/ferrum2-socks5/src/lib.rs`
- 客户端和服务端 network adapter

步骤：

1. 让 `GenerationBoundTcpStream` 直接拥有 stream、pinned cancellation future 和原子/普通 closed 状态；利用 `&mut self` 排他性直接 poll。
2. generation 变化只触发一次关闭结果，不为每次 read/write 获取多把 `std::sync::Mutex`。
3. 删除不再需要的 per-connection monitor task，或将其改为只发无锁取消信号；不得与 I/O 任务共享可变 stream。
4. SOCKS reply 完成后把底层 IO 所有权移交给数据流，删除 relay 阶段的 `Arc<Mutex<IO>>`。

验收：

- 普通数据 poll 不获取 `std::sync::Mutex`；
- network generation 切换、取消、reset、EOF、half-close 和 shutdown race 测试通过；
- Windows native contract 通过；
- Windows TCP bulk CPU/吞吐改善且无 p99 回退。

建议拆成两个提交：

- `perf(runtime): make generation-bound TCP streams lock-free`
- `perf(socks): transfer TCP stream ownership after handshake`

### 阶段 6：TUN ready-flow 驱动

主要文件：

- `crates/ferrum2-tun/src/tcp/mod.rs`
- `crates/ferrum2-tun/src/tcp/owner.rs`
- `crates/ferrum2-tun/src/stack/tcp.rs`
- `crates/ferrum2-tun/src/lifecycle/live/owner.rs`

分两步实施：

1. 单次 bridge 获取：
   - 将多个 capacity/state/read/write 方法合并到一个内部 `drive` 操作；
   - 每个 flow visit 最多获取一次 bridge；
   - 保持现有 per-flow quantum 和 RX/TX 轮换公平性。
2. ready-flow scheduler：
   - 应用读写、socket readiness、shutdown 和 reset 只把对应 flow 标为 ready；
   - queue/bitset 使用去重标志；
   - slot generation 阻止已复用 slot 的陈旧 wake；
   - 全量 scan 仅保留为受控维护路径，不处于逐包热路径。

完成后再依据 profile 决定是否合并/缩小 smoltcp 与 bridge 的四个 32 KiB buffer；不要在 scheduler 变更中同时改变容量和背压合同。

验收：

- 一轮工作量与 ready flow 数量相关，而不是 live flow 数量；
- 4096 个 idle flow + 1 个 active flow 时，不访问其余 4095 个 bridge；
- 无 lost wake、重复入队、stale generation 或饥饿；
- TUN 公平性、背压、FIN/RST、adapter reset 和 fuzz corpus 通过；
- Windows TUN lab 的吞吐、CPU 和 owner/Tokio wake 次数按 paired policy 通过。

建议拆成两个提交：

- `perf(tun): drive each TCP bridge once per visit`
- `perf(tun): schedule only ready TCP flows`

### 阶段 7：只按 profile 证据处理剩余成本

候选项：

1. 将 relay idle tracking 合并进一个自定义双向 relay future，避免每次 write 的 `Arc<Notify>`；前提是现有 profile 显示其占比显著。
2. 对连接 churn 引入分级 buffer pool；所有回收 buffer 必须清理曾包含的明文或密文敏感范围。
3. 对 32 KiB/64 KiB record 做独立 A/B，联合评估吞吐、RSS、公平性和小请求延迟。
4. 评估 TCP keepalive、TFO、send/recv buffer 配置；保持默认行为不变，除非有跨平台资格证据。
5. 仅对真正的透明 relay 评估 Linux splice；普通加密 client/server path 不纳入。

## 5. 每阶段测试矩阵

先运行目标测试，再运行相关完整 gate：

```text
cargo test -p ferrum2-shadowsocks --features tokio --locked
cargo test -p ferrum2-runtime --test backpressure --test half_close --locked
cargo test -p ferrum2-client --all-features --no-run --locked
cargo test -p ferrum2-tun --lib --no-default-features --features fuzzing --locked
cargo test -p ferrum2-platform-windows --lib --no-default-features --features fuzzing --locked
cargo check -p ferrum2-tun -p ferrum2-platform-windows --all-features --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo run -p ferrum2-m4-qualification --bin m4-qualification --locked -- self-check
```

Windows TUN 或 generation-bound stream 变化还必须运行匹配 profile/target 的 native local contract 和批准的 Hyper-V qualification；不得把真实 adapter、route、DNS、WFP 或 Hyper-V 状态变更加入 hosted library tests。

性能验收统一使用 release binary、相同主机/CPU affinity、相同日志级别、相同 cipher/profile、paired parent/candidate 顺序和仓库现有 performance policy。不得用单次 best result 作结论。

## 6. 全局完成标准

以下条件全部满足后，TCP 热路径优化才算完成：

- Shadowsocks steady-state RX/TX：`0 allocation / 0 reallocation per frame`；
- 解密状态机不存在按最大 65,551 字节执行的逐帧清零；
- 数据 frame 编码不存在为插入长度头执行的整 payload memmove；
- 所有 handshake/data 路径正确接受合法 partial I/O；
- TUN 单轮调度复杂度与 ready flow 数量相关；
- Windows 与 SOCKS 数据 poll 不使用同步 mutex 包裹底层 stream；
- `tcp-bulk`、`tcp-stream-64k`、`tcp-request-1k`、`tcp-scale-10k` 均通过 paired performance policy；
- 正确性、interop、half-close、backpressure、取消、Windows native 和 TUN qualification 全部通过；
- 每阶段都有独立、可审查、可回退的提交和对应测量证据。

## 7. 风险与停止条件

- 原位解密会按新契约破坏认证失败后的 buffer；失败必须终止 flow、清理敏感范围且不提交 nonce。不得把这项放宽扩展到 nonce exhaustion：后者仍须保持 buffer/counter 不变。
- poll 内循环可能影响 Tokio 公平性；达到 cooperative budget 必须让出执行权。
- ready-flow scheduler 最危险的是 lost wake 和 stale slot；没有 generation/race 测试不得合并。
- buffer pooling 会延长敏感数据驻留时间；没有清理合同和 RSS/churn 证据不得实施。
- 某阶段若 correctness gate 失败，立即停止后续性能工作；若 paired performance policy 未通过，则保留 profile 证据并回退该阶段，不用后续大改掩盖结果。

## 8. 参考实现基线

- sing-box：`72686480c54296bca29d7e3ab35f29b9dc6e4c4f`
- sing：`3f8f790b7a2968307bbf900544fc8030791c715e`
- sing-shadowsocks2：`1f9f20777fd1aedc3aeaebbc08fad00a2e2f8c40`
- shadowsocks-rust：`692160c1f43a33d5ffdfd01db30d8e1be46b84a3`

借鉴范围限定为：原位 AEAD、buffer headroom/ownership、首包合并、partial I/O 状态机和可配置 socket 行为；不复制其任务数量、超时默认值、64 KiB 固定 buffer 或 transparent relay splice 设计。
