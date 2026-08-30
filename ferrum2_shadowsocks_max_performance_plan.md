# Ferrum2 Shadowsocks 最大性能数据面方案

> **分析快照：2026-08-29（Asia/Tokyo）**  
> **目标：**详细比较 sing-box/sing 与 shadowsocks-rust 的 TCP/UDP 数据面，实现取长补短，并结合 ferrum2 当前 `bda542efe21941706f4d79dd007d1131e03a20cc` 的真实代码、约束与已发生回归，给出可落地、可验证、以最大性能为目标的实施方案。  
> **重要前提：**“最大性能”是设计目标，不等于在未测量前承诺固定百分比；所有默认启用都必须通过 ferrum2 现有的 approved-host、A/A 校准和六对 ABBA 证据门禁。

---

## 0. 执行结论

### 最终推荐：Fused Two-Buffer Shadowsocks Relay

建议实现一个 **Fused Two-Buffer Shadowsocks Relay（FTBR，融合式双缓冲 Shadowsocks relay）**，核心取舍如下：

1. **调度和背压语义采用 Tokio / shadowsocks-rust 的模型**
   - 每个方向独立状态机；
   - buffer 空时只读一次；
   - 一旦读到非空数据，必须先写完或遇到 `Pending`，不能继续读取来“凑满”；
   - EOF 后排空已有数据，再做 write-half shutdown；
   - 两个方向继续独立运行，直到都完成。

2. **数据所有权和最终布局采用 sing-box/sing 的模型**
   - writer 声明所需 front headroom、rear headroom 和最大 payload；
   - plaintext 直接读入最终 Shadowsocks wire 的 payload 区域；
   - 长度字段和 tag 在预留区域中原地生成；
   - 解密后的 plaintext 直接从 flow 的 decrypt backing 写入目标 socket；
   - 不再经过额外的通用 relay buffer。

3. **复用 ferrum2 已有优势，而不是照搬任一项目**
   - 保留 destructive `open_in_place`；
   - 保留 nonce 只在成功后提交；
   - 保留 detached tag 的最终布局 seal；
   - 保留现有 `PollBudget`、取消、idle timer、half-close 和资源预算；
   - 保留 UDP direct-to-wire、owned wire、固定 response wire lease 和成功路径逻辑 `clear()`。

4. **生产快路径只先覆盖最常见的单跳组合**
   - 客户端：SOCKS TCP socket ↔ 单个 Shadowsocks client flow；
   - 服务端：单个 Shadowsocks server flow ↔ direct target TCP socket；
   - multi-hop、插件、复杂 wrapper、未知 endpoint 自动回退到当前 `TokioFramed + relay_lifecycle`。

5. **第一版不增加全局 TCP buffer pool**
   - ferrum2 的 flow 已经永久持有一块 encrypt buffer 和一块 decrypt buffer；
   - 最大性能方案应直接把这两块变成 relay 的两个方向 buffer；
   - 这样可移除当前 relay 额外持有的两块 32 KiB buffer；
   - 每个活跃单跳连接可直接减少 **64 KiB 的 tracked relay capacity**，同时避免全局 pool 竞争和跨连接 plaintext 复用问题。

一句话概括：

> **用 shadowsocks-rust 的“读一次就写”的状态机纪律，配上 sing-box 的 owned-buffer/headroom 数据布局，再用 ferrum2 已有的原地 crypto、显式公平预算和资源门禁来实现。**

---

## 1. 对比基线与版本

本报告按下列精确版本分析，避免把不同年代的实现混在一起：

| 项目 | 分支/版本 | 精确版本 |
|---|---|---|
| sing-box | `testing` | `f5b8b7a57922084361907a13273f2c88f35ae7c7` |
| sagernet/sing | sing-box 当前依赖 | `v0.9.0-beta.4` |
| sing-shadowsocks | sing-box 当前 inbound 依赖 | `v0.2.8` |
| sing-shadowsocks2 | sing-box 当前 outbound 依赖 | `v0.2.1` |
| shadowsocks-rust | `master` | `5f2cbad93168d098d780dbd5323ad7a4a4167b62` |
| ferrum2 | 当前性能 PR head | `bda542efe21941706f4d79dd007d1131e03a20cc` |
| ferrum2 基线 | PR base | `bd0742464b15d43dc1dc72c56f78a81dc3c02a1f` |

sing-box 当前 `go.mod` 明确绑定上述 sing、sing-shadowsocks 和 sing-shadowsocks2 版本。[^singbox-gomod]

---

# 第一部分：两种参考实现的深入分析

## 2. sing-box / sing：以 buffer ownership 为中心的能力协商 copy engine

### 2.1 双向 relay 的基本调度

sing-box 的连接管理器为两个方向分别启动一个 goroutine：

```text
goroutine upload:   inbound  -> outbound
goroutine download: outbound -> inbound
```

每个方向调用 sing 的 `bufio.CopyWithIncreateBuffer`。正常 EOF 后，对目标执行 `CloseWrite`；另一方向仍可继续运行。[^singbox-route-conn]

这给它带来三个特点：

- 一个方向的慢 writer 不直接阻塞反方向；
- 不需要在单个状态机里自行处理方向公平性；
- Go runtime/netpoll 负责 goroutine 的唤醒和调度。

ferrum2 不必照搬“两 goroutine/两 task”，但必须保留同样的**方向独立性**。在 Rust/Tokio 中，一个 bidirectional future 内部维护两个独立单向 FSM，通常比拆成两个 task 更易维持连接所有权、取消和 half-close。

---

### 2.2 copy engine 不是简单的 `io.Copy`

sing 的 copy engine 会按 endpoint 能力选择不同路径：

```text
1. 两端都可安全暴露 syscall fd
   -> 尝试 splice/direct path

2. source 支持 ReadWaiter，destination 支持 ExtendedWriter
   -> owned pooled buffer handoff

3. 两端支持 vectorised read/write
   -> readv/writev 风格批处理

4. 以上都不满足
   -> pool buffer fallback
```

其关键 owned-buffer 循环近似：

```go
for {
    buffer = source.WaitReadBuffer()
    destination.WriteBuffer(buffer)
}
```

拿到一个非空 buffer 后立即交给 writer，不再额外读取第二个 buffer等待“凑满”。[^sing-copy][^sing-copy-direct]

这点非常关键：

> sing 的 32 KiB 是 buffer **容量**，不是 write 的 **触发阈值**。

---

### 2.3 layout negotiation：front/rear headroom

sing 的 `ReadWaitOptions` 会根据 destination 计算：

- `FrontHeadroom`
- `RearHeadroom`
- MTU
- reader overhead
- 是否进入大 buffer 模式
- batch size

source 在读取前就按 destination 的布局需求拿到合适 buffer。[^sing-read-options]

对经典 Shadowsocks AEAD TCP writer，sing-shadowsocks2 声明：

```text
FrontHeadroom = 2-byte length + 16-byte length tag = 18 bytes
RearHeadroom  = 16-byte payload tag
```

writer 的 `WriteBuffer` 会：

1. 用 `ExtendHeader(18)` 打开前置区域；
2. 写入并原地加密 length；
3. 对原 payload 区原地 seal；
4. 在末尾扩展 payload tag；
5. 把同一个 buffer 的所有权交给底层 writer。[^sing-ss-writer]

布局为：

```text
读取前
┌─────────────────┬──────────────────────────┬──────────────┐
│ 18B front space │ plaintext write region   │ 16B rear cap │
└─────────────────┴──────────────────────────┴──────────────┘

seal 后
┌──────────────────┬───────────────────────────┬─────────────┐
│ encrypted length │ encrypted payload         │ payload tag │
└──────────────────┴───────────────────────────┴─────────────┘
```

因此 raw plaintext → Shadowsocks 的热路径可以不发生 relay-buffer → crypto-buffer 的 payload copy。

---

### 2.4 解密方向：完整 frame 的 owned handoff

sing-shadowsocks2 的 reader：

1. 读完整 encrypted length；
2. 原地打开 length；
3. 按 length 申请一个 pooled frame buffer；
4. 读完整 ciphertext + tag；
5. 原地 `Open`；
6. truncate 到 plaintext length；
7. 通过 `WaitReadBuffer()` 把这个 buffer 直接返回。[^sing-ss-reader]

当下游不要求额外 headroom 时，返回的就是 decrypt frame 本身；copy engine 随即调用目标的 `WriteBuffer`。

所以常见 Shadowsocks → raw TCP 路径为：

```text
encrypted socket
    -> one owned frame buffer
    -> in-place open
    -> direct WriteBuffer to plain socket
```

它消除了 decrypt scratch → generic relay buffer 的额外 copy。

不过 sing-box 并不是所有组合都零 copy：

- 下游需要当前 buffer 不具备的 headroom；
- wrapper 不实现 ExtendedReader/Writer；
- handshake/cached data；
- multi-hop layout 不兼容；
- fallback 普通 `Read`/`Write`；

这些情况下仍会复制。`WaitReadBuffer()` 的代码也明确：当 destination 需要 headroom 时，会创建正确布局的新 buffer 并复制 cache。[^sing-ss-reader]

---

### 2.5 buffer 尺寸、自适应与 vectorized I/O

sing 的标准 TCP buffer 为 32 KiB。[^sing-buffer-size]

copy engine 默认在累计传输约 512,000 bytes 后允许进入 increase-buffer/vectorized 候选，默认 vector batch size 为 8。[^sing-copy]

需要区分两种 batching：

**安全 batching：**

```text
一次 readv/read syscall 获取当前已经 ready 的数据
-> 立即写出
```

**危险 batching：**

```text
已经有数据
-> 人为继续 poll/read
-> 等未来更多数据或填满 32 KiB
-> 才写出
```

sing 做的是前者。它可以批量处理已经 ready 的 buffer，但不把“未来可能到来的数据”作为当前写出的前置条件。

---

### 2.6 sing-box 方案的优势

- 最强的跨层 buffer ownership contract；
- raw → SS 可直接读入最终 wire payload region；
- SS → raw 可直接交付 decrypted owned frame；
- 通用 copy engine 能按能力降级；
- 可复用 pool 和 size class；
- plain→plain 可在 Linux 尝试 splice；
- UDP 也有 owned packet、batch read/write 能力抽象。

### 2.7 sing-box 方案的局限

- Go interface/capability graph 很宽，维护成本较高；
- `sync.Pool` 的保留和回收不完全确定；
- 两 goroutine/连接增加调度实体；
- layout 不兼容时仍会 copy；
- 把完整通用能力体系照搬到 ferrum2 会扩大公共 API，并可能产生无人使用的抽象。

**对 ferrum2 的启示：**借鉴 ownership/layout 原理，但先做一个窄而深的单跳 Shadowsocks 私有快路径，不先复制整套通用接口体系。

---

## 3. shadowsocks-rust：以 Tokio CopyBuffer 语义为核心的稳健实现

### 3.1 自定义 relay，但语义直接借自 Tokio

shadowsocks-rust 的 `CopyBuffer` 明确说明来自 Tokio。其关键顺序是：

```rust
if buffer_is_empty {
    poll_read_once();
}

while buffer_has_data {
    poll_write_until_drained_or_pending();
}

if eof_and_empty {
    flush_and_finish();
}
```

即：

```text
buffer 空 -> read 一次
read 得到 n > 0 -> 立即进入 write
未写完 -> 禁止继续 read
写完 -> 才允许下一次 read
```

`copy_encrypted_bidirectional` 为两个方向分别创建一个 `CopyBuffer`。[^ssrust-copy]

这正是 ferrum2 此前 RELAY-002 所缺失的核心不变量。

---

### 3.2 method-dependent relay buffer

shadowsocks-rust 的 encrypted copy buffer 大小按 cipher category 选择：

| category | plain relay buffer 上限 |
|---|---:|
| classic AEAD | `0x3FFF`，即 16,383 bytes |
| stream/none | 16 KiB |
| AEAD-2022 | `0xFFFF`，即 65,535 bytes |

普通非 Shadowsocks `copy_bidirectional` 则使用每方向 8 KiB。[^ssrust-copy]

这使其 frame 粒度与协议最大 payload 对齐，但 AEAD-2022 高并发时每连接内存会明显增大。

---

### 3.3 TCP decrypt：原地 open，但随后 copy-out

classic AEAD reader 使用内部可复用 `BytesMut`：

```text
WaitSalt
-> ReadLength
-> ReadData
-> BufferedData
```

它会把完整 ciphertext 读入内部 buffer，原地 decrypt，然后 truncate tag。[^ssrust-aead-read]

但是它作为 `AsyncRead` 向 relay 提供数据时执行：

```rust
buf.put_slice(&self.buffer[pos..]);
```

因此存在：

```text
decrypt internal BytesMut
    -> memcpy
CopyBuffer
```

即使没有每 frame allocator，payload 本身仍被复制一次。

AEAD-2022 reader 使用同样的内部 buffer + `BufferedData` 模型。[^ssrust-aead2022]

---

### 3.4 TCP encrypt：内部组帧 buffer，再 copy-in

writer 的状态为：

```text
AssemblePacket
-> Writing { pos }
```

它会：

1. 在内部 `BytesMut` 中写 length；
2. seal length；
3. `put_slice(input_plaintext)`；
4. seal payload；
5. 把内部 ciphertext buffer 完整写出。[^ssrust-aead-write]

所以 plain→encrypted 路径还有：

```text
CopyBuffer
    -> memcpy
EncryptedWriter internal BytesMut
```

AEAD-2022 writer 也是同样结构，只多出 first header 状态。[^ssrust-aead2022]

因此，shadowsocks-rust TCP 的优势是**状态机可靠、buffer 可复用、partial write 正确**，但不是最小 copy 路径。

---

### 3.5 shadowsocks-rust TCP 完整 copy 图

单个 proxy 节点的两个方向近似如下。

**encrypted → plain：**

```text
kernel
  -> decrypt internal buffer
  -> [额外 memcpy]
  -> relay CopyBuffer
  -> kernel
```

**plain → encrypted：**

```text
kernel
  -> relay CopyBuffer
  -> [额外 memcpy]
  -> encrypt internal buffer
  -> kernel
```

客户端和服务端都采用该结构时，端到端每个 payload byte 可能在两个节点上各经历一次额外用户态 copy。

---

### 3.6 调度公平性的一个细节

shadowsocks-rust 的 CopyBuffer 会循环推进，直到 endpoint 返回 `Pending`、EOF 或错误。它没有 ferrum2 当前显式的：

- frame budget；
- byte budget；
- ready-I/O budget。

在真实网络中 socket 通常会自然产生 `Pending`，所以一般不会出问题；但在 loopback、内存 IO 或持续 ready 场景中，显式 cooperative budget 更稳妥。

因此 ferrum2 应借用它的 **read→write 顺序**，但继续保留自己的 `PollBudget`，不要原样复制其无限推进循环。

---

### 3.7 first payload / early data

shadowsocks-rust 会把 target address 与首次 payload 拼接到 first packet，避免地址与首包拆成额外 write；client/server 也包含“server-first protocol”处理。[^ssrust-client][^ssrust-server]

这部分思路与 ferrum2 当前 first-write/initial-payload 设计一致，应继续保留。

---

### 3.8 shadowsocks-rust UDP

其 UDP AEAD：

- encrypt 在新 `BytesMut` 中写 salt、address、payload、tag，再原地 seal；
- decrypt 在调用方 buffer 内原地 open；
- 解析地址后，用 `copy_within(payload_start..payload_end, 0)` 把 payload 移到 buffer 头。[^ssrust-udp-aead]

`ProxySocket::send`/`send_to` 常为每次 datagram 新建一个 `BytesMut`；poll send 路径也会新建 `BytesMut::with_capacity(payload.len()+256)`。[^ssrust-udp-socket]

server 多 worker 接收时，为把数据送到中心 association map，会使用 `Bytes::copy_from_slice` 通过 mpsc channel 转交；主接收路径也有类似 copy。[^ssrust-udp-server]

所以它的 UDP 更强调可移植性和实现清晰度，不是本次三者中最激进的数据移动方案。

---

### 3.9 shadowsocks-rust 方案的优势

- relay 顺序正确，直接可作为 ferrum2 状态机语义参考；
- partial write、EOF、half-close 边界清晰；
- 内部 crypto buffer 长期复用；
- Rust/Tokio，无 GC；
- first payload 合并合理；
- 生产 client/server 都实际使用该 relay。[^ssrust-server]

### 3.10 shadowsocks-rust 方案的局限

- TCP decrypt→relay 和 relay→encrypt 各有一层 payload copy；
- AEAD-2022 每方向 relay buffer 可达 65,535 bytes；
- 没有 ferrum2 的显式 poll fairness budget；
- UDP 发送常有 per-datagram buffer 构造；
- UDP address stripping 用 `copy_within`；
- 多核 UDP 接收经中心 channel 时产生 copy 和队列开销。

---

## 4. 三者横向比较

| 维度 | sing-box/sing | shadowsocks-rust | ferrum2 当前 | 推荐目标 |
|---|---|---|---|---|
| 双向调度 | 两 goroutine | 单 future、两个 CopyBuffer | Tokio `copy_bidirectional_with_sizes` | 单 future、两个独立 FSM、轮换优先级 |
| read→write 纪律 | owned buffer 到手立即写 | 读一次后写完 | Tokio 已验证 | 强制不变量 |
| TCP decrypt→plain | owned frame 可直交 | internal buffer 再 copy-out | decrypt scratch 再 copy 到 Tokio buffer | decrypt backing 直接写 |
| TCP plain→encrypt | headroom 原地 seal | relay buffer 再 copy-in | relay buffer 再 copy 到 final-layout scratch | raw read 直接进入 final payload region |
| buffer ownership | 最强、通用 | 常规 borrowed AsyncRead/Write | 有 borrowed plaintext view，但 relay 未使用 | 私有、窄接口、connection-local |
| 公平预算 | 依赖 scheduler/netpoll | 无显式 byte/frame budget | 已有 8 frame / 256 KiB / 64 IO | 保留 ferrum2 |
| TCP 每连接内存 | pool/动态 | relay + crypto internal | 2×32 KiB relay + flow encrypt/decrypt | 只保留 flow encrypt/decrypt |
| UDP | owned + batch capability | 多处 alloc/copy/channel | direct-to-wire + owned wire + fixed lease | 保留 ferrum2，后续只做证据驱动增强 |
| unsafe/syscall | Go runtime/syscall 封装 | crate 内实现 | workspace `unsafe_code = forbid` | 不新增自制 unsafe |
| 适合直接照搬部分 | ownership/layout | relay FSM 语义 | crypto/预算/资源控制 | 三者融合 |

---

# 第二部分：ferrum2 当前实际情况

## 5. 当前 TCP 数据路径

### 5.1 生产 relay

当前 `relay_lifecycle` 使用：

```rust
tokio::io::copy_bidirectional_with_sizes(
    inbound,
    outbound,
    32_768,
    32_768,
)
```

即每方向一块固定 32 KiB application buffer。[^ferrum2-relay]

当前客户端和服务端生产路径都通过 `TokioFramed` 接入该 relay。[^ferrum2-client-callsite][^ferrum2-server-callsite]

这条路径已经恢复正确吞吐和背压，是必须保留的 fallback 与 correctness oracle。

---

### 5.2 当前 decrypt 路径

flow：

1. 把 encrypted length/payload 读入可复用 `BytesMut`；
2. 原地 `open_in_place`；
3. 保存 `DataRx::Ready { position }`；
4. `PlainBufferedDuplex` 可返回当前 plaintext borrowed view；
5. 但 `TokioFramed::AsyncRead` 会把该 view copy 到 Tokio relay 的 `ReadBuf`。[^ferrum2-flow][^ferrum2-tokio-adapter]

所以：

```text
transport
 -> decrypt BytesMut
 -> in-place open
 -> memcpy
 -> Tokio relay buffer
 -> target socket
```

原地解密保留了 crypto 内部优化，但跨层交付仍有一次 payload copy。

---

### 5.3 当前 encrypt 路径

`seal_data_chunk_into`：

1. 清理并 resize 最终 contiguous wire scratch；
2. 写 length；
3. `copy_from_slice(payload)` 到最终 payload region；
4. detached seal length；
5. detached seal payload；
6. staged partial write 到 tunnel。[^ferrum2-wire]

所以：

```text
plain socket
 -> Tokio relay buffer
 -> memcpy
 -> final wire scratch
 -> in-place seal
 -> tunnel socket
```

crypto 已经不再创建临时 Vec 或回拷 ciphertext，但 plaintext 仍从 relay buffer copy 到 encrypt scratch。

---

### 5.4 ferrum2 已经优于参考实现的部分

- TCP `open_in_place` destructive failure；
- auth failure不提交 nonce；
- detached tag 最终布局；
- receive exact-length preparation；
- per-poll 8 frame / 256 KiB / 64 ready-I/O 公平预算；
- idle notification coalescing；
- 统一 cancellation、half-close、owner accounting；
- UDP owned wire、borrowed view、direct-to-wire；
- server UDP response codec 固定最多 4 shard、每 shard 2 个 prepaid wire lease；
- 固定 budget 和 semaphore 定向等待，而非广播唤醒。[^ferrum2-crypto][^ferrum2-udp-wire][^ferrum2-response-codec]

这些都应作为新快路径的基础，而不是被参考实现替换。

---

## 6. RELAY-002 回归给出的硬约束

此前失败状态机的错误不是“自定义 relay 必然慢”，而是：

```text
reader Ready
 -> 继续读
 -> 继续读
 -> 直到 32 KiB 满 / Pending / EOF
 -> 才开始写
```

客户端和服务端串联后，`tcp-bulk` 从约 257–263 MB/s 降到 25–29 MB/s，约 -90%。

由此得到不可妥协的状态机不变量：

```text
I1. pending plaintext/wire 非空 => 禁止再次读取
I2. 一次 read 得到 n > 0 => 下一步必须给 writer 推进机会
I3. partial write 未完成 => 必须保留 buffer 与 offset
I4. 32 KiB 仅是容量，绝不是 flush threshold
I5. 两方向不得共享一块 buffer
I6. 内部预算耗尽才 self-wake；没有进展不得 busy wake
```

---

# 第三部分：目标架构

## 7. Fused Two-Buffer Relay 总体设计

### 7.1 目标内存模型

当前单跳连接大致拥有：

```text
flow.encrypt buffer
flow.decrypt buffer
Tokio relay A->B 32 KiB
Tokio relay B->A 32 KiB
```

目标：

```text
upload direction   = flow.encrypt buffer
download direction = flow.decrypt buffer
```

移除两块通用 relay buffer。

这是比照搬 sing 全局 pool 更符合 ferrum2 的做法，因为：

- flow 本来就拥有并复用这两块 buffer；
- 无需额外 allocator/pool；
- 无锁；
- 无跨连接 plaintext reuse；
- ownership 与 flow 生命周期天然一致；
- owner registry 可保持确定性。

---

### 7.2 post-handshake upload 最终布局

后续 Shadowsocks data frame：

```text
front = ENCRYPTED_LENGTH_LEN = 2 + 16 = 18 bytes
rear  = TAG_LEN = 16 bytes
payload_cap = 当前 32,768 bytes
```

读取前准备：

```text
┌──────────────────┬──────────────────────────┬───────────────┐
│ initialized 18 B │ append/read payload area │ reserved 16 B │
└──────────────────┴──────────────────────────┴───────────────┘
```

步骤：

1. `encrypt.clear()`；
2. `encrypt.resize(18, 0)`；
3. 一次 `poll_read_buf` 把 plain bytes 直接 append 到 offset 18；
4. read 返回 `n > 0` 后，不再 read；
5. resize/保留尾部 16 bytes；
6. 在 `[0..2]` 写 length；
7. seal `[0..18]`；
8. seal payload region，并把 detached tag 写到 rear；
9. 立即 drain wire；
10. 完成后 `clear()`，进入下一次 read。

这里没有：

```text
relay buffer -> encrypt scratch
```

payload 从 raw socket 进入用户态时，已经处于最终 wire backing。

实现可继续满足 `unsafe_code = forbid`：

- 预先 reserve 完整 capacity；
- 用安全的 `BytesMut::resize` 初始化小型 header 区；
- 使用当前 `tokio_util::io::poll_read_buf` append；
- Pending 期间不 reserve、不 resize、不移动 buffer；
- Ready 后才 seal。

---

### 7.3 upload FSM

```rust
enum UploadState {
    ReadingPlain,
    WritingWire {
        payload_len: usize,
        wire_pos: usize,
    },
    ShuttingDownTunnel,
    Done,
}
```

状态规则：

```text
ReadingPlain:
  poll_read 一次
  n == 0 -> ShuttingDownTunnel
  n > 0  -> seal in final layout -> WritingWire

WritingWire:
  poll_write(wire[wire_pos..])
  partial -> update wire_pos，保持状态
  Pending -> return Pending
  complete -> clear -> ReadingPlain

ShuttingDownTunnel:
  poll_shutdown(tunnel write half)
  complete -> Done
```

**禁止**在 `WritingWire` 中调用 plain reader。

---

### 7.4 download FSM

当前 flow 已能返回 authenticated plaintext borrowed view，因此第一版不必移动 `BytesMut` ownership。

```rust
enum DownloadState {
    FillingPlaintext,
    WritingPlaintext,
    ShuttingDownPlain,
    Done,
}
```

行为：

```text
FillingPlaintext:
  poll_fill_plain_buf()
  empty EOF -> ShuttingDownPlain
  non-empty -> WritingPlaintext

WritingPlaintext:
  poll_write(current_plaintext)
  partial -> consume(n)，继续 WritingPlaintext
  Pending -> return Pending
  current frame fully consumed -> FillingPlaintext
```

这相当于一个严格的 `AsyncBufRead -> AsyncWrite` copy：

> 只要 decrypt view 还有一个 byte，就不得读取下一 encrypted frame。

因此可以消除：

```text
decrypt BytesMut -> Tokio relay buffer
```

同时不需要把 decrypt buffer移出 flow。

后续若要支持 endpoint ownership transfer，可再把 borrowed view 升级成 `OwnedChunk`；对单跳 raw target，borrowed direct-write 已足以达到零额外 payload copy。

---

### 7.5 bidirectional orchestrator

外层 future 维护：

```rust
struct FusedRelay {
    upload: UploadState,
    download: DownloadState,
    poll_upload_first: bool,
}
```

每次 `poll`：

```text
if poll_upload_first:
    poll upload
    poll download
else:
    poll download
    poll upload

poll_upload_first = !poll_upload_first
```

保留 ferrum2 现有 per-poll budget：

- `POLL_FRAME_BUDGET = 8`
- `POLL_BYTE_BUDGET = 256 KiB`
- `POLL_READY_IO_BUDGET = 64`

推荐 outer relay 也有统一 budget，方向各有局部计数。任何方向耗尽预算：

1. 记录已取得进展；
2. `wake_by_ref()`；
3. 返回 `Pending`；
4. 下一 poll 轮换首方向。

这比 sing 依赖 runtime 调度更确定，也比 shadowsocks-rust 无显式预算更稳妥。

---

### 7.6 生命周期和 idle 语义

当前 runtime 的 idle/cancel supervisor 不应与 copy engine 绑死。

建议把 `relay_with_controls` 拆成：

```text
A. relay supervisor
   - cancellation
   - idle timer
   - activity signal
   - stats
   - terminal mapping

B. relay engine
   - Tokio fallback engine
   - Fused Shadowsocks engine
```

定义低开销 progress handle：

```rust
pub struct RelayProgress {
    inbound_to_outbound: u64,
    outbound_to_inbound: u64,
    activity: Arc<ActivitySignal>,
}
```

engine 仅在目标 writer 真正成功接受 `n > 0` bytes 后调用：

```rust
progress.record(direction, n);
```

这样：

- idle reset 与真实写推进绑定；
- 两个 engine 使用同一 supervisor；
- A/B 不会因 timeout/cancellation 语义不同而失真；
- 当前 `relay_lifecycle` API 和 fallback 继续存在。

---

### 7.7 fast-path 选择

第一版使用静态、低风险选择：

```text
Client SOCKS single-hop + concrete ClientFlow
    -> fused fast path

Server SS single-hop + direct target stream
    -> fused fast path

BoxedClientFlow / multi-hop
plugin/TLS/mux/unknown wrapper
capability incompatible
    -> current Tokio fallback
```

不建议一开始做复杂运行时 downcast graph。快路径应由调用点在编译期知道 endpoint 类型时直接选择。

建议把新实现保持 `pub(crate)` 或 sealed capability，直到至少出现第二个真实使用者，避免再次留下失败且无人调用的公共 API。

---

## 8. 建议接口草图

### 8.1 第一阶段：专用、深接口

优先在 `ferrum2-shadowsocks` 内部建立：

```rust
trait FusedPlainRelay {
    fn poll_plain_to_tunnel<P>(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        plain: Pin<&mut P>,
        progress: &mut RelayProgress,
        budget: &mut RelayPollBudget,
    ) -> Poll<Result<DirectionDone, ShadowsocksError>>
    where
        P: AsyncRead + AsyncWrite + Unpin;

    fn poll_tunnel_to_plain<P>(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        plain: Pin<&mut P>,
        progress: &mut RelayProgress,
        budget: &mut RelayPollBudget,
    ) -> Poll<Result<DirectionDone, ShadowsocksError>>
    where
        P: AsyncRead + AsyncWrite + Unpin;
}
```

实际实现可以不是公开 trait，而是 `ClientFlow`/`ServerFlow` 的 crate-private 方法。

优点：

- 直接访问 flow 的 encrypt/decrypt/state/cipher；
- 无动态分派；
- 无通用 ownership API 扩散；
- 可复用现有 protocol invariants；
- 可在一个 commit 中限定生产调用点。

---

### 8.2 第二阶段：证明确有第二个用户后再抽象

若 multi-hop、其他协议或 TLS wrapper 也需要，可以抽象为：

```rust
struct BufferLayout {
    front: usize,
    rear: usize,
    payload_capacity: usize,
}

trait OwnedRead {
    fn poll_read_owned(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        layout: BufferLayout,
        buffer: &mut OwnedBuffer,
    ) -> Poll<Result<OwnedReadOutcome, Error>>;
}

trait OwnedWrite {
    fn required_layout(&self) -> BufferLayout;

    fn poll_write_owned(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut OwnedBuffer,
    ) -> Poll<Result<OwnedWriteOutcome, Error>>;
}
```

但不应把它作为第一阶段前置条件。sing 的通用接口是多年演进结果；ferrum2 当前更需要先证明单跳生产路径收益。

---

## 9. 建议文件级改动

### 9.1 `crates/ferrum2-runtime/src/relay.rs`

- 抽出 supervisor；
- 保留当前 `relay_lifecycle` 和 `relay_bidirectional`；
- 增加 crate 可复用的 progress/activity handle；
- 允许外部 engine 在相同 idle/cancel/stats 语义下运行；
- 不在 runtime 中依赖 Shadowsocks。

### 9.2 新增 `crates/ferrum2-shadowsocks/src/tcp/fused_relay.rs`

包含：

- `FusedRelay` future；
- `UploadState`；
- `DownloadState`；
- 方向轮换；
- outer budget；
- EOF/half-close；
- progress 回调。

### 9.3 `crates/ferrum2-shadowsocks/src/tcp/flow/io.rs`

- 复用现有 `PollBudget`；
- 增加“直接从 plain reader 填充 encrypt final layout”的内部操作；
- 增加“直接把 current plaintext view 写向 plain writer”的操作；
- 禁止新路径调用普通 `poll_write_plain` 后再做二次 scratch copy。

### 9.4 `crates/ferrum2-shadowsocks/src/tcp/wire.rs`

新增类似：

```rust
prepare_data_chunk_layout(buffer, payload_capacity);
seal_prepositioned_data_chunk(sealer, buffer, payload_len);
```

`seal_prepositioned_data_chunk` 必须假设 payload 已经位于最终区域，不再接受单独 `&[u8]` source，也不调用 `copy_from_slice(payload)`。

保留现有 `seal_data_chunk_into` 给 fallback、测试和未知调用方。

### 9.5 `crates/ferrum2-shadowsocks/src/tokio.rs`

- 保留 `TokioFramed`；
- 新增 fused relay adapter 或构造器；
- fallback 仍走当前 AsyncRead/AsyncWrite。

### 9.6 生产调用点

修改：

- `bins/ferrum2-client/src/run/socks/tcp_command.rs`
- `bins/ferrum2-server/src/run/tcp/connection.rs`

先通过 evidence-only candidate 开关选择：

```text
candidate off -> current relay_lifecycle
candidate on  -> fused Shadowsocks relay
```

完成证据后再考虑默认启用；不提供永久用户配置开关，避免维护两套长期语义。

---

# 第四部分：frame size、批处理和 pipeline

## 10. 32 KiB 应继续是首个候选，不是等待阈值

参考项目差异：

- sing-shadowsocks2 classic AEAD：16,383 bytes；[^sing-classic-max]
- shadowsocks-rust classic AEAD：16,383 bytes；
- shadowsocks-rust AEAD-2022：65,535 bytes；
- ferrum2 当前 encode cap：32,768 bytes。

第一版 fused relay 应保持 ferrum2 当前 32 KiB cap，以便 A/B 只测数据移动差异。

必须满足：

```text
read 返回 1460 bytes -> 立刻封装 1460-byte SS frame
read 返回 8 KiB      -> 立刻封装 8-KiB SS frame
read 返回 32 KiB     -> 封装 32-KiB SS frame
```

绝不等待 frame 变大。

---

## 11. frame size 应作为独立实验

在 fused relay 证明后，再单独比较：

| candidate | 优势 | 风险 |
|---|---|---|
| 16 KiB | 较低内存和 latency | 更多 tag/frame/syscall |
| 32 KiB | 当前平衡点 | 可能未充分利用 bulk |
| 64 KiB | 更少 frame/tag overhead | 更高内存、较长单次 crypto、可能影响 tail latency |
| adaptive | 小流低延迟、大流高吞吐 | 状态和证据复杂 |

可借鉴 sing 的“累计约 512 KB 后增加 buffer”思路，但应做 ferrum2 专属实验：

```text
初始 cap = 32 KiB
累计传输超过阈值
-> 允许 buffer grow 到 64 KiB
```

即使 cap 变为 64 KiB，也仍是“单次 read 返回多少就写多少”，不是等待 64 KiB。

不要把 frame-size 改动和 fused copy-elimination 放进同一候选，否则无法归因。

---

## 12. 不建议第一版做 depth-2 read-ahead

每方向一块 in-flight buffer 是正确默认：

- writer Pending 时自然向 source 施加 backpressure；
- 不额外占内存；
- 不需要 frame queue；
- 不会重现串联 batching；
- socket send buffer 已提供内核级排队。

只有在 high-RTT/高 BDP 场景明确显示单 in-flight buffer 限制吞吐时，才单独测试 depth=2。默认不得 read-ahead。

---

## 13. vectorized I/O 的适用边界

可接受：

- 一次 `readv` 获取已经 ready 的多个区域；
- 一次 `writev` 写已经完成的多个 buffer；
- UDP 一次收发多个已经 ready 的 datagram。

不可接受：

- 为构成 vector batch 主动等待；
- reader 连续 Ready 就无界读；
- 用 timer 延迟小流量默认路径。

对于 fused TCP，最终 wire 已 contiguous，单次 `poll_write` 通常优于拆 header/payload `writev`。只有 profile 证明多 frame 已经 ready 且 syscall 成本主导时，才考虑 vectored writer。

---

# 第五部分：UDP 最大性能方案

## 14. 不要改回 shadowsocks-rust 式 UDP

ferrum2 当前 UDP 已经具有明显更优的数据所有权特征：

- `reserve_seal` 直接在最终 output 中建立 body；
- `open_packet_in_place_borrowed` 返回 target/payload view；
- `open_packet_owned` 保留完整 wire ownership 和 range；
- `OwnedOpenedPacket` 用 range + `split_off` 交付 payload，而不是 `copy_within`；
- 成功路径只逻辑 `clear()`；
- 错误路径和未交付 owned packet 物理 zeroize；
- response wire 使用固定 shard、固定 lease 和 budget。[^ferrum2-udp-wire][^ferrum2-response-codec]

因此不应采用 shadowsocks-rust 的：

- 每 send 新建 `BytesMut`；
- decrypt 后 `copy_within`；
- 多 worker → center channel 的 `Bytes::copy_from_slice`。

---

## 15. UDP 下一步只建议两个证据候选

### 15.1 Owned datagram headroom：消除 payload→wire copy

当前 direct-to-wire 仍需要把 payload 写入 wire body。下一步最大潜力是让上游 datagram buffer本身带有：

- 最大 header headroom；
- tag rearroom；
- payload range。

路径变为：

```text
target socket recv
 -> directly into future SS body payload range
 -> fill semantic header
 -> seal same backing
 -> send
```

这与 sing 的 packet headroom 思路一致。

但它需要重构 `Datagram` ownership，并处理：

- target address 在 `recv_from` 完成后才知道；
- request/response header 最大长度不同；
- 最大 wire budget；
- multi-hop atomicity；
- failure zeroize；
- Windows IOCP buffer lifetime。

应在 TCP fused relay 后单独实施。

### 15.2 Safe batched datagram I/O

只在 profile 显示 syscall-bound 时考虑：

- Linux safe `recvmmsg/sendmmsg` abstraction；
- io_uring 或受审计依赖；
- Windows 对应 batch/IOCP strategy。

当前 workspace `unsafe_code = forbid`，且现有 PR 已明确没有满足引入 `recvmmsg/sendmmsg` 的 profile 前提。[^ferrum2-pr]

因此：

- 不写自制 unsafe syscall wrapper；
- 不因“理论上更快”直接加入；
- 只在 safe abstraction、正确性和 A/B 都成立时启用；
- batch 只能消费已经 ready 的 datagram。

---

## 16. UDP worker 架构

保留 ferrum2 当前方向：

- 独立 owned `SO_REUSEPORT` listener；
- 固定 receive worker；
- shard-local budget/codec；
- 不经中心 mpsc 复制 payload；
- bounded admission；
- fail-closed 平台能力检查。

这比 shadowsocks-rust “多个 recv worker + channel 汇总到中心 association map”更适合极限吞吐。

---

# 第六部分：内存、安全与平台

## 17. 为什么第一版不用全局 TCP pool

sing 的 pool 很适合其通用 Go copy engine，但 ferrum2 已有 connection-local scratch。

全局 pool 的代价：

- 跨 worker contention；
- capacity retention；
- plaintext 跨连接复用；
- 安全上可能要求 release 时 zeroize；
- zeroize 会重新引入大额内存带宽；
- budget/lease 复杂度扩大。

推荐：

```text
Tier 0: connection-local encrypt/decrypt buffers
Tier 1: 仅当 profile 证明连接建立 allocation 成本显著时，
        再研究 per-worker size-class pool
```

若未来引入 pool：

- 只保留固定 size class；
- 全局 byte budget；
- 不保留异常大 capacity；
- plaintext buffer 跨连接前按安全策略 zeroize；
- ciphertext-only buffer可采用较轻策略；
- pool miss、wait、retained bytes 必须可观测。

---

## 18. destructive failure 语义必须保留

当前 TCP opener：

- 成功：原地解密、truncate tag、提交 nonce；
- auth failure：正文被 destructive primitive 清除，nonce 不提交。[^ferrum2-crypto]

新 relay 不得：

- 在失败后尝试恢复原 ciphertext；
- 把失败 buffer 交给普通 writer；
- 将失败 plaintext/ciphertext buffer 放入跨连接 pool；
- 因 zero-copy 改变 terminal/abortive-close 语义。

UDP 同样保持：

```text
accepted success -> logical clear/reuse
auth/semantic failure -> physical zeroize
```

---

## 19. Windows / IOCP 约束

owned buffer 设计必须保证：

- `poll_read`/`poll_write` Pending 期间 backing address 稳定；
- Pending 时不 reserve、不 resize、不 split；
- buffer 和 offset 存在于 future/flow 状态中；
- completion Ready 后才改变布局；
- cancellation 后不能立即复用仍可能被 proactor 引用的 memory。

第一版通过预 reserve 完整容量和 connection-local storage 可自然满足。

---

## 20. Linux plain-to-plain direct path

sing 可在两端暴露 raw fd 时使用 splice。对 Shadowsocks AEAD 本身不能绕过用户态 crypto。

ferrum2 可把 plain-to-plain kernel-copy 作为独立候选，但必须：

- 只覆盖 Direct SOCKS/纯 relay；
- 使用受审计的 safe abstraction；
- 不新增 workspace 内 unsafe；
- 不和 Shadowsocks fused relay混合测试；
- half-close、cancellation、metrics 必须一致。

它不是本方案的 P0，因为当前关键 copy 位于 Shadowsocks 协议层。

---

# 第七部分：构建与 CPU 优化

## 21. 结构优化优先于 build profile

当前 workspace 已有：

- `performance-thin-lto`：ThinLTO + codegen-units=1；
- `performance-panic-abort-strip`；
- profiling profile；
- workspace `unsafe_code = forbid`。[^ferrum2-cargo]

建议顺序：

1. 先完成 fused data path；
2. 固定代码后测 ThinLTO/CGU1；
3. 再测 PGO；
4. 固定部署硬件才测 `target-cpu=native` 或明确 ISA baseline；
5. allocator 替换只在 hot-path allocation 仍存在时测试。

不要在同一个 A/B 候选中同时修改：

- relay 结构；
- frame size；
- LTO；
- allocator；
- worker count；
- socket buffer。

否则无法知道收益来自哪里。

---

## 22. PGO 方案

若追求固定主机最大性能，可建立独立 PGO pipeline：

```text
instrumented build
 -> TCP upload/download/bidi + UDP + DNS/rule representative workload
 -> merge profile
 -> optimized-use build
 -> exact binary identity
 -> approved-host ABBA
```

训练集必须包含：

- AES-128/256-GCM；
- ChaCha20-Poly1305；
- 小 frame；
- bulk；
- 高并发；
- UDP 最大包；
- DNS/rule hot path；

否则 PGO 可能只优化某个 benchmark。

---

# 第八部分：可观测性与验收

## 23. 必须新增的结构指标

建议增加低基数、Relaxed 或 evidence-only 指标：

```text
tcp_fused_fast_path_connections
tcp_fused_fallback_connections{reason}

tcp_plain_to_encrypt_copy_bytes
tcp_decrypt_to_plain_copy_bytes

tcp_owned_upload_frames
tcp_borrowed_download_frames
tcp_partial_writes
tcp_poll_budget_yields
tcp_frames_per_connection

tcp_encrypt_buffer_capacity
tcp_decrypt_buffer_capacity
tcp_relay_buffer_capacity_removed

udp_payload_to_wire_copy_bytes
udp_owned_fast_path_hits
udp_codec_wait_ns
udp_pool_misses
```

目标结构断言：

```text
单跳 raw <-> Shadowsocks fused fast path（handshake 后）：

tcp_plain_to_encrypt_copy_bytes == 0
tcp_decrypt_to_plain_copy_bytes == 0
generic relay buffers == 0
flow direction buffers == 2
```

若结构指标未达到零 copy，即使 throughput 偶然提升，也说明实现没有完成目标。

---

## 24. 针对历史回归的序列测试

必须增加一个精确事件序列 fake IO：

```text
reader:
  Ready(4 KiB)
  Ready(4 KiB)
  Ready(4 KiB)
  ...

writer:
  Ready
```

期望事件：

```text
READ -> WRITE -> READ -> WRITE -> ...
```

禁止出现：

```text
READ -> READ
```

除非第一次 read 返回 0 或发生明确协议级内部 exact-read（例如同一个 encrypted frame 的 length/payload读取）；plaintext relay 层不得连续读多个逻辑 chunk 来攒批。

---

## 25. 功能和边界测试矩阵

### 25.1 单方向

- empty stream；
- 1 byte；
- 16 KiB - 1；
- 16 KiB；
- 32 KiB；
- 32 KiB + 1；
- 64 KiB；
- u16 max incoming frame；
- EOF 恰在 frame 边界；
- EOF 在 length 中间；
- EOF 在 payload/tag 中间；
- writer 每次只写 1 byte；
- writer 每 N 次返回 Pending；
- reader 连续 Ready；
- read Ready + write Pending；
- cancellation during read；
- cancellation during partial write；
- auth failure；
- nonce exhaustion；
- write zero。

### 25.2 双向

- upload bulk + download tiny control messages；
- download bulk + upload tiny messages；
- 双向同时 bulk；
- 一边 half-close，另一边继续；
- 两边同时 EOF；
- 一边错误、另一边 Pending；
- idle timer 与刚完成 write 的竞争；
- generation/network cancellation。

### 25.3 平台

- Linux GNU/musl；
- Windows MSVC/IOCP；
- loopback；
- 人工 high RTT；
- slow writer；
- socket buffer 较小；
- high concurrency。

---

## 26. benchmark 矩阵

### TCP

| 维度 | 场景 |
|---|---|
| payload | 64B、1KiB、4KiB、16KiB、32KiB、64KiB、bulk |
| 方向 | upload、download、bidirectional |
| 并发 | 1、8、32、128 |
| cipher | AES-128-GCM、AES-256-GCM、ChaCha20-Poly1305 |
| writer | normal、1-byte partial、slow |
| RTT | loopback、10ms、50ms |
| flow | single-hop、multi-hop fallback |
| lifecycle | half-close、idle、cancel |

指标：

- throughput；
- CPU cycles/byte；
- instructions/byte；
- p50/p99 latency；
- context switches；
- syscalls/MB；
- allocator calls；
- RSS/connection；
- LLC misses；
- memory bandwidth；
- fast-path hit rate。

### UDP

- 64B、128B、1KiB、MTU、最大 wire；
- concurrency 1/8/32；
- request/response；
- session churn；
- codec contention；
- reuseport workers 1/N；
- packet loss/backpressure。

---

## 27. adoption gate

继续使用现有 A/A 校准和 6-pair ABBA，不调整阈值。

默认采用 fused path 的必要条件：

1. 所有 correctness、fuzz、M0、Windows/Linux 门禁通过；
2. 单跳结构指标证明两类 payload copy 都为 0；
3. 每连接删除两块固定 relay buffer；
4. mandatory TCP 场景没有 confirmed regression；
5. 至少一个预期 CPU/throughput 场景越过其校准噪声带；
6. p99 latency 没有超出校准后的回归带；
7. slow-writer/half-close/cancellation 没有 busy loop；
8. multi-hop fallback 与当前语义一致；
9. 证据绑定同一 exact SHA、policy 和 binary identity。

如果只达到结构目标但性能落在噪声带内：

- 可以保留 candidate；
- 不应自动默认启用；
- 先分析 CPU、cache、syscall 和内存指标。

---

# 第九部分：分阶段实施顺序

## Phase 0：先补结构观测

只增加：

- copy bytes；
- buffer capacity；
- partial write；
- frame 数；
- fast-path/fallback reason；
- owner accounting。

不改数据路径，建立 current baseline。

---

## Phase 1：download direct-write

使用现有 `PlainBufferedDuplex`：

```text
decrypt frame
-> borrowed plaintext view
-> direct poll_write target
-> consume
```

不修改 upload。

这是最小风险、最容易验证的一半；其状态机应严格参考 Tokio/shadowsocks-rust CopyBuffer。

---

## Phase 2：upload final-layout read

让 raw reader直接 append 到 `flow.encrypt` 的 payload region：

```text
read plaintext into final layout
-> seal length/payload in place
-> drain wire
```

删除 `seal_data_chunk_into(source, scratch)` 中该快路径的 payload copy。

---

## Phase 3：组合为 Fused bidirectional relay

- 两方向轮换优先；
- 共享 supervisor；
- 完整 half-close；
- current Tokio fallback；
- client/server 两个生产调用点启用 evidence candidate。

---

## Phase 4：默认采用单跳快路径

仅在 Phase 1–3 的同一最终 SHA 证据全通过后：

- 单跳 concrete flow 默认 fused；
- multi-hop/unknown wrapper 自动 fallback；
- 删除临时配置开关；
- 保留 Tokio engine 作为永久通用路径。

---

## Phase 5：frame-size 独立实验

按 16/32/64 KiB 和 adaptive 分别 A/B，不与结构变化合并。

---

## Phase 6：multi-hop ownership

只有 profile 证明 multi-hop copy 显著后再做：

- target layout negotiation；
- 外层 flow 直接在 sink-compatible buffer 中 decrypt；
- layout 不兼容时允许恰好一次 copy；
- 不追求跨任意层的强行 zero-copy。

---

## Phase 7：UDP owned headroom

让 target socket receive 直接落入未来 Shadowsocks wire body；保留 bounded lease 和失败 zeroize。

---

## Phase 8：safe batch syscall / PGO

分别作为独立候选。

---

# 第十部分：明确不做的事情

1. 不恢复“读到 32 KiB 才写”的 relay。
2. 不用一块 buffer 同时服务两个方向。
3. 不在 writer Pending 时继续 read-ahead。
4. 不把全局 pool 当成第一阶段前置条件。
5. 不让 auth failure 恢复“原 buffer 不变”。
6. 不从 shadowsocks-rust 移植 UDP `copy_within` 路径。
7. 不通过中心 mpsc 复制所有 UDP payload。
8. 不新增自制 unsafe syscall wrapper。
9. 不把结构、frame size、LTO、allocator、worker 数混进同一个候选。
10. 不因 workflow 绿色就替代 artifact/raw/identity 重算。
11. 不保留失败且无人调用的公共 relay API。
12. 不在没有 profile 的情况下默认开启 busy poll、io_uring 或大 socket buffer。

---

# 第十一部分：预期收益与不确定性

## 28. 可以确定的结构收益

单跳快路径完成后，可以确定：

- 每方向消除一层用户态 payload copy；
- 每连接移除两块固定 32 KiB generic relay buffer；
- handshake 后 hot path 不需要新 payload allocation；
- partial write buffer ownership 更直接；
- decrypt plaintext 不再复制到 Tokio relay buffer；
- plaintext 不再复制到 encrypt scratch；
- 仍保留完整 backpressure 和 half-close。

---

## 29. 性能收益最可能出现的地方

收益会在以下场景更明显：

- 高并发；
- AES-NI/硬件 AES 很快，memcpy 占比上升；
- 大流量双端均运行 ferrum2；
- 内存带宽或 LLC 压力较高；
- Windows 上减少中间 buffer；
- 每连接 RSS 是容量瓶颈。

收益可能较小的场景：

- ChaCha crypto 本身占主导；
- 网络带宽远低于 CPU 能力；
- 极小、稀疏流；
- wrapper 导致 fallback；
- multi-hop 尚未进入 owned path。

不能在实施前诚实地承诺固定提升百分比；但该方案把单跳 Shadowsocks 用户态 payload copy 降到理论最小，同时保留已经证明正确的调度语义，是当前代码基础上最有可能获得最大综合性能的方向。

---

# 第十二部分：最终优先级

| 优先级 | 项目 | 建议 |
|---|---|---|
| P0 | 结构指标 | 立即做 |
| P0 | download borrowed direct-write | 立即做 |
| P0 | upload final-layout direct-read | 立即做 |
| P0 | fused bidirectional + Tokio fallback | 立即做 |
| P0 | exact sequence/backpressure tests | 立即做 |
| P1 | 单跳 approved-host ABBA | 必须做 |
| P1 | frame-size 16/32/64 独立实验 | fused 通过后做 |
| P1 | UDP payload-in-place headroom | TCP 收口后做 |
| P2 | multi-hop layout negotiation | profile 后做 |
| P2 | PGO / target CPU | 结构稳定后做 |
| P3 | safe `recvmmsg/sendmmsg` / io_uring | syscall-bound 证据后做 |
| 不建议 | 恢复单缓冲攒满 relay | 不做 |
| 不建议 | 全局 TCP pool 先行 | 不做 |
| 不建议 | 一次性重写所有 relay API | 不做 |

---

# 最终结论

sing-box 的核心优势不是“Go 更快”，而是它把 **buffer ownership 与 protocol layout** 做成了 copy engine 的一等能力。

shadowsocks-rust 的核心优势不是“自定义比 Tokio 更快”，而是它严格遵守：

```text
read once
-> write pending bytes completely
-> then read again
```

ferrum2 当前最有价值的资产则是：

- 已验证的 Tokio fallback；
- destructive in-place crypto；
- final-layout detached seal；
- explicit poll budget；
- 资源预算和固定 lease；
- 严格性能证据控制器。

因此最大性能方案不是选择其中一个项目照搬，而是：

> **以 shadowsocks-rust/Tokio 的背压状态机为骨架，以 sing-box 的 owned-buffer/headroom 为数据布局，以 ferrum2 的两块 flow-local scratch、destructive crypto、PollBudget 和证据门禁为实现基础。**

具体落地形态应是：

```text
每连接、每方向一块 buffer
+ 立即 read→write
+ plaintext 直接读入最终 wire
+ decrypted view 直接写 socket
+ 两方向公平独立
+ current Tokio 自动 fallback
```

这是在 ferrum2 当前约束下，风险、可维护性、内存占用和极限吞吐之间最优的工程解。

---

# 源码依据

[^singbox-gomod]: [sing-box go.mod：当前 sing / sing-shadowsocks / sing-shadowsocks2 依赖版本](https://github.com/SagerNet/sing-box/blob/f5b8b7a57922084361907a13273f2c88f35ae7c7/go.mod)

[^singbox-route-conn]: [sing-box route/conn.go：两个方向独立 connectionCopy 与 half-close](https://github.com/SagerNet/sing-box/blob/f5b8b7a57922084361907a13273f2c88f35ae7c7/route/conn.go)

[^sing-copy]: [sing common/bufio/copy.go：能力协商、512 KB increase threshold、CopyConn](https://github.com/SagerNet/sing/blob/v0.9.0-beta.4/common/bufio/copy.go)

[^sing-copy-direct]: [sing common/bufio/copy_direct.go：splice、WaitReadBuffer→WriteBuffer、vectorized path](https://github.com/SagerNet/sing/blob/v0.9.0-beta.4/common/bufio/copy_direct.go)

[^sing-read-options]: [sing common/network/direct.go：ReadWaitOptions、front/rear headroom 与 buffer sizing](https://github.com/SagerNet/sing/blob/v0.9.0-beta.4/common/network/direct.go)

[^sing-ss-reader]: [sing-shadowsocks2 internal/shadowio/reader.go：原地 decrypt 和 owned WaitReadBuffer](https://github.com/SagerNet/sing-shadowsocks2/blob/v0.2.1/internal/shadowio/reader.go)

[^sing-ss-writer]: [sing-shadowsocks2 internal/shadowio/writer.go：WriteBuffer、18B front headroom、16B rear headroom](https://github.com/SagerNet/sing-shadowsocks2/blob/v0.2.1/internal/shadowio/writer.go)

[^sing-buffer-size]: [sing common/buf/buffer_standard.go：32 KiB TCP buffer](https://github.com/SagerNet/sing/blob/v0.9.0-beta.4/common/buf/buffer_standard.go)

[^sing-classic-max]: [sing-shadowsocks2 shadowaead/protocol.go：classic AEAD MaxPacketSize=16KiB-1](https://github.com/SagerNet/sing-shadowsocks2/blob/v0.2.1/shadowaead/protocol.go)

[^ssrust-copy]: [shadowsocks-rust tcprelay/utils.rs：Tokio-derived CopyBuffer 与 bidirectional copy](https://github.com/shadowsocks/shadowsocks-rust/blob/5f2cbad93168d098d780dbd5323ad7a4a4167b62/crates/shadowsocks/src/relay/tcprelay/utils.rs)

[^ssrust-aead-read]: [shadowsocks-rust tcprelay/aead.rs：classic AEAD DecryptedReader](https://github.com/shadowsocks/shadowsocks-rust/blob/5f2cbad93168d098d780dbd5323ad7a4a4167b62/crates/shadowsocks/src/relay/tcprelay/aead.rs)

[^ssrust-aead-write]: [shadowsocks-rust tcprelay/aead.rs：EncryptedWriter AssemblePacket/Writing](https://github.com/shadowsocks/shadowsocks-rust/blob/5f2cbad93168d098d780dbd5323ad7a4a4167b62/crates/shadowsocks/src/relay/tcprelay/aead.rs)

[^ssrust-aead2022]: [shadowsocks-rust tcprelay/aead_2022.rs：AEAD-2022 reader/writer 与 65,535 max payload](https://github.com/shadowsocks/shadowsocks-rust/blob/5f2cbad93168d098d780dbd5323ad7a4a4167b62/crates/shadowsocks/src/relay/tcprelay/aead_2022.rs)

[^ssrust-client]: [shadowsocks-rust proxy_stream/client.rs：first packet 拼接与 CryptoStream](https://github.com/shadowsocks/shadowsocks-rust/blob/5f2cbad93168d098d780dbd5323ad7a4a4167b62/crates/shadowsocks/src/relay/tcprelay/proxy_stream/client.rs)

[^ssrust-server]: [shadowsocks-rust server/tcprelay.rs：生产调用 copy_encrypted_bidirectional](https://github.com/shadowsocks/shadowsocks-rust/blob/5f2cbad93168d098d780dbd5323ad7a4a4167b62/crates/shadowsocks-service/src/server/tcprelay.rs)

[^ssrust-udp-aead]: [shadowsocks-rust udprelay/aead.rs：UDP encrypt/decrypt 与 copy_within](https://github.com/shadowsocks/shadowsocks-rust/blob/5f2cbad93168d098d780dbd5323ad7a4a4167b62/crates/shadowsocks/src/relay/udprelay/aead.rs)

[^ssrust-udp-socket]: [shadowsocks-rust udprelay/proxy_socket.rs：per-send BytesMut 和 caller recv buffer](https://github.com/shadowsocks/shadowsocks-rust/blob/5f2cbad93168d098d780dbd5323ad7a4a4167b62/crates/shadowsocks/src/relay/udprelay/proxy_socket.rs)

[^ssrust-udp-server]: [shadowsocks-rust server/udprelay.rs：多 worker、mpsc 与 Bytes::copy_from_slice](https://github.com/shadowsocks/shadowsocks-rust/blob/5f2cbad93168d098d780dbd5323ad7a4a4167b62/crates/shadowsocks-service/src/server/udprelay.rs)

[^ferrum2-relay]: [ferrum2 runtime/relay.rs：当前 2×32 KiB Tokio relay 与 idle supervisor](https://github.com/zzffu/ferrum2/blob/bda542efe21941706f4d79dd007d1131e03a20cc/crates/ferrum2-runtime/src/relay.rs)

[^ferrum2-flow]: [ferrum2 tcp/flow/io.rs：decrypt FSM、PollBudget、staged write](https://github.com/zzffu/ferrum2/blob/bda542efe21941706f4d79dd007d1131e03a20cc/crates/ferrum2-shadowsocks/src/tcp/flow/io.rs)

[^ferrum2-tokio-adapter]: [ferrum2 tokio.rs：TokioFramed AsyncRead/AsyncBufRead/AsyncWrite](https://github.com/zzffu/ferrum2/blob/bda542efe21941706f4d79dd007d1131e03a20cc/crates/ferrum2-shadowsocks/src/tokio.rs)

[^ferrum2-wire]: [ferrum2 tcp/wire.rs：final-layout seal_data_chunk_into 与 detached tag](https://github.com/zzffu/ferrum2/blob/bda542efe21941706f4d79dd007d1131e03a20cc/crates/ferrum2-shadowsocks/src/tcp/wire.rs)

[^ferrum2-crypto]: [ferrum2 crypto/tcp/aead.rs：destructive open、nonce commit、detached seal](https://github.com/zzffu/ferrum2/blob/bda542efe21941706f4d79dd007d1131e03a20cc/crates/ferrum2-crypto/src/tcp/aead.rs)

[^ferrum2-udp-wire]: [ferrum2 udp/wire.rs：direct-to-wire、borrowed/owned open、range ownership](https://github.com/zzffu/ferrum2/blob/bda542efe21941706f4d79dd007d1131e03a20cc/crates/ferrum2-shadowsocks/src/udp/wire.rs)

[^ferrum2-response-codec]: [ferrum2 server UDP response_codec.rs：固定 shard、wire lease、semaphore 和 budget](https://github.com/zzffu/ferrum2/blob/bda542efe21941706f4d79dd007d1131e03a20cc/bins/ferrum2-server/src/run/udp/response_codec.rs)

[^ferrum2-client-callsite]: [ferrum2 client tcp_command.rs：TokioFramed + relay_lifecycle](https://github.com/zzffu/ferrum2/blob/bda542efe21941706f4d79dd007d1131e03a20cc/bins/ferrum2-client/src/run/socks/tcp_command.rs)

[^ferrum2-server-callsite]: [ferrum2 server connection.rs：TokioFramed + relay_lifecycle](https://github.com/zzffu/ferrum2/blob/bda542efe21941706f4d79dd007d1131e03a20cc/bins/ferrum2-server/src/run/tcp/connection.rs)

[^ferrum2-pr]: [ferrum2 PR #3：当前范围、unsafe/recvmmsg 约束与验证说明](https://github.com/zzffu/ferrum2/pull/3)

[^ferrum2-cargo]: [ferrum2 Cargo.toml：unsafe forbid、profiling、ThinLTO/CGU1、panic-abort profile](https://github.com/zzffu/ferrum2/blob/bda542efe21941706f4d79dd007d1131e03a20cc/Cargo.toml)
