# ADR-0002: M0 secret、key lookup、clock 与 entropy 边界

- **Status:** Accepted
- **Date:** 2026-07-27
- **Owners:** Architect / Team Lead
- **Related milestone/spec/tickets:** M0；`docs/specs/SPEC-0001-m0-aes128-tcp-vertical-slice.md`；M0-T02、M0-T03；关闭 DEC-003

## Context and problem

M0 只有一个 AES-128 PSK，但 v0 后续必须增加另外两个方法，未来还可能增加
multi-user/SIP023。若 protocol 状态机直接持有裸 key、读取系统时间或调用全局 RNG，
安全负向测试无法确定性覆盖，扩展 key selection 时也会重写 transport state
machine。

## Decision drivers and invariants

- base64 解码后的 AES-128 PSK 必须恰好 16 bytes。
- PSK、session subkey 及 secret-bearing config 不得出现在 `Debug`、`Display`、
  error、panic、trace 或 metric。
- salt/padding 使用 OS CSPRNG；生产环境不存在 deterministic fallback。
- wall time 只用于 SIP022 timestamp；monotonic time 只用于 replay retention 和
  timeout。
- nonce/key pair 不得复用；nonce overflow 必须在复用前失败。
- test adapters 与 production adapters 穿过同一 narrow interface。

## Options considered

### Option A：secret newtype + capability-style key provider + injected clock/entropy

protocol 只能请求派生 session key，无法取得可长期复制的 PSK bytes；系统能力通过
泛型注入，测试使用 scripted adapters。

### Option B：在 config 中保存 `String`，protocol 按连接解码并调用系统 API

实现直接，但 raw config/PSK 容易进入派生 `Debug`/parser error，且错误、时间和 RNG
路径不可重复测试。

### Option C：现在实现完整 multi-user/SIP023 key database

会扩大 M0 产品范围；当前只需保留不会迫使 TCP framing 重写的 lookup seam。

## Decision

### Secret ownership

- `Aes128Psk` 是持有 `Zeroizing<[u8; 16]>` 的私有字段 newtype，实现
  `ZeroizeOnDrop`，不实现明文 `Display`；`Debug` 恒为
  `Aes128Psk([REDACTED])`。
- typed config 解析期间，原始文件与 PSK token 使用 `Zeroizing<String>`；
  strict base64 解码直接写入固定 `[u8; 16]`，拒绝 whitespace、URL-safe alphabet、
  非 canonical padded encoding 和非 16-byte结果。临时 decode/KDF buffers 在返回
  前显式 zeroize。
- `TcpSubkey`、AEAD owner 与 nonce state 均为不可 clone 的 secret owner；
  `TcpSealer`/`TcpOpener` 独占 counter，protocol 无法设置 counter 或重复使用相同
  owner。
- M0 单 PSK 由进程级 `SinglePskProvider` 独占，连接只获取完成一次 KDF 所需的
  scoped capability，不复制 PSK 到 session/task-local diagnostics。

### Key lookup seam

key lookup 位于 `ferrum2-crypto`，语义为：

```rust
pub enum KeySelector<'a> {
    Default,
    Identity(&'a [u8; 16]),
}

pub trait KeyProvider: Send + Sync {
    type Error;
    fn with_key<T>(
        &self,
        selector: KeySelector<'_>,
        use_key: impl FnOnce(SecretKeyRef<'_>) -> T,
    ) -> Result<T, Self::Error>;
}
```

`SecretKeyRef` 只暴露 `derive_tcp_subkey(method, salt)`，不暴露 raw bytes。
M0 的 `SinglePskProvider` 只接受 `Default`，任何 identity selector 失败关闭。
未来 identity prelude 可以在进入共同 TCP frame state machine 前产生 selector；
本 ADR 不实现、解析或宣称 SIP023。

### Clock seam

```rust
pub trait Clock {
    fn unix_seconds(&self) -> Result<u64, ClockError>;
    fn monotonic_now(&self) -> MonotonicInstant;
}
```

- SIP022 timestamp 使用 `unix_seconds`；`abs_diff(local, peer) <= 30` 接受，
  `31` 秒及以上拒绝。
- replay expiry只使用本seam的monotonic time。runtime handshake/connect/idle/
  shutdown deadline不依赖crypto `Clock`，而使用ADR-0005的Tokio monotonic timer。
- wall clock 早于 Unix epoch、读取失败或算术溢出时只终止相关 flow 并 fail closed；
  wall-clock 回退不能缩短 replay retention。
- production 使用 system adapter；测试 fake clock 必须能独立推进 wall 与 monotonic
  time。该trait只由crypto/shadowsocks path消费，不进入`ferrum2-runtime` dependency。

### Entropy 与 nonce

```rust
pub trait SecureRandom {
    fn fill(&self, destination: &mut [u8]) -> Result<(), RandomError>;
}
```

- production adapter 的唯一来源是 `getrandom::fill`；失败立即终止相关 handshake，
  不使用时间、计数器或弱随机 fallback。
- request/response salt 各 16 bytes；padding 长度用 rejection sampling 从 CSPRNG
  无偏选取。response salt 若等于对应 request salt，必须重新采样；连续八次冲突后
  作为 entropy failure 关闭。
- AEAD nonce 为 12-byte little-endian unsigned counter，从全零开始。每个成功的
  chunk operation 后 checked increment；若下一次会复用/溢出，先返回
  `NonceExhausted`，不输出或接受 plaintext。
- request/response 各有独立 salt、subkey、counter。production 不允许注入
  scripted source；测试 adapter 可产生重复、失败或边界序列。

### Redaction contract

对外错误只有 closed enum code 和必要的非敏感 field path。source error 的
`Display` 不向 operator 透传。任何日志/metric API 都不接受 PSK、subkey、raw
config、salt、nonce 类型；这些类型不实现 tracing field conversion。

## Consequences and tradeoffs

### Positive

- time、entropy、nonce overflow 和 secret lifetime 可以确定性验证。
- future key selection 改变 lookup/prelude，而非 AES/TCP frame state machine。
- raw key 不穿过 core、runtime、observability 或 connector。

### Negative

- capability-style provider 与不可 clone state 比直接传 `[u8; 16]` 更复杂。
- 无法用 safe Rust 对已释放 heap 做 byte inspection；zeroization 证据由
  `ZeroizeOnDrop`、显式 clear seam 和依赖审查共同组成，不能夸大为物理内存保证。
- 进程重启不会保存任何 salt/key state；持久化不在 M0 范围。

## Compatibility and upstream divergence

SIP022 的 AES-128 session key 固定为
`BLAKE3-DERIVE("shadowsocks 2022 session subkey", PSK || salt)` 输出前 16 bytes，
empty AAD。此细节由协议 fixture 和两个 reference 的双向互操作共同锁定，但 reference
行为不覆盖 fixed specification。

## Migration and rollback

首次 schema 无 secret migration。M1 可增加 method-specific secret newtype；
multi-user/SIP023 需要新 ADR 扩展 selector/provider，但不得让现有 AES-128 TCP
state machine读取 key database。回滚不涉及持久状态。

## Verification plan

- M0-CRYPTO-003：固定 KDF/counter fixture。
- M0-CRYPTO-004：redacted `Debug`、explicit-clear seam、entropy failure、nonce
  overflow 和 response-salt collision。
- M0-PROTO-003、M0-REPLAY-003：独立 wall/monotonic fake clock 边界。
- M0-OBS-001：sentinel secret 对 error/log/trace/metrics 输出全量扫描。

## References

- `AGENTS.md` critical invariants
- `docs/research/M0-upstream-baseline.md`
- [固定 SIP022 文件](https://github.com/shadowsocks/shadowsocks-org/blob/34598d65054dad975d330ff9d7317b0d41cf1efd/docs/doc/sip022.md)
- [BLAKE3 derive-key API](https://docs.rs/blake3/1.8.5/blake3/fn.derive_key.html)
