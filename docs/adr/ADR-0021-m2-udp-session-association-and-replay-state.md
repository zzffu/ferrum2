# ADR-0021: M2 UDP session association and replay security state

- **Status:** Accepted
- **Date:** 2026-07-28
- **Owners:** Architect / Team Lead
- **Related milestone/spec/tickets:** M2；`SPEC-0003`；`TEST-0003`；
  M2-T02、M2-T04；扩展 ADR-0004、ADR-0016

## Context and decision boundary

SIP022 要求 server 按 session ID 路由、每 direction 使用 sliding replay window、
valid packet 才更新 client address，并至少保留 60 秒 state；client 还必须处理
server restart 后的多个 server-session associations。规范没有规定 window width
或 ferrum2 的 bounded association policy。

本 ADR 冻结 8,128-lag replay profile、current+old association、atomic admission、
generation binding 和 eviction safety。Generic capacity数值与 task/socket owner
属于 ADR-0022。

## Outcome invariants

- incoming replay state 每 session、每 direction 独立。
- window 同时表示 highest packet ID 和向后 8,128 个 ID，共 8,129 个可表示值；
  duplicate 或更旧 packet 拒绝。
- preliminary ID check 可以早做，但 window 只在完整 authentication、type、
  timestamp、response binding、padding/address/length semantics 和 capacity
  reservation 成功后原子 recheck/commit。
- invalid、stale、unbound、duplicate、too-old、queue/full 或 generation failure
  不刷新 idle/activity、association age、last peer 或 replay state。
- server session key 只由 authenticated client session ID 决定；source address
  不是 identity。
- last-seen client address 只在 accepted client packet 的 replay commit 同一
  serialized transition 更新；response 发往该 latest validated peer。
- client 对一个 client session 恰保留 current + old 两个 server-session
  associations。
- replay/session/association state 至少保留 60 秒；wall-clock rollback 不延长或
  缩短 monotonic lifetime。
- response capability generation-bound；removed/recreated session 的 stale
  target response 不得写入新 session 或新 peer。

## Options considered

### Option A：source address + packet ID 作 session key

无法支持合法 roaming，且同一 NAT address 会产生 alias。拒绝。

### Option B：unbounded server-session association map

最直接贴近“more than one”，但 client memory/attack surface 无明确上限。拒绝。

### Option C：current + old，8,129-value window，serialized atomic commit

采用 SIP022 明确允许的替代策略，并固定与 pinned reference 相容的 window
profile。接受。

## Decision

### Sliding window

首个 accepted ID 成为 highest。之后：

- `id > highest`：window 前移，保留仍在 8,128-lag 范围的 bits；
- `highest - id <= 8_128` 且 bit 未置位：可接受；
- 已置位是 duplicate；差值大于 8,128 是 too old；
- arithmetic 必须 overflow-safe。

同一 ID 的 concurrent arrivals 在 serialized/atomic recheck 后恰有一个成功。
Window representation、word count和算法是 implementation freedom；不得复制
compatibility implementation code而缺少 provenance/license review。

### Client current + old association

第一个 valid server session 成为 current。不同 valid server ID 到达时：

- 若没有 old，原 current 降为 old，新 ID 成为 current；
- 若 old 自最后一个 valid packet 起已满 60 秒，可丢弃 old、轮换；
- 否则第三个 ID 拒绝且不改变 current/old/activity。

来自 current 或 old 的 valid packet 使用各自 independent replay window。
Tampered、stale、wrong-client-ID、duplicate 或 semantic-invalid packet 不刷新
60-second age。每个 association 至少保留 60 秒；更长的 configured session idle
timeout 可以延长它。

### Server transition and response binding

Server packet path：

```text
wire hard bound
→ authenticate
→ full semantic validation
→ reserve session/buffer/queue capacity
→ serialized replay + generation recheck
→ replay/peer/activity commit
→ enqueue/resolve/send
```

任何 pre-commit failure 释放 reservation且零 accepted mutation。New client
session 在 capacity reservation 后创建；new server session ID 不能等于其 client
ID，碰撞遵守 ADR-0020 的 8-draw limit。

Target-side response 只能持有 opaque `(session generation, direction capability)`；
不得以 freely constructible session ID 查表并发送。Session removal invalidates
all handles。

### Eviction interaction

只有达到 configured idle timeout 的 session 是 eligible expired。Capacity full
时先按 deterministic oldest expiry 清理；没有 eligible expired session 就拒绝
new authenticated session。不得为腾容量忘记 active、未满 idle 或 required
60-second replay/association state。

## Consequences and tradeoffs

- Positive：reordering、duplicate、roaming 和 restart association 有一个可测试的
  deterministic contract。
- Positive：capacity failure不能毒化 replay window，generation 防止 ABA
  misdelivery。
- Negative：8,129-value bitmap/state比小 window 占更多内存；已计入 ADR-0022
  session cap。
- Negative：第三个 server session 在 old 活跃时被拒绝；这是规范明确允许的
  bounded alternative。

## Compatibility and rollback

State 只在 process memory 中；restart 会丢失，与现有 TCP replay state一致。
没有 persisted migration。回滚 M1 删除 UDP state，不改变 TCP salt replay。

## Verification seam

- ID `highest+1/highest/highest-1/highest-8128/highest-8129` boundary table；
- duplicate/out-of-order/large-jump/overflow 和 64-way same-ID race；
- auth/semantic/capacity failures 前后 window/activity/peer snapshot不变；
- paused-time current+old 的 59.999/60.000 秒轮换；
- same ID/new source、same source/new ID、stale generation response；
- expiry/full/oldest cleanup 与 no-active-eviction。

## References

- `docs/research/M2-udp-baseline.md`
- `docs/adr/ADR-0004-m0-sip022-tcp-security-state.md`
- `docs/adr/ADR-0016-m0-invariant-first-contract-and-equivalent-evidence.md`
- [Pinned SIP022 source](https://github.com/shadowsocks/shadowsocks-org/blob/34598d65054dad975d330ff9d7317b0d41cf1efd/docs/doc/sip022.md)
