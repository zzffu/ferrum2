# ferrum2 v0 差距分析

## 当前证据基线

本分析在 2026-07-28 的 M2 planning source
`master@589970c5b15023a2f184e41a839253a7685b222b` 更新。历史 baseline 和
完整证据由 M0/M1 handoff、roadmap、CI status与Git history追溯。

已关闭的 M1 product/release baseline：

- exact product/release SHA：
  `874c83d0ee71054bd702d6ecac55e88d9e2fbcef`；
- local authoritative full、milestone ratchet、Rust 1.85、Windows MSVC、
  Linux GNU、Linux musl均通过；
- GitHub Actions run `30367147537` attempt 1记录M1-INT-001～012恰12项PASS；
- 三个method-bound TCP profiles、IPv4/IPv6/domain target、bounded resolution、
  two binaries、direct TCP、observability和lifecycle已存在；
- durable evidence见`docs/handoffs/HANDOFF-M1-2026-07-28.md`和
  `docs/ci-status.md`。

M2 planning baseline：

- `ADR-0020`～`ADR-0022` Accepted；
- `SPEC-0003`/`TEST-0003` Approved；
- M2-T01～T05 ready且ownership-disjoint；
- initial implementation frontier是M2-T01 + M2-T03；
- Product/Architect/QA完成只读planning analysis，没有blocker/major；
- preflight baseline test budget为code `7720`、tests `15759`、ratio `2.041321`。

M1 evidence只证明entry/regression baseline，不能作为M2 UDP implementation、
local echo或12-cell hosted completion evidence。

## M2 当前实现差距

| ID | 当前代码/证据 | M2 必须结果 | 严重度 | Primary owner/evidence |
|---|---|---|---|---|
| GAP-M2-C01 | crypto canonical type仍为`TcpMethodProfile`，只有TCP salt/subkey/AEAD owners | transport-neutral profile + alias；opaque AES UDP header/session capability和ChaCha XChaCha direct-PSK capability | P0 | M2-T01；profile/primitive fixture table |
| GAP-M2-C02 | 没有UDP primitive/composite fixtures、8-byte session owner或24-byte nonce evidence | pinned XChaCha/AES header rows和independent三方法request/response expected wire/provenance | P0 | M2-T01/T02；M2 research + fixture hashes |
| GAP-M2-P01 | `ferrum2-shadowsocks`只有TCP framing/replay/flow | bounded packet API、type/timestamp/address/padding/binding/full-length semantics和65,507 wire bound | P0 | M2-T02；`udp_packets` table |
| GAP-M2-P02 | 没有UDP replay window或association state | per-direction 8,129-value window、post-validation/reservation atomic commit、current+old 60s policy | P0 | M2-T02；replay/session tables |
| GAP-M2-P03 | 没有session-ID routing、roaming或response generation | authenticated client-ID key、valid peer update、stale handle rejection | P0 | M2-T02；routing/generation table |
| GAP-M2-R01 | core/runtime是stream-only，无datagram/session/socket owner | minimal core value；4,096 sessions、16MiB allocated bytes、depth-4 queues、300s idle、one socket/task owner | P0 | M2-T03；generic resource/lifecycle table |
| GAP-M2-R02 | direct connector仅TCP；无UDP resolution/send/deadline/expiry | IP send、system domain≤16 candidates、single absolute deadline、expiry/cancel/shutdown cleanup | P0 | M2-T03；scripted resolver + owner snapshots |
| GAP-M2-F01 | server只bind TCP；config/metrics只有TCP | schema v1 `[udp]`、same-port atomic dual bind、direct composition、七个closed metric families | P0 | M2-T04；config/bind/observability tables |
| GAP-M2-F02 | local product harness无UDP path | 三方法protocol API→server→direct echo、focused IPv6/domain/backpressure/lifecycle | P0 | M2-T04；bounded process matrix |
| GAP-M2-F03 | qualification固定M1 TCP 12案且external support是TCP/SOCKS process path | M2-UDP-INT-001～012、black-box protocol example、three datagrams/source、12/12 exact-SHA fail-closed | P0 | M2-T05；pure plan + hosted report |

## 已冻结的 M2 设计与研究

1. **Crypto boundary：**ADR-0020选择transport-neutral `MethodProfile`并保留
   `TcpMethodProfile` alias；AES separate header/session key和ChaCha direct-PSK
   XChaCha留在opaque crypto capability。
2. **Replay/session：**ADR-0021固定highest+8,128 window、current+old、
   authenticated client-session-ID routing、valid roaming、post-capacity atomic
   mutation和generation binding。
3. **Runtime/resources：**ADR-0022固定minimal core datagram、generic runtime、
   session/allocated-byte/queue/wire/idle bounds、expired-oldest-or-reject和
   one socket/task perserver session。
4. **Config/composition：**`server.listen`同地址/端口bind TCP+UDP；
   `[udp].enabled`默认true、false为TCP-only escape；双bind transaction和offline
   validation。
5. **Fixture/interop：**M2 research固定SIP022 revision、XChaCha draft vector、
   independent composite inputs、existing reference pins和
   M2-UDP-INT-001～012 black-box process boundary。

## 后续里程碑差距

| ID | 未交付结果 | 里程碑 | 规划前仍需冻结 |
|---|---|---|---|
| GAP-O203 | 最终 operator config/log/metrics compatibility 与 full lifecycle qualification | M3 | final schema、packaging/native runner/soak contract |
| GAP-P201 | 同机可比 shadowsocks-rust TCP throughput ≥90% | M4 | hardware/config/warm-up/repetition/statistics |
| GAP-P202 | 10,000 idle TCP sessions 的 task/memory stability | M4 | measurement window、numeric stability/FD thresholds |

明确不属于差距：

- public client UDP inbound、SOCKS5 UDP ASSOCIATE、routing、DNS
  proxy/cache/custom resolver、multiple upstreams、
  chaining、hot reload、management API、SIP023、多用户、reduced-round ChaCha；
  它们是v0 non-goals，而不是延期后可静默加入M2的需求。

## 风险与控制点

| 风险 | 等级 | 控制 |
|---|---|---|
| AES/ChaCha UDP construction错误或key/nonce pair reuse | P0 | ADR-0020 opaque capability；primitive+composite expected bytes；counter/entropy table |
| auth/semantics/capacity前mutation或并发duplicate双accept | P0 | ADR-0021 fixed ordering；recording snapshots；64-way same-ID race |
| source address identity、association rotation或generation ABA | P0 | routing/roaming/current+old/stale-handle state table |
| allocated-capacity漏计、unbounded queue或active eviction | P0 | ADR-0022 permits/depth-4/expired-oldest；generic saturation/concurrency |
| resolver deadline reset、task/socket/session leak | P0 | 16 candidates/single deadline；paused-time owner snapshots |
| dual bind partial startup或default-enabled兼容回归 | P0 | config/offline table；same-port bind transaction；UDP-disabled/TCP regression |
| fixture来源/rights或generator自证 | P0 | frozen sources/inputs；independent generator；source/output hashes |
| 12-cell missing/setup failure或harness-linked self-test被当PASS | P0 | fixed IDs、black-box example、failure continuation、12/12+cleanup/exact SHA |
| test lines继续放大既有2.041 ratio | P1 | packet/replay/session/resource parameter tables；ticket/milestone ratchet |
| hosted provider unavailable | P1 | BLOCKED，不以旧 run、本机或不同 SHA 结果豁免 |

## 优先级与执行前沿

```text
M2-T01 crypto ───────┐
                     ├─ M2-T02 protocol/replay ─┬─ M2-T04 composition
M2-T03 core/runtime ─┘                          └─ M2-T05 qualification impl
                                                  │
M2-T04 ───────────── T05 integration/release ─────┘
```

M2-T01与M2-T03是initial frontier，可在独立worktrees并行。T02等待二者；T05可在
T02后与后续product work并行实现，但等待T04 integrated后才能integration/release。
每票需Architect/QA各一次exact-candidate full review；只有blocker/major阻断，
最多一次substantive repair与一次targeted re-review。

Execute不隐含remote authority。12-cell hosted release evidence到达前，M2可完成
本地implementation/integration但不能close；push/workflow run/rerun必须由用户对
exact target另行授权。
