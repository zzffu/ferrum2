# ferrum2 v0 差距分析

## 当前证据基线

本分析在 2026-07-28 的
`master@e677d84ca37f14e5f2009788d2a3af1989e050c2` 更新。它取代 bootstrap
时期“仓库只有控制面/没有 Cargo workspace”的当前态描述；历史调查仍可从 Git
history 与 M0 upstream baseline 追溯。

已关闭的 M0 product baseline：

- exact product/integration SHA：
  `8318ef106d6cd4e029bd3b02aa64125fabdda462`；
- local authoritative full gate 通过；
- GitHub Actions run `30331336772` attempt 1 的 quality、Rust 1.85 MSRV、
  Windows MSVC、Linux GNU、Linux musl、AES-128 四案 interop 全部 success；
- Cargo workspace、两个 binaries、typed config、AES-128 SIP022 TCP、
  SOCKS5 IPv4 CONNECT、direct outbound、observability、bounded lifecycle、
  exact replay 与 hosted qualification 已存在；
- durable evidence 见 `docs/handoffs/HANDOFF-M0-2026-07-28.md` 和
  `docs/ci-status.md`。

M1 planning baseline：

- `ADR-0018`/`ADR-0019` Accepted；
- `SPEC-0002`/`TEST-0002` Approved；
- M1-T01～T04 ready 且 ownership-disjoint；
- 唯一 implementation-ready frontier 是 M1-T01；
- Product/Architect/QA 已完成只读规划审查；没有 blocker/major 未处置。

M0 hosted evidence 只证明 entry/regression baseline，不能作为 M1 completion
evidence。M1 尚无 implementation commit、12-cell hosted run 或新方法/地址行为
PASS 声明。

## M1 当前实现差距

| ID | 当前代码/证据 | M1 必须结果 | 严重度 | Primary owner/evidence |
|---|---|---|---|---|
| GAP-M1-C01 | `ferrum2-crypto` 是 fixed 16-byte PSK/salt/subkey 与 AES-128 owner；method enum 只有一个有效 profile | 三个且仅三个 method-bound profiles；AES-128 16 bytes，AES-256/ChaCha 32 bytes；无 raw-key/mismatch | P0 | M1-T01；method/primitive fixture table |
| GAP-M1-C02 | composition roots 解析后丢弃 `config.method` | validated method+PSK 不可分离地进入 client/server flow | P0 | M1-T03；offline config + real-process seam |
| GAP-M1-C03 | Shadowsocks factories、salt/first-read 固定 AES-128，request 43/response 59 bytes | AES-128 43/59，AES-256/ChaCha 59/91，复用唯一 TCP security/lifecycle state path | P0 | M1-T02；shared-flow method matrix |
| GAP-M1-C04 | AES-256/ChaCha primitive 与 SIP022 wire fixture 尚不存在 | reviewed AES-256 proposal cases、RFC 8439 vector、independent repository-owned wire expected bytes/provenance | P0 | M1-T01/T02；research + fixture hashes |
| GAP-M1-F01 | SOCKS5 与 SIP022 只接受 IPv4 ATYP | IPv4、IPv6、1～255-byte ASCII domain 与 nonzero port end-to-end | P0 | M1-T02；address-path table |
| GAP-M1-F02 | runtime dialer/direct outbound/domain owner/endpoint/reply 是 IPv4-only 或未完整约束 | bounded system resolution、最多16 candidates、single absolute deadline、end-to-end `SocketAddr` reply | P0 | M1-T02；paused-time resolver/dialer evidence |
| GAP-M1-F03 | qualification 固定 AES-128 四案 | M1-INT-001～012 对3 methods×2 references×2 directions恰好12案，12/12+cleanup才PASS | P0 | M1-T04；exact-SHA hosted report |
| GAP-M1-O01 | M0 full/MSRV/platform/observability evidence已存在，但未覆盖M1 changes | 同一M1 candidate的full、MSRV、三平台smoke、redaction/cardinality与M0回归 | P0 | T03/T04 integration/release gates |

## 已冻结的 M1 设计与研究

1. **Method/crypto boundary：**ADR-0018 选择 method-bound secret/profile，
   AEAD owner 内部 enum dispatch，一个 shared TCP flow；禁止 negotiation、
   fallback 与 reduced-round ChaCha。
2. **ChaCha width：**32-byte PSK/salt/subkey 是显式 compatibility interpretation，
   由固定 SIP022、RFC 8439、两个 references 与 independent fixture 共同验证，
   不冒充规范原文。
3. **Target boundary：**ADR-0019 冻结 IPv4/IPv6/ASCII domain、zero-port/length
   validation、16-candidate system resolution、one absolute deadline 和
   `SocketAddr` reply。
4. **Fixture/dependency：**M1 research 固定 AES-256 cases 13/14、RFC 8439
   §2.8.2、synthetic wire inputs、`chacha20poly1305 = 0.11.0` exact
   revision/features/rights contract。
5. **Interop：**保留 sing-box 1.13.14、shadowsocks-rust 1.24.0 pins 和
   ADR-0014/0017 thin hosted boundary，固定 M1-INT-001～012。

## 后续里程碑差距

| ID | 未交付结果 | 里程碑 | 规划前仍需冻结 |
|---|---|---|---|
| GAP-C004 | 三方法 UDP protocol path、per-direction replay/window、bounded sessions 与12案UDP interop | M2 | protocol API、window/session/buffer/idle limits、eviction/concurrency |
| GAP-O203 | 最终 operator config/log/metrics compatibility 与 full lifecycle qualification | M3 | final schema、packaging/native runner/soak contract |
| GAP-P201 | 同机可比 shadowsocks-rust TCP throughput ≥90% | M4 | hardware/config/warm-up/repetition/statistics |
| GAP-P202 | 10,000 idle TCP sessions 的 task/memory stability | M4 | measurement window、numeric stability/FD thresholds |

明确不属于差距：

- SOCKS5 UDP inbound、routing、DNS proxy/cache/custom resolver、multiple upstreams、
  chaining、hot reload、management API、SIP023、多用户、reduced-round ChaCha；
  它们是 v0 non-goals，而不是延期后可静默加入 M1 的需求。

## 风险与控制点

| 风险 | 等级 | 控制 |
|---|---|---|
| method/key/salt width 错配或三套 state machine 漂移 | P0 | ADR-0018 capability + one-flow table + Architect/QA exact-SHA review |
| authentication 前 resolution/dial/replay mutation | P0 | recording address/order table；negative rows零副作用 |
| resolver/candidate input 无界或 deadline reset | P0 | 16 candidates；paused-time single absolute deadline |
| partial `SocketAddrV4` conversion | P0 | core→SOCKS5→SIP022→runtime→reply end-to-end table |
| fixture 来源/rights 或 generator 自证 | P0 | frozen primary sources/inputs；independent generator；source/output hashes |
| 12-cell missing/setup failure 被当 PASS | P0 | fixed IDs、failure continuation、12/12+cleanup、same run/attempt/SHA |
| test lines 继续放大既有 2.092 ratio | P1 | reuse parameterized suites；ticket/milestone ratchet；fixtures excluded |
| hosted provider unavailable | P1 | BLOCKED，不以旧 run、本机或不同 SHA 结果豁免 |

## 优先级与执行前沿

```text
M1-T01
├─ M1-T02 ── M1-T03 ──(integration blocker)── M1-T04
└─ M1-T04 implementation
```

M1-T01 是唯一 initial frontier。T01 done 后，T02 与 T04 implementation 可在独立
worktrees 并行；T03 等待 T02；T04 等 T03 integrated 后最后集成。每票需
Architect/QA 各一次 exact-candidate full review；只有 blocker/major 阻断，最多
一次 substantive repair 与一次 targeted re-review。

execute 不隐含 remote authority。12-cell hosted release evidence 到达前，M1
可以完成本地 implementation/integration，但不能 close；push/workflow run/rerun
必须由用户对 exact target 另行授权。
