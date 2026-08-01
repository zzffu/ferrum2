+++
id = "M0-T03"
title = "Implement the SIP022 AES-128 TCP security state machine"
milestone = "M0"
status = "done"
priority = "P0"
blocked_by = ["M0-T02"]
owns = [
  "crates/ferrum2-shadowsocks/src/**",
  "crates/ferrum2-shadowsocks/tests/**",
  "tests/fixtures/sip022/**",
]
spec = "docs/specs/SPEC-0001-m0-aes128-tcp-vertical-slice.md"
test_plan = "docs/test-plans/TEST-0001-m0-aes128-tcp-vertical-slice.md"
acceptance = [
  "M0-PROTO-001 through M0-PROTO-009 pass for framing, authentication, semantic bounds, side-effect ordering, fixed reusable allocation requests, the reviewed composite wire fixture, fair pending-response duplex progress, core Session initial-payload ownership, post-fixed fragmentation, poll admission, and exact terminal behavior",
  "M0-REPLAY-001 through M0-REPLAY-004 pass, including exactly one success for 64 concurrent duplicates, 59.999/60-second retention, wall rollback, and full-capacity fail-closed behavior",
  "M0-DETECT-001 proves one completed underlying operation for each initial read/write, terminal installation before exactly-one AbortiveClose even when marking fails, and M0-BIND-001 proves full request-salt response binding before forwarding",
  "Every approved initial failure maps to closed ShadowsocksError::Detection; post-first-envelope failures exhaustively map to ProtocolReason or TransportPhase; all errors and observers retain no source, wire, secret, or peer text",
  "The opened Shadowsocks stream delegates core LocalEndpoint to its connector-owned transport without performing a second socket query",
  "ClientTcpOutbound dials only its stored configured Shadowsocks server endpoint while encoding only the distinct application target in the SIP022 request",
  "Opaque ClientFlow and ServerFlow retain the unsplit transport, both logical direction states, current cipher owners, pending one-shot derivation capabilities, reusable scratch, and one lifecycle/fatal latch while exposing only executor-neutral PlainDuplex; normal one-direction EOF or shutdown leaves the other direction live",
  "ShadowsocksTcpInbound returns Session<ServerFlow, NoReply> with exact target and one bounded authenticated initial_payload owner; ServerFlow begins at the subsequent request-frame state and never repeats that payload",
  "M0-ENDPOINT-001 connector_error_before_write proves every connector error leaves TransportIo completed first-write count at zero",
  "The reviewed unofficial composite SIP022 fixture uses every exact ADR-0004 input, a generator that imports no ferrum2 production module, and PROVENANCE.toml source/output hashes before exact request/response wire tests pass",
  "ADR-0012 phased client open returns one opaque ConnectedClientOpen after dialing only the configured server and consumes it once to first-write only the application target; it exposes no raw transport or protocol state",
  "M0-ENDPOINT-001 client_open_phase_contract proves connector completion and request first-write are independently controllable, actual first-write failures keep ADR-0010 Detection mapping, and cancellation drops the sole transport owner without detached tasks",
]
+++

# M0-T03: Implement the SIP022 AES-128 TCP security state machine

## Outcome

交付不拥有CLI/direct policy的SIP022 AES-128 TCP client/server framing、exact replay、
detection-prevention classification与response binding；所有 reject ordering 可由
recording adapters直接证明。

## Context

本票建立M0最高风险的wire contract。T07只组合已通过的protocol；不得在binary中
修补或复制framing。

## In scope

- request/response fixed/variable/data chunk codecs与typed state transitions。
- ADR-0010 opaque `ClientFlow`/`ServerFlow`、executor-neutral `TransportIo`/
  `PlainDuplex` seam、single fatal arbitration与direction-local normal close。
- ADR-0012 opaque `ConnectedClientOpen` seam，分离configured-server connect完成与
  consuming application-target request first-write；不在protocol crate引入Tokio。
- single-completed-operation `TransportIo` fixed-region contract和contiguous
  first-write buffers。
- fixed-capacity frame scratch、checked length/address/padding parse。
- core `Session<ServerFlow, NoReply>` target/initial-payload ownership；flow不拥有
  direct connector或重复交付initial payload。
- exact replay store、atomic check/insert、monotonic TTL/capacity behavior。
- closed detection failure classification、response request-salt binding。
- positive/composite fixture、tamper/truncation/order/replay/concurrency tests。

### Reopened narrow ADR-0012 repair

历史T03 completion evidence保持有效。本次只允许修改
`crates/ferrum2-shadowsocks/src/**`与对应tests，以把现有fused client open拆成
opaque connected capability和consuming request-first-write phase。不得改变wire、
KDF、nonce、replay、binding、Detection/Protocol/Transport taxonomy、public raw
state、manifest/dependency、server flow或产品范围。T07继续拥有Tokio configured
deadlines（默认10秒/5秒）及其paused-time数值证据；T03只提供executor-neutral
phase boundary和controlled-future证据。
该repair由用户“后续授权所有堵塞点”的明确授权单独覆盖；它不重置或放宽其他票的
全局repair budget，也不产生任何remote授权。

## Out of scope

- socket zero-linger adapter/native cross-process probe（T06/T07）。
- direct target connect、relay、SOCKS5或binary composition。
- other cipher methods、UDP、SIP023、多用户。
- 修改dependency或core contracts。

## Implementation notes and constraints

- ADR-0016只允许替换private test helper、recording adapter或result-carrier spelling；
  `TransportIo`、`PlainDuplex`、`ConnectedClientOpen`及opaque ownership/phase/error/
  caller-capability语义保持本票规范。替代evidence必须覆盖相同ordering、terminal、
  fragmentation、allocation和mutation，并经Architect/QA执行前映射。
- 严格采用ADR-0004的先完整authentication/semantics、后replay mutation、再connector
  顺序。
- 不能用`read_exact`/`write_all`替代first-header底层调用证明。
- 只有43/59-byte fixed region与contiguous first-write是single completed
  operation；post-fixed region必须checked bounded-fill并接受任意fragmentation。
- input length不能触发input-sized reserve；使用approved fixed maximum scratch。
- 每flow一个encrypt、每receive direction一个decrypt scratch必须跨handshake与
  subsequent frames复用；allocation observer证明fixed usable-limit request、
  count/storage identity与零growth。authenticated initial payload是auth/semantics后
  创建的独立bounded `Session` owner，最大65526 bytes。
- 每次outer poll最多一个underlying operation；partial always-ready transport必须
  self-wake/Pending，不能饿死反方向。
- 合法zero-length subsequent frame面对非空destination时必须认证、推进nonce并
  self-wake/Pending，不能以`Ok(0)`伪装EOF。
- live replay entry不得在60秒前evict；capacity full拒绝新flow。
- 任何reference divergence先上报，不在实现里静默兼容。
- initial Detection、post-first-envelope Protocol与Transport failure按ADR-0010
  exact enums/table分离；只有Detection abortive，且terminal-installed observer
  event必须先于mark，所有类别不得保留source error文本。
- client response仍pending时必须保持`16385 -> admit 16384`非fatal边界，并证明
  subsequent request-TX nonce/I/O failure不改类为Detection；server response仍
  pending时的subsequent request-RX auth/bounds/nonce/I/O failure同样不得改类；
  focused table必须证明对应Protocol/Transport与零abortive。不得为client TX注入
  被ADR-0010 admission cap排除的`FrameBounds` terminal。
- write-after-shutdown只在RX仍open的Live state安装`Transport(Write)`；Normal安装
  后不可替换，重复read/write/flush/shutdown遵循ADR-0010 closed success语义。
- encrypted stream必须委托underlying `LocalEndpoint`的已存endpoint；不得依赖
  socket/runtime type或在first-write后重新查询socket。
- `ClientTcpOutbound`必须在构造时持有configured Shadowsocks server endpoint；
  connector只接收该endpoint，`open`收到的application target只进入request encoder。
- T07 adapter只委托poll/endpoint/abortive traits；不得暴露或复制cipher/frame/
  transition逻辑。不得physical split transport或引入shared mutex。

## Validation commands

```bash
cargo test -p ferrum2-shadowsocks --locked
cargo test -p ferrum2-shadowsocks --test tcp_ordering --locked
cargo test -p ferrum2-shadowsocks --test tcp_ordering --locked connector_target_and_request_target
cargo test -p ferrum2-shadowsocks --test tcp_ordering --locked connector_error_before_write
cargo test -p ferrum2-shadowsocks --test tcp_ordering --locked client_open_phase_contract
cargo test -p ferrum2-shadowsocks --test tcp_allocation_bounds --locked
cargo test -p ferrum2-shadowsocks --test tcp_vectors --locked
cargo test -p ferrum2-shadowsocks --test tcp_replay --locked
cargo test -p ferrum2-shadowsocks --test detection_prevention --locked
cargo test -p ferrum2-shadowsocks --test response_binding --locked
cargo test -p ferrum2-shadowsocks --test tcp_duplex --locked
cargo test -p ferrum2-shadowsocks --test tcp_fragmentation --locked
cargo test -p ferrum2-shadowsocks --test tcp_flow_contract --locked
cargo test -p ferrum2-shadowsocks --lib --locked flow_internal_contract
cargo clippy -p ferrum2-shadowsocks --all-targets --all-features --locked -- -D warnings
cargo fmt -p ferrum2-shadowsocks -- --check
```

## Risks

- fixed specification没有官方protocol KAT；fixture independence/provenance必须经review。
- replay mutex linearization或cleanup race可能允许双接受或提前遗忘。
- short I/O与native close外观仍需T07/T08在真实socket验证。

## Completion evidence

- Branch: `codex/ticket/m0-t03`
- Candidate: `05605d328cc35952676cadc8ce30e6c4b91fbf7a`
- Team Lead lineage/ownership/clean-worktree checks: PASS；12 additions，全部属于
  T03 ownership；无 manifest/lock change
- Engineer gates: package 27/27、ordering 4/4、focused connector 1/1、
  allocation 3/3、vectors 2/2、replay 5/5、detection 7/7、binding 3/3、
  strict Clippy/fmt/diff PASS
- Initial review: Architect **BLOCK**、QA **BLOCK**。QA确认fixed scratch并非
  single/reusable，且allocation observer、response/data-frame negative matrix与
  forward/accepted ordering evidence不完整。Architect另确认现有typed transition
  在等待response header时串行独占transport，随后丢失一侧cipher owner，无法组成
  concurrent relay；server transition还丢弃authenticated initial payload，并把
  post-fixed合法TCP fragmentation误判为detection failure。
- Historical contract finding (2026-07-27，blanket blocker authorization之前)：
  repair前必须显式冻结transport split ownership、pending-response
  duplex、scratch ownership、subsequent bounded-fill与split后fatal-error ownership，
  并映射到SPEC-0001/TEST-0001；当时未开始repair 1/2，candidate未integrate。
- Historical Product scope triage: **BLOCK code-only repair**；所需修正保持现有M0产品与wire
  行为不变，但属于未冻结的cross-module public concurrency contract，必须先获得
  窄合同修订授权与Product/Architect/QA批准；授权缺口现已被后续用户授权取代，
  合同gate要求仍有效。
- User authorization: 已授权后续M0内全部本地窄blocker；ADR-0010与对应
  SPEC/TEST/T03/T07窄修订已获Product/Architect/QA **PASS**，repair可以开始。
  该授权不改变原T08 conditional exact-SHA push边界，也不授权其他remote mutation。
- ADR-0010 contract gate: Product **PASS**、Architect **PASS**、QA **PASS**；
  `workflow.py validate`与`git diff --check`均exit 0，无BLOCKER/REQUIRED/advisory。
- Repair 1/2 `8d772f4758f3f497ce8afe973354fed744c51e33` closed the
  production duplex/state defects. Repair 2/2
  `2ce254f8fac5d11f9e1d3637901b207a7697b328` added substantial direct
  ordering/allocation/fairness/fragmentation/terminal evidence and all 14 then-current
  ticket commands passed, but final Architect/QA **BLOCK** rejected its public hidden
  nonce hooks, release flags and expanded `BufferObserver` callback; remaining
  Detection/client-bounds rows were incomplete.
- User-authorized extra narrow repair
  `3a9114dd9456c1b8d680889dba03d41b885b7aca` removed every rejected
  public/release test seam, restored the frozen observer interface, and added only
  crate-private nonce-mapping/capacity evidence plus the missing Detection/client
  admission rows. All 15 ticket commands passed: package 63, ordering 5 plus two
  focused 1/1 cases, allocation 5, vectors 2, replay 5, Detection 11, binding 3,
  duplex 6, fragmentation 10, flow 8, internal filter exact 4, strict Clippy and
  formatting. Architect **PASS**; branch QA found no repair-specific defect and
  required the approved same-SHA T02/T03 integration evidence.
- Local integration merge `22d6cccd7650f2936041aa553ba9cf0a967f68f4`
  combined T02 and T03. Its first package run exposed a Windows checkout-only
  provenance failure: `core.autocrlf=true` changed reviewed LF text to CRLF before
  the test hashed working-tree bytes. Isolated repair
  `1f76597dc74dff90a9592302ec0cf28f77594b16` canonicalizes only valid UTF-8
  CRLF/LF text for provenance hashing, rejects bare CR, documents that contract,
  and leaves fixture/generator blobs, expected hashes, production code and wire
  behavior unchanged. Repair Architect/QA both **PASS**.
- Final T03 checkpoint
  `4bf758ae76421856bb527db3afe165d47e6fd4aa` passed the original provenance
  repro, all 15 ticket commands, release check, T02 owner filter exact 2/2 and T03
  private filter exact 4/4 on the same SHA. Combined integration Architect
  **PASS_WITH_ACTIONS** and QA **PASS**; the only action was this control-document
  closeout. Workspace quick/full remain T07/T08 gates because their binary/harness
  entrypoints are not yet integrated.
- The extra T03 repair remains an explicit user-authorized exception to
  `max_repair_attempts_per_ticket = 2`; the global budget is unchanged.
- Fixture generator/output SHA-256:
  `ca8d181b…faa39` / `c7f210d6…11f0`
- Integrated commit: `4bf758ae76421856bb527db3afe165d47e6fd4aa`
- ADR-0012 phased-open repair candidate:
  `8f0d1e0dc3a385cdefa5d491b642143ee0fe9400` on
  `codex/repair/m0-t03-client-open-phase`; ticket Architect **PASS**、QA
  **PASS_WITH_ACTIONS**，唯一downstream action是在T07汇合binary entrypoints后重跑
  workspace quick。
- Repair integration merge `951806d4b4bdf7c7b8682058582945a3caf3ad3d`；
  combined T03/T06 checkpoint
  `2ce77082ed65bfe1a8707f8923f27dc75c2f5c6a`上T03 package 64、
  ordering 6、全部focused/security/flow commands、联合normal/all-features
  97/97、strict Clippy/fmt/locked metadata/scope/lineage/cleanliness均PASS。
  Combined Architect/QA均**PASS**，无T03 corrective action。
- Remote state: nothing pushed or published
