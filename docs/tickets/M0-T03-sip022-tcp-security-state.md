+++
id = "M0-T03"
title = "Implement the SIP022 AES-128 TCP security state machine"
milestone = "M0"
status = "blocked"
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
- single-completed-operation `TransportIo` fixed-region contract和contiguous
  first-write buffers。
- fixed-capacity frame scratch、checked length/address/padding parse。
- core `Session<ServerFlow, NoReply>` target/initial-payload ownership；flow不拥有
  direct connector或重复交付initial payload。
- exact replay store、atomic check/insert、monotonic TTL/capacity behavior。
- closed detection failure classification、response request-salt binding。
- positive/composite fixture、tamper/truncation/order/replay/concurrency tests。

## Out of scope

- socket zero-linger adapter/native cross-process probe（T06/T07）。
- direct target connect、relay、SOCKS5或binary composition。
- other cipher methods、UDP、SIP023、多用户。
- 修改dependency或core contracts。

## Implementation notes and constraints

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
  Detection/client-bounds rows were incomplete. Under the user's blanket local
  blocker authorization, one extra narrow repair must remove those public/release
  seams and use only the approved private unit evidence above. No code from this
  branch is integrated yet.
- Scheduler state: preserved at `codex/ticket/m0-t03@2ce254f8`; blocked solely
  by the reopened M0-T02 private-owner evidence. M0-T03 must not resume until
  M0-T02 is reviewed, integrated and returned to `done`. The subsequent extra
  narrow T03 repair is an explicit one-time user-authorized exception to
  `max_repair_attempts_per_ticket = 2`, not a global budget change.
- Fixture generator/output SHA-256:
  `ca8d181b…faa39` / `c7f210d6…11f0`
- Integrated commit: pending
