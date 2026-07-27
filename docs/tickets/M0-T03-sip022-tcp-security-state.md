+++
id = "M0-T03"
title = "Implement the SIP022 AES-128 TCP security state machine"
milestone = "M0"
status = "review"
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
  "M0-PROTO-001 through M0-PROTO-006 pass for framing, authentication, semantic bounds, side-effect ordering, fixed allocation caps, and the reviewed composite wire fixture",
  "M0-REPLAY-001 through M0-REPLAY-004 pass, including exactly one success for 64 concurrent duplicates, 59.999/60-second retention, wall rollback, and full-capacity fail-closed behavior",
  "M0-DETECT-001 proves one underlying operation for each initial read/write and M0-BIND-001 proves full request-salt response binding before forwarding",
  "Every approved initial failure maps to the closed ShadowsocksError::Detection variant, calls core AbortiveClose exactly once, enters terminal state, and imports no socket or runtime type",
  "The opened Shadowsocks stream delegates core LocalEndpoint to its connector-owned transport without performing a second socket query",
  "M0-ENDPOINT-001 connector_error_before_write proves every connector error leaves HeaderIo first-write count at zero",
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
- single-underlying-I/O `HeaderIo` contract和contiguous first-write buffers。
- fixed-capacity frame scratch、checked length/address/padding parse。
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
- input length不能触发input-sized reserve；使用approved fixed maximum scratch。
- live replay entry不得在60秒前evict；capacity full拒绝新flow。
- 任何reference divergence先上报，不在实现里静默兼容。
- encrypted stream必须委托underlying `LocalEndpoint`的已存endpoint；不得依赖
  socket/runtime type或在first-write后重新查询socket。

## Validation commands

```bash
cargo test -p ferrum2-shadowsocks --locked
cargo test -p ferrum2-shadowsocks --test tcp_ordering --locked
cargo test -p ferrum2-shadowsocks --test tcp_ordering --locked connector_error_before_write
cargo test -p ferrum2-shadowsocks --test tcp_allocation_bounds --locked
cargo test -p ferrum2-shadowsocks --test tcp_vectors --locked
cargo test -p ferrum2-shadowsocks --test tcp_replay --locked
cargo test -p ferrum2-shadowsocks --test detection_prevention --locked
cargo test -p ferrum2-shadowsocks --test response_binding --locked
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
  strict Clippy/fmt/diff PASS；Architect/QA review pending
- Fixture generator/output SHA-256:
  `ca8d181b…faa39` / `c7f210d6…11f0`
- Integrated commit: pending
