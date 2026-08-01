+++
id = "M2-T02"
title = "Implement the bounded SIP022 UDP packet, association, and replay state"
milestone = "M2"
status = "done"
priority = "P0"
risk = "critical"
implementation_blocked_by = ["M2-T01", "M2-T03"]
review_blocked_by = []
integration_blocked_by = ["M2-T01", "M2-T03"]
release_blocked_by = []
required_reviews = ["architect", "qa"]
owns = [
  "crates/ferrum2-shadowsocks/Cargo.toml",
  "crates/ferrum2-shadowsocks/src/**",
  "crates/ferrum2-shadowsocks/tests/common/**",
  "crates/ferrum2-shadowsocks/tests/udp_packets.rs",
  "crates/ferrum2-shadowsocks/tests/udp_replay.rs",
  "crates/ferrum2-shadowsocks/tests/udp_sessions.rs",
  "tests/fixtures/sip022/**",
]
spec = "docs/specs/SPEC-0003-m2-sip022-udp-protocol-and-direct-server.md"
test_plan = "docs/test-plans/TEST-0003-m2-sip022-udp-protocol-and-direct-server.md"
acceptance = [
  "One transport-neutral bounded packet API uses the T01 capabilities for all three methods and round-trips client and server IPv4, IPv6, and 1-to-255-byte ASCII-domain datagrams without exposing raw keys or owning sockets",
  "Committed independent request and response fixtures prove exact AES separate-header and ChaCha nonce/body layouts, message types, timestamp, response client-session binding, padding, addresses, payload, and 65507-byte complete-wire bounds",
  "Malformed, oversized, tampered, truncated, stale, wrong-type, unbound, invalid-address, invalid-padding, and ambiguous-length packets fail closed with zero target exposure, peer-sized allocation, accepted session, replay, peer, activity, queue, resolve, or send mutation",
  "Each incoming direction uses an independent window representing the highest ID plus 8128 earlier IDs; duplicate, too-old, jump, overflow and 64-way same-ID concurrency rows prove atomic post-validation and post-reservation recheck and commit",
  "Client sessions retain exactly current and old server-session associations with independent windows, reject a third ID until the old association has had no valid packet for 60 seconds, and do not refresh age from invalid traffic",
  "Server state keys only on authenticated client session ID, permits valid source-address roaming, separates same-source different IDs, and rejects stale generation-bound response capabilities after remove and recreate",
  "Shared TCP protocol behavior, buffer reuse, redacted closed errors, dependency direction, full crate lint, and ticket test-budget pass without copied per-method state machines",
]
+++

# M2-T02: Implement the bounded SIP022 UDP packet, association, and replay state

## Outcome

在T01 crypto和T03 minimal datagram/runtime contracts上交付一个无socket的SIP022
UDP protocol deep module，完整拥有wire semantics、replay、association和generation
binding。

## In scope

- Three-method request/response packet codec和composite fixtures。
- Address/padding/timestamp/type/binding/full-length/65,507 bounds。
- Per-direction 8,129-value sliding windows和atomic commit。
- Client current+old associations；server session-ID routing/roaming/generation。

## Out of scope

- Tokio socket/session table、runtime resource policy和binary config。
- Public client inbound或SOCKS5 UDP ASSOCIATE。
- Hosted process adapter/example和reference orchestration。

## Contract references

- `ADR-0020`：method crypto capability。
- `ADR-0021`：replay/association/routing ordering。
- `ADR-0022`：capacity reservation和core datagram seam。
- `SPEC-0003` M2-AC-02/03；`TEST-0003` T02 tables。

## Primary evidence

| Acceptance | Primary evidence |
|---|---|
| 1 | one three-method/address packet API table |
| 2 | committed composite expected-wire table |
| 3 | authenticated semantic negative table with recording snapshots |
| 4 | replay boundary + 64-way concurrency table |
| 5 | paused-time association rotation table |
| 6 | routing/roaming/generation session table |
| 7 | TCP regression + architecture/lint/budget |

Real socket tests只证明adapter interaction，不复制本票codec/state tables。

## Validation commands

```powershell
cargo test -p ferrum2-shadowsocks --locked
cargo clippy -p ferrum2-shadowsocks --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
$env:PYTHONUTF8='1'
python .agents/skills/milestone-workflow/scripts/workflow.py test-budget --gate ticket --base <ticket-base-sha>
git diff --check
```

## Ownership and risks

- T02不编辑T05-owned `examples/udp_protocol_client.rs`。
- Replay mutation必须晚于T03 reservation；race失败释放permit且不刷新activity。
- Compatibility source只允许研究behavior/parameter，不复制代码而无provenance。
- UDP tables按packet/replay/session分三处，不按method/direction继续膨胀。

## Completion evidence

- Branch/worktree/candidates: `codex/ticket/m2-t02`,
  `C:\project\ferrum2\.worktrees\m2-t02`; initial
  `0d88666d2f46ef85b376c12c55ffb34a784a8451`, repaired
  `4d1c65b4d9af03f008b51cae3b5f058ca1edea64`. Product integration is
  `6e54cce52e5e29135acd91f6337a4516a094852e`.
- Reviews: QA full `PASS_WITH_NOTES`; Architect full `BLOCK` on
  `ARCH-M2-T02-001` (`major`). The one substantive repair added the client
  response pending/commit seam; Architect targeted re-review `PASS` resolved
  the finding. Exact-SHA Wave-2 Architect and QA integration gates both
  `PASS_WITH_NOTES`, with no blocker or major finding.
- Validation: all Shadowsocks TCP/UDP tests, architecture/workspace-policy,
  strict Clippy, fmt, docs, fixture reproduction, binary build,
  authoritative quick 3/3, authoritative full 4/4, workflow validation,
  review-state/integration-gate checks, and `git diff --check` exited 0.
- Ticket test budget `PASS`: code `10628`, tests `17947`, ratio `1.689`,
  baseline `2.041`; delta `918/1010`, allowance `1038`. Repair-only delta
  was code `45`, tests `85`, allowance `165`.
- Accepted review debt: `QA-M2-T02-N01`; T04 must place both protocol commit
  calls inside T03 reserved `commit_*_with` closures and prove the exact call
  placement. No repair override or authorization was used.
- Push/publish state: nothing pushed or published.
