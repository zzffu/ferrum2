+++
id = "M2-T03"
title = "Add the minimal core datagram value and bounded direct UDP runtime"
milestone = "M2"
status = "done"
priority = "P0"
risk = "critical"
implementation_blocked_by = []
review_blocked_by = []
integration_blocked_by = []
release_blocked_by = []
required_reviews = ["architect", "qa"]
owns = [
  "crates/ferrum2-core/**",
  "crates/ferrum2-runtime/**",
]
spec = "docs/specs/SPEC-0003-m2-sip022-udp-protocol-and-direct-server.md"
test_plan = "docs/test-plans/TEST-0003-m2-sip022-udp-protocol-and-direct-server.md"
acceptance = [
  "Core adds only a runtime-neutral bounded normalized-target plus owned-payload datagram value and preserves the existing stream Session, Inbound, Outbound, Connector, LocalEndpoint, and SessionReply source and dependency contracts",
  "A protocol-neutral runtime manager independently enforces client or server session capacity default 4096 and range 1 through 65535, global allocated-capacity bytes default 16 MiB and range 1 through 256 MiB, and fixed depth-four queues per session and direction",
  "Scratch, encoded, decoded, moved, shared, and queued buffers reserve and release byte permits exactly once; saturation, queue-full, cancellation, and handler failure apply backpressure or a stable affected-datagram failure without accepted-state mutation or input-dependent allocation",
  "Capacity full purges the deterministic oldest eligible idle-expired session and otherwise rejects the new session without evicting active or protected state; concurrent admission has one bounded outcome and generation invalidates late work",
  "Each server session owns one direct UDP socket and one supervised task; IPv4 and IPv6 send directly while ASCII domains consume at most 16 ordered system-resolver candidates under one monotonic absolute per-datagram deadline",
  "Paused-time idle, target failure, listener cancellation, graceful shutdown, and forced shutdown evidence returns sessions, sockets, tasks, queues, scratch and byte counters to baseline while existing TCP runtime tests and ticket lint/budget pass",
]
+++

# M2-T03: Add the minimal core datagram value and bounded direct UDP runtime

## Outcome

提供不依赖Shadowsocks的bounded datagram/session/socket owner，使protocol可组合到
direct UDP而不改变既有stream contracts。

## In scope

- Minimal core datagram value。
- Generic session/generation table、global byte permits和depth-4 queues。
- One direct socket/task perserver session、resolver/deadline、idle/eviction。
- Cancellation、shutdown、owner snapshots和backpressure。

## Out of scope

- SIP022 parsing/crypto/replay或server composition。
- Operator config/metrics names。
- Public UDP inbound和external qualification。

## Contract references

- `ADR-0022`：numeric resources、core/runtime boundary和lifecycle。
- `ADR-0021`：reservation must precede protocol replay commit。
- `SPEC-0003` M2-AC-04；`TEST-0003` T03 generic evidence。

## Primary evidence

| Acceptance | Primary evidence |
|---|---|
| 1 | direct API/dependency inspection + existing architecture contract |
| 2 | one generic limits/reservation table |
| 3 | allocated-capacity accounting/backpressure table |
| 4 | paused-time expiry/full/concurrent admission table |
| 5 | scripted resolver/direct socket deadline table |
| 6 | owner snapshot lifecycle table + TCP regression/lint/budget |

Fake packet handler是正确的cheapest seam；本票不需要Shadowsocks或real server。

## Validation commands

```powershell
cargo test -p ferrum2-core -p ferrum2-runtime --locked
cargo clippy -p ferrum2-core -p ferrum2-runtime --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
$env:PYTHONUTF8='1'
python .agents/skills/milestone-workflow/scripts/workflow.py test-budget --gate ticket --base <ticket-base-sha>
git diff --check
```

## Ownership and risks

- T03与T01是initial parallel frontier；不得编辑root manifest/lock或等待protocol。
- Runtime不能记录wire session IDs或依赖`ferrum2-shadowsocks`。
- Byte accounting按allocated capacity；move/shared backing必须有single-charge owner。
- 不按limit种类拆多个test harness或用无意义production line改善ratio。

## Completion evidence

- Branch/worktree/candidates: `codex/ticket/m2-t03`,
  `C:\project\ferrum2\.worktrees\m2-t03`; initial
  `de78a4d41126d8740611bb431fa4839663ed6f31`, repaired
  `491954d8ea8fdf5faad17b0b360f353283d44898`. Product integration is
  `0dff5c104149e7042f5e62dc10831f208a0e16ad`.
- Reviews: Architect and QA full reviews `BLOCK` on
  `ARCH-M2-T03-001` and `QA-M2-T03-001` (`major`). One combined substantive
  repair retained direct-owner capacity through task/socket reap and moved
  activity commit after successful generation-validated handling; both
  targeted re-reviews `PASS` and resolved their original IDs. Exact-SHA
  Wave-1 Architect and QA integration gates both `PASS`, with no new finding.
- Validation: core/runtime package tests and all 12 UDP runtime tests passed;
  strict Clippy, fmt, `git diff --check`, binary build, authoritative quick
  3/3 and full 4/4 all exited 0 on the reviewed candidates/integration as
  applicable.
- Ticket test budget `PASS`: code `9108`, tests `16545`, ratio `1.817`,
  baseline `2.041`; delta `1388/786`, allowance `1508`.
- Accepted review debt: none. No repair override or authorization was used.
- Push/publish state: nothing pushed or published.
