# M6 — 有界 SOCKS5 UDP ASSOCIATE

- **Status:** executing
- **Baseline:** `35354f274847d2608a2009e04aaa3b17fb4fa8f4`
- **Strategy:** drain
- **Owner:** primary thread

## Outcome

在显式 client `[udp]` opt-in 下，把 SOCKS5 `UDP ASSOCIATE` 经现有三方法
SIP022 UDP 转发到 configured server direct UDP path；association、client endpoint、
buffers、queues、idle、tasks 和 shutdown 全部有界且可证明，不加入 routing。

## Non-goals

- SOCKS5 UDP fragmentation/reassembly、`BIND`、新 auth method 或 UDP-over-TCP。
- Routing、DNS proxy/custom resolver、multi-inbound/outbound/upstream、load balancing
  或 chaining。
- IPv6 operator listen/server endpoint、transparent/TUN inbound、SIP023/multi-user。
- 新 dependency、benchmark framework、throughput/10k-UDP claim、package/release/publish。

## Exit criteria

- [ ] Old client v1 documents keep UDP disabled and existing TCP behavior；explicit
      `[udp]` validates offline and enables only the new command path。
- [ ] RFC 1928 control reply/lifetime、standalone UDP header、IPv4/IPv6/domain targets、
      exact failure mapping、source-IP/port pin、multi-target and silent drop behavior pass
      positive/negative tests。
- [ ] Every association uses one collision-safe SIP022 UDP client session and the existing
      runtime session/byte/queue/idle limits；no peer-sized allocation or accepted mutation
      precedes validation and reservation。
- [ ] Control close、idle、I/O failure、capacity pressure、cancellation、graceful/forced
      shutdown and restart/rebind return every owner and socket to baseline。
- [ ] Three methods pass local public-path evidence and the existing external UDP `12/12`
      matrix on one exact SHA/run/attempt, with FerrumClient rows using the client binary。
- [ ] Full、MSRV、three native targets、test budget and blocking Architect/QA review pass；
      missing/failed/unauthorized evidence blocks close。

## Tickets

| Ticket | Outcome | Depends on | Status |
|---|---|---|---|
| M6-T01 | Add the SOCKS5 command/control and standalone UDP wire interface | — | done |
| M6-T02 | Compose the bounded opt-in client association and prove local lifecycle | M6-T01 | ready |
| M6-T03 | Move FerrumClient external rows to the public binary and qualify exact SHA | M6-T02 | todo |

The tickets serialize because T02 consumes T01's interface and T03 changes the evidence
adapter only after the product path is integrated. Owned product/evidence paths do not
overlap across concurrent writers。

## Blocker / next action

No current blocker。M6-T01 is accepted at exact integration product SHA
`7534912c7aed84d5ce4efd09b8532305dc3923e4`；execute M6-T02 next from the T01
acceptance commit in its own branch and worktree。No remote action is authorized。
