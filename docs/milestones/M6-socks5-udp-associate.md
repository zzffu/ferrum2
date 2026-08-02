# M6 — 有界 SOCKS5 UDP ASSOCIATE

- **Status:** closed
- **Qualification:** exact `7f1e45c174e749d3dddd32d187365722cce94dbe`, run
  [`30765897553/1`](https://github.com/zzffu/ferrum2/actions/runs/30765897553)
- **Close contract:** user-authorized quality、MSRV、platform `3/3` and interop success；
  performance and its dependent aggregate are not required or claimed
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

- [x] Old client v1 documents keep UDP disabled and existing TCP behavior；explicit
      `[udp]` validates offline and enables only the new command path。
- [x] RFC 1928 control reply/lifetime、standalone UDP header、IPv4/IPv6/domain targets、
      exact failure mapping、source-IP/port pin、multi-target and silent drop behavior pass
      positive/negative tests。
- [x] Every association uses one collision-safe SIP022 UDP client session and the existing
      runtime session/byte/queue/idle limits；no peer-sized allocation or accepted mutation
      precedes validation and reservation。
- [x] Control close、idle、I/O failure、capacity pressure、cancellation、graceful/forced
      shutdown and restart/rebind return every owner and socket to baseline。
- [x] Three methods pass local public-path evidence and the existing external UDP `12/12`
      matrix on one exact SHA/run/attempt, with FerrumClient rows using the client binary。
- [x] Full、MSRV、three native targets、test budget and blocking Architect/QA review pass；
      missing/failed/unauthorized evidence blocks close。

## Tickets

| Ticket | Outcome | Depends on | Status |
|---|---|---|---|
| M6-T01 | Add the SOCKS5 command/control and standalone UDP wire interface | — | done |
| M6-T02 | Compose the bounded opt-in client association and prove local lifecycle | M6-T01 | done |
| M6-T03 | Move FerrumClient external rows to the public binary and qualify exact SHA | M6-T02 | done |
| M6-T04 | Cap the test-budget ratio without deleting independent evidence | M6-T03 | done |

The tickets serialize because T02 consumes T01's interface、T03 changes the evidence
adapter after product integration, and T04 binds its exact ceiling to the resulting Rust
tree. Owned product/evidence paths do not overlap across concurrent writers。

## Close evidence

Exact candidate `7f1e45c174e749d3dddd32d187365722cce94dbe`, tree
`fc2052de743ae5447617b59b06e331f468efd7a3`, passed serial local Full、Rust 1.85、
100-cycle、docs and the exact-ceiling ticket/milestone/CI budget gates。Automatic push run
[`30765897553/1`](https://github.com/zzffu/ferrum2/actions/runs/30765897553) recorded
quality、MSRV、Windows MSVC、Linux GNU、Linux musl and interop `success` on that same SHA；
interop's fail-closed marker checks prove TCP `12/12`、UDP `12/12` and both cleanup results。

The user explicitly defined those four job groups as M6 hosted success and waived waiting for
the long-running existing performance job or its dependent repository aggregate。Neither is
claimed as PASS or used for an M6 performance statement。The single authorized non-force push
is consumed；no rerun、dispatch、second push、PR、tag、release or publication occurred or is
authorized。This documentation-only closeout is local and is not hosted evidence。
