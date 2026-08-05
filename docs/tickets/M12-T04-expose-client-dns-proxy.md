---
id: M12-T04
milestone: M12
status: active
depends_on: [M12-T03]
owns:
  - crates/ferrum2-dns/src/proxy.rs
  - crates/ferrum2-dns/tests/proxy_contract.rs
  - bins/ferrum2-client/src/dns_egress.rs
  - bins/ferrum2-client/src/run.rs
---

# M12-T04 — Expose client DNS proxy

## Outcome

Compose every client DNS inbound as one aggregate-bounded UDP/TCP process root that parses、frames and
encodes through Hickory，selects exactly one DNS server action per question and carries that server over
its absent-direct or configured Shadowsocks detour。

## Acceptance

- [ ] Real UDP and TCP queries prove DNS-inbound/network/absolute-qname:53 first/final selection and
      positive/negative/EDNS/truncation behavior through Hickory。
- [ ] Distinct direct、concrete、fixed-chain and selector detours carry UDP/TCP/DoT/DoH to the configured
      numeric server；bootstrap never runs ordinary route and TCP-family flows/UDP queries preserve
      existing selector snapshot semantics。
- [ ] Detoured UDP reuses existing SIP022 packet/session owners and succeeds with public `[udp]` off
      without accepting SOCKS5 `UDP ASSOCIATE`；public opt-in on/off never creates two managers。
- [ ] FORMERR/NOTIMP/REFUSED/drop/close/SERVFAIL behavior is exact for malformed、shape、class/opcode、
      frame、busy、timeout and upstream failures，with zero unauthorized upstream work。
- [ ] Two-listener aggregate connection/inflight saturation、TCP multi-query/idle/half-frame and forced
      shutdown plus detour connection/session saturation keep fixed permits、queues、buffers and tasks。
- [ ] Prepare failure rolls back paired UDP/TCP sockets and all roots；success/failure shutdown reaches
      zero DNS/egress owners and exact listener、Shadowsocks-hop、DNS-upstream rebind。
- [ ] Each prepared client DNS root retains both `TaggedResolver` and its `TaggedResolverOwner`；run、
      rollback and forced shutdown drop/close the resolver then explicitly await the owner，never relying
      on owner `Drop` as the transitive reap path。
- [ ] Destination/tag/bootstrap/TLS/path sentinels are absent from stderr/trace/metrics；`TEST-0013` T04、
      Full、footprint and blocking reviews pass。

## Validation

Run `TEST-0013` T04 commands，then repository Full commands before integration。

## Rollback / risk

Rollback removes client DNS roots while retaining tagged upstreams for later server composition。Main
risks are using Hickory's unbounded stock accept loop、incorrect UDP truncation or connection admission
being multiplied by inbound count，plus accidentally forking the SIP022 UDP data plane for internal DNS。
