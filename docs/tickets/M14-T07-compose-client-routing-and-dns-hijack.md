---
id: M14-T07
milestone: M14
status: ready
depends_on:
  - M14-T06
owns:
  - bins/ferrum2-client/src/dns_egress.rs
  - bins/ferrum2-client/src/run.rs
  - bins/ferrum2-client/src/run/context.rs
  - bins/ferrum2-client/src/run/dns.rs
  - bins/ferrum2-client/src/run/egress/**
  - bins/ferrum2-client/src/run/observation.rs
  - bins/ferrum2-client/src/run/socks.rs
  - bins/ferrum2-client/src/run/test_support.rs
  - bins/ferrum2-client/src/run/tests.rs
  - crates/ferrum2-core/src/lib.rs
  - crates/ferrum2-socks5/src/lib.rs
  - crates/ferrum2-socks5/tests/command.rs
  - tests/m0-harness/tests/architecture.rs
---

# M14-T07 — Compose client routing and DNS hijack

## Outcome

Compose client TCP/UDP terminal route、reject and DNS hijack，then make schema-v2 SOCKS UDP classify once
from its first valid datagram and own exactly one lazy selected plan for the association。

## Acceptance

- [ ] Client TCP decides from known request fields only，never waits for payload，maps reject to SOCKS
      `0x02` and serves multiple hijacked DNS frames through the existing answering interface。
- [ ] `UDP ASSOCIATE` returns its one relay endpoint before payload。Wrong-source/malformed/fragmented
      packets cannot classify it；the first source/wire-valid packet is cached，fills association route
      metadata，borrow-sniffs DNS and runs the ordered program exactly once。
- [ ] Terminal route resolves one plan/selector snapshot、lazy-creates one bounded owner and forwards the
      cached first packet exactly once。Later packets keep their own targets through that plan and never
      read rules/final/selector again；a later selector switch or differently matching target cannot move
      the association。
- [ ] Terminal hijack keeps the whole association in DNS answering and returns each response with that
      request's target；later non-DNS/malformed data never routes。Terminal reject silently drops the
      classification packet and ends the association。Neither path creates Shadowsocks state。
- [ ] `SocksUdpEndpoint` exclusively owns application socket/source/SOCKS wire and all
      `ClientUdpAssociation` upstream/one-plan/session/runtime fields are private；no plan-keyed map、
      endpoint trait/factory or per-datagram route branch remains。
- [ ] Existing static UDP setup snapshot、server/DNS behavior、chain order/credentials、all-layer
      atomicity、idle/cancel/grace/force/owner/rebind and low-cardinality observations remain exact。
- [ ] T07 focused、Quick、footprint integrity and diff gates pass。

## Validation

```powershell
cargo test -p ferrum2-socks5 --test command --locked
cargo test -p ferrum2-client client_route_reject_hijack --locked
cargo test -p ferrum2-client routed_udp_first_valid_packet_selects_association_once --locked
cargo test -p ferrum2-client dns_proxy_detour_saturation_shutdown_and_exact_rebind --locked
cargo test -p ferrum2-client udp_chain_invalid_inner_state_and_shutdown_are_atomic --locked
cargo test -p ferrum2-client -p ferrum2-dns -p ferrum2-socks5 --locked
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo clippy -p ferrum2-client -p ferrum2-dns -p ferrum2-socks5 --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## Result

- Commit: —
- Review: —
- Footprint: —
- Notes: —

## Rollback / risk

Rollback removes schema-v2 client composition with the rest of M14；it does not restore a second runtime
path inside the M14 product。The highest risk is invalid input claiming the association、first-packet
loss/duplication or later traffic re-entering route policy。
