---
id: M14-T07
milestone: M14
status: done
depends_on:
  - M14-T06
owns:
  - Cargo.lock
  - bins/ferrum2-client/Cargo.toml
  - bins/ferrum2-client/src/dns_egress.rs
  - bins/ferrum2-client/src/run.rs
  - bins/ferrum2-client/src/run/context.rs
  - bins/ferrum2-client/src/run/dns.rs
  - bins/ferrum2-client/src/run/egress/**
  - bins/ferrum2-client/src/run/observation.rs
  - bins/ferrum2-client/src/run/socks.rs
  - bins/ferrum2-client/src/run/test_support.rs
  - bins/ferrum2-client/src/run/tests.rs
  - bins/ferrum2-server/src/run/observation.rs
  - crates/ferrum2-core/src/lib.rs
  - crates/ferrum2-socks5/src/lib.rs
  - crates/ferrum2-socks5/tests/command.rs
  - tests/m0-harness/tests/architecture.rs
  - tests/m0-harness/tests/config_cli.rs
  - tests/m0-harness/tests/socks_udp_local_e2e.rs
  - tests/m0-harness/tests/workspace_policy.rs
---

# M14-T07 — Compose client routing and DNS hijack

## Outcome

Compose client TCP/UDP terminal route、reject and DNS hijack，then make schema-v2 SOCKS UDP classify once
from its first valid datagram and own exactly one lazy selected plan for the association。

## Acceptance

- [x] Client TCP decides from known request fields only，never waits for payload，maps reject to SOCKS
      `0x02` and serves multiple hijacked DNS frames through the existing answering interface。
- [x] `UDP ASSOCIATE` returns its one relay endpoint before payload。Wrong-source/malformed/fragmented
      packets cannot classify it；the first source/wire-valid packet is cached，fills association route
      metadata，borrow-sniffs DNS and runs the ordered program exactly once。
- [x] Terminal route resolves one plan/selector snapshot、lazy-creates one bounded owner and forwards the
      cached first packet exactly once。Later packets keep their own targets through that plan and never
      read rules/final/selector again；a later selector switch or differently matching target cannot move
      the association。
- [x] Terminal hijack keeps the whole association in DNS answering and returns each response with that
      request's target；later non-DNS/malformed data never routes。Terminal reject silently drops the
      classification packet and ends the association。Neither path creates Shadowsocks state。
- [x] `SocksUdpEndpoint` exclusively owns application socket/source/SOCKS wire and all
      `ClientUdpAssociation` upstream/one-plan/session/runtime fields are private；no plan-keyed map、
      endpoint trait/factory or per-datagram route branch remains。
- [x] Existing static UDP setup snapshot、server/DNS behavior、chain order/credentials、all-layer
      atomicity、idle/cancel/grace/force/owner/rebind and low-cardinality observations remain exact。
- [x] T07 focused、Quick、footprint integrity and diff gates pass。

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

- Commit: initial `201a07a30a4e0bb7667e92a72d5e8def809fe201`；bounded repair
  `cbf2a6b8a8e3ea95e4fd4b971d3b823779d7fbd7`；accepted post-escalation product
  `548029ef1156608bcd924c2d8104b9ec6f8dc3be`；integration
  `1e29a5edbc82bd3ec7fa01aa3723331e6c54fab3`。
- Review: initial Architect/QA `BLOCK` on pre-bound UDP owner mutation and incomplete architecture/
  reject evidence。One bounded repair closed those findings but changed schema-v1 static capacity failure from
  setup-time `0x01` to post-success first-packet failure。Two required independent
  `gpt-5.6-sol/xhigh` read-only analyses selected the same single-association split-phase repair；final
  targeted Architect/QA both returned `PASS` with all findings closed and no new finding。
- Footprint: zero-exit `REVIEW_REQUIRED`；integrity and ratio `PASS`；ticket case/support/fixture
  `+161/0/0`，code growth `+490`，ratio `1.760476`。The advisory is accepted for distinct in-place
  state-machine、architecture and E2E evidence，with no helper、support module、fixture or harness。
- Notes: Exact integration focused and Quick pass；the accepted product also passed Rust 1.88 workspace
  check/build/test。Schema-v1 static UDP again performs session/buffer/socket admission before success
  while plan/live-ID activation remains first-valid-packet lazy；schema-v2 validates the selected-plan
  bound before every owner、source-accept and send mutation。No remote action occurred in T07。

## Rollback / risk

Rollback removes schema-v2 client composition with the rest of M14；it does not restore a second runtime
path inside the M14 product。The highest risk is invalid input claiming the association、first-packet
loss/duplication or later traffic re-entering route policy。
