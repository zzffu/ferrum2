---
id: M16-T03
milestone: M16
status: planned
depends_on:
  - M16-T02
owns:
  - crates/ferrum2-runtime/src/connector.rs
  - crates/ferrum2-runtime/src/udp.rs
  - bins/ferrum2-client/src/dns_egress.rs
  - bins/ferrum2-client/src/run/egress/
  - bins/ferrum2-client/src/run/io.rs
  - bins/ferrum2-client/src/run/observation.rs
  - bins/ferrum2-client/src/run/socks.rs
  - bins/ferrum2-client/src/run/tun.rs
  - tests/m0-harness/tests/local_e2e.rs
  - tests/m0-harness/tests/socks_udp_local_e2e.rs
---

# M16-T03 — Compose shared client direct TCP and UDP

## Outcome

Deepen the one binary-private client egress engine so SOCKS、TUN and DNS callers can execute a singleton
direct plan as bounded raw TCP/UDP while every existing Shadowsocks one-hop/chain path remains unchanged。
This ticket deliberately runs without product-owned capture；T04 later injects the Windows binder at the
socket seam established here。

## Acceptance

- [ ] Extend the T02 closed `ClientOutboundContext` Direct branch from its pre-socket refusal to raw execution；
      `ClientEgressEngine` alone dispatches kind，while core plan identity and callers remain kind-agnostic。
- [ ] TUN numeric and SOCKS numeric/domain direct TCP reaches the original target，relays exact bytes and
      half-close，and creates zero SIP022 flow/crypto owner；selected failures never fallback。
- [ ] Direct UDP reuses existing bounded resolver/socket/session/cancellation ownership，sends raw payload，
      admits only bound responses and preserves TUN mapping/SOCKS association selection lifetime and limits。
- [ ] Direct payload bounds do not subtract SIP022 overhead；invalid/over-limit first datagrams commit no
      mapping/session/activity and a later valid candidate reselects as specified by M15。
- [ ] Windows TUN-selected direct whose immutable original target is IPv6 fails before resolver/socket creation
      for TCP and UDP with auto-route off or on，and never falls back unpinned。SOCKS/non-Windows direct
      IPv6 and M15 manual-route IPv6 proxy/reject/DNS behavior remain unchanged。
- [ ] DNS no-detour and direct detour normalize to the same direct socket path；proxy detours remain exact。
      No caller retains a raw system connect/bind path that would bypass the future binder。
- [ ] Static/rule/final/selector process witnesses cover direct and proxy for SOCKS and memory-device TUN
      IPv4/IPv6 TCP/UDP，including zero proxy-endpoint traffic on direct。
- [ ] Planned `m16_redaction` client tests inject target、endpoint、DNS name、tag、packet and secret sentinels
      through direct errors/observations and prove none reaches errors、logs、traces or metric labels。
- [ ] Focused runtime/client/process tests、Full-impact architecture guard and footprint disposition pass。

## Validation

```sh
cargo test -p ferrum2-runtime direct_ --locked
cargo test -p ferrum2-client direct_tcp --locked
cargo test -p ferrum2-client direct_udp --locked
cargo test -p ferrum2-client dns_egress --locked
cargo test -p ferrum2-client m16_redaction --locked
cargo test -p ferrum2-m0-harness --test local_e2e --locked direct_
cargo test -p ferrum2-m0-harness --test socks_udp_local_e2e --locked direct_
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
sh scripts/test-budget.sh ticket --base <accepted-M16-T02-sha> --candidate <candidate-sha>
git diff --check <accepted-M16-T02-sha>..<candidate-sha>
```

## Result

- Commit: —
- Review: —
- Footprint: —
- Notes: —

## Rollback / risk

Rollback restores the all-Shadowsocks dispatch while leaving the accepted config ticket to be reverted with
it if necessary。The dominant risk is duplicating existing direct UDP/session ownership；reuse and owner-count
evidence are required。
