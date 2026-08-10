---
id: M16-T05
milestone: M16
status: planned
depends_on:
  - M16-T04
owns:
  - crates/ferrum2-wintun/src/
  - bins/ferrum2-client/src/dns_egress.rs
  - bins/ferrum2-client/src/run.rs
  - bins/ferrum2-client/src/run/dns.rs
  - bins/ferrum2-client/src/run/tun.rs
  - tests/m0-harness/tests/architecture.rs
  - tests/m0-harness/tests/local_e2e.rs
---

# M16-T05 — Steer Wintun DNS and synthetic DNS traffic

## Outcome

Complete the auto-DNS vertical by leasing only the owned Wintun interface's resolver settings，intercepting
the exact configured IPv4/IPv6 TCP/UDP port-53 destinations before ordinary routing，and carrying every
selected upstream through the existing DNS proxy and pinned client egress owners。

## Acceptance

- [ ] Auto-DNS snapshots、applies and reads back both-family settings only on the new Wintun interface；
      physical DNS sentinels never change and partial family failure reverses exactly。
- [ ] Cleanup restores the snapshot only if current state still equals the owned applied value；an external
      replacement is preserved and reported as a fixed cleanup conflict。
- [ ] Exact synthetic address:53 TCP/UDP enters existing `DnsProxy` before ordinary route and creates no
      Shadowsocks owner unless the selected DNS server uses a proxy detour；wrong address/port and auto-DNS-off
      retain ordinary/M15 behavior。
- [ ] No-detour/direct-detour and proxy-detoured UDP/TCP/DoT/DoH upstreams all use the T04 physical binding
      seam and preserve existing deadline、TLS/HTTP identity、admission and no-fallback rules。
- [ ] Windows resolver UDP and TCP witnesses pass on both accepted guest baselines；evidence is described as
      steering，with no other-interface、DoH/DoQ、WFP or anti-leak claim。
- [ ] Failure-position、redaction、architecture、focused DNS/process and footprint checks pass。

## Validation

```sh
cargo test -p ferrum2-wintun managed_dns --locked
cargo test -p ferrum2-client tun_auto_dns --locked
cargo test -p ferrum2-client dns_egress --locked
cargo test -p ferrum2-dns --test proxy_contract --locked
cargo test -p ferrum2-m0-harness --test local_e2e --locked dns_
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
sh scripts/test-budget.sh ticket --base <accepted-M16-T04-sha> --candidate <candidate-sha>
git diff --check <accepted-M16-T04-sha>..<candidate-sha>
```

## Result

- Commit: —
- Review: —
- Footprint: —
- Notes: —

## Rollback / risk

Rollback removes auto-DNS while retaining accepted auto-route/direct behavior。The dominant risk is claiming
exclusive DNS control from per-interface settings；both documentation and VM evidence must remain bounded to
observed resolver steering。
