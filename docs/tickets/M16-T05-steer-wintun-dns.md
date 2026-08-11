---
id: M16-T05
milestone: M16
status: done
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

Complete the IPv4 auto-DNS vertical by leasing only the owned Wintun interface's IPv4 resolver settings，
intercepting the exact configured IPv4 TCP/UDP port-53 destination before ordinary routing，and carrying every
selected upstream through the existing DNS proxy and pinned client egress owners。

## Acceptance

- [x] Auto-DNS snapshots、applies and reads back IPv4 settings only on the new Wintun interface；physical DNS
      sentinels and the M15 IPv6 adapter address never change，and partial apply reverses exactly。
- [x] Cleanup restores the snapshot only if current state still equals the owned applied value；an external
      replacement is preserved and reported as a fixed cleanup conflict。
- [x] Exact synthetic IPv4 address:53 TCP/UDP enters existing `DnsProxy` before ordinary route and creates no
      Shadowsocks owner unless the selected DNS server uses a proxy detour；wrong address/port and auto-DNS-off
      retain ordinary/M15 behavior。
- [x] No-detour/direct-detour and proxy-detoured UDP/TCP/DoT/DoH upstreams all use the T04 physical binding
      seam and preserve existing deadline、TLS/HTTP identity、admission and no-fallback rules。
- [x] Windows resolver UDP and TCP witnesses pass on the exact current qualification VM/checkpoint；evidence
      reports `dns=2/2` and is described as IPv4 steering，with no managed-IPv6、other-interface、DoH/DoQ、
      WFP、anti-leak or cross-version claim。
- [x] Failure-position、redaction、architecture、focused DNS/process and footprint checks pass。

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

- Commit: `54f06a40b871f39911c583c327b4ba33c12a9646`（tree
  `debb88be678043fdad76773dc9259787dd60582d`，parent `430bc4ceb9a1d64c25945cca0a9dc8f676e80984`）。
- Review: Final root Architect/QA audit on descendant `d76268b…` is `PASS` with zero blocker、major or minor；
  the earlier focused Architect review's two scope notes remain non-findings。
- Footprint: Integrity/category/ratio `PASS`；numeric `REVIEW_REQUIRED` is accepted at code/tests
  `31932/54626`、ratio `1.710698`、case/support/fixture delta `+197/0/0` and code growth `+224`。The
  growth stays in the existing inline tables/architecture file with no helper、fixture、harness or dependency。
- Notes: Focused managed-DNS/TUN/DNS-egress/proxy/local-E2E rows pass `1/2/7/5/2`。The exact restored-VM
  descendant `d76268b…` supplies the required Windows resolver `dns=2/2` witness while preserving M15 IPv6；
  no global DNS、anti-leak or managed-IPv6 claim is made。

## Rollback / risk

Rollback removes auto-DNS while retaining accepted auto-route/direct behavior。The dominant risk is claiming
exclusive DNS control from per-interface settings；both documentation and VM evidence must remain bounded to
observed resolver steering。
