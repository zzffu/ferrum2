---
id: M14-T06
milestone: M14
status: done
depends_on:
  - M14-T05
owns:
  - Cargo.lock
  - bins/ferrum2-client/src/dns_egress.rs
  - bins/ferrum2-client/src/run.rs
  - bins/ferrum2-client/src/run/dns.rs
  - bins/ferrum2-server/Cargo.toml
  - bins/ferrum2-server/src/dns_egress.rs
  - bins/ferrum2-server/src/run.rs
  - bins/ferrum2-server/src/run/dns.rs
  - crates/ferrum2-config/src/model.rs
  - crates/ferrum2-config/tests/config_contract.rs
  - crates/ferrum2-dns/src/lib.rs
  - crates/ferrum2-dns/src/proxy.rs
  - crates/ferrum2-dns/src/resolver.rs
  - crates/ferrum2-dns/src/runtime_owner.rs
  - crates/ferrum2-dns/tests/proxy_contract.rs
  - crates/ferrum2-dns/tests/resource_lifecycle.rs
  - crates/ferrum2-dns/tests/tagged_upstreams.rs
  - tests/m0-harness/tests/architecture.rs
  - tests/m0-harness/tests/workspace_policy.rs
---

# M14-T06 — Extend DNS policy and answering

## Outcome

Extend client query and server application-resolution policy while making the existing
`DnsProxy::answer` interface reusable by dedicated and ordinary ingress，without another DNS module or
changing M12 upstream/detour behavior。

## Acceptance

- [x] Dedicated listener and ordinary inbound identities cannot collide；client selection supports
      transport、qname exact/suffix and the closed qtype set with mandatory final。
- [x] Server resolution supports application network、domain exact/suffix and port/range without qtype，
      and performs one selected A+AAAA sequence under the existing deadline。
- [x] `DnsProxy::answer` remains the only parse/select/query/encode implementation；listener and future
      hijack adapters reuse it without a delegating service、copied codec or second framer。
- [x] Direct/detoured UDP/TCP/DoT/DoH、selected failure no fallback、UDP TC same server/address/plan、
      busy/timeout response and redaction remain exact。
- [x] DNS owner shutdown、active query reap and listener/upstream rebind remain bounded and awaited。
- [x] T06 focused、Quick、footprint integrity and diff gates pass。

## Validation

```powershell
cargo test -p ferrum2-dns --test proxy_contract --locked
cargo test -p ferrum2-dns --test tagged_upstreams --locked -- --nocapture
cargo test -p ferrum2-dns --test resource_lifecycle --locked -- --nocapture
cargo test -p ferrum2-client dns_proxy_first_match_direct_and_detoured_transports --locked
cargo test -p ferrum2-server tagged_dns_selection_uses_authenticated_original_context_and_final --locked
cargo test -p ferrum2-client -p ferrum2-server -p ferrum2-dns --locked
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo clippy -p ferrum2-dns -p ferrum2-client -p ferrum2-server --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## Result

- Commit: initial `1e21082f35f2ac46a55660e7aca2256b9b6903c3`；bounded repair
  `d4210e40c73daad077c463c5c9db2b9f4b3dddbb`；accepted post-escalation product
  `4cb3c2da75fb8bf29e8aeca093b8b46e06a4f9af`；integration
  `2735853ba75183c4046365793020e57f3e1667ca`。
- Review: initial QA `BLOCK` on disconnected live policy evidence；one bounded repair closed the client
  unknown-qtype seam but targeted QA retained the production server policy handoff and rejected a copied
  test DNS codec。Two required independent `gpt-5.6-sol/xhigh` read-only analyses selected the same
  Hickory dev-only typed-fixture and token-guard repair；final targeted Architect/QA both returned `PASS`
  with `QA-001..003` closed and no new findings。
- Footprint: zero-exit `REVIEW_REQUIRED`；integrity/category/ratio `PASS`；ticket case/support/fixture
  `+611/0/0`，code growth `+42`，ratio `1.789147`。
- Notes: Exact integration focused and Quick pass；Rust 1.88 workspace check/build/test passed on the
  accepted product。Unknown wire qtypes remain distinct from `ANY`，selected DNS failure has no fallback，
  and the only new edge is exact existing `hickory-proto 0.26.1/std` under server dev-dependencies。No new
  package identity、product dependency、second DNS implementation、helper、fixture、harness or remote action。

## Rollback / risk

Rollback restores M12 exact-target DNS policy and listener-only answering。The primary risks are a second
DNS implementation or fallback across action domains；architecture and failure mutations are blocking。
