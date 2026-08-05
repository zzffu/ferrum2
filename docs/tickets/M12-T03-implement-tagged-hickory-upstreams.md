---
id: M12-T03
milestone: M12
status: active
depends_on: [M12-T02]
owns:
  - Cargo.lock
  - Cargo.toml
  - bins/ferrum2-server/src/run.rs
  - crates/ferrum2-dns/Cargo.toml
  - crates/ferrum2-dns/src/lib.rs
  - crates/ferrum2-dns/src/resolver.rs
  - crates/ferrum2-dns/src/runtime_owner.rs
  - crates/ferrum2-dns/src/runtime_provider.rs
  - crates/ferrum2-dns/src/error.rs
  - crates/ferrum2-dns/tests/tagged_upstreams.rs
  - crates/ferrum2-dns/tests/resource_lifecycle.rs
  - crates/ferrum2-dns/tests/fixtures/m12-test-ca.der
  - crates/ferrum2-dns/tests/fixtures/m12-resolver-test.der
  - crates/ferrum2-dns/tests/fixtures/m12-resolver-test.pk8
  - crates/ferrum2-dns/tests/fixtures/README.md
  - tests/m0-harness/tests/workspace_policy.rs
---

# M12-T03 — Implement tagged Hickory upstreams

## Outcome

Create lazy tagged UDP/TCP/DoT/DoH resolvers over one bounded Hickory runtime-provider seam that accepts
direct or existing-plan egress，with exact selected-server semantics、absolute deadline、global admission
and ferrum-owned awaited background tasks。

## Acceptance

- [ ] One server per action handles positive A/AAAA/CNAME、NXDOMAIN and NODATA over all four transports；
      cache/retry are zero and no tag races、retries、downgrades or fallbacks。
- [ ] Direct and scripted-detour adapters receive the exact numeric target and plan identity；TCP streams
      and UDP sockets use fixed buffers/queues，while Hickory retains DNS/TLS/HTTP framing。
- [ ] UDP truncation alone upgrades to TCP at the same address/tag；spoof、malformed、TCP half-frame、
      TLS trust/name/time and DoH path/status/body failures retain the same detour snapshot and close
      without another tag/member or accepted state。
- [ ] Numeric bootstrap uses the direct adapter when `detour` is absent and remains the final target of
      the selected plan when present；WebPKI verification is mandatory and the test-only ephemeral root
      creates no product custom-CA/insecure surface。
- [ ] Test-only encrypted fixtures use exact workspace-pinned、already-locked Rustls/H2 packages and a
      dev-only Hickory server HTTPS edge；the normal product graph stays featureless at that edge and
      adds no package identity、provider or operator TLS surface。
- [ ] Global saturation、absolute timeout、fixed buffer/queue/connection ceilings and valid-after-failure
      recovery include detour selection/handshake and are observable and stable。
- [ ] Every lazy Hickory task and detour bridge/session task，including Hickory's directly spawned DoH
      driver，is contained by a ferrum-owned runtime、dropped/aborted if needed and awaited to zero with
      exact direct/first-hop/upstream rebind；`TEST-0013` T03、Full、footprint and blocking reviews pass。

## Validation

Run `TEST-0013` T03 commands，then repository Full commands before integration。

## Rollback / risk

Rollback leaves validated DNS config rejected at runtime until the ticket is removed。Primary risk is a
detached Hickory/detour task、a lifetime bridge with unbounded buffering or a library default silently
widening retries、buffers or TLS policy。
