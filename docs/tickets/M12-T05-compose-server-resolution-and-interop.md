---
id: M12-T05
milestone: M12
status: active
depends_on: [M12-T04]
owns:
  - .github/workflows/m0.yml
  - Cargo.lock
  - bins/ferrum2-server/Cargo.toml
  - bins/ferrum2-server/src/dns_egress.rs
  - bins/ferrum2-server/src/run.rs
  - crates/ferrum2-dns/Cargo.toml
  - crates/ferrum2-dns/src/resolver.rs
  - tests/m0-harness/src/local_support/mod.rs
  - tests/m0-harness/src/external_support/mod.rs
  - tests/m0-harness/src/qualification/mod.rs
  - tests/m0-harness/src/bin/m0_qualification.rs
  - tests/m0-harness/tests/local_e2e.rs
  - tests/m0-harness/tests/udp_local_e2e.rs
  - tests/m0-harness/tests/architecture.rs
  - tests/m0-harness/tests/qualification_contract.rs
  - tests/m0-harness/tests/workspace_policy.rs
  - tests/interop/versions.toml
---

# M12-T05 — Compose server resolution and interop

## Outcome

Select a tagged DNS resolver and its optional server-direct detour for authenticated TCP/UDP domain
targets，preserve the existing connector/deadline/candidate seams and prove real process behavior against
pinned external DNS software。

## Dependency boundary

The server adds only the existing workspace `ferrum2-dns` direct edge required to compose T03's public
resolver/owner API。The existing lock package row and workspace-policy dependency assertion may change
only to record that local edge；no root dependency、new package identity or provider is added。
`run.rs` may declare the sibling `dns_egress.rs` module directly，so `main.rs` remains out of scope。

ADR-0031's selected-profile trust injection is implemented only as the default-off
`ferrum2-dns/__interop-test-root` feature。It embeds the already reviewed M12 synthetic CA and still
verifies certificate chain、time and configured name；it adds no config、CLI、environment、runtime root
input or insecure verifier。Normal/default/release builds remain WebPKI-only。Only the isolated DNS
qualification build may enable it，and that target directory must be deleted after the run。

The existing `external_support` provider/process owner and `qualification_contract` test seam are the
only authorized external-runner paths；T05 must extend them rather than create a second harness。
`.github/workflows/m0.yml` may change only in one isolated single-parent control-only commit before any
Rust/product commit，to provision the exact pinned CoreDNS/BIND artifacts and make the existing interop
job require the DNS qualification result。The existing control commit may be amended before the first
product commit so its isolated client/server build enables `ferrum2-dns/__interop-test-root`；it remains
one control commit。It must not change triggers、performance/manual-dispatch semantics、unrelated jobs or
test-footprint policy，and later product commits must inherit the amended blob unchanged。

## Acceptance

- [ ] DNS-present server uses authenticated inbound/network/original target for first/final selection；
      DNS detour and application outbound may name different direct tags，while DNS-absent system
      resolver、IP bypass、pre-resolution outbound route and 16 candidates remain exact。
- [ ] Actual client→server→target TCP/UDP cases use distinct synthetic answers to prove selected action；
      empty/wrong/timeout/exhausted results never connect/forward or fall back。
- [ ] Existing qualification provider pins/hashes/licenses CoreDNS 1.14.6 and BIND 9.20.26 without a
      second harness or public-network DNS dependency。
- [ ] CoreDNS UDP/TCP/DoT/DoH and BIND-to-ferrum UDP/TCP matrices pass positive、NXDOMAIN/NODATA、EDNS/
      truncation、TLS/HTTP negatives through both direct and real client Shadowsocks detours and cleanup。
- [ ] Direct/indirect loop、success/failure cycles、redaction、zero Hickory/process owners and exact
      DNS/detour/upstream/target rebind pass；`TEST-0013` T05、Rust 1.88、footprint and blocking reviews
      pass。

## Validation

Run `TEST-0013` T05 commands，then repository Full commands before integration。

## Rollback / risk

Rollback restores system resolution and removes DNS external rows；client proxy may remain only if
server DNS config is rejected。Main risk is granting a fresh deadline after lookup or accidentally
routing DNS bootstrap/application targets through the wrong outbound plan。
