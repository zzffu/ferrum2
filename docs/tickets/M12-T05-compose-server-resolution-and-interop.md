---
id: M12-T05
milestone: M12
status: active
depends_on: [M12-T04]
owns:
  - Cargo.lock
  - bins/ferrum2-server/Cargo.toml
  - bins/ferrum2-server/src/dns_egress.rs
  - bins/ferrum2-server/src/run.rs
  - tests/m0-harness/src/local_support/mod.rs
  - tests/m0-harness/src/qualification/mod.rs
  - tests/m0-harness/src/bin/m0_qualification.rs
  - tests/m0-harness/tests/local_e2e.rs
  - tests/m0-harness/tests/udp_local_e2e.rs
  - tests/m0-harness/tests/architecture.rs
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
only to record that local edge；no root dependency、new package identity、feature or provider is added。
`run.rs` may declare the sibling `dns_egress.rs` module directly，so `main.rs` remains out of scope。

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
