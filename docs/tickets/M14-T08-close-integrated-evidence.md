---
id: M14-T08
milestone: M14
status: ready
depends_on:
  - M14-T07
owns:
  - Cargo.lock
  - .github/workflows/m0.yml
  - tests/m0-harness/src/**
  - tests/m0-harness/tests/architecture.rs
  - tests/m0-harness/tests/lifecycle_cycles.rs
  - tests/m0-harness/tests/local_e2e.rs
  - tests/m0-harness/tests/qualification_contract.rs
  - tests/m0-harness/tests/socks_udp_local_e2e.rs
  - tests/m0-harness/tests/udp_local_e2e.rs
  - tests/m0-harness/tests/workspace_policy.rs
  - tools/ferrum2-m4-qualification/**
---

# M14-T08 — Close integrated evidence

## Outcome

Prove the completed M14 behavior through the existing real-process、architecture、lifecycle and
qualification-driver modules，repairing only review findings within an explicitly amended lease。

## Acceptance

- [ ] Four M14 real-process TCP/UDP client/server rows prove sniff/route/reject/hijack、malformed
      no-fallback、zero owners and exact rebind。The client UDP row uses separate associations for
      terminal actions and proves first-packet route plus later different target/same real outbound；
      together with T07's mandatory actual selector-switch row and architecture mutation guard，this
      proves no rule/final/selector re-read without adding a binary control endpoint。Applicable
      M10～M13 rows remain green or are explicitly superseded。
- [ ] Architecture evidence rejects concrete protocols in core、second route/DNS/SIP022 implementations、
      parser dependency reversal、server multi-hop scalar selection、client UDP field reach-through、
      a plan-keyed association and any per-datagram client routed UDP branch。
- [ ] The existing qualification driver gains the planned no-sniff/64-rule/sniff/hijack/resource
      measurements and the schema-v1 routed-UDP migration rejection measurement。TLS/HTTP recognition
      uses valid distinguishable inputs and mutation-sensitive terminal oracles；no second harness/job or
      threshold claim is added。
- [ ] Any workflow change is an isolated reviewed control commit and preserves automatic/manual evidence
      separation。No remote run occurs in T08。
- [ ] One full Architect and QA review identifies zero blockers after at most one targeted repair round；
      product-path repairs require a ticket ownership amendment before editing。
- [ ] T08 focused、Full、footprint integrity and diff gates pass。

## Validation

```powershell
cargo build --workspace --bins --locked
cargo test -p ferrum2-client routed_udp_first_valid_packet_selects_association_once --locked
cargo test -p ferrum2-m0-harness --test local_e2e m14_server_tcp_sniff_routes_rejects_and_replays_prefix --locked -- --exact --nocapture
cargo test -p ferrum2-m0-harness --test udp_local_e2e m14_server_udp_dns_sniff_routes_and_rejects_before_target --locked -- --exact --nocapture
cargo test -p ferrum2-m0-harness --test local_e2e m14_client_tcp_dns_hijack_reuses_policy_and_reaps --locked -- --exact --nocapture
cargo test -p ferrum2-m0-harness --test socks_udp_local_e2e m14_client_udp_association_actions_route_once_and_reap --locked -- --exact --nocapture
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo test -p ferrum2-m0-harness --test qualification_contract --locked
cargo test -p ferrum2-m4-qualification --locked
cargo run -p ferrum2-m4-qualification --locked -- self-check
cargo test --workspace --all-features --locked
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

Harness/tool changes are removed without changing product semantics。Do not use a broad T08 lease to hide
product repair ownership；amend exact paths and repeat the bounded review when necessary。
