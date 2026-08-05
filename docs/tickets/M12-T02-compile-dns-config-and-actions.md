---
id: M12-T02
milestone: M12
status: planned
depends_on: [M12-T01]
owns:
  - crates/ferrum2-core/src/lib.rs
  - crates/ferrum2-core/tests/selector_contract.rs
  - crates/ferrum2-config/src/lib.rs
  - crates/ferrum2-config/tests/config_contract.rs
  - tests/m0-harness/tests/config_cli.rs
---

# M12-T02 — Compile DNS config and actions

## Outcome

Validate the additive client/server DNS graph and compile its independent server actions through the
same runtime-neutral first-match implementation already used by outbound routing，then resolve optional
DNS detours as roots of the existing egress graph before side effects。

## Acceptance

- [ ] DNS-absent legacy/M7/M8/M10/M11 client/server values remain exact；client DNS inbounds and server
      resolver-only role enforce all counts、tags、collisions、reachability and role bounds。
- [ ] UDP/TCP/DoT/DoH fields、numeric bootstrap、TLS identity、DoH path、timeout/inflight and direct/
      wildcard loop cases validate at one closed redacted field。
- [ ] `dns.servers[].detour` absent means direct；client concrete/chain/selector and server direct tags
      resolve through the existing graph，count as reachability roots and reject legacy/unknown/inbound/
      DNS/wrong-role references at one redacted field。
- [ ] UDP DNS detour acceptance does not enable or require public `[udp]`，and both values survive
      validation independently。
- [ ] One core first-match action table serves existing outbound routes and DNS server actions；all
      current route/selector results remain exact and no DNS/Hickory/config/runtime type enters core。
- [ ] DNS rules use existing inbound/network/exact-target/first/final semantics with `server` only；
      detour does not route the bootstrap target，and cross-action fields、unknown actions、selected-error
      or detour fallback fail closed。
- [ ] `TEST-0013` T02、repository Quick、ticket footprint and blocking Architect/QA review pass on one
      exact candidate。

## Validation

Run `TEST-0013` T02 commands，then repository Quick commands。

## Rollback / risk

Rollback removes `[dns]` acceptance and restores the old private route matcher。Main risk is subtly
changing ordinary terminal-dot、selector-plan/reachability or first/final behavior while extracting the
shared seam。
