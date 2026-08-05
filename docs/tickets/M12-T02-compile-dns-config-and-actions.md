---
id: M12-T02
milestone: M12
status: done
depends_on: [M12-T01]
owns:
  - crates/ferrum2-core/src/lib.rs
  - crates/ferrum2-core/tests/selector_contract.rs
  - crates/ferrum2-config/src/lib.rs
  - crates/ferrum2-config/tests/config_contract.rs
  - tests/m0-harness/src/local_support/mod.rs
  - tests/m0-harness/tests/config_cli.rs
---

# M12-T02 — Compile DNS config and actions

## Outcome

Validate the additive client/server DNS graph and compile its independent server actions through the
same runtime-neutral first-match implementation already used by outbound routing，then resolve optional
DNS detours as roots of the existing egress graph before side effects。

## Acceptance

- [x] DNS-absent legacy/M7/M8/M10/M11 client/server values remain exact；client DNS inbounds and server
      resolver-only role enforce all counts、tags、collisions、reachability and role bounds。
- [x] UDP/TCP/DoT/DoH fields、numeric bootstrap、TLS identity、DoH path、timeout/inflight and direct/
      wildcard loop cases validate at one closed redacted field。
- [x] `dns.servers[].detour` absent means direct；client concrete/chain/selector and server direct tags
      resolve through the existing graph，count as reachability roots and reject legacy/unknown/inbound/
      DNS/wrong-role references at one redacted field。
- [x] UDP DNS detour acceptance does not enable or require public `[udp]`，and both values survive
      validation independently。
- [x] One core first-match action table serves existing outbound routes and DNS server actions；all
      current route/selector results remain exact and no DNS/Hickory/config/runtime type enters core。
- [x] DNS rules use existing inbound/network/exact-target/first/final semantics with `server` only；
      detour does not route the bootstrap target，and cross-action fields、unknown actions、selected-error
      or detour fallback fail closed。
- [x] `TEST-0013` T02、repository Quick、ticket footprint and blocking Architect/QA review pass on one
      exact candidate。

## Validation

Run `TEST-0013` T02 commands，then repository Quick commands。

## Result

- Candidate exact：`c2e922d0e4d29e7398ebb0cd3da0dce1516a8a54`；integrated exact：
  `bf26d1587517fe80e701d73abfb45a340f4caa6c`。The isolated inherited-MSRV Clippy repair is
  `ed63450949b090ac092ebcfad8ca5761ed6c5c71`。
- Review：initial Architect/QA found error-provenance、negative-matrix and duplicate-network-parser
  blockers；one bounded repair closed `ARCH-001/002` and `QA-001/002/003`，and both targeted
  re-reviews returned `PASS` with no unresolved blocking ID。
- Validation：core `5/5`、config `16/16`、CLI `5/5`、scoped Clippy、fmt、repository Quick and
  diff checks pass on candidate and integration。The first integration CLI run used stale pre-T02
  binaries；the required workspace bin build followed by an unchanged rerun passed `5/5`。
- Footprint：integrity/category `PASS`，code/tests `16676/33123`、ratio `1.986268` `PASS`，
  case/support/fixture delta `+439/-1/0`。Test growth `438` is `WARN` and `config_contract.rs`
  1,485 semantic test LOC triggers numeric `REVIEW_REQUIRED`；Architect/QA accepted the single
  table/helper and no-fixture evidence。
- Residual：supplementary workspace Clippy exposes three unchanged Rust-1.88 `collapsible_if` warnings
  in server `run.rs`；they are outside T02 and must be repaired under explicit ownership before T06。

## Rollback / risk

Rollback removes `[dns]` acceptance and restores the old private route matcher。Main risk is subtly
changing ordinary terminal-dot、selector-plan/reachability or first/final behavior while extracting the
shared seam。
