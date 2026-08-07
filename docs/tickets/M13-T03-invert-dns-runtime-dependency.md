---
id: M13-T03
milestone: M13
status: done
depends_on: [M13-T02]
owns:
  - Cargo.lock
  - crates/ferrum2-dns/Cargo.toml
  - crates/ferrum2-dns/src/lib.rs
  - crates/ferrum2-dns/src/resolver.rs
  - crates/ferrum2-dns/src/runtime_owner.rs
  - crates/ferrum2-dns/src/runtime_provider.rs
  - crates/ferrum2-dns/tests/proxy_contract.rs
  - crates/ferrum2-dns/tests/resource_lifecycle.rs
  - crates/ferrum2-dns/tests/tagged_upstreams.rs
  - bins/ferrum2-client/src/run.rs
  - bins/ferrum2-client/src/dns_egress.rs
  - bins/ferrum2-server/src/run.rs
  - bins/ferrum2-server/src/dns_egress.rs
  - tests/m0-harness/tests/architecture.rs
  - tests/m0-harness/tests/workspace_policy.rs
---

# M13-T03 — Invert the DNS runtime dependency

## Outcome

Give DNS its own validated runtime spec，replace its duplicate snapshot with core's owned value and move
config-to-runtime conversion to client/server composition without changing DNS behavior。

## Acceptance

- [ ] `TaggedResolver` consumes DNS-owned specs；DNS source/public interface no longer mentions config
      DTOs or exports `PlanSnapshot`。
- [ ] Cargo metadata proves DNS's only normal workspace-internal dependency is core，config has no DNS
      edge and no third-party identity/feature/provider changes；the existing DNS manifest/feature
      policy guard is updated in place from the superseded config edge to the approved core edge。
- [ ] Client/server pure conversions preserve all UDP/TCP/DoT/DoH direct/detour values，validation/error
      ordering and zero-side-effect `--check-config` behavior；binary-owned unit tables prove conversion，
      while the unchanged config contract remains DTO/schema evidence。
- [ ] Four transports、server order、no fallback/cache/retry、selector snapshot and UDP TC same-plan
      behavior pass through `EgressPlanSnapshot` with no hop copy。
- [ ] Existing DNS owner/admission/deadline/shutdown/rebind and redaction evidence remains exact。
- [ ] `TEST-0014` T03、repository Quick、ticket footprint and blocking Architect/QA review pass on one
      exact candidate。

## Validation

Run `TEST-0014` T03 commands，then repository Quick。Replace DNS's old type in place；do not retain a
compatibility wrapper or solve the edge by making config depend on DNS。

## Result

- Commit: initial `adfe4120eb8c91230fd37c4c9171a4354092e5a2`；accepted repair
  `dd532597f171dff45b738623e8be6c5e039252a1`；integration merge
  `768c750a4edfe0818717e2b6f6a8e99a99c10f2e`。
- Review: initial Architect/QA `BLOCK` on `ARCH-M13T03-001/002` and
  `M13-T03-QA-001/002`；one bounded evidence-only repair；targeted Architect/QA `PASS`，all IDs closed。
- Notes: Authentic RED was the exact architecture dependency command at bound base `cc1eb53d…`，which
  failed `0/1` on the old DNS-to-config edge before the implementation and passed `1/1` afterward。
  Integration T03 focused and Quick passed；footprint integrity `PASS`，ticket case/support/fixture delta
  `+219/0/0`。Numeric `REVIEW_REQUIRED` is accepted for necessary conversion/identity evidence in the two
  existing large binary test targets；ticket growth itself passed and no helper、fixture or harness was
  added。No remote action。

## Rollback / risk

Rollback restores the DNS/config edge and old internal adapter only together。Primary risks are mapping
drift between binaries、snapshot timing drift and unintentionally changing Hickory transport options。
