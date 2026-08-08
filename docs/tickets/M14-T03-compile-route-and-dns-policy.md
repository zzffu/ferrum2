---
id: M14-T03
milestone: M14
status: ready
depends_on:
  - M14-T02
owns:
  - bins/ferrum2-client/src/run.rs
  - bins/ferrum2-server/src/run.rs
  - crates/ferrum2-config/src/error.rs
  - crates/ferrum2-config/src/lib.rs
  - crates/ferrum2-config/src/model.rs
  - crates/ferrum2-config/src/raw.rs
  - crates/ferrum2-config/src/validation.rs
  - crates/ferrum2-config/src/validation/**
  - crates/ferrum2-config/tests/config_contract.rs
  - tests/m0-harness/tests/config_cli.rs
  - tests/m0-harness/tests/socks_udp_local_e2e.rs
---

# M14-T03 — Compile route and DNS policy

## Outcome

Compile explicit schema version 2 ordinary/DNS matchers and actions into bounded typed programs，while
rejecting schema-v1 client routed+UDP migration and every unsupported role/network/action or unreachable
shape before runtime side effects。

## Acceptance

- [ ] Scalar/list spellings、AND/OR semantics、normalization、64-rule/value ceilings and exact legacy shape
      compile identically for both roles。
- [ ] Schema version 2 is selected only when declared；schema-v1 client routed+UDP fails on the redacted
      migration field before side effects，and no validated/runtime model represents its former
      per-datagram behavior。Other supported schema-v1 shapes remain exact。
- [ ] Action required/forbidden fields、unconditional terminal reachability、sniff defaults/ranges and
      checked aggregate prefix bound fail on the correct redacted config field。
- [ ] The complete client/server TCP/UDP capability matrix is enforced at compile time；protocol rules
      require an earlier conservatively covering sniff rule。
- [ ] Client DNS qname/suffix/qtype/transport and server application domain/suffix/port policy compile
      separately，with listener/ordinary identities distinct and no server qtype。
- [ ] Missing new fields and missing DNS retain the current config/CLI cohort except the explicit v1
      client routed+UDP migration row；unknown versions、M14 fields in v1 and heuristic fallback fail with
      zero side effects。
- [ ] `--check-config` accepts the fully compiled schema-v2 model；until T05/T07 consume that model，both
      existing run entrypoints reject version 2 before observability、runtime、listener or task creation
      instead of silently executing the legacy route/DNS views。
- [ ] The existing SOCKS UDP process harness retires only the explicitly superseded schema-v1
      per-datagram multi-outbound row；two-hop success remains on static/selector roots and credential
      failures run through the supported static root until T07 adds schema-v2 association evidence。
- [ ] T03 focused、Quick、footprint integrity and diff gates pass。

## Validation

```powershell
cargo test -p ferrum2-config --test config_contract --locked
cargo test -p ferrum2-m0-harness --test config_cli --locked
cargo test -p ferrum2-config --locked
cargo clippy -p ferrum2-config --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## Result

- Commit: —
- Review: —
- Footprint: —
- Notes: —

## Rollback / risk

Rollback removes version-2 raw/model/compiler fields。The primary risk is accepting a rule that an
ingress cannot execute or accidentally compiling the retired per-datagram client path；the version/role
matrix is a blocking config table，not a runtime fallback。The two run-entry latches are temporary
fail-closed guards and must be replaced，not bypassed，when T05/T07 compose their respective typed models。
