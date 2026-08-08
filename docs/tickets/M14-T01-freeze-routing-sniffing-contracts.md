---
id: M14-T01
milestone: M14
status: ready
depends_on: []
owns:
  - CONTEXT.md
  - ci/test-budget-baseline.txt
  - docs/adr/ADR-0032-m13-egress-and-module-seams.md
  - docs/adr/ADR-0033-m14-ordered-route-program-and-protocol-sniffing.md
  - docs/milestones/M14-bounded-protocol-sniffing-and-ordered-route-dns-rules.md
  - docs/roadmap.md
  - docs/specs/SPEC-0014-m13-behavior-preserving-architecture-consolidation.md
  - docs/specs/SPEC-0015-m14-bounded-protocol-sniffing-and-ordered-route-dns-rules.md
  - docs/test-plans/TEST-0015-m14-bounded-protocol-sniffing-and-ordered-route-dns-rules.md
  - docs/tickets/M14-T*.md
---

# M14-T01 — Freeze routing and sniffing contracts

## Outcome

Accept one control/Markdown commit that pins the exact M14 base，closes the M13 snapshot wording mismatch，
records the protocol-neutral route、existing DNS-answering and schema-v2 association-routing seams，
reviews all parser/matcher dependencies and activates the M14 footprint baseline before product work。

## Acceptance

- [ ] Qualified M13 product/tree and planning HEAD/tree/parent resolve exactly；their intervening diff has
      no Rust、manifest or lock change。
- [ ] ADR-0032/SPEC-0014 distinguish client/multi-hop/DNS owned snapshots from the validated server
      one-hop scalar path without rewriting M13 evidence。
- [ ] ADR-0033、SPEC-0015、TEST-0015 and all nine tickets agree on actions、matcher/capability semantics、
      schema-v2 first-valid-datagram association selection、schema-v1 routed+UDP migration rejection、
      failure ordering、serial graph、ownership、review bound and remote boundary。No contract retains a
      per-datagram client routed UDP implementation。
- [ ] The two M14 research notes distinguish RFC permission from the source-derived sing-box behavior：
      one association-selected outbound and variable per-packet destinations。
- [ ] Exact Hickory/rustls reuse、locked `ipnet 2.12.1` and new no-default `httparse 1.10.1` have recorded
      license、MSRV、feature、unsafe/source and dependency dispositions；any failure blocks T02。
- [ ] Schema 3 M14 policy uses exact `cc8a0c2…` counts `21814/39632` and
      `33883/5152/597`，unchanged thresholds、revision 1 and TEST-0015 reforecast reference。
- [ ] Current selector/config/DNS/architecture evidence and repository Quick pass unchanged；no Rust
      product、workflow、harness or remote state changes。

## Validation

```powershell
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh verify
cargo test -p ferrum2-core --test selector_contract --locked
cargo test -p ferrum2-config --test config_contract --locked
cargo test -p ferrum2-dns --test proxy_contract --locked
cargo test -p ferrum2-client routed_udp_uses_lazy_endpoint_legs_and_rejects_cross_leg_responses --locked
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo build --workspace --bins --locked
cargo test --workspace --locked
git diff --check
```

## Result

- Commit: —
- Review: —
- Footprint: —
- Notes: —

## Rollback / risk

Rollback restores the M13 footprint policy and removes only M14 planning changes。The main risk is an
unreviewed parser dependency、moved base or contradictory UDP granularity；T02 must bind the exact
accepted T01 commit。
