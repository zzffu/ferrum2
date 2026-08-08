---
id: M14-T05
milestone: M14
status: ready
depends_on:
  - M14-T04
owns:
  - Cargo.lock
  - bins/ferrum2-server/Cargo.toml
  - bins/ferrum2-server/src/run.rs
  - bins/ferrum2-server/src/run/observation.rs
  - bins/ferrum2-server/src/run/tcp.rs
  - bins/ferrum2-server/src/run/test_support.rs
  - bins/ferrum2-server/src/run/tests.rs
  - bins/ferrum2-server/src/run/udp.rs
  - crates/ferrum2-observability/src/lib.rs
  - crates/ferrum2-observability/tests/metrics_contract.rs
  - crates/ferrum2-observability/tests/tracing_contract.rs
  - crates/ferrum2-runtime/Cargo.toml
  - crates/ferrum2-runtime/src/lib.rs
  - crates/ferrum2-runtime/src/owner.rs
  - crates/ferrum2-runtime/src/sniff.rs
  - tests/m0-harness/tests/architecture.rs
  - tests/m0-harness/tests/config_cli.rs
  - tests/m0-harness/tests/workspace_policy.rs
---

# M14-T05 — Compose server routing and sniffing

## Outcome

Compose authenticated server TCP/UDP through the ordered program，bounded sniffing，terminal direct route
or reject，with exact prefix replay and unchanged SIP022/replay/resource ordering。

## Acceptance

- [ ] Runtime provides one lazy、deadline/cancellation/buffer-owned bounded prefix collector with closed
      timeout/limit/I/O outcomes and no route ownership。
- [ ] Server TCP authenticates first，sniffs before direct open，continues on nonfatal outcomes，rejects
      without target work and replays the full prefix exactly once on route。
- [ ] Server UDP authenticates/prepares first，borrow-sniffs before target reservation and retains exact
      reserve/commit ordering；reject forwards nothing while consuming required replay/binding state。
- [ ] Unauthenticated input cannot mutate/emit sniff policy，and terminal failure never evaluates later
      rules/final。
- [ ] Validated server route remains one hop，with switch/no-fallback、cancel/grace/force/owner/rebind and
      redacted telemetry exact。
- [ ] T05 focused、Quick、footprint integrity and diff gates pass。

## Validation

```powershell
cargo test -p ferrum2-runtime sniff_prefix --locked
cargo test -p ferrum2-server route_sniff_reject --locked
cargo test -p ferrum2-server lifecycle_composition_contract_prefix --locked
cargo test -p ferrum2-server --locked
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo clippy -p ferrum2-runtime -p ferrum2-server --all-targets --all-features --locked -- -D warnings
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

Rollback restores current direct selection/prefix forwarding。Authentication-before-policy、prefix
integrity and UDP prepare/reserve/commit order are blocking and may not be simplified during repair。
