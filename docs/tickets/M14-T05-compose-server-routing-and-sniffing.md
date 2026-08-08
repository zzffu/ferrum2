---
id: M14-T05
milestone: M14
status: done
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

- [x] Runtime provides one lazy、deadline/cancellation/buffer-owned bounded prefix collector with closed
      timeout/limit/I/O outcomes and no route ownership。
- [x] Server TCP authenticates first，sniffs before direct open，continues on nonfatal outcomes，rejects
      without target work and replays the full prefix exactly once on route。
- [x] Server UDP authenticates/prepares first，borrow-sniffs before target reservation and retains exact
      reserve/commit ordering；reject forwards nothing while consuming required replay/binding state。
- [x] Unauthenticated input cannot mutate/emit sniff policy，and terminal failure never evaluates later
      rules/final。
- [x] Validated server route remains one hop，with switch/no-fallback、cancel/grace/force/owner/rebind and
      redacted telemetry exact。
- [x] T05 focused、Quick、footprint integrity and diff gates pass。

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

- Commit: initial `da0d9a21db23d4ecad97ffe77f07067c430c758b`；bounded repair
  `7db1fc84f43d486f56f2f55682a6cac72bd888ea`；accepted post-escalation product
  `83e55038cfc6b840ef1774ee5669b4fa2cba57e0`；integration
  `4c65bb0294892b2133116d57a4262f7d9de69c56`。
- Review: initial Architect/QA `BLOCK`；one bounded repair closed cancellation、prefix ownership、most
  telemetry/UDP ordering and evidence findings，but targeted re-review still blocked real `limit`
  reachability、the unified UDP protocol-session ceiling and selected-open-failure evidence。Two required
  independent `gpt-5.6-sol/xhigh` read-only analyses both selected the same existing-seam correction；final
  targeted Architect/QA returned `PASS` with `ARCH-001..006` and `QA-001..003` closed。
- Footprint: zero-exit `REVIEW_REQUIRED`；integrity/category/ratio `PASS`；ticket case/support/fixture
  `+1508/0/0`，code growth `+692`，ratio `1.767212`。
- Notes: Exact integration focused and Quick pass。The first integration CLI attempt used the stale
  pre-merge binary because bins had not yet been rebuilt；building workspace bins and rerunning the same
  table passed `6/6`，then the complete workspace Quick passed unchanged。Rust 1.88 check/build/test passed
  on the accepted product；no dependency、new harness/helper/fixture、remote action or publication was added。

## Rollback / risk

Rollback restores current direct selection/prefix forwarding。Authentication-before-policy、prefix
integrity and UDP prepare/reserve/commit order are blocking and may not be simplified during repair。
