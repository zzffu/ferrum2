# TEST-0008 — M7 tagged static composition evidence

- **Status:** Approved
- **Milestone:** M7
- **Spec:** `docs/specs/SPEC-0008-m7-tagged-static-composition.md`

## Evidence map

| Requirement | Primary evidence | Gate |
|---|---|---|
| M7-MUST-01 legacy compatibility | preserved v1 fixture/value/side-effect table plus legacy-to-single normalized graph rows | T01 config |
| M7-MUST-02 tags/references | bounded table for syntax/count/duplicate/cross-namespace/dangling/unreferenced/mixed/collision/redaction and zero-resource check | T01 config/security |
| M7-MUST-03 static concrete mapping | binary-interface table for two mappings、shared outbound and referenced-outbound failure without fallback | T02/T03 product |
| M7-MUST-04 shared state/budgets | aggregate two-listener permit/session/byte snapshots、cross-listener TCP replay and UDP inbound-binding table | T02/T03 security/runtime |
| M7-MUST-05 process transaction | first/middle/last TCP/UDP/metrics prepare failure、root fatal、signal、owner baseline and exact rebind table | T02/T03 lifecycle |
| M7-MUST-06 wire/operator regression | existing legacy config、CLI、observability、TCP/UDP protocol/local suites unchanged | T01～T04 regression |
| M7-MUST-07 multi-instance path | bounded real-process two-client/two-server TCP+UDP table plus focused sharing/no-fallback/failure rows | T04 product |
| M7-MUST-08 qualification | Full、MSRV、three native targets、TCP/UDP `24/24`、budget and exact-commit reviews | T04 release |

## T01 config graph evidence

- Keep every baseline client/server fixture's normalized listen/server、method/PSK redaction、
  runtime/replay/UDP/logging/metrics values and old CLI output exact。Prove legacy normalization
  yields one inbound/outbound without exposing synthetic tags。
- Positive table covers one/two/64 entries、one outbound shared by multiple inbounds、exact
  case-sensitive references and all three methods through the unchanged global credential。
- Negative table covers 0/65 entries；empty/65-byte/non-ASCII/whitespace/invalid-character tag；
  duplicate inbound、duplicate outbound、inbound/outbound collision；missing/dangling/
  wrong-namespace reference；unreferenced outbound；legacy/tagged mixing；duplicate listens；
  every metrics/listen and client server/local-listen collision。
- Every negative asserts stable kind/field and verifies rendered Display/Debug excludes raw source、
  all tag/endpoint sentinels and PSK。The table pins the seven approved non-indexed tagged field
  identities。`--check-config` positive/negative rows prove no listener、connector、session
  table、buffer or task side effect。
- Before T02/T03 consume the collections，a multi-inbound run must fail with the existing
  `startup.protocol` error before observability/runtime/listener creation；a one-entry tagged run
  remains behavior-equivalent to legacy。

```powershell
cargo test -p ferrum2-config --locked
cargo test -p ferrum2-m0-harness --test config_cli --locked
cargo clippy -p ferrum2-config -p ferrum2-m0-harness --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## T02 server composition evidence

- Direct binary-interface table creates two ordered TCP/UDP inbounds plus optional metrics and
  proves all roots are prepared before any accept/receive poll。Occupy first/middle/last TCP、UDP
  and metrics positions；every row exits with the original closed startup cause、zero owner delta
  and immediate rebind of all earlier addresses。
- With aggregate `max_connections=1`, hold one admitted TCP flow on inbound A and prove inbound B
  cannot admit until that same permit returns。Replay one authenticated request salt from A to B；
  B rejects before direct connect/forwarding while a fresh B flow succeeds。
- With aggregate UDP session/byte limits at the smallest useful test values, admit on A and prove
  B observes the same saturation。Replay/cross-ingress a live session on B and assert no protocol
  replay/activity、peer、runtime queue、target send or response mutation；valid A response egresses
  A。Normal same-inbound peer roaming remains a regression row。
- Required-root terminal failure cancels all siblings and reaps shared state；signal graceful/
  forced paths and restart/rebind retain the existing single grace/five-second cleanup contract。

```powershell
cargo test -p ferrum2-runtime --test lifecycle --test shutdown --test udp_runtime --locked
cargo test -p ferrum2-server --locked
cargo clippy -p ferrum2-runtime -p ferrum2-server --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## T03 client composition evidence

- Direct binary-interface table binds two SOCKS listeners to distinct Shadowsocks server addresses
  and proves accepted TCP/UDP work uses only its pre-resolved context。A stopped referenced server
  fails that inbound without trying the live sibling outbound；two inbounds sharing one outbound
  both succeed。
- Aggregate `max_connections=1` and UDP max-session/byte rows pressure different listeners and
  prove one process-wide owner。Global client UDP live-ID collision checks remain eight bounded
  attempts and one ID cannot be live through two inbounds。
- First/middle/metrics prepare failure、root fatal、control close、idle、graceful/forced shutdown
  and exact restart/rebind return all listener/permit/task/session/socket/buffer owners to baseline。
- Existing SOCKS CONNECT replies/half-close and UDP source pin/FRAG/drop/size behavior remain exact。

```powershell
cargo test -p ferrum2-client --locked
cargo test -p ferrum2-socks5 -p ferrum2-shadowsocks -p ferrum2-runtime --locked
cargo clippy -p ferrum2-client -p ferrum2-socks5 -p ferrum2-shadowsocks -p ferrum2-runtime --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## T04 real-process and qualification evidence

- Reuse existing local process helpers。One bounded table starts tagged client/server configs with
  at least two inbounds/outbounds each；all three methods exercise both TCP mappings and both UDP
  mappings without a tag cross product。Focused rows cover shared outbound、no fallback、aggregate
  admission、partial bind、root fatal、signal、restart/rebind and at least 100 completed cycles per
  binary path。
- Existing legacy `local_e2e`、server `udp_local_e2e`、client `socks_udp_local_e2e` and
  lifecycle tests run unchanged as regression。Architecture evidence asserts `ferrum2-core` and
  protocol modules gained no config/runtime/Endpoint dependency or generic adapter registry。
- Existing external IDs、reference versions、payloads、deadlines and cleanup remain unchanged：
  TCP `M1-INT-001..012` and UDP `M2-UDP-INT-001..012` each require `12/12` on one exact SHA。
- Native Windows/GNU/musl rows add tagged offline config and bounded multi-listener rollback/rebind
  to the existing artifact smoke；no provider/job is added。

```powershell
cargo test -p ferrum2-m0-harness --test architecture --test config_cli --test lifecycle_cycles --test local_e2e --test udp_local_e2e --test socks_udp_local_e2e --locked
cargo build --workspace --bins --locked
cargo +1.85.0 check --workspace --all-targets --locked
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## Integration gate

Run serially on one accepted integration SHA：

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo build --workspace --bins --locked
cargo test --workspace --all-features --locked
cargo test -p ferrum2-m0-harness --test lifecycle_cycles full_qualification_runs_twenty_cycles_per_category_and_at_least_100_per_binary --locked -- --ignored --exact --nocapture
cargo doc --workspace --all-features --no-deps --locked
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh milestone --candidate <accepted-integration-sha>
git diff --check
```

After separate explicit authorization, one automatic push run/attempt for that exact SHA must
pass quality/Full/security/process、Rust 1.85、Windows MSVC、Linux GNU/musl、TCP
`12/12`+cleanup、UDP `12/12`+cleanup and the repository final qualification summary。Existing
performance may run as regression but M7 adds no performance/resource threshold。

## Stop rules

- Any legacy incompatibility、unvalidated/dangling reference、tag leakage/cardinality、cross-
  listener replay、multiplied resource cap、partial activation、owner leak、fallback/routing、
  Full/MSRV/platform/interop/budget or blocking-review failure blocks M7。
- A product `Endpoint` interface、new dependency or per-entry PSK/method is scope expansion and
  requires a new approved contract before implementation。
- Provider unavailable、skipped required row、wrong SHA/run/attempt or absent remote authorization
  is not PASS。One full Architect/QA review and one targeted re-review are the default bound。
