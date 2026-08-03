# TEST-0009 — M8 shared first-match routing evidence

- **Status:** Approved
- **Milestone:** M8
- **Spec:** `docs/specs/SPEC-0009-m8-first-match-routing.md`

## Evidence map

| Requirement | Primary evidence | Gate |
|---|---|---|
| M8-MUST-01 compatible modes | preserved legacy/static fixture values plus routed/static/legacy exclusivity and zero-resource CLI rows | T01 config |
| M8-MUST-02 bounded graph | table for 0/64/65 rules、matcher grammar、tag/final resolution、unreferenced outbound、field identity and redaction | T01 config/security |
| M8-MUST-03 first-match | core interface table for order、AND/wildcards、final、IP/domain/port equality and no failure fallback | T01 core |
| M8-MUST-04 shared ordering | four caller seam rows proving target validation precedes select and select precedes every outbound/state side effect | T01～T03 architecture/security |
| M8-MUST-05 client routing | client TCP two-upstream table and one UDP association routing two targets with exact response-source/leg ownership | T02 product/security |
| M8-MUST-06 server routing | authenticated TCP/UDP direct-identity selection table with pre-commit ordering and preserved inbound binding | T03 product/security |
| M8-MUST-07 bounds/lifecycle | lazy leg、aggregate owner/byte/session snapshots、cancel/fatal/idle/rebind and unchanged observability tables | T02/T03 runtime |
| M8-MUST-08 qualification | bounded real-process matrix、Full、MSRV、three native targets、existing TCP/UDP `24/24`、Budget and exact reviews | T04 release |

## T01 shared module and config evidence

- Core interface table uses overlapping rules to prove document order，each optional matcher alone，
  all three together，wildcards and total final。Exact target rows cover IPv4、IPv6、same-domain
  ASCII case、different port、trailing dot and unmatched domain without DNS。
- Preserve every legacy/M7 static normalized value and runtime choice。Routed positives cover
  0/1/64 rules、shared final、all three matcher kinds、all outbounds referenced and both roles。
- Static compatibility rows query both networks and multiple targets to prove one inbound keeps
  its M7 outbound through the same selection interface。
- Negative table covers 65 rules、empty-predicate rule、unknown network、empty/non-ASCII/256-byte
  domain、zero port、legacy/route and static/route mixing、partial static bindings、missing/
  dangling/wrong-namespace inbound/outbound/final and unreferenced outbound。
- Every negative asserts the seven approved non-indexed route fields and excludes route/tag/target/
  endpoint/PSK sentinels from Display/Debug。`--check-config` creates no runtime resource。
- Until its composition ticket consumes routed mode，each role's normal run fails with existing
  `startup.protocol` before subscriber/runtime/listener creation；legacy/static execution remains。

```powershell
cargo test -p ferrum2-core -p ferrum2-config --locked
cargo test -p ferrum2-m0-harness --test config_cli --locked
cargo clippy -p ferrum2-core -p ferrum2-config -p ferrum2-m0-harness --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## T02 client routing evidence

- Direct client seam accepts two SOCKS inbounds and two Shadowsocks servers。TCP rows prove inbound-
  only、network-only、exact-target、overlap order and final selection after target parse；an occupied/
  stopped selected server never attempts the live sibling。
- One SOCKS UDP association sends alternating exact targets through two real UDP Shadowsocks
  servers and receives both responses。A third rule/endpoint proves independent protocol
  association state rather than exhausting one leg's two server-session generations。
- Response-source table injects an inactive configured endpoint、wrong active endpoint、tampered、
  duplicate and stale packets；none may reserve/materialize/commit、refresh idle or reach client。
  Duplicate tags with one endpoint reuse one leg；unused outbounds own no leg/ID。
- Association snapshots prove exactly one application/upstream socket and fixed buffer set，
  aggregate `udp.max_sessions` remains association-based，live legs stay within
  `associations * configured-outbounds`，and control EOF、idle、I/O、cancel、forced and root fatal
  reap every ID/owner with exact rebind。
- Existing SOCKS replies、source pin、FRAG/drop/bounds、TCP half-close、deadlines and static/legacy
  client rows remain exact。

```powershell
cargo test -p ferrum2-client --locked
cargo test -p ferrum2-socks5 -p ferrum2-shadowsocks -p ferrum2-runtime --locked
cargo test -p ferrum2-m0-harness --test config_cli --locked
cargo clippy -p ferrum2-client -p ferrum2-socks5 -p ferrum2-shadowsocks -p ferrum2-runtime --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## T03 server routing evidence

- Authenticated TCP seam uses two inbounds、overlapping rules and instrumented direct outbounds to
  prove selection after replay/target acceptance and before connect/initial-payload forwarding。
  Final and selected-failure rows prove no next-rule/final retry。
- UDP pending-request table proves per-datagram selection before protocol/runtime commit，including
  one live SIP022 session alternating exact targets/direct identities。Different ports and a
  domain target prove pre-resolution matching。
- Cross-inbound packet、duplicate/stale/tampered request and capacity failure rows keep route
  evaluation pure and preserve replay/activity/peer/queue/target state。Responses always egress the
  bound inbound；same-inbound roaming remains。
- Aggregate TCP admission、replay、UDP session/bytes，root fatal、signal、graceful/forced shutdown
  and restart/rebind retain M7 owner baselines。Equivalent direct tags do not create duplicate
  socket/runtime owners。

```powershell
cargo test -p ferrum2-server --locked
cargo test -p ferrum2-runtime --test lifecycle --test shutdown --test udp_runtime --locked
cargo test -p ferrum2-m0-harness --test config_cli --locked
cargo clippy -p ferrum2-server -p ferrum2-runtime --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## T04 real-process and qualification evidence

- Reuse existing process helpers。A bounded table starts two client and server inbounds/outbounds，
  covers ordered rule、AND、wildcard and final for TCP/UDP，and routes two targets within one SOCKS
  UDP association to distinct servers。All three methods are covered without a rule/method cross
  product。
- Focused rows cover selected upstream unavailable/no fallback、response source mismatch、partial
  bind、root fatal、signal、restart/rebind and at least 100 completed cycles。Existing legacy and M7
  static `local_e2e`、`udp_local_e2e`、`socks_udp_local_e2e` remain unchanged regression。
- Architecture evidence proves one core selection module，no duplicate matcher in protocol/runtime，
  no route trait/Endpoint/factory/registry/new dependency and no tag/destination observability。
- Existing external case IDs、reference versions、payloads、deadlines and cleanup remain unchanged：
  TCP `M1-INT-001..012` and UDP `M2-UDP-INT-001..012` each require `12/12` on one exact SHA。
- Native Windows/GNU/musl rows add routed offline validation and bounded TCP/UDP route smoke to the
  existing artifact driver without a provider/workflow job。

```powershell
cargo test -p ferrum2-m0-harness --test architecture --test config_cli --test lifecycle_cycles --test local_e2e --test udp_local_e2e --test socks_udp_local_e2e --locked
cargo build --workspace --bins --locked
cargo +1.85.0 check --workspace --all-targets --locked
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## M8 test envelope

The schema 2 policy binds exact baseline `404b62758a191fe879243c755c75bcf8b300040d` at
code/tests `15529/25482`。The accepted evidence estimate is：

| Slice | Maximum new test lines |
|---|---:|
| T01 core route interface + config/CLI tables | 220 |
| T02 client TCP/UDP route and ownership tables | 240 |
| T03 server TCP/UDP ordering and lifecycle tables | 180 |
| T04 real-process/native qualification additions | 120 |
| One explicit repair contingency | 80 |
| **M8 envelope** | **840** |

`ticket_warning=240` flags any ticket larger than the largest accepted slice for explicit
Architect/QA explanation。The envelope may shrink but cannot increase during M8。

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

After separate explicit authorization，one automatic push run/attempt for that exact SHA must pass
quality/Full/security/process、Rust 1.85、Windows MSVC、Linux GNU/musl、existing TCP
`12/12`+cleanup、UDP `12/12`+cleanup、Budget and final qualification。Performance may run
as regression but M8 adds no threshold/claim。

## Stop rules

- Any legacy/static incompatibility、inert/unresolved route、wrong order/final、post-resolution
  target match、pre-auth routing side effect、UDP association pin、fallback、source/session
  crossover、multiplied eager owner、leak、observability cardinality、Full/MSRV/platform/interop/
  Budget or blocking-review failure blocks M8。
- CIDR/domain-pattern/DNS/user matcher、new adapter kind、generic route/Endpoint interface、
  dependency or resource setting is scope expansion and requires a new approved contract。
- Provider unavailable、skipped row、wrong SHA/run/attempt or absent remote authorization is not
  PASS。One full Architect/QA review and one targeted re-review are the default bound。
