# TEST-0014 — M13 behavior-preserving architecture evidence

- **Status:** Approved
- **Milestone:** M13
- **Spec:** `docs/specs/SPEC-0014-m13-behavior-preserving-architecture-consolidation.md`

## Evidence map

| Requirement | Cheapest sufficient primary evidence | Gate |
|---|---|---|
| M13-MUST-01 M12 compatibility | existing config/core/DNS/client/server focused cohorts plus real-process TCP/UDP/DNS witnesses | T01 and T03～T05 |
| M13-MUST-02 owned snapshot | core selector contract table and allocation-identity/redacted-debug unit rows | T02 core |
| M13-MUST-03 DNS inversion | Cargo metadata architecture guard、config conversion table、existing tagged upstream/lifecycle tests | T03 DNS |
| M13-MUST-04 TCP egress | existing client chain/deadline/cancel tests through the new engine plus DNS TCP consumer witness | T04 TCP |
| M13-MUST-05 UDP egress | existing UDP chain/atomicity tests plus exact-key idle reuse/failure mutation table | T05 UDP |
| M13-MUST-06 ownership modules | architecture source/dependency guard and unchanged package/public-path tests | T06 structure |
| M13-MUST-07 security/resources/lifecycle | existing negative、owner-counter、forced shutdown and exact-rebind evidence | T03～T07 |
| M13-MUST-08 scope closure | workspace metadata/source guards、Cargo lock diff and footprint integrity | T01/T06/T07 |
| M13-MUST-09 qualification | serial local gate and exact-SHA hosted automatic + manual resource evidence | T07 exact SHA |

## TDD seams and loop

The agreed test seams are：

1. `ferrum2_core::route` selection/control interface；
2. `TaggedResolver`/`DnsEgress` runtime interface；
3. private client `ClientEgressEngine` interface consumed by SOCKS and DNS adapters；
4. `ProcessRoot`/`ProcessSupervisor` observable lifecycle；
5. Cargo metadata and existing architecture harness for dependency/source ownership。

Each T02～T06 slice starts with one failing assertion at its seam，adds only enough implementation to
make it green，then repeats。A failing end-state guard is never integrated by itself；T01 records the
target assertions and existing M12 evidence rather than landing a permanently red suite。Tests do not
call moved private helpers or duplicate their implementation。

## T01 exact baseline and contract evidence

- Record qualified product `c06386e9…` and planning HEAD/tree/parent `4810ec5c…` /
  `d732eccc…` / `0b854e7a…`。Confirm that intervening commits change no Rust product/test source。
- Activate schema 3 for M13 at code/tests `18940/39748` and case/support/fixture
  `33999/5152/597`，with unchanged thresholds and `policy_revision=1`。
- Inventory current dependency/copy/coupling witnesses named in the milestone。Map every existing M10～
  M12 focused test to one M13 MUST；do not create a second baseline runner。
- Run the existing route、DNS and client snapshot/no-fallback tests unchanged。Any baseline failure blocks
  implementation rather than being reclassified as refactor fallout。

```powershell
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh verify
cargo test -p ferrum2-core --test selector_contract --locked
cargo test -p ferrum2-dns --locked
cargo test -p ferrum2-client dns_proxy_selector_snapshot_and_no_fallback --locked
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo fmt --all -- --check
git diff --check
```

## T02 core owned-snapshot evidence

- Extend `crates/ferrum2-core/tests/selector_contract.rs` and the existing core unit module。Do not create
  another route fixture or selector implementation。
- A table covers static、routed first-match、final、direct、2-hop chain and nested selector actions through
  both borrowed and owned interfaces。Hops and selection grain are exact。
- Hold an owned snapshot，switch its selector and prove its hops/pointer stay fixed while a later snapshot
  observes the new plan。Repeated selection/clone of the same plan retains the hop-slice allocation。
- Assert `Clone/Eq/Hash` key behavior、empty-plan impossibility and exact
  `EgressPlanSnapshot([redacted])` debug with sentinel outbound identities absent。
- Mutation cases kill hop copying、reversal/truncation、borrowed API drift、final-plan drift and a snapshot
  that re-reads selector state。

```powershell
cargo test -p ferrum2-core --test selector_contract --locked
cargo test -p ferrum2-core --locked
cargo clippy -p ferrum2-core --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## T03 DNS runtime-model and dependency evidence

- Extend the existing config contract rows only to prove client/server pure conversion of already
  validated UDP/TCP/DoT/DoH direct/detoured values。Schema/error/redaction cohorts remain byte-for-byte
  equivalent and no conversion performs side effects。
- Reuse `tagged_upstreams.rs` for selected plan identity、four transports、TC same-plan/no fallback and
  `resource_lifecycle.rs` for owner shutdown。Replace `PlanSnapshot` use with core snapshots in place；do
  not layer a compatibility wrapper in DNS。
- Extend `architecture.rs`'s existing Cargo metadata map so `ferrum2-dns` permits only
  `ferrum2-core` as a normal workspace-internal edge and config permits no DNS edge。Assert the DNS public
  module no longer exports `PlanSnapshot` or imports config DTOs。
- Client/server composition tables use the same validated cases。Direct and detoured server order、TLS
  identity/path、no retry/cache、selector snapshot and error mapping remain exact。

```powershell
cargo test -p ferrum2-config --test config_contract --locked
cargo test -p ferrum2-dns --test tagged_upstreams --locked -- --nocapture
cargo test -p ferrum2-dns --test resource_lifecycle --locked -- --nocapture
cargo test -p ferrum2-dns --locked
cargo test -p ferrum2-client dns_proxy_first_match_direct_and_detoured_transports --locked
cargo test -p ferrum2-server tagged_dns_selection_uses_authenticated_original_context_and_final --locked
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo clippy -p ferrum2-config -p ferrum2-dns -p ferrum2-client -p ferrum2-server --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## T04 shared client TCP egress evidence

- Move the existing chain tests with the TCP module and drive them through `ClientEgressEngine`，not the
  old `open_chain_with_deadlines` helper。Reuse current scripted connector/clock/random/flow observers。
- Direct、2-hop mixed-method/distinct-PSK、selector snapshot and first/later-hop failure cases prove exact
  open order、target nesting、deadlines、half-close、cancellation and zero owners with no retry/fallback。
- Extend the existing DNS selector/transport table so a DNS TCP/DoT/DoH detour and SOCKS CONNECT call the
  same engine interface。A mutation that leaves the DNS adapter on an old helper must fail。
- Source guards reject `RouteTable`/selector/SOCKS ownership in the engine and reject `ClientContext`、
  `ClientRouting` or chain-helper imports in the DNS adapter。

```powershell
cargo test -p ferrum2-client tcp_chain_opens_hops_in_order_with_distinct_credentials_and_no_fallback --locked
cargo test -p ferrum2-client tcp_chain_failure_and_cancellation_drop_every_layer --locked
cargo test -p ferrum2-client dns_proxy_selector_snapshot_and_no_fallback --locked
cargo test -p ferrum2-client dns_proxy_first_match_direct_and_detoured_transports --locked
cargo test -p ferrum2-client --locked
cargo clippy -p ferrum2-client --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## T05 shared bounded UDP egress evidence

- Move existing UDP prepare/activate/reserve/encode/accept/commit tests behind the association interface。
  Reuse the current manager、live-ID registry、socket fixtures and packet observers；do not add a second
  fake data plane。
- Existing static/routed/selector and `2..=8` nested chain tables prove selection grain、all-layer
  authentication-before-mutation、cross-plan binding、invalid-inner atomicity、capacity and shutdown。
- Extend the existing DNS UDP pool regression as one table：same first server + equal snapshot reuses；
  different hop/order、selector switch、I/O/auth failure、cancel、partial operation and saturation discard。
  A following valid query succeeds and all owners/rebinds return exact。
- UDP TC retains the same server/address/snapshot。Public UDP disabled/internal DNS enabled remains exact。
  Source guards reject direct imports of association/codec helpers from the DNS adapter。

```powershell
cargo test -p ferrum2-client udp_chain_selector_snapshots_and_cross_plan_binding --locked
cargo test -p ferrum2-client udp_chain_invalid_inner_state_and_shutdown_are_atomic --locked
cargo test -p ferrum2-client dns_proxy_detoured_udp_with_public_associate_off --locked
cargo test -p ferrum2-client dns_proxy_detour_saturation_shutdown_and_exact_rebind --locked
cargo test -p ferrum2-client dns_proxy_first_match_direct_and_detoured_transports --locked
cargo test -p ferrum2-dns --test tagged_upstreams truncation_and_invalid_wire_inputs_never_change_plan_or_transport --locked
cargo test -p ferrum2-client -p ferrum2-dns --locked
cargo clippy -p ferrum2-client -p ferrum2-dns --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## T06 ownership split and architecture evidence

- Move tests with core/config/client/server ownership，preserving test names where practical。Existing
  `config_contract`、client/server package tests and architecture harness are the interface evidence；no
  new process harness or helper tree is permitted。
- Extend architecture guards to require the approved deep-module dependency map，public core/config paths，
  absence of duplicate plan/DNS/SIP022 implementations and the client DNS import restrictions。
- Assert composition `run.rs` files contain only root/context/supervisor/report wiring and no TCP chain
  loop、UDP encode/accept/commit path、`DnsEgress` implementation or DNS wire code。Do not use exact line
  counts as a correctness gate。
- Server UDP capability/reserve/commit ordering，config error ordering/zero-side-effect behavior and all
  client/server lifecycle tests remain green after source movement。
- Inspect Cargo metadata/lock to prove no member、normal dependency、provider or feature identity changed。

```powershell
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo test -p ferrum2-config --test config_contract --locked
cargo test -p ferrum2-core -p ferrum2-dns -p ferrum2-client -p ferrum2-server --locked
cargo test -p ferrum2-m0-harness --test local_e2e tagged_dns_tcp_resolution_uses_detour_and_reaps --locked -- --exact --nocapture
cargo test -p ferrum2-m0-harness --test udp_local_e2e tagged_dns_udp_resolution_uses_detour_and_reaps --locked -- --exact --nocapture
cargo clippy -p ferrum2-core -p ferrum2-config -p ferrum2-dns -p ferrum2-client -p ferrum2-server --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## T07 exact qualification evidence

- Re-run every T01～T06 focused command on the accepted integration SHA；ticket-branch results do not
  substitute for integration evidence。
- Run repository Full serially，Rust 1.88 check/build/test and the ignored 100+ lifecycle case。Existing
  SIP022 TCP/UDP `12/12` each plus cleanup and all CoreDNS/BIND DNS cases remain independent gates。
- Architect reviews module depth、interface size、dependency direction and absence of layered compatibility
  wrappers；QA reviews every compatibility、negative、resource、shutdown and exact-rebind claim。Blocking
  findings must be zero after at most one full review and one targeted re-review。
- Performance is required。After separate authorization，the existing manual job runs legacy M4 plus M12
  DNS direct/detoured resource profiles on the same exact SHA。No new workload、threshold or claim is
  implied unless a real regression requires a separately approved repair。

## Test-footprint forecast

Schema 3 resets at exact planning baseline `4810ec5c5a1063cb8e60d1b950900c7f38d74548` with code/tests
`18940/39748`、ratio `2.098627` and case/support/fixture `33999/5152/597`。

| Slice | Case LOC | Support LOC | Fixture LOC |
|---|---:|---:|---:|
| T01 contract/control | 0 | 0 | 0 |
| T02 owned snapshot | 80 | 0 | 0 |
| T03 DNS model/dependency | 110 | 0 | 0 |
| T04 TCP engine | 80 | 0 | 0 |
| T05 UDP association/reuse | 140 | 0 | 0 |
| T06 architecture guards | 140 | 0 | 0 |
| T07 qualification | 0 | 0 | 0 |
| **Total** | **550** | **0** | **0** |

Net growth forecasts milestone `WARN` (`>240` and `<=600`) while the existing ratio remains `WARN`。
Moving existing inline tests into new owner files may independently report file-size
`REVIEW_REQUIRED` because a new file's semantic test LOC is compared with zero；that expected signal must
be dispositioned as reviewed movement plus distinct guards，not hidden by leaving tests in `run.rs` or
deleting evidence。No third helper、Rust fixture、second harness or copied data plane is forecast。

## Serial integration gate

Run exactly on one accepted integration SHA：

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo build --workspace --bins --locked
cargo test --workspace --all-features --locked
cargo +1.88.0 check --workspace --all-targets --locked
cargo +1.88.0 build --workspace --bins --locked
cargo +1.88.0 test --workspace --locked
cargo test -p ferrum2-m0-harness --test lifecycle_cycles full_qualification_runs_twenty_cycles_per_category_and_at_least_100_per_binary --locked -- --ignored --exact --nocapture
cargo doc --workspace --all-features --no-deps --locked
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh milestone --candidate <accepted-integration-sha>
git diff --check
```

After separate explicit authorizations，one non-force push of that exact SHA must pass automatic quality、
test-footprint、Rust 1.88、Windows MSVC、Linux GNU/musl、SIP022 interop、CoreDNS/BIND and aggregate
qualification。One separately authorized manual dispatch must pass the existing performance/resource
job。No rerun、second push、PR、tag、release or publication is implied。

## Stop rules

- Any schema/error/wire/selection/fallback/resource/lifecycle/telemetry drift，plan copy，wrong reuse key，
  DNS/config reverse edge，client DNS helper reach-through，detached owner or failed exact rebind blocks。
- A new crate/dependency/unsafe/fixture/harness/data plane/registry or product behavior is scope expansion
  and needs a new approved contract。
- Numeric footprint findings do not waive correctness；integrity failure、blocking review、missing remote
  authorization or wrong exact SHA/run/attempt is blocking。
