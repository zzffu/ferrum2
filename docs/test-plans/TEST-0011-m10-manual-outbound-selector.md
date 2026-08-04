# TEST-0011 — M10 manual outbound selector evidence

- **Status:** Approved
- **Milestone:** M10
- **Spec:** `docs/specs/SPEC-0011-m10-manual-outbound-selector.md`

## Evidence map

| Requirement | Primary evidence | Gate |
|---|---|---|
| M10-MUST-01 compatible shape | preserved legacy/static/routed values plus selector/tagged/legacy exclusivity through public loaders and CLI | T01 config |
| M10-MUST-02 bounded DAG | table for counts、members、defaults、unknowns、duplicates、reachability and latent cycles | T01 config/core |
| M10-MUST-03 public control | external integration test for public construction、default/current query、nested query、switch and exact redacted no-mutation errors | T01 public interface |
| M10-MUST-04 concurrency | std-thread readers/writers observe only complete members and a deterministic post-join switch | T01 public interface |
| M10-MUST-05 actions/snapshots | static/routed selector action table plus existing TCP/UDP call-site tests | T01/T02 product |
| M10-MUST-06 both roles | client Shadowsocks and server direct selector identity tests across TCP/UDP | T02 product |
| M10-MUST-07 preservation | existing auth/replay/owner/source/lifecycle/observability suites and architecture inspection | T02/T03 security/runtime |
| M10-MUST-08 qualification | Full、MSRV、100+ lifecycle、three targets、TCP/UDP `24/24`、footprint and exact reviews | T03 release |

## T01 core, config and public-interface evidence

- Add exactly one Rust integration-test file under `crates/ferrum2-core/tests/`。It imports only public
  selector/control types and uses only `std::thread`、`Arc` and `Barrier`；no dev dependency、private
  state、sleep or probabilistic “both values observed” assertion。
- One table proves public construction、explicit defaults、immediate nested query versus concrete
  resolution、valid switch and already-current no-op。Its error rows distinguish unknown and
  concrete-as-selector、unknown/case-mismatched/non-member/descendant-only member，assert no mutation，
  and verify tag/member/index sentinels are absent from both `Display` and `Debug`。Outer/inner changes
  remain independent except during recursive resolution。A selector-valued final row proves live
  `select()` changes while concrete `final_outbound()` stays on the configured-default leaf。
- One bounded concurrency table starts readers/writers together。Every query/resolution is a configured
  complete member/leaf；writer winner is unspecified。After join，one deterministic switch/query proves
  final visibility。
- Extend existing `config_contract.rs` helpers/tables，not a new helper。Both roles cover static binding、
  route rule/final、shared/nested selectors、concrete reachable only through a selector and selector
  state shared by multiple action roots。The client final-selector row also proves public `server` is the
  configured-default compatibility snapshot before and after switching through the public accessor。
- Negative rows cover zero/65 selectors、zero/65 members、duplicate/global-collision tags、duplicate/
  dangling/inbound-as-member、missing/dangling/non-member default、unreachable nodes and self/two-node/
  longer latent cycles。Each asserts exact field/kind and redacts tag/member/default/endpoint/PSK sentinels。
- `--check-config` adds one positive and one cycle-negative row to the existing CLI table，with no new
  process helper。Normal no-selector run remains exact；selector config must never be accepted inertly。

```powershell
cargo test -p ferrum2-core --test selector_contract --locked
cargo test -p ferrum2-config --test config_contract --locked
cargo test -p ferrum2-m0-harness --test config_cli --locked
cargo clippy -p ferrum2-core -p ferrum2-config -p ferrum2-m0-harness --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## T02 data-plane selection evidence

- Extend，do not copy，the existing client `routed_tcp_selects_after_target_and_never_falls_back`
  and `routed_udp_uses_lazy_endpoint_legs_and_rejects_cross_leg_responses` tables。Switch only through
  the public control handle；an already-open TCP flow and already-selected/in-flight UDP leg/response
  remain on A，while the next existing selection call uses B。Selecting an unavailable member remains
  deterministic no-fallback。
- Extend the existing server `tagged_tcp_shares_static_direct_mapping_and_one_replay_store` and
  `tagged_udp_is_process_bounded_and_bound_to_its_local_inbound` tables with instrumented direct
  identities。Authenticated work captures current concrete identity before open/reserve/commit；a later
  request observes a switch without mutating rejected replay/session/queue state。
- Static client UDP additionally proves its already-prepared association keeps its setup snapshot；a
  new association observes the new current member。Routed client/server UDP retain their existing
  per-datagram selection granularity and response binding。
- Shared/nested selectors referenced by multiple inbounds/rules prove one process-local current state，
  no eager endpoint leg/socket/buffer/ID per selector，and no binary tag lookup。
- Existing auth/order/source pin、cross-inbound binding、replay、aggregate admission/session/bytes/IDs、
  idle/cancel/fatal/forced/rebind and observability tests remain unchanged regression evidence。

```powershell
cargo test -p ferrum2-client run::tests::routed_tcp_selects_after_target_and_never_falls_back --locked -- --exact
cargo test -p ferrum2-client run::tests::routed_udp_uses_lazy_endpoint_legs_and_rejects_cross_leg_responses --locked -- --exact
cargo test -p ferrum2-server run::tests::tagged_tcp_shares_static_direct_mapping_and_one_replay_store --locked -- --exact
cargo test -p ferrum2-server run::tests::tagged_udp_is_process_bounded_and_bound_to_its_local_inbound --locked -- --exact
cargo test -p ferrum2-client -p ferrum2-server --locked
cargo clippy -p ferrum2-client -p ferrum2-server --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## T03 qualification evidence

- Do not add a process-switch harness：M10 deliberately has no child-process control channel。Reuse the
  existing real-process tagged/routed TCP and one-association UDP regressions to prove default startup、
  protocol behavior、no-fallback、response source binding、100+ cycles and exact rebind。
- The unchanged architecture test remains regression evidence；exact-SHA Architect inspection，not a new
  selector-specific test amendment，proves one runtime-neutral core selector module，no duplicate
  selector logic in protocols/runtime，no new trait/dependency/control transport and no selector/tag
  telemetry。
- Existing external case IDs、versions、payloads、deadlines and cleanup remain unchanged：TCP
  `M1-INT-001..012` and UDP `M2-UDP-INT-001..012` each require `12/12` on one exact SHA。
- Existing Windows/GNU/musl jobs compile the atomic selector path and run the preserved artifact profile；
  no new provider、job or platform-specific selector hook is added。

```powershell
cargo build --workspace --bins --locked
cargo test -p ferrum2-m0-harness --test local_e2e tagged_two_by_two_tcp_matrix_covers_all_methods_and_exact_rebind --locked -- --exact --nocapture
cargo test -p ferrum2-m0-harness --test socks_udp_local_e2e one_association_alternates_two_targets_and_preserves_response_sources --locked -- --exact --nocapture
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo +1.85.0 check --workspace --all-targets --locked
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## Test-footprint forecast

Schema 3 exact base is `99bd62e9673f8743a0ea6597962fbfc22b3e3ce7` at code/tests
`15996/26916`，ratio `1.682671`。Forecast：

| Slice | Case LOC | Support LOC | Fixture LOC |
|---|---:|---:|---:|
| T01 public selector contract | 70 | 0 | 0 |
| T01 config/CLI tables | 85 | 0 | 0 |
| T02 client TCP/UDP additions | 45 | 0 | 0 |
| T02 server TCP/UDP additions | 30 | 0 | 0 |
| T03 reused tests plus review-only architecture evidence | 0 | 0 | 0 |
| **Total** | **230** | **0** | **0** |

The total stays below the default `>240` change-set warning。Growing `config_contract.rs` from
`871` semantic test LOC is expected file `WARN`；growing client/server `run.rs` from `3390/1777`
is expected file `REVIEW_REQUIRED`。Architect/QA must disposition those signals；do not split or delete
independent evidence merely to improve LOC。No third helper、fixture or new harness is planned。

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
`12/12`+cleanup、UDP `12/12`+cleanup、footprint and final qualification。Performance may run as
regression but M10 adds no threshold/claim。

## Stop rules

- Any preserved-config incompatibility、accepted inert/unresolved selector、invalid default、latent
  cycle、torn/invalid concurrent result、private test mutation、post-snapshot reroute、fallback/retry、
  multiplied eager owner、source/replay crossover、tag telemetry、Full/MSRV/platform/interop/footprint
  integrity or blocking-review failure blocks M10。
- External control、persistence、auto selection/health/retry/load balancing、dynamic membership、CAS/
  graph transaction、new adapter/trait/dependency is scope expansion and needs a new approved contract。
- Provider unavailable、skipped row、wrong SHA/run/attempt or absent remote authorization is not PASS。
  One full Architect/QA review and one targeted re-review are the default bound。
