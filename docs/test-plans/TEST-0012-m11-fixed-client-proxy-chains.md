# TEST-0012 — M11 fixed client proxy chain evidence

- **Status:** Approved
- **Milestone:** M11
- **Spec:** `docs/specs/SPEC-0012-m11-fixed-client-proxy-chains.md`

## Evidence map

| Requirement | Primary evidence | Gate |
|---|---|---|
| M11-MUST-01 credentials/compatibility | public loader tables for global inheritance、complete override、partial/width/canonical negatives and preserved cohort | T01 config |
| M11-MUST-02 bounded chains | chain count/tag/hop/reference/reachability matrix through loader and CLI | T01 config/core |
| M11-MUST-03 immutable plan | public route/selector table plus client selection snapshot tests | T01/T02/T03 |
| M11-MUST-04 TCP order | mixed-method nested-flow test with ordered connector/wire witnesses and per-layer failures | T02 TCP |
| M11-MUST-05 UDP order/binding | mixed-method nested packet table covering wrap/open order、intermediate target and cross-plan responses | T03 UDP |
| M11-MUST-06 UDP bounds/mutation | exact nested maximum/+1 and invalid-inner-then-valid replay/association evidence | T03 UDP |
| M11-MUST-07 cleanup | focused owner cancellation plus real-process success/failure/rebind cycles | T02/T03/T04 lifecycle |
| M11-MUST-08 redaction | distinct global/hop PSK sentinels across config errors、runtime errors、stderr、trace and metrics | T01/T04 security |
| M11-MUST-09 seams/non-goals | existing architecture/dependency tests plus exact-SHA Architect inspection | T02/T03/T05 architecture |
| M11-MUST-10 qualification | Full、MSRV、100+ lifecycle、three platforms、TCP/UDP `24/24`、footprint、reviews and manual performance | T05 release |

## T01 config and immutable-plan evidence

- Extend the existing `config_contract.rs` table/helper rather than adding a parser harness。Positive
  rows cover all-global legacy、tagged inheritance、one inherited plus one explicit outbound、all three
  methods across global/override positions and Debug redaction。Negative rows cover either half of the
  credential pair、unsupported method、bad/canonical base64 and every key-width mismatch using distinct
  global/outbound sentinels。
- Chain rows cover absent、one、64 and rejected empty/65 collections；2/8 and rejected 0/1/9 hops；
  ordered distinct concrete refs；duplicate、unknown、case mismatch and inbound/selector/chain-as-hop；
  global tag collisions；and direct/chain/selector reachability through static、rule and final roots。
  Server and legacy client reject `chains`/per-outbound credentials rather than accepting inert state。
- Extend `selector_contract.rs` through its public compile/route/control interfaces。Direct selection
  remains one hop；static/rule/final may choose an ordered plan；a selector switch chooses a whole plan，
  while the previously returned plan remains unchanged。No private index、tag lookup or mutation hook is
  used。
- `config_cli.rs` adds one valid mixed-credential chain and one partial-credential/invalid-hop table row。
  Both client `--check-config` cases finish before process resources；normal startup must not accept a
  chain and then silently run one hop。

```powershell
cargo test -p ferrum2-core --test selector_contract --locked
cargo test -p ferrum2-config --test config_contract --locked
cargo test -p ferrum2-m0-harness --test config_cli --locked
cargo clippy -p ferrum2-core -p ferrum2-config -p ferrum2-m0-harness --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## T02 TCP chain evidence

- Extend the existing `tcp_flow_contract`/client composition test seams；do not copy an encoder or start
  a second protocol implementation。One table uses at least the rotations AES-128→AES-256、AES-256→
  ChaCha20 and ChaCha20→AES-128 with distinct synthetic PSKs。Recording transport witnesses prove one
  raw A dial and request targets B then application，and kill swapped order、skipped hop or wrong key
  provider mutations。
- Outer and inner request/response tamper、hop-1 wrong PSK、hop-2 wrong PSK、unavailable first hop and
  terminal later hop each prove zero retry/fallback and no application payload before the failing layer
  is accepted。A valid request after each isolated negative proves no global state poisoning。
- A selector switches from one direct/chain member after the first plan snapshot。The open nested flow
  stays on its captured hops；the next connection uses the new complete plan。Failure never mutates the
  public selector current member。
- Cancellation/timeout/short-write/half-close tests inspect the complete recursive owner and fixed
  per-layer buffers。All nested layers terminate under the existing connection owner；no task、socket or
  key provider survives failure。

```powershell
cargo test -p ferrum2-shadowsocks --test tcp_flow_contract --locked
cargo test -p ferrum2-client run::tests::tcp_chain_opens_hops_in_order_with_distinct_credentials_and_no_fallback --locked -- --exact
cargo test -p ferrum2-client run::tests::tcp_chain_failure_and_cancellation_drop_every_layer --locked -- --exact
cargo test -p ferrum2-shadowsocks -p ferrum2-client --locked
cargo clippy -p ferrum2-shadowsocks -p ferrum2-client --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## T03 UDP chain evidence

- Extend `udp_packets.rs` and the existing client UDP composition tables。For each mixed-method rotation，
  decode with server-side existing protocol owners to prove innermost final target/payload，each outer
  next-hop target and matching credential。Open the response in the inverse order and assert the final
  SOCKS target/source。
- A table flips one authenticated/header/body byte at each layer，uses a wrong PSK at each layer，replays
  outer and inner packets，injects the wrong intermediate target and crosses two plans sharing a first-hop
  endpoint。Every row fails closed without another send candidate or application output。
- Exact nested request limits are calculated for IPv4、domain and IPv6 final targets and mixed methods。
  Exact maximum succeeds；maximum+1 and eight-hop accumulated overhead fail before reservation/session/
  counter mutation。The evidence observes fixed-capacity reuse and rejects a per-hop maximum buffer。
- For a fully authenticated outer response with an invalid inner layer，all pending accepted mutations
  remain uncommitted；the corresponding valid response is then accepted once and its replay is rejected。
  Static association and routed per-datagram selector snapshots remain exact。
- Idle、control close、I/O failure and forced cancellation drop all per-plan/per-hop sessions、live IDs、
  sockets/buffers/tasks under the existing association owner and aggregate limits。

```powershell
cargo test -p ferrum2-shadowsocks --test udp_packets --locked
cargo test -p ferrum2-client run::tests::udp_chain_layers_mixed_credentials_bounds_and_response_binding --locked -- --exact
cargo test -p ferrum2-client run::tests::udp_chain_invalid_inner_state_and_shutdown_are_atomic --locked -- --exact
cargo test -p ferrum2-shadowsocks -p ferrum2-client --locked
cargo clippy -p ferrum2-shadowsocks -p ferrum2-client --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## T04 real-process acceptance evidence

- Extend `local_support` with one chain-aware config spelling built from existing process/config helpers；
  do not add a second child-process harness、SIP022 encoder or dependency。Each test owns one client、two
  existing ferrum2 server processes and one echo target。
- Table-drive three two-hop method rotations with distinct PSKs。Across the rows，static binding、route
  rule/final and selector-default each select the chain；one hop inherits global credentials and one uses
  an explicit pair。TCP sends a multi-frame payload and half-closes；UDP sends at least three datagrams and
  checks final response source/payload。
- Focused failure rows use existing recording/tamper seams to prove unavailable/wrong-credential later
  hop never reaches the application target and never reroutes。Distinct global/hop PSK sentinels are
  absent from both child stderr and metrics。
- Repeat bounded success plus hop-1/later-hop failure for TCP and UDP，then terminate/reap all children、
  observe zero client owners and exact TCP/UDP listener rebind。Existing 100+ global lifecycle remains
  independent qualification evidence。

```powershell
cargo build --workspace --bins --locked
cargo test -p ferrum2-m0-harness --test local_e2e fixed_two_hop_tcp_chain_uses_distinct_credentials_and_reaps --locked -- --exact --nocapture
cargo test -p ferrum2-m0-harness --test socks_udp_local_e2e fixed_two_hop_udp_chain_uses_distinct_credentials_and_reaps --locked -- --exact --nocapture
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo +1.85.0 check --workspace --all-targets --locked
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
```

## T05 qualification evidence

- Re-run the T01 public config/plan commands、the four T02/T03 exact composition commands and both T04
  process tests on the accepted integration SHA。The unchanged security/protocol suites remain required；
  no local result substitutes for an unrun exact-SHA gate。
- Existing external case IDs and providers stay exact：TCP `M1-INT-001..012` and UDP
  `M2-UDP-INT-001..012` each require `12/12` plus cleanup。They prove each unchanged hop wire/state
  machine；the new real-process rows prove ferrum2's multi-hop composition。
- Existing Windows/GNU/musl jobs compile the path-aware owner and run their current artifact profile。
  Exact-SHA Architect inspection proves core has only runtime-neutral plan selection、protocol code owns
  no routing policy，and no duplicate crypto/state machine、dependency or per-hop telemetry was added。
- Performance is required。After separate explicit remote authorization，dispatch `.github/workflows/
  m0.yml` for the accepted exact SHA and require the independent `performance` job's THP apply/restore、
  fixed load、10k/resource samples、drain and cleanup to pass。The result is regression/resource evidence
  only；M11 defines no throughput ratio threshold。

## Test-footprint forecast

Schema 3 resets at exact baseline `7a3c876681255b88492b3608af4fa52497435efc` with code/tests
`16646/27342`、ratio `1.642557` and case/support/fixture `22795/3950/597`。Forecast：

| Slice | Case LOC | Support LOC | Fixture LOC |
|---|---:|---:|---:|
| T01 config、CLI and public plan tables | 190 | 0 | 0 |
| T02 TCP nesting、failure and cleanup | 125 | 0 | 0 |
| T03 UDP layering、bounds and atomicity | 175 | 0 | 0 |
| T04 real-process mixed credentials and rebind | 150 | 80 | 0 |
| T05 reused qualification/review evidence | 0 | 0 | 0 |
| **Total** | **640** | **80** | **0** |

The honest milestone forecast exceeds the default `>600` change-set signal and therefore expects a
numeric `REVIEW_REQUIRED` disposition；it is not a correctness waiver or stop condition。Each ticket
stays at or below `240` expected test growth。Growing `config_contract.rs` (`979` test LOC)、
`local_support/mod.rs` (`920`) and `socks_udp_local_e2e.rs` (`825`) expects file `WARN`；growing client
`run.rs` (`3527`) expects file `REVIEW_REQUIRED`。Architect/QA must confirm each row proves a distinct
config、TCP、UDP or real-process failure mode。No fixture、new harness or third equivalent helper is
planned。

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

After separate explicit authorization，one non-force push of the exact accepted SHA must pass automatic
quality、test-footprint、Rust 1.85、Windows MSVC、Linux GNU/musl、TCP/UDP `12/12` each plus cleanup
and final qualification。A second explicit authorization is required for the exact-SHA manual
performance dispatch。No run/attempt/SHA splicing、rerun、second push、PR、tag、release or publication is
implied。

## Stop rules

- Any preserved-config drift、partial credential acceptance、inert/unresolved chain、hop reorder、wrong
  credential owner、one-hop truncation、post-snapshot plan change、retry/fallback、cross-plan response、
  invalid-inner partial commit、wire overflow、unbounded/eager owner、secret/tag telemetry or cleanup
  leak blocks M11。
- A new cipher/KDF/state machine、protocol-core replacement、per-hop detached relay task、new crate/
  dependency、dynamic chain、server credential selection or automatic upstream policy is scope expansion
  and needs a new approved contract。
- Footprint numeric `WARN`/`REVIEW_REQUIRED` requires recorded disposition but is not itself a correctness
  failure。Integrity failure、blocking review、provider unavailable、skipped evidence、wrong SHA/run/
  attempt or absent remote authorization is blocking。One full review and one targeted re-review are the
  default bound。
