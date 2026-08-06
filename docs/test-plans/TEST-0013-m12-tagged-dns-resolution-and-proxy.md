# TEST-0013 — M12 tagged DNS evidence

- **Status:** Approved
- **Milestone:** M12
- **Spec:** `docs/specs/SPEC-0013-m12-tagged-dns-resolution-and-proxy.md`

## Evidence map

| Requirement | Primary evidence | Gate |
|---|---|---|
| M12-MUST-01 dependency/MSRV | exact metadata/tree/features、workspace policy、Rust 1.88 Full check | T01 dependency |
| M12-MUST-02 additive config | client/server loader tables、detour action roots and preserved schema cohort | T02 config |
| M12-MUST-03 transport/bootstrap | server-shape matrix、direct/detoured numeric target、loop/TLS negatives | T02/T03 |
| M12-MUST-04 shared matcher/action | outbound regression、DNS first-match and no-bootstrap-reroute mutation tables | T02 core |
| M12-MUST-05 client proxy | real UDP/TCP proxy over direct and Shadowsocks-detoured Hickory transports | T04 proxy |
| M12-MUST-06 server resolver | authenticated TCP/UDP resolution through explicit server-direct detour | T05 server |
| M12-MUST-07 failure semantics | four-transport table、detour snapshots、TC same-plan upgrade and no fallback | T03/T04 |
| M12-MUST-08 bounds | timeout、DNS+egress saturation、4,096/65,535 boundaries and resource counters | T03/T04 |
| M12-MUST-09 lifecycle | tracked Hickory/detour tasks、rollback、forced cleanup and exact rebind | T03～T05 |
| M12-MUST-10 loop/privacy | direct/detour graph loops、deadline containment and sentinel leak sweep | T02/T04/T05 |
| M12-MUST-11 interop | CoreDNS four transports direct/detoured、BIND dig UDP/TCP client | T05 interop |
| M12-MUST-12 qualification | focused reruns、Full/MSRV/lifecycle/platform/SIP022+DNS interop/footprint/reviews/performance | T06 release |

## T01 dependency and MSRV evidence

- Pin exact Hickory 0.26.1 workspace dependencies with ADR-0031 features and add the smallest compiling
  `ferrum2-dns` crate. Extend the existing workspace-policy table rather than adding a dependency
  scanner.
- Assert root and all metadata package `rust_version` values are 1.88.0，the GitHub MSRV job invokes
  only `+1.88.0` and the selected build toolchain remains 1.97.1.
- Inspect normal and all-feature trees. Exactly one Hickory 0.26.1 family is allowed；`system-config`、
  DNSSEC、recursor、DoQ/DoH3、AWS-LC and duplicate TLS/provider edges are forbidden.
- Record resolved license/provenance and confirm the lockfile contains no Git source、unreviewed patch or
  second DNS implementation. The 0.26.1 package release must remain reachable from its official release
  and crates metadata.

~~~powershell
cargo +1.88.0 metadata --format-version 1 --locked
cargo +1.88.0 check --workspace --all-targets --locked
cargo tree -p ferrum2-dns -e features --locked
cargo tree -p ferrum2-dns --all-features -e features --locked
cargo test -p ferrum2-m0-harness --test workspace_policy --locked
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
~~~

## T02 configuration and shared-rule evidence

- Extend `config_contract.rs` with one table，not a second TOML harness. Preserve the full legacy/M7/M8/
  M10/M11 client/server cohort when DNS is absent. Positive client rows cover 1/64 inbounds and
  servers、all four transports、IPv4/IPv6 bootstrap、DoH default/custom path and first/final actions.
  Positive rows also cover absent-direct detour，client concrete/chain/selector detours and server
  direct-outbound detours. A detour-only outbound/chain/selector is reachable. Server rows omit DNS
  inbounds and select servers from authenticated inbound contexts.
- Negative rows isolate absent/0/65 counts、duplicate/global collisions、unknown/unreachable server、
  role-inert shape、timeout/inflight bounds、transport spelling、numeric address/zero port、TLS field
  pairing、DoH path length/form、legacy/unknown/inbound/DNS/wrong-role detour、direct/wildcard loop and
  concrete-hop/listener collision. Each row asserts the one closed redacted field and zero side effects.
- Refactor the existing core route tests before adding DNS rows. The same public matcher table must
  prove inbound/network/target wildcards、ASCII case folding、IP/port/terminal-dot exactness、conditionless
  shadowing and first/final selection for two action types.
- Compile detour references as additional roots of the existing outbound/chain/selector graph and expose
  one resolved plan handle，not another graph. Mutation rows kill copied/reversed matching、bootstrap
  ordinary-route selection、DNS `outbound` acceptance、ordinary `server` acceptance and selected-error/
  detour fallback. Existing selector/plan snapshots remain exact.

~~~powershell
cargo test -p ferrum2-core --test selector_contract --locked
cargo test -p ferrum2-config --test config_contract --locked
cargo test -p ferrum2-m0-harness --test config_cli --locked
cargo clippy -p ferrum2-core -p ferrum2-config -p ferrum2-m0-harness --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
~~~

## T03 tagged Hickory transport and owner evidence

- Build one deterministic synthetic upstream fixture behind Hickory public interfaces. A table selects
  one tagged UDP、TCP、DoT or DoH server and proves A、AAAA、CNAME chain、NXDOMAIN and NODATA. Distinct
  records per tag prove exact action identity.
- Exercise the same resolver through direct and scripted-detour Hickory `RuntimeProvider` adapters.
  TCP creation returns a bounded owned stream；UDP creation returns a bounded socket adapter. Both
  expose the supplied numeric target and plan identity without copying DNS framing or transport logic.
- UDP TC triggers one TCP request to the same address/tag under the same deadline. Timeout、I/O、wrong
  source/ID、malformed response、TCP half-frame、DoT trust/name/time error and DoH path/status/content
  type/body error each prove no second tag、detour/member、downgrade or retry. TC retains the original
  detour-plan snapshot.
- Use an ephemeral CA only in test construction. Production constructors must contain WebPKI roots and
  expose no insecure/custom-root config. Test certificates and private keys are synthetic fixtures and
  excluded from logs and release assets.
- Set Hickory retry/cache to zero and inspect the effective options. Saturate the shared
  `max_inflight` boundary，hold slow direct/detoured UDP/TCP/TLS/HTTP operations and prove stable DNS plus
  egress task/socket/session/queue/buffer ceilings、one absolute deadline and a following valid query.
- Exercise the ferrum2-owned Hickory runtime task set: lazy connection creation、normal completion、
  detour bridge/session creation、resolver drop、forced abort and shutdown all join to zero. No detached
  Tokio task remains after direct、first-hop and final endpoint rebind.

~~~powershell
cargo test -p ferrum2-dns --test tagged_upstreams --locked -- --nocapture
cargo test -p ferrum2-dns --test resource_lifecycle --locked -- --nocapture
cargo test -p ferrum2-dns --locked
cargo clippy -p ferrum2-dns --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
~~~

## T04 client DNS proxy evidence

- Extend client composition with one DNS process-root constructor and keep parsing/framing in Hickory.
  A focused in-process table sends real UDP datagrams and TCP frames to one bound listener and proves
  DNS inbound、network、absolute-name:53 selection plus final action.
- Give rule-selected and final DNS servers different direct/concrete/chain/selector detours and synthetic
  answers. Across the table，UDP、TCP、DoT and DoH reach the numeric CoreDNS endpoint through the expected
  existing egress plan. The DNS bootstrap target never enters ordinary outbound routing.
- Detoured UDP reuses the existing SIP022 UDP codec/session owners. With public `[udp]` disabled，the
  internal DNS query succeeds while SOCKS5 `UDP ASSOCIATE` remains rejected；enabling public UDP does not
  create a second manager or multiply its configured limits.
- Positive rows cover A/AAAA/CNAME/NXDOMAIN/NODATA、case-equivalent names、terminal-dot distinction、
  EDNS size and UDP response truncation followed by client TCP retry. A single TCP connection handles
  several complete queries and clean EOF.
- Negative rows cover malformed/no-ID UDP drop、zero/multiple questions、non-QUERY、non-IN、65,535 exact
  TCP frame、zero/partial frame、idle、busy、upstream timeout and selected failure. Exact response codes
  and zero unauthorized upstream requests are asserted.
- Switch a detour selector during slow work. UDP logical queries and new TCP-family connections take the
  later snapshot，while an already opened TCP/DoT/DoH flow retains its concrete plan；UDP TC retains its
  original plan. No switch interrupts a query or causes member fallback.
- Run global in-flight、aggregate DNS-TCP-connection and existing outbound/session saturation across two
  DNS inbounds. Observe fixed permits/queues/buffers/tasks，then drain、terminate the client and rebind
  DNS listeners、Shadowsocks hops and DNS upstream endpoints.
- Sweep client stderr、trace and metrics using distinct qname、tag、bootstrap、TLS-name and path
  sentinels. Only closed DNS stage/reason/transport identities may appear.

~~~powershell
cargo test -p ferrum2-dns --test proxy_contract --locked
cargo test -p ferrum2-client run::tests::dns_proxy_first_match_direct_and_detoured_transports --locked -- --exact
cargo test -p ferrum2-client run::tests::dns_proxy_detour_saturation_shutdown_and_exact_rebind --locked -- --exact
cargo test -p ferrum2-client -p ferrum2-dns --locked
cargo clippy -p ferrum2-client -p ferrum2-dns --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
~~~

## T05 server resolution and external interoperability

- Adapt existing runtime resolver seams，rather than replacing connectors. The server selects one DNS
  action from the authenticated inbound/network/original target and supplies that tagged Hickory
  resolver to TCP/UDP direct. Its optional detour resolves through the server's existing direct-outbound
  graph. Preserve system resolvers when DNS is absent and the 16-candidate/absolute-deadline contract
  when present.
- Extend `local_support` and existing process helpers. One actual client→server→target TCP case and one
  UDP case use synthetic names with distinct answers from rule-selected and final servers. Explicit DNS
  detour and application outbound tags differ，proving that lookup egress does not replace application
  routing. IP bypass、wrong answer、empty answer、timeout、candidate exhaustion and no-fallback rows prove
  no target work before an accepted result.
- Extend the existing external qualification provider/runner，not a second harness. Add CoreDNS 1.14.6
  and BIND 9.20.26 entries to `tests/interop/versions.toml` with official source commit、asset size、
  SHA-256 and license review. Provisioning or hash failure remains FAIL/BLOCK.
- CoreDNS serves one synthetic zone on separate loopback UDP/TCP/DoT/DoH endpoints. Ferrum2 queries each
  transport directly and through a real client Shadowsocks detour for positive A/AAAA and NXDOMAIN/
  NODATA，then BIND `dig` queries ferrum2 proxy via UDP and `+tcp`. The encrypted positive rows use only
  an isolated client/server build with the default-off `ferrum2-dns/__interop-test-root` feature and the
  reviewed M12 fixture root；normal/default/release artifacts remain WebPKI-only，the feature accepts no
  runtime trust input and its target directory is deleted after the run. No public DNS request is allowed.
- Repeat success、detour connect/handshake/UDP failure、TLS failure、DoH failure、direct-loop rejection
  and indirect-loop timeout，then reap all children、tracked Hickory/detour tasks and target workers.
  Exact DNS listener、Shadowsocks hop、upstream TCP+UDP rebind and sentinel absence in child stderr/
  metrics are blocking.

~~~powershell
cargo build --workspace --bins --locked
cargo build -p ferrum2-client -p ferrum2-server --features ferrum2-dns/__interop-test-root --locked
cargo test -p ferrum2-m0-harness --test local_e2e tagged_dns_tcp_resolution_uses_detour_and_reaps --locked -- --exact --nocapture
cargo test -p ferrum2-m0-harness --test udp_local_e2e tagged_dns_udp_resolution_uses_detour_and_reaps --locked -- --exact --nocapture
cargo test -p ferrum2-m0-harness --test architecture --locked
cargo +1.88.0 check --workspace --all-targets --locked
cargo +1.88.0 check -p ferrum2-dns -p ferrum2-client -p ferrum2-server --features ferrum2-dns/__interop-test-root --locked
cargo run -p ferrum2-m0-harness --bin m0-qualification --locked -- --dns-only
& 'C:\Program Files\Git\bin\bash.exe' scripts/test-budget.sh ticket --base <exact-ticket-base-sha> --candidate HEAD
git diff --check
~~~

## T06 exact qualification evidence

- Re-run all T01～T05 focused commands on the accepted integration SHA. A ticket-branch result does not
  substitute for the integrated product.
- Run repository Full serially，the ignored 100+ lifecycle test and Rust 1.88.0 check/build/test. Existing
  SIP022 TCP/UDP cases remain `12/12` each plus cleanup；DNS interop is an additional result and cannot
  replace either.
- Three release targets compile the Hickory/ring graph and exercise the existing native artifact
  profile. Architect verifies core/config/protocol/runtime/egress seams and absence of copied rule、DNS
  parser/framing or SIP022 data-plane code；QA verifies every negative/resource/cleanup claim.
- Performance is required. After separate explicit authorization，the existing manual workflow job
  records the current throughput/resource profile with DNS roots enabled but idle，then authorized
  direct and detoured DNS query-load phases record bounded tasks/RSS/drain. No ratio threshold or
  product claim is added.

## Test-footprint forecast

Schema 3 resets at exact baseline `c733e0dd03e711c045c0b7a4ee189277fbe37698` with code/tests
`16023/32456`、ratio `2.025588` and case/support/fixture `27788/4071/597`. Forecast:

| Slice | Case LOC | Support LOC | Fixture LOC |
|---|---:|---:|---:|
| T01 dependency/MSRV policy | 90 | 0 | 0 |
| T02 config、shared matcher and detour roots | 250 | 0 | 0 |
| T03 tagged transports、detour adapters and lifecycle | 300 | 60 | 0 |
| T04 client UDP/TCP proxy and real egress detours | 280 | 60 | 0 |
| T05 server detour/process/external interop | 240 | 120 | 0 |
| T06 qualification plus bounded DNS resource harness repair | 0 | 500 | 0 |
| **Total** | **1160** | **740** | **0** |

The honest milestone forecast exceeds the default `>600` change-set signal and therefore expects
numeric `REVIEW_REQUIRED`. T02～T05 (`250`、`360`、`340`、`360`) each expect ticket `WARN` but remain
below ticket review；the bounded T06 repair expects `500` support LOC and ticket `WARN`. Existing
`bins/ferrum2-client/src/run.rs` already has 7,018 semantic test LOC and
will continue to report file `REVIEW_REQUIRED` if changed；server/config/local-support files may report
`WARN`.
Implementation should keep protocol-heavy tests in new bounded DNS test files and make composition-root
changes thin，but MUST NOT delete independent evidence merely to reduce the signal. No Rust fixture LOC、
second process harness or copied DNS codec is forecast.

## Integration gate

Run serially on one accepted integration SHA:

~~~powershell
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
~~~

After explicit authorization，one non-force push of the exact accepted SHA must pass automatic quality、
test-footprint、Rust 1.88、Windows MSVC、Linux GNU/musl、existing TCP/UDP `12/12` each plus cleanup、
DNS interoperability and final qualification. A separately authorized manual dispatch must pass the
independent performance/resource contract. No rerun、second push、PR、tag、release or publication is
implied.

## Stop rules

- Any preserved-config drift、hostname bootstrap、wrong detour plan、ordinary-route bootstrap、public UDP
  opt-in drift、direct/detour loop、second matcher/parser/framer/SIP022 data plane、cross-tag/member retry、
  plaintext downgrade、selected-error fallback、post-resolution ordinary routing、unbounded query/
  connection/session/task/buffer、unawaited Hickory/detour task、destination telemetry or cleanup/rebind
  failure blocks M12.
- An insecure verifier、custom CA product field、DNSSEC/DoQ/DoH3、cache、general retry、server group、
  suffix/CIDR/qtype rule or standalone DNS binary is scope expansion and needs a new approved contract.
- Numeric footprint `WARN`/`REVIEW_REQUIRED` requires recorded Architect/QA disposition but is not a
  correctness waiver or automatic failure. Integrity failure、blocking review、provider unavailable、
  skipped evidence、wrong SHA/run/attempt or absent remote authorization is blocking.
