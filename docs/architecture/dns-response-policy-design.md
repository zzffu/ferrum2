# Explicit DNS response policy

## Decision

Keep schema version 2 and the existing configuration → runtime-neutral blueprint → DNS execution ownership. Replace implicit CIDR-triggered upstream queries with three explicit operations: `evaluate`, `match_response`, and `respond`. This is a policy change, not a guarantee that geography-based leak tests will report a single resolver.

The configuration interface remains a flat ordered `dns.route.rules` list. `route` selects an upstream and terminates; `reject` terminates without another query; `evaluate` queries its upstream and continues with its response; `respond` returns the latest evaluated response without another query. A rule without match fields is unconditional. `match_response = true` selects response-IP RuleSet matching; ordinary inline domain, inbound, transport, query-type, and application-port constraints still match the original query. Response-mode RuleSet references match only relevant answer addresses, not unrelated answer/additional records. An empty RuleSet field imposes no address constraint.

The recommended configuration keeps domain-based domestic routing first, then evaluates the proxy DNS, routes response-CIDR matches to domestic DNS, and otherwise responds with the evaluated proxy answer. Connection routing and explicitly selected Direct resolvers are unchanged.

## Modules and interfaces

- `ferrum2-config` parses and prepares actions and matching mode, validates server references and legal field combinations offline, and permits unconditional rules. It performs no DNS I/O. `route` and `evaluate` require a server and may specify strategy; `reject` and `respond` forbid server/outbound/strategy fields. `outbound` remains invalid for DNS actions.
- `ferrum2-rule` owns the runtime-neutral descriptors and `DnsPolicyMatchMode::{Query, Response}`. Both descriptor and runtime rule constructors take `(matcher, mode, action)`. Action descriptors add `Evaluate(route)` and `Respond`. Materialized validation rejects query-mode references to any CIDR-capable RuleSet; there is no implicit legacy interpretation. Response-mode references require CIDR capability. Mixed RuleSets use only their CIDR entries in response mode. Response matching and `respond` require a preceding `evaluate` declaration. Empty matchers are valid.
- `ferrum2-dns::policy` owns ordered evaluation, the frozen RuleSet snapshot, matching, and state errors; it performs no I/O. The execution steps remain `RouteImmediately`, `EvaluateResponse`, `AcceptResponse`, `Reject`, and `Final`, but evaluation steps now originate only from explicit actions. No DNS message is cloned into the policy machine: the proxy lends the evaluated message while the machine advances to the next I/O or terminal step.
- `ferrum2-dns::proxy` remains the only policy I/O adapter. It owns actual responses, uses the existing per-query server/name/type memo, and moves the selected response to the caller. `AcceptResponse` identifies the most recently evaluated server and its strategy. Persistent cache keys retain server, canonical name, query type, and generation; a cache hit must preserve policy decisions.
- Client composition, dashboard catalog, fixtures, and qualification callers consume the same descriptors. No new resolver, global cache, configuration-to-DNS dependency, or network-layer interception mechanism is introduced.

## State and failures

A query begins with no evaluated response. A matching `evaluate` yields `EvaluateResponse`; calling the machine again before supplying that response is an error. Supplying the response advances subsequent rules against that borrowed response. Another executed `evaluate` replaces the latest response. `respond` produces `AcceptResponse` for that latest response. Terminal steps cannot resume evaluation.

A preceding conditional `evaluate` declaration is not proof it executed. If response-dependent evaluation is reached without a runtime response, fail closed with a protocol error, never query `final`. Static validation rejects use before any preceding declaration; runtime validation handles skipped conditional actions.

Transport/TLS/timeouts terminate the query without switching upstream. An evaluated DNS error response other than NXDOMAIN terminates with that upstream response rather than enabling a fallback query. NXDOMAIN and valid empty answers remain responses: their address predicates miss and `respond` can return them unchanged. CNAME traversal and relevant A/AAAA addresses reuse `ResponseSemantics`. The chosen domestic upstream's result is terminal; no hidden return to the earlier proxy answer on domestic failure.

`final` is the terminal route after rule exhaustion, not an error handler. `respond` forbids a strategy override; it inherits the evaluated action's strategy for application resolution. Ordinary DNS wire query type/response binding retains existing semantics.

## Candidate indexing and resource invariants

Query-only policies retain allocation-free evaluation scratch and the existing indexed/small-linear selection. Response-mode rules must never be excluded by a query-domain RuleSet index or by a non-address query type: such rules can still select terminal actions or fail closed when evaluation was skipped. Their scalar/inline query constraints may still narrow candidates. No re-expansion of RuleSets into individual DNS rules, no response clone per matched row, and no unbounded per-request retained history are introduced; memo storage is bounded by configured distinct upstreams and the existing response limits.

## Cutover and verification

Remove empty-rule and response-dependent-reject prohibitions where superseded, and reject implicit response rules rather than accepting both semantics. Migrate repository examples and test fixtures to explicit evaluation. Desktop deployment configuration and the currently running client remain untouched.

Verify observable contracts: domestic early routing never queries remote; non-domestic response matching never queries domestic; a domestic response match returns the selected domestic answer; `respond` does not query again; repeated evaluation selects the latest result; transport and DNS failure do not query fallback; skipped evaluation fails closed; negative/empty/CNAME/AAAA/cache responses preserve decisions; and indexed rules retain response candidates. Run a real unprivileged client with local controlled DNS peers and query-count evidence, followed by affected-package formatting, lint, tests, and client/qualification test compilation. No real TUN adapter or host network mutation is part of this work.

## Executed verification

The Windows native client/server build succeeded. A separate unprivileged client
ran with TUN disabled, a reviewed pinned CNIP SRS, two controlled loopback UDP
DNS peers, and an isolated dashboard. Thirteen wire-query scenarios verified:
domain-first domestic selection; remote-only A, AAAA and TXT results; remote
CIDR hit and CNAME-to-CIDR hit returning the domestic answer; NXDOMAIN; remote
SERVFAIL; selected-domestic SERVFAIL; latest of two evaluations; skipped
conditional evaluation; timeout; and TCP DNS ingress. Peer query counts proved
that `respond` did not query again and errors did not switch upstreams. The
existing UDP resolver retransmitted the timed-out query to the same upstream;
the configured 500 ms deadline was retained.

Offline validation accepted the documented example and rejected `respond`
before any `evaluate`. Materialization accepted the explicit policy and rejected
the otherwise-identical legacy CIDR rule without `match_response`. Separate
cache directories avoided the running client's exclusive RuleSet cache lease.
Chromium displayed `match_response = true` in the embedded dashboard and its DNS
form returned the expected remote answer through ordinary policy selection.

Executed gates:

```text
cargo build -p ferrum2-client -p ferrum2-server --bins --locked
cargo test -p ferrum2-rule -p ferrum2-config -p ferrum2-dns -p ferrum2-server --features ferrum2-dns/__interop-test-root --locked
cargo clippy -p ferrum2-rule -p ferrum2-config -p ferrum2-dns -p ferrum2-client -p ferrum2-server -p ferrum2-rule-qualification --all-targets --all-features --locked -- -D warnings
cargo test -p ferrum2-client -p ferrum2-rule-qualification --all-features --no-run --locked
cargo test -p ferrum2-m0-harness --test dns_udp_detour_e2e --test client_resolver_local_e2e --test workspace_policy --locked
cargo fmt --all -- --check
```

The affected-package suites passed 304 tests; the three process/policy harness
suites passed 35 tests. Client and timed qualification test binaries were only
compiled, not executed. No Linux, real-TUN, live proxy-service, or performance
qualification is implied. The user's desktop configuration and running client
were not modified or restarted.
