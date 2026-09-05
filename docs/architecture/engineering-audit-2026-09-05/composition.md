# Composition and observability engineering audit — stage one

Scope: `bins/ferrum2-client`, `bins/ferrum2-server`, `crates/ferrum2-observability`. Read against HEAD `2fb0dd4a9099837b81586a11fba4d265777674bb`, 2026-09-05. Product sources were not changed. Existing working-tree documentation changes belong to the coordinating audit.

## Coverage and limits

All 80 production-bearing `src/*.rs` modules in this partition were read in full, including platform/test conditional branches in those modules, and traced through prepare/materialize, root preparation/activation, SOCKS/SS/TUN execution, physical egress, reset and shutdown. Root and all three scoped AGENTS, root/package manifests, README, docs index, DNS/RuleSet configuration guide, managed-TUN guide and paired SOCKS/server examples were read. Historical remediation evidence was not treated as full-review evidence.

The machine-readable ledger is `composition-coverage.json`. `reviewed` means full static production-module review, not executed verification or proof of absence of bugs. Test-only modules have individual states; most remain pending full evidence review. The observability external `metrics_contract.rs` and `network_metrics_contract.rs`, client SOCKS `tests/boundaries.rs` and TUN `tests/udp_route.rs` were read in full, plus inline tests encountered in fully read production files. Search-only test hits are not credited as reviewed.

No tests, binaries, resource-exhaustion experiments, failure injection, host networking changes or profiling were run in this partition. Client tests remain compile-only. New dynamic verification is deferred per the coordinator's instruction after automatic content review interrupted other agents' experiments. Findings below separate static fact from still-unverified reachability/timing. No performance improvement is claimed.

## Static findings

### C1 — P2: legal public telemetry variants alias series or index beyond the family

- Locations: `crates/ferrum2-observability/src/metrics/core.rs:154`, `:162`, `:468`, `:495`, `:547`, `:560`; `src/metrics/family.rs:164`; public variants in `src/trace/schema.rs:66` and `:95`.
- Fact: OUTCOMES omits `Outcome::Dropped`; STAGES omits `Stage::Tun`. Public metric methods accept those enums without restriction and calculate flattened array indices using enum discriminants and the shorter list lengths.
- Static arithmetic: `connection(Client, Socks5, Dropped)` addresses the slot labelled `(Client, Shadowsocks, Accepted)`; `connection(Server, Shadowsocks, Dropped)` indexes immediately past CONNECTION_SERIES. A Client/Tun generic failure aliases Server/Config; Server/Tun is beyond FAILURE_SERIES. UDP methods have the same defect.
- Impact: a legal API call silently mislabels telemetry or panics. No present production caller using these exact unsupported combinations was established; the public contract defect itself is certain. Existing `metrics_contract.rs:60` calls its grid complete but mirrors the six-outcome omission.
- Contract: scoped observability closed dimensions/stable labels; root exhaustive-known-variant and observable-behavior testing rules.
- Direction: make each metric input domain match its actual supported vocabulary, or include every accepted variant in the grid. Keep enum-to-index and enumeration coverage under one closed owner rather than relying on parallel hand-maintained lists. Verify all legal tuples have their own exact labels and never panic; preserve existing family names and values.

### C2 — P2: first rejected-for-budget SOCKS UDP packet pins the zero-port association

- Locations: `bins/ferrum2-client/src/run/socks/association.rs:413` (also `:169`), `:470` onward; `run/egress/udp/association.rs:494`; `run/observation.rs:274`.
- Fact: after SOCKS decoding and payload-length checks, `endpoint.accept(source_port)` commits pin and activity before egress preparation and request byte reservation. Request reservation may return BufferLimit. `record_udp_runtime_error` deliberately treats BufferLimit as a nonterminal drop, so the Shadowsocks relay can remain alive with the rejected packet's source port pinned.
- Trigger/impact: first valid-wire datagram on a zero-port association passes packet-size limits while the shared budget has enough fixed-buffer capacity but insufficient request capacity. A later valid packet from another source port on the same client IP is rejected despite no first accepted datagram having occurred. The exact asynchronous scenario has not been executed.
- Contract: client AGENTS explicitly says wrong-source, malformed, fragmented, rejected, or over-limit packets must not pin a zero-port association. Current boundary tests cover wire-size over-limit, not this deferred admission rejection.
- Direction: retain a candidate source until the request has crossed the actual accepted/admitted boundary; update idle activity at that same point. Preserve no-pin behavior for every precommit failure. Verify rejected first request then accepted alternate source under a controlled safe test seam, without running the client test binary on an ordinary host.

### C3 — P2: a frozen TUN Reject association swallows later synthetic DNS

- Locations: `bins/ferrum2-client/src/run/tun/udp/association.rs:400` and callers `:300`, `:385`; contrast Route branch per-datagram synthetic handling at `:563` onward.
- Fact: `run_udp_reject_association` receives and rejects every later packet and has neither synthetic-address configuration nor a DNS proxy/context. Therefore it cannot apply exact synthetic DNS matching for a later destination on the same source association.
- Cross-layer evidence: platform reviewer confirmed `ferrum2-tun` existing-association dispatch forwards actual datagram targets to the retained channel (`stack/mod.rs` enqueue and `udp/table.rs` existing enqueue); it does not bypass the retained handler for synthetic DNS.
- Trigger/impact: same source sends an ordinary datagram whose terminal is Reject, then a query to the configured synthetic address:53; query is discarded until expiry/reset. Static call-chain is conclusive; no packet scenario was run.
- Contract: client AGENTS requires synthetic DNS matching for each destination before ordinary association freezing; the existing Route branch already preserves it after freezing. Keep rejection frozen for ordinary traffic.
- Direction: put per-datagram synthetic DNS preprocessing ahead of dispatch by frozen terminal, including Reject. Verify ordinary reject remains frozen, later exact synthetic DNS is answered, other port-53 destinations remain rejected, and peer authorization occurs only after an answer.

### C4 — P2: non-TUN network-root cancellation detaches a blocking snapshot owner

- Locations: client `run/tun/network_lifecycle.rs:134`, `:246`, `:256`; server `run/network.rs:214`, `:272`.
- Fact: network reset creates a `spawn_blocking` task for `NetworkSnapshot::capture` and awaits its JoinHandle inside the reset future. The outer cancellation select returns immediately, dropping that future/JoinHandle without joining the already-started blocking task. In contrast the monitor wait paths in both files explicitly signal then await their blocking owner.
- Impact: a root can report stopped while a native catalog snapshot worker is still running. Tokio runtime destruction may subsequently wait outside the process-supervisor cleanup evidence. An actual prolonged native call or shutdown hang was not demonstrated; the ownership gap on cancellation is certain.
- Contract: explicit bounded task and shutdown ownership, join every acquired temporary owner, deterministic cleanup. No default-route/DNS/adapter mutation is involved in the proposed ownership repair.
- Direction: preserve the snapshot JoinHandle across cancellation and join through the root's cleanup path, or use a bounded supervised snapshot service. Native call cancellation limitations must be stated separately from application ownership. Validate completion ordering through an injected catalogue/worker seam after authorized verification resumes.

### C5 — P2: client TCP sniff outcomes are emitted as UDP and collector failure detail is lost

- Locations: `bins/ferrum2-client/src/run/observation.rs:35`, `:55`; `run/routing.rs:235`–`:249`; contrast server `run/observation.rs:82`.
- Fact: client `record_sniff` always invokes `metrics.sniff(Role::Client, Transport::Udp, ...)`, while `select_tcp` calls it for managed TUN TCP. Metrics::sniff emits the same tuple as a trace, so both channels are wrong. TCP Timeout/Unavailable/ReadError/Cancelled are collapsed to Unknown instead of the existing closed Timeout/Unavailable outcomes.
- Impact: TUN TCP sniff traffic increases UDP series; TCP-specific performance and failure attribution is misleading. Static caller-to-emitter mismatch is certain; no live sniff traffic was run.
- Contract: exact single closed metric-and-trace tuple per sniff attempt and stable label meanings.
- Direction: pass the closed transport and collector outcome into the observation owner; share the existing server mapping where useful. Verify complete TCP/UDP parser and collector tuples via safe mapping/observation contracts, including sentinel absence.

### C6 — P2 observability completeness: server startup loses root/endpoint-stage identity

- Locations: server `run.rs:654` report_result; listener binds at `run.rs:537`, `:557`, `:582`; `run/io.rs:7`. Client closed report in `run/shutdown_diagnostic.rs` provides the existing useful contrast.
- Fact: server discards ProcessReport root identity/phase and returns StartupBind for required UDP, TCP and metrics endpoints. Even bind-vs-listen stage is flattened. This prevents a redacted stderr record from distinguishing the candidate server startup.bind already observed by the coordinator.
- Impact: operational qualification failure cannot be attributed to root kind and declaration index from product output. This does not establish which endpoint caused the earlier host incident and does not justify changing host network notifications.
- Contract: stable closed error categories and explicit lifecycle evidence. Config alias validation is a separate foundations finding.
- Direction: preserve category plus closed root role, declaration index and endpoint acquisition stage in a server report. Do not log endpoint values, tags, peer addresses or raw OS error chains. Keep the original failing process result and cleanup evidence together. Coordinate the schema with the runner's typed evidence consumer.

### C7 — P3: documented interface-resolution diagnostics have no production emitter caller

- Locations: `crates/ferrum2-observability/src/trace/emit.rs:182` exposes the emitter; client `run/egress/network.rs:396` and server `run/network.rs:467` only update metric counters; `docs/config-v2-tun.md` Operational metrics says interface resolution emits closed structured diagnostics.
- Fact: full production module review plus repository caller search found the interface-resolution emitter referenced by tracing contract tests, not the binaries. Normal socket observations update metrics only. The lightweight reset emitter is likewise not integrated, although reset metrics are updated.
- Impact: operator documentation promises diagnostic records that real paths do not produce; unit emitter tests alone do not establish product integration.
- Direction: decide the intended production observation contract in unified design. If diagnostic events are retained, wire one redacted typed emission at the common completed-resolution boundary with deliberate level/rate behavior and verify through a composed path. Avoid high-volume unsolicited info logs in a hot path.

## Architecture and API observations for the later design phase

### Additional C8 — P2: server listener erases recoverable accept errors

- Location: `bins/ferrum2-server/src/run/tcp/listener.rs:35`–`:40` maps every `poll_accept` error to `io::ErrorKind::Other`; client counterpart preserves the original error.
- Static cross-layer fact: runtime reviewer confirmed AffineConnectionExecutor's `is_transient_accept_error` retries Interrupted, WouldBlock, ConnectionAborted and ConnectionReset, while Other becomes ListenerFailure. Thus a transient per-connection accept error on the server becomes fatal to the required TCP root/process.
- Contract: preserve runtime accept/admission error semantics and fail only on terminal listener failures; redaction does not require erasing io::ErrorKind.
- Direction: retain the closed original error kind at this adapter boundary and verify through the existing safe listener seam after verification resumes. No transient-error experiment was run by this reviewer.

- Server DNS builds a full proxy/policy/cache graph in `dns_egress.rs:85`–`:224`, but runtime Direct resolvers deliberately use exact tagged or system resolution and bypass that proxy. `new_observed/new_inner`, configured-application backend and proxy accessor are effectively test-only and protected by broad `allow(dead_code)` attributes (`:85`, `:105`, `:121`, `:233`, `:417`). Preserve required offline/materialization policy validation, but remove obsolete production state and migrate tests to the current caller contract rather than retaining a second unused DNS architecture.
- ClientPhysicalConnector (`run/egress/network.rs:283`) and ServerUdpListener (`server/run/udp/listener.rs:28`) have correct native future-returning Send contracts but no trait-purpose/implementor-obligation documentation. Document cancellation safety, expected read-buffer shape, readiness behavior, generation semantics and redacted error obligations.
- Closed telemetry enums marked non_exhaustive force future callers toward catch-alls even though the repository explicitly rejects compatibility shims and wants known-variant completeness. Review this API policy together with C1; do not mechanically remove attributes without updating callers.
- Client `ClientUdpAssociation` (`run/egress/udp/association.rs`) still combines proxy/direct state with many independent Options and a boolean metering policy. Its methods correctly centralize metered-vs-unmetered selection, but data validity is enforced by distant expects. A closed Direct/Proxy resource state and named accounting policy can improve invariants without splitting the 931-line file mechanically or duplicating packet logic.
- Both run roots still use positional DNS tuples and optional resource bundles (`client/run.rs:522`, `server/run.rs:284`), including test-only unmaterialized states mixed into production types. The materialization Pending/Absent and Prepared/Cleaned owners themselves are sound improvements and should be retained. Prefer one explicit production handoff plus separate test construction seams.
- Telemetry remains manually balanced around TCP futures. Forced future drop can bypass post-await decrements; most shutdown metrics endpoints disappear concurrently, so externally visible stale gauges were not demonstrated. A scoped connection observation owner is a design candidate, not a proved running-process metric leak.
- Several mappings retain wildcard known-enum fallbacks, notably both materialize/outcome SRS kind classifiers and server UDP observation. Replace with explicit known variants where the upstream enum is closed; io::ErrorKind remains nonexhaustive and legitimately needs an otherwise mapping.
- Client route snapshot uses handle.snapshot_owned without a selector-generation retry for TCP/SOCKS. TUN UDP alone does before/after generation checks. Foundations owns the multi-selector linearizability question: current result is one complete immutable legal plan, but concurrent nested selection need not represent one instant. Treat desired semantics as an explicit design contract, not an already reproduced policy violation.

## Cross-partition findings and deferred performance hypotheses

- Runtime/DNS reviewer owns system lookup_host blocking-worker ownership. Its repair scope must include client `materialize/endpoint.rs:533` and server `materialize/endpoint.rs:394`; outer timeouts do not cancel internal getaddrinfo. This is separate from C4's native network-snapshot worker.
- Foundations owns listener wildcard/specific-address alias validation. Composition confirms all such late bind failures are fail-closed; C6 concerns diagnosing the failed resource, not making occupied binds succeed.
- Repeated full DNS blueprint/egress construction per configured fixed-endpoint lookup, client DNS TCP two duplex bridges/two registered tasks, always-on route match timing and histogram locks, response encoding scratch mutex, and metric text canonicalization allocations are profiling hypotheses only. No claim about dominant CPU cost or benefit is made before post-remediation Qualification and fast CPU profiling.
- Client direct UDP retains one socket/family/interface selected from the first target, consistent with frozen association policy; mixed-family later-target behavior must be specified in architecture rather than casually reopening sockets as a performance fix.
- Server UDP route error `?` at `run/udp/run_loop.rs:206` bypasses the explicit shutdown epilogue if it ever returns Err. The current selector implementation has no returning Err branch, so this is a latent future-maintenance hazard, not a demonstrated reachable leak.

## Positive contracts retained by this review

Offline CLI exits before runtime construction; materialization-only uses pending construction plans, joins active initial tagged/RuleSet transports, and keeps client failure exit 1 vs server 2. Process roots own listener rollback; server binds UDP before its TCP readiness surface. Route/SS response commit tokens stay move-only and colocated with publication. Server UDP freezes authenticated identity across runtime rebuild/reset, rechecks a concurrent winner after opening a provisional socket, and does not hold shared admission across async socket/DNS work. TUN metering exceptions remain origin-gated and do not bypass session/packet/generation bounds. Registry and trace boundaries remain private, with closed metadata allowlisting and no discovered peer/key value logging in reviewed production paths.

These static results are inputs to the complete-workspace architecture pass, not authorization to start isolated fixes or final qualification.
