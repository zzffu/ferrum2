# Runtime / DNS / RuleSet stage-one engineering audit

Candidate: `2fb0dd4a`; product working tree was clean when checked. This is a read-only audit checkpoint, not completion of the full repository audit, a remediation, or a performance qualification.

## Coverage and inputs

Read the root AGENTS.md and all three scoped AGENTS.md, root/package manifests, README.md, docs/README.md, docs/config-v2-dns-rulesets.md, docs/architecture/invariants.md, and engineering-remediation-2026-09-05.md. No additional scoped guides existed below these three crates. Historical remediation evidence is context only; it is not full audit proof.

`runtime-dns-coverage.json` records every src Rust file individually: **62 production files reviewed, 0 partially reviewed, 3 dedicated test-only modules excluded**. The previously partial runtime `reset.rs` method boundary was completed by a static-only follow-up read of lines 581–621; no additional finding was identified. Dedicated test modules were not individually audited. Inline tests were viewed where included in reads, but that is not a complete test-source audit.

The review checked actual production text, not search matches alone: APIs/visibility, trait contracts and Send, matches, responsibility/dependency edges, deadlines/cancellation/backpressure/resource bounds, error closure, ownership and shutdown, and hot-path assumptions. Findings below distinguish code facts from unproven runtime consequences.

## Findings

### RD-01 — P1: a tagged query panic skips child cleanup and can defeat aggregate resource admission

Location: `crates/ferrum2-dns/src/runtime_owner/command_loop.rs`, all three `queries.spawn` closures and `completed = queries.join_next()`; `runtime_provider/tracking.rs::TaskSet::{spawn_counted,abort_and_join}`.

Contract: all Hickory and detour tasks belong to their query and must be cancelled/joined before query admission is reusable; failures must remain observable.

Confirmed static facts: `query_tasks.abort_and_join().await` runs only after the query body completes normally. An injected egress future panic unwinds past it. The command-loop completion branch discards JoinError, as does final query reaping. TaskSet uses Arc<Mutex<JoinSet>> and a registered task can retain a DnsTaskRegistrar containing another Arc of that same TaskSet. Such a task outlives the panicked query and can keep the TaskSet alive. QueryAdmission is not kept alive by the weak query scope, so the permit can be reused. Even without a retained task, query panic becomes a closed-channel Shutdown result and may be absent from final successful shutdown reporting.

Trigger/impact: panic during egress construction/poll after registering a pending bridge/session. Repeated logical queries can leave resources beyond `max_inflight` until exclusive runtime destruction. This is a static candidate, **not dynamically confirmed**. Existing R2 fixed proxy TCP/UDP task supervision, not these command-loop paths.

Direction: a single query-runner owner must retain the task set across unwind, always abort/join it, release admission afterwards, and preserve a sticky closed task-failure result. Drain all work even after the first error. Add bounded injected panic tests for each command variant, retained registrar task, and final zero owner counts.

### RD-02 — P1: RuleSet remote body and cache input have no practical byte limit

Location: `crates/ferrum2-ruleset/src/loader.rs::accept_download` (total accumulation and write loop); `source.rs::RuleSetLoaderConfig`; `cache.rs::read_cache_sync` (serde_json::from_reader and digest loop).

Confirmed static facts: streamed bytes only face u64 arithmetic overflow and a time deadline; loader config has no maximum resource length. Metadata is deserialized directly from an uncapped file before validation of URL/digest strings. Cached SRS is hashed until EOF without a file-size cap. Fixed 32 KiB copy storage bounds one buffer, not disk bytes or parsed metadata allocation.

Trigger/impact: a selected HTTPS server serves a large fast response, or a corrupt/oversized local cache metadata entry is present. Disk usage can grow with throughput × configured timeout; metadata memory and cache processing time are unbounded by an application size contract. No large-input reproduction was run. SRS declared-length/decompression bounds are owned by the foundations audit and should be coordinated as a common resource budget, not duplicated here.

Direction: validate compressed download/cache and metadata byte caps before and during reading; preserve a closed size-limit category; bound parsed validator lengths and decoded/compiled costs with ferrum2-rule. Verify exact-bound, bound+1, missing/misleading Content-Length, streaming overflow, oversized metadata, old-generation retention, temp cleanup and owner zero.

### RD-03 — P1: RuleSet shutdown does not own all blocking filesystem work

Location: `loader.rs::load_with_capabilities` (`tokio::fs::create_dir_all`); `accept_download` (`tokio::fs::File::from_std`, write_all, flush, sync_all); `blocking.rs::BlockingTaskOwner::shutdown`.

Confirmed static facts: R4's owner retains at most two explicit spawn_blocking closures and retryably joins them. Directory creation and async file writes/sync use Tokio filesystem work outside that owner. Loader shutdown only joins its BlockingTaskOwner. Dropping or timing out the async caller does not provide an application join handle for these Tokio-internal blocking operations. The compiler closure receives only a path while NamedTempFile remains in the cancellable async frame.

Impact: cancellation can return to composition shutdown while underlying file work is still running; a two-worker bound is therefore not a bound on all cache work. Slow OS filesystem behavior is an environment limitation, but missing application ownership is a concrete code boundary. No induced filesystem blocking experiment was run.

Direction: one bounded cache worker seam should own directory/file/temp/compile/commit lifetime and cancellation or retryable joins. A bounded chunk handoff may preserve download backpressure. OS calls that cannot be interrupted must remain joined and reported honestly; do not promise a hard OS deadline. Validate cancellation during directory creation, writes, sync, compile and commit, worker admission, temp lifetime, retryable shutdown and final joins.

### RD-04 — P1 pending validation: system DNS deadlines cancel waiters, not OS resolver work

Location: runtime `connector.rs::SystemTcpResolver::resolve`, `udp/direct.rs::SystemUdpResolver::resolve`; dns `application.rs::SystemApplicationResolveBackend::resolve`; ruleset `https.rs::{SystemRuleSetHostResolver::resolve,resolve_explicit_host}`. Composition audit reports the same path in client/server endpoint materialization.

Confirmed code fact: these paths directly use `tokio::net::lookup_host`; callers often time out the returned future. They contain no common operation admission permit retained by the actual OS lookup and no application-owned join/retry handle. Prior repository remediation records already identify Tokio's blocking resolver implementation.

Impact hypothesis: slow getaddrinfo calls can continue after flow/query permits are released, allow repeated replacement work, and delay runtime/thread teardown. Actual OS hang duration and production accumulation were not measured. This is not a claim that configured Hickory resolution silently falls back to system DNS: inspected configured paths fail closed.

Direction: a shared system-resolution owner beneath protocol composition, with bounded actual work and explicit shutdown joins; preserve system resolution semantics, per-request absolute deadlines and no configured fallback. Verify with an injected blocking backend, cancel waiters, prove actual-work capacity retained, then release and join. Platform cancel APIs may require a separately reviewed implementation. Do not substitute abort of a spawn_blocking handle for native cancellation.

### RD-05 — P2: Direct UDP erases terminal outcomes and task panics

Location: runtime `udp/direct.rs::commit_session_with_resolver_arc`, `reserve_session_inner`, `shutdown_with_control`.

Confirmed facts: the spawned owner does `let _ = run_direct_session(...).await`; JoinSet stores `()`. Admission reaping and shutdown reaping also discard JoinError. The R3 Drop guard correctly retires exact generation and releases capacity even after a panic, but cleanup correctness does not make the terminal cause observable.

Impact: resolve/send/receive/handler failures and panic look like ordinary session disappearance; process composition cannot reliably attribute loss. No need to make ordinary session errors process-fatal.

Direction: closed terminal outcome owner/observer, with exactly-once accounting for normal/idle/cancel/error/panic and no peer/source-error formatting. Validate each outcome and owner baseline, including panic before/after first poll, without introducing a parallel telemetry schema.

### RD-06 — P2: generation-bound socket monitor tasks have no join owner or accounting

Location: runtime `network_socket/generation.rs::{GenerationBoundTcpStream,GenerationBoundUdpSocket}::new/Drop`.

Confirmed facts: each socket spawns a `_monitor: JoinHandle<()>`. Drop synchronously closes physical resource/acknowledgement state and sends an oneshot, then drops the JoinHandle. No monitor join or dedicated monitor count exists. The monitor can still be queued when network_runtime_owners returns to baseline. The normal socket close itself is synchronous and not claimed to leak.

Impact: successful resource-zero evidence cannot prove all generation monitor tasks reaped; rapid turnover can temporarily accumulate uncounted tasks. Magnitude and persistent leakage are unmeasured.

Direction: service/runtime-owned tracked monitor JoinSet with bounded admission and explicit shutdown; alternatively eliminate separate monitors only if idle sockets still close upon reset and reset acknowledgements remain correct. Verify blocked-before-first-poll turnover, reset/drop race, all tasks joined, exact physical close before owner acknowledgement. Keep mutex/Arc poll cost as a profiling hypothesis until measured.

### RD-07 — P2: protocol-commit panic can become a double panic in UDP rollback Drop

Location: runtime `udp/session.rs::{PendingUdpDatagram::commit_inner_with,commit_immediate_inner_with,Drop}`, `PendingUdpSession::Drop`, and manager lock users.

Confirmed static facts: the injected `protocol_commit()` runs while the manager std::sync::Mutex guard is live. A panic poisons that lock. PendingUdpDatagram's unwinding Drop then locks with `expect("UDP session state lock poisoned")`, which panics again; PendingUdpSession rollback and DirectOwnerLifetime can likewise hit the poison. Public callback docs specify serialization but no no-panic or no-reentrancy obligation.

Impact: an otherwise containable callback panic may abort the process during unwinding rather than close one session. This is **static reasoning only**; no double-panic subprocess was run. Reentrancy into manager methods also deadlocks and should be forbidden or structurally prevented in the seam.

Direction: contain unwind while the lock is still unpoisoned, release lock before rollback/rethrow or closed failure; ensure arbitrary external callbacks cannot reenter manager ownership. Tests must be bounded child processes for abort cases and then normal in-process owner-baseline assertions after remediation. Preserve protocol/queue atomic commit semantics.

### RD-08 — P2: two-file cache replacement is not an atomic cache-generation commit

Location: ruleset `cache.rs::commit_cache`: `srs_temp.persist` precedes `meta_temp.persist`.

Confirmed static facts: two independent replacements can leave new .srs with old .meta if the second replacement fails or the process stops between them. Reads correctly reject digest mismatches. Live refresh snapshot remains old, but the previously valid offline cache can already be lost. Concurrent loader calls using the same cache name are not serialized across this pair.

Impact: later offline startup can fail despite a previously valid cache; this is availability/recoverability, not acceptance of corrupt content. Crash/concurrent-writer schedules were not dynamically reproduced.

Direction: immutable generation/digest-addressed payload plus one atomically switched metadata/index owner, or one atomically replaced container; serialize same-resource commit. Inject failure between each durable operation, verify either complete old or complete new cache is readable and incompatible refresh keeps prior cache intact.

## Architecture and performance observations (not measured bottlenecks)

- Dependency boundaries are respected in inspected manifests: runtime only core/net; DNS core/net/rule; RuleSet core/dns/rule. Crate roots use private implementation modules and curated exports.
- Existing R1 metrics whole-I/O deadline, R2 proxy task supervision, R3 direct UDP Drop lifetime, R4 explicit blocking owner, R6 fair direct UDP progress and R7 monotonic activity are present. Timer reuse was not reintroduced.
- Large cohesive owners remain: reset.rs, connection_executor production, DNS proxy/owner/model. Extract around query lifetime, monitor lifetime, cache transaction and admission state before cosmetic line-count splits. Keep corresponding behavioral tests with owners.
- Native future-returning Send traits exist for socket/dialer seams; boxed futures are used for object-safe injected backends. Some observer/marker trait obligations need clearer bounded/nonblocking and panic contracts. Boolean arguments in private UDP reservation/activation helpers obscure intent; replace with named modes during relevant owner redesign.
- UDP manager scans for lowest free slot and idle eviction under a shared mutex; receive allocates maximum wire capacity per response and notifies all buffer waiters on release. DNS cache random refresh and expiry purge scan under one mutex. Generation TCP wrappers take several locks and poll boxed cancellation per I/O operation. DNS CNAME matching can rescan the Answer list repeatedly. These are profiling candidates, not proven speedups/regressions.
- RuleSet refresh and initial snapshot `builder.build()` run synchronously in async frames after SRS compile. Their size-dependent latency deserves measurement/ownership review; no timing claim is made.
- Preserve current fixed buffer/backpressure, generation, redaction, exact ordered routing and successful work semantics. Do not optimize away bounds or reproduce withdrawn timers without new independent measurements.

## Actual verification and stop limitation

Ran `cargo test -p ferrum2-runtime -p ferrum2-dns -p ferrum2-ruleset --features ferrum2-dns/__interop-test-root --locked`. Saved log: `target/remediation-audit/runtime-dns-tests.log`. It contains **224 passed, 0 failed, 0 ignored** across 39 successful result groups including doc-tests. `runtime-dns-test-summary.json` records mechanically summed results; the log ended in successful doc-tests. The original tool session completion was not separately polled before the stop instruction.

A scratch-only `dns-panic-repro.rs` was compiled against existing rlibs. Its sole execution failed before the intended fault path with `there is no reactor running` (incompatible selected Tokio artifact context); that run confirms none of RD-01's intended effects. Source and log are retained under target; no product or test-source files were modified. Do not count this as a successful reproduction.

The parent then instructed that automatic content review interrupted dynamic fault reproduction and required stopping all such work. I did not retry, rewrite, or repeat the rejected operation, did not run additional tests, and saved this checkpoint only. Consequently dynamic reproductions for the findings, missing file-range coverage, formatting/lint/package-gate expansion, cross-platform tests and performance/privileged qualification remain unperformed. No adapter, route, host DNS, physical interface, or privileged network state was modified; no external DNS/HTTPS was intentionally invoked by scratch code.


Static-only follow-up: completed reset.rs coverage after explicit authorization. No further dynamic reproductions or tests were executed. Earlier dynamic restrictions remain in force.
