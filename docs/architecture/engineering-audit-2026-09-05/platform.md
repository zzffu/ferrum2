# Windows platform and TUN engineering audit — 2026-09-05

Snapshot: `2fb0dd4a9099837b81586a11fba4d265777674bb`. Read-only production review; no product edits, commits, adapter creation, route/DNS/WFP/interface mutation, or new fault-injection harness. Root and both crate AGENTS, `docs/config-v2-tun.md`, and `docs/architecture/invariants.md` were read. Every production source module in these two crates was read; `platform-coverage.json` distinguishes production review from separate test/support modules. Inline test portions are not counted as production.

The existing owner boundary is valuable: packet validation/reassembly, bridge state, runtime lifecycle, and platform operations have identifiable owners; no new umbrella crate or mechanical size split is justified. Remaining defects concentrate in cancellation handshakes and preservation of cleanup integrity. Historical R8 and host qualification do not prove those interleavings safe.

## Findings

### PLAT-01 — P1: Joining the owner while retaining its lifecycle completion sender creates a shutdown dependency cycle

Locations: `crates/ferrum2-tun/src/runtime.rs:133`, `:137`, `:228`, `:244`; `crates/ferrum2-tun/src/lifecycle/live/rebuild.rs:19`; `crates/ferrum2-tun/src/runtime/thread.rs:19`, `:78`.

Contract: shutdown/rollback/cancel must retain native join ownership and make every native wait stoppable before join. R8 correctly retains the JoinHandle, but that is insufficient without closing its dependencies.

Static ownership timeline:
1. The native owner calls `request_client_network_lifecycle`: it sends `NetworkResetRequest` into the capacity-one Tokio queue, then blocks in `completion_receiver.blocking_recv()`.
2. The queued request owns the sole completion Sender. The root owns the queue Receiver.
3. `TunRoot::run` can observe forced cancellation, or cancellation with no remaining handlers/flow counts, before servicing that queued request. The latter is especially plausible during reset after stack quiescence. It exits the service loop and calls `self.owner.reap().await` while `self.network_resets` remains alive in the enclosing root. Rollback also calls reap without dropping/closing/draining that Receiver.
4. Reap sets stop and signals work, then waits for native join. Neither signal interrupts `blocking_recv`. The native thread waits for the Sender held by the root queue; the root waits for the native thread before dropping that queue.
5. Cancellation of the reap future also waits through `PendingThreadJoin::drop`; it cannot break the cycle. Dropping the root directly encounters the owner field first, before its queue field.

Fact: the source establishes both retained ownership and uninterruptible wait; no scheduler fairness or timeout in these functions breaks the cycle. Limitation: the queue-at-exit schedule was not dynamically reproduced. Do not label this a measured hang. Fix direction: one lifecycle bridge owner must quiesce/close queued and in-flight requests before owner join, and the native request must have a stop-aware response wait. Preserve R8 exactly-once join and cleanup result precedence. Validation needed: hosted injected native-owner tests for queued reset + graceful stop, forced stop, rollback and future Drop; bound the harness independently and assert native cleanup completion before root completion.

### PLAT-02 — P1: Preparation cancellation can retain the initialization sender behind the native join

Locations: `crates/ferrum2-tun/src/process/live.rs:87`, `:128`, `:132`, `:197`; `crates/ferrum2-tun/src/lifecycle/live/owner.rs:650`–`:667`.

Static ownership timeline:
1. Native initialization creates a synchronous completion channel and sends `OwnerReady::Ready { initialization, ... }` to the capacity-one readiness queue.
2. Native then waits in `initialized.recv()`.
3. The preparation loop checks cancellation and deadline before `ready_receiver.try_recv()`. If Ready is queued concurrently, either early return enters `cancel_prepare(guard).await` / `prepare_failure(guard).await` while local `ready_receiver` is still alive and retains the Ready payload and its completion Sender.
4. Guard reap waits for native termination; native recv waits for the Sender in the retained local Receiver. Setting stop cannot release recv.

Fact: the explicit cancellation/deadline path and ownership cycle are supported by static review. Arbitrary future Drop has a separate local-drop-order question and is not asserted to deadlock. Already-dequeued requests have cancellation response paths; see cross-check.md. The queued interleaving was not dynamically exercised. Fix direction: the readiness handshake must be owned together with the join guard, so cancellation drops/responds to Ready before join; native initialization waiting must also be stoppable. Validation: cancellation before readiness polling, deadline boundary after Ready enqueue, and dropped preparation future, with independently bounded fake operations and no real adapter.

### PLAT-03 — P1: Cancellation masks adapter-creation cleanup failure

Location: `crates/ferrum2-tun/src/lifecycle/live/owner.rs:129`–`:146`.

On `Adapter::create` error, the stop/shutdown check returns `OwnerExit::Stopped` before `error.is_cleanup_failure()`. A cancelled setup whose reverse transaction failed is therefore reported as successful cancellation instead of terminal cleanup failure. `process/live.rs::cancel_prepare` only returns its cleanup error for `OwnerExit::CleanupFailed`, so the information is lost end to end. The platform constructor explicitly supplies this failure distinction.

Fact: deterministic error-priority defect in the displayed branch. Dynamic combined cancellation/cleanup failure not injected. Fix: cleanup-integrity failure must outrank cancellation in one exhaustive adapter-create disposition owner. Verify every operation/cleanup/strict-route failure crossed with cancellation and deadline, and the resulting root report.

### PLAT-04 — P1: Failed notification-subscription rollback is reduced to an ordinary setup failure

Locations: `crates/ferrum2-platform-windows/src/windows/core/notification/mod.rs:49`–`:65`; `.../windows/live/wintun.rs:485`–`:522`; `.../windows/core/managed/mod.rs:174`–`:188`.

When subscription two or three fails and cancellation of an earlier handle also fails, `subscribe_notification_sequence` deliberately leaks handle/context to prevent callback use-after-free, then returns the original operation error. That loses the cleanup classification. In adapter preparation these notifications are not yet in `self.managed`; the outer cleanup journal cannot see them and `finish_setup_transaction` can report an ordinary creation error. A later `snapshot_underlay` failure similarly drops the local notification owner before it reaches the adapter journal, with Drop discarding close failure.

Fact: the safety-preserving leak is intentional and preferable to freeing reachable context; its failure classification is missing. Impact: retry instead of terminal cleanup failure, potentially accumulating retained callback registrations across retries; not a demonstrated memory-safety exploit. Fix: preserve ownership in a staged managed transaction before further fallible work; return cleanup-classified setup outcomes and propagate them through CreateError. Verify subscription rollback failure and underlay-capture failure + notification-close failure with injected operations.

### PLAT-05 — P2: Unknown route/address readback is treated as confirmed managed-state damage

Locations: `.../windows/core/managed/mod.rs:158`; `.../windows/core/managed/state.rs:96`; `.../windows/live/wintun.rs:231`–`:276`; `.../windows/live/managed.rs:193`.

`managed_routes_match` maps `ManagedRouteRead::Failed` to false, and `managed_state_health` turns false into Route damage. Address readback similarly uses `is_ok_and`, and interface identity readback is boolean. Thus a transient OS read failure can be escalated to full rebuild even though object absence/mismatch has not been confirmed. This conflicts with the explicit lightweight-reset/full-rebuild split and the existing Retry disposition for recoverable readback failures.

Fact: information loss and resulting classification are direct. Limitation: no live transient failure reproduced. Fix: model exact/missing-or-mismatched/unavailable outcomes separately; only confirmed mismatch should yield managed damage, with closed recoverable/terminal error categories for unavailable readback. Verify both families and ensure transient failure preserves adapter, session and ledger.

### PLAT-06 — P2: Runtime managed-health audit omits the owned MTU state

Locations: `.../windows/live/wintun.rs:231`–`:276`, `:374`; `.../windows/live/managed.rs:226`.

MTU is journaled and checked at setup and reverse cleanup, but `managed_device_health` neither verifies that the expected MTU journal slots are present nor reads current MTUs. An interface notification after MTU damage can therefore be classified unchanged while the stack continues assuming configured MTU. At cleanup the mismatch finally becomes a cleanup conflict.

Fact: no MTU health readback exists in this audit path. Impact depends on external MTU change; no host mutation performed. Fix: include family-specific MTU state in the managed health/ledger contract, with unavailable reads distinguished from confirmed damage. Validate IPv4, IPv6 and dual-stack corruption/absence scenarios using injected rows.

### PLAT-07 — P2: DLL size rejection happens after unbounded file reading

Locations: `.../windows/live/loader.rs:201`–`:204`, `:364`–`:370`.

`verify_artifact` obtains metadata size, but Rust evaluates `cng_sha256(file)?` before `validate_artifact(bytes, ...)`; hashing calls `read_to_end` into a Vec and only then checks the pinned 427,552-byte size. A wrong oversized sibling DLL consumes its entire contents before rejection and may exceed startup memory/time expectations.

Fact: unbounded read before size rejection. Limitation: no large file or resource-exhaustion test was created. Fix: reject metadata length first and additionally bound the read to pinned size plus one byte (or exact read + EOF check); preserve held file identity and hash. Verify wrong-size rejection without reading body using an injected reader, and exact hash/provenance cases.

### PLAT-08 — P2: Directory verification failure leaks a raw handle

Location: `.../windows/live/loader.rs:277`–`:303`, especially `verify_directory_non_reparse(handle)?` before `DirectoryHandle(handle)`.

After CreateFileW succeeds, a reparse/non-directory rejection or attribute-query failure returns before the raw HANDLE is RAII-owned. Earlier held ancestor handles are dropped, but the current raw handle leaks. Setup retries can repeat it.

Fact: early-return lifetime defect; no live rejection test performed. Fix: construct DirectoryHandle immediately after successful open, then verify through its borrowed raw value. Verify exact once close on verification failure with an injected handle owner; retain directory no-delete sharing and path checks.

### PLAT-09 — P2: The validated platform configuration can be mutated after validation

Locations: `crates/ferrum2-platform-windows/src/lib.rs:107`–`:117`; `.../windows/live/wintun.rs:90`.

AdapterConfig constructor checks name/ring/MTU/time/family constraints, but these fields are public and mutable, while Adapter::create does not revalidate them. A caller can construct a valid value, then set ring capacity to zero or clear both families before entering the FFI transaction. It can also invalidate family compatibility after `with_managed_network` succeeds. Current TUN caller reconstructs through the constructor; no current in-repository exploitation was identified.

Fact: public API does not enforce its stated validated-input invariant. Fix: make fields private with narrow read access and validated constructors/builders; retain platform ownership of platform validation, rather than copying it into TUN. Verify public construction rejects malformed values before injected operations and update all in-repository callers.

### PLAT-10 — P2: Initialization callback can outlive ready_timeout

Location: `crates/ferrum2-tun/src/process/live.rs:137`–`:157`.

After Ready is received before the deadline, preparation awaits `handle_network_lifecycle(... Initialize)` with cancellation only; it has no deadline branch or post-completion deadline check. A slow/stuck initialization hook therefore extends the advertised startup bound indefinitely unless an external cancellation arrives. The earlier polling loop deadline does not govern this await.

Fact: missing deadline coverage. Limitation: caller hooks may supply other bounds, but process_root's public callback contract does not require them and its own ready_timeout is not preserved. Fix: carry the same startup deadline through initialization, terminate the handshake with Stopped on expiry, and join safely per PLAT-02. Verify boundary completion and pending-hook timeout through a hosted seam.

### PLAT-11 — P3: Trait and unsafe-boundary obligations are not consistently documented

Examples: `.../windows/core/managed/mod.rs:26`, `:71`, `:103`, `:131`, `:192`, `:235`; `.../windows/core/loader.rs:4`; `.../windows/core/network/mod.rs:182`, `:206`; `.../windows/core/network/contract.rs:15`; `.../windows/core/strict_route/mod.rs:8`; `.../windows/core/notification/mod.rs:72`; `.../windows/core/raw.rs:31`; `.../windows/live/wintun.rs:307`.

The injected synchronous traits have no purpose/implementor-obligation documentation. Their correctness depends on non-obvious rules such as whether a failed create already owns state, exact readback semantics, cancellation draining callbacks, and close retryability. Many raw union/FFI blocks similarly omit local lifetime/ownership justification, though some newer loader/notification/WFP blocks document it well. The two allowed unsafe module boundaries are preserved; no async-trait or missing async Send contract was found in these crates.

Fix: document obligations at each existing seam and local unsafe invariants; do not create forwarding traits merely to satisfy a count. Verification is targeted code review plus existing transaction tests and normal clippy/check gates.

### PLAT-12 — P3: TCP generation exhaustion returns an unusable slot to the free-list top

Locations: `crates/ferrum2-tun/src/stack/tcp.rs:164`; `crates/ferrum2-tun/src/udp/mod.rs:68`; compare `.../udp/table.rs::remove`.

GenerationTable::recycle succeeds when incrementing MAX-1 to MAX, while current treats MAX as retired. TCP pushes that retired slot back onto its LIFO free list; admit_tcp sees None at the top and rejects new admissions without popping it, even if other slots are free. UDP explicitly checks current after recycle and avoids this. Trigger needs roughly four billion reuses of one slot within a stack generation; no practical incident asserted. Fix: retire exhausted TCP slots as UDP already does. Verify near-exhaustion injected generation values and admission through another free slot.

## Design and performance observations (not measured regressions)

- Lifecycle cancellation should be consolidated by ownership of handshake + native thread + close result, rather than moving branches out of the 856-line owner_main mechanically. owner_main combines startup/reset/rebuild staging and repeats quiesce/drop/cleanup; staged owned session/attempt values are the useful seam. Reassembly is a cohesive 477-production-line state machine with large inline tests and the existing size exception; no mechanical split recommended.
- UDP bridge (821 lines) combines leases/commit, ADF reservations, response queuing and public candidate/association views; table (890 lines) combines bounded source slots, deadlines, owner controls and response validation. Extract only a complete lease/peer-policy or response lifecycle owner with colocated tests. Preserve EIM mapping, drop-new, first-route freeze in callers, exact generation and response-drop accounting, and the intentional unmetered TUN exception.
- `Stack` and TcpFlowEntry expose most internals crate-wide; method ownership can narrow sibling access, but wrapping every field is not useful. `process_root` still has twelve positional parameters and three same-typed errors despite a private RootSpec; a reviewed public construction request would make the capability boundary clearer. Config/AdapterConfig/ManagedNetworkConfig derive Debug over identity-bearing fields; no current logging sink was demonstrated, but safe redacted Debug is a useful hardening follow-up aligned with SEC-01.
- `pending_tcp_fin_generation` reparses/checksums every front output packet before checking TCP FIN. Output was already validated in MemoryTx or UDP injection. Retaining validated output metadata could avoid redundant parsing; prove identical FIN acknowledgment behavior, local control handling, and ring-full semantics before profiling gains.
- `drive_tcp` visits every active flow and obtains multiple bridge mutex locks even after its byte budget is exhausted. The work quantum is bounded in transferred bytes, not number of live-flow inspections; maximum is 4096. Smoltcp egress and poll-delay also traverse sockets. Treat ready-set/cursor changes as a profiling hypothesis, not an assumed optimization; retain fairness and FIN/reset progress for idle and blocked flows.
- UDP response send and existing-request enqueue allocate payload storage before `try_send` reports full. Reserving capacity before copying may reduce overload allocation, but requires exact queue/drop metrics and generation recheck and must not change backpressure policy.
- Owner callbacks/events can execute while TCP bridge locks are held. Their nonblocking/no-reentry obligations should be explicit before optimizations involving reentrant instrumentation.
- The parser enforces declared lengths, IPv4 header and transport checksums, the IPv4 UDP zero-checksum exception, unicast/nonzero ports, bounded option/extension walking, and reparse after strict bounded reassembly. Protocol policy gaps (for example acceptance breadth of fragment option layouts) were not independently checked against external RFCs and are not promoted to findings.
- Unsupported adapter preparation fails closed. Hosted tests do not compile the concrete live backend; numerous live owner/setup glue branches therefore lack direct hosted execution despite strong pure contracts. Tests of reducers alone cannot prove those ownership handshakes.

## Verification and limits

Actually run on this Windows workspace at the stated HEAD:

- `cargo test -p ferrum2-tun --lib --no-default-features --features fuzzing --locked`: 128 passed, 0 failed.
- `cargo test -p ferrum2-platform-windows --lib --no-default-features --features fuzzing --locked`: 59 passed, 0 failed.

No production modifications were made, so format/lint change gates were not required for this read-only subtask. No client test binary, real-adapter runner, new deadlock harness, fault-injection or resource-exhaustion experiment was executed. Parent instruction explicitly stopped new dynamic reproductions after automatic content review interrupted related groups; findings above retain precise static evidence and identify dynamic follow-up gaps. No historical safe test / live-host result is substituted for current path verification, and no performance improvement or no-regression result is claimed.
