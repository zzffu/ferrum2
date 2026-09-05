# Independent static cross-check

Reviewed platform.md PLAT-01 through PLAT-04 and composition.md C1/C2/C3 against their production call chains. Read applicable root, TUN, Windows platform, client and observability guides. No code changes, dynamic reproduction, tests, abnormal input or host operation were performed. Findings below classify confirmation, corrections and remaining uncertainty only.

## PLAT-01 — Confirmed conditional wait cycle; retain P1 static classification

The native request in crates/ferrum2-tun/src/lifecycle/live/rebuild.rs::request_client_network_lifecycle first blocking_send's a NetworkResetRequest, then blocking_recv's its oneshot. The queued request owns the sender. TunRoot keeps network_resets as a field after owner in runtime.rs. Its forced and empty/quiescent cancellation exits stop servicing requests, abort/join handlers, and await owner.reap while retaining network_resets. OwnerThread::reap sets stop and signals work, then joins through PendingThreadJoin. Neither flag nor WorkSignal is selected by the completion blocking_recv, so a queued request at this point forms the stated root→join→completion-sender-in-root cycle. The done oneshot is sent only after owner_main returns and cannot independently release it. PendingThreadJoin Drop preserves the join wait rather than cancelling it; native thread unpark cannot release channel recv.

Important qualification: when TunRoot has already dequeued a request, its inner reset select explicitly observes forced/graceful cancellation and sends NetworkResetBridgeOutcome::Stopped. That path releases the native wait and is not this deadlock. Dropping the completion sender or dropping the queue receiver would also release the wait, but the explicit reap path retains the receiver until after join. A stop observed by owner_main before issuing the request also avoids the cycle. Therefore describe the exact queued/not-yet-serviced interleaving, not every shutdown.

Rollback is not automatically excluded merely because activate has not run. lifecycle/live/session.rs::run_active_session performs underlay/notification/managed-health processing before checking control.active; an inactive prepared owner can enter reset/rebuild and issue a lifecycle request. The ordinary stop checks at owner loop and after quiescence narrow the race window but do not guard the blocking channel wait itself. Native cleanup duration/OS scheduling were not measured; no observed hang is asserted.

## PLAT-02 — Confirmed explicit preparation cancellation/deadline cycle; Drop claims need narrower wording

process/live.rs creates ready_receiver before guard, then checks cancellation and deadline before try_recv. Native owner.rs sends OwnerReady::Ready containing initialization Sender into the sync queue, then initialized.recv waits for a response. The explicit cancellation/deadline return awaits cancel_prepare/prepare_failure(guard) while ready_receiver remains a live local. Ready queued just before that exit therefore retains the sender behind guard.reap. Stop and OwnerWake do not interrupt std::sync::mpsc::Receiver::recv. The native ready sender itself is not the awaited completion sender; dropping it cannot break initialization recv.

Safe existing paths: once Ready is extracted, the deadline branch sends Stopped before reap; the initialization callback select sends Stopped on cancellation or Retry on callback failure before cleanup. If readiness send fails because the outer receiver was dropped, its Ready payload and initialization sender are dropped, allowing initialized.recv to return Stopped. These release paths must remain explicit in the finding.

The explicit early-return await paths are sufficient for the P1 static finding. Do not broaden this to every arbitrary dropped preparation future without establishing the generator's exact live-local destruction order at that suspension point. In particular, a future suspended inside the extracted-Ready callback owns initialization separately, and dropping that sender can release the native wait. No Drop scheduling experiment was performed.

## PLAT-03 — Confirmed error-priority loss; distinguish flag loss from proven residual state

owner.rs Adapter::create Err branch checks stop/shutdown first and returns Stopped; only afterward does it test error.is_cleanup_failure. CreateError contains an explicit cleanup_failed bit, including strict-route-install plus cleanup failure. process/live.rs cancel_prepare emits the supplied cleanup error only for OwnerExit::CleanupFailed; hence the cleanup bit is lost end to end when cancellation overlaps a create failure. No later code in that return branch can recover it.

Platform Adapter::create invokes finish_setup_transaction and then local Adapter Drop can attempt cleanup again. Therefore the original cleanup-failure flag does not by itself prove permanent residue remains after all attempts. The established issue is failure to preserve the terminal cleanup-integrity outcome promised by the contract, not an observed leaked adapter/route. The combined cancellation/error timing remains unexecuted.

## PLAT-04 — Confirmed rollback classification loss; intentional retained callback ownership is not unsafe freeing

windows/core/notification/mod.rs::subscribe_notification_sequence cancels prior handles on a later subscription failure. cancel_notification_handles retains failed handles; leak_notification_owners forgets both handles and callback context. The helper then returns the original subscription Error. This is deliberate lifetime preservation for callbacks, and must not be described as use-after-free.

windows/live/notification.rs::subscribe_network_changes uses this helper directly. In wintun.rs::prepare_managed, NotificationOwners is local until after snapshot_underlay succeeds and self.managed is populated. A snapshot error drops that local owner; NotificationOwners::drop calls close and discards its result. Failed close again retains handle/context intentionally. Since neither failed partial subscription nor this local owner reached self.managed, the outer adapter journal cannot report their close result.

Additional corroboration: core/managed/mod.rs::finish_setup_transaction matches Err(_) and derives CreateError only from the outer cleanup callback and strict-route flag. Thus it would discard a cleanup-kind setup error as well. owner_main retries ordinary creation failures while its starting deadline permits, and ordinary rebuild creation failures enter backoff; repeated retained registrations are a plausible consequence. Their real frequency/count and OS cancellation behavior remain unmeasured. P1 cleanup-contract severity is supportable; no memory-safety exploitation is established.

## C1 — Confirmed public API defect; no demonstrated current product call using the bad tuple

trace/schema.rs Outcome discriminants are Accepted=0 through Timeout=5, Dropped=6; Stage is Config=0 through Shutdown=8, Tun=9. metrics/core.rs OUTCOMES contains six entries and STAGES nine. connection/failure/udp_datagram/udp_failure flatten the public enum discriminants using those shorter lengths. family.rs metric directly indexes the fixed array.

Consequently connection(Client,Socks5,Dropped) index 6 aliases Client/Shadowsocks/Accepted; connection(Server,Shadowsocks,Dropped) index 24 is beyond the 24-entry grid. failure(Client,Tun,reason) aliases Server/Config with that reason; Server/Tun is out of range. UDP grids have the equivalent flaw. This arithmetic does not require a runtime reproduction.

Repository production search for Stage::Tun/Outcome::Dropped found the concrete Tun/Dropped vocabulary in the dedicated tracing emitter and TunDiagnosticReason mapping. TUN Reject uses Outcome::Rejected. No generic Metrics call chain passing the exact dangerous variants was established in this cross-check. Keep P2 public-contract bug wording; do not claim an observed production panic or that Wintun ring-full currently calls the broken generic grid.

## C2 — Confirmed early SOCKS pin can survive budget rejection in the real relay caller

run/socks/association.rs::classify_udp_association selects terminal and checks wire/payload length, then calls endpoint.accept before prepare_udp_for_ingress and forward_udp_request. endpoint.rs accept mutates SocksUdpSourcePin and last_valid. source_pinning.rs admits thereafter requires that port and never clears the pin.

The real proxy preparation in run/egress/udp/association.rs reserves a PendingUdpSession and fixed buffers, returns pending_session: Some, and opens the upstream Shadowsocks socket. First forwarding calls reserve_application_datagram before commit_application_datagram. BufferLimit returns through record_udp_runtime_error, which classifies it as nonterminal and returns true. relay_udp_association continues its loop.

Checked potential escape: runtime udp/manager.rs cancellation(handle) and idle_deadline(handle) use matching_entry without requiring committed=true. Thus a failed first datagram reservation does not automatically make either API fail just because the session is provisional. With no concurrent cancellation, expiry, control close or upstream error, the loop can retain the pinned port; a later different port is rejected by endpoint.receive before decode/admission. This supports C2 rather than merely an early transient assignment that is always immediately dropped.

Scope qualification: if prepare_udp_for_ingress itself fails or activate fails, the whole association returns and does not remain pinned; C2's retained-pin consequence requires successful fixed-resource preparation followed by the nonterminal request reservation failure. The shared-budget schedule was not executed. Existing lifecycle signals/idle expiry eventually terminate the association but do not undo the wrong pin while it is live.

## C3 — Confirmed synthetic DNS loss after frozen Reject on the real existing-association path

run/tun/udp/association.rs run_udp handles synthetic first target before ordinary classification. Ordinary Reject commits candidate into an association and calls run_udp_reject_association. The already-committed synthetic-first→ordinary transition can also enter that Reject handler. The handler owns routing/generation/cancellation/metrics but no SyntheticDns/proxy context, and discards every received datagram with Outcome::Rejected. The Route handler explicitly tests synthetic_dns.matches for every later datagram, confirming the intended per-destination exception exists only on that branch.

Cross-layer path confirmed independently: ferrum2-tun stack/mod.rs enqueue_complete sends parsed UDP to udp.admit; udp/table.rs looks up the slot by endpoints.source, then enqueue_existing sends UdpDatagram with the new endpoints.target to the retained sender. It contains no synthetic-address bypass and existing association admission is not keyed by target. Therefore a later valid same-family synthetic-address:53 query from the same source reaches the Reject handler and is discarded.

Scope qualification: request must pass ordinary packet/family/queue/generation validity and the association must remain live. Expiry, session cancellation, forced cancellation or route generation change can end it, allowing a later fresh candidate; they do not restore synthetic DNS on the retained Reject path. No datagram scenario was executed. C3 remains a P2 behavior-contract finding, not an observed host DNS outage.

## Final cross-check status

All seven requested conclusions have static support with the qualifications above. The material correction is to narrow arbitrary-future-Drop language in PLAT-02 and make the queued-versus-dequeued release paths explicit in PLAT-01/02. C1 remains a public API issue without a demonstrated current production dangerous tuple. No new implementation/design proposal or verification claim is introduced by this cross-check.
