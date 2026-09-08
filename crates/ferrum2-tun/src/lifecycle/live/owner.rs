use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferrum2_net::NetworkSnapshot;

use super::super::reducer::LifecycleReducer;
use super::ordinary::{OrdinaryResetOutcome, OrdinaryResetRequest, complete_ordinary_reset};
use super::prepare::{build_adapter_config, wait_owner_delay};
use super::rebuild::{
    OwnerAttempt, PendingFullRebuild, adapter_underlay_is_current, request_full_rebuild_transition,
    start_full_rebuild,
};
use super::reset::{
    NetworkResetHealthDisposition, classify_network_reset_health,
    classify_network_reset_refresh_error,
};
use super::session::{ActiveSession, SessionExit, run_active_session};
use super::tcp_epoch::{TcpEpochError, start as start_tcp_epoch, stop as stop_tcp_epoch};
use crate::stack::Stack;
use crate::supervisor::runtime::{NetworkDebounce, RestartBackoff, session_cancellation};
use crate::system_tcp::PortQuarantine;
use crate::{
    Config, NetworkResetBridgeOutcome, OwnerControl, OwnerExit, OwnerSessionServices, OwnerWake,
    TunEvent, TunNetworkLifecycle, TunNetworkResetReason, UdpResponseDropReason,
};

pub(crate) fn owner_main(
    config: Config,
    initial_network_generation: u64,
    control: OwnerControl,
    initial_deadline: std::time::Instant,
    services: OwnerSessionServices,
) -> OwnerExit {
    let OwnerSessionServices {
        registry,
        udp_buffer_budget,
        runtime,
        network_catalog,
        events,
        underlay,
        flow_output,
        datagram_output,
        network_lifecycle_output,
        max_udp_associations,
    } = services;
    let ready = network_lifecycle_output.clone();
    let adapter_config = match build_adapter_config(&config) {
        Ok(adapter) => adapter,
        Err(_) => {
            ready.close();
            return OwnerExit::RuntimeFailed;
        }
    };
    let current_work = Arc::new(std::sync::Mutex::new(
        None::<ferrum2_platform_windows::WorkSignal>,
    ));
    let signalled_work = Arc::clone(&current_work);
    let owner_thread = std::thread::current();
    let owner_wake = OwnerWake::new(move || {
        if let Ok(work) = signalled_work.lock()
            && let Some(work) = work.as_ref()
        {
            let _ = work.signal();
        }
        owner_thread.unpark();
    });
    let mut ready = Some(ready);
    let mut generation = initial_network_generation;
    let mut completed_reset: Option<Arc<NetworkSnapshot>> = None;
    let mut backoff = RestartBackoff::default();
    let supervisor_origin = std::time::Instant::now();
    let mut debounce = NetworkDebounce::default();
    let port_quarantine = Arc::new(Mutex::new(PortQuarantine::default()));
    let mut lifecycle = LifecycleReducer::starting(OwnerAttempt::Starting);

    'owner: loop {
        if control.stop.load(Ordering::Acquire) || control.shutdown.load(Ordering::Acquire) {
            let _ = underlay.invalidate();
            let cleanup_failed = lifecycle
                .stop()
                .is_some_and(|attempt| attempt.cleanup(&events));
            return if cleanup_failed {
                OwnerExit::CleanupFailed
            } else {
                OwnerExit::Stopped
            };
        }
        let resume = if let Some(delay) = lifecycle.backoff_delay() {
            if !wait_owner_delay(&control, delay) {
                let _ = underlay.invalidate();
                let cleanup_failed = lifecycle
                    .stop()
                    .is_some_and(|attempt| attempt.cleanup(&events));
                return if cleanup_failed {
                    OwnerExit::CleanupFailed
                } else {
                    OwnerExit::Stopped
                };
            }
            lifecycle
                .resume()
                .expect("only backoff state exposes a delay")
        } else {
            lifecycle
                .begin_transition()
                .expect("owner loop begins only a staged transition")
        };
        let (attempt, existing_adapter) = resume.into_transition();
        let reset_reason = attempt.reset_reason();
        if let Some(reason) = attempt.reset_start_pending() {
            events.emit(TunEvent::NetworkResetStarted(reason));
        }
        let deadline = if attempt.is_starting() {
            initial_deadline
        } else {
            std::time::Instant::now()
                .checked_add(config.ready_timeout)
                .unwrap_or_else(std::time::Instant::now)
        };
        let adapter = if let Some(existing) = existing_adapter {
            existing
        } else {
            match ferrum2_platform_windows::Adapter::create(
                adapter_config.clone(),
                deadline,
                &control.stop,
                network_catalog.clone(),
            ) {
                Ok(adapter) => {
                    if config.strict_route {
                        events.emit(TunEvent::StrictRouteFilterInstalled);
                    }
                    adapter
                }
                Err(error) => {
                    if error.is_strict_route_install_failure() {
                        events.emit(TunEvent::StrictRouteFilterInstallFailed);
                    }
                    if error.is_cleanup_failure() {
                        let _ = underlay.invalidate();
                        attempt.emit_rebuild_failed(&events);
                        if let Some(ready) = ready.take() {
                            ready.close();
                        }
                        return OwnerExit::CleanupFailed;
                    }
                    if control.stop.load(Ordering::Acquire)
                        || control.shutdown.load(Ordering::Acquire)
                    {
                        let _ = underlay.invalidate();
                        attempt.emit_rebuild_failed(&events);
                        return OwnerExit::Stopped;
                    }
                    if attempt.is_starting() {
                        let now = std::time::Instant::now();
                        if now < initial_deadline {
                            let delay = backoff
                                .next_delay()
                                .min(initial_deadline.saturating_duration_since(now));
                            lifecycle
                                .back_off(attempt.resume_with(None), delay)
                                .expect("failed creation is a transitioning attempt");
                            continue;
                        }
                    }
                    if let Some(ready) = ready.take() {
                        ready.close();
                        return OwnerExit::RuntimeFailed;
                    }
                    let delay = backoff.next_delay();
                    lifecycle
                        .back_off(attempt.resume_with(None), delay)
                        .expect("failed rebuild creation is a transitioning attempt");
                    continue;
                }
            }
        };
        let mut adapter = AttemptAdapter {
            inner: adapter,
            current_work: &current_work,
        };
        if let Ok(mut work) = current_work.lock() {
            *work = Some(adapter.inner.work_signal());
        } else {
            if let Some(ready) = ready.take() {
                ready.close();
            }
            return adapter.finish(OwnerExit::RuntimeFailed);
        }

        while attempt.is_rebuilding() && !adapter_underlay_is_current(&adapter.inner) {
            match adapter.inner.refresh_underlay() {
                Ok(_) => {}
                Err(error) => match classify_network_reset_refresh_error(error) {
                    NetworkResetHealthDisposition::Retry => {
                        if !wait_owner_delay(&control, backoff.next_delay()) {
                            attempt.emit_rebuild_failed(&events);
                            return adapter.finish(OwnerExit::Stopped);
                        }
                    }
                    NetworkResetHealthDisposition::RuntimeFailed
                    | NetworkResetHealthDisposition::CleanupFailed => {
                        attempt.emit_rebuild_failed(&events);
                        let exit = if matches!(
                            classify_network_reset_refresh_error(error),
                            NetworkResetHealthDisposition::CleanupFailed
                        ) {
                            OwnerExit::CleanupFailed
                        } else {
                            OwnerExit::RuntimeFailed
                        };
                        return adapter.finish(exit);
                    }
                    NetworkResetHealthDisposition::Healthy
                    | NetworkResetHealthDisposition::FullRebuild(_) => {
                        unreachable!("refresh errors have an exact retry or terminal disposition")
                    }
                },
            }
        }

        if let Some(reason) = reset_reason {
            match complete_ordinary_reset(OrdinaryResetRequest {
                adapter: &mut adapter.inner,
                control: &control,
                backoff: &mut backoff,
                events: &events,
                link: &network_lifecycle_output,
                current_generation: generation,
                reason,
                settle_underlay: false,
                completed: completed_reset.as_ref(),
            }) {
                OrdinaryResetOutcome::Completed(snapshot) => completed_reset = Some(snapshot),
                OrdinaryResetOutcome::FullRebuild(damage) => {
                    let rebuild = match start_full_rebuild(
                        PendingFullRebuild::new(
                            damage,
                            completed_reset
                                .as_ref()
                                .map_or(generation, |snapshot| snapshot.generation()),
                            control.flow_count.load(Ordering::Acquire),
                            control.association_count.load(Ordering::Acquire),
                        )
                        .ok_or(OwnerExit::RuntimeFailed),
                        &network_lifecycle_output,
                        &control,
                        &mut backoff,
                        &events,
                    ) {
                        Ok(rebuild) => rebuild,
                        Err(exit) => {
                            return adapter.finish(exit);
                        }
                    };
                    if adapter.cleanup().is_err() {
                        rebuild.emit_failed(&events);
                        return OwnerExit::CleanupFailed;
                    }
                    completed_reset = None;
                    lifecycle
                        .stage(OwnerAttempt::rebuild(rebuild, None))
                        .expect("managed damage stages a rebuild attempt");
                    continue;
                }
                OrdinaryResetOutcome::RuntimeFailed => {
                    return adapter.finish(OwnerExit::RuntimeFailed);
                }
                OrdinaryResetOutcome::CleanupFailed => {
                    return adapter.finish(OwnerExit::CleanupFailed);
                }
                OrdinaryResetOutcome::Stopped => {
                    return adapter.finish(OwnerExit::Stopped);
                }
            }
        }

        let candidate_generation = attempt
            .pending_rebuild()
            .map(|rebuild| rebuild.generation)
            .or_else(|| {
                completed_reset
                    .as_ref()
                    .map(|snapshot| snapshot.generation())
            })
            .or_else(|| generation.checked_add(1));
        let Some(candidate_generation) = candidate_generation else {
            attempt.emit_rebuild_failed(&events);
            return match adapter.cleanup() {
                Ok(()) => OwnerExit::RuntimeFailed,
                Err(_) => OwnerExit::CleanupFailed,
            };
        };
        let (session_cancel_handle, session_cancel) =
            session_cancellation(candidate_generation, owner_wake.clone());
        debug_assert_eq!(session_cancel_handle.generation(), candidate_generation);
        let stack = Stack::new_with_udp(
            (config.ipv4, config.ipv6),
            usize::from(config.mtu),
            config.max_tcp_flows,
            config.tcp_timeout,
            Arc::clone(&control.flow_count),
            registry.clone(),
            max_udp_associations,
            config.udp_timeout,
            config.udp_filtering,
            candidate_generation,
            owner_wake.clone(),
            Arc::clone(&port_quarantine),
        );
        let (mut stack, flows, datagrams) = match stack {
            Ok(ready_stack) => ready_stack,
            Err(()) => {
                session_cancel_handle.cancel();
                if let Some(reason) = reset_reason {
                    events.emit(TunEvent::NetworkResetFailed(reason));
                    let delay = backoff.next_delay();
                    lifecycle
                        .back_off(
                            OwnerAttempt::reset(
                                adapter.retain(),
                                TunNetworkResetReason::Retry,
                                true,
                            ),
                            delay,
                        )
                        .expect("failed reset stack construction backs off atomically");
                    continue;
                }
                if attempt.is_rebuilding() {
                    if adapter.cleanup().is_err() {
                        attempt.emit_rebuild_failed(&events);
                        return OwnerExit::CleanupFailed;
                    }
                    let delay = backoff.next_delay();
                    lifecycle
                        .back_off(attempt.resume_with(None), delay)
                        .expect("failed rebuilt stack construction preserves rebuild ownership");
                    continue;
                }
                let cleanup = adapter.cleanup();
                if cleanup.is_err() {
                    if let Some(ready) = ready.take() {
                        ready.close();
                    }
                    return OwnerExit::CleanupFailed;
                }
                if let Some(ready) = ready.take() {
                    ready.close();
                    return OwnerExit::RuntimeFailed;
                }
                let delay = backoff.next_delay();
                lifecycle
                    .back_off(attempt.resume_with(None), delay)
                    .expect("failed startup stack construction preserves startup phase");
                continue;
            }
        };
        stack.set_udp_buffer_budget(udp_buffer_budget.clone());
        stack.set_event_sink(events.clone());
        if attempt.is_starting() && std::time::Instant::now() >= initial_deadline {
            session_cancel_handle.cancel();
            stack.quiesce(
                candidate_generation.saturating_add(1),
                UdpResponseDropReason::OwnerFatal,
            );
            let cleanup = adapter.cleanup();
            if let Some(ready) = ready.take() {
                ready.close();
            }
            return if cleanup.is_err() {
                OwnerExit::CleanupFailed
            } else {
                OwnerExit::RuntimeFailed
            };
        }
        match classify_network_reset_health(adapter.inner.managed_health()) {
            NetworkResetHealthDisposition::Healthy => {}
            disposition => {
                session_cancel_handle.cancel();
                stack.quiesce(
                    candidate_generation.saturating_add(1),
                    UdpResponseDropReason::SessionReset,
                );
                drop(flows);
                drop(datagrams);
                drop(stack);
                if let Some(reason) = reset_reason {
                    events.emit(TunEvent::NetworkResetFailed(reason));
                }
                if disposition == NetworkResetHealthDisposition::Retry && reset_reason.is_some() {
                    let delay = backoff.next_delay();
                    lifecycle
                        .back_off(
                            OwnerAttempt::reset(
                                adapter.retain(),
                                TunNetworkResetReason::Retry,
                                true,
                            ),
                            delay,
                        )
                        .expect("transient reset health failure preserves the adapter");
                    continue;
                }
                if let NetworkResetHealthDisposition::FullRebuild(damage) = disposition
                    && !attempt.is_starting()
                    && !attempt.is_rebuilding()
                {
                    let rebuild = match start_full_rebuild(
                        PendingFullRebuild::new(
                            damage,
                            completed_reset
                                .as_ref()
                                .map_or(generation, |snapshot| snapshot.generation()),
                            control.flow_count.load(Ordering::Acquire),
                            control.association_count.load(Ordering::Acquire),
                        )
                        .ok_or(OwnerExit::RuntimeFailed),
                        &network_lifecycle_output,
                        &control,
                        &mut backoff,
                        &events,
                    ) {
                        Ok(rebuild) => rebuild,
                        Err(exit) => {
                            return adapter.finish(exit);
                        }
                    };
                    if adapter.cleanup().is_err() {
                        rebuild.emit_failed(&events);
                        return OwnerExit::CleanupFailed;
                    }
                    completed_reset = None;
                    lifecycle
                        .stage(OwnerAttempt::rebuild(rebuild, None))
                        .expect("reset damage stages a full rebuild");
                    continue;
                }
                if matches!(
                    disposition,
                    NetworkResetHealthDisposition::RuntimeFailed
                        | NetworkResetHealthDisposition::CleanupFailed
                ) {
                    attempt.emit_rebuild_failed(&events);
                    let exit = if disposition == NetworkResetHealthDisposition::CleanupFailed {
                        OwnerExit::CleanupFailed
                    } else {
                        OwnerExit::RuntimeFailed
                    };
                    return adapter.finish(exit);
                }
                let cleanup = adapter.cleanup();
                if cleanup.is_err() {
                    attempt.emit_rebuild_failed(&events);
                    if let Some(ready) = ready.take() {
                        ready.close();
                    }
                    return OwnerExit::CleanupFailed;
                }
                if attempt.is_starting() {
                    let now = std::time::Instant::now();
                    if now < initial_deadline {
                        let delay = backoff
                            .next_delay()
                            .min(initial_deadline.saturating_duration_since(now));
                        lifecycle
                            .back_off(attempt.resume_with(None), delay)
                            .expect("startup health retry preserves the startup phase");
                        continue;
                    }
                    if let Some(ready) = ready.take() {
                        ready.close();
                    }
                    return OwnerExit::RuntimeFailed;
                }
                let delay = backoff.next_delay();
                lifecycle
                    .back_off(attempt.resume_with(None), delay)
                    .expect("rebuild health retry preserves rebuild metadata");
                continue;
            }
        }
        if let Some(reason) = reset_reason
            && !adapter_underlay_is_current(&adapter.inner)
        {
            session_cancel_handle.cancel();
            stack.quiesce(
                candidate_generation.saturating_add(1),
                UdpResponseDropReason::SessionReset,
            );
            drop(flows);
            drop(datagrams);
            drop(stack);
            lifecycle
                .stage(OwnerAttempt::reset(adapter.retain(), reason, false))
                .expect("stale reset underlay stages the retained adapter");
            continue;
        }
        let snapshot = if reset_reason.is_some() {
            Ok(Arc::clone(completed_reset.as_ref().expect(
                "ordinary reset completed before stack replacement",
            )))
        } else {
            NetworkSnapshot::capture(
                candidate_generation,
                &adapter.inner.network_interface_catalog(),
            )
            .map(Arc::new)
        };
        let snapshot = match snapshot {
            Ok(snapshot) => snapshot,
            Err(_) => {
                session_cancel_handle.cancel();
                stack.quiesce(
                    candidate_generation.saturating_add(1),
                    UdpResponseDropReason::SessionReset,
                );
                drop(flows);
                drop(datagrams);
                drop(stack);
                if let Some(reason) = reset_reason {
                    events.emit(TunEvent::NetworkResetFailed(reason));
                    let delay = backoff.next_delay();
                    lifecycle
                        .back_off(
                            OwnerAttempt::reset(
                                adapter.retain(),
                                TunNetworkResetReason::Retry,
                                true,
                            ),
                            delay,
                        )
                        .expect("snapshot retry preserves reset ownership");
                    continue;
                }
                let cleanup = adapter.cleanup();
                if cleanup.is_err() {
                    attempt.emit_rebuild_failed(&events);
                    if let Some(ready) = ready.take() {
                        ready.close();
                    }
                    return OwnerExit::CleanupFailed;
                }
                if attempt.is_starting() {
                    let now = std::time::Instant::now();
                    if now < initial_deadline {
                        let delay = backoff
                            .next_delay()
                            .min(initial_deadline.saturating_duration_since(now));
                        lifecycle
                            .back_off(attempt.resume_with(None), delay)
                            .expect("snapshot startup retry preserves startup phase");
                        continue;
                    }
                    if let Some(ready) = ready.take() {
                        ready.close();
                    }
                    return OwnerExit::RuntimeFailed;
                }
                let delay = backoff.next_delay();
                lifecycle
                    .back_off(attempt.resume_with(None), delay)
                    .expect("snapshot rebuild retry preserves rebuild metadata");
                continue;
            }
        };
        if underlay.publish(adapter.inner.underlay_policy()).is_err() {
            session_cancel_handle.cancel();
            stack.quiesce(
                candidate_generation.saturating_add(1),
                UdpResponseDropReason::OwnerFatal,
            );
            if let Some(reason) = reset_reason {
                events.emit(TunEvent::NetworkResetFailed(reason));
            }
            attempt.emit_rebuild_failed(&events);
            let cleanup = adapter.cleanup();
            if let Some(ready) = ready.take() {
                ready.close();
            }
            return if cleanup.is_err() {
                OwnerExit::CleanupFailed
            } else {
                OwnerExit::RuntimeFailed
            };
        }
        if let Some(reason) = reset_reason
            && !adapter_underlay_is_current(&adapter.inner)
        {
            let underlay_failed = underlay.invalidate().is_err();
            session_cancel_handle.cancel();
            stack.quiesce(
                candidate_generation.saturating_add(1),
                UdpResponseDropReason::SessionReset,
            );
            drop(flows);
            drop(datagrams);
            drop(stack);
            if underlay_failed {
                events.emit(TunEvent::NetworkResetFailed(reason));
                return adapter.finish(OwnerExit::RuntimeFailed);
            }
            lifecycle
                .stage(OwnerAttempt::reset(adapter.retain(), reason, false))
                .expect("post-publication reset revalidation preserves the adapter");
            continue;
        }
        if attempt.is_rebuilding() && !adapter_underlay_is_current(&adapter.inner) {
            let underlay_failed = underlay.invalidate().is_err();
            session_cancel_handle.cancel();
            stack.quiesce(
                candidate_generation.saturating_add(1),
                UdpResponseDropReason::SessionReset,
            );
            drop(flows);
            drop(datagrams);
            drop(stack);
            if underlay_failed {
                attempt.emit_rebuild_failed(&events);
                return adapter.finish(OwnerExit::RuntimeFailed);
            }
            lifecycle
                .stage(OwnerAttempt::rebuild(
                    attempt
                        .pending_rebuild()
                        .expect("rebuild attempt retains its metadata"),
                    Some(adapter.retain()),
                ))
                .expect("stale rebuilt underlay preserves adapter and rebuild metadata");
            continue;
        }
        // Observe the shared clock before binding: a failed epoch has no packet loop to
        // advance deferred quarantine, and must still recover once old identities expire.
        let now_millis = i64::try_from(supervisor_origin.elapsed().as_millis()).unwrap_or(i64::MAX);
        stack.expire_deadlines(now_millis);
        if let Err(tcp_error) = start_tcp_epoch(&mut stack, &mut adapter.inner, &runtime) {
            session_cancel_handle.cancel();
            stack.quiesce(
                candidate_generation.saturating_add(1),
                UdpResponseDropReason::OwnerFatal,
            );
            drop(flows);
            drop(datagrams);
            drop(stack);
            let underlay_failed = underlay.invalidate().is_err();
            if tcp_error == TcpEpochError::Cleanup || underlay_failed {
                if let Some(reason) = reset_reason {
                    events.emit(TunEvent::NetworkResetFailed(reason));
                }
                attempt.emit_rebuild_failed(&events);
                if let Some(ready) = ready.take() {
                    ready.close();
                }
                let exit = if tcp_error == TcpEpochError::Cleanup {
                    OwnerExit::CleanupFailed
                } else {
                    OwnerExit::RuntimeFailed
                };
                return adapter.finish(exit);
            }
            if let Some(reason) = reset_reason {
                events.emit(TunEvent::NetworkResetFailed(reason));
                let delay = backoff.next_delay();
                lifecycle
                    .back_off(
                        OwnerAttempt::reset(adapter.retain(), TunNetworkResetReason::Retry, true),
                        delay,
                    )
                    .expect("failed TCP reset epoch backs off with the retained adapter");
                continue;
            }
            if attempt.is_rebuilding() {
                if adapter.cleanup().is_err() {
                    attempt.emit_rebuild_failed(&events);
                    return OwnerExit::CleanupFailed;
                }
                let delay = backoff.next_delay();
                lifecycle
                    .back_off(attempt.resume_with(None), delay)
                    .expect("failed rebuilt TCP epoch preserves rebuild ownership");
                continue;
            }
            if adapter.cleanup().is_err() {
                if let Some(ready) = ready.take() {
                    ready.close();
                }
                return OwnerExit::CleanupFailed;
            }
            let now = std::time::Instant::now();
            if now < initial_deadline {
                let delay = backoff
                    .next_delay()
                    .min(initial_deadline.saturating_duration_since(now));
                lifecycle
                    .back_off(attempt.resume_with(None), delay)
                    .expect("failed startup TCP epoch preserves startup ownership");
                continue;
            }
            if let Some(ready) = ready.take() {
                ready.close();
            }
            return OwnerExit::RuntimeFailed;
        }
        let mut epoch = ActiveEpoch {
            adapter,
            stack,
            flows,
            datagrams,
            pending_flow: None,
            pending_datagram: None,
            cancellation: session_cancel_handle,
            generation: candidate_generation,
            control: &control,
            events: &events,
            underlay: &underlay,
            supervisor_origin,
        };
        if let Some(rebuild) = attempt.pending_rebuild() {
            let outcome = request_full_rebuild_transition(
                &network_lifecycle_output,
                Arc::clone(&snapshot),
                TunNetworkLifecycle::FullRebuildCompleted(rebuild.reason),
                &control,
                &mut backoff,
            );
            if outcome != NetworkResetBridgeOutcome::Completed {
                let exit = epoch.abort(OwnerExit::Stopped);
                rebuild.emit_failed(&events);
                return exit;
            }
        }
        if attempt.is_starting() {
            let outcome = network_lifecycle_output.request(
                Arc::clone(&snapshot),
                crate::TunNetworkLifecycle::Initialize,
            );
            if outcome != NetworkResetBridgeOutcome::Completed {
                let exit = if outcome == NetworkResetBridgeOutcome::Stopped {
                    OwnerExit::Stopped
                } else {
                    OwnerExit::RuntimeFailed
                };
                return epoch.abort(exit);
            }
        }
        if epoch.stack.tcp_failed() {
            if let Some(reason) = reset_reason {
                events.emit(TunEvent::NetworkResetFailed(reason));
            }
            attempt.emit_rebuild_failed(&events);
            if let Some(ready) = ready.take() {
                ready.close();
            }
            return epoch.abort(OwnerExit::RuntimeFailed);
        }
        if attempt.is_starting() {
            if std::time::Instant::now() >= initial_deadline {
                return epoch.abort(OwnerExit::RuntimeFailed);
            }
            ready
                .take()
                .expect("first runtime retains readiness")
                .prepared(owner_wake.clone());
        }
        generation = candidate_generation;
        events.emit(TunEvent::SessionGeneration(generation));
        events.emit(TunEvent::SessionActive(true));
        lifecycle
            .activate()
            .expect("completed setup activates only a transitioning attempt");
        if attempt.is_starting() {
            events.emit(TunEvent::SessionStarted);
        } else if let Some(reason) = reset_reason {
            events.emit(TunEvent::NetworkResetSucceeded(reason));
        } else {
            attempt.emit_rebuild_succeeded(&events);
        }
        control.admitting.store(
            control.active.load(Ordering::Acquire)
                && !control.shutdown.load(Ordering::Acquire)
                && !control.stop.load(Ordering::Acquire),
            Ordering::Release,
        );

        // The epoch retains all queues until retirement has fenced and quiesced them.
        let session_started = std::time::Instant::now();
        debounce.clear();
        let session_exit = run_active_session(&mut ActiveSession {
            adapter: &mut epoch.adapter.inner,
            stack: &mut epoch.stack,
            flows: &mut epoch.flows,
            datagrams: &mut epoch.datagrams,
            pending_flow: &mut epoch.pending_flow,
            pending_datagram: &mut epoch.pending_datagram,
            control: &control,
            flow_output: &flow_output,
            datagram_output: &datagram_output,
            cancellation: &session_cancel,
            events: &events,
            supervisor_origin,
            debounce: &mut debounce,
            audit_managed_dns: config.ipv4_dns_address.is_some()
                || config.ipv6_dns_address.is_some(),
        });
        let mut retired = epoch.retire(session_exit, |adapter, settle_underlay| {
            complete_ordinary_reset(OrdinaryResetRequest {
                adapter,
                control: &control,
                backoff: &mut backoff,
                events: &events,
                link: &network_lifecycle_output,
                current_generation: generation,
                reason: TunNetworkResetReason::NetworkChange,
                settle_underlay,
                completed: None,
            })
        });
        completed_reset = retired.completed_reset.take();
        let rebuild_tcp_associations = retired.tcp_associations;
        let rebuild_udp_associations = retired.udp_associations;
        let session_exit = retired.exit;
        let underlay_failed = retired.underlay_failed;
        if let SessionExit::Terminal(exit) = session_exit {
            return retired.finish(exit);
        }
        if underlay_failed {
            if matches!(session_exit, SessionExit::ResetNetwork { .. }) {
                events.emit(TunEvent::NetworkResetFailed(
                    TunNetworkResetReason::NetworkChange,
                ));
            }
            return retired.finish(OwnerExit::RuntimeFailed);
        }
        if control.stop.load(Ordering::Acquire)
            || control.shutdown.load(Ordering::Acquire)
            || matches!(session_exit, SessionExit::Stopped)
        {
            if matches!(session_exit, SessionExit::ResetNetwork { .. }) {
                events.emit(TunEvent::NetworkResetFailed(
                    TunNetworkResetReason::NetworkChange,
                ));
            }
            return retired.finish(OwnerExit::Stopped);
        }
        let damage = match session_exit {
            SessionExit::ResetNetwork { .. } => {
                debug_assert!(completed_reset.is_some());
                if session_started.elapsed() >= Duration::from_secs(5) {
                    backoff.reset();
                }
                debounce.clear();
                lifecycle
                    .stage(OwnerAttempt::reset(
                        retired.retain(),
                        TunNetworkResetReason::NetworkChange,
                        false,
                    ))
                    .expect("completed reset retains its adapter and immutable snapshot");
                continue 'owner;
            }
            SessionExit::FullRebuild(damage) => damage,
            SessionExit::Stopped | SessionExit::Terminal(_) => {
                unreachable!("stopped and terminal sessions exit before rebuild dispatch")
            }
        };
        let rebuild = match start_full_rebuild(
            PendingFullRebuild::new(
                damage,
                generation,
                rebuild_tcp_associations,
                rebuild_udp_associations,
            )
            .ok_or(OwnerExit::RuntimeFailed),
            &network_lifecycle_output,
            &control,
            &mut backoff,
            &events,
        ) {
            Ok(rebuild) => rebuild,
            Err(exit) => {
                return retired.finish(exit);
            }
        };
        if retired.cleanup().is_err() {
            rebuild.emit_failed(&events);
            return OwnerExit::CleanupFailed;
        }
        if session_started.elapsed() >= Duration::from_secs(5) {
            backoff.reset();
        }
        debounce.clear();
        lifecycle
            .stage(OwnerAttempt::rebuild(rebuild, None))
            .expect("active managed damage stages a rebuild");
        continue 'owner;
    }
}

fn clear_owner_work(current_work: &std::sync::Mutex<Option<ferrum2_platform_windows::WorkSignal>>) {
    if let Ok(mut work) = current_work.lock() {
        *work = None;
    }
}

/// The preparation/rebuild attempt owns its managed identities and the published
/// work signal together. Consuming cleanup cannot leave a stale adapter wakeup;
/// retaining transfers identities back to the reducer without cleaning them.
#[must_use = "managed identities must be retained or explicitly cleaned up"]
struct AttemptAdapter<'a> {
    inner: ferrum2_platform_windows::Adapter,
    current_work: &'a Mutex<Option<ferrum2_platform_windows::WorkSignal>>,
}

impl AttemptAdapter<'_> {
    fn cleanup(self) -> Result<(), ()> {
        clear_owner_work(self.current_work);
        self.inner.cleanup().map_err(|_| ())
    }

    fn finish(self, clean_exit: OwnerExit) -> OwnerExit {
        match self.cleanup() {
            Ok(()) => clean_exit,
            Err(()) => OwnerExit::CleanupFailed,
        }
    }

    fn retain(self) -> ferrum2_platform_windows::Adapter {
        self.inner
    }
}

/// Owns a successfully bound TCP epoch, including the queues that can still
/// contain identities from that epoch. It can only leave through abort or retire;
/// neither path delegates fallible network cleanup to Drop.
#[must_use = "a bound epoch must be explicitly aborted or retired"]
struct ActiveEpoch<'a> {
    adapter: AttemptAdapter<'a>,
    stack: Stack,
    flows: tokio::sync::mpsc::Receiver<crate::TcpFlow>,
    datagrams: tokio::sync::mpsc::Receiver<crate::UdpCandidate>,
    pending_flow: Option<crate::TcpFlow>,
    pending_datagram: Option<crate::UdpCandidate>,
    cancellation: crate::supervisor::runtime::SessionCancelHandle,
    generation: u64,
    control: &'a OwnerControl,
    events: &'a crate::TunEventSink,
    underlay: &'a crate::UnderlayPublisher,
    supervisor_origin: std::time::Instant,
}

/// TCP and queued traffic have been retired. Only the managed adapter remains:
/// a reset may retain its identities, while a rebuild or exit must consume cleanup.
#[must_use = "a retired epoch must retain or clean up its managed adapter"]
struct RetiredEpoch<'a> {
    adapter: AttemptAdapter<'a>,
    exit: SessionExit,
    underlay_failed: bool,
    completed_reset: Option<Arc<NetworkSnapshot>>,
    tcp_associations: usize,
    udp_associations: usize,
}

impl<'a> ActiveEpoch<'a> {
    fn abort(mut self, exit: OwnerExit) -> OwnerExit {
        self.cancellation.cancel();
        let next = self.generation.saturating_add(1);
        let _ = self.stack.fence_generation(next);
        let tcp_cleanup_failed = stop_tcp_epoch(&mut self.stack, &mut self.adapter.inner).is_err();
        self.stack.quiesce(next, UdpResponseDropReason::OwnerFatal);
        let _ = self.underlay.invalidate();
        self.adapter.finish(if tcp_cleanup_failed {
            OwnerExit::CleanupFailed
        } else {
            exit
        })
    }
    fn retire(
        self,
        session_exit: SessionExit,
        reset: impl FnOnce(&mut ferrum2_platform_windows::Adapter, bool) -> OrdinaryResetOutcome,
    ) -> RetiredEpoch<'a> {
        let Self {
            mut adapter,
            mut stack,
            flows,
            datagrams,
            pending_flow,
            pending_datagram,
            cancellation,
            generation,
            control,
            events,
            underlay,
            supervisor_origin,
        } = self;
        let mut completed_reset = None;
        control.admitting.store(false, Ordering::Release);
        events.emit(TunEvent::SessionActive(false));
        let tcp_associations = control.flow_count.load(Ordering::Acquire);
        let udp_associations = stack.live_udp_associations();
        let underlay_failed = underlay.invalidate().is_err();
        let mut session_exit = session_exit;
        let mut tcp_epoch_stop_attempted = false;
        if !underlay_failed
            && !control.stop.load(Ordering::Acquire)
            && !control.shutdown.load(Ordering::Acquire)
            && let SessionExit::ResetNetwork { settle_underlay } = session_exit
        {
            // Polling and admission are paused. Fence published flows before the reset
            // barrier, then close and join listener work before clearing its ingress guard.
            let fenced = generation
                .checked_add(1)
                .ok_or(())
                .and_then(|next| stack.fence_generation(next));
            if fenced.is_err() {
                session_exit = SessionExit::Terminal(OwnerExit::RuntimeFailed);
            } else {
                tcp_epoch_stop_attempted = true;
                let notified = super::tcp_epoch::drain_fenced(
                    &mut stack,
                    &mut adapter.inner,
                    supervisor_origin,
                    events,
                );
                if stop_tcp_epoch(&mut stack, &mut adapter.inner).is_err() {
                    session_exit = SessionExit::Terminal(OwnerExit::CleanupFailed);
                } else if notified.is_err() {
                    session_exit = SessionExit::Terminal(OwnerExit::RuntimeFailed);
                } else {
                    cancellation.cancel();
                    match reset(&mut adapter.inner, settle_underlay) {
                        OrdinaryResetOutcome::Completed(snapshot) => {
                            completed_reset = Some(snapshot)
                        }
                        OrdinaryResetOutcome::FullRebuild(damage) => {
                            session_exit = SessionExit::FullRebuild(damage)
                        }
                        OrdinaryResetOutcome::RuntimeFailed => {
                            session_exit = SessionExit::Terminal(OwnerExit::RuntimeFailed)
                        }
                        OrdinaryResetOutcome::CleanupFailed => {
                            session_exit = SessionExit::Terminal(OwnerExit::CleanupFailed)
                        }
                        OrdinaryResetOutcome::Stopped => session_exit = SessionExit::Stopped,
                    }
                }
            }
        }
        if stack
            .fence_generation(generation.saturating_add(1))
            .is_err()
            && !matches!(
                session_exit,
                SessionExit::Terminal(OwnerExit::CleanupFailed)
            )
        {
            session_exit = SessionExit::Terminal(OwnerExit::RuntimeFailed);
        }
        cancellation.cancel();
        if !tcp_epoch_stop_attempted {
            let notified = super::tcp_epoch::drain_fenced(
                &mut stack,
                &mut adapter.inner,
                supervisor_origin,
                events,
            );
            if stop_tcp_epoch(&mut stack, &mut adapter.inner).is_err() {
                session_exit = SessionExit::Terminal(OwnerExit::CleanupFailed);
            } else if notified.is_err()
                && !matches!(
                    session_exit,
                    SessionExit::Terminal(OwnerExit::CleanupFailed)
                )
            {
                session_exit = SessionExit::Terminal(OwnerExit::RuntimeFailed);
            }
        }
        let teardown_now =
            i64::try_from(supervisor_origin.elapsed().as_millis()).unwrap_or(i64::MAX);
        let _ = stack.expire_deadlines(teardown_now);
        let response_drop_reason =
            if underlay_failed || matches!(session_exit, SessionExit::Terminal(_)) {
                UdpResponseDropReason::OwnerFatal
            } else {
                match session_exit {
                    SessionExit::ResetNetwork { .. } | SessionExit::FullRebuild(_) => {
                        UdpResponseDropReason::SessionReset
                    }
                    SessionExit::Stopped => UdpResponseDropReason::Shutdown,
                    SessionExit::Terminal(_) => unreachable!("terminal sessions are owner-fatal"),
                }
            };
        stack.quiesce(generation.saturating_add(1), response_drop_reason);
        control.association_count.store(0, Ordering::Release);
        drop(pending_flow);
        drop(pending_datagram);
        drop(flows);
        drop(datagrams);
        drop(stack);
        RetiredEpoch {
            adapter,
            exit: session_exit,
            underlay_failed,
            completed_reset,
            tcp_associations,
            udp_associations,
        }
    }
}

impl RetiredEpoch<'_> {
    fn finish(self, exit: OwnerExit) -> OwnerExit {
        self.adapter.finish(exit)
    }

    fn cleanup(self) -> Result<(), ()> {
        self.adapter.cleanup()
    }

    fn retain(self) -> ferrum2_platform_windows::Adapter {
        self.adapter.retain()
    }
}
