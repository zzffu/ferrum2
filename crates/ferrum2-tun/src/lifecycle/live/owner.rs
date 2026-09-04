use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use ferrum2_net::NetworkSnapshot;

use super::super::reducer::LifecycleReducer;
use super::prepare::{build_adapter_config, wait_owner_delay};
use super::rebuild::{
    OwnerAttempt, PendingFullRebuild, adapter_underlay_is_current,
    request_client_network_lifecycle, request_full_rebuild_transition, start_full_rebuild,
};
use super::reset::{
    NetworkResetHealthDisposition, NetworkResetRefreshOutcome, classify_network_reset_health,
    classify_network_reset_refresh_error, refresh_network_runtime,
};
use super::session::{ActiveSession, SessionExit, run_active_session};
use crate::stack::Stack;
use crate::supervisor::runtime::{NetworkDebounce, RestartBackoff, session_cancellation};
use crate::{
    Config, NetworkResetBridgeOutcome, OwnerControl, OwnerExit, OwnerReady, OwnerSessionServices,
    OwnerWake, TunEvent, TunNetworkLifecycle, TunNetworkResetReason, UdpResponseDropReason,
};

pub(crate) fn owner_main(
    config: Config,
    initial_network_generation: u64,
    control: OwnerControl,
    initial_deadline: std::time::Instant,
    services: OwnerSessionServices,
) -> OwnerExit {
    let OwnerSessionServices {
        ready,
        registry,
        network_catalog,
        events,
        underlay,
        flow_output,
        datagram_output,
        network_lifecycle_output,
        max_udp_associations,
    } = services;
    let adapter_config = match build_adapter_config(&config) {
        Ok(adapter) => adapter,
        Err(_) => {
            let _ = ready.send(OwnerReady::Failed);
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
    let mut backoff = RestartBackoff::default();
    let supervisor_origin = std::time::Instant::now();
    let mut debounce = NetworkDebounce::default();
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
        let mut adapter = if let Some(existing) = existing_adapter {
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
                    if control.stop.load(Ordering::Acquire)
                        || control.shutdown.load(Ordering::Acquire)
                    {
                        let _ = underlay.invalidate();
                        attempt.emit_rebuild_failed(&events);
                        return OwnerExit::Stopped;
                    }
                    if error.is_cleanup_failure() {
                        attempt.emit_rebuild_failed(&events);
                        if let Some(ready) = ready.take() {
                            let _ = ready.send(OwnerReady::Failed);
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
                                .expect("failed creation is a transitioning attempt");
                            continue;
                        }
                    }
                    if let Some(ready) = ready.take() {
                        let _ = ready.send(OwnerReady::Failed);
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
        if let Ok(mut work) = current_work.lock() {
            *work = Some(adapter.work_signal());
        } else {
            if let Some(ready) = ready.take() {
                let _ = ready.send(OwnerReady::Failed);
            }
            return finish_adapter(&current_work, adapter, OwnerExit::RuntimeFailed);
        }

        while attempt.is_rebuilding() && !adapter_underlay_is_current(&adapter) {
            match adapter.refresh_underlay() {
                Ok(_) => {}
                Err(error) => match classify_network_reset_refresh_error(error) {
                    NetworkResetHealthDisposition::Retry => {
                        if !wait_owner_delay(&control, backoff.next_delay()) {
                            attempt.emit_rebuild_failed(&events);
                            return finish_adapter(&current_work, adapter, OwnerExit::Stopped);
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
                        return finish_adapter(&current_work, adapter, exit);
                    }
                    NetworkResetHealthDisposition::Healthy
                    | NetworkResetHealthDisposition::FullRebuild(_) => {
                        unreachable!("refresh errors have an exact retry or terminal disposition")
                    }
                },
            }
        }

        if let Some(reason) = reset_reason
            && !adapter_underlay_is_current(&adapter)
        {
            match refresh_network_runtime(
                &mut adapter,
                &control,
                &mut backoff,
                &events,
                reason,
                false,
            ) {
                NetworkResetRefreshOutcome::Refreshed(reason) => {
                    lifecycle
                        .stage(OwnerAttempt::reset(adapter, reason, false))
                        .expect("refreshed reset stages the next attempt");
                    continue;
                }
                NetworkResetRefreshOutcome::FullRebuild(damage) => {
                    let rebuild = match start_full_rebuild(
                        PendingFullRebuild::new(
                            damage,
                            generation,
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
                            return finish_adapter(&current_work, adapter, exit);
                        }
                    };
                    clear_owner_work(&current_work);
                    if adapter.cleanup().is_err() {
                        rebuild.emit_failed(&events);
                        return OwnerExit::CleanupFailed;
                    }
                    lifecycle
                        .stage(OwnerAttempt::rebuild(rebuild, None))
                        .expect("managed damage stages a rebuild attempt");
                    continue;
                }
                NetworkResetRefreshOutcome::RuntimeFailed => {
                    return finish_adapter(&current_work, adapter, OwnerExit::RuntimeFailed);
                }
                NetworkResetRefreshOutcome::CleanupFailed => {
                    return finish_adapter(&current_work, adapter, OwnerExit::CleanupFailed);
                }
                NetworkResetRefreshOutcome::Stopped => {
                    return finish_adapter(&current_work, adapter, OwnerExit::Stopped);
                }
            }
        }

        let candidate_generation = attempt
            .pending_rebuild()
            .map(|rebuild| rebuild.generation)
            .or_else(|| generation.checked_add(1));
        let Some(candidate_generation) = candidate_generation else {
            attempt.emit_rebuild_failed(&events);
            if let Ok(mut work) = current_work.lock() {
                *work = None;
            }
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
            config.tcp_buffer_bytes,
            config.tcp_timeout,
            Arc::clone(&control.flow_count),
            registry.clone(),
            max_udp_associations,
            config.udp_timeout,
            config.udp_filtering,
            candidate_generation,
            owner_wake.clone(),
        );
        let (mut stack, mut flows, mut datagrams) = match stack {
            Ok(ready_stack) => ready_stack,
            Err(()) => {
                session_cancel_handle.cancel();
                if let Some(reason) = reset_reason {
                    events.emit(TunEvent::NetworkResetFailed(reason));
                    let delay = backoff.next_delay();
                    lifecycle
                        .back_off(
                            OwnerAttempt::reset(adapter, TunNetworkResetReason::Retry, true),
                            delay,
                        )
                        .expect("failed reset stack construction backs off atomically");
                    continue;
                }
                if attempt.is_rebuilding() {
                    clear_owner_work(&current_work);
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
                clear_owner_work(&current_work);
                let cleanup = adapter.cleanup();
                if cleanup.is_err() {
                    if let Some(ready) = ready.take() {
                        let _ = ready.send(OwnerReady::Failed);
                    }
                    return OwnerExit::CleanupFailed;
                }
                if let Some(ready) = ready.take() {
                    let _ = ready.send(OwnerReady::Failed);
                    return OwnerExit::RuntimeFailed;
                }
                let delay = backoff.next_delay();
                lifecycle
                    .back_off(attempt.resume_with(None), delay)
                    .expect("failed startup stack construction preserves startup phase");
                continue;
            }
        };
        stack.set_event_sink(events.clone());
        if attempt.is_starting() && std::time::Instant::now() >= initial_deadline {
            session_cancel_handle.cancel();
            stack.quiesce(
                candidate_generation.saturating_add(1),
                UdpResponseDropReason::OwnerFatal,
            );
            clear_owner_work(&current_work);
            let cleanup = adapter.cleanup();
            if let Some(ready) = ready.take() {
                let _ = ready.send(OwnerReady::Failed);
            }
            return if cleanup.is_err() {
                OwnerExit::CleanupFailed
            } else {
                OwnerExit::RuntimeFailed
            };
        }
        match classify_network_reset_health(adapter.managed_health()) {
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
                if disposition == NetworkResetHealthDisposition::Retry
                    && let Some(reason) = reset_reason
                {
                    let delay = backoff.next_delay();
                    lifecycle
                        .back_off(OwnerAttempt::reset(adapter, reason, false), delay)
                        .expect("transient reset health preserves the logical reset attempt");
                    continue;
                }
                if let Some(reason) = reset_reason {
                    events.emit(TunEvent::NetworkResetFailed(reason));
                }
                if let NetworkResetHealthDisposition::FullRebuild(damage) = disposition
                    && !attempt.is_starting()
                    && !attempt.is_rebuilding()
                {
                    let rebuild = match start_full_rebuild(
                        PendingFullRebuild::new(
                            damage,
                            generation,
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
                            return finish_adapter(&current_work, adapter, exit);
                        }
                    };
                    clear_owner_work(&current_work);
                    if adapter.cleanup().is_err() {
                        rebuild.emit_failed(&events);
                        return OwnerExit::CleanupFailed;
                    }
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
                    return finish_adapter(&current_work, adapter, exit);
                }
                clear_owner_work(&current_work);
                let cleanup = adapter.cleanup();
                if cleanup.is_err() {
                    attempt.emit_rebuild_failed(&events);
                    if let Some(ready) = ready.take() {
                        let _ = ready.send(OwnerReady::Failed);
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
                        let _ = ready.send(OwnerReady::Failed);
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
            && !adapter_underlay_is_current(&adapter)
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
                .stage(OwnerAttempt::reset(adapter, reason, false))
                .expect("stale reset underlay stages the retained adapter");
            continue;
        }
        let snapshot =
            NetworkSnapshot::capture(candidate_generation, &adapter.network_interface_catalog())
                .map(Arc::new);
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
                    let delay = backoff.next_delay();
                    lifecycle
                        .back_off(OwnerAttempt::reset(adapter, reason, false), delay)
                        .expect("snapshot retry preserves the logical reset attempt");
                    continue;
                }
                clear_owner_work(&current_work);
                let cleanup = adapter.cleanup();
                if cleanup.is_err() {
                    attempt.emit_rebuild_failed(&events);
                    if let Some(ready) = ready.take() {
                        let _ = ready.send(OwnerReady::Failed);
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
                        let _ = ready.send(OwnerReady::Failed);
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
        if let Some(reason) = reset_reason {
            let outcome = request_client_network_lifecycle(
                &network_lifecycle_output,
                Arc::clone(&snapshot),
                TunNetworkLifecycle::ResetNetwork(reason),
            );
            if outcome != NetworkResetBridgeOutcome::Completed {
                session_cancel_handle.cancel();
                stack.quiesce(
                    candidate_generation.saturating_add(1),
                    UdpResponseDropReason::SessionReset,
                );
                drop(flows);
                drop(datagrams);
                drop(stack);
                events.emit(TunEvent::NetworkResetFailed(reason));
                let delay = backoff.next_delay();
                lifecycle
                    .back_off(
                        OwnerAttempt::reset(adapter, TunNetworkResetReason::Retry, true),
                        delay,
                    )
                    .expect("lifecycle callback retry preserves reset ownership");
                continue;
            }
        }
        if underlay.publish(adapter.underlay_policy()).is_err() {
            session_cancel_handle.cancel();
            stack.quiesce(
                candidate_generation.saturating_add(1),
                UdpResponseDropReason::OwnerFatal,
            );
            if let Some(reason) = reset_reason {
                events.emit(TunEvent::NetworkResetFailed(reason));
            }
            attempt.emit_rebuild_failed(&events);
            clear_owner_work(&current_work);
            let cleanup = adapter.cleanup();
            if let Some(ready) = ready.take() {
                let _ = ready.send(OwnerReady::Failed);
            }
            return if cleanup.is_err() {
                OwnerExit::CleanupFailed
            } else {
                OwnerExit::RuntimeFailed
            };
        }
        if let Some(reason) = reset_reason
            && !adapter_underlay_is_current(&adapter)
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
                return finish_adapter(&current_work, adapter, OwnerExit::RuntimeFailed);
            }
            lifecycle
                .stage(OwnerAttempt::reset(adapter, reason, false))
                .expect("post-publication reset revalidation preserves the adapter");
            continue;
        }
        if attempt.is_rebuilding() && !adapter_underlay_is_current(&adapter) {
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
                return finish_adapter(&current_work, adapter, OwnerExit::RuntimeFailed);
            }
            lifecycle
                .stage(OwnerAttempt::rebuild(
                    attempt
                        .pending_rebuild()
                        .expect("rebuild attempt retains its metadata"),
                    Some(adapter),
                ))
                .expect("stale rebuilt underlay preserves adapter and rebuild metadata");
            continue;
        }
        if let Some(rebuild) = attempt.pending_rebuild() {
            let outcome = request_full_rebuild_transition(
                &network_lifecycle_output,
                Arc::clone(&snapshot),
                TunNetworkLifecycle::FullRebuildCompleted(rebuild.reason),
                &control,
                &mut backoff,
            );
            if outcome != NetworkResetBridgeOutcome::Completed {
                session_cancel_handle.cancel();
                stack.quiesce(
                    candidate_generation.saturating_add(1),
                    UdpResponseDropReason::OwnerFatal,
                );
                let _ = underlay.invalidate();
                clear_owner_work(&current_work);
                rebuild.emit_failed(&events);
                return finish_adapter(&current_work, adapter, OwnerExit::Stopped);
            }
        }
        if attempt.is_starting() {
            let (initialization, initialized) = std::sync::mpsc::sync_channel(1);
            let sender = ready
                .take()
                .expect("first TUN runtime retains its ready sender");
            if sender
                .send(OwnerReady::Ready {
                    work: owner_wake.clone(),
                    snapshot: Arc::clone(&snapshot),
                    initialization,
                })
                .is_err()
            {
                control.stop.store(true, Ordering::Release);
            }
            let outcome = initialized
                .recv()
                .unwrap_or(NetworkResetBridgeOutcome::Stopped);
            if outcome != NetworkResetBridgeOutcome::Completed {
                session_cancel_handle.cancel();
                stack.quiesce(
                    candidate_generation.saturating_add(1),
                    UdpResponseDropReason::OwnerFatal,
                );
                let _ = underlay.invalidate();
                let exit = if outcome == NetworkResetBridgeOutcome::Stopped {
                    OwnerExit::Stopped
                } else {
                    OwnerExit::RuntimeFailed
                };
                return finish_adapter(&current_work, adapter, exit);
            }
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

        let mut pending_flow = None;
        let mut pending_datagram = None;
        let session_started = std::time::Instant::now();
        debounce.clear();
        let session_exit = run_active_session(&mut ActiveSession {
            adapter: &mut adapter,
            stack: &mut stack,
            flows: &mut flows,
            datagrams: &mut datagrams,
            pending_flow: &mut pending_flow,
            pending_datagram: &mut pending_datagram,
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
        control.admitting.store(false, Ordering::Release);
        events.emit(TunEvent::SessionActive(false));
        let rebuild_tcp_associations = control.flow_count.load(Ordering::Acquire);
        let rebuild_udp_associations = stack.live_udp_associations();
        let underlay_failed = underlay.invalidate().is_err();
        session_cancel_handle.cancel();
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
        if underlay_failed {
            if matches!(session_exit, SessionExit::ResetNetwork { .. }) {
                events.emit(TunEvent::NetworkResetFailed(
                    TunNetworkResetReason::NetworkChange,
                ));
            }
            return finish_adapter(&current_work, adapter, OwnerExit::RuntimeFailed);
        }
        if let SessionExit::Terminal(exit) = session_exit {
            return finish_adapter(&current_work, adapter, exit);
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
            return finish_adapter(&current_work, adapter, OwnerExit::Stopped);
        }
        let damage = match session_exit {
            SessionExit::ResetNetwork { settle_underlay } => match refresh_network_runtime(
                &mut adapter,
                &control,
                &mut backoff,
                &events,
                TunNetworkResetReason::NetworkChange,
                settle_underlay,
            ) {
                NetworkResetRefreshOutcome::Refreshed(reason) => {
                    if session_started.elapsed() >= Duration::from_secs(5) {
                        backoff.reset();
                    }
                    debounce.clear();
                    lifecycle
                        .stage(OwnerAttempt::reset(adapter, reason, false))
                        .expect("active reset stages the retained adapter");
                    continue 'owner;
                }
                NetworkResetRefreshOutcome::FullRebuild(damage) => damage,
                NetworkResetRefreshOutcome::RuntimeFailed => {
                    return finish_adapter(&current_work, adapter, OwnerExit::RuntimeFailed);
                }
                NetworkResetRefreshOutcome::CleanupFailed => {
                    return finish_adapter(&current_work, adapter, OwnerExit::CleanupFailed);
                }
                NetworkResetRefreshOutcome::Stopped => {
                    return finish_adapter(&current_work, adapter, OwnerExit::Stopped);
                }
            },
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
                return finish_adapter(&current_work, adapter, exit);
            }
        };
        clear_owner_work(&current_work);
        if adapter.cleanup().is_err() {
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

fn finish_adapter(
    current_work: &std::sync::Mutex<Option<ferrum2_platform_windows::WorkSignal>>,
    adapter: ferrum2_platform_windows::Adapter,
    clean_exit: OwnerExit,
) -> OwnerExit {
    clear_owner_work(current_work);
    match adapter.cleanup() {
        Ok(()) => clean_exit,
        Err(_) => OwnerExit::CleanupFailed,
    }
}
