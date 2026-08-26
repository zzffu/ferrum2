use std::io;
use std::sync::Arc;

use ferrum2_crypto::Clock as _;
use ferrum2_observability::{Direction, Outcome, Reason, Role, Stage};
use ferrum2_runtime::{
    DirectUdpSocketFactory, MAX_UDP_WIRE_DATAGRAM_BYTES, PreparedProcessRoot, ProcessCancellation,
    ProcessFuture, UdpCommitError, UdpRuntimeError,
};
use ferrum2_shadowsocks::UdpPacketError;

use crate::run::observation::{
    record_udp_failure, record_udp_protocol_failure, record_udp_request_accepted,
    record_udp_runtime_failure, update_udp_resource_metrics,
};
use crate::run::routing::ServerTerminalRoute;
use crate::run::{RunError, run_error_for_rule_compile};

use super::admission::{
    PreparedUdpServer, protocol_identity_has_capacity, reconcile_udp_generations,
    resolve_udp_selection_candidates,
};
use super::commit::{
    NewDirectCommitError, commit_existing_direct_request, commit_new_direct_session,
    commit_rejected_request,
};
use super::listener::{MAX_UDP_LISTENER_READINESS_DRAIN, ServerUdpListener, ServerUdpRuntime};
use super::physical::ServerUdpNetworkPolicy;
use super::route::select_udp_route;

impl<L, SF> PreparedUdpServer<L, SF>
where
    L: ServerUdpListener,
    SF: DirectUdpSocketFactory<OpenContext = Option<ServerUdpNetworkPolicy>>,
{
    async fn run_with_cancellation(
        self,
        mut cancellation: ProcessCancellation,
    ) -> Result<(), RunError> {
        let shutdown_cancellation = cancellation.clone();
        self.run_with_shutdown(
            async move { cancellation.cancelled().await },
            move |runtime| runtime.shutdown_with_cancellation(shutdown_cancellation),
        )
        .await
    }

    pub(super) async fn run_with_shutdown<S, C, F>(
        self,
        shutdown: S,
        shutdown_runtime: C,
    ) -> Result<(), RunError>
    where
        S: std::future::Future<Output = ()>,
        C: FnOnce(ServerUdpRuntime<L, SF>) -> F,
        F: std::future::Future<Output = usize>,
    {
        let Self {
            inbound,
            routing,
            listener,
            protocol,
            clock,
            config,
            registry,
            metrics,
            direct_resolvers,
            connect_timeout,
            network_policies,
            mut runtime,
            mappings,
            admission,
            mut route_scratch,
            mut scratch,
            mut wire,
            mut maintenance,
            _receive_scratch,
            _receive_wire,
        } = self;
        maintenance.tick().await;
        let mut removals = runtime.sessions().subscribe_removals();
        tokio::pin!(shutdown);
        let mut readiness_drain = 0;

        let terminal = 'packets: loop {
            if readiness_drain == MAX_UDP_LISTENER_READINESS_DRAIN {
                readiness_drain = 0;
                tokio::select! {
                    biased;
                    _ = &mut shutdown => break Ok(()),
                    _ = tokio::task::yield_now() => {}
                }
            }
            wire.clear();
            let received = if readiness_drain == 0 {
                tokio::select! {
                    biased;
                    _ = &mut shutdown => break Ok(()),
                    _ = maintenance.tick() => {
                        let maintenance_guard = tokio::select! {
                            biased;
                            _ = &mut shutdown => break Ok(()),
                            guard = admission.lock() => guard,
                        };
                        mappings.prune_protocol(&protocol, clock.monotonic_now());
                        drop(maintenance_guard);
                        update_udp_resource_metrics(&metrics, &registry);
                        continue;
                    }
                    removed = removals.recv() => {
                        match removed {
                            Ok(handle) => mappings.invalidate_handle(handle),
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                                reconcile_udp_generations(&runtime, &mappings);
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                break Err(RunError::RuntimeRoot);
                            }
                        }
                        continue;
                    }
                    received = listener.recv_buf_from(&mut wire) => received,
                }
            } else {
                match listener.try_recv_buf_from(&mut wire) {
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        readiness_drain = 0;
                        continue;
                    }
                    received => received,
                }
            };
            let (wire_len, peer) = match received {
                Ok(received)
                    if received.0 == wire.len() && received.0 <= MAX_UDP_WIRE_DATAGRAM_BYTES =>
                {
                    received
                }
                Ok(_) | Err(_) => {
                    record_udp_failure(&metrics, Stage::Listen, Reason::Receive, Outcome::Failed);
                    break Err(RunError::RuntimeListener);
                }
            };
            readiness_drain += 1;
            let wire = wire.as_ref();
            let pending = match protocol.prepare_request(clock.as_ref(), wire, &mut scratch) {
                Ok(pending) => pending,
                Err(error) => {
                    record_udp_protocol_failure(&metrics, error);
                    continue;
                }
            };
            // The shared gate protects only protocol/mapping observations and their
            // synchronous commit. In particular, it is never held while a provisional
            // runtime session opens its socket below.
            let admission_guard = tokio::select! {
                biased;
                _ = &mut shutdown => break Ok(()),
                guard = admission.lock() => guard,
            };
            let existing = match protocol.existing_capability(&pending) {
                Ok(existing) => existing,
                Err(error) => {
                    record_udp_protocol_failure(&metrics, error);
                    break Err(RunError::RuntimeRoot);
                }
            };
            let terminal = if let Some(capability) = existing {
                let Some(identity) = mappings.identity(capability) else {
                    // Authenticated protocol state without a frozen routing identity
                    // cannot safely be routed again.
                    record_udp_protocol_failure(&metrics, UdpPacketError::Binding);
                    continue;
                };
                if identity.inbound != inbound {
                    record_udp_protocol_failure(&metrics, UdpPacketError::Binding);
                    continue;
                }
                identity.terminal
            } else {
                match protocol_identity_has_capacity(
                    &runtime,
                    &mappings,
                    &protocol,
                    &clock,
                    config.max_sessions,
                ) {
                    Ok(false) => {
                        record_udp_runtime_failure(&metrics, UdpRuntimeError::SessionLimit);
                        continue;
                    }
                    Ok(true) => {}
                    Err(error) => {
                        record_udp_protocol_failure(&metrics, error);
                        break Err(RunError::RuntimeRoot);
                    }
                }
                select_udp_route(
                    &routing,
                    inbound,
                    pending.datagram().target(),
                    pending.datagram().payload(),
                    &metrics,
                    &mut route_scratch,
                )
                .map_err(run_error_for_rule_compile)?
            };
            if terminal == ServerTerminalRoute::Reject {
                match commit_rejected_request(
                    &protocol,
                    &mappings,
                    pending,
                    existing,
                    peer,
                    clock.monotonic_now(),
                    inbound,
                ) {
                    Ok(()) => metrics.udp_datagram(
                        Role::Server,
                        Direction::ClientToTarget,
                        Outcome::Rejected,
                    ),
                    Err(error) => record_udp_protocol_failure(&metrics, error),
                }
                continue;
            }
            if let Some((capability, binding)) = existing.and_then(|capability| {
                mappings
                    .handle(capability)
                    .map(|binding| (capability, binding))
            }) {
                if binding.inbound != inbound {
                    record_udp_protocol_failure(&metrics, UdpPacketError::Binding);
                    continue;
                }
                let ServerTerminalRoute::Direct(_) = terminal else {
                    unreachable!("rejected UDP route returned before direct session reuse")
                };
                let handle = binding.handle;
                let reserved =
                    runtime.reserve_datagram(handle, pending.datagram().allocated_capacity());
                match reserved {
                    Ok(reservation) => {
                        // QA-M2-T02-N01: replay/peer/activity advances only
                        // while T03 holds this generation/queue reservation.
                        let committed = commit_existing_direct_request(
                            &protocol,
                            &mappings,
                            reservation,
                            pending,
                            capability,
                            handle,
                            peer,
                            &clock,
                        );
                        match committed {
                            Ok(()) => record_udp_request_accepted(&metrics, wire_len),
                            Err(UdpCommitError::Runtime(error)) => {
                                record_udp_runtime_failure(&metrics, error);
                            }
                            Err(UdpCommitError::Protocol(error)) => {
                                record_udp_protocol_failure(&metrics, error);
                            }
                        }
                        continue;
                    }
                    Err(UdpRuntimeError::Cancelled) => {
                        mappings.invalidate_handle(handle);
                    }
                    Err(error) => {
                        record_udp_runtime_failure(&metrics, error);
                        continue;
                    }
                }
            }

            drop(admission_guard);
            let ServerTerminalRoute::Direct(outbound) = terminal else {
                unreachable!("rejected UDP route returned before direct session admission")
            };
            let mut outbound = outbound;
            'open_direct: loop {
                let Some(session_resolver) = direct_resolvers
                    .get(outbound)
                    .cloned()
                    .map(|resolver| resolver.for_inbound(inbound))
                else {
                    record_udp_failure(
                        &metrics,
                        Stage::Config,
                        Reason::ConfigSemantic,
                        Outcome::Failed,
                    );
                    continue 'packets;
                };
                let selection_target = pending.datagram().target().clone();
                let initial_candidates = tokio::select! {
                    biased;
                    _ = &mut shutdown => break 'packets Ok(()),
                    selection = resolve_udp_selection_candidates(
                        &session_resolver,
                        &selection_target,
                        connect_timeout,
                    ) => selection,
                };
                let initial_candidates = match initial_candidates {
                    Ok(candidates) => candidates,
                    Err(error) => {
                        record_udp_runtime_failure(&metrics, error);
                        continue 'packets;
                    }
                };
                let open_context = if let Some(policies) = network_policies.as_ref() {
                    let Some(outbound_policy) =
                        policies.outbound_dial_options.get(outbound).cloned()
                    else {
                        record_udp_failure(
                            &metrics,
                            Stage::Config,
                            Reason::ConfigSemantic,
                            Outcome::Failed,
                        );
                        continue 'packets;
                    };
                    Some(ServerUdpNetworkPolicy {
                        outbound: outbound_policy,
                        route: Arc::clone(&policies.route_network),
                    })
                } else {
                    None
                };
                let provisional = tokio::select! {
                    biased;
                    _ = &mut shutdown => break 'packets Ok(()),
                    provisional = runtime.reserve_session_with_initial_candidates(
                        tokio::time::Instant::now(),
                        pending.datagram().allocated_capacity(),
                        open_context,
                        initial_candidates,
                    ) => provisional,
                };
                let provisional = match provisional {
                    Ok(admission) => admission,
                    Err(error) => {
                        record_udp_runtime_failure(&metrics, error);
                        continue 'packets;
                    }
                };

                // A concurrent first packet may have frozen this identity while the
                // provisional socket was opening. The winner's terminal governs the
                // losing packet; only an orphaned, different Direct requires reopening.
                let admission_guard = tokio::select! {
                    biased;
                    _ = &mut shutdown => break 'packets Ok(()),
                    guard = admission.lock() => guard,
                };
                let existing = match protocol.existing_capability(&pending) {
                    Ok(existing) => existing,
                    Err(error) => {
                        record_udp_protocol_failure(&metrics, error);
                        break 'packets Err(RunError::RuntimeRoot);
                    }
                };
                if let Some(capability) = existing {
                    let Some(identity) = mappings.identity(capability) else {
                        drop(provisional);
                        record_udp_protocol_failure(&metrics, UdpPacketError::Binding);
                        continue 'packets;
                    };
                    if identity.inbound != inbound {
                        drop(provisional);
                        record_udp_protocol_failure(&metrics, UdpPacketError::Binding);
                        continue 'packets;
                    }
                    match identity.terminal {
                        ServerTerminalRoute::Reject => {
                            drop(provisional);
                            match commit_rejected_request(
                                &protocol,
                                &mappings,
                                pending,
                                Some(capability),
                                peer,
                                clock.monotonic_now(),
                                inbound,
                            ) {
                                Ok(()) => metrics.udp_datagram(
                                    Role::Server,
                                    Direction::ClientToTarget,
                                    Outcome::Rejected,
                                ),
                                Err(error) => record_udp_protocol_failure(&metrics, error),
                            }
                            continue 'packets;
                        }
                        ServerTerminalRoute::Direct(frozen_outbound) => {
                            if let Some(binding) = mappings.handle(capability) {
                                match runtime.reserve_datagram(
                                    binding.handle,
                                    pending.datagram().allocated_capacity(),
                                ) {
                                    Ok(reservation) => {
                                        drop(provisional);
                                        let committed = commit_existing_direct_request(
                                            &protocol,
                                            &mappings,
                                            reservation,
                                            pending,
                                            capability,
                                            binding.handle,
                                            peer,
                                            &clock,
                                        );
                                        match committed {
                                            Ok(()) => {
                                                record_udp_request_accepted(&metrics, wire_len)
                                            }
                                            Err(UdpCommitError::Runtime(error)) => {
                                                record_udp_runtime_failure(&metrics, error);
                                            }
                                            Err(UdpCommitError::Protocol(error)) => {
                                                record_udp_protocol_failure(&metrics, error);
                                            }
                                        }
                                        continue 'packets;
                                    }
                                    Err(UdpRuntimeError::Cancelled) => {
                                        mappings.invalidate_handle(binding.handle);
                                    }
                                    Err(error) => {
                                        drop(provisional);
                                        record_udp_runtime_failure(&metrics, error);
                                        continue 'packets;
                                    }
                                }
                            }
                            if frozen_outbound != outbound {
                                drop(provisional);
                                drop(admission_guard);
                                outbound = frozen_outbound;
                                continue 'open_direct;
                            }
                        }
                    }
                } else {
                    match protocol_identity_has_capacity(
                        &runtime,
                        &mappings,
                        &protocol,
                        &clock,
                        config.max_sessions,
                    ) {
                        Ok(false) => {
                            drop(provisional);
                            record_udp_runtime_failure(&metrics, UdpRuntimeError::SessionLimit);
                            continue 'packets;
                        }
                        Ok(true) => {}
                        Err(error) => {
                            drop(provisional);
                            record_udp_protocol_failure(&metrics, error);
                            break 'packets Err(RunError::RuntimeRoot);
                        }
                    }
                }
                let committed = commit_new_direct_session(
                    &mut runtime,
                    provisional,
                    pending,
                    session_resolver,
                    &protocol,
                    &mappings,
                    peer,
                    &clock,
                    inbound,
                    outbound,
                );
                match committed {
                    Ok(_) => {
                        record_udp_request_accepted(&metrics, wire_len);
                    }
                    Err(NewDirectCommitError::Runtime(error)) => {
                        record_udp_runtime_failure(&metrics, error)
                    }
                    Err(NewDirectCommitError::Protocol(error)) => {
                        record_udp_protocol_failure(&metrics, error)
                    }
                    Err(NewDirectCommitError::Identity) => {
                        record_udp_protocol_failure(&metrics, UdpPacketError::Generation);
                        break 'packets Err(RunError::RuntimeRoot);
                    }
                }
                drop(admission_guard);
                update_udp_resource_metrics(&metrics, &registry);
                continue 'packets;
            }
        };

        let forced = if terminal.is_err() {
            runtime.shutdown(std::time::Duration::ZERO).await
        } else {
            shutdown_runtime(runtime).await
        };
        for _ in 0..forced {
            metrics.udp_forced_shutdown(Role::Server);
        }
        update_udp_resource_metrics(&metrics, &registry);
        terminal
    }
}

impl<L, F> PreparedProcessRoot<RunError> for PreparedUdpServer<L, F>
where
    L: ServerUdpListener,
    F: DirectUdpSocketFactory<OpenContext = Option<ServerUdpNetworkPolicy>>,
{
    fn activate(&mut self) -> Result<(), RunError> {
        Ok(())
    }

    fn run(
        self: Box<Self>,
        cancellation: ProcessCancellation,
    ) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async move { self.run_with_cancellation(cancellation).await })
    }

    fn rollback(self: Box<Self>) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async { Ok(()) })
    }
}
