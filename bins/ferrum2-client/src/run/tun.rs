use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use ferrum2_config::TunConfig;
use ferrum2_core::TargetAddr;
use ferrum2_core::route::{EgressPlanSnapshot, Network};
use ferrum2_dns::{DnsProxy, ProxyIngress, ProxyTransport};
use ferrum2_observability::{
    Direction, Metrics, NetworkLifecycleOperation, NetworkLifecycleResult, NetworkResetReason,
    Outcome, Role, Transport, TunDiagnosticReason, TunIpFamily, TunPacketRejectReason,
    TunUdpResponseDropReason, emit_tun_diagnostic,
};
use ferrum2_runtime::{
    NetworkResetCoordinator, NetworkResetHookRegistration, NetworkResetHookStage,
    NetworkResetIntent, NetworkResetLimits, NetworkResetOutcome,
    NetworkResetReason as RuntimeNetworkResetReason, NetworkRuntimeOwnerKind, NetworkSnapshot,
    NetworkSnapshotPublisher, ProcessCancellation, ProcessRoot, ResetNetwork, relay_lifecycle,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;

use super::RunError;
use super::context::{ClientContext, ClientRouting};
use super::egress::{
    ClientRequestOrigin, ClientUdpAssociation, UdpPlanResponseError, composed_udp_plan_limit,
};
use super::routing::{
    ClientTerminalRoute, ReplayIo, RouteGeneration, RouteGenerationChange, relay_hijacked_tcp,
};
use super::tokio_io::TokioFramed;

pub(super) fn process_root(
    config: TunConfig,
    udp_idle_timeout: Duration,
    context: Arc<ClientContext>,
    routing: Arc<ClientRouting>,
    inbound: usize,
    underlay: ferrum2_tun::UnderlayPublisher,
    direct_binder: bool,
) -> ProcessRoot<RunError> {
    let strict_route = config.strict_route_effective();
    let synthetic_dns = SyntheticDns {
        ipv4: config.ipv4_dns_address,
        ipv6: config.ipv6_dns_address,
    };
    let metrics = Arc::clone(&context.metrics);
    let network_reset = Arc::new(OnceLock::new());
    let handler_context = Arc::clone(&context);
    let udp_context = Arc::clone(&context);
    let reset_context = Arc::clone(&context);
    let tcp_routing = Arc::clone(&routing);
    let tcp_network_reset = Arc::clone(&network_reset);
    let udp_network_reset = Arc::clone(&network_reset);
    let reset_driver = Arc::clone(&network_reset);
    ferrum2_tun::process_root(
        ferrum2_tun::Config {
            adapter_name: config.adapter_name,
            ipv4: config
                .ipv4_address
                .map(|network| (network.addr(), network.prefix_len())),
            ipv6: config
                .ipv6_address
                .map(|network| (network.addr(), network.prefix_len())),
            mtu: config.mtu,
            ring_capacity: config.ring_capacity,
            ready_timeout: config.ready_timeout,
            max_tcp_flows: config.max_tcp_flows,
            tcp_buffer_bytes: config.tcp_buffer_bytes,
            tcp_timeout: context.runtime.idle_timeout,
            udp_timeout: udp_idle_timeout,
            max_udp_mappings: config.max_udp_mappings,
            udp_filtering: match config.udp_filtering {
                ferrum2_config::UdpFiltering::AddressDependent => {
                    ferrum2_tun::UdpFiltering::AddressDependent
                }
                ferrum2_config::UdpFiltering::EndpointIndependent => {
                    ferrum2_tun::UdpFiltering::EndpointIndependent
                }
            },
            capture_routes: config
                .capture_routes
                .into_iter()
                .map(|route| (route.network(), route.prefix_len()))
                .collect(),
            physical_endpoints: config.physical_endpoints,
            default_binder: direct_binder,
            ipv4_dns_address: synthetic_dns.ipv4,
            ipv6_dns_address: synthetic_dns.ipv6,
            strict_route,
        },
        underlay,
        RunError::StartupProtocol,
        RunError::RuntimeRoot,
        RunError::ShutdownCleanup,
        context.registry.clone(),
        move |flow, cancellation, session_cancellation| {
            let context = Arc::clone(&handler_context);
            let routing = Arc::clone(&tcp_routing);
            let network_reset = Arc::clone(&tcp_network_reset);
            Box::pin(async move {
                let network_reset = Arc::clone(
                    network_reset
                        .get_or_init(|| Arc::new(ClientNetworkResetRuntime::new(&context))),
                );
                let generation = network_reset.coordinator.status().published_generation();
                let Ok(mut owner) = network_reset
                    .coordinator
                    .register_runtime_owner(generation, NetworkRuntimeOwnerKind::TcpConnection)
                else {
                    return;
                };
                tokio::select! {
                    _ = owner.cancelled() => {}
                    _ = run_tcp(
                        flow.target(),
                        flow,
                        cancellation,
                        context,
                        routing,
                        inbound,
                        synthetic_dns,
                        Some(session_cancellation),
                    ) => {}
                }
            })
        },
        move |candidate, cancellation, session_cancellation| {
            let context = Arc::clone(&udp_context);
            let routing = Arc::clone(&routing);
            let network_reset = Arc::clone(&udp_network_reset);
            Box::pin(async move {
                let network_reset = Arc::clone(
                    network_reset
                        .get_or_init(|| Arc::new(ClientNetworkResetRuntime::new(&context))),
                );
                let generation = network_reset.coordinator.status().published_generation();
                let Ok(mut owner) = network_reset
                    .coordinator
                    .register_runtime_owner(generation, NetworkRuntimeOwnerKind::UdpAssociation)
                else {
                    return;
                };
                tokio::select! {
                    _ = owner.cancelled() => {}
                    _ = run_udp(
                        candidate,
                        cancellation,
                        context,
                        routing,
                        inbound,
                        synthetic_dns,
                        session_cancellation,
                    ) => {}
                }
            })
        },
        move |snapshot, reason| {
            let network_reset = Arc::clone(
                reset_driver
                    .get_or_init(|| Arc::new(ClientNetworkResetRuntime::new(&reset_context))),
            );
            Box::pin(async move { network_reset.reset(snapshot, reason).await })
        },
        move |event| record_tun_event(&metrics, event),
    )
}

type ClientNetworkResetAction = Arc<dyn Fn(u64) -> Result<(), ()> + Send + Sync>;

struct ClientNetworkResetHook {
    accepted_generation: AtomicU64,
    action: ClientNetworkResetAction,
}

impl ClientNetworkResetHook {
    fn new(initial_generation: u64, action: ClientNetworkResetAction) -> Self {
        Self {
            accepted_generation: AtomicU64::new(initial_generation),
            action,
        }
    }
}

impl ResetNetwork for ClientNetworkResetHook {
    fn reset_network(
        &self,
        snapshot: Arc<NetworkSnapshot>,
    ) -> ferrum2_runtime::NetworkResetFuture<'_> {
        Box::pin(async move {
            let generation = snapshot.generation();
            let current = self.accepted_generation.load(Ordering::Acquire);
            if generation < current {
                return Err(ferrum2_runtime::NetworkResetError);
            }
            if generation == current {
                return Ok(());
            }
            (self.action)(generation).map_err(|()| ferrum2_runtime::NetworkResetError)?;
            self.accepted_generation
                .store(generation, Ordering::Release);
            Ok(())
        })
    }
}

struct ClientNetworkResetRuntime {
    coordinator: NetworkResetCoordinator,
    _registrations: [NetworkResetHookRegistration; 4],
}

impl ClientNetworkResetRuntime {
    fn new(context: &Arc<ClientContext>) -> Self {
        const INITIAL_GENERATION: u64 = 1;

        let initial = Arc::new(
            NetworkSnapshot::new(INITIAL_GENERATION, None, None)
                .expect("empty initial client network snapshot is valid"),
        );
        let coordinator = NetworkResetCoordinator::new(
            NetworkSnapshotPublisher::new(initial),
            NetworkResetLimits::default(),
            context.registry.clone(),
        );
        let accept: ClientNetworkResetAction = Arc::new(|_| Ok(()));
        // The owner has already constructed the stack when it crosses the bounded bridge.
        // Router and inbound listeners retain no interface-bound cache today, so their hooks are
        // generation acceptance barriers. Outbound owns the shared UDP sessions (including DNS
        // UDP egress) and cancels them below; TUN TCP work is acknowledged by runtime owners.
        let stack = Arc::new(ClientNetworkResetHook::new(
            INITIAL_GENERATION,
            Arc::clone(&accept),
        ));
        let router = Arc::new(ClientNetworkResetHook::new(
            INITIAL_GENERATION,
            Arc::clone(&accept),
        ));
        let egress = Arc::clone(&context.egress);
        let reset_metrics = Arc::clone(&context.metrics);
        let outbound = Arc::new(ClientNetworkResetHook::new(
            INITIAL_GENERATION,
            Arc::new(move |_| {
                let udp_associations = egress.reset_network();
                reset_metrics.network_associations_reset(
                    NetworkLifecycleOperation::ResetNetwork,
                    Transport::Udp,
                    udp_associations,
                );
                Ok(())
            }),
        ));
        let metrics = Arc::clone(&context.metrics);
        let inbound_dns = Arc::new(ClientNetworkResetHook::new(
            INITIAL_GENERATION,
            Arc::new(move |generation| {
                metrics.set_network_generation(generation);
                Ok(())
            }),
        ));
        let registrations = [
            coordinator
                .register_reset_hook(NetworkResetHookStage::Stack, stack)
                .expect("fresh client reset coordinator accepts stack hook"),
            coordinator
                .register_reset_hook(NetworkResetHookStage::Router, router)
                .expect("fresh client reset coordinator accepts router hook"),
            coordinator
                .register_reset_hook(NetworkResetHookStage::Outbound, outbound)
                .expect("fresh client reset coordinator accepts outbound hook"),
            coordinator
                .register_reset_hook(NetworkResetHookStage::Inbound, inbound_dns)
                .expect("fresh client reset coordinator accepts inbound/DNS hook"),
        ];
        Self {
            coordinator,
            _registrations: registrations,
        }
    }

    async fn reset(
        &self,
        snapshot: Arc<NetworkSnapshot>,
        reason: ferrum2_tun::TunNetworkResetReason,
    ) -> Result<(), ferrum2_tun::TunNetworkResetError> {
        let reason = match reason {
            ferrum2_tun::TunNetworkResetReason::NetworkChange => {
                RuntimeNetworkResetReason::InterfaceChanged
            }
            ferrum2_tun::TunNetworkResetReason::Retry => RuntimeNetworkResetReason::ExplicitRequest,
        };
        let report = self
            .coordinator
            .reset_network(snapshot, NetworkResetIntent::Ordinary(reason))
            .await
            .map_err(|_| ferrum2_tun::TunNetworkResetError)?;
        match report.outcome() {
            NetworkResetOutcome::Noop | NetworkResetOutcome::ResetCompleted => Ok(()),
            NetworkResetOutcome::FullRebuildRequired(_)
            | NetworkResetOutcome::FullRebuildAcknowledged => {
                Err(ferrum2_tun::TunNetworkResetError)
            }
        }
    }
}

fn record_tun_event(metrics: &Metrics, event: ferrum2_tun::TunEvent) {
    use ferrum2_tun::TunEvent;

    match event {
        TunEvent::PacketAccepted => metrics.tun_packet_accepted(),
        TunEvent::PacketFoundationDropped => metrics.tun_packet_foundation_dropped(),
        TunEvent::SessionStarted => metrics.tun_session_started(),
        TunEvent::NetworkResetStarted(reason) => metrics.network_reset(
            map_network_reset_reason(reason),
            NetworkLifecycleResult::Started,
        ),
        TunEvent::NetworkResetSucceeded(reason) => metrics.network_reset(
            map_network_reset_reason(reason),
            NetworkLifecycleResult::Succeeded,
        ),
        TunEvent::NetworkResetFailed(reason) => metrics.network_reset(
            map_network_reset_reason(reason),
            NetworkLifecycleResult::Failed,
        ),
        TunEvent::SessionRestartStarted => metrics.tun_session_restart_started(),
        TunEvent::SessionRestartSucceeded => metrics.tun_session_restart_succeeded(),
        TunEvent::SessionRestartFailed => metrics.tun_session_restart_failed(),
        TunEvent::SessionGeneration(generation) => {
            metrics.set_tun_session_generation(generation);
        }
        TunEvent::SessionActive(active) => metrics.set_tun_session_active(active),
        TunEvent::PacketIngress => metrics.tun_packet_ingress(),
        TunEvent::PacketEgress => metrics.tun_packet_egress(),
        TunEvent::PacketRejected(reason) => metrics.tun_packet_rejected(match reason {
            ferrum2_tun::TunRejectReason::InvalidIpVersion => {
                TunPacketRejectReason::InvalidIpVersion
            }
            ferrum2_tun::TunRejectReason::FamilyDisabled => TunPacketRejectReason::FamilyDisabled,
            ferrum2_tun::TunRejectReason::InvalidIpLength => TunPacketRejectReason::InvalidIpLength,
            ferrum2_tun::TunRejectReason::InvalidIpChecksum => {
                TunPacketRejectReason::InvalidIpChecksum
            }
            ferrum2_tun::TunRejectReason::InvalidExtensionHeader => {
                TunPacketRejectReason::InvalidExtensionHeader
            }
            ferrum2_tun::TunRejectReason::UnsupportedIpProtocol => {
                TunPacketRejectReason::UnsupportedIpProtocol
            }
            ferrum2_tun::TunRejectReason::IcmpEchoUnsupported => {
                TunPacketRejectReason::IcmpEchoUnsupported
            }
            ferrum2_tun::TunRejectReason::FragmentMalformed => {
                TunPacketRejectReason::FragmentMalformed
            }
            ferrum2_tun::TunRejectReason::FragmentOverlap => TunPacketRejectReason::FragmentOverlap,
            ferrum2_tun::TunRejectReason::FragmentTimeout => TunPacketRejectReason::FragmentTimeout,
            ferrum2_tun::TunRejectReason::FragmentLimit => TunPacketRejectReason::FragmentLimit,
            ferrum2_tun::TunRejectReason::InvalidTransportLength => {
                TunPacketRejectReason::InvalidTransportLength
            }
            ferrum2_tun::TunRejectReason::InvalidTransportChecksum => {
                TunPacketRejectReason::InvalidTransportChecksum
            }
            ferrum2_tun::TunRejectReason::InvalidSource => TunPacketRejectReason::InvalidSource,
            ferrum2_tun::TunRejectReason::InvalidDestination => {
                TunPacketRejectReason::InvalidDestination
            }
            ferrum2_tun::TunRejectReason::IngressFull => TunPacketRejectReason::IngressFull,
            ferrum2_tun::TunRejectReason::TcpFlowLimit => TunPacketRejectReason::TcpFlowLimit,
            ferrum2_tun::TunRejectReason::UdpAssociationLimit => {
                TunPacketRejectReason::UdpAssociationLimit
            }
            ferrum2_tun::TunRejectReason::UdpCandidateTimeout => {
                TunPacketRejectReason::UdpCandidateTimeout
            }
            ferrum2_tun::TunRejectReason::UdpQueueFull => TunPacketRejectReason::UdpQueueFull,
            ferrum2_tun::TunRejectReason::UdpResponseFiltered => {
                TunPacketRejectReason::UdpResponseFiltered
            }
            ferrum2_tun::TunRejectReason::UdpResponseClosed => {
                TunPacketRejectReason::UdpResponseClosed
            }
            ferrum2_tun::TunRejectReason::StaleGeneration => TunPacketRejectReason::StaleGeneration,
            ferrum2_tun::TunRejectReason::WintunRingFull => TunPacketRejectReason::WintunRingFull,
        }),
        TunEvent::InternalEgressBackpressured => metrics.tun_internal_egress_backpressured(),
        TunEvent::WintunRingFullDropped => metrics.tun_wintun_ring_full_dropped(),
        TunEvent::TcpFlowsActive(flows) => metrics.set_tun_tcp_flows_active(flows),
        TunEvent::TcpFlowRejectedLimit => metrics.tun_tcp_flow_rejected_limit(),
        TunEvent::TcpFlowResetRestart => metrics.tun_tcp_flow_reset_restart(),
        TunEvent::TcpBridgeBlocked => metrics.tun_tcp_bridge_blocked(),
        TunEvent::UdpAssociationsActive(associations) => {
            metrics.set_tun_udp_associations_active(associations);
        }
        TunEvent::UdpCandidatesActive(candidates) => {
            metrics.set_tun_udp_candidates_active(candidates);
        }
        TunEvent::UdpAssociationCreated => metrics.tun_udp_association_created(),
        TunEvent::UdpAssociationRejectedLimit => metrics.tun_udp_association_rejected_limit(),
        TunEvent::UdpDatagramQueueFull => metrics.tun_udp_datagram_queue_full(),
        TunEvent::UdpResponseQueueFull => metrics.tun_udp_response_queue_full(),
        TunEvent::UdpResponseFiltered => metrics.tun_udp_response_filtered(),
        TunEvent::UdpResponseDropped(reason) => metrics.tun_udp_response_dropped(match reason {
            ferrum2_tun::UdpResponseDropReason::StaleGeneration => {
                TunUdpResponseDropReason::StaleGeneration
            }
            ferrum2_tun::UdpResponseDropReason::AssociationClosed => {
                TunUdpResponseDropReason::AssociationClosed
            }
            ferrum2_tun::UdpResponseDropReason::QueueFull => TunUdpResponseDropReason::QueueFull,
            ferrum2_tun::UdpResponseDropReason::MalformedResponse => {
                TunUdpResponseDropReason::MalformedResponse
            }
            ferrum2_tun::UdpResponseDropReason::Filtered => TunUdpResponseDropReason::Filtered,
            ferrum2_tun::UdpResponseDropReason::InjectionRejected => {
                TunUdpResponseDropReason::InjectionRejected
            }
            ferrum2_tun::UdpResponseDropReason::SessionReset => {
                TunUdpResponseDropReason::SessionReset
            }
            ferrum2_tun::UdpResponseDropReason::Shutdown => TunUdpResponseDropReason::Shutdown,
            ferrum2_tun::UdpResponseDropReason::OwnerFatal => TunUdpResponseDropReason::OwnerFatal,
        }),
        TunEvent::UdpPendingResponses(responses) => {
            metrics.set_tun_pending_udp_responses(responses);
        }
        TunEvent::UdpStaleGeneration => metrics.tun_udp_stale_generation(),
        TunEvent::ReassemblyEntriesActive(entries) => {
            metrics.set_tun_reassembly_entries_active(entries);
        }
        TunEvent::ReassemblyStarted => metrics.tun_reassembly_started(),
        TunEvent::ReassemblyCompleted => metrics.tun_reassembly_completed(),
        TunEvent::ReassemblyDroppedOverlap => metrics.tun_reassembly_dropped_overlap(),
        TunEvent::ReassemblyDroppedTimeout => metrics.tun_reassembly_dropped_timeout(),
        TunEvent::ReassemblyDroppedLimit => metrics.tun_reassembly_dropped_limit(),
        TunEvent::ReassemblyDroppedMalformed => metrics.tun_reassembly_dropped_malformed(),
        TunEvent::NetworkChange => metrics.tun_network_change(),
        TunEvent::UnderlayBindStale => metrics.tun_underlay_bind_stale(),
        TunEvent::Diagnostic { reason, family } => emit_tun_diagnostic(
            Role::Client,
            match reason {
                ferrum2_tun::TunDiagnosticReason::WintunRingFull => {
                    TunDiagnosticReason::WintunRingFull
                }
            },
            match family {
                ferrum2_tun::TunIpFamily::Ipv4 => TunIpFamily::Ipv4,
                ferrum2_tun::TunIpFamily::Ipv6 => TunIpFamily::Ipv6,
            },
        ),
    }
}

const fn map_network_reset_reason(
    reason: ferrum2_tun::TunNetworkResetReason,
) -> NetworkResetReason {
    match reason {
        ferrum2_tun::TunNetworkResetReason::NetworkChange => NetworkResetReason::NetworkChange,
        ferrum2_tun::TunNetworkResetReason::Retry => NetworkResetReason::Retry,
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SyntheticDns {
    ipv4: Option<std::net::Ipv4Addr>,
    ipv6: Option<std::net::Ipv6Addr>,
}

impl SyntheticDns {
    fn matches(self, target: SocketAddr) -> bool {
        match target {
            SocketAddr::V4(target) => target.port() == 53 && Some(*target.ip()) == self.ipv4,
            SocketAddr::V6(target) => target.port() == 53 && Some(*target.ip()) == self.ipv6,
        }
    }
}

#[derive(Clone)]
enum TunUdpPlan {
    Route {
        snapshot: EgressPlanSnapshot,
        request_payload_bound: usize,
    },
    SyntheticDns,
    HijackDns,
    Reject,
}

const fn target_payload_within_bound(payload_len: usize, payload_bound: usize) -> bool {
    payload_len <= payload_bound
}

async fn run_udp(
    candidate: ferrum2_tun::UdpCandidate,
    cancellation: ProcessCancellation,
    context: Arc<ClientContext>,
    routing: Arc<ClientRouting>,
    inbound: usize,
    synthetic_dns: SyntheticDns,
    session_cancellation: ferrum2_tun::SessionCancellation,
) {
    let first_target = candidate.first_target();
    let Ok(first_application_target) = TargetAddr::ip(first_target) else {
        return;
    };
    if synthetic_dns.matches(first_target) {
        run_udp_synthetic_candidate(
            candidate,
            cancellation,
            context,
            routing,
            inbound,
            synthetic_dns,
            session_cancellation,
        )
        .await;
        return;
    }
    let Ok(mut route_scratch) = routing.route_scratch() else {
        return;
    };
    let first_request = TunUdpRouteRequest {
        routing: &routing,
        inbound,
        synthetic_dns,
        target: &first_application_target,
        payload: candidate.first_payload(),
        metrics: &context.metrics,
    };
    let Ok((route_generation, plan)) =
        select_udp_target_generation_stable(first_request, route_scratch.as_mut())
    else {
        return;
    };
    let route_change = routing.watch_route_generation_from(route_generation);
    run_udp_first_ordinary_candidate(
        candidate,
        route_generation,
        route_change,
        plan,
        cancellation,
        context,
        routing,
        inbound,
        synthetic_dns,
        session_cancellation,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn run_udp_synthetic_candidate(
    candidate: ferrum2_tun::UdpCandidate,
    cancellation: ProcessCancellation,
    context: Arc<ClientContext>,
    routing: Arc<ClientRouting>,
    inbound: usize,
    synthetic_dns: SyntheticDns,
    session_cancellation: ferrum2_tun::SessionCancellation,
) {
    let Some(proxy) = tun_dns_proxy(&context) else {
        return;
    };
    let packet_payload_bound = candidate.packet_payload_bound();
    let Ok(mut association) = candidate
        .commit_association_with_payload_bound(packet_payload_bound)
        .await
    else {
        return;
    };
    let response_sink = association.response_sink();
    let peer_policy = association.peer_policy();

    loop {
        let mut forced = cancellation.clone();
        let datagram = tokio::select! {
            () = forced.forced() => return,
            () = session_cancellation.cancelled() => return,
            datagram = association.receive() => datagram,
        };
        let Some(datagram) = datagram else {
            return;
        };
        if synthetic_dns.matches(datagram.target()) {
            if !answer_tun_udp_dns(
                datagram,
                &proxy,
                inbound,
                &cancellation,
                &session_cancellation,
                None,
                None,
                &routing,
                &response_sink,
                &peer_policy,
            )
            .await
            {
                return;
            }
            continue;
        }

        let Ok(mut route_scratch) = routing.route_scratch() else {
            return;
        };
        let Ok(target) = TargetAddr::ip(datagram.target()) else {
            return;
        };
        let request = TunUdpRouteRequest {
            routing: &routing,
            inbound,
            synthetic_dns,
            target: &target,
            payload: datagram.payload(),
            metrics: &context.metrics,
        };
        let Ok((route_generation, plan)) =
            select_udp_target_generation_stable(request, route_scratch.as_mut())
        else {
            return;
        };
        let route_change = routing.watch_route_generation_from(route_generation);
        run_udp_committed_plan(
            association,
            datagram,
            route_generation,
            route_change,
            plan,
            cancellation,
            context,
            routing,
            inbound,
            synthetic_dns,
            session_cancellation,
            proxy,
        )
        .await;
        return;
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_udp_first_ordinary_candidate(
    candidate: ferrum2_tun::UdpCandidate,
    route_generation: RouteGeneration,
    mut route_change: RouteGenerationChange,
    plan: TunUdpPlan,
    cancellation: ProcessCancellation,
    context: Arc<ClientContext>,
    routing: Arc<ClientRouting>,
    inbound: usize,
    synthetic_dns: SyntheticDns,
    session_cancellation: ferrum2_tun::SessionCancellation,
) {
    match plan {
        TunUdpPlan::Route {
            snapshot,
            request_payload_bound,
        } => {
            if !target_payload_within_bound(candidate.first_payload().len(), request_payload_bound)
            {
                return;
            }
            let Some(mut egress) = prepare_tun_udp_egress(
                &cancellation,
                &session_cancellation,
                &context,
                &routing,
                inbound,
                candidate.first_target(),
                route_generation,
                &mut route_change,
                snapshot,
            )
            .await
            else {
                return;
            };
            // The sink retains the TUN packet ceiling because later synthetic DNS answers share
            // this source association. Proxy decoding enforces its own per-packet response bound.
            let Ok(association) = candidate.commit_association().await else {
                return;
            };
            if !udp_route_generation_is_current(&routing, route_generation) {
                return;
            }
            run_udp_route_association(
                association,
                None,
                route_generation,
                route_change,
                request_payload_bound,
                cancellation,
                session_cancellation,
                context,
                routing,
                inbound,
                synthetic_dns,
                &mut egress,
            )
            .await;
        }
        TunUdpPlan::HijackDns => {
            let Some(proxy) = tun_dns_proxy(&context) else {
                return;
            };
            if !udp_route_generation_is_current(&routing, route_generation) {
                return;
            }
            let Ok(association) = candidate.commit_association().await else {
                return;
            };
            run_udp_dns_association(
                association,
                None,
                route_generation,
                route_change,
                cancellation,
                session_cancellation,
                routing,
                inbound,
                proxy,
            )
            .await;
        }
        TunUdpPlan::Reject => {
            if !udp_route_generation_is_current(&routing, route_generation) {
                return;
            }
            let Ok(association) = candidate.commit_association().await else {
                return;
            };
            run_udp_reject_association(
                association,
                route_generation,
                route_change,
                cancellation,
                session_cancellation,
                routing,
                &context.metrics,
            )
            .await;
        }
        TunUdpPlan::SyntheticDns => {}
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_udp_committed_plan(
    association: ferrum2_tun::UdpAssociation,
    first_datagram: ferrum2_tun::UdpDatagram,
    route_generation: RouteGeneration,
    mut route_change: RouteGenerationChange,
    plan: TunUdpPlan,
    cancellation: ProcessCancellation,
    context: Arc<ClientContext>,
    routing: Arc<ClientRouting>,
    inbound: usize,
    synthetic_dns: SyntheticDns,
    session_cancellation: ferrum2_tun::SessionCancellation,
    proxy: Arc<DnsProxy>,
) {
    match plan {
        TunUdpPlan::Route {
            snapshot,
            request_payload_bound,
            ..
        } => {
            if !target_payload_within_bound(first_datagram.payload().len(), request_payload_bound) {
                return;
            }
            let Some(mut egress) = prepare_tun_udp_egress(
                &cancellation,
                &session_cancellation,
                &context,
                &routing,
                inbound,
                first_datagram.target(),
                route_generation,
                &mut route_change,
                snapshot,
            )
            .await
            else {
                return;
            };
            run_udp_route_association(
                association,
                Some(first_datagram),
                route_generation,
                route_change,
                request_payload_bound,
                cancellation,
                session_cancellation,
                context,
                routing,
                inbound,
                synthetic_dns,
                &mut egress,
            )
            .await;
        }
        TunUdpPlan::HijackDns => {
            run_udp_dns_association(
                association,
                Some(first_datagram),
                route_generation,
                route_change,
                cancellation,
                session_cancellation,
                routing,
                inbound,
                proxy,
            )
            .await;
        }
        TunUdpPlan::Reject => {
            run_udp_reject_association(
                association,
                route_generation,
                route_change,
                cancellation,
                session_cancellation,
                routing,
                &context.metrics,
            )
            .await;
        }
        TunUdpPlan::SyntheticDns => {}
    }
}

#[derive(Clone, Copy)]
struct TunUdpRouteRequest<'a> {
    routing: &'a ClientRouting,
    inbound: usize,
    synthetic_dns: SyntheticDns,
    target: &'a TargetAddr,
    payload: &'a [u8],
    metrics: &'a ferrum2_observability::Metrics,
}

fn select_udp_target_generation_stable(
    request: TunUdpRouteRequest<'_>,
    scratch: Option<&mut ferrum2_rule::RuleEvaluationScratch>,
) -> Result<(RouteGeneration, TunUdpPlan), ferrum2_rule::RuleCompileError> {
    let before = request.routing.route_generation();
    let plan = select_udp_target_with_scratch(request, scratch)?;
    let after = request.routing.route_generation();
    if before == after {
        return Ok((after, plan));
    }
    Err(ferrum2_rule::RuleCompileError::Internal)
}

fn select_udp_target_with_scratch(
    request: TunUdpRouteRequest<'_>,
    scratch: Option<&mut ferrum2_rule::RuleEvaluationScratch>,
) -> Result<TunUdpPlan, ferrum2_rule::RuleCompileError> {
    if is_synthetic_dns_target(request.target, request.synthetic_dns) {
        return Ok(TunUdpPlan::SyntheticDns);
    }
    let terminal = request.routing.select_terminal_with_scratch(
        request.inbound,
        Network::Udp,
        request.target,
        Some(request.payload),
        request.metrics,
        scratch,
    )?;
    let selected = match terminal {
        ClientTerminalRoute::Route(plan) => {
            let Some(target) = request.target.as_socket_addr() else {
                return Ok(TunUdpPlan::Reject);
            };
            let encoded_target_len = match target {
                SocketAddr::V4(_) => 7,
                SocketAddr::V6(_) => 19,
            };
            let request_payload_bound = composed_udp_plan_limit(
                &request.routing.outbounds,
                plan.hops(),
                false,
                encoded_target_len,
            );
            TunUdpPlan::Route {
                snapshot: plan,
                request_payload_bound,
            }
        }
        ClientTerminalRoute::HijackDns => TunUdpPlan::HijackDns,
        ClientTerminalRoute::Reject => TunUdpPlan::Reject,
    };
    Ok(selected)
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn select_udp_target(
    routing: &ClientRouting,
    inbound: usize,
    ipv4_dns_address: Option<std::net::Ipv4Addr>,
    ipv6_dns_address: Option<std::net::Ipv6Addr>,
    target: &TargetAddr,
    payload: &[u8],
    _response_payload_bound: usize,
    metrics: &ferrum2_observability::Metrics,
) -> Option<TunUdpPlan> {
    let mut scratch = routing.route_scratch().ok().flatten();
    select_udp_target_with_scratch(
        TunUdpRouteRequest {
            routing,
            inbound,
            synthetic_dns: SyntheticDns {
                ipv4: ipv4_dns_address,
                ipv6: ipv6_dns_address,
            },
            target,
            payload,
            metrics,
        },
        scratch.as_mut(),
    )
    .ok()
}

fn tun_dns_proxy(context: &ClientContext) -> Option<Arc<DnsProxy>> {
    context
        .dns
        .as_ref()
        .and_then(|proxy| proxy.get())
        .map(Arc::clone)
}

fn udp_route_generation_is_current(routing: &ClientRouting, generation: RouteGeneration) -> bool {
    routing.route_generation() == generation
}

async fn wait_for_optional_udp_route_generation_change(
    route_change: Option<&mut RouteGenerationChange>,
) {
    match route_change {
        Some(route_change) => route_change.await,
        None => std::future::pending().await,
    }
}

async fn run_udp_reject_association(
    mut association: ferrum2_tun::UdpAssociation,
    route_generation: RouteGeneration,
    mut route_change: RouteGenerationChange,
    cancellation: ProcessCancellation,
    session_cancellation: ferrum2_tun::SessionCancellation,
    routing: Arc<ClientRouting>,
    metrics: &Metrics,
) {
    loop {
        if !udp_route_generation_is_current(&routing, route_generation) {
            return;
        }
        let mut forced = cancellation.clone();
        tokio::select! {
            biased;
            () = forced.forced() => return,
            () = session_cancellation.cancelled() => return,
            () = &mut route_change => return,
            datagram = association.receive() => {
                if datagram.is_none() {
                    return;
                }
                metrics.udp_datagram(
                    Role::Client,
                    Direction::ClientToTarget,
                    Outcome::Rejected,
                );
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn prepare_tun_udp_egress(
    cancellation: &ProcessCancellation,
    session_cancellation: &ferrum2_tun::SessionCancellation,
    context: &ClientContext,
    routing: &ClientRouting,
    inbound: usize,
    first_target: SocketAddr,
    route_generation: RouteGeneration,
    route_change: &mut RouteGenerationChange,
    snapshot: EgressPlanSnapshot,
) -> Option<ClientUdpAssociation> {
    if !udp_route_generation_is_current(routing, route_generation) {
        return None;
    }
    let Ok(first_target) = TargetAddr::ip(first_target) else {
        return None;
    };
    let mut forced = cancellation.clone();
    let prepared = tokio::select! {
        () = forced.forced() => return None,
        () = session_cancellation.cancelled() => return None,
        () = route_change => return None,
        prepared = context.egress.prepare_udp_for_ingress(
            ClientRequestOrigin::Tun,
            inbound,
            Some(snapshot),
            Some(&first_target),
        ) => prepared.ok()?,
    };
    if !udp_route_generation_is_current(routing, route_generation) {
        return None;
    }
    let mut prepared = prepared;
    prepared.activate(&context.egress).ok()?;
    udp_route_generation_is_current(routing, route_generation).then_some(prepared)
}

enum TunUdpPeerReservation {
    Pending(ferrum2_tun::UdpPeerReservation),
    Ready,
}

impl TunUdpPeerReservation {
    fn commit(self) -> bool {
        match self {
            Self::Pending(reservation) => matches!(
                reservation.commit(),
                ferrum2_tun::UdpPeerAuthorization::Authorized
                    | ferrum2_tun::UdpPeerAuthorization::AlreadyAuthorized
                    | ferrum2_tun::UdpPeerAuthorization::NotRequired
            ),
            Self::Ready => true,
        }
    }
}

fn reserve_tun_udp_peer(
    policy: &ferrum2_tun::UdpPeerPolicyHandle,
    peer: std::net::IpAddr,
) -> Option<TunUdpPeerReservation> {
    match policy.reserve_peer(peer) {
        ferrum2_tun::UdpPeerReservationOutcome::Reserved(reservation) => {
            Some(TunUdpPeerReservation::Pending(reservation))
        }
        ferrum2_tun::UdpPeerReservationOutcome::AlreadyAuthorized
        | ferrum2_tun::UdpPeerReservationOutcome::NotRequired => Some(TunUdpPeerReservation::Ready),
        ferrum2_tun::UdpPeerReservationOutcome::InvalidPeer
        | ferrum2_tun::UdpPeerReservationOutcome::LimitReached => None,
    }
}

fn commit_peer_after_success<E>(
    sent: Result<usize, E>,
    expected: usize,
    commit: impl FnOnce() -> bool,
) -> bool {
    if !matches!(sent, Ok(length) if length == expected) {
        return false;
    }
    commit()
}

fn authorize_dns_peer_after_answer<T>(
    response: Option<T>,
    target: SocketAddr,
    authorize: impl FnOnce(std::net::IpAddr) -> bool,
) -> Option<T> {
    let response = response?;
    authorize(target.ip()).then_some(response)
}

fn record_tun_udp_response_outcome(outcome: ferrum2_tun::UdpResponseSendOutcome) -> bool {
    outcome == ferrum2_tun::UdpResponseSendOutcome::Queued
}

#[allow(clippy::too_many_arguments)]
async fn run_udp_route_association(
    mut association: ferrum2_tun::UdpAssociation,
    mut pending_datagram: Option<ferrum2_tun::UdpDatagram>,
    route_generation: RouteGeneration,
    mut route_change: RouteGenerationChange,
    request_payload_bound: usize,
    cancellation: ProcessCancellation,
    session_cancellation: ferrum2_tun::SessionCancellation,
    context: Arc<ClientContext>,
    routing: Arc<ClientRouting>,
    inbound: usize,
    synthetic_dns: SyntheticDns,
    egress: &mut ClientUdpAssociation,
) {
    if !udp_route_generation_is_current(&routing, route_generation) {
        return;
    }
    let response_sink = association.response_sink();
    let peer_policy = association.peer_policy();
    let Ok(mut egress_cancelled) = egress.cancellation() else {
        return;
    };
    loop {
        if !udp_route_generation_is_current(&routing, route_generation) {
            return;
        }
        if let Some(datagram) = pending_datagram.take() {
            if synthetic_dns.matches(datagram.target()) {
                let Some(proxy) = tun_dns_proxy(&context) else {
                    continue;
                };
                if !answer_tun_udp_dns(
                    datagram,
                    &proxy,
                    inbound,
                    &cancellation,
                    &session_cancellation,
                    Some(route_generation),
                    Some(&mut route_change),
                    &routing,
                    &response_sink,
                    &peer_policy,
                )
                .await
                {
                    return;
                }
                continue;
            }
            let target = datagram.target();
            let Ok(application_target) = TargetAddr::ip(target) else {
                continue;
            };
            if !target_payload_within_bound(datagram.payload().len(), request_payload_bound) {
                continue;
            }
            let Some(peer_reservation) = reserve_tun_udp_peer(&peer_policy, target.ip()) else {
                continue;
            };
            let payload_len = datagram.payload().len();
            let wire_len = match egress.prepare_application_request(
                &context.egress,
                &routing.outbounds,
                application_target,
                datagram.payload(),
                Instant::now(),
            ) {
                Ok(length) => length,
                Err(UdpPlanResponseError::Packet(_) | UdpPlanResponseError::Runtime(_)) => continue,
            };
            drop(datagram);
            let mut send_forced = cancellation.clone();
            let sent = tokio::select! {
                biased;
                () = send_forced.forced() => return,
                () = session_cancellation.cancelled() => return,
                () = &mut route_change => return,
                changed = egress_cancelled.changed() => {
                    let _ = changed;
                    return;
                }
                result = egress.send_encoded_request(wire_len) => result,
            };
            if session_cancellation.is_cancelled()
                || !udp_route_generation_is_current(&routing, route_generation)
            {
                return;
            }
            if !commit_peer_after_success(sent, wire_len, || peer_reservation.commit()) {
                return;
            }
            context.metrics.udp_datagram(
                Role::Client,
                Direction::ClientToTarget,
                Outcome::Accepted,
            );
            context.metrics.add_udp_bytes(
                Role::Client,
                Direction::ClientToTarget,
                payload_len as u64,
            );
            continue;
        }

        let Ok(idle_deadline) = egress.idle_deadline() else {
            return;
        };
        let mut forced = cancellation.clone();
        tokio::select! {
            biased;
            () = forced.forced() => return,
            () = session_cancellation.cancelled() => return,
            () = &mut route_change => return,
            changed = egress_cancelled.changed() => {
                let _ = changed;
                return;
            }
            () = tokio::time::sleep_until(idle_deadline) => {
                if egress.idle_expired(idle_deadline) {
                    return;
                }
            }
            datagram = association.receive() => {
                let Some(datagram) = datagram else { return };
                pending_datagram = Some(datagram);
            }
            received = egress.receive_response_wire() => {
                let Ok(wire_len) = received else { return };
                if session_cancellation.is_cancelled()
                    || !udp_route_generation_is_current(&routing, route_generation)
                {
                    return;
                }
                let Ok(response) = egress.prepare_application_response(
                    &context.egress,
                    &routing.outbounds,
                    wire_len,
                ) else {
                    continue;
                };
                let Some(source) = response.datagram().target().as_socket_addr() else { continue };
                let payload = response.datagram().payload();
                if !udp_route_generation_is_current(&routing, route_generation) {
                    return;
                }
                let response_outcome = response_sink.send(source, payload);
                if !udp_route_generation_is_current(&routing, route_generation) {
                    return;
                }
                if record_tun_udp_response_outcome(response_outcome) {
                    context.metrics.udp_datagram(
                        Role::Client,
                        Direction::TargetToClient,
                        Outcome::Accepted,
                    );
                    context.metrics.add_udp_bytes(
                        Role::Client,
                        Direction::TargetToClient,
                        payload.len() as u64,
                    );
                }
                egress.recycle_application_response(response);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_udp_dns_association(
    mut association: ferrum2_tun::UdpAssociation,
    mut pending_datagram: Option<ferrum2_tun::UdpDatagram>,
    route_generation: RouteGeneration,
    mut route_change: RouteGenerationChange,
    cancellation: ProcessCancellation,
    session_cancellation: ferrum2_tun::SessionCancellation,
    routing: Arc<ClientRouting>,
    inbound: usize,
    proxy: Arc<DnsProxy>,
) {
    if !udp_route_generation_is_current(&routing, route_generation) {
        return;
    }
    let response_sink = association.response_sink();
    let peer_policy = association.peer_policy();
    loop {
        if !udp_route_generation_is_current(&routing, route_generation) {
            return;
        }
        if let Some(datagram) = pending_datagram.take() {
            if !answer_tun_udp_dns(
                datagram,
                &proxy,
                inbound,
                &cancellation,
                &session_cancellation,
                Some(route_generation),
                Some(&mut route_change),
                &routing,
                &response_sink,
                &peer_policy,
            )
            .await
            {
                return;
            }
            continue;
        }
        let mut forced = cancellation.clone();
        let datagram = tokio::select! {
            biased;
            () = forced.forced() => return,
            () = session_cancellation.cancelled() => return,
            () = &mut route_change => return,
            datagram = association.receive() => datagram,
        };
        let Some(datagram) = datagram else { return };
        pending_datagram = Some(datagram);
    }
}

#[allow(clippy::too_many_arguments)]
async fn answer_tun_udp_dns(
    datagram: ferrum2_tun::UdpDatagram,
    proxy: &DnsProxy,
    inbound: usize,
    cancellation: &ProcessCancellation,
    session_cancellation: &ferrum2_tun::SessionCancellation,
    route_generation: Option<RouteGeneration>,
    route_change: Option<&mut RouteGenerationChange>,
    routing: &ClientRouting,
    response_sink: &ferrum2_tun::UdpResponseSink,
    peer_policy: &ferrum2_tun::UdpPeerPolicyHandle,
) -> bool {
    if route_generation
        .is_some_and(|generation| !udp_route_generation_is_current(routing, generation))
    {
        return false;
    }
    let target = datagram.target();
    let mut answer_forced = cancellation.clone();
    let response = tokio::select! {
        biased;
        () = answer_forced.forced() => return false,
        () = session_cancellation.cancelled() => return false,
        () = wait_for_optional_udp_route_generation_change(route_change) => {
            return false;
        }
        response = proxy.answer(
            ProxyIngress::Ordinary(inbound),
            ProxyTransport::Udp,
            datagram.payload(),
        ) => response,
    };
    if session_cancellation.is_cancelled()
        || route_generation
            .is_some_and(|generation| !udp_route_generation_is_current(routing, generation))
    {
        return false;
    }
    if let Some(response) = authorize_dns_peer_after_answer(response, target, |peer| {
        reserve_tun_udp_peer(peer_policy, peer).is_some_and(TunUdpPeerReservation::commit)
    }) {
        if route_generation
            .is_some_and(|generation| !udp_route_generation_is_current(routing, generation))
        {
            return false;
        }
        // Local DNS replies retain the per-datagram synthetic or hijacked endpoint.
        let outcome = response_sink.send(target, &response);
        if route_generation
            .is_some_and(|generation| !udp_route_generation_is_current(routing, generation))
        {
            return false;
        }
        record_tun_udp_response_outcome(outcome);
    }
    true
}

async fn wait_for_session_cancellation(
    session_cancellation: &Option<ferrum2_tun::SessionCancellation>,
) {
    match session_cancellation {
        Some(session_cancellation) => session_cancellation.cancelled().await,
        None => std::future::pending().await,
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_tcp<IO>(
    target: SocketAddr,
    mut flow: IO,
    mut cancellation: ProcessCancellation,
    context: Arc<ClientContext>,
    routing: Arc<ClientRouting>,
    inbound: usize,
    synthetic_dns: SyntheticDns,
    session_cancellation: Option<ferrum2_tun::SessionCancellation>,
) where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    if synthetic_dns.matches(target) {
        let Some(proxy) = context
            .dns
            .as_ref()
            .and_then(|proxy| proxy.get())
            .map(Arc::clone)
        else {
            return;
        };
        let mut process_cancelled = cancellation.clone();
        relay_hijacked_tcp(
            &mut flow,
            inbound,
            &proxy,
            context.runtime.idle_timeout,
            async {
                tokio::select! {
                    () = process_cancelled.forced() => {},
                    () = wait_for_session_cancellation(&session_cancellation) => {},
                }
            },
        )
        .await;
        return;
    }
    let Ok(target) = TargetAddr::ip(target) else {
        return;
    };
    let mut process_cancelled = cancellation.clone();
    let Ok(Some(selection)) = routing
        .select_tcp(
            inbound,
            &target,
            &mut flow,
            async {
                tokio::select! {
                    () = process_cancelled.forced() => {},
                    () = wait_for_session_cancellation(&session_cancellation) => {},
                }
            },
            &context.registry,
            &context.metrics,
        )
        .await
    else {
        return;
    };
    let mut flow = ReplayIo::new(flow, selection.prefix);
    match selection.terminal {
        ClientTerminalRoute::Reject => {}
        ClientTerminalRoute::HijackDns => {
            let Some(proxy) = context
                .dns
                .as_ref()
                .and_then(|proxy| proxy.get())
                .map(Arc::clone)
            else {
                return;
            };
            let mut process_cancelled = cancellation.clone();
            relay_hijacked_tcp(
                &mut flow,
                inbound,
                &proxy,
                context.runtime.idle_timeout,
                async {
                    tokio::select! {
                        () = process_cancelled.forced() => {},
                        () = wait_for_session_cancellation(&session_cancellation) => {},
                    }
                },
            )
            .await;
        }
        ClientTerminalRoute::Route(plan) => {
            let opened = tokio::select! {
                _ = cancellation.forced() => return,
                () = wait_for_session_cancellation(&session_cancellation) => return,
                opened = context.egress.open_tcp_for_ingress(
                    ClientRequestOrigin::Tun,
                    inbound,
                    Some(plan),
                    &target,
                    None,
                    #[cfg(test)]
                    None,
                ) => opened,
            };
            let Ok(opened) = opened else {
                return;
            };
            let mut opened = TokioFramed::new(opened);
            let mut process_cancelled = cancellation.clone();
            let _ = relay_lifecycle(
                &mut flow,
                &mut opened,
                context.runtime.idle_timeout,
                &context.registry,
                async {
                    tokio::select! {
                        () = process_cancelled.forced() => {},
                        () = wait_for_session_cancellation(&session_cancellation) => {},
                    }
                },
            )
            .await;
        }
    }
}

fn is_synthetic_dns_target(target: &TargetAddr, synthetic_dns: SyntheticDns) -> bool {
    target
        .as_socket_addr()
        .is_some_and(|target| synthetic_dns.matches(target))
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;
    use std::sync::Arc;
    use std::time::Duration;

    use ferrum2_dns::{DnsUpstreamSpec, DnsUpstreamTransport, TaggedResolver};
    use ferrum2_runtime::{
        OwnerRegistry, PreparedProcessRoot, ProcessCancellation, ProcessFuture, ProcessRoot,
        ProcessSupervisor,
    };
    use tokio::sync::Notify;

    use super::super::test_support::*;
    use super::super::{RunError, report_result};
    use super::{
        ClientNetworkResetHook, SyntheticDns, TunUdpPlan, TunUdpRouteRequest,
        authorize_dns_peer_after_answer, commit_peer_after_success, record_tun_event, run_tcp,
        select_udp_target, select_udp_target_generation_stable, target_payload_within_bound,
        udp_route_generation_is_current,
    };

    #[tokio::test]
    async fn client_network_hook_retries_failure_and_accepts_each_generation_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use ferrum2_runtime::{NetworkSnapshot, ResetNetwork};

        let attempts = Arc::new(AtomicUsize::new(0));
        let action_attempts = Arc::clone(&attempts);
        let hook = ClientNetworkResetHook::new(
            1,
            Arc::new(move |generation| {
                assert_eq!(generation, 2);
                if action_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(())
                } else {
                    Ok(())
                }
            }),
        );
        let second = Arc::new(NetworkSnapshot::new(2, None, None).unwrap());
        assert!(hook.reset_network(Arc::clone(&second)).await.is_err());
        assert!(hook.reset_network(Arc::clone(&second)).await.is_ok());
        assert!(hook.reset_network(second).await.is_ok());
        assert_eq!(attempts.load(Ordering::SeqCst), 2);

        let stale = Arc::new(NetworkSnapshot::new(1, None, None).unwrap());
        assert!(hook.reset_network(stale).await.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn every_tun_event_maps_to_one_exact_metric_or_closed_diagnostic() {
        use ferrum2_tun::{
            TunDiagnosticReason, TunEvent, TunIpFamily, TunNetworkResetReason, TunRejectReason,
            UdpResponseDropReason,
        };

        let metrics = ferrum2_observability::Metrics::new();
        let events = [
            TunEvent::PacketAccepted,
            TunEvent::PacketFoundationDropped,
            TunEvent::SessionStarted,
            TunEvent::NetworkResetStarted(TunNetworkResetReason::NetworkChange),
            TunEvent::NetworkResetSucceeded(TunNetworkResetReason::NetworkChange),
            TunEvent::NetworkResetFailed(TunNetworkResetReason::NetworkChange),
            TunEvent::NetworkResetStarted(TunNetworkResetReason::Retry),
            TunEvent::NetworkResetSucceeded(TunNetworkResetReason::Retry),
            TunEvent::NetworkResetFailed(TunNetworkResetReason::Retry),
            TunEvent::SessionRestartStarted,
            TunEvent::SessionRestartSucceeded,
            TunEvent::SessionRestartFailed,
            TunEvent::SessionGeneration(7),
            TunEvent::SessionActive(true),
            TunEvent::PacketIngress,
            TunEvent::PacketEgress,
            TunEvent::InternalEgressBackpressured,
            TunEvent::WintunRingFullDropped,
            TunEvent::TcpFlowsActive(11),
            TunEvent::TcpFlowRejectedLimit,
            TunEvent::TcpFlowResetRestart,
            TunEvent::TcpBridgeBlocked,
            TunEvent::UdpAssociationsActive(13),
            TunEvent::UdpCandidatesActive(17),
            TunEvent::UdpAssociationCreated,
            TunEvent::UdpAssociationRejectedLimit,
            TunEvent::UdpDatagramQueueFull,
            TunEvent::UdpResponseQueueFull,
            TunEvent::UdpResponseFiltered,
            TunEvent::UdpResponseDropped(UdpResponseDropReason::OwnerFatal),
            TunEvent::UdpPendingResponses(1),
            TunEvent::UdpStaleGeneration,
            TunEvent::ReassemblyEntriesActive(19),
            TunEvent::ReassemblyStarted,
            TunEvent::ReassemblyCompleted,
            TunEvent::ReassemblyDroppedOverlap,
            TunEvent::ReassemblyDroppedTimeout,
            TunEvent::ReassemblyDroppedLimit,
            TunEvent::ReassemblyDroppedMalformed,
            TunEvent::NetworkChange,
            TunEvent::UnderlayBindStale,
            TunEvent::Diagnostic {
                reason: TunDiagnosticReason::WintunRingFull,
                family: TunIpFamily::Ipv4,
            },
        ];
        for event in events {
            record_tun_event(&metrics, event);
        }
        let reject_reasons = [
            TunRejectReason::InvalidIpVersion,
            TunRejectReason::FamilyDisabled,
            TunRejectReason::InvalidIpLength,
            TunRejectReason::InvalidIpChecksum,
            TunRejectReason::InvalidExtensionHeader,
            TunRejectReason::UnsupportedIpProtocol,
            TunRejectReason::IcmpEchoUnsupported,
            TunRejectReason::FragmentMalformed,
            TunRejectReason::FragmentOverlap,
            TunRejectReason::FragmentTimeout,
            TunRejectReason::FragmentLimit,
            TunRejectReason::InvalidTransportLength,
            TunRejectReason::InvalidTransportChecksum,
            TunRejectReason::InvalidSource,
            TunRejectReason::InvalidDestination,
            TunRejectReason::IngressFull,
            TunRejectReason::TcpFlowLimit,
            TunRejectReason::UdpAssociationLimit,
            TunRejectReason::UdpCandidateTimeout,
            TunRejectReason::UdpQueueFull,
            TunRejectReason::UdpResponseFiltered,
            TunRejectReason::UdpResponseClosed,
            TunRejectReason::StaleGeneration,
            TunRejectReason::WintunRingFull,
        ];
        for reason in reject_reasons {
            record_tun_event(&metrics, TunEvent::PacketRejected(reason));
        }

        let output = metrics.encode_text().expect("TUN metrics");
        for sample in [
            "ferrum2_tun_packets_accepted_total 1",
            "ferrum2_tun_packets_foundation_dropped_total 1",
            "ferrum2_tun_session_started_total 1",
            "ferrum2_network_reset_total{reason=\"network_change\",result=\"started\"} 1",
            "ferrum2_network_reset_total{reason=\"network_change\",result=\"succeeded\"} 1",
            "ferrum2_network_reset_total{reason=\"network_change\",result=\"failed\"} 1",
            "ferrum2_network_reset_total{reason=\"retry\",result=\"started\"} 1",
            "ferrum2_network_reset_total{reason=\"retry\",result=\"succeeded\"} 1",
            "ferrum2_network_reset_total{reason=\"retry\",result=\"failed\"} 1",
            "ferrum2_tun_session_restart_started_total 1",
            "ferrum2_tun_session_restart_succeeded_total 1",
            "ferrum2_tun_session_restart_failed_total 1",
            "ferrum2_tun_session_generation 7",
            "ferrum2_tun_session_active 1",
            "ferrum2_tun_packets_ingress_total 1",
            "ferrum2_tun_packets_egress_total 1",
            "ferrum2_tun_internal_egress_backpressured_total 1",
            "ferrum2_tun_wintun_ring_full_dropped_total 1",
            "ferrum2_tun_tcp_flows_active 11",
            "ferrum2_tun_tcp_flows_rejected_limit_total 1",
            "ferrum2_tun_tcp_flows_reset_restart_total 1",
            "ferrum2_tun_tcp_bridge_blocked_total 1",
            "ferrum2_tun_udp_associations_active 13",
            "ferrum2_tun_udp_candidates_active 17",
            "ferrum2_tun_udp_association_created_total 1",
            "ferrum2_tun_udp_association_rejected_limit_total 1",
            "ferrum2_tun_udp_datagram_queue_full_total 1",
            "ferrum2_tun_pending_udp_responses 1",
            "ferrum2_tun_udp_response_queue_full_total 1",
            "ferrum2_tun_udp_response_filtered_total 1",
            "ferrum2_tun_udp_response_dropped_total{reason=\"owner_fatal\"} 1",
            "ferrum2_tun_udp_stale_generation_total 1",
            "ferrum2_tun_reassembly_entries_active 19",
            "ferrum2_tun_reassembly_started_total 1",
            "ferrum2_tun_reassembly_completed_total 1",
            "ferrum2_tun_reassembly_dropped_overlap_total 1",
            "ferrum2_tun_reassembly_dropped_timeout_total 1",
            "ferrum2_tun_reassembly_dropped_limit_total 1",
            "ferrum2_tun_reassembly_dropped_malformed_total 1",
            "ferrum2_tun_network_change_total 1",
            "ferrum2_tun_underlay_bind_stale_total 1",
        ] {
            assert!(
                output.lines().any(|line| line == sample),
                "missing {sample}"
            );
        }
        assert!(!output.contains("ferrum2_tun_route_detect"));
        assert!(!output.contains("ferrum2_tun_route_conflict"));
        assert_eq!(
            output
                .lines()
                .filter(
                    |line| line.starts_with("ferrum2_tun_packets_rejected_total{")
                        && line.ends_with(" 1")
                )
                .count(),
            reject_reasons.len()
        );
    }

    #[test]
    fn deferred_then_injected_udp_response_keeps_rejected_metrics_at_zero() {
        let metrics = ferrum2_observability::Metrics::new();
        record_tun_event(&metrics, ferrum2_tun::TunEvent::InternalEgressBackpressured);
        record_tun_event(&metrics, ferrum2_tun::TunEvent::UdpPendingResponses(1));
        record_tun_event(&metrics, ferrum2_tun::TunEvent::UdpPendingResponses(0));

        let output = metrics.encode_text().expect("deferred TUN UDP metrics");
        assert!(
            output
                .lines()
                .any(|line| line == "ferrum2_tun_internal_egress_backpressured_total 1")
        );
        assert!(
            output
                .lines()
                .any(|line| line == "ferrum2_tun_pending_udp_responses 0")
        );
        let rejected = output
            .lines()
            .filter(|line| line.starts_with("ferrum2_tun_packets_rejected_total{"))
            .collect::<Vec<_>>();
        assert!(
            rejected.iter().all(|line| line.ends_with(" 0")),
            "a delayed response that is later injected is not rejected: {rejected:?}"
        );
    }

    #[test]
    fn deferred_then_dropped_udp_response_counts_each_terminal_metric_once() {
        let metrics = ferrum2_observability::Metrics::new();
        record_tun_event(&metrics, ferrum2_tun::TunEvent::InternalEgressBackpressured);
        record_tun_event(&metrics, ferrum2_tun::TunEvent::UdpPendingResponses(1));
        record_tun_event(
            &metrics,
            ferrum2_tun::TunEvent::UdpResponseDropped(
                ferrum2_tun::UdpResponseDropReason::InjectionRejected,
            ),
        );
        record_tun_event(
            &metrics,
            ferrum2_tun::TunEvent::PacketRejected(ferrum2_tun::TunRejectReason::InvalidIpChecksum),
        );
        record_tun_event(&metrics, ferrum2_tun::TunEvent::UdpPendingResponses(0));

        let output = metrics.encode_text().expect("terminal TUN UDP metrics");
        assert!(output.lines().any(|line| {
            line == "ferrum2_tun_udp_response_dropped_total{reason=\"injection_rejected\"} 1"
        }));
        assert!(output.lines().any(|line| {
            line == "ferrum2_tun_packets_rejected_total{reason=\"invalid_ip_checksum\"} 1"
        }));
        assert_eq!(
            output
                .lines()
                .filter(|line| {
                    line.starts_with("ferrum2_tun_udp_response_dropped_total{")
                        && line.ends_with(" 1")
                })
                .count(),
            1
        );
        assert_eq!(
            output
                .lines()
                .filter(|line| {
                    line.starts_with("ferrum2_tun_packets_rejected_total{") && line.ends_with(" 1")
                })
                .count(),
            1
        );
        assert!(
            output
                .lines()
                .any(|line| line == "ferrum2_tun_pending_udp_responses 0")
        );
    }

    struct NeverPrepared;

    impl PreparedProcessRoot<RunError> for NeverPrepared {
        fn activate(&mut self) -> Result<(), RunError> {
            Ok(())
        }

        fn run(
            self: Box<Self>,
            _cancellation: ProcessCancellation,
        ) -> ProcessFuture<Result<(), RunError>> {
            Box::pin(async { Ok(()) })
        }

        fn rollback(self: Box<Self>) -> ProcessFuture<Result<(), RunError>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[test]
    fn synthetic_dns_matches_each_configured_family_exactly() {
        let dns = SyntheticDns {
            ipv4: Some("198.18.0.1".parse().unwrap()),
            ipv6: Some("fd00::1".parse().unwrap()),
        };
        for (target, expected) in [
            ("198.18.0.1:53", true),
            ("[fd00::1]:53", true),
            ("198.18.0.1:54", false),
            ("[fd00::1]:54", false),
            ("198.18.0.2:53", false),
            ("[fd00::2]:53", false),
        ] {
            assert_eq!(dns.matches(target.parse().unwrap()), expected, "{target}");
        }
        assert!(!SyntheticDns::default().matches("198.18.0.1:53".parse().unwrap()));
        assert!(!SyntheticDns::default().matches("[fd00::1]:53".parse().unwrap()));
    }

    #[tokio::test]
    async fn selector_switch_invalidates_the_frozen_tun_udp_association() {
        let (outbounds, route, selector) = chain_test_setup(
            [
                ferrum2_crypto::MethodProfile::Blake3Aes128Gcm2022,
                ferrum2_crypto::MethodProfile::Blake3Aes256Gcm2022,
                ferrum2_crypto::MethodProfile::Blake3ChaCha20Poly13052022,
                ferrum2_crypto::MethodProfile::Blake3Aes128Gcm2022,
            ],
            20_000,
        );
        let routing = ClientRouting {
            legacy: route,
            program: None,
            outbounds,
            selector: selector.clone(),
        };
        let target = TargetAddr::ip("192.0.2.8:53".parse().unwrap()).unwrap();
        let metrics = ferrum2_observability::Metrics::new();
        let (first_generation, first_plan) = select_udp_target_generation_stable(
            TunUdpRouteRequest {
                routing: &routing,
                inbound: 0,
                synthetic_dns: SyntheticDns::default(),
                target: &target,
                payload: b"first",
                metrics: &metrics,
            },
            None,
        )
        .expect("first stable generation");
        let TunUdpPlan::Route {
            snapshot: first_snapshot,
            ..
        } = first_plan
        else {
            panic!("first route target");
        };
        let mut route_change = routing.watch_route_generation_from(first_generation);
        assert_eq!(first_snapshot.hops(), &[0, 1]);
        assert!(udp_route_generation_is_current(&routing, first_generation));

        selector.switch("manual", "a-b").expect("no-op switch");
        assert!(selector.switch("manual", "missing").is_err());
        assert!(udp_route_generation_is_current(&routing, first_generation));

        selector.switch("manual", "c-d").expect("effective switch");
        assert!(
            !udp_route_generation_is_current(&routing, first_generation),
            "the active association must terminate instead of selecting another route"
        );
        tokio::time::timeout(Duration::from_millis(50), &mut route_change)
            .await
            .expect("generation watcher must wake a blocked association");
        assert_eq!(
            first_snapshot.hops(),
            &[0, 1],
            "the frozen snapshot is never rewritten in place"
        );
    }

    #[test]
    fn schema_v2_selector_switch_changes_composite_tun_udp_generation() {
        let (path, _) = client_test_config(reserve_address(), reserve_address());
        std::fs::write(
            &path,
            r#"schema_version = 2
[tun]
tag = "tun-in"
adapter_name = "Ferrum2"
ipv4_address = "198.18.0.2/30"
[[outbounds]]
tag = "direct"
type = "direct"
[[outbounds]]
tag = "proxy"
server = "192.0.2.10:8388"
[[selectors]]
tag = "manual"
outbounds = ["direct", "proxy"]
default = "direct"
[route]
final = "manual"
[[route.rules]]
inbound = "tun-in"
network = "tcp"
action = "route"
outbound = "direct"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#,
        )
        .expect("schema-v2 selector config");
        let config = ferrum2_config::load_client(&path).expect("validated schema-v2 selector");
        std::fs::remove_file(path).expect("remove schema-v2 selector config");
        assert!(
            config.route_program.is_some(),
            "missing compiled route program"
        );
        let inbound = config.inbounds.len();
        let selector = config.selector_control();
        let outbounds = prepare_client_outbounds(config.outbounds).expect("outbound contexts");
        let routing = ClientRouting {
            legacy: config.route,
            program: config.route_program,
            outbounds,
            selector: selector.clone(),
        };
        let target = TargetAddr::ip("192.0.2.8:53".parse().unwrap()).unwrap();
        let metrics = ferrum2_observability::Metrics::new();
        let mut scratch = routing
            .route_scratch()
            .expect("route scratch")
            .expect("compiled route scratch");
        let select = |payload: &[u8], scratch: &mut ferrum2_rule::RuleEvaluationScratch| {
            select_udp_target_generation_stable(
                TunUdpRouteRequest {
                    routing: &routing,
                    inbound,
                    synthetic_dns: SyntheticDns::default(),
                    target: &target,
                    payload,
                    metrics: &metrics,
                },
                Some(scratch),
            )
            .expect("stable schema-v2 selection")
        };

        let (first_generation, first_plan) = select(b"first", &mut scratch);
        let TunUdpPlan::Route {
            snapshot: first_snapshot,
            ..
        } = first_plan
        else {
            panic!("first schema-v2 route");
        };
        assert_eq!(first_snapshot.hops(), &[0]);

        selector.switch("manual", "proxy").expect("selector switch");
        let (second_generation, second_plan) = select(b"second", &mut scratch);
        let TunUdpPlan::Route {
            snapshot: second_snapshot,
            ..
        } = second_plan
        else {
            panic!("second schema-v2 route");
        };
        assert_ne!(second_generation, first_generation);
        assert_eq!(second_snapshot.hops(), &[1]);
    }

    #[test]
    fn tun_udp_authorizes_only_successful_send_or_dns_answer_and_adf_ignores_port() {
        let first: SocketAddr = "192.0.2.8:53".parse().unwrap();
        let second_port: SocketAddr = "192.0.2.8:5353".parse().unwrap();
        let authorized = std::cell::RefCell::new(Vec::new());
        assert!(!commit_peer_after_success(Err::<usize, ()>(()), 4, || {
            authorized.borrow_mut().push(first.ip());
            true
        },));
        assert!(!commit_peer_after_success(Ok::<usize, ()>(3), 4, || {
            authorized.borrow_mut().push(first.ip());
            true
        },));
        assert!(
            authorized.borrow().is_empty(),
            "failed sends authorize nobody"
        );

        assert!(commit_peer_after_success(Ok::<usize, ()>(4), 4, || {
            authorized.borrow_mut().push(first.ip());
            true
        },));
        assert!(commit_peer_after_success(Ok::<usize, ()>(4), 4, || {
            authorized.borrow_mut().push(second_port.ip());
            true
        },));
        assert_eq!(
            *authorized.borrow(),
            [first.ip(), first.ip()],
            "ADF authorization is keyed by IP rather than UDP port"
        );

        let ordinary_dns: SocketAddr = "198.51.100.53:53".parse().unwrap();
        let missing = authorize_dns_peer_after_answer(None::<Vec<u8>>, ordinary_dns, |peer| {
            authorized.borrow_mut().push(peer);
            true
        });
        assert!(missing.is_none());
        assert_eq!(
            authorized.borrow().len(),
            2,
            "missing DNS answers authorize nobody"
        );

        let answer = authorize_dns_peer_after_answer(Some(vec![1, 2, 3]), ordinary_dns, |peer| {
            authorized.borrow_mut().push(peer);
            true
        });
        assert_eq!(answer.as_deref(), Some([1, 2, 3].as_slice()));
        assert_eq!(authorized.borrow().last(), Some(&ordinary_dns.ip()));
        assert!(
            authorize_dns_peer_after_answer(Some(()), ordinary_dns, |_| false).is_none(),
            "DNS response survived a rejected ADF reservation"
        );

        let synthetic_dns: SocketAddr = "198.18.0.1:53".parse().unwrap();
        assert!(
            authorize_dns_peer_after_answer(Some(()), synthetic_dns, |peer| {
                authorized.borrow_mut().push(peer);
                true
            })
            .is_some()
        );
        assert_eq!(authorized.borrow().last(), Some(&synthetic_dns.ip()));
    }

    #[tokio::test]
    async fn tun_udp_route_snapshot_is_bounded_and_immutable_after_selection() {
        let (outbounds, route, selector) = chain_test_setup(
            [
                ferrum2_crypto::MethodProfile::Blake3Aes128Gcm2022,
                ferrum2_crypto::MethodProfile::Blake3Aes256Gcm2022,
                ferrum2_crypto::MethodProfile::Blake3ChaCha20Poly13052022,
                ferrum2_crypto::MethodProfile::Blake3Aes128Gcm2022,
            ],
            20_000,
        );
        let routing = ClientRouting {
            legacy: route,
            program: None,
            outbounds,
            selector: selector.clone(),
        };
        let target = TargetAddr::ip("192.0.2.1:53".parse().expect("target")).expect("target");
        let metrics = ferrum2_observability::Metrics::new();
        let first = select_udp_target(&routing, 0, None, None, &target, b"first", 1_392, &metrics)
            .expect("first selector snapshot");
        let TunUdpPlan::Route {
            snapshot: first_snapshot,
            request_payload_bound: bound,
            ..
        } = first
        else {
            panic!("route target plan");
        };
        assert_eq!(first_snapshot.hops(), &[0, 1]);
        assert!(
            bound > 1_392,
            "reassembled request inherited the response-injection MTU bound"
        );
        assert!(target_payload_within_bound(1_393, bound));
        let oversized = select_udp_target(
            &routing,
            0,
            None,
            None,
            &target,
            &vec![0; bound + 1],
            1_392,
            &metrics,
        )
        .expect("oversized datagram still snapshots its target plan");
        let TunUdpPlan::Route {
            snapshot: oversized_snapshot,
            request_payload_bound: oversized_bound,
            ..
        } = oversized
        else {
            panic!("route target plan");
        };
        assert_eq!(oversized_snapshot.hops(), &[0, 1]);
        assert_eq!(oversized_bound, bound);

        selector
            .switch("manual", "c-d")
            .expect("switch after rejected candidate");
        let selected =
            select_udp_target(&routing, 0, None, None, &target, b"valid", 1_392, &metrics)
                .expect("current association selector");
        let TunUdpPlan::Route { snapshot, .. } = selected else {
            panic!("route target plan");
        };
        assert_eq!(snapshot.hops(), &[2, 3]);
        selector
            .switch("manual", "a-b")
            .expect("switch after terminal snapshot");
        assert_eq!(
            snapshot.hops(),
            &[2, 3],
            "the selected association owns an immutable plan snapshot"
        );

        let registry = OwnerRegistry::new();
        let live_ids = Arc::new(Mutex::new(HashSet::new()));
        let outbounds = prepare_client_outbounds(vec![
            ferrum2_config::ClientOutboundConfig::Direct {
                domain_resolver: ferrum2_config::DirectDomainResolver::System,
                dial_options: Default::default(),
            },
            ferrum2_config::ClientOutboundConfig::Shadowsocks {
                server: "192.0.2.77:8388".parse().unwrap(),
                psk: Arc::new(default_test_psk()),
                dial_options: Default::default(),
            },
        ])
        .expect("direct and proxy outbounds");
        let (route, direct_selector) = compile_selector_plans(
            &[TaggedInbound::new("tun", 0)],
            &[
                TaggedOutbound::new("direct", 0),
                TaggedOutbound::new("proxy", 1),
            ],
            &[],
            &[SelectorDefinition::new(
                "manual",
                vec!["direct", "proxy"],
                Some("direct"),
            )],
            TaggedRoute::Static(vec![TaggedStaticBinding::new("tun", "manual")]),
        )
        .expect("direct selector route");
        let routing = ClientRouting {
            legacy: route,
            program: None,
            outbounds: Arc::clone(&outbounds),
            selector: direct_selector.clone(),
        };
        let first_echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("first direct TUN UDP target");
        let second_echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("second direct TUN UDP target");
        let target = TargetAddr::ip(first_echo.local_addr().unwrap()).unwrap();
        let second_target = TargetAddr::ip(second_echo.local_addr().unwrap()).unwrap();
        let selected = select_udp_target(
            &routing,
            0,
            None,
            None,
            &target,
            b"tun-direct",
            1_392,
            &Metrics::new(),
        )
        .expect("direct TUN UDP selection");
        let TunUdpPlan::Route {
            snapshot: direct,
            request_payload_bound: bound,
            ..
        } = selected
        else {
            panic!("direct route target plan");
        };
        assert!(
            bound > 1_392,
            "Direct request limit inherited the response-injection MTU bound"
        );
        assert!(target_payload_within_bound(1_393, bound));
        assert_eq!(direct.hops(), &[0]);
        let engine = ClientEgressEngine::new(
            outbounds,
            TokioConnector::new(TcpConnector::new(Duration::from_secs(1))),
            SystemClock::new(),
            SystemRandom,
            (Duration::from_secs(1), Duration::from_secs(1)),
            Some(ClientUdpContext {
                manager: UdpSessionManager::new(UdpRuntimeLimits::default(), registry.clone()),
                live_ids: Arc::clone(&live_ids),
            }),
            None,
        );
        let mut association = engine
            .prepare_udp(
                super::super::egress::ClientRequestOrigin::Tun,
                Some(direct),
                Some(&target),
            )
            .await
            .expect("direct TUN UDP association");
        #[cfg(windows)]
        assert_eq!(engine.managed_binding_calls(), 1);
        association.activate(&engine).expect("direct activation");
        let length = association
            .prepare_application_request(
                &engine,
                &routing.outbounds,
                target.clone(),
                b"tun-direct",
                Instant::now(),
            )
            .unwrap_or_else(|_| panic!("direct TUN request"));
        association
            .send_encoded_request(length)
            .await
            .expect("direct TUN send");
        let mut raw = [0_u8; 32];
        let (length, peer) = first_echo
            .recv_from(&mut raw)
            .await
            .expect("first direct TUN receive");
        assert_eq!(&raw[..length], b"tun-direct");
        first_echo.send_to(b"tun-reply", peer).await.unwrap();
        let length = association.receive_response_wire().await.unwrap();
        let response = association
            .prepare_application_response(&engine, &routing.outbounds, length)
            .unwrap_or_else(|_| panic!("direct TUN response"));
        assert_eq!(response.datagram().target(), &target);
        assert_eq!(response.datagram().payload(), b"tun-reply");
        association.recycle_application_response(response);

        let length = association
            .prepare_application_request(
                &engine,
                &routing.outbounds,
                second_target.clone(),
                b"second-target",
                Instant::now(),
            )
            .unwrap_or_else(|_| panic!("second direct TUN request"));
        association
            .send_encoded_request(length)
            .await
            .expect("second direct TUN send");
        let (length, second_peer) = second_echo
            .recv_from(&mut raw)
            .await
            .expect("second direct TUN receive");
        assert_eq!(&raw[..length], b"second-target");
        assert_eq!(second_peer, peer, "one direct socket serves every target");
        second_echo
            .send_to(b"second-reply", second_peer)
            .await
            .unwrap();
        let length = association.receive_response_wire().await.unwrap();
        let response = association
            .prepare_application_response(&engine, &routing.outbounds, length)
            .unwrap_or_else(|_| panic!("second direct TUN response"));
        assert_eq!(response.datagram().target(), &second_target);
        assert_eq!(response.datagram().payload(), b"second-reply");
        association.recycle_application_response(response);
        assert!(live_ids.lock().expect("live SIP022 IDs").is_empty());
    }

    #[test]
    fn synthetic_dns_precedes_one_frozen_ordinary_udp_route() {
        let (path, _) = client_test_config(reserve_address(), reserve_address());
        std::fs::write(
            &path,
            r#"schema_version = 2
[tun]
tag = "tun-in"
adapter_name = "Ferrum2"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
[[outbounds]]
tag = "fallback"
server = "192.0.2.10:8388"
[[outbounds]]
tag = "direct"
type = "direct"
[route]
final = "fallback"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "192.0.2.53"
port = 53
action = "hijack-dns"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "192.0.2.54"
port = 53
action = "reject"
[[route.rules]]
inbound = "tun-in"
network = "udp"
ip = "192.0.2.60"
action = "route"
outbound = "direct"
[dns]
[[dns.inbounds]]
tag = "dns-control"
listen = "127.0.0.1:5300"
[[dns.servers]]
tag = "resolver"
transport = "udp"
address = "127.0.0.1:5301"
[dns.route]
final = "resolver"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#,
        )
        .expect("TUN UDP modes config");
        let config = ferrum2_config::load_client(&path).expect("validated TUN UDP modes");
        std::fs::remove_file(path).expect("remove TUN UDP modes config");
        let inbound = config.inbounds.len();
        let selector = config.selector_control();
        let outbounds = prepare_client_outbounds(config.outbounds).expect("outbound contexts");
        let routing = ClientRouting {
            legacy: config.route,
            program: config.route_program,
            outbounds,
            selector,
        };
        let metrics = ferrum2_observability::Metrics::new();
        let synthetic_v4 = Ipv4Addr::new(198, 18, 0, 1);
        let synthetic_target =
            TargetAddr::ip("198.18.0.1:53".parse().expect("synthetic DNS target"))
                .expect("synthetic DNS target");
        let synthetic = select_udp_target(
            &routing,
            inbound,
            Some(synthetic_v4),
            None,
            &synthetic_target,
            b"query",
            1_392,
            &metrics,
        )
        .expect("synthetic DNS plan");
        assert!(matches!(synthetic, TunUdpPlan::SyntheticDns));

        let direct_target = TargetAddr::ip("192.0.2.60:443".parse().unwrap()).unwrap();
        let proxy_target = TargetAddr::ip("192.0.2.61:443".parse().unwrap()).unwrap();
        let first = select_udp_target(
            &routing,
            inbound,
            Some(synthetic_v4),
            None,
            &direct_target,
            b"direct-a",
            1_392,
            &metrics,
        )
        .expect("first ordinary plan");
        let TunUdpPlan::Route {
            snapshot: frozen,
            request_payload_bound: frozen_bound,
            ..
        } = first
        else {
            panic!("first ordinary target must select Direct");
        };
        assert_eq!(frozen.hops(), &[1]);

        let encoded = metrics.encode_text().expect("route-once metrics");
        assert!(
            encoded.lines().any(|line| {
                line.starts_with("ferrum2_rule_program_candidate_count_count{program=\"route\"}")
                    && line.ends_with(" 1")
            }),
            "synthetic DNS plus the first ordinary target must invoke the router once\n{encoded}"
        );

        let verification_metrics = ferrum2_observability::Metrics::new();
        let independently_selected_second = select_udp_target(
            &routing,
            inbound,
            Some(synthetic_v4),
            None,
            &proxy_target,
            b"proxy-b",
            1_392,
            &verification_metrics,
        )
        .expect("independent target-B policy witness");
        let TunUdpPlan::Route {
            snapshot: independently_selected_second,
            request_payload_bound: proxy_bound,
            ..
        } = independently_selected_second
        else {
            panic!("target B proxy route");
        };
        assert_eq!(independently_selected_second.hops(), &[0]);
        assert_eq!(frozen.hops(), &[1]);
        assert!(
            frozen_bound > proxy_bound,
            "Direct and proxy should retain distinct plan limits"
        );
        assert!(target_payload_within_bound(proxy_bound + 1, frozen_bound));
    }

    #[tokio::test]
    async fn managed_tun_lifecycle_cancelled_prepare_cleanup_failure_maps_to_shutdown_cleanup() {
        let entered = Arc::new(Notify::new());
        let prepare_entered = Arc::clone(&entered);
        let root = ProcessRoot::new_cancellable(move |mut cancellation| async move {
            prepare_entered.notify_one();
            cancellation.cancelled().await;
            Err::<Option<NeverPrepared>, _>(RunError::ShutdownCleanup)
        });
        let supervisor =
            ProcessSupervisor::new(vec![root], Duration::from_secs(1), OwnerRegistry::new())
                .expect("one required root");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let run = tokio::spawn(supervisor.run_until(async move {
            let _ = shutdown_rx.await;
        }));

        entered.notified().await;
        shutdown_tx.send(()).expect("shutdown");
        let report = run.await.expect("process owner");
        assert_eq!(report_result(report), Err(RunError::ShutdownCleanup));
    }

    #[tokio::test]
    async fn tun_auto_dns_tcp_answer_failure_closes_flow_before_ordinary_route() {
        let fallback = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("fallback listener");
        let fallback_address = match fallback.local_addr().expect("fallback address") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!("IPv4 fallback"),
        };
        let dns_upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("DNS upstream");
        let dns_address = dns_upstream.local_addr().expect("DNS upstream address");
        let dns_inbound = reserve_address();
        let (path, _) = client_test_config(reserve_address(), fallback_address);
        std::fs::write(
            &path,
            format!(
                r#"schema_version = 2
[tun]
tag = "tun-in"
adapter_name = "Ferrum2"
ipv4_address = "198.18.0.2/30"
ipv6_address = "fd00::2/126"
[[outbounds]]
tag = "fallback"
server = "{fallback_address}"
[route]
final = "fallback"
[dns]
[[dns.inbounds]]
tag = "dns-control"
listen = "{dns_inbound}"
[[dns.servers]]
tag = "resolver"
transport = "udp"
address = "{dns_address}"
[dns.route]
final = "resolver"
[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#
            ),
        )
        .expect("TUN DNS failure config");
        let config = ferrum2_config::load_client(&path).expect("validated TUN DNS config");
        std::fs::remove_file(&path).expect("remove TUN DNS config");
        let runtime = config.runtime;
        let selector = config.selector_control();
        let test_server = match config.outbounds[0].server().unwrap() {
            SocketAddr::V4(server) => server,
            SocketAddr::V6(_) => panic!("IPv4 test server"),
        };
        let outbounds = prepare_client_outbounds(config.outbounds).expect("test outbounds");
        let routing = Arc::new(ClientRouting {
            legacy: config.route,
            program: config.route_program,
            outbounds: Arc::clone(&outbounds),
            selector,
        });
        let (resolver, mut resolver_owner) = TaggedResolver::direct(
            vec![DnsUpstreamSpec {
                transport: DnsUpstreamTransport::Udp,
                target: TargetAddr::ip(dns_address).expect("numeric DNS target"),
                resolved_targets: Box::new([]),
                detour: None,
            }],
            Duration::from_secs(1),
            NonZeroU16::new(1).expect("one DNS query"),
        )
        .expect("test resolver");
        resolver_owner.ready().await.expect("resolver ready");
        let proxy = Arc::new(DnsProxy::new(Arc::new(resolver), |_, _, _, _| Some(0)));
        let dns = Arc::new(std::sync::OnceLock::new());
        assert!(dns.set(proxy).is_ok(), "one DNS proxy");
        let registry = OwnerRegistry::new();
        let context = Arc::new(ClientContext {
            inbound: Socks5Inbound::new(),
            egress: Arc::new(ClientEgressEngine::new(
                outbounds,
                TokioConnector::new(TcpConnector::with_resolution_adapters(
                    ferrum2_runtime::SystemSocketInspector,
                    ferrum2_runtime::SystemTcpDialer,
                    crate::run::egress::system_application_resolver(),
                    runtime.connect_timeout,
                )),
                SystemClock::new(),
                SystemRandom,
                (runtime.connect_timeout, runtime.handshake_timeout),
                None,
                None,
            )),
            keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(default_test_psk())),
            runtime,
            udp_associate_enabled: false,
            registry: registry.clone(),
            metrics: Arc::new(Metrics::new()),
            dns: Some(dns),
            test_udp_server: test_server,
        });

        let (cancellation_sender, cancellation_receiver) = tokio::sync::oneshot::channel();
        let root = ProcessRoot::new_cancellable(move |mut cancellation| async move {
            cancellation_sender
                .send(cancellation.clone())
                .expect("one cancellation view");
            cancellation.cancelled().await;
            Ok::<Option<NeverPrepared>, RunError>(None)
        });
        let cancellation_registry = OwnerRegistry::new();
        let supervisor = ProcessSupervisor::new(
            vec![root],
            Duration::from_secs(1),
            cancellation_registry.clone(),
        )
        .expect("cancellation root");
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
        let supervisor = tokio::spawn(supervisor.run_until(async move {
            let _ = shutdown_receiver.await;
        }));
        let cancellation = cancellation_receiver.await.expect("active cancellation");

        let target: SocketAddr = "192.0.2.53:53".parse().expect("DNS target");
        let (flow, mut peer) = tokio::io::duplex(64);
        peer.write_all(&[0, 1, 0])
            .await
            .expect("malformed DNS frame");
        peer.shutdown().await.expect("DNS request half-close");
        run_tcp(
            target,
            flow,
            cancellation.clone(),
            Arc::clone(&context),
            routing,
            0,
            SyntheticDns {
                ipv4: Some(Ipv4Addr::new(192, 0, 2, 53)),
                ipv6: None,
            },
            None,
        )
        .await;
        assert_eq!(peer.read(&mut [0; 1]).await.expect("terminal close"), 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), fallback.accept())
                .await
                .is_err(),
            "DNS failure evaluated the final route or fallback egress"
        );
        assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());

        let direct_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("direct TUN TCP target");
        let direct_target = direct_listener.local_addr().expect("direct TUN target");
        let direct_registry = OwnerRegistry::new();
        let direct_outbounds =
            prepare_client_outbounds(vec![ferrum2_config::ClientOutboundConfig::Direct {
                domain_resolver: ferrum2_config::DirectDomainResolver::System,
                dial_options: Default::default(),
            }])
            .expect("direct TUN outbound");
        let direct_routing = Arc::new(ClientRouting {
            legacy: ferrum2_rule::RouteTable::static_bindings(vec![0]).expect("direct TUN route"),
            program: None,
            outbounds: Arc::clone(&direct_outbounds),
            selector: ferrum2_rule::SelectorControl::empty(),
        });
        let direct_context = Arc::new(ClientContext {
            inbound: Socks5Inbound::new(),
            egress: Arc::new(ClientEgressEngine::new(
                direct_outbounds,
                TokioConnector::new(TcpConnector::with_resolution_adapters(
                    ferrum2_runtime::SystemSocketInspector,
                    ferrum2_runtime::SystemTcpDialer,
                    crate::run::egress::system_application_resolver(),
                    context.runtime.connect_timeout,
                )),
                SystemClock::new(),
                SystemRandom,
                (
                    context.runtime.connect_timeout,
                    context.runtime.handshake_timeout,
                ),
                None,
                None,
            )),
            keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(default_test_psk())),
            runtime: context.runtime,
            udp_associate_enabled: false,
            registry: direct_registry.clone(),
            metrics: Arc::new(Metrics::new()),
            dns: None,
            test_udp_server: reserve_address(),
        });
        let target = tokio::spawn(async move {
            let (mut stream, _) = direct_listener.accept().await.expect("direct TUN accept");
            let mut request = Vec::new();
            stream
                .read_to_end(&mut request)
                .await
                .expect("direct TUN target read");
            stream
                .write_all(b"tun-reply")
                .await
                .expect("direct TUN target reply");
            stream
                .shutdown()
                .await
                .expect("direct TUN target half close");
            request
        });
        let (flow, mut peer) = tokio::io::duplex(64);
        let direct = tokio::spawn(run_tcp(
            direct_target,
            flow,
            cancellation.clone(),
            direct_context,
            direct_routing,
            0,
            SyntheticDns::default(),
            None,
        ));
        peer.write_all(b"tun-direct")
            .await
            .expect("direct TUN write");
        peer.shutdown().await.expect("direct TUN half close");
        let mut response = Vec::new();
        peer.read_to_end(&mut response)
            .await
            .expect("direct TUN response");
        assert_eq!(response, b"tun-reply");
        assert_eq!(
            target.await.expect("direct TUN target owner"),
            b"tun-direct"
        );
        direct.await.expect("direct TUN relay owner");
        assert_eq!(active(direct_registry.snapshot()), OwnerSnapshot::default());

        shutdown_sender.send(()).expect("stop cancellation root");
        assert_eq!(
            report_result(supervisor.await.expect("cancellation supervisor")),
            Ok(())
        );
        drop(context);
        resolver_owner.shutdown().await.expect("resolver shutdown");
        assert_eq!(
            active(cancellation_registry.snapshot()),
            OwnerSnapshot::default()
        );
    }
}
