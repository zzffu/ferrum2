use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ferrum2_config::TunConfig;
use ferrum2_core::TargetAddr;
use ferrum2_core::route::{EgressPlanSnapshot, Network};
use ferrum2_dns::{ProxyIngress, ProxyTransport};
use ferrum2_observability::{
    Direction, Metrics, Outcome, Role, TunDiagnosticReason, TunIpFamily, TunPacketRejectReason,
    TunUdpResponseDropReason, emit_tun_diagnostic,
};
use ferrum2_runtime::{ProcessCancellation, ProcessRoot, relay_lifecycle};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::Instant;

use super::RunError;
use super::context::{ClientContext, ClientRouting};
use super::egress::{ClientRequestOrigin, UdpPlanResponseError, composed_udp_plan_limit};
use super::routing::{ClientTerminalRoute, ReplayIo, RouteGeneration, relay_hijacked_tcp};
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
    let synthetic_dns = SyntheticDns {
        ipv4: config.ipv4_dns_address,
        ipv6: config.ipv6_dns_address,
    };
    let metrics = Arc::clone(&context.metrics);
    let handler_context = Arc::clone(&context);
    let udp_context = Arc::clone(&context);
    let tcp_routing = Arc::clone(&routing);
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
        },
        underlay,
        RunError::StartupProtocol,
        RunError::RuntimeRoot,
        RunError::ShutdownCleanup,
        context.registry.clone(),
        move |flow, cancellation, session_cancellation| {
            let context = Arc::clone(&handler_context);
            let routing = Arc::clone(&tcp_routing);
            Box::pin(run_tcp(
                flow.target(),
                flow,
                cancellation,
                context,
                routing,
                inbound,
                synthetic_dns,
                Some(session_cancellation),
            ))
        },
        move |candidate, cancellation, session_cancellation| {
            let context = Arc::clone(&udp_context);
            let routing = Arc::clone(&routing);
            Box::pin(run_udp(
                candidate,
                cancellation,
                context,
                routing,
                inbound,
                synthetic_dns,
                session_cancellation,
            ))
        },
        move |event| record_tun_event(&metrics, event),
    )
}

fn record_tun_event(metrics: &Metrics, event: ferrum2_tun::TunEvent) {
    use ferrum2_tun::TunEvent;

    match event {
        TunEvent::PacketAccepted => metrics.tun_packet_accepted(),
        TunEvent::PacketFoundationDropped => metrics.tun_packet_foundation_dropped(),
        TunEvent::SessionStarted => metrics.tun_session_started(),
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

const TUN_UDP_TARGET_CAPACITY: usize = 256;
const TUN_UDP_TARGET_QUEUE_DEPTH: usize = 16;

#[derive(Clone)]
enum TunUdpTargetPlan {
    Route {
        snapshot: EgressPlanSnapshot,
        payload_bound: usize,
    },
    SyntheticDns,
    HijackDns,
    Reject,
}

struct TunUdpTargetChild {
    id: u64,
    sender: mpsc::Sender<ferrum2_tun::UdpDatagram>,
    abort: tokio::task::AbortHandle,
}

impl Drop for TunUdpTargetChild {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct TunUdpTargetKey {
    target: SocketAddr,
    route_generation: RouteGeneration,
}

struct TunUdpTargetTable<K, T> {
    entries: HashMap<K, T>,
    capacity: usize,
}

impl<K, T> TunUdpTargetTable<K, T>
where
    K: Copy + Eq + std::hash::Hash,
{
    fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity),
            capacity,
        }
    }

    fn get(&self, key: K) -> Option<&T> {
        self.entries.get(&key)
    }

    fn insert(&mut self, key: K, child: T) -> Result<(), T> {
        if self.entries.len() >= self.capacity {
            return Err(child);
        }
        match self.entries.entry(key) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(child);
                Ok(())
            }
            std::collections::hash_map::Entry::Occupied(_) => Err(child),
        }
    }

    fn remove(&mut self, key: K) -> Option<T> {
        self.entries.remove(&key)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

impl<K> TunUdpTargetTable<K, TunUdpTargetChild>
where
    K: Copy + Eq + std::hash::Hash,
{
    fn remove_closed(&mut self) {
        self.entries.retain(|_, child| !child.sender.is_closed());
    }
}

impl TunUdpTargetTable<TunUdpTargetKey, TunUdpTargetChild> {
    fn remove_stale_generations(&mut self, generation: RouteGeneration) {
        self.entries
            .retain(|key, _| key.route_generation == generation);
    }
}

async fn commit_udp_candidate_if_admitted<T, E, F, Fut>(
    plan: &TunUdpTargetPlan,
    commit: F,
) -> Result<Option<T>, E>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    if matches!(plan, TunUdpTargetPlan::Reject) {
        return Ok(None);
    }
    commit().await.map(Some)
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
    let Ok(mut route_scratch) = routing.route_scratch() else {
        return;
    };
    let first_target = candidate.first_target();
    let Ok(first_application_target) = TargetAddr::ip(first_target) else {
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
    let Ok((first_route_generation, first_plan)) =
        select_udp_target_generation_stable(first_request, route_scratch.as_mut())
    else {
        return;
    };
    let Ok(Some(mut association)) =
        commit_udp_candidate_if_admitted(&first_plan, || candidate.commit_association()).await
    else {
        return;
    };
    let response = association.response_sink();
    let peer_policy = association.peer_policy();
    let mut first_plan = Some((
        TunUdpTargetKey {
            target: first_target,
            route_generation: first_route_generation,
        },
        first_plan,
    ));
    let mut targets: TunUdpTargetTable<TunUdpTargetKey, TunUdpTargetChild> =
        TunUdpTargetTable::new(TUN_UDP_TARGET_CAPACITY);
    let mut children = JoinSet::new();
    let mut next_child_id = 0_u64;

    loop {
        let mut forced = cancellation.clone();
        tokio::select! {
            () = forced.forced() => break,
            () = session_cancellation.cancelled() => break,
            completed = children.join_next(), if !children.is_empty() => {
                if let Some(Ok((key, id))) = completed
                    && targets.get(key).is_some_and(|child| child.id == id)
                {
                    targets.remove(key);
                }
            }
            datagram = association.receive() => {
                let Some(datagram) = datagram else { break };
                let target = datagram.target();
                let route_generation = routing.route_generation();
                targets.remove_stale_generations(route_generation);
                let key = TunUdpTargetKey {
                    target,
                    route_generation,
                };
                let existing = targets
                    .get(key)
                    .map(|child| (child.id, child.sender.clone()));
                let datagram = if let Some((id, sender)) = existing {
                    match sender.try_send(datagram) {
                        Ok(()) => continue,
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            context.metrics.tun_udp_datagram_queue_full();
                            context
                                .metrics
                                .tun_packet_rejected(TunPacketRejectReason::UdpQueueFull);
                            continue;
                        }
                        Err(mpsc::error::TrySendError::Closed(error)) => {
                            if targets.get(key).is_some_and(|child| child.id == id) {
                                targets.remove(key);
                            }
                            error
                        }
                    }
                } else {
                    datagram
                };

                targets.remove_closed();
                if targets.len() >= TUN_UDP_TARGET_CAPACITY
                    || children.len() >= TUN_UDP_TARGET_CAPACITY
                {
                    context.metrics.tun_udp_datagram_queue_full();
                    context
                        .metrics
                        .tun_packet_rejected(TunPacketRejectReason::UdpQueueFull);
                    continue;
                }
                let Ok(application_target) = TargetAddr::ip(target) else {
                    continue;
                };
                let selected = match first_plan.take() {
                    Some((first_key, plan)) if first_key == key => (key.route_generation, plan),
                    Some(first) => {
                        first_plan = Some(first);
                        let request = TunUdpRouteRequest {
                            routing: &routing,
                            inbound,
                            synthetic_dns,
                            target: &application_target,
                            payload: datagram.payload(),
                            metrics: &context.metrics,
                        };
                        let Ok(selected) = select_udp_target_generation_stable(
                            request,
                            route_scratch.as_mut(),
                        ) else {
                            continue;
                        };
                        selected
                    }
                    None => {
                        let request = TunUdpRouteRequest {
                            routing: &routing,
                            inbound,
                            synthetic_dns,
                            target: &application_target,
                            payload: datagram.payload(),
                            metrics: &context.metrics,
                        };
                        let Ok(selected) = select_udp_target_generation_stable(
                            request,
                            route_scratch.as_mut(),
                        ) else {
                            continue;
                        };
                        selected
                    }
                };
                let (route_generation, plan) = selected;
                let key = TunUdpTargetKey {
                    target,
                    route_generation,
                };
                targets.remove_stale_generations(route_generation);
                let (sender, receiver) = mpsc::channel(TUN_UDP_TARGET_QUEUE_DEPTH);
                if sender.try_send(datagram).is_err() {
                    continue;
                }
                let id = next_child_id;
                next_child_id = next_child_id.wrapping_add(1);
                let child_context = Arc::clone(&context);
                let child_routing = Arc::clone(&routing);
                let child_cancellation = cancellation.clone();
                let child_session_cancellation = session_cancellation.clone();
                let child_response = response.clone();
                let child_peer_policy = peer_policy.clone();
                let abort = children.spawn(async move {
                    run_udp_target_child(
                        target,
                        route_generation,
                        plan,
                        receiver,
                        child_cancellation,
                        child_session_cancellation,
                        child_context,
                        child_routing,
                        inbound,
                        child_response,
                        child_peer_policy,
                    )
                    .await;
                    (key, id)
                });
                if targets
                    .insert(key, TunUdpTargetChild { id, sender, abort })
                    .is_err()
                {
                    continue;
                }
            }
        }
    }

    drop(targets);
    children.abort_all();
    while children.join_next().await.is_some() {}
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
    mut scratch: Option<&mut ferrum2_rule::RuleEvaluationScratch>,
) -> Result<(RouteGeneration, TunUdpTargetPlan), ferrum2_rule::RuleCompileError> {
    for _ in 0..3 {
        let before = request.routing.route_generation();
        let plan = select_udp_target_with_scratch(request, scratch.as_deref_mut())?;
        let after = request.routing.route_generation();
        if before == after {
            return Ok((after, plan));
        }
    }
    Err(ferrum2_rule::RuleCompileError::Internal)
}

fn select_udp_target_with_scratch(
    request: TunUdpRouteRequest<'_>,
    scratch: Option<&mut ferrum2_rule::RuleEvaluationScratch>,
) -> Result<TunUdpTargetPlan, ferrum2_rule::RuleCompileError> {
    if is_synthetic_dns_target(request.target, request.synthetic_dns) {
        return Ok(TunUdpTargetPlan::SyntheticDns);
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
                return Ok(TunUdpTargetPlan::Reject);
            };
            let encoded_target_len = match target {
                SocketAddr::V4(_) => 7,
                SocketAddr::V6(_) => 19,
            };
            let payload_bound = composed_udp_plan_limit(
                &request.routing.outbounds,
                plan.hops(),
                false,
                encoded_target_len,
            );
            TunUdpTargetPlan::Route {
                snapshot: plan,
                payload_bound,
            }
        }
        ClientTerminalRoute::HijackDns => TunUdpTargetPlan::HijackDns,
        ClientTerminalRoute::Reject => TunUdpTargetPlan::Reject,
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
) -> Option<TunUdpTargetPlan> {
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

#[allow(clippy::too_many_arguments)]
async fn run_udp_target_child(
    target: SocketAddr,
    route_generation: RouteGeneration,
    plan: TunUdpTargetPlan,
    receiver: mpsc::Receiver<ferrum2_tun::UdpDatagram>,
    cancellation: ProcessCancellation,
    session_cancellation: ferrum2_tun::SessionCancellation,
    context: Arc<ClientContext>,
    routing: Arc<ClientRouting>,
    inbound: usize,
    response: ferrum2_tun::UdpResponseSink,
    peer_policy: ferrum2_tun::UdpPeerPolicyHandle,
) {
    match plan {
        TunUdpTargetPlan::Route {
            snapshot,
            payload_bound,
        } => {
            run_udp_route_child(
                target,
                route_generation,
                payload_bound,
                receiver,
                cancellation,
                session_cancellation,
                context,
                routing,
                inbound,
                response,
                peer_policy,
                snapshot,
            )
            .await;
        }
        TunUdpTargetPlan::SyntheticDns | TunUdpTargetPlan::HijackDns => {
            run_udp_dns_child(
                target,
                route_generation,
                receiver,
                cancellation,
                session_cancellation,
                context,
                routing,
                inbound,
                response,
                peer_policy,
            )
            .await;
        }
        TunUdpTargetPlan::Reject => {
            run_udp_reject_child(receiver, cancellation, session_cancellation).await;
        }
    }
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
async fn run_udp_route_child(
    target: SocketAddr,
    route_generation: RouteGeneration,
    payload_bound: usize,
    mut receiver: mpsc::Receiver<ferrum2_tun::UdpDatagram>,
    cancellation: ProcessCancellation,
    session_cancellation: ferrum2_tun::SessionCancellation,
    context: Arc<ClientContext>,
    routing: Arc<ClientRouting>,
    inbound: usize,
    response_sink: ferrum2_tun::UdpResponseSink,
    peer_policy: ferrum2_tun::UdpPeerPolicyHandle,
    plan: EgressPlanSnapshot,
) {
    if routing.route_generation() != route_generation {
        return;
    }
    let mut force = cancellation.clone();
    let Ok(original_target) = TargetAddr::ip(target) else {
        return;
    };
    let prepared = tokio::select! {
        () = force.forced() => return,
        () = session_cancellation.cancelled() => return,
        prepared = context.egress.prepare_udp_for_ingress(
            ClientRequestOrigin::Tun,
            inbound,
            Some(plan),
            Some(&original_target),
        ) => prepared,
    };
    let Ok(mut association) = prepared else {
        return;
    };
    if association.activate(&context.egress).is_err() {
        return;
    }
    let Ok(mut session_cancelled) = association.cancellation() else {
        return;
    };
    loop {
        if routing.route_generation() != route_generation {
            return;
        }
        let Ok(idle_deadline) = association.idle_deadline() else {
            return;
        };
        let mut forced = cancellation.clone();
        tokio::select! {
            () = forced.forced() => return,
            () = session_cancellation.cancelled() => return,
            changed = session_cancelled.changed() => {
                let _ = changed;
                return;
            }
            () = tokio::time::sleep_until(idle_deadline) => {
                if association.idle_expired(idle_deadline) {
                    return;
                }
            }
            datagram = receiver.recv() => {
                let Some(datagram) = datagram else { return };
                if routing.route_generation() != route_generation {
                    return;
                }
                if datagram.target() != target
                    || !target_payload_within_bound(datagram.payload().len(), payload_bound)
                {
                    continue;
                }
                let Some(peer_reservation) = reserve_tun_udp_peer(&peer_policy, target.ip()) else {
                    return;
                };
                let payload_len = datagram.payload().len();
                let wire_len = match association.prepare_application_request(
                    &context.egress,
                    &routing.outbounds,
                    original_target.clone(),
                    datagram.payload(),
                    Instant::now(),
                ) {
                    Ok(length) => length,
                    Err(UdpPlanResponseError::Packet(_)
                        | UdpPlanResponseError::Runtime(_)) => continue,
                };
                drop(datagram);
                let mut send_forced = cancellation.clone();
                let sent = tokio::select! {
                    () = send_forced.forced() => return,
                    () = session_cancellation.cancelled() => return,
                    changed = session_cancelled.changed() => {
                        let _ = changed;
                        return;
                    }
                    result = association.send_encoded_request(wire_len) => result,
                };
                if session_cancellation.is_cancelled()
                    || routing.route_generation() != route_generation
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
            }
            received = association.receive_response_wire() => {
                let Ok(wire_len) = received else { return };
                if session_cancellation.is_cancelled()
                    || routing.route_generation() != route_generation
                {
                    return;
                }
                let Ok(response) = association.prepare_application_response(
                    &context.egress,
                    &routing.outbounds,
                    wire_len,
                ) else {
                    continue;
                };
                let Some(source) = response.datagram().target().as_socket_addr() else { continue };
                let payload = response.datagram().payload();
                if record_tun_udp_response_outcome(response_sink.send(source, payload)) {
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
                association.recycle_application_response(response);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_udp_dns_child(
    target: SocketAddr,
    route_generation: RouteGeneration,
    mut receiver: mpsc::Receiver<ferrum2_tun::UdpDatagram>,
    cancellation: ProcessCancellation,
    session_cancellation: ferrum2_tun::SessionCancellation,
    context: Arc<ClientContext>,
    routing: Arc<ClientRouting>,
    inbound: usize,
    response_sink: ferrum2_tun::UdpResponseSink,
    peer_policy: ferrum2_tun::UdpPeerPolicyHandle,
) {
    if routing.route_generation() != route_generation {
        return;
    }
    let Some(proxy) = context
        .dns
        .as_ref()
        .and_then(|proxy| proxy.get())
        .map(Arc::clone)
    else {
        return;
    };
    loop {
        let mut forced = cancellation.clone();
        let datagram = tokio::select! {
            () = forced.forced() => return,
            () = session_cancellation.cancelled() => return,
            datagram = receiver.recv() => datagram,
        };
        let Some(datagram) = datagram else { return };
        if routing.route_generation() != route_generation {
            return;
        }
        if datagram.target() != target {
            continue;
        }
        let mut answer_forced = cancellation.clone();
        let response = tokio::select! {
            () = answer_forced.forced() => return,
            () = session_cancellation.cancelled() => return,
            response = proxy.answer(
                    ProxyIngress::Ordinary(inbound),
                    ProxyTransport::Udp,
                    datagram.payload(),
                ) => response,
        };
        if session_cancellation.is_cancelled() || routing.route_generation() != route_generation {
            return;
        }
        if let Some(response) = authorize_dns_peer_after_answer(response, target, |peer| {
            reserve_tun_udp_peer(&peer_policy, peer).is_some_and(TunUdpPeerReservation::commit)
        }) {
            // Both synthetic and ordinary hijack-DNS replies originate from the
            // exact endpoint selected for this target. ADF authorization is
            // published only after a successful local answer exists.
            record_tun_udp_response_outcome(response_sink.send(target, &response));
        }
    }
}

async fn run_udp_reject_child(
    mut receiver: mpsc::Receiver<ferrum2_tun::UdpDatagram>,
    cancellation: ProcessCancellation,
    session_cancellation: ferrum2_tun::SessionCancellation,
) {
    loop {
        let mut forced = cancellation.clone();
        if tokio::select! {
            () = forced.forced() => None,
            () = session_cancellation.cancelled() => None,
            datagram = receiver.recv() => datagram,
        }
        .is_none()
        {
            return;
        }
    }
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
        SyntheticDns, TUN_UDP_TARGET_CAPACITY, TunUdpRouteRequest, TunUdpTargetChild,
        TunUdpTargetKey, TunUdpTargetPlan, TunUdpTargetTable, authorize_dns_peer_after_answer,
        commit_peer_after_success, commit_udp_candidate_if_admitted, record_tun_event, run_tcp,
        select_udp_target, select_udp_target_generation_stable, target_payload_within_bound,
    };

    #[test]
    fn every_tun_event_maps_to_one_exact_metric_or_closed_diagnostic() {
        use ferrum2_tun::{
            TunDiagnosticReason, TunEvent, TunIpFamily, TunRejectReason, UdpResponseDropReason,
        };

        let metrics = ferrum2_observability::Metrics::new();
        let events = [
            TunEvent::PacketAccepted,
            TunEvent::PacketFoundationDropped,
            TunEvent::SessionStarted,
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
        assert!(!rejected.is_empty(), "closed reject series are prebound");
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

    #[test]
    fn tun_udp_target_table_is_drop_new_without_lru_eviction() {
        let first: SocketAddr = "192.0.2.1:1".parse().unwrap();
        let mut targets = TunUdpTargetTable::new(TUN_UDP_TARGET_CAPACITY);
        for port in 1..=u16::try_from(TUN_UDP_TARGET_CAPACITY).unwrap() {
            targets
                .insert(SocketAddr::new(first.ip(), port), port)
                .expect("target below fixed capacity");
        }
        let newcomer: SocketAddr = "192.0.2.1:257".parse().unwrap();
        assert_eq!(targets.insert(newcomer, 257), Err(257));
        assert_eq!(targets.len(), TUN_UDP_TARGET_CAPACITY);
        assert_eq!(targets.get(first), Some(&1), "oldest live target remains");
        assert!(targets.get(newcomer).is_none(), "new target is dropped");
    }

    #[tokio::test]
    async fn tun_udp_target_children_have_isolated_bounded_queues() {
        let first: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let second: SocketAddr = "198.51.100.1:53".parse().unwrap();
        let (first_sender, mut first_receiver) = tokio::sync::mpsc::channel(1);
        let (second_sender, mut second_receiver) = tokio::sync::mpsc::channel(1);
        let mut targets = TunUdpTargetTable::new(2);
        targets.insert(first, first_sender).unwrap();
        targets.insert(second, second_sender).unwrap();

        targets.get(first).unwrap().try_send(b'a').unwrap();
        targets.get(second).unwrap().try_send(b'b').unwrap();
        assert!(targets.get(first).unwrap().try_send(b'x').is_err());
        assert_eq!(first_receiver.recv().await, Some(b'a'));
        assert_eq!(second_receiver.recv().await, Some(b'b'));
    }

    #[tokio::test]
    async fn selector_switch_rekeys_and_retires_tun_udp_target_child() {
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
        let target_socket = target.as_socket_addr().unwrap();
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
        let TunUdpTargetPlan::Route {
            snapshot: first_snapshot,
            ..
        } = first_plan
        else {
            panic!("first route target");
        };
        assert_eq!(first_snapshot.hops(), &[0, 1]);

        let first_key = TunUdpTargetKey {
            target: target_socket,
            route_generation: first_generation,
        };
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let mut tasks = tokio::task::JoinSet::new();
        let abort = tasks.spawn(std::future::pending::<()>());
        let mut targets = TunUdpTargetTable::new(1);
        assert!(
            targets
                .insert(
                    first_key,
                    TunUdpTargetChild {
                        id: 0,
                        sender,
                        abort,
                    },
                )
                .is_ok(),
            "first child"
        );

        selector.switch("manual", "a-b").expect("no-op switch");
        assert!(selector.switch("manual", "missing").is_err());
        assert_eq!(routing.route_generation(), first_generation);
        targets.remove_stale_generations(first_generation);
        assert!(targets.get(first_key).is_some(), "no-op retired child");

        selector.switch("manual", "c-d").expect("effective switch");
        let (second_generation, second_plan) = select_udp_target_generation_stable(
            TunUdpRouteRequest {
                routing: &routing,
                inbound: 0,
                synthetic_dns: SyntheticDns::default(),
                target: &target,
                payload: b"second",
                metrics: &metrics,
            },
            None,
        )
        .expect("second stable generation");
        let TunUdpTargetPlan::Route {
            snapshot: second_snapshot,
            ..
        } = second_plan
        else {
            panic!("second route target");
        };
        assert_ne!(second_generation, first_generation);
        assert_eq!(second_snapshot.hops(), &[2, 3]);

        targets.remove_stale_generations(second_generation);
        assert!(targets.get(first_key).is_none());
        assert!(receiver.recv().await.is_none(), "stale sender stayed alive");
        let cancelled = tasks
            .join_next()
            .await
            .expect("stale task")
            .expect_err("stale task was not aborted");
        assert!(cancelled.is_cancelled());

        let second_key = TunUdpTargetKey {
            target: target_socket,
            route_generation: second_generation,
        };
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let abort = tasks.spawn(std::future::pending::<()>());
        assert!(
            targets
                .insert(
                    second_key,
                    TunUdpTargetChild {
                        id: 1,
                        sender,
                        abort,
                    },
                )
                .is_ok(),
            "new-generation child"
        );
        assert!(targets.get(second_key).is_some());
        drop(targets);
        let cancelled = tasks
            .join_next()
            .await
            .expect("new task")
            .expect_err("table drop did not abort child");
        assert!(cancelled.is_cancelled());
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
        let TunUdpTargetPlan::Route {
            snapshot: first_snapshot,
            ..
        } = first_plan
        else {
            panic!("first schema-v2 route");
        };
        assert_eq!(first_snapshot.hops(), &[0]);

        selector.switch("manual", "proxy").expect("selector switch");
        let (second_generation, second_plan) = select(b"second", &mut scratch);
        let TunUdpTargetPlan::Route {
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
    async fn rejected_first_udp_target_never_commits_association() {
        let committed = std::cell::Cell::new(false);
        let result = commit_udp_candidate_if_admitted(&TunUdpTargetPlan::Reject, || async {
            committed.set(true);
            Ok::<_, ()>(())
        })
        .await;
        assert_eq!(result, Ok(None));
        assert!(!committed.get(), "Reject invoked the association commit");

        let result = commit_udp_candidate_if_admitted(&TunUdpTargetPlan::SyntheticDns, || async {
            committed.set(true);
            Ok::<_, ()>(7_u8)
        })
        .await;
        assert_eq!(result, Ok(Some(7)));
        assert!(
            committed.get(),
            "admitted target skipped association commit"
        );
    }

    #[tokio::test]
    async fn tun_udp_target_plan_is_bounded_and_immutable_after_selection() {
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
        let TunUdpTargetPlan::Route {
            snapshot: first_snapshot,
            payload_bound: bound,
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
        let TunUdpTargetPlan::Route {
            snapshot: oversized_snapshot,
            payload_bound: oversized_bound,
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
                .expect("current per-target selector");
        let TunUdpTargetPlan::Route { snapshot, .. } = selected else {
            panic!("route target plan");
        };
        assert_eq!(snapshot.hops(), &[2, 3]);
        selector
            .switch("manual", "a-b")
            .expect("switch after terminal snapshot");
        assert_eq!(
            snapshot.hops(),
            &[2, 3],
            "target child owns an immutable plan snapshot"
        );

        let registry = OwnerRegistry::new();
        let live_ids = Arc::new(Mutex::new(HashSet::new()));
        let outbounds = prepare_client_outbounds(vec![
            ferrum2_config::ClientOutboundConfig::Direct {
                domain_resolver: ferrum2_config::DirectDomainResolver::System,
            },
            ferrum2_config::ClientOutboundConfig::Shadowsocks {
                server: "192.0.2.77:8388".parse().unwrap(),
                psk: Arc::new(default_test_psk()),
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
        let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("direct TUN UDP target");
        let target = TargetAddr::ip(echo.local_addr().unwrap()).unwrap();
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
        let TunUdpTargetPlan::Route {
            snapshot: direct,
            payload_bound: bound,
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
        direct_selector
            .switch("manual", "proxy")
            .expect("switch after direct snapshot");
        assert_eq!(direct.hops(), &[0], "Direct TUN target child is immutable");
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
        let (length, peer) = echo.recv_from(&mut raw).await.expect("direct TUN receive");
        assert_eq!(&raw[..length], b"tun-direct");
        echo.send_to(b"tun-reply", peer).await.unwrap();
        let length = association.receive_response_wire().await.unwrap();
        let response = association
            .prepare_application_response(&engine, &routing.outbounds, length)
            .unwrap_or_else(|_| panic!("direct TUN response"));
        assert_eq!(response.datagram().target(), &target);
        assert_eq!(response.datagram().payload(), b"tun-reply");
        association.recycle_application_response(response);
        assert!(live_ids.lock().expect("live SIP022 IDs").is_empty());
    }

    #[test]
    fn tun_udp_targets_independently_select_direct_proxy_dns_and_reject() {
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
        for (address, expected) in [("192.0.2.53:53", "dns"), ("192.0.2.54:53", "reject")] {
            let target = TargetAddr::ip(address.parse().expect("target")).expect("target");
            let plan = select_udp_target(
                &routing, inbound, None, None, &target, b"query", 1_392, &metrics,
            )
            .expect("terminal mode");
            assert!(
                matches!(
                    (plan, expected),
                    (TunUdpTargetPlan::HijackDns, "dns") | (TunUdpTargetPlan::Reject, "reject")
                ),
                "ordinary route fallback did not replace the terminal mode"
            );
        }

        let direct_target = TargetAddr::ip("192.0.2.60:443".parse().unwrap()).unwrap();
        let proxy_target = TargetAddr::ip("192.0.2.61:443".parse().unwrap()).unwrap();
        let direct = select_udp_target(
            &routing,
            inbound,
            None,
            None,
            &direct_target,
            b"direct-a",
            1_392,
            &metrics,
        )
        .expect("target A plan");
        let proxy = select_udp_target(
            &routing,
            inbound,
            None,
            None,
            &proxy_target,
            b"proxy-b",
            1_392,
            &metrics,
        )
        .expect("target B plan");
        let TunUdpTargetPlan::Route {
            snapshot: direct,
            payload_bound: direct_bound,
        } = direct
        else {
            panic!("target A direct route");
        };
        let TunUdpTargetPlan::Route {
            snapshot: proxy,
            payload_bound: proxy_bound,
        } = proxy
        else {
            panic!("target B proxy route");
        };
        assert_eq!(direct.hops(), &[1], "target A independently selects Direct");
        assert_eq!(proxy.hops(), &[0], "target B independently selects proxy");
        assert!(
            direct_bound > proxy_bound,
            "Direct and proxy should retain distinct plan limits"
        );
        let between_limits = proxy_bound + 1;
        assert!(target_payload_within_bound(between_limits, direct_bound));
        assert!(!target_payload_within_bound(between_limits, proxy_bound));

        let synthetic_v4 = Ipv4Addr::new(198, 18, 0, 1);
        let synthetic_v6 = "fd00::1".parse().unwrap();
        for (target, configured_v4, configured_v6, hijacked) in [
            ("198.18.0.1:53", Some(synthetic_v4), None, true),
            ("[fd00::1]:53", None, Some(synthetic_v6), true),
            ("198.18.0.1:54", Some(synthetic_v4), None, false),
            ("[fd00::1]:54", None, Some(synthetic_v6), false),
            ("198.18.0.2:53", Some(synthetic_v4), None, false),
            ("[fd00::2]:53", None, Some(synthetic_v6), false),
            ("198.18.0.1:53", None, Some(synthetic_v6), false),
            ("[fd00::1]:53", Some(synthetic_v4), None, false),
        ] {
            let target = TargetAddr::ip(target.parse().unwrap()).unwrap();
            let plan = select_udp_target(
                &routing,
                inbound,
                configured_v4,
                configured_v6,
                &target,
                b"query",
                1_392,
                &metrics,
            )
            .expect("bounded synthetic candidate");
            assert_eq!(
                matches!(plan, TunUdpTargetPlan::SyntheticDns),
                hijacked,
                "synthetic target {target:?}"
            );
        }

        let synthetic_target: SocketAddr = "198.18.0.1:53".parse().unwrap();
        let synthetic = select_udp_target(
            &routing,
            inbound,
            Some(synthetic_v4),
            None,
            &TargetAddr::ip(synthetic_target).unwrap(),
            b"query",
            1_392,
            &metrics,
        )
        .unwrap();
        let ordinary_target = direct_target.as_socket_addr().unwrap();
        let ordinary = select_udp_target(
            &routing,
            inbound,
            Some(synthetic_v4),
            None,
            &direct_target,
            b"ordinary",
            1_392,
            &metrics,
        )
        .unwrap();
        let mut coexist = TunUdpTargetTable::new(2);
        assert!(coexist.insert(synthetic_target, synthetic).is_ok());
        assert!(coexist.insert(ordinary_target, ordinary).is_ok());
        assert!(matches!(
            coexist.get(synthetic_target),
            Some(TunUdpTargetPlan::SyntheticDns)
        ));
        assert!(matches!(
            coexist.get(ordinary_target),
            Some(TunUdpTargetPlan::Route { .. })
        ));
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
