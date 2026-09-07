use std::net::SocketAddr;
use std::sync::Arc;

use ferrum2_core::TargetAddr;
use ferrum2_core::route::EgressPlanSnapshot;
use ferrum2_dns::DnsProxy;
use ferrum2_observability::{Direction, Outcome, Role, TunUdpAssociationRouteResult};
use ferrum2_runtime::ProcessCancellation;
use tokio::time::Instant;

use crate::run::context::{ClientContext, ClientRouting};
use crate::run::routing::{RouteGeneration, RouteGenerationChange};

use super::dns::answer_tun_udp_dns;
use super::route::{
    RouteEgress, TunUdpRouteRequest, select_udp_target_generation_stable, tun_dns_proxy,
    udp_route_generation_is_current,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::run::tun) struct SyntheticDns {
    pub(in crate::run::tun) ipv4: Option<std::net::Ipv4Addr>,
    pub(in crate::run::tun) ipv6: Option<std::net::Ipv6Addr>,
}

impl SyntheticDns {
    pub(in crate::run::tun) fn matches(self, target: SocketAddr) -> bool {
        match target {
            SocketAddr::V4(target) => target.port() == 53 && Some(*target.ip()) == self.ipv4,
            SocketAddr::V6(target) => target.port() == 53 && Some(*target.ip()) == self.ipv6,
        }
    }
}

#[derive(Clone)]
pub(in crate::run::tun) enum TunUdpPlan {
    Route {
        snapshot: EgressPlanSnapshot,
        request_payload_bound: usize,
    },
    SyntheticDns,
    HijackDns,
    Reject,
}

pub(in crate::run::tun) const fn target_payload_within_bound(
    payload_len: usize,
    payload_bound: usize,
) -> bool {
    payload_len <= payload_bound
}

pub(super) struct DispatchServices {
    pub(super) cancellation: ProcessCancellation,
    pub(super) session_cancellation: ferrum2_tun::SessionCancellation,
    pub(super) context: Arc<ClientContext>,
    pub(super) routing: Arc<ClientRouting>,
    pub(super) inbound: usize,
    synthetic_dns: SyntheticDns,
    proxy: Option<Arc<DnsProxy>>,
}

pub(super) struct OrdinaryGeneration {
    pub(super) value: RouteGeneration,
    pub(super) changed: RouteGenerationChange,
}

enum OrdinaryTerminal {
    Reject,
    Route(Box<RouteEgress>),
    HijackDns,
}

enum OrdinaryPolicy {
    Unselected,
    Selected {
        generation: OrdinaryGeneration,
        terminal: OrdinaryTerminal,
    },
}

impl OrdinaryPolicy {
    fn generation(&self) -> Option<&OrdinaryGeneration> {
        match self {
            Self::Unselected => None,
            Self::Selected { generation, .. } => Some(generation),
        }
    }
    fn generation_mut(&mut self) -> Option<&mut OrdinaryGeneration> {
        match self {
            Self::Unselected => None,
            Self::Selected { generation, .. } => Some(generation),
        }
    }
    fn terminal(&self) -> Option<&OrdinaryTerminal> {
        match self {
            Self::Unselected => None,
            Self::Selected { terminal, .. } => Some(terminal),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum DatagramAction {
    Dns,
    SelectOrdinary,
    Reject,
    Route,
}

fn datagram_action(
    synthetic: SyntheticDns,
    target: SocketAddr,
    terminal: Option<&OrdinaryTerminal>,
) -> DatagramAction {
    if synthetic.matches(target) {
        return DatagramAction::Dns;
    }
    match terminal {
        None => DatagramAction::SelectOrdinary,
        Some(OrdinaryTerminal::Reject) => DatagramAction::Reject,
        Some(OrdinaryTerminal::HijackDns) => DatagramAction::Dns,
        Some(OrdinaryTerminal::Route(_)) => DatagramAction::Route,
    }
}

impl DispatchServices {
    pub(super) fn current(&self, generation: Option<&OrdinaryGeneration>) -> bool {
        !self.cancellation.is_forced()
            && !self.session_cancellation.is_cancelled()
            && generation.is_none_or(|generation| {
                udp_route_generation_is_current(&self.routing, generation.value)
            })
    }

    async fn select_ordinary(&self, target: SocketAddr, payload: &[u8]) -> Option<OrdinaryPolicy> {
        let Ok(mut scratch) = self.routing.route_scratch() else {
            self.context
                .metrics
                .tun_udp_association_route(TunUdpAssociationRouteResult::Failure);
            return None;
        };
        let target = TargetAddr::ip(target).ok()?;
        let (value, plan) = select_udp_target_generation_stable(
            TunUdpRouteRequest {
                routing: &self.routing,
                inbound: self.inbound,
                synthetic_dns: self.synthetic_dns,
                target: &target,
                payload,
                metrics: &self.context.metrics,
            },
            &mut scratch,
        )
        .ok()?;
        let mut generation = OrdinaryGeneration {
            value,
            changed: self.routing.watch_route_generation_from(value),
        };
        let terminal = match plan {
            TunUdpPlan::Route {
                snapshot,
                request_payload_bound,
            } => {
                if !target_payload_within_bound(payload.len(), request_payload_bound) {
                    return None;
                }
                OrdinaryTerminal::Route(Box::new(
                    RouteEgress::prepare(
                        self,
                        &mut generation,
                        &target,
                        snapshot,
                        request_payload_bound,
                    )
                    .await?,
                ))
            }
            TunUdpPlan::HijackDns => {
                self.proxy.as_ref()?;
                OrdinaryTerminal::HijackDns
            }
            TunUdpPlan::Reject => OrdinaryTerminal::Reject,
            TunUdpPlan::SyntheticDns => return None,
        };
        self.current(Some(&generation))
            .then_some(OrdinaryPolicy::Selected {
                generation,
                terminal,
            })
    }
}

pub(in crate::run::tun) async fn run_udp(
    candidate: ferrum2_tun::UdpCandidate,
    cancellation: ProcessCancellation,
    context: Arc<ClientContext>,
    routing: Arc<ClientRouting>,
    inbound: usize,
    synthetic_dns: SyntheticDns,
    session_cancellation: ferrum2_tun::SessionCancellation,
) {
    let services = DispatchServices {
        proxy: tun_dns_proxy(&context),
        cancellation,
        session_cancellation,
        context,
        routing,
        inbound,
        synthetic_dns,
    };
    let ordinary = if synthetic_dns.matches(candidate.first_target()) {
        if services.proxy.is_none() {
            return;
        }
        OrdinaryPolicy::Unselected
    } else {
        let Some(policy) = services
            .select_ordinary(candidate.first_target(), candidate.first_payload())
            .await
        else {
            return;
        };
        policy
    };
    // First ordinary egress admission and request bounds are checked before the
    // native candidate commit. The association keeps the TUN packet ceiling so
    // later synthetic answers do not inherit a proxy request bound.
    let Ok(association) = candidate.commit_association().await else {
        return;
    };
    let response_sink = association.response_sink();
    let peer_policy = association.peer_policy();
    TunUdpDispatch {
        association,
        ordinary,
        services,
        response_sink,
        peer_policy,
    }
    .run()
    .await;
}

struct TunUdpDispatch {
    association: ferrum2_tun::UdpAssociation,
    ordinary: OrdinaryPolicy,
    services: DispatchServices,
    response_sink: ferrum2_tun::UdpResponseSink,
    peer_policy: ferrum2_tun::UdpPeerPolicyHandle,
}

enum DispatchEvent {
    Stop,
    Datagram(Option<ferrum2_tun::UdpDatagram>),
    Response(std::io::Result<usize>),
    Idle(Instant),
}

impl TunUdpDispatch {
    async fn run(mut self) {
        loop {
            if !self.services.current(self.ordinary.generation()) {
                return;
            }
            match self.next_event().await {
                DispatchEvent::Stop | DispatchEvent::Datagram(None) => return,
                DispatchEvent::Datagram(Some(datagram)) => {
                    if !self.dispatch(datagram).await {
                        return;
                    }
                }
                DispatchEvent::Response(Err(_)) => return,
                DispatchEvent::Response(Ok(wire_len)) => {
                    let OrdinaryPolicy::Selected {
                        generation,
                        terminal: OrdinaryTerminal::Route(route),
                    } = &mut self.ordinary
                    else {
                        return;
                    };
                    if !route.accept_response(
                        wire_len,
                        &self.services,
                        generation,
                        &self.response_sink,
                    ) {
                        return;
                    }
                }
                DispatchEvent::Idle(deadline) => {
                    let OrdinaryPolicy::Selected {
                        terminal: OrdinaryTerminal::Route(route),
                        ..
                    } = &self.ordinary
                    else {
                        return;
                    };
                    if route.egress.idle_expired(deadline) {
                        return;
                    }
                }
            }
        }
    }

    async fn dispatch(&mut self, datagram: ferrum2_tun::UdpDatagram) -> bool {
        if !self.services.current(self.ordinary.generation()) {
            return false;
        }
        let mut action = datagram_action(
            self.services.synthetic_dns,
            datagram.target(),
            self.ordinary.terminal(),
        );
        if action == DatagramAction::SelectOrdinary {
            let Some(policy) = self
                .services
                .select_ordinary(datagram.target(), datagram.payload())
                .await
            else {
                return false;
            };
            self.ordinary = policy;
            action = match self.ordinary.terminal() {
                Some(OrdinaryTerminal::Reject) => DatagramAction::Reject,
                Some(OrdinaryTerminal::HijackDns) => DatagramAction::Dns,
                Some(OrdinaryTerminal::Route(_)) => DatagramAction::Route,
                None => return false,
            };
        }
        match action {
            DatagramAction::Dns => {
                let Some(proxy) = &self.services.proxy else {
                    return true;
                };
                answer_tun_udp_dns(
                    datagram,
                    proxy,
                    &self.services,
                    self.ordinary.generation_mut(),
                    &self.response_sink,
                    &self.peer_policy,
                )
                .await
            }
            DatagramAction::Reject => {
                self.services.context.metrics.udp_datagram(
                    Role::Client,
                    Direction::ClientToTarget,
                    Outcome::Rejected,
                );
                true
            }
            DatagramAction::Route => {
                let OrdinaryPolicy::Selected {
                    generation,
                    terminal: OrdinaryTerminal::Route(route),
                } = &mut self.ordinary
                else {
                    return false;
                };
                route
                    .send(datagram, &self.services, generation, &self.peer_policy)
                    .await
            }
            DatagramAction::SelectOrdinary => unreachable!("ordinary selection completed"),
        }
    }

    async fn next_event(&mut self) -> DispatchEvent {
        let (generation_change, route) = match &mut self.ordinary {
            OrdinaryPolicy::Unselected => (None, None),
            OrdinaryPolicy::Selected {
                generation,
                terminal,
            } => (
                Some(&mut generation.changed),
                match terminal {
                    OrdinaryTerminal::Route(route) => Some(route),
                    OrdinaryTerminal::Reject | OrdinaryTerminal::HijackDns => None,
                },
            ),
        };
        let (egress, egress_cancelled, idle_deadline) = match route {
            Some(route) => {
                let Ok(deadline) = route.egress.idle_deadline() else {
                    return DispatchEvent::Stop;
                };
                (
                    Some(&mut route.egress),
                    Some(&mut route.cancelled),
                    Some(deadline),
                )
            }
            None => (None, None, None),
        };
        let mut forced = self.services.cancellation.clone();
        tokio::select! {
            biased;
            () = forced.forced() => DispatchEvent::Stop,
            () = self.services.session_cancellation.cancelled() => DispatchEvent::Stop,
            () = super::route::wait_for_optional_udp_route_generation_change(generation_change) => DispatchEvent::Stop,
            () = async { match egress_cancelled { Some(cancelled) => { let _ = cancelled.changed().await; }, None => std::future::pending().await } } => DispatchEvent::Stop,
            deadline = async { match idle_deadline { Some(deadline) => { tokio::time::sleep_until(deadline).await; deadline }, None => std::future::pending().await } } => DispatchEvent::Idle(deadline),
            datagram = self.association.receive() => DispatchEvent::Datagram(datagram),
            response = async { match egress { Some(egress) => egress.receive_response_wire().await, None => std::future::pending().await } } => DispatchEvent::Response(response),
        }
    }
}

pub(super) enum TunUdpPeerReservation {
    Pending(ferrum2_tun::UdpPeerReservation),
    Ready,
}

impl TunUdpPeerReservation {
    pub(super) fn commit(self) -> bool {
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

pub(super) fn reserve_tun_udp_peer(
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

pub(in crate::run::tun) fn commit_peer_after_success<E>(
    sent: Result<usize, E>,
    expected: usize,
    commit: impl FnOnce() -> bool,
) -> bool {
    if !matches!(sent, Ok(length) if length == expected) {
        return false;
    }
    commit()
}

pub(in crate::run::tun) fn authorize_dns_peer_after_answer<T>(
    response: Option<T>,
    target: SocketAddr,
    authorize: impl FnOnce(std::net::IpAddr) -> bool,
) -> Option<T> {
    let response = response?;
    authorize(target.ip()).then_some(response)
}

pub(super) fn record_tun_udp_response_outcome(
    outcome: ferrum2_tun::UdpResponseSendOutcome,
) -> bool {
    outcome == ferrum2_tun::UdpResponseSendOutcome::Queued
}

pub(in crate::run::tun) async fn wait_for_session_cancellation(
    session_cancellation: &Option<ferrum2_tun::SessionCancellation>,
) {
    match session_cancellation {
        Some(session_cancellation) => session_cancellation.cancelled().await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests;
