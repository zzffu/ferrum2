use std::net::SocketAddr;
use std::sync::Arc;

use ferrum2_core::TargetAddr;
use ferrum2_core::route::EgressPlanSnapshot;
use ferrum2_dns::DnsProxy;
use ferrum2_observability::{Direction, Metrics, Outcome, Role, TunUdpAssociationRouteResult};
use ferrum2_runtime::ProcessCancellation;
use tokio::time::Instant;

use crate::run::context::{ClientContext, ClientRouting};
use crate::run::egress::{ClientRequestOrigin, ClientUdpAssociation, UdpPlanResponseError};
use crate::run::routing::{RouteGeneration, RouteGenerationChange};

use super::dns::{answer_tun_udp_dns, run_udp_dns_association};
use super::route::{
    TunUdpRouteRequest, select_udp_target_generation_stable, tun_dns_proxy,
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

pub(in crate::run::tun) async fn run_udp(
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
        context
            .metrics
            .tun_udp_association_route(TunUdpAssociationRouteResult::Failure);
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
        select_udp_target_generation_stable(first_request, &mut route_scratch)
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
            context
                .metrics
                .tun_udp_association_route(TunUdpAssociationRouteResult::Failure);
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
            select_udp_target_generation_stable(request, &mut route_scratch)
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
        biased;
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

pub(in crate::run::tun) async fn wait_for_session_cancellation(
    session_cancellation: &Option<ferrum2_tun::SessionCancellation>,
) {
    match session_cancellation {
        Some(session_cancellation) => session_cancellation.cancelled().await,
        None => std::future::pending().await,
    }
}
