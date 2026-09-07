use std::net::SocketAddr;
use std::sync::Arc;

use ferrum2_core::TargetAddr;
use ferrum2_core::route::Network;
use ferrum2_dns::DnsProxy;
use ferrum2_observability::TunUdpAssociationRouteResult;

use crate::run::context::{ClientContext, ClientRouting};
use crate::run::egress::composed_udp_plan_limit;
use crate::run::routing::{ClientTerminalRoute, RouteGeneration, RouteGenerationChange};
use crate::run::tun::tcp::is_synthetic_dns_target;

use super::association::{SyntheticDns, TunUdpPlan};

#[derive(Clone, Copy)]
pub(in crate::run::tun) struct TunUdpRouteRequest<'a> {
    pub(in crate::run::tun) routing: &'a ClientRouting,
    pub(in crate::run::tun) inbound: usize,
    pub(in crate::run::tun) synthetic_dns: SyntheticDns,
    pub(in crate::run::tun) target: &'a TargetAddr,
    pub(in crate::run::tun) payload: &'a [u8],
    pub(in crate::run::tun) metrics: &'a ferrum2_observability::Metrics,
}

pub(in crate::run::tun) fn select_udp_target_generation_stable(
    request: TunUdpRouteRequest<'_>,
    scratch: &mut ferrum2_rule::RuleEvaluationScratch,
) -> Result<(RouteGeneration, TunUdpPlan), ferrum2_rule::RuleCompileError> {
    let before = request.routing.route_generation();
    let plan = match select_udp_target_with_scratch(request, scratch) {
        Ok(plan) => plan,
        Err(error) => {
            request
                .metrics
                .tun_udp_association_route(TunUdpAssociationRouteResult::Failure);
            return Err(error);
        }
    };
    let after = request.routing.route_generation();
    if before != after {
        request
            .metrics
            .tun_udp_association_route(TunUdpAssociationRouteResult::StaleGeneration);
        return Err(ferrum2_rule::RuleCompileError::Internal);
    }
    match &plan {
        TunUdpPlan::Route { .. } | TunUdpPlan::HijackDns => request
            .metrics
            .tun_udp_association_route(TunUdpAssociationRouteResult::Success),
        TunUdpPlan::Reject => request
            .metrics
            .tun_udp_association_route(TunUdpAssociationRouteResult::Rejected),
        // Synthetic DNS is preprocessing for the same source-keyed association. Its first
        // ordinary datagram performs and records the association's sole route evaluation.
        TunUdpPlan::SyntheticDns => {}
    }
    Ok((after, plan))
}

fn select_udp_target_with_scratch(
    request: TunUdpRouteRequest<'_>,
    scratch: &mut ferrum2_rule::RuleEvaluationScratch,
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
                ferrum2_shadowsocks::UdpPacketDirection::Request,
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
pub(in crate::run::tun) fn select_udp_target(
    routing: &ClientRouting,
    inbound: usize,
    ipv4_dns_address: Option<std::net::Ipv4Addr>,
    ipv6_dns_address: Option<std::net::Ipv6Addr>,
    target: &TargetAddr,
    payload: &[u8],
    _response_payload_bound: usize,
    metrics: &ferrum2_observability::Metrics,
) -> Option<TunUdpPlan> {
    let mut scratch = routing.route_scratch().ok()?;
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
        &mut scratch,
    )
    .ok()
}

pub(in crate::run::tun) fn tun_dns_proxy(context: &ClientContext) -> Option<Arc<DnsProxy>> {
    context
        .dns
        .as_ref()
        .and_then(|proxy| proxy.get())
        .map(Arc::clone)
}

pub(in crate::run::tun) fn udp_route_generation_is_current(
    routing: &ClientRouting,
    generation: RouteGeneration,
) -> bool {
    routing.route_generation() == generation
}

pub(super) async fn wait_for_optional_udp_route_generation_change(
    route_change: Option<&mut RouteGenerationChange>,
) {
    match route_change {
        Some(route_change) => route_change.await,
        None => std::future::pending().await,
    }
}

pub(super) struct RouteEgress {
    pub(super) egress: crate::run::egress::ClientUdpAssociation,
    pub(super) cancelled: tokio::sync::watch::Receiver<bool>,
    request_payload_bound: usize,
}

impl RouteEgress {
    pub(super) async fn prepare(
        services: &super::association::DispatchServices,
        generation: &mut super::association::OrdinaryGeneration,
        first_target: &TargetAddr,
        snapshot: ferrum2_core::route::EgressPlanSnapshot,
        request_payload_bound: usize,
    ) -> Option<Self> {
        if !services.current(Some(generation)) {
            return None;
        }
        let mut forced = services.cancellation.clone();
        let mut egress = tokio::select! {
            biased;
            () = forced.forced() => return None,
            () = services.session_cancellation.cancelled() => return None,
            () = &mut generation.changed => return None,
            prepared = services.context.egress.prepare_udp_for_ingress(
                crate::run::egress::ClientRequestOrigin::Tun, services.inbound,
                Some(snapshot), Some(first_target),
            ) => prepared.ok()?,
        };
        if !services.current(Some(generation)) {
            return None;
        }
        egress.activate(&services.context.egress).ok()?;
        let cancelled = egress.cancellation().ok()?;
        services.current(Some(generation)).then_some(Self {
            egress,
            cancelled,
            request_payload_bound,
        })
    }

    pub(super) async fn send(
        &mut self,
        datagram: ferrum2_tun::UdpDatagram,
        services: &super::association::DispatchServices,
        generation: &mut super::association::OrdinaryGeneration,
        peer_policy: &ferrum2_tun::UdpPeerPolicyHandle,
    ) -> bool {
        use super::association::{
            commit_peer_after_success, reserve_tun_udp_peer, target_payload_within_bound,
        };
        use crate::run::egress::UdpPlanResponseError;
        use ferrum2_observability::{Direction, Outcome, Role};
        let target = datagram.target();
        let Ok(application_target) = TargetAddr::ip(target) else {
            return true;
        };
        if !target_payload_within_bound(datagram.payload().len(), self.request_payload_bound) {
            return true;
        }
        let Some(peer) = reserve_tun_udp_peer(peer_policy, target.ip()) else {
            return true;
        };
        let payload_len = datagram.payload().len();
        let wire_len = match self.egress.prepare_application_request(
            &services.context.egress,
            &services.routing.outbounds,
            application_target,
            datagram.payload(),
            tokio::time::Instant::now(),
        ) {
            Ok(length) => length,
            Err(UdpPlanResponseError::Packet(_) | UdpPlanResponseError::Runtime(_)) => return true,
        };
        drop(datagram);
        let mut forced = services.cancellation.clone();
        let sent = tokio::select! {
            biased;
            () = forced.forced() => return false,
            () = services.session_cancellation.cancelled() => return false,
            () = &mut generation.changed => return false,
            changed = self.cancelled.changed() => { let _ = changed; return false; }
            result = self.egress.send_encoded_request(wire_len) => result,
        };
        if !services.current(Some(generation)) {
            return false;
        }
        if !commit_peer_after_success(sent, wire_len, || peer.commit()) {
            return false;
        }
        services.context.metrics.udp_datagram(
            Role::Client,
            Direction::ClientToTarget,
            Outcome::Accepted,
        );
        services.context.metrics.add_udp_bytes(
            Role::Client,
            Direction::ClientToTarget,
            payload_len as u64,
        );
        true
    }

    pub(super) fn accept_response(
        &mut self,
        wire_len: usize,
        services: &super::association::DispatchServices,
        generation: &super::association::OrdinaryGeneration,
        response_sink: &ferrum2_tun::UdpResponseSink,
    ) -> bool {
        use ferrum2_observability::{Direction, Outcome, Role};
        if !services.current(Some(generation)) {
            return false;
        }
        let Ok(response) = self.egress.prepare_application_response(
            &services.context.egress,
            &services.routing.outbounds,
            wire_len,
        ) else {
            return true;
        };
        let Some(source) = response.datagram().target().as_socket_addr() else {
            return true;
        };
        let payload = response.datagram().payload();
        if !services.current(Some(generation)) {
            return false;
        }
        let outcome = response_sink.send(source, payload);
        if !services.current(Some(generation)) {
            return false;
        }
        if super::association::record_tun_udp_response_outcome(outcome) {
            services.context.metrics.udp_datagram(
                Role::Client,
                Direction::TargetToClient,
                Outcome::Accepted,
            );
            services.context.metrics.add_udp_bytes(
                Role::Client,
                Direction::TargetToClient,
                payload.len() as u64,
            );
        }
        self.egress.recycle_application_response(response);
        true
    }
}
