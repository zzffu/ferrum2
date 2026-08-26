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
