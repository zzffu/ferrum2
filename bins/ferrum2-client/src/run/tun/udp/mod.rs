mod association;
mod dns;
mod route;

pub(super) use association::{SyntheticDns, run_udp, wait_for_session_cancellation};
#[cfg(test)]
pub(super) use association::{
    TunUdpPlan, authorize_dns_peer_after_answer, commit_peer_after_success,
    target_payload_within_bound,
};
#[cfg(test)]
pub(super) use route::select_udp_target;
#[cfg(test)]
pub(super) use route::{
    TunUdpRouteRequest, select_udp_target_generation_stable, udp_route_generation_is_current,
};
