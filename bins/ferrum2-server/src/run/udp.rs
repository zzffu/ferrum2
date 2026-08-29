mod admission;
mod commit;
mod identity;
mod listener;
mod listener_bind;
mod physical;
#[cfg_attr(feature = "candidate-udp-owned-headroom", allow(dead_code))]
mod response_codec;
mod route;
mod run_loop;
#[cfg(test)]
mod tests;

pub(in crate::run) use admission::{
    ServerUdpShared, prepare_udp_server_with_network, udp_runtime_limits,
    validate_udp_listener_budget,
};
#[cfg(all(windows, not(test)))]
pub(in crate::run) use identity::ServerUdpNetworkReset;
pub(in crate::run) use identity::UdpMappings;
pub(in crate::run) use listener_bind::{bind_server_udp_listener, validate_udp_receive_workers};
