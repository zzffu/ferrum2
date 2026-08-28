mod context;
mod engine;
mod network;
mod tcp;
mod udp;

pub(in crate::run) use context::{
    ClientOutboundContext, ClientRequestOrigin, ClientShadowsocksContext, prepare_client_outbounds,
    runtime_dial_options, runtime_route_network,
};
pub(in crate::run) use engine::{ClientEgressEngine, ClientOpenFailure, ClientPlanFailure};
pub(in crate::run) use network::ClientDnsResetAction;
#[cfg(any(windows, test))]
pub(in crate::run) use network::io_error_from_network_service;
#[cfg(test)]
pub(in crate::run) use network::system_application_resolver;
#[cfg(all(windows, not(test)))]
pub(in crate::run) use network::{ClientNetworkSocketService, NetworkServiceConnector};
pub(in crate::run) use tcp::ClientTcpFlow;
pub(super) use udp::{
    ClientUdpAssociation, ClientUdpContext, UdpPlanResponseError, UdpSendError,
    composed_udp_plan_limit, send_with_lifecycle,
};
#[cfg(test)]
pub(super) use udp::{
    IdSequenceRandom, UdpIoFaultPlan, UdpIoOperation, composed_udp_request_limit,
    composed_udp_response_limit,
};
#[cfg(test)]
pub(in crate::run) const MAX_UDP_PLAN_HOPS: usize = udp::MAX_UDP_PLAN_HOPS;
