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
#[cfg(any(windows, test))]
pub(in crate::run) use network::io_error_from_network_service;
#[cfg(test)]
pub(in crate::run) use network::test_application_resolver;
pub(in crate::run) use network::{ClientDnsResetAction, ClientNetworkResetHub};
#[cfg(all(windows, not(test)))]
pub(in crate::run) use network::{ClientNetworkSocketService, NetworkServiceConnector};
pub(super) use udp::{
    ClientUdpAssociation, ClientUdpContext, UdpPlanResponseError, composed_udp_plan_limit,
};
#[cfg(test)]
pub(super) use udp::{
    IdSequenceRandom, UdpIoFaultPlan, UdpIoOperation, composed_udp_request_limit,
    composed_udp_response_limit,
};
