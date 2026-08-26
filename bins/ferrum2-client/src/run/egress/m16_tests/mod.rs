use super::super::context::SelectedEgress;
use super::super::network::ClientPhysicalConnector;
use super::*;
use crate::run::test_support::*;
use ferrum2_runtime::{
    NetworkRuntimeResourceAdmissionError, NetworkSocketServiceError, SystemNetworkSocketError,
};

mod engine;
mod network;

pub(in crate::run) use network::{ApplicationRoute, EmptyNetworkCatalog, RoutedApplicationBackend};

fn explicit_interface_error() -> NetworkSocketServiceError<SystemNetworkSocketError<()>> {
    let snapshot = ferrum2_net::NetworkSnapshot::new(1, None, None).unwrap();
    let resolver = ferrum2_net::NetworkInterfaceResolver::new(EmptyNetworkCatalog);
    let resolution = resolver
        .resolve(
            &DialOptions::new(Some("missing-interface"), None, None),
            &RouteNetworkOptions::default(),
            "203.0.113.1:443".parse().unwrap(),
            &snapshot,
        )
        .unwrap_err();
    NetworkSocketServiceError::Admission(NetworkRuntimeResourceAdmissionError::InterfaceResolution(
        resolution,
    ))
}

fn proxy() -> ferrum2_config::ClientOutboundConfig {
    ferrum2_config::ClientOutboundConfig::Shadowsocks {
        server: "198.51.100.222:62016".parse().unwrap(),
        psk: Arc::new(ferrum2_crypto::MethodPsk::aes128(*b"m16-secret-key!!")),
        dial_options: Default::default(),
    }
}

fn selected(hops: Vec<usize>) -> EgressPlanSnapshot {
    let (_, handles) = ferrum2_core::route::compile_egress_plans_with_roots(
        &[TaggedInbound::new("entry", 0)],
        &[
            TaggedOutbound::new("direct-a", 0),
            TaggedOutbound::new("direct-b", 1),
            TaggedOutbound::new("m16-tag-sentinel", 2),
        ],
        &[TaggedPlan::new("selected", hops)],
        &[],
        &["selected", "direct-a", "direct-b", "m16-tag-sentinel"],
    )
    .expect("selected plan");
    handles[0].snapshot_owned()
}
