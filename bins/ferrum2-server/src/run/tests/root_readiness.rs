#![allow(unused_imports)]

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use ferrum2_core::{ConnectError, Connector, TargetAddr};
use ferrum2_crypto::{MethodProfile, MethodTcpSalt};
use ferrum2_runtime::OwnerSnapshot;
use ferrum2_shadowsocks::{ClientTcpOutbound, UdpClientSession, encode_request_first_write};
use hickory_proto::op::{Message, OpCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record, RecordType};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::super::*;
use crate::run::test_support::*;

#[test]
fn dns_policy_and_state_failures_keep_closed_runtime_categories() {
    for error in [
        ferrum2_dns::DnsPolicyCompileError::Allocation,
        ferrum2_dns::DnsPolicyCompileError::IndexOverflow,
    ] {
        assert_eq!(
            run_error_for_dns_policy_compile(error),
            RunError::RuleAllocation
        );
        assert_eq!(
            run_error_for_dns_state(dns_egress::ServerDnsStateBuildError::DnsPolicy(error)),
            RunError::RuleAllocation
        );
    }
    for error in [
        ferrum2_dns::DnsPolicyCompileError::EmptyRule,
        ferrum2_dns::DnsPolicyCompileError::InvalidQueryMatchSet,
        ferrum2_dns::DnsPolicyCompileError::DuplicateConstraint,
        ferrum2_dns::DnsPolicyCompileError::InvalidPortRange,
        ferrum2_dns::DnsPolicyCompileError::UnknownRuleSet,
        ferrum2_dns::DnsPolicyCompileError::ResponseDependentReject,
        ferrum2_dns::DnsPolicyCompileError::Internal,
    ] {
        assert_eq!(
            run_error_for_dns_policy_compile(error),
            RunError::RuleCompile
        );
        assert_eq!(
            run_error_for_dns_state(dns_egress::ServerDnsStateBuildError::DnsPolicy(error)),
            RunError::RuleCompile
        );
    }
    assert_eq!(
        run_error_for_dns_state(dns_egress::ServerDnsStateBuildError::CacheAllocation),
        RunError::RuleAllocation
    );
    assert_eq!(
        run_error_for_dns_state(dns_egress::ServerDnsStateBuildError::InvalidRuntime),
        RunError::StartupProtocol
    );
}

#[test]
fn validated_server_network_policies_reach_the_shared_runtime_resolver() {
    struct NoRouteCatalog;

    impl ferrum2_net::NetworkInterfaceCatalog for NoRouteCatalog {
        fn read_interfaces(
            &self,
        ) -> Result<
            Vec<ferrum2_net::NetworkInterfaceObservation>,
            ferrum2_net::NetworkInterfaceCatalogError,
        > {
            Err(ferrum2_net::NetworkInterfaceCatalogError)
        }

        fn system_best_route(
            &self,
            _: SocketAddr,
        ) -> Result<ferrum2_net::SystemBestRoute, ferrum2_net::NetworkInterfaceCatalogError>
        {
            Err(ferrum2_net::NetworkInterfaceCatalogError)
        }
    }

    let listen = reserve_address();
    let source = format!(
        r#"schema_version = 2
[[inbounds]]
tag = "server"
listen = "{listen}"

[[outbounds]]
tag = "direct"
bind_interface = "Server Ethernet"
inet4_bind_address = "198.51.100.10"
inet6_bind_address = "2001:db8::20"

[route]
auto_detect_interface = true
default_interface = "Fallback Ethernet"
final = "direct"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#
    );
    let (path, config) = server_test_config_source("network-policy-retention", &source);
    let route = runtime_route_network(&config.route_network);
    let dial = runtime_dial_options(config.outbounds[0].dial_options());
    assert!(route.auto_detect_interface());
    assert_eq!(route.default_interface(), Some("Fallback Ethernet"));
    assert_eq!(dial.bind_interface(), Some("Server Ethernet"));

    let binding = ferrum2_net::InterfaceBinding::new(
        "Server Ethernet",
        17,
        23,
        [
            "198.51.100.10".parse().unwrap(),
            "2001:db8::20".parse().unwrap(),
        ],
    )
    .unwrap();
    let snapshot =
        ferrum2_net::NetworkSnapshot::new(1, Some(binding.clone()), Some(binding)).unwrap();
    let resolved = ferrum2_net::NetworkInterfaceResolver::new(NoRouteCatalog)
        .resolve(&dial, &route, "203.0.113.9:443".parse().unwrap(), &snapshot)
        .unwrap();
    assert_eq!(
        resolved.selection_source(),
        ferrum2_net::InterfaceSelectionSource::OutboundExplicit
    );
    assert_eq!(
        resolved.source_address(),
        Some("198.51.100.10".parse().unwrap())
    );
    std::fs::remove_file(path).unwrap();
}
