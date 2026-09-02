#![allow(dead_code)]

use std::fs;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use ferrum2_config::{
    ClientV2Resources, ServerV2Resources, finish_client_v2, finish_server_v2, prepare_client,
    prepare_server,
};

const PSK: &str = "AAECAwQFBgcICQoLDA0ODw==";

mod dns_resource {
    pub(super) const DNS_MAX_INFLIGHT: u16 = 32;
}

mod profile_contract {
    pub(super) const PROFILE_UDP_MAX_BUFFERED_BYTES: usize = 16 * 1024 * 1024;
}

#[path = "../src/m4_support/proxy_config.rs"]
mod proxy_config;

fn address(port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)
}

fn write_config(source: &str) -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::new().expect("temporary proxy config");
    fs::write(file.path(), source).expect("write proxy config");
    file
}

#[test]
fn generated_client_configs_prepare_and_finish_through_the_real_v2_contract() {
    let proxy = address(10_800);
    let server = address(8_388);
    let unselected = address(8_389);
    let direct = proxy_config::profile_direct_udp_client_config(address(10_801));
    let dns_concurrency =
        proxy_config::profile_dns_client_config(address(10_805), address(5_359), address(5_360));
    let ordinary = proxy_config::ferrum_client_config(proxy, server, Some(address(9_090)));
    let dns_resource = proxy_config::ferrum_dns_resource_client_config(
        proxy,
        server,
        address(5_353),
        address(5_354),
        address(5_355),
        address(5_356),
        address(9_091),
    );
    let profile_shadowsocks =
        proxy_config::profile_shadowsocks_udp_client_config(address(10_802), server);
    let m14_udp = proxy_config::m14_udp_client_config(
        address(10_803),
        server,
        unselected,
        address(20_001),
        address(20_002),
        1_048_576,
    );
    let m14_dns_hijack = proxy_config::m14_dns_hijack_client_config(
        address(10_804),
        server,
        address(5_357),
        address(5_358),
    );

    let cases = [
        ("ordinary", ordinary, vec![Some(SocketAddr::V4(server))]),
        (
            "DNS resource",
            dns_resource,
            vec![Some(SocketAddr::V4(server))],
        ),
        ("profile DNS concurrency", dns_concurrency, vec![None]),
        ("profile direct UDP", direct, vec![None]),
        (
            "profile Shadowsocks UDP",
            profile_shadowsocks,
            vec![Some(SocketAddr::V4(server))],
        ),
        (
            "M14 UDP",
            m14_udp,
            vec![
                Some(SocketAddr::V4(server)),
                Some(SocketAddr::V4(unselected)),
            ],
        ),
        (
            "M14 DNS hijack",
            m14_dns_hijack,
            vec![Some(SocketAddr::V4(server))],
        ),
    ];
    for (name, source, expected_servers) in cases {
        let file = write_config(&source);
        let prepared = prepare_client(file.path())
            .unwrap_or_else(|error| panic!("{name} client config must prepare: {error}"));
        let finished = finish_client_v2(prepared, ClientV2Resources::default())
            .unwrap_or_else(|error| panic!("{name} client config must finish: {error}"));
        assert_eq!(
            finished
                .outbounds
                .iter()
                .map(ferrum2_config::ClientOutboundConfig::server)
                .collect::<Vec<_>>(),
            expected_servers,
            "{name} client outbound endpoints"
        );
    }
}

#[test]
fn generated_server_configs_keep_the_real_v2_server_contract() {
    let server = address(8_388);
    let ordinary = proxy_config::ferrum_server_config(server, Some(address(9_090)));
    let dns_resource =
        proxy_config::ferrum_dns_resource_server_config(server, address(5_355), address(9_091));
    let m14_udp = proxy_config::m14_udp_server_config(server, 1_048_576);
    let m14_rules =
        proxy_config::m14_tcp_server_config(server, proxy_config::M14TcpProfile::Rules64);
    let m14_http =
        proxy_config::m14_tcp_server_config(server, proxy_config::M14TcpProfile::HttpSniff);
    let m14_tls =
        proxy_config::m14_tcp_server_config(server, proxy_config::M14TcpProfile::TlsSniff);

    for (name, source) in [
        ("ordinary", ordinary),
        ("DNS resource", dns_resource),
        ("M14 UDP", m14_udp),
        ("M14 TCP 64 rules", m14_rules),
        ("M14 TCP HTTP sniff", m14_http),
        ("M14 TCP TLS sniff", m14_tls),
    ] {
        let file = write_config(&source);
        let prepared = prepare_server(file.path())
            .unwrap_or_else(|error| panic!("{name} server config must prepare: {error}"));
        finish_server_v2(prepared, ServerV2Resources::default())
            .unwrap_or_else(|error| panic!("{name} server config must finish: {error}"));
    }
}
