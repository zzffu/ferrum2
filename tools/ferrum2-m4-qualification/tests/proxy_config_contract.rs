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

    for (name, source) in [("ordinary", ordinary), ("DNS resource", dns_resource)] {
        let file = write_config(&source);
        let prepared = prepare_client(file.path())
            .unwrap_or_else(|error| panic!("{name} client config must prepare: {error}"));
        let finished = finish_client_v2(prepared, ClientV2Resources::default())
            .unwrap_or_else(|error| panic!("{name} client config must finish: {error}"));
        assert_eq!(
            finished.outbounds[0].server(),
            Some(SocketAddr::V4(server)),
            "{name} client Shadowsocks endpoint"
        );
    }
}

#[test]
fn generated_server_configs_keep_the_real_v2_server_contract() {
    let server = address(8_388);
    let ordinary = proxy_config::ferrum_server_config(server, Some(address(9_090)));
    let dns_resource =
        proxy_config::ferrum_dns_resource_server_config(server, address(5_355), address(9_091));

    for (name, source) in [("ordinary", ordinary), ("DNS resource", dns_resource)] {
        let file = write_config(&source);
        let prepared = prepare_server(file.path())
            .unwrap_or_else(|error| panic!("{name} server config must prepare: {error}"));
        finish_server_v2(prepared, ServerV2Resources::default())
            .unwrap_or_else(|error| panic!("{name} server config must finish: {error}"));
    }
}
