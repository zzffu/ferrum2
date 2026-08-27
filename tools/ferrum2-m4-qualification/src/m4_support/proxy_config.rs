use std::net::SocketAddrV4;

use super::PSK;
use super::dns_resource::DNS_MAX_INFLIGHT;

pub(super) fn ferrum_client_config(
    listen: SocketAddrV4,
    server: SocketAddrV4,
    metrics: Option<SocketAddrV4>,
) -> String {
    let metrics = metrics
        .map(|address| format!("\n[metrics]\nlisten = \"{address}\"\n"))
        .unwrap_or_default();
    format!(
        "schema_version = 2\n\n[[inbounds]]\ntag = \"client-in\"\nlisten = \"{listen}\"\noutbound = \"proxy\"\n\n\
         [[outbounds]]\ntag = \"proxy\"\ntype = \"shadowsocks\"\nserver = \"{server}\"\n\
         method = \"2022-blake3-aes-128-gcm\"\npsk = \"{PSK}\"\n\n\
         [runtime]\nmax_connections = 12000\nlisten_backlog = 65535\n\
         idle_timeout_ms = 3600000\n\n[logging]\nlevel = \"error\"\n{metrics}"
    )
}

pub(super) fn ferrum_server_config(listen: SocketAddrV4, metrics: Option<SocketAddrV4>) -> String {
    let metrics = metrics
        .map(|address| format!("\n[metrics]\nlisten = \"{address}\"\n"))
        .unwrap_or_default();
    format!(
        "schema_version = 2\n\n[[inbounds]]\ntag = \"server-in\"\nlisten = \"{listen}\"\noutbound = \"direct\"\n\n\
         [[outbounds]]\ntag = \"direct\"\n\n\
         [shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"{PSK}\"\n\n\
         [runtime]\nmax_connections = 12000\nlisten_backlog = 65535\n\
         idle_timeout_ms = 3600000\n\n[udp]\nenabled = false\n\n\
         [logging]\nlevel = \"error\"\n{metrics}"
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn ferrum_dns_resource_client_config(
    proxy: SocketAddrV4,
    server: SocketAddrV4,
    direct_dns: SocketAddrV4,
    detoured_dns: SocketAddrV4,
    direct_upstream: SocketAddrV4,
    detoured_upstream: SocketAddrV4,
    metrics: SocketAddrV4,
) -> String {
    format!(
        "schema_version = 2\n\
         [[inbounds]]\ntag = \"socks\"\nlisten = \"{proxy}\"\n\
         [[outbounds]]\ntag = \"dns-hop\"\ntype = \"shadowsocks\"\nserver = \"{server}\"\n\
         method = \"2022-blake3-aes-128-gcm\"\npsk = \"{PSK}\"\n\
         [route]\nfinal = \"dns-hop\"\n\
         [dns]\ntimeout_ms = 5000\nmax_inflight = {DNS_MAX_INFLIGHT}\n\
         [[dns.inbounds]]\ntag = \"dns-direct\"\nlisten = \"{direct_dns}\"\n\
         [[dns.inbounds]]\ntag = \"dns-detoured\"\nlisten = \"{detoured_dns}\"\n\
         [[dns.servers]]\ntag = \"direct\"\ntransport = \"udp\"\naddress = \"{direct_upstream}\"\n\
         [[dns.servers]]\ntag = \"detoured\"\ntransport = \"udp\"\naddress = \"{detoured_upstream}\"\ndetour = \"dns-hop\"\n\
         [dns.route]\nfinal = \"direct\"\n\
         [[dns.route.rules]]\ninbound = \"dns-detoured\"\naction = \"route\"\nserver = \"detoured\"\n\
         [runtime]\nmax_connections = 1024\nlisten_backlog = 1024\nidle_timeout_ms = 3600000\n\
         [udp]\nenabled = false\n\
         [logging]\nlevel = \"error\"\n\
         [metrics]\nlisten = \"{metrics}\"\n"
    )
}

pub(super) fn ferrum_dns_resource_server_config(
    listen: SocketAddrV4,
    dns_upstream: SocketAddrV4,
    metrics: SocketAddrV4,
) -> String {
    format!(
        "schema_version = 2\n\
         [[inbounds]]\ntag = \"server-in\"\nlisten = \"{listen}\"\n\
         [[outbounds]]\ntag = \"app-direct\"\n\
         [[outbounds]]\ntag = \"dns-direct\"\n\
         [route]\nfinal = \"app-direct\"\n\
         [dns]\ntimeout_ms = 5000\nmax_inflight = {DNS_MAX_INFLIGHT}\n\
         [[dns.servers]]\ntag = \"server-direct\"\ntransport = \"udp\"\naddress = \"{dns_upstream}\"\ndetour = \"dns-direct\"\n\
         [dns.route]\nfinal = \"server-direct\"\n\
         [shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"{PSK}\"\n\
         [runtime]\nmax_connections = 1024\nlisten_backlog = 1024\nidle_timeout_ms = 3600000\n\
         [udp]\n\
         [logging]\nlevel = \"error\"\n\
         [metrics]\nlisten = \"{metrics}\"\n"
    )
}

pub(super) fn reference_client_config(listen: SocketAddrV4, server: SocketAddrV4) -> String {
    format!(
        "{{\"local_address\":\"127.0.0.1\",\"local_port\":{},\
         \"server\":\"127.0.0.1\",\"server_port\":{},\"password\":\"{PSK}\",\
         \"method\":\"2022-blake3-aes-128-gcm\",\"mode\":\"tcp_only\"}}",
        listen.port(),
        server.port()
    )
}

pub(super) fn reference_server_config(listen: SocketAddrV4) -> String {
    format!(
        "{{\"server\":\"127.0.0.1\",\"server_port\":{},\"password\":\"{PSK}\",\
         \"method\":\"2022-blake3-aes-128-gcm\",\"mode\":\"tcp_only\"}}",
        listen.port()
    )
}
