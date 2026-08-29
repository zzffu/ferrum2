use std::net::SocketAddrV4;

use super::PSK;
use super::dns_resource::DNS_MAX_INFLIGHT;
use super::profile_contract::PROFILE_UDP_MAX_BUFFERED_BYTES;

fn render_client_shadowsocks_outbound(tag: &str, server: SocketAddrV4) -> String {
    format!(
        "[[outbounds]]\ntag = \"{tag}\"\ntype = \"shadowsocks\"\nserver = \"{server}\"\n\
         method = \"2022-blake3-aes-128-gcm\"\npsk = \"{PSK}\"\n"
    )
}

#[derive(Clone, Copy)]
pub(super) enum M14TcpProfile {
    Rules64,
    HttpSniff,
    TlsSniff,
}

pub(super) fn ferrum_client_config(
    listen: SocketAddrV4,
    server: SocketAddrV4,
    metrics: Option<SocketAddrV4>,
) -> String {
    let metrics = metrics
        .map(|address| format!("\n[metrics]\nlisten = \"{address}\"\n"))
        .unwrap_or_default();
    let outbound = render_client_shadowsocks_outbound("proxy", server);
    format!(
        "schema_version = 2\n\n[[inbounds]]\ntag = \"client-in\"\nlisten = \"{listen}\"\noutbound = \"proxy\"\n\n\
         {outbound}\n\
         [runtime]\nmax_connections = 12000\nlisten_backlog = 65535\n\
         idle_timeout_ms = 3600000\n\n[logging]\nlevel = \"error\"\n{metrics}"
    )
}

pub(super) fn profile_direct_tcp_client_config(listen: SocketAddrV4) -> String {
    format!(
        "schema_version = 2\n\n[[inbounds]]\ntag = \"client-in\"\nlisten = \"{listen}\"\noutbound = \"direct\"\n\n\
         [[outbounds]]\ntag = \"direct\"\ntype = \"direct\"\n\n\
         [runtime]\nmax_connections = 128\nlisten_backlog = 1024\n\
         idle_timeout_ms = 60000\n\n[udp]\nenabled = false\n\n\
         [logging]\nlevel = \"error\"\n"
    )
}

pub(super) fn profile_dns_udp_client_config(
    listen: SocketAddrV4,
    dns_listen: SocketAddrV4,
    upstream: SocketAddrV4,
    metrics: SocketAddrV4,
) -> String {
    format!(
        "schema_version = 2\n\n[[inbounds]]\ntag = \"client-in\"\nlisten = \"{listen}\"\noutbound = \"direct\"\n\n\
         [[outbounds]]\ntag = \"direct\"\ntype = \"direct\"\n\n\
         [dns]\ntimeout_ms = 5000\nmax_inflight = 32\n\
         [[dns.inbounds]]\ntag = \"profile-dns\"\nlisten = \"{dns_listen}\"\n\
         [[dns.servers]]\ntag = \"profile-upstream\"\ntransport = \"udp\"\naddress = \"{upstream}\"\n\
         [dns.route]\nfinal = \"profile-upstream\"\n\n\
         [runtime]\nmax_connections = 128\nlisten_backlog = 1024\nidle_timeout_ms = 60000\n\n\
         [udp]\nenabled = false\n\n[logging]\nlevel = \"error\"\n\n\
         [metrics]\nlisten = \"{metrics}\"\n"
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
    let outbound = render_client_shadowsocks_outbound("dns-hop", server);
    format!(
        "schema_version = 2\n\
         [[inbounds]]\ntag = \"socks\"\nlisten = \"{proxy}\"\n\
         {outbound}\
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

pub(super) fn profile_direct_udp_client_axis_config(
    listen: SocketAddrV4,
    max_sessions: usize,
    metrics: Option<SocketAddrV4>,
) -> String {
    let metrics = metrics
        .map(|address| format!("[metrics]\nlisten = \"{address}\"\n"))
        .unwrap_or_default();
    format!(
        "schema_version = 2\n[[inbounds]]\ntag = \"profile-in\"\nlisten = \"{listen}\"\n\
         outbound = \"profile-direct\"\n\
         [[outbounds]]\ntag = \"profile-direct\"\ntype = \"direct\"\n\
         [runtime]\nmax_connections = 128\nidle_timeout_ms = 60000\n\
         [udp]\nenabled = true\nmax_sessions = {max_sessions}\nmax_buffered_bytes = {PROFILE_UDP_MAX_BUFFERED_BYTES}\nidle_timeout_ms = 60000\n\
         [logging]\nlevel = \"error\"\n{metrics}"
    )
}

pub(super) fn profile_shadowsocks_udp_client_axis_config(
    listen: SocketAddrV4,
    server: SocketAddrV4,
    max_sessions: usize,
    metrics: Option<SocketAddrV4>,
) -> String {
    let outbound = render_client_shadowsocks_outbound("profile-proxy", server);
    let metrics = metrics
        .map(|address| format!("[metrics]\nlisten = \"{address}\"\n"))
        .unwrap_or_default();
    format!(
        "schema_version = 2\n[[inbounds]]\ntag = \"profile-in\"\nlisten = \"{listen}\"\n\
         {outbound}\
         [route]\nfinal = \"profile-proxy\"\n\
         [runtime]\nmax_connections = 128\nidle_timeout_ms = 60000\n\
         [udp]\nenabled = true\nmax_sessions = {max_sessions}\nmax_buffered_bytes = {PROFILE_UDP_MAX_BUFFERED_BYTES}\nidle_timeout_ms = 60000\n\
         [logging]\nlevel = \"error\"\n{metrics}"
    )
}

pub(super) fn m14_udp_client_config(
    listen: SocketAddrV4,
    server: SocketAddrV4,
    unselected: SocketAddrV4,
    first: SocketAddrV4,
    second: SocketAddrV4,
    max_buffered_bytes: usize,
) -> String {
    let selected_outbound = render_client_shadowsocks_outbound("selected", server);
    let unselected_outbound = render_client_shadowsocks_outbound("unselected", unselected);
    format!(
        "schema_version = 2\n[[inbounds]]\ntag = \"in\"\nlisten = \"{listen}\"\n\
         {selected_outbound}\
         {unselected_outbound}\
         [route]\nfinal = \"unselected\"\n\
         [[route.rules]]\ninbound = \"in\"\nnetwork = \"udp\"\n\
         ip = \"{}\"\nport = {}\naction = \"route\"\noutbound = \"selected\"\n\
         [[route.rules]]\ninbound = \"in\"\nnetwork = \"udp\"\n\
         ip = \"{}\"\nport = {}\naction = \"route\"\noutbound = \"unselected\"\n\
         [runtime]\nmax_connections = 128\nidle_timeout_ms = 60000\n\
         [udp]\nmax_sessions = 16\nmax_buffered_bytes = {max_buffered_bytes}\nidle_timeout_ms = 60000\n\
         [logging]\nlevel = \"error\"\n",
        first.ip(),
        first.port(),
        second.ip(),
        second.port(),
    )
}

pub(super) fn m14_dns_hijack_client_config(
    proxy: SocketAddrV4,
    protected: SocketAddrV4,
    dns_listen: SocketAddrV4,
    upstream: SocketAddrV4,
) -> String {
    let outbound = render_client_shadowsocks_outbound("protected", protected);
    format!(
        "schema_version = 2\n[[inbounds]]\ntag = \"in\"\nlisten = \"{proxy}\"\n\
         {outbound}\
         [route]\nfinal = \"protected\"\n\
         [[route.rules]]\ninbound = \"in\"\nnetwork = \"tcp\"\nport = 53\naction = \"hijack-dns\"\n\
         [[route.rules]]\ninbound = \"in\"\nnetwork = \"udp\"\nport = 53\naction = \"sniff\"\nsniffers = \"dns\"\n\
         [[route.rules]]\ninbound = \"in\"\nnetwork = \"udp\"\nport = 53\nprotocol = \"dns\"\naction = \"hijack-dns\"\n\
         [dns]\nmax_inflight = 4\n[[dns.inbounds]]\ntag = \"dedicated\"\nlisten = \"{dns_listen}\"\n\
         [[dns.servers]]\ntag = \"upstream\"\ntransport = \"udp\"\naddress = \"{upstream}\"\n\
         [dns.route]\nfinal = \"upstream\"\n\
         [runtime]\nmax_connections = 128\nidle_timeout_ms = 60000\n\
         [udp]\nmax_sessions = 16\nmax_buffered_bytes = 1048576\nidle_timeout_ms = 60000\n\
         [logging]\nlevel = \"error\"\n"
    )
}

pub(super) fn m14_udp_server_config(listen: SocketAddrV4, max_buffered_bytes: usize) -> String {
    format!(
        "schema_version = 2\n[[inbounds]]\ntag = \"server-in\"\nlisten = \"{listen}\"\noutbound = \"direct\"\n\
         [[outbounds]]\ntag = \"direct\"\n\
         [shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"{PSK}\"\n\
         [runtime]\nmax_connections = 128\nidle_timeout_ms = 60000\n\
         [udp]\nmax_sessions = 16\nmax_buffered_bytes = {max_buffered_bytes}\nidle_timeout_ms = 60000\n\
         [logging]\nlevel = \"error\"\n"
    )
}

pub(super) fn profile_udp_server_axis_config(
    listen: SocketAddrV4,
    max_buffered_bytes: usize,
    max_sessions: usize,
    receive_workers: usize,
    metrics: Option<SocketAddrV4>,
) -> String {
    let metrics = metrics
        .map(|address| format!("[metrics]\nlisten = \"{address}\"\n"))
        .unwrap_or_default();
    format!(
        "schema_version = 2\n[[inbounds]]\ntag = \"server-in\"\nlisten = \"{listen}\"\noutbound = \"direct\"\n\
         [[outbounds]]\ntag = \"direct\"\n\
         [shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"{PSK}\"\n\
         [runtime]\nmax_connections = 128\nidle_timeout_ms = 60000\n\
         [udp]\nmax_sessions = {max_sessions}\nmax_buffered_bytes = {max_buffered_bytes}\nidle_timeout_ms = 60000\nreceive_workers = {receive_workers}\n\
         [logging]\nlevel = \"error\"\n{metrics}"
    )
}

pub(super) fn profile_udp_server_config(
    listen: SocketAddrV4,
    max_buffered_bytes: usize,
    max_sessions: usize,
) -> String {
    m14_udp_server_config(listen, max_buffered_bytes).replace(
        "max_sessions = 16",
        &format!("max_sessions = {max_sessions}"),
    )
}

pub(super) fn m14_tcp_server_config(listen: SocketAddrV4, profile: M14TcpProfile) -> String {
    match profile {
        M14TcpProfile::Rules64 => {
            let mut rules = String::new();
            for port in 1..=64 {
                rules.push_str(&format!(
                    "[[route.rules]]\ninbound = \"in\"\nnetwork = \"tcp\"\nport = {port}\n\
                     action = \"route\"\noutbound = \"direct\"\n"
                ));
            }
            format!(
                "schema_version = 2\n[[inbounds]]\ntag = \"in\"\nlisten = \"{listen}\"\n\
                 [[outbounds]]\ntag = \"direct\"\n[route]\nfinal = \"direct\"\n{rules}\
                 [shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"{PSK}\"\n\
                 [udp]\nenabled = false\n[logging]\nlevel = \"error\"\n"
            )
        }
        M14TcpProfile::HttpSniff | M14TcpProfile::TlsSniff => {
            let protocol = match profile {
                M14TcpProfile::HttpSniff => "http",
                M14TcpProfile::TlsSniff => "tls",
                M14TcpProfile::Rules64 => unreachable!(),
            };
            format!(
                "schema_version = 2\n[[inbounds]]\ntag = \"in\"\nlisten = \"{listen}\"\n\
                 [[outbounds]]\ntag = \"direct\"\n[route]\nfinal = \"direct\"\n\
                 [route.sniff]\ntimeout_ms = 300\nmax_bytes = 8192\n\
                 [[route.rules]]\ninbound = \"in\"\nnetwork = \"tcp\"\naction = \"sniff\"\n\
                 sniffers = \"{protocol}\"\n\
                 [[route.rules]]\ninbound = \"in\"\nnetwork = \"tcp\"\nprotocol = \"{protocol}\"\n\
                 action = \"reject\"\n\
                 [shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"{PSK}\"\n\
                 [udp]\nenabled = false\n[logging]\nlevel = \"error\"\n"
            )
        }
    }
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
