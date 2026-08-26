use std::fs;
use std::io;
use std::net::SocketAddrV4;
use std::path::{Path, PathBuf};

use super::{SYNTHETIC_PSK, TCP_METHOD_CONFIGS};

#[derive(Clone, Copy)]
pub enum ChainRoot {
    Static,
    RouteRule {
        target: SocketAddrV4,
        fallback_hop: usize,
    },
    RouteFinal,
    SelectorDefault,
}

#[allow(clippy::too_many_arguments)]
pub fn write_two_hop_client_config(
    directory: &Path,
    listen: SocketAddrV4,
    servers: [SocketAddrV4; 2],
    inherited: (&str, &str),
    explicit: (&str, &str),
    root: ChainRoot,
    udp: bool,
    metrics: Option<SocketAddrV4>,
) -> io::Result<PathBuf> {
    let network = if udp { "udp" } else { "tcp" };
    let opposite_network = if udp { "tcp" } else { "udp" };
    let (inbound_outbound, selection) = match root {
        ChainRoot::Static => ("outbound = \"two-hop\"\n".to_owned(), String::new()),
        ChainRoot::RouteRule {
            target,
            fallback_hop,
        } => {
            let fallback = ["hop-a", "hop-b"][fallback_hop];
            (
                String::new(),
                format!(
                    "[route]\nfinal = \"{fallback}\"\n\
                     [[route.rules]]\nnetwork = \"{network}\"\nip = \"{}\"\nport = {}\naction = \"route\"\noutbound = \"two-hop\"\n\
                     [[route.rules]]\nnetwork = \"{network}\"\nip = \"{}\"\nport = {}\naction = \"route\"\noutbound = \"{fallback}\"\n",
                    target.ip(),
                    target.port(),
                    target.ip(),
                    target.port(),
                ),
            )
        }
        ChainRoot::RouteFinal => (
            String::new(),
            format!(
                "[route]\nfinal = \"two-hop\"\n\
                 [[route.rules]]\nnetwork = \"{opposite_network}\"\naction = \"route\"\noutbound = \"hop-a\"\n"
            ),
        ),
        ChainRoot::SelectorDefault => (
            "outbound = \"manual\"\n".to_owned(),
            "[[selectors]]\ntag = \"manual\"\noutbounds = [\"two-hop\", \"hop-a\"]\ndefault = \"two-hop\"\n".to_owned(),
        ),
    };
    let udp = if udp { "[udp]\n" } else { "" };
    let metrics = metrics
        .map(|address| format!("[metrics]\nlisten = \"{address}\"\n"))
        .unwrap_or_default();
    let config = format!(
        "schema_version = 2\n\
         [[inbounds]]\ntag = \"socks\"\nlisten = \"{listen}\"\n{inbound_outbound}\
         [[outbounds]]\ntag = \"hop-a\"\ntype = \"shadowsocks\"\nserver = \"{}\"\nmethod = \"{}\"\npsk = \"{}\"\n\
         [[outbounds]]\ntag = \"hop-b\"\ntype = \"shadowsocks\"\nserver = \"{}\"\nmethod = \"{}\"\npsk = \"{}\"\n\
         [[chains]]\ntag = \"two-hop\"\nhops = [\"hop-a\", \"hop-b\"]\n\
         {selection}\
         {udp}{metrics}",
        servers[0], inherited.0, inherited.1, servers[1], explicit.0, explicit.1,
    );
    let path = directory.join("two-hop-client.toml");
    fs::write(&path, config)?;
    Ok(path)
}

pub fn write_client_config(
    directory: &Path,
    listen: SocketAddrV4,
    server: SocketAddrV4,
    metrics: Option<SocketAddrV4>,
) -> io::Result<PathBuf> {
    write_client_config_with_psk(directory, listen, server, metrics, SYNTHETIC_PSK)
}

pub fn write_udp_client_config(
    directory: &Path,
    listen: SocketAddrV4,
    server: SocketAddrV4,
    metrics: Option<SocketAddrV4>,
) -> io::Result<PathBuf> {
    let path = write_client_config(directory, listen, server, metrics)?;
    let mut config = fs::read_to_string(&path)?;
    config.push_str("\n[udp]\n");
    fs::write(&path, config)?;
    Ok(path)
}

pub fn write_tagged_client_config(
    directory: &Path,
    listens: [SocketAddrV4; 2],
    servers: [SocketAddrV4; 2],
    outbound_for_inbound: [usize; 2],
    udp: bool,
) -> io::Result<PathBuf> {
    let udp = if udp { "\n[udp]\n" } else { "" };
    let outbound_one = if outbound_for_inbound.contains(&1) {
        format!(
            "\n[[outbounds]]\ntag = \"out-1\"\ntype = \"shadowsocks\"\nserver = \"{}\"\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"{SYNTHETIC_PSK}\"\n",
            servers[1]
        )
    } else {
        String::new()
    };
    let config = format!(
        "schema_version = 2\n\
         \n\
         [[inbounds]]\n\
         tag = \"in-a\"\n\
         listen = \"{}\"\n\
         outbound = \"out-{}\"\n\
         \n\
         [[inbounds]]\n\
         tag = \"in-b\"\n\
         listen = \"{}\"\n\
         outbound = \"out-{}\"\n\
         \n\
         [[outbounds]]\n\
         tag = \"out-0\"\n\
         type = \"shadowsocks\"\n\
         server = \"{}\"\n\
         method = \"2022-blake3-aes-128-gcm\"\n\
         psk = \"{SYNTHETIC_PSK}\"\n\
         {}\n\
         {udp}",
        listens[0],
        outbound_for_inbound[0],
        listens[1],
        outbound_for_inbound[1],
        servers[0],
        outbound_one,
    );
    let path = directory.join("tagged-client.toml");
    fs::write(&path, config)?;
    Ok(path)
}

pub fn write_tagged_server_config(
    directory: &Path,
    listens: [SocketAddrV4; 2],
    outbound_for_inbound: [usize; 2],
    udp: bool,
) -> io::Result<PathBuf> {
    let udp = if udp {
        ""
    } else {
        "\n[udp]\nenabled = false\n"
    };
    let outbound_one = if outbound_for_inbound.contains(&1) {
        "\n[[outbounds]]\ntag = \"out-1\"\n"
    } else {
        ""
    };
    let config = format!(
        "schema_version = 2\n\
         \n\
         [[inbounds]]\n\
         tag = \"in-a\"\n\
         listen = \"{}\"\n\
         outbound = \"out-{}\"\n\
         \n\
         [[inbounds]]\n\
         tag = \"in-b\"\n\
         listen = \"{}\"\n\
         outbound = \"out-{}\"\n\
         \n\
         [[outbounds]]\n\
         tag = \"out-0\"\n\
         {}\n\
         \n\
         [shadowsocks]\n\
         method = \"2022-blake3-aes-128-gcm\"\n\
         psk = \"{SYNTHETIC_PSK}\"\n\
         {udp}",
        listens[0], outbound_for_inbound[0], listens[1], outbound_for_inbound[1], outbound_one,
    );
    let path = directory.join("tagged-server.toml");
    fs::write(&path, config)?;
    Ok(path)
}

#[allow(clippy::too_many_arguments)]
pub fn write_tagged_dns_server_config(
    directory: &Path,
    listen: SocketAddrV4,
    selected_name: &str,
    selected_port: u16,
    network: &str,
    upstreams: [SocketAddrV4; 2],
    udp: bool,
) -> io::Result<PathBuf> {
    write_tagged_dns_server_matrix_config(
        directory,
        listen,
        network,
        &[("selected", upstreams[0]), ("final", upstreams[1])],
        &[(selected_name, selected_port, "selected")],
        "final",
        2_000,
        4,
        udp,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn write_tagged_dns_server_matrix_config(
    directory: &Path,
    listen: SocketAddrV4,
    network: &str,
    servers: &[(&str, SocketAddrV4)],
    rules: &[(&str, u16, &str)],
    final_server: &str,
    timeout_ms: u16,
    max_inflight: u16,
    udp: bool,
    metrics: Option<SocketAddrV4>,
) -> io::Result<PathBuf> {
    let udp = if udp {
        ""
    } else {
        "\n[udp]\nenabled = false\n"
    };
    let mut config = format!(
        "schema_version = 2\n\
         [[inbounds]]\ntag = \"in\"\nlisten = \"{listen}\"\n"
    );
    for (tag, _) in servers {
        config.push_str(&format!(
            "[[outbounds]]\ntag = \"app-{tag}\"\ndomain_resolver = \"{tag}\"\n"
        ));
    }
    config.push_str(&format!(
        "[[outbounds]]\ntag = \"dns-direct\"\n\
         [route]\nfinal = \"app-{final_server}\"\n"
    ));
    for (name, port, server) in rules {
        config.push_str(&format!(
            "[[route.rules]]\ninbound = \"in\"\nnetwork = \"{network}\"\ndomain = \"{name}\"\nport = {port}\naction = \"route\"\noutbound = \"app-{server}\"\n"
        ));
    }
    config.push_str(&format!(
        "[dns]\ntimeout_ms = {timeout_ms}\nmax_inflight = {max_inflight}\n"
    ));
    for (tag, address) in servers {
        config.push_str(&format!(
            "[[dns.servers]]\ntag = \"{tag}\"\ntransport = \"udp\"\naddress = \"{address}\"\ndetour = \"dns-direct\"\n"
        ));
    }
    config.push_str(&format!("[dns.route]\nfinal = \"{final_server}\"\n"));
    for (name, port, server) in rules {
        config.push_str(&format!(
            "[[dns.route.rules]]\ninbound = \"in\"\nnetwork = \"{network}\"\ndomain = \"{name}\"\nport = {port}\naction = \"route\"\nserver = \"{server}\"\n"
        ));
    }
    config.push_str(&format!(
        "[shadowsocks]\nmethod = \"2022-blake3-aes-128-gcm\"\npsk = \"{SYNTHETIC_PSK}\"\n{udp}"
    ));
    if let Some(metrics) = metrics {
        config.push_str(&format!("\n[metrics]\nlisten = \"{metrics}\"\n"));
    }
    let path = directory.join(format!("tagged-dns-server-{network}.toml"));
    fs::write(&path, config)?;
    Ok(path)
}

pub fn route_tagged_config(path: &Path, route: &str) -> io::Result<()> {
    let config = fs::read_to_string(path)?
        .replace("outbound = \"out-0\"\n", "")
        .replace("outbound = \"out-1\"\n", "");
    fs::write(path, config + route)
}

pub fn force_outbound_policy_denial(path: &Path, outbound_tag: &str) -> io::Result<()> {
    const MISSING_INTERFACE: &str = "ferrum2-m0-missing-interface-7f43c4d8";

    let config = fs::read_to_string(path)?;
    let header = format!("[[outbounds]]\ntag = \"{outbound_tag}\"\n");
    if config.matches(&header).count() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "outbound tag is not unique in test config",
        ));
    }
    let replacement = format!("{header}bind_interface = \"{MISSING_INTERFACE}\"\n");
    fs::write(path, config.replacen(&header, &replacement, 1))
}

pub fn write_client_config_with_psk(
    directory: &Path,
    listen: SocketAddrV4,
    server: SocketAddrV4,
    metrics: Option<SocketAddrV4>,
    psk: &str,
) -> io::Result<PathBuf> {
    let metrics = metrics
        .map(|address| format!("\n[metrics]\nlisten = \"{address}\"\n"))
        .unwrap_or_default();
    let config = format!(
        "schema_version = 2\n\
         \n\
         [[inbounds]]\n\
         tag = \"proxy\"\n\
         listen = \"{listen}\"\n\
         outbound = \"proxy-out\"\n\
         \n\
         [[outbounds]]\n\
         tag = \"proxy-out\"\n\
         type = \"shadowsocks\"\n\
         server = \"{server}\"\n\
         method = \"2022-blake3-aes-128-gcm\"\n\
         psk = \"{psk}\"\n\
         {metrics}"
    );
    let path = directory.join("client.toml");
    fs::write(&path, config)?;
    Ok(path)
}

pub fn write_server_config(
    directory: &Path,
    listen: SocketAddrV4,
    metrics: Option<SocketAddrV4>,
) -> io::Result<PathBuf> {
    write_server_config_with_psk(directory, listen, metrics, SYNTHETIC_PSK)
}

pub fn write_server_config_with_psk(
    directory: &Path,
    listen: SocketAddrV4,
    metrics: Option<SocketAddrV4>,
    psk: &str,
) -> io::Result<PathBuf> {
    write_server_config_variant(directory, listen, metrics, psk, "")
}

pub fn write_tcp_only_server_config(
    directory: &Path,
    listen: SocketAddrV4,
    metrics: Option<SocketAddrV4>,
) -> io::Result<PathBuf> {
    write_tcp_only_server_config_with_psk(directory, listen, metrics, SYNTHETIC_PSK)
}

pub fn write_tcp_only_server_config_with_psk(
    directory: &Path,
    listen: SocketAddrV4,
    metrics: Option<SocketAddrV4>,
    psk: &str,
) -> io::Result<PathBuf> {
    write_server_config_variant(
        directory,
        listen,
        metrics,
        psk,
        "\n[udp]\nenabled = false\n",
    )
}

fn write_server_config_variant(
    directory: &Path,
    listen: SocketAddrV4,
    metrics: Option<SocketAddrV4>,
    psk: &str,
    udp: &str,
) -> io::Result<PathBuf> {
    let metrics = metrics
        .map(|address| format!("\n[metrics]\nlisten = \"{address}\"\n"))
        .unwrap_or_default();
    let config = format!(
        "schema_version = 2\n\
         \n\
         [[inbounds]]\n\
         tag = \"proxy\"\n\
         listen = \"{listen}\"\n\
         outbound = \"direct\"\n\
         \n\
         [[outbounds]]\n\
         tag = \"direct\"\n\
         \n\
         [shadowsocks]\n\
         method = \"2022-blake3-aes-128-gcm\"\n\
         psk = \"{psk}\"\n\
         {udp}\
         {metrics}"
    );
    let path = directory.join("server.toml");
    fs::write(&path, config)?;
    Ok(path)
}

pub fn rewrite_config_method(path: &Path, method: (&str, &str)) -> io::Result<()> {
    let config = fs::read_to_string(path)?
        .replace(TCP_METHOD_CONFIGS[0].0, method.0)
        .replace(SYNTHETIC_PSK, method.1);
    fs::write(path, config)
}
