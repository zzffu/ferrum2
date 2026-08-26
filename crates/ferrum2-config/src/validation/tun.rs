use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use crate::error::{ConfigError, ConfigField};
use crate::model::{
    ClientOutboundConfig, DnsConfig, TunConfig, UdpFiltering, ValidatedClientConfig,
};
use crate::raw::RawTun;

use super::common::{sockets_alias, validate_tag};

pub(super) struct ValidatedTun {
    pub(super) tag: String,
    pub(super) outbound: Option<String>,
    pub(super) config: TunConfig,
}

pub(super) fn validate_tun(raw: RawTun) -> Result<ValidatedTun, ConfigError> {
    validate_tag(&raw.tag, ConfigField::TunTag)?;
    if raw.adapter_name.is_empty()
        || raw.adapter_name.encode_utf16().count() >= 128
        || raw.adapter_name.chars().any(char::is_control)
    {
        return Err(ConfigError::semantic(ConfigField::TunAdapterName));
    }
    let ipv4_address = raw
        .ipv4_address
        .as_deref()
        .map(validate_tun_ipv4_address)
        .transpose()?;
    let ipv6_address = raw
        .ipv6_address
        .as_deref()
        .map(validate_tun_ipv6_address)
        .transpose()?;
    if ipv4_address.is_none() && ipv6_address.is_none() {
        return Err(ConfigError::semantic(ConfigField::Tun));
    }
    let capture_routes = compile_capture_routes(
        raw.auto_route,
        raw.route_address.as_deref(),
        raw.route_exclude_address.as_deref(),
        ipv4_address.is_some(),
        ipv6_address.is_some(),
    )?;
    if raw.auto_dns && !raw.auto_route {
        return Err(ConfigError::semantic(ConfigField::TunAutoDns));
    }
    if !raw.auto_dns {
        if raw.ipv4_dns_address.is_some() {
            return Err(ConfigError::semantic(ConfigField::TunIpv4DnsAddress));
        }
        if raw.ipv6_dns_address.is_some() {
            return Err(ConfigError::semantic(ConfigField::TunIpv6DnsAddress));
        }
    } else if raw.ipv4_dns_address.is_none() && raw.ipv6_dns_address.is_none() {
        return Err(ConfigError::semantic(ConfigField::TunAutoDns));
    }
    let ipv4_dns_address = raw
        .ipv4_dns_address
        .as_deref()
        .map(|address| {
            validate_tun_ipv4_dns(
                address,
                ipv4_address
                    .ok_or_else(|| ConfigError::semantic(ConfigField::TunIpv4DnsAddress))?,
            )
        })
        .transpose()?;
    let ipv6_dns_address = raw
        .ipv6_dns_address
        .as_deref()
        .map(|address| {
            validate_tun_ipv6_dns(
                address,
                ipv6_address
                    .ok_or_else(|| ConfigError::semantic(ConfigField::TunIpv6DnsAddress))?,
            )
        })
        .transpose()?;
    if !(1_280..=1_500).contains(&raw.mtu) {
        return Err(ConfigError::semantic(ConfigField::TunMtu));
    }
    if !(131_072..=67_108_864).contains(&raw.ring_capacity) || !raw.ring_capacity.is_power_of_two()
    {
        return Err(ConfigError::semantic(ConfigField::TunRingCapacity));
    }
    if !(1_000..=60_000).contains(&raw.ready_timeout_ms) {
        return Err(ConfigError::semantic(ConfigField::TunReadyTimeout));
    }
    if !(1..=4_096).contains(&raw.max_tcp_flows) {
        return Err(ConfigError::semantic(ConfigField::TunMaxTcpFlows));
    }
    if !(4_096..=262_144).contains(&raw.tcp_buffer_bytes) {
        return Err(ConfigError::semantic(ConfigField::TunTcpBufferBytes));
    }
    if !(1..=8_192).contains(&raw.max_udp_mappings) {
        return Err(ConfigError::semantic(ConfigField::TunMaxUdpMappings));
    }
    let udp_filtering = match raw.udp_filtering.as_str() {
        "address_dependent" => UdpFiltering::AddressDependent,
        "endpoint_independent" => UdpFiltering::EndpointIndependent,
        _ => return Err(ConfigError::semantic(ConfigField::TunUdpFiltering)),
    };

    Ok(ValidatedTun {
        tag: raw.tag,
        outbound: raw.outbound,
        config: TunConfig {
            adapter_name: raw.adapter_name.into_boxed_str(),
            ipv4_address,
            ipv6_address,
            auto_route: raw.auto_route,
            strict_route: raw.strict_route,
            capture_routes,
            auto_dns: raw.auto_dns,
            ipv4_dns_address,
            ipv6_dns_address,
            physical_endpoints: Vec::new(),
            mtu: raw.mtu as u16,
            ring_capacity: raw.ring_capacity as u32,
            ready_timeout: Duration::from_millis(raw.ready_timeout_ms),
            max_tcp_flows: raw.max_tcp_flows as usize,
            tcp_buffer_bytes: raw.tcp_buffer_bytes as usize,
            max_udp_mappings: raw.max_udp_mappings as usize,
            udp_filtering,
        },
    })
}

pub(super) fn validate_tun_ipv4_address(value: &str) -> Result<Ipv4Net, ConfigError> {
    let network: Ipv4Net = value
        .parse()
        .map_err(|_| ConfigError::semantic(ConfigField::TunIpv4Address))?;
    let address = network.addr();
    if address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || address == network.network()
        || address == network.broadcast()
    {
        return Err(ConfigError::semantic(ConfigField::TunIpv4Address));
    }
    Ok(network)
}

pub(super) fn validate_tun_ipv6_address(value: &str) -> Result<Ipv6Net, ConfigError> {
    let network: Ipv6Net = value
        .parse()
        .map_err(|_| ConfigError::semantic(ConfigField::TunIpv6Address))?;
    let address = network.addr();
    if address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || address == network.network()
    {
        return Err(ConfigError::semantic(ConfigField::TunIpv6Address));
    }
    Ok(network)
}

pub(super) fn validate_tun_ipv4_dns(
    value: &str,
    network: Ipv4Net,
) -> Result<Ipv4Addr, ConfigError> {
    let address: Ipv4Addr = value
        .parse()
        .map_err(|_| ConfigError::semantic(ConfigField::TunIpv4DnsAddress))?;
    if address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || !network.contains(&address)
        || address == network.addr()
        || address == network.network()
        || address == network.broadcast()
    {
        return Err(ConfigError::semantic(ConfigField::TunIpv4DnsAddress));
    }
    Ok(address)
}

pub(super) fn validate_tun_ipv6_dns(
    value: &str,
    network: Ipv6Net,
) -> Result<std::net::Ipv6Addr, ConfigError> {
    let address: std::net::Ipv6Addr = value
        .parse()
        .map_err(|_| ConfigError::semantic(ConfigField::TunIpv6DnsAddress))?;
    if address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || !network.contains(&address)
        || address == network.addr()
        || address == network.network()
    {
        return Err(ConfigError::semantic(ConfigField::TunIpv6DnsAddress));
    }
    Ok(address)
}

pub(super) fn compile_capture_routes(
    auto_route: bool,
    includes: Option<&[String]>,
    excludes: Option<&[String]>,
    ipv4_enabled: bool,
    ipv6_enabled: bool,
) -> Result<Vec<IpNet>, ConfigError> {
    if !auto_route {
        if includes.is_some() {
            return Err(ConfigError::semantic(ConfigField::TunRouteAddress));
        }
        if excludes.is_some() {
            return Err(ConfigError::semantic(ConfigField::TunRouteExcludeAddress));
        }
        return Ok(Vec::new());
    }

    let parse = |values: &[String], field| {
        values
            .iter()
            .map(|value| {
                let network: IpNet = value.parse().map_err(|_| ConfigError::semantic(field))?;
                match network {
                    IpNet::V4(network) if ipv4_enabled => Ok(IpNet::V4(
                        Ipv4Net::new(network.network(), network.prefix_len())
                            .expect("parsed IPv4 prefix remains valid when normalized"),
                    )),
                    IpNet::V6(network) if ipv6_enabled => Ok(IpNet::V6(
                        Ipv6Net::new(network.network(), network.prefix_len())
                            .expect("parsed IPv6 prefix remains valid when normalized"),
                    )),
                    IpNet::V4(_) | IpNet::V6(_) => Err(ConfigError::semantic(field)),
                }
            })
            .collect::<Result<Vec<_>, _>>()
    };
    if includes.is_some_and(<[String]>::is_empty) {
        return Err(ConfigError::semantic(ConfigField::TunRouteAddress));
    }
    let includes = includes.unwrap_or(&[]);
    if includes.len() > 64 {
        return Err(ConfigError::semantic(ConfigField::TunRouteAddress));
    }
    let mut includes = if includes.is_empty() {
        let mut defaults =
            Vec::with_capacity(usize::from(ipv4_enabled) + usize::from(ipv6_enabled));
        if ipv4_enabled {
            defaults.push(IpNet::V4("0.0.0.0/0".parse().expect("fixed IPv4 prefix")));
        }
        if ipv6_enabled {
            defaults.push(IpNet::V6("::/0".parse().expect("fixed IPv6 prefix")));
        }
        defaults
    } else {
        parse(includes, ConfigField::TunRouteAddress)?
    };
    let excludes = excludes.unwrap_or(&[]);
    if excludes.len() > 64 {
        return Err(ConfigError::semantic(ConfigField::TunRouteExcludeAddress));
    }
    let excludes = aggregate_ip_nets(parse(excludes, ConfigField::TunRouteExcludeAddress)?);
    includes = aggregate_ip_nets(includes);

    for exclude in excludes {
        let mut next = Vec::new();
        for route in includes {
            subtract_ip_net(route, exclude, &mut next);
        }
        includes = next;
    }
    includes = aggregate_ip_nets(includes);
    includes = split_default_routes(includes);
    includes.sort_unstable();
    if !(1..=256).contains(&includes.len()) {
        return Err(ConfigError::semantic(ConfigField::TunRouteAddress));
    }
    Ok(includes)
}

pub(super) fn aggregate_ip_nets(routes: Vec<IpNet>) -> Vec<IpNet> {
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    for route in routes {
        match route {
            IpNet::V4(route) => ipv4.push(route),
            IpNet::V6(route) => ipv6.push(route),
        }
    }
    Ipv4Net::aggregate(&ipv4)
        .into_iter()
        .map(IpNet::V4)
        .chain(Ipv6Net::aggregate(&ipv6).into_iter().map(IpNet::V6))
        .collect()
}

pub(super) fn subtract_ip_net(route: IpNet, exclude: IpNet, output: &mut Vec<IpNet>) {
    match (route, exclude) {
        (IpNet::V4(route), IpNet::V4(exclude)) => {
            subtract_ipv4_net(route, exclude, output);
        }
        (IpNet::V6(route), IpNet::V6(exclude)) => {
            subtract_ipv6_net(route, exclude, output);
        }
        (route, _) => output.push(route),
    }
}

pub(super) fn subtract_ipv4_net(route: Ipv4Net, exclude: Ipv4Net, output: &mut Vec<IpNet>) {
    if exclude.prefix_len() <= route.prefix_len() && exclude.contains(&route.network()) {
        return;
    }
    if !route.contains(&exclude.network()) {
        output.push(IpNet::V4(route));
        return;
    }
    for child in route
        .subnets(route.prefix_len() + 1)
        .expect("a partially excluded IPv4 prefix can split")
    {
        subtract_ipv4_net(child, exclude, output);
    }
}

pub(super) fn subtract_ipv6_net(route: Ipv6Net, exclude: Ipv6Net, output: &mut Vec<IpNet>) {
    if exclude.prefix_len() <= route.prefix_len() && exclude.contains(&route.network()) {
        return;
    }
    if !route.contains(&exclude.network()) {
        output.push(IpNet::V6(route));
        return;
    }
    for child in route
        .subnets(route.prefix_len() + 1)
        .expect("a partially excluded IPv6 prefix can split")
    {
        subtract_ipv6_net(child, exclude, output);
    }
}

pub(super) fn split_default_routes(routes: Vec<IpNet>) -> Vec<IpNet> {
    let mut output = Vec::with_capacity(routes.len().saturating_add(2));
    for route in routes {
        match route {
            IpNet::V4(route) if route.prefix_len() == 0 => output.extend(
                route
                    .subnets(1)
                    .expect("IPv4 default route has /1 children")
                    .map(IpNet::V4),
            ),
            IpNet::V6(route) if route.prefix_len() == 0 => output.extend(
                route
                    .subnets(1)
                    .expect("IPv6 default route has /1 children")
                    .map(IpNet::V6),
            ),
            route => output.push(route),
        }
    }
    output
}

pub(super) fn validate_tun_targets(
    tun: &mut TunConfig,
    outbounds: &[ClientOutboundConfig],
    physical_first_hops: &[usize],
    direct_detours: &[bool],
    dns: Option<&DnsConfig>,
) -> Result<(), ConfigError> {
    if !tun.auto_route {
        return Ok(());
    }
    for outbound in physical_first_hops
        .iter()
        .filter_map(|index| outbounds.get(*index))
    {
        if let ClientOutboundConfig::Shadowsocks { server, .. } = outbound {
            tun.physical_endpoints.push(*server);
        }
    }
    if let Some(dns) = dns {
        let mut direct_detours = direct_detours.iter();
        for server in &dns.servers {
            let direct = if server.detour.is_none() {
                true
            } else {
                *direct_detours
                    .next()
                    .expect("validated detour physical plan")
            };
            if direct {
                if server.resolved_targets.is_empty() {
                    let Some(address) = server.target.as_socket_addr() else {
                        continue;
                    };
                    tun.physical_endpoints.push(address);
                } else {
                    tun.physical_endpoints
                        .extend(server.resolved_targets.iter().copied());
                }
            }
        }
    }
    // Loopback first hops never cross the managed interface. Keeping them in the physical
    // underlay plan would ask Windows to bind a software-loopback route as a hardware egress.
    tun.physical_endpoints.retain(|endpoint| match endpoint {
        SocketAddr::V4(endpoint) => !endpoint.ip().is_loopback(),
        SocketAddr::V6(endpoint) => {
            !endpoint.ip().is_loopback()
                && !endpoint
                    .ip()
                    .to_ipv4_mapped()
                    .is_some_and(|address| address.is_loopback())
        }
    });
    tun.physical_endpoints.sort_unstable();
    tun.physical_endpoints.dedup();
    if tun.physical_endpoints.len() > 256 {
        return Err(ConfigError::semantic(ConfigField::TunAutoRoute));
    }
    for endpoint in &tun.physical_endpoints {
        match endpoint {
            SocketAddr::V4(endpoint)
                if tun
                    .ipv4_address
                    .is_some_and(|network| network.contains(endpoint.ip())) =>
            {
                return Err(ConfigError::semantic(ConfigField::TunIpv4Address));
            }
            SocketAddr::V6(endpoint)
                if tun
                    .ipv6_address
                    .is_some_and(|network| network.contains(endpoint.ip())) =>
            {
                return Err(ConfigError::semantic(ConfigField::TunIpv6Address));
            }
            SocketAddr::V4(_) | SocketAddr::V6(_) => {}
        }
    }
    Ok(())
}

pub(crate) fn finish_client_tun_targets(
    config: &mut ValidatedClientConfig,
    physical_first_hops: &[usize],
    direct_detours: &[bool],
) -> Result<(), ConfigError> {
    let Some(tun) = &mut config.tun else {
        return Ok(());
    };
    tun.physical_endpoints.clear();
    validate_tun_targets(
        tun,
        &config.outbounds,
        physical_first_hops,
        direct_detours,
        config.dns.as_ref(),
    )
}

pub(crate) fn validate_finished_client_endpoints(
    config: &ValidatedClientConfig,
    direct_detours: &[bool],
) -> Result<(), ConfigError> {
    for server in config
        .outbounds
        .iter()
        .filter_map(ClientOutboundConfig::server)
    {
        if config
            .inbounds
            .iter()
            .any(|inbound| SocketAddr::V4(inbound.listen) == server)
        {
            return Err(ConfigError::semantic(ConfigField::OutboundsServer));
        }
    }
    let Some(dns) = &config.dns else {
        return Ok(());
    };
    for inbound in &dns.inbounds {
        if config
            .outbounds
            .iter()
            .filter_map(ClientOutboundConfig::server)
            .any(|server| sockets_alias(server, inbound.listen))
        {
            return Err(ConfigError::semantic(ConfigField::DnsInboundsListen));
        }
    }
    let mut direct_detours = direct_detours.iter();
    for server in &dns.servers {
        let may_dial_direct = if server.detour.is_none() {
            true
        } else {
            *direct_detours
                .next()
                .ok_or_else(|| ConfigError::semantic(ConfigField::ResourceMaterialization))?
        };
        if may_dial_direct {
            let aliases_listener = server.target.as_socket_addr().is_some_and(|address| {
                dns.inbounds
                    .iter()
                    .any(|inbound| sockets_alias(inbound.listen, address))
            }) || server.resolved_targets.iter().any(|address| {
                dns.inbounds
                    .iter()
                    .any(|inbound| sockets_alias(inbound.listen, *address))
            });
            if aliases_listener {
                return Err(ConfigError::semantic(ConfigField::DnsServersAddress));
            }
        }
    }
    if direct_detours.next().is_some() {
        return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
    }
    Ok(())
}
