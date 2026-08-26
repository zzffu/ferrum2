use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::num::NonZeroU16;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ferrum2_core::TargetAddr;
use ferrum2_core::route::compile_egress_plans_with_roots;
use ferrum2_crypto::{MethodProfile, MethodPsk};
use ferrum2_rule::{
    EgressPlanHandle, SelectorCompileError, SelectorControl, SelectorDefinition, TaggedInbound,
    TaggedOutbound, TaggedPlan,
};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{ConfigError, ConfigField};
use crate::model::{
    ClientDnsRoute, ClientInboundConfig, ClientOutboundConfig, DirectDomainResolver,
    DnsCacheConfig, DnsConfig, DnsEndpointMode, DnsInboundConfig, DnsRuntimeConfig,
    DnsServerConfig, DnsStrategy, DnsTransport, LoggingConfig, LoggingLevel, MetricsConfig,
    OutboundDialOptions, ReplayConfig, RouteNetworkConfig, RuntimeConfig, ServerDnsRoute,
    ServerInboundConfig, ServerOutboundConfig, TunConfig, UdpConfig, UdpFiltering,
    ValidatedClientConfig, ValidatedServerConfig,
};
use crate::raw::{
    RawChain, RawClientInbound, RawClientOutbound, RawClientRoot, RawDns, RawLogging, RawMetrics,
    RawReplay, RawRoute, RawRuntime, RawSelector, RawServerInbound, RawServerOutbound,
    RawServerRoot, RawTun, RawUdp, SecretString,
};

pub(super) mod v2;
pub(crate) use v2::validate_version;

const MAX_INTERFACE_NAME_UTF16_UNITS: usize = 256;

fn client_global_tags(raw: &RawClientRoot) -> Vec<String> {
    raw.inbounds
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|item| item.tag.clone())
        .chain(
            raw.outbounds
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(|item| item.tag.clone()),
        )
        .chain(
            raw.chains
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .filter_map(|item| item.tag.clone()),
        )
        .chain(
            raw.selectors
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(|item| item.tag.clone()),
        )
        .chain(raw.tun.iter().map(|tun| tun.tag.clone()))
        .collect()
}

fn server_global_tags(raw: &RawServerRoot) -> Vec<String> {
    raw.inbounds
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|item| item.tag.clone())
        .chain(
            raw.outbounds
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(|item| item.tag.clone()),
        )
        .chain(
            raw.selectors
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(|item| item.tag.clone()),
        )
        .collect()
}

fn dns_detour_tags(raw: &RawDns) -> Vec<&str> {
    raw.servers
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .filter_map(|server| server.detour.as_deref())
        .collect()
}

#[derive(Clone, Copy)]
enum DnsRole {
    Client,
    Server,
}

struct DnsValidationContext<'a> {
    role: DnsRole,
    global_tags: &'a [String],
    ordinary_listens: &'a [SocketAddr],
    outbound_servers: &'a [SocketAddr],
    dependency_servers: &'a [usize],
}

struct GraphValidation<'a> {
    route_roots: &'a [&'a str],
    detour_tags: &'a [&'a str],
    retained_client_inbounds: usize,
    explicit_route: bool,
}

fn validate_dns(
    raw: Option<RawDns>,
    context: DnsValidationContext<'_>,
    detours: Vec<EgressPlanHandle>,
) -> Result<Option<DnsConfig>, ConfigError> {
    let Some(raw) = raw else {
        debug_assert!(detours.is_empty());
        return Ok(None);
    };
    let dns_runtime = validate_dns_runtime(&raw)?;
    let timeout = bounded_duration(raw.timeout_ms, 100, 30_000, ConfigField::DnsTimeout)?;
    let max_inflight = bounded_nonzero_u16(raw.max_inflight, ConfigField::DnsMaxInflight)?;
    if max_inflight.get() > 4_096 {
        return Err(ConfigError::semantic(ConfigField::DnsMaxInflight));
    }

    let raw_inbounds = match (context.role, raw.inbounds) {
        (DnsRole::Client, Some(inbounds)) => {
            validate_count(inbounds.len(), ConfigField::DnsInbounds)?;
            inbounds
        }
        (DnsRole::Client, None) => return Err(ConfigError::semantic(ConfigField::DnsInbounds)),
        (DnsRole::Server, None) => Vec::new(),
        (DnsRole::Server, Some(_)) => {
            return Err(ConfigError::semantic(ConfigField::DnsInbounds));
        }
    };
    let mut inbounds = Vec::with_capacity(raw_inbounds.len());
    for (index, inbound) in raw_inbounds.iter().enumerate() {
        validate_tag(&inbound.tag, ConfigField::DnsInboundsTag)?;
        if context.global_tags.contains(&inbound.tag)
            || raw_inbounds[..index]
                .iter()
                .any(|other| other.tag == inbound.tag)
        {
            return Err(ConfigError::semantic(ConfigField::DnsInboundsTag));
        }
        let listen = parse_socket(&inbound.listen, ConfigField::DnsInboundsListen)?;
        if context
            .ordinary_listens
            .iter()
            .chain(inbounds.iter().map(|item: &DnsInboundConfig| &item.listen))
            .any(|other| sockets_alias(*other, listen))
            || context
                .outbound_servers
                .iter()
                .any(|server| sockets_alias(*server, listen))
        {
            return Err(ConfigError::semantic(ConfigField::DnsInboundsListen));
        }
        inbounds.push(DnsInboundConfig { listen });
    }

    let raw_servers = raw
        .servers
        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsServers))?;
    validate_count(raw_servers.len(), ConfigField::DnsServers)?;
    let mut servers = Vec::with_capacity(raw_servers.len());
    let mut detours = detours.into_iter();
    for (index, server) in raw_servers.iter().enumerate() {
        validate_tag(&server.tag, ConfigField::DnsServersTag)?;
        if raw_servers[..index]
            .iter()
            .any(|other| other.tag == server.tag)
        {
            return Err(ConfigError::semantic(ConfigField::DnsServersTag));
        }
        let transport = match server.transport.as_str() {
            "udp" => DnsTransport::Udp,
            "tcp" => DnsTransport::Tcp,
            "dot" => DnsTransport::Dot,
            "doh" => DnsTransport::Doh,
            _ => return Err(ConfigError::semantic(ConfigField::DnsServersTransport)),
        };
        let address = parse_socket(&server.address, ConfigField::DnsServersAddress)?;
        if server.detour.is_none()
            && inbounds
                .iter()
                .any(|inbound| sockets_alias(inbound.listen, address))
        {
            return Err(ConfigError::semantic(ConfigField::DnsServersAddress));
        }
        let server_name = match transport {
            DnsTransport::Udp | DnsTransport::Tcp if server.server_name.is_some() => {
                return Err(ConfigError::semantic(ConfigField::DnsServersServerName));
            }
            DnsTransport::Dot | DnsTransport::Doh => {
                let name = server
                    .server_name
                    .as_deref()
                    .filter(|name| valid_tls_name(name))
                    .ok_or_else(|| ConfigError::semantic(ConfigField::DnsServersServerName))?;
                Some(Box::from(name))
            }
            _ => None,
        };
        let path = match transport {
            DnsTransport::Doh => {
                let path = server.path.as_deref().unwrap_or("/dns-query");
                if !valid_doh_path(path) {
                    return Err(ConfigError::semantic(ConfigField::DnsServersPath));
                }
                Some(Box::from(path))
            }
            _ if server.path.is_some() => {
                return Err(ConfigError::semantic(ConfigField::DnsServersPath));
            }
            _ => None,
        };
        let detour = server.detour.as_ref().map(|_| {
            detours
                .next()
                .expect("validated detour roots preserve server order")
        });
        servers.push(DnsServerConfig {
            transport,
            target: TargetAddr::ip(address)
                .map_err(|_| ConfigError::semantic(ConfigField::DnsServersAddress))?,
            resolved_targets: Box::new([]),
            endpoint_mode: DnsEndpointMode::Numeric,
            server_name,
            path,
            detour,
        });
    }
    debug_assert!(detours.next().is_none());

    let route = raw
        .route
        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRoute))?;
    let final_tag = route
        .final_server
        .as_deref()
        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteFinal))?;
    validate_tag(final_tag, ConfigField::DnsRouteFinal)?;
    let final_server = raw_servers
        .iter()
        .position(|server| server.tag == final_tag)
        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteFinal))?;
    let mut reached = vec![false; servers.len()];
    reached[final_server] = true;
    for &server in context.dependency_servers {
        *reached
            .get_mut(server)
            .ok_or_else(|| ConfigError::semantic(ConfigField::ResourceMaterialization))? = true;
    }
    for rule in route.rules {
        if rule.outbound.is_some() {
            return Err(ConfigError::semantic(ConfigField::DnsRouteRulesServer));
        }
        let action = rule
            .action
            .as_deref()
            .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteRulesAction))?;
        if action == "reject" {
            if rule.server.is_some() {
                return Err(ConfigError::semantic(ConfigField::DnsRouteRulesServer));
            }
            continue;
        }
        if action != "route" {
            return Err(ConfigError::semantic(ConfigField::DnsRouteRulesAction));
        }
        let server_tag = rule
            .server
            .as_deref()
            .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteRulesServer))?;
        validate_tag(server_tag, ConfigField::DnsRouteRulesServer)?;
        let server = raw_servers
            .iter()
            .position(|candidate| candidate.tag == server_tag)
            .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteRulesServer))?;
        reached[server] = true;
    }
    if reached.contains(&false) {
        return Err(ConfigError::semantic(ConfigField::DnsRouteRulesServer));
    }
    Ok(Some(DnsConfig {
        inbounds,
        servers,
        timeout,
        max_inflight,
        runtime: dns_runtime,
    }))
}

fn validate_dns_runtime(raw: &RawDns) -> Result<DnsRuntimeConfig, ConfigError> {
    let strategy = match raw.strategy.as_deref().unwrap_or("prefer_ipv4") {
        "prefer_ipv4" => DnsStrategy::PreferIpv4,
        "prefer_ipv6" => DnsStrategy::PreferIpv6,
        "ipv4_only" => DnsStrategy::Ipv4Only,
        "ipv6_only" => DnsStrategy::Ipv6Only,
        _ => return Err(ConfigError::semantic(ConfigField::DnsStrategy)),
    };
    let cache = raw.cache.as_ref().map_or(
        Ok(DnsCacheConfig {
            enabled: true,
            max_entries: 8_192,
        }),
        |cache| {
            if cache.max_entries == 0 || cache.max_entries > 1_000_000 {
                return Err(ConfigError::semantic(ConfigField::DnsCacheMaxEntries));
            }
            Ok(DnsCacheConfig {
                enabled: cache.enabled,
                max_entries: cache.max_entries,
            })
        },
    )?;
    Ok(DnsRuntimeConfig::new(strategy, cache))
}

pub(super) fn validate_direct_domain_resolver(
    resolver: Option<&str>,
    strategy: Option<&str>,
    dns: Option<&RawDns>,
    default_strategy: DnsStrategy,
) -> Result<DirectDomainResolver, ConfigError> {
    let Some(resolver) = resolver else {
        if strategy.is_some() {
            return Err(ConfigError::semantic(ConfigField::OutboundsDomainStrategy));
        }
        return Ok(DirectDomainResolver::System);
    };
    validate_tag(resolver, ConfigField::OutboundsDomainResolver)?;
    let server = dns
        .and_then(|dns| dns.servers.as_deref())
        .unwrap_or(&[])
        .iter()
        .position(|candidate| candidate.tag == resolver)
        .ok_or_else(|| ConfigError::semantic(ConfigField::OutboundsDomainResolver))?;
    let strategy = match strategy {
        None => default_strategy,
        Some("prefer_ipv4") => DnsStrategy::PreferIpv4,
        Some("prefer_ipv6") => DnsStrategy::PreferIpv6,
        Some("ipv4_only") => DnsStrategy::Ipv4Only,
        Some("ipv6_only") => DnsStrategy::Ipv6Only,
        Some(_) => return Err(ConfigError::semantic(ConfigField::OutboundsDomainStrategy)),
    };
    Ok(DirectDomainResolver::DnsServer { server, strategy })
}

fn parse_socket(value: &str, field: ConfigField) -> Result<SocketAddr, ConfigError> {
    let address: SocketAddr = value.parse().map_err(|_| ConfigError::semantic(field))?;
    if address.port() == 0 {
        Err(ConfigError::semantic(field))
    } else {
        Ok(address)
    }
}

fn sockets_alias(left: SocketAddr, right: SocketAddr) -> bool {
    left.port() == right.port()
        && left.is_ipv4() == right.is_ipv4()
        && (left.ip() == right.ip() || left.ip().is_unspecified() || right.ip().is_unspecified())
}

fn valid_tls_name(name: &str) -> bool {
    (1..=253).contains(&name.len())
        && name.is_ascii()
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

fn valid_doh_path(path: &str) -> bool {
    (1..=1_024).contains(&path.len())
        && path.is_ascii()
        && path.starts_with('/')
        && !path.starts_with("//")
        && path
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'?' | b'#'))
}

struct ValidatedTun {
    tag: String,
    outbound: Option<String>,
    config: TunConfig,
}

fn validate_tun(raw: RawTun) -> Result<ValidatedTun, ConfigError> {
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

fn validate_tun_ipv4_address(value: &str) -> Result<Ipv4Net, ConfigError> {
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

fn validate_tun_ipv6_address(value: &str) -> Result<Ipv6Net, ConfigError> {
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

fn validate_tun_ipv4_dns(value: &str, network: Ipv4Net) -> Result<Ipv4Addr, ConfigError> {
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

fn validate_tun_ipv6_dns(value: &str, network: Ipv6Net) -> Result<std::net::Ipv6Addr, ConfigError> {
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

fn compile_capture_routes(
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

fn aggregate_ip_nets(routes: Vec<IpNet>) -> Vec<IpNet> {
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

fn subtract_ip_net(route: IpNet, exclude: IpNet, output: &mut Vec<IpNet>) {
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

fn subtract_ipv4_net(route: Ipv4Net, exclude: Ipv4Net, output: &mut Vec<IpNet>) {
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

fn subtract_ipv6_net(route: Ipv6Net, exclude: Ipv6Net, output: &mut Vec<IpNet>) {
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

fn split_default_routes(routes: Vec<IpNet>) -> Vec<IpNet> {
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

fn validate_tun_targets(
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

pub(super) fn finish_client_tun_targets(
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

pub(super) fn validate_finished_client_endpoints(
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

pub(super) struct PreparedClientValidation {
    pub(super) config: ValidatedClientConfig,
    pub(super) physical_first_hops: Vec<usize>,
    pub(super) direct_detours: Vec<bool>,
    pub(super) dependency_egress_plans: Vec<EgressPlanHandle>,
    pub(super) dependency_egress_direct: Vec<bool>,
}

pub(super) struct PreparedServerValidation {
    pub(super) config: ValidatedServerConfig,
    pub(super) dependency_egress_plans: Vec<EgressPlanHandle>,
    pub(super) dependency_egress_direct: Vec<bool>,
}

pub(super) fn validate_client_prepared(
    raw: RawClientRoot,
    rule_set_tags: &[&str],
    dependency_egress_tags: &[&str],
    dependency_dns_servers: &[usize],
) -> Result<PreparedClientValidation, ConfigError> {
    validate_client_inner(
        raw,
        rule_set_tags,
        dependency_egress_tags,
        dependency_dns_servers,
        true,
    )
}

fn validate_client_inner(
    mut raw: RawClientRoot,
    rule_set_tags: &[&str],
    dependency_egress_tags: &[&str],
    dependency_dns_servers: &[usize],
    defer_tun_targets: bool,
) -> Result<PreparedClientValidation, ConfigError> {
    let schema_version = v2::validate_version(raw.schema_version)?;
    let route_network = validate_route_network(raw.route.as_ref())?;
    let default_direct_strategy = raw
        .dns
        .as_ref()
        .map(validate_dns_runtime)
        .transpose()?
        .map_or(DnsStrategy::PreferIpv4, DnsRuntimeConfig::strategy);
    let direct_domain_resolvers = raw
        .outbounds
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|outbound| {
            (outbound.outbound_type.as_deref() == Some("direct"))
                .then(|| {
                    validate_direct_domain_resolver(
                        outbound.domain_resolver.as_deref(),
                        outbound.domain_strategy.as_deref(),
                        raw.dns.as_ref(),
                        default_direct_strategy,
                    )
                })
                .transpose()
        })
        .collect::<Result<Vec<_>, _>>()?;
    let global_tags = client_global_tags(&raw);
    let socks_inbound_count = raw.inbounds.as_deref().map_or(0, <[RawClientInbound]>::len);
    let mut tun = raw.tun.take().map(validate_tun).transpose()?;
    if let Some(tun) = &tun {
        raw.inbounds
            .get_or_insert_with(Vec::new)
            .push(RawClientInbound {
                tag: tun.tag.clone(),
                listen: "0.0.0.0:0".to_owned(),
                outbound: tun.outbound.clone(),
            });
    }
    let context_inbounds = raw
        .inbounds
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|inbound| inbound.tag.clone())
        .collect::<Vec<_>>();
    let context_outbounds = raw
        .inbounds
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|inbound| inbound.outbound.clone())
        .collect::<Vec<_>>();
    let explicit_route = raw.route.is_some();
    let route_draft = v2::compile_route_draft(
        raw.route.as_ref(),
        &context_inbounds,
        &context_outbounds,
        rule_set_tags,
        v2::Role::Client,
        tun.as_ref().map(|_| socks_inbound_count),
        raw.dns.is_some(),
        raw.runtime.max_connections,
    )?;
    let route_roots = route_draft.root_tags();
    let dns_detour_tags = raw.dns.as_ref().map(dns_detour_tags).unwrap_or_default();
    let detour_tags = dependency_egress_tags
        .iter()
        .copied()
        .chain(dns_detour_tags.iter().copied())
        .collect::<Vec<_>>();
    let (inbounds, outbounds, selector, mut roots, physical_first_hops, mut direct_detours) =
        validate_client_graph(
            raw.inbounds,
            raw.outbounds,
            raw.chains,
            raw.selectors,
            &direct_domain_resolvers,
            GraphValidation {
                route_roots: &route_roots,
                detour_tags: &detour_tags,
                retained_client_inbounds: socks_inbound_count,
                explicit_route,
            },
        )?;
    if roots.len() < route_roots.len()
        || direct_detours.len() != detour_tags.len()
        || roots.len() - route_roots.len() != detour_tags.len()
    {
        return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
    }
    let dns_direct_detours = direct_detours.split_off(dependency_egress_tags.len());
    let mut detours = roots.split_off(route_roots.len());
    let dns_detours = detours.split_off(dependency_egress_tags.len());
    let route = route_draft.finish(roots, selector)?;
    let ordinary_listens = inbounds
        .iter()
        .map(|inbound| SocketAddr::V4(inbound.listen))
        .collect::<Vec<_>>();
    let outbound_servers = outbounds
        .iter()
        .filter_map(ClientOutboundConfig::server)
        .collect::<Vec<_>>();
    let dns_route_raw = raw.dns.clone();
    let dns = validate_dns(
        raw.dns,
        DnsValidationContext {
            role: DnsRole::Client,
            global_tags: &global_tags,
            ordinary_listens: &ordinary_listens,
            outbound_servers: &outbound_servers,
            dependency_servers: dependency_dns_servers,
        },
        dns_detours,
    )?;
    if let Some(tun) = &mut tun {
        if tun.config.auto_dns && dns.is_none() {
            return Err(ConfigError::semantic(ConfigField::TunAutoDns));
        }
        if !defer_tun_targets {
            validate_tun_targets(
                &mut tun.config,
                &outbounds,
                &physical_first_hops,
                &dns_direct_detours,
                dns.as_ref(),
            )?;
        }
    }
    let dns_route = dns_route_raw.as_ref().map(|dns| ClientDnsRoute {
        listener_count: dns.inbounds.as_deref().map_or(0, <[_]>::len),
        ordinary_count: context_inbounds.len(),
        rule_count: dns.route.as_ref().map_or(0, |route| route.rules.len()),
        policy_blueprint: None,
    });
    let runtime = validate_runtime(raw.runtime)?;
    let udp = raw.udp.map(validate_udp).transpose()?;
    let logging = validate_logging(raw.logging)?;
    let mut listens: Vec<_> = inbounds.iter().map(|inbound| inbound.listen).collect();
    if let Some(dns) = &dns {
        listens.extend(
            dns.inbounds
                .iter()
                .filter_map(|inbound| match inbound.listen {
                    SocketAddr::V4(listen) => Some(listen),
                    SocketAddr::V6(_) => None,
                }),
        );
    }
    let metrics = validate_metrics(raw.metrics, &listens)?;
    Ok(PreparedClientValidation {
        config: ValidatedClientConfig {
            schema_version,
            inbounds,
            outbounds,
            route,
            route_network,
            tun: tun.map(|tun| tun.config),
            dns,
            dns_route,
            runtime,
            udp,
            logging,
            metrics,
        },
        physical_first_hops,
        direct_detours: dns_direct_detours,
        dependency_egress_plans: detours,
        dependency_egress_direct: direct_detours,
    })
}

pub(super) fn validate_server_prepared(
    raw: RawServerRoot,
    rule_set_tags: &[&str],
    dependency_egress_tags: &[&str],
    dependency_dns_servers: &[usize],
) -> Result<PreparedServerValidation, ConfigError> {
    validate_server_inner(
        raw,
        rule_set_tags,
        dependency_egress_tags,
        dependency_dns_servers,
    )
}

fn validate_server_inner(
    raw: RawServerRoot,
    rule_set_tags: &[&str],
    dependency_egress_tags: &[&str],
    dependency_dns_servers: &[usize],
) -> Result<PreparedServerValidation, ConfigError> {
    if raw.tun.is_some() {
        return Err(ConfigError::semantic(ConfigField::Tun));
    }
    let schema_version = v2::validate_version(raw.schema_version)?;
    let route_network = validate_route_network(raw.route.as_ref())?;
    let default_direct_strategy = raw
        .dns
        .as_ref()
        .map(validate_dns_runtime)
        .transpose()?
        .map_or(DnsStrategy::PreferIpv4, DnsRuntimeConfig::strategy);
    let direct_domain_resolvers = raw
        .outbounds
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|outbound| {
            validate_direct_domain_resolver(
                outbound.domain_resolver.as_deref(),
                outbound.domain_strategy.as_deref(),
                raw.dns.as_ref(),
                default_direct_strategy,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let global_tags = server_global_tags(&raw);
    let context_inbounds = raw
        .inbounds
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|inbound| inbound.tag.clone())
        .collect::<Vec<_>>();
    let context_outbounds = raw
        .inbounds
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|inbound| inbound.outbound.clone())
        .collect::<Vec<_>>();
    if raw.chains.is_some() {
        return Err(ConfigError::semantic(ConfigField::Chains));
    }
    let explicit_route = raw.route.is_some();
    let route_draft = v2::compile_route_draft(
        raw.route.as_ref(),
        &context_inbounds,
        &context_outbounds,
        rule_set_tags,
        v2::Role::Server,
        None,
        raw.dns.is_some(),
        raw.runtime.max_connections,
    )?;
    let route_roots = route_draft.root_tags();
    let dns_detour_tags = raw.dns.as_ref().map(dns_detour_tags).unwrap_or_default();
    let detour_tags = dependency_egress_tags
        .iter()
        .copied()
        .chain(dns_detour_tags.iter().copied())
        .collect::<Vec<_>>();
    let (inbounds, outbounds, selector, mut roots) = validate_server_graph(
        raw.inbounds,
        raw.outbounds,
        raw.selectors,
        &direct_domain_resolvers,
        GraphValidation {
            route_roots: &route_roots,
            detour_tags: &detour_tags,
            retained_client_inbounds: 0,
            explicit_route,
        },
    )?;
    if roots.len() < route_roots.len() || roots.len() - route_roots.len() != detour_tags.len() {
        return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
    }
    let mut detours = roots.split_off(route_roots.len());
    let dns_detours = detours.split_off(dependency_egress_tags.len());
    let route = route_draft.finish(roots, selector)?;
    let dns_route_raw = raw.dns.clone();
    let dns = validate_dns(
        raw.dns,
        DnsValidationContext {
            role: DnsRole::Server,
            global_tags: &global_tags,
            ordinary_listens: &[],
            outbound_servers: &[],
            dependency_servers: dependency_dns_servers,
        },
        dns_detours,
    )?;
    let dns_route = dns_route_raw.as_ref().map(|dns| ServerDnsRoute {
        ordinary_count: context_inbounds.len(),
        rule_count: dns.route.as_ref().map_or(0, |route| route.rules.len()),
        policy_blueprint: None,
    });
    let method = parse_method(&raw.shadowsocks.method, ConfigField::ShadowsocksMethod)?;
    let psk = parse_psk(method, &raw.shadowsocks.psk, ConfigField::ShadowsocksPsk)?;
    let runtime = validate_runtime(raw.runtime)?;
    let replay = validate_replay(raw.replay)?;
    let udp = validate_udp(raw.udp)?;
    let logging = validate_logging(raw.logging)?;
    let listens: Vec<_> = inbounds.iter().map(|inbound| inbound.listen).collect();
    let metrics = validate_metrics(raw.metrics, &listens)?;
    let mut dependency_egress_direct = Vec::new();
    dependency_egress_direct
        .try_reserve_exact(detours.len())
        .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
    dependency_egress_direct.resize(detours.len(), true);
    Ok(PreparedServerValidation {
        config: ValidatedServerConfig {
            schema_version,
            inbounds,
            outbounds,
            route,
            route_network,
            dns,
            dns_route,
            psk,
            runtime,
            replay,
            udp,
            logging,
            metrics,
        },
        dependency_egress_plans: detours,
        dependency_egress_direct,
    })
}

fn validate_route_network(raw: Option<&RawRoute>) -> Result<RouteNetworkConfig, ConfigError> {
    let Some(raw) = raw else {
        return Ok(RouteNetworkConfig::default());
    };
    let default_interface = validate_interface_name(
        raw.default_interface.as_deref(),
        ConfigField::RouteDefaultInterface,
    )?;
    Ok(RouteNetworkConfig {
        auto_detect_interface: raw.auto_detect_interface,
        default_interface,
    })
}

fn validate_interface_name(
    raw: Option<&str>,
    field: ConfigField,
) -> Result<Option<Box<str>>, ConfigError> {
    raw.map(|name| {
        if name.is_empty()
            || name.encode_utf16().count() > MAX_INTERFACE_NAME_UTF16_UNITS
            || name.chars().any(char::is_control)
        {
            return Err(ConfigError::semantic(field));
        }
        Ok(name.to_owned().into_boxed_str())
    })
    .transpose()
}

fn validate_outbound_dial_options(
    bind_interface: Option<&str>,
    inet4_bind_address: Option<&str>,
    inet6_bind_address: Option<&str>,
) -> Result<OutboundDialOptions, ConfigError> {
    Ok(OutboundDialOptions {
        bind_interface: validate_interface_name(
            bind_interface,
            ConfigField::OutboundsBindInterface,
        )?,
        inet4_bind_address: inet4_bind_address
            .map(|address| {
                address
                    .parse::<Ipv4Addr>()
                    .map_err(|_| ConfigError::semantic(ConfigField::OutboundsInet4BindAddress))
            })
            .transpose()?,
        inet6_bind_address: inet6_bind_address
            .map(|address| {
                address
                    .parse::<Ipv6Addr>()
                    .map_err(|_| ConfigError::semantic(ConfigField::OutboundsInet6BindAddress))
            })
            .transpose()?,
    })
}

type ValidatedClientGraph = (
    Vec<ClientInboundConfig>,
    Vec<ClientOutboundConfig>,
    SelectorControl,
    Vec<EgressPlanHandle>,
    Vec<usize>,
    Vec<bool>,
);

#[allow(clippy::too_many_arguments)]
fn validate_client_graph(
    tagged_inbounds: Option<Vec<RawClientInbound>>,
    tagged_outbounds: Option<Vec<RawClientOutbound>>,
    chains: Option<Vec<RawChain>>,
    selectors: Option<Vec<RawSelector>>,
    direct_domain_resolvers: &[Option<DirectDomainResolver>],
    validation: GraphValidation<'_>,
) -> Result<ValidatedClientGraph, ConfigError> {
    let GraphValidation {
        route_roots,
        detour_tags,
        retained_client_inbounds: socks_inbound_count,
        explicit_route,
    } = validation;
    let inbounds = tagged_inbounds.ok_or_else(|| ConfigError::semantic(ConfigField::Inbounds))?;
    let outbounds =
        tagged_outbounds.ok_or_else(|| ConfigError::semantic(ConfigField::Outbounds))?;
    if selectors.as_deref().is_some_and(<[RawSelector]>::is_empty) {
        return Err(ConfigError::semantic(ConfigField::Selectors));
    }
    validate_count(inbounds.len(), ConfigField::Inbounds)?;
    validate_count(outbounds.len(), ConfigField::Outbounds)?;

    let mut listens = Vec::with_capacity(inbounds.len());
    for (index, inbound) in inbounds.iter().enumerate() {
        validate_tag(&inbound.tag, ConfigField::InboundsTag)?;
        if inbounds[..index]
            .iter()
            .any(|other| other.tag == inbound.tag)
        {
            return Err(ConfigError::semantic(ConfigField::InboundsTag));
        }
        let listen = if index < socks_inbound_count {
            parse_endpoint(&inbound.listen, ConfigField::InboundsListen)?
        } else {
            SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0)
        };
        if index < socks_inbound_count && listens.contains(&listen) {
            return Err(ConfigError::semantic(ConfigField::InboundsListen));
        }
        listens.push(listen);
    }

    let mut validated_outbounds = Vec::with_capacity(outbounds.len());
    for (index, outbound) in outbounds.iter().enumerate() {
        validate_tag(&outbound.tag, ConfigField::OutboundsTag)?;
        if inbounds.iter().any(|inbound| inbound.tag == outbound.tag)
            || outbounds[..index]
                .iter()
                .any(|other| other.tag == outbound.tag)
        {
            return Err(ConfigError::semantic(ConfigField::OutboundsTag));
        }
        let dial_options = validate_outbound_dial_options(
            outbound.bind_interface.as_deref(),
            outbound.inet4_bind_address.as_deref(),
            outbound.inet6_bind_address.as_deref(),
        )?;
        match outbound
            .outbound_type
            .as_deref()
            .ok_or_else(|| ConfigError::semantic(ConfigField::OutboundsType))?
        {
            "direct" => {
                if outbound.server.is_some() {
                    return Err(ConfigError::semantic(ConfigField::OutboundsServer));
                }
                if outbound.method.is_some() {
                    return Err(ConfigError::semantic(ConfigField::OutboundsMethod));
                }
                if outbound.psk.is_some() {
                    return Err(ConfigError::semantic(ConfigField::OutboundsPsk));
                }
                let domain_resolver = direct_domain_resolvers
                    .get(index)
                    .copied()
                    .flatten()
                    .ok_or_else(|| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
                validated_outbounds.push(ClientOutboundConfig::Direct {
                    domain_resolver,
                    dial_options,
                });
            }
            "shadowsocks" => {
                let method = outbound
                    .method
                    .as_deref()
                    .ok_or_else(|| ConfigError::semantic(ConfigField::OutboundsMethod))?;
                let psk = outbound
                    .psk
                    .as_ref()
                    .ok_or_else(|| ConfigError::semantic(ConfigField::OutboundsPsk))?;
                let method = parse_method(method, ConfigField::OutboundsMethod)?;
                let psk = Arc::new(parse_psk(method, psk, ConfigField::OutboundsPsk)?);
                let server = parse_socket(
                    outbound
                        .server
                        .as_deref()
                        .ok_or_else(|| ConfigError::semantic(ConfigField::OutboundsServer))?,
                    ConfigField::OutboundsServer,
                )?;
                if listens
                    .iter()
                    .any(|listen| SocketAddr::V4(*listen) == server)
                {
                    return Err(ConfigError::semantic(ConfigField::OutboundsServer));
                }
                validated_outbounds.push(ClientOutboundConfig::Shadowsocks {
                    server,
                    psk,
                    dial_options,
                });
            }
            _ => return Err(ConfigError::semantic(ConfigField::OutboundsType)),
        }
    }

    let plans = validate_chains(
        chains.as_deref(),
        &inbounds,
        &outbounds,
        &validated_outbounds,
        selectors.as_deref(),
    )?;
    for (index, tag) in route_roots.iter().copied().enumerate() {
        if !outbounds.iter().any(|outbound| outbound.tag == tag)
            && !chains
                .as_deref()
                .is_some_and(|chains| chains.iter().any(|chain| chain.tag.as_deref() == Some(tag)))
            && !selectors
                .as_deref()
                .is_some_and(|selectors| selectors.iter().any(|selector| selector.tag == tag))
        {
            return Err(ConfigError::semantic(if !explicit_route {
                ConfigField::InboundsOutbound
            } else if index == 0 {
                ConfigField::RouteFinal
            } else {
                ConfigField::RouteRulesOutbound
            }));
        }
    }
    if detour_tags.iter().any(|tag| {
        !outbounds.iter().any(|outbound| outbound.tag == **tag)
            && !chains.as_deref().is_some_and(|chains| {
                chains
                    .iter()
                    .any(|chain| chain.tag.as_deref() == Some(*tag))
            })
            && !selectors
                .as_deref()
                .is_some_and(|selectors| selectors.iter().any(|selector| selector.tag == **tag))
    }) {
        return Err(ConfigError::semantic(ConfigField::DnsServersDetour));
    }
    let graph_roots = route_roots
        .iter()
        .copied()
        .chain(detour_tags.iter().copied())
        .collect::<Vec<_>>();
    let extra_roots = graph_roots.as_slice();
    let ordinary_roots = route_roots
        .iter()
        .map(|tag| (*tag).to_owned())
        .collect::<Vec<_>>();
    let (selector, detours) = compile_graph_roots(
        &inbounds
            .iter()
            .map(|inbound| inbound.tag.as_str())
            .collect::<Vec<_>>(),
        &outbounds
            .iter()
            .map(|outbound| outbound.tag.as_str())
            .collect::<Vec<_>>(),
        selectors.as_deref().unwrap_or(&[]),
        &plans,
        extra_roots,
        explicit_route,
    )?;
    let validated_inbounds = listens
        .into_iter()
        .take(socks_inbound_count)
        .map(|listen| ClientInboundConfig { listen })
        .collect::<Vec<_>>();
    let first_hops = |root: &str| {
        let mut pending = vec![root];
        let mut first = Vec::new();
        while let Some(tag) = pending.pop() {
            if let Some(index) = outbounds.iter().position(|outbound| outbound.tag == tag) {
                first.push(index);
            } else if let Some(chain) = chains
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .find(|chain| chain.tag.as_deref() == Some(tag))
            {
                first.push(
                    outbounds
                        .iter()
                        .position(|outbound| {
                            Some(&outbound.tag) == chain.hops.as_ref().and_then(|hops| hops.first())
                        })
                        .expect("validated chain first hop"),
                );
            } else if let Some(selector) = selectors
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .find(|selector| selector.tag == tag)
            {
                pending.extend(selector.outbounds.iter().map(String::as_str));
            }
        }
        first.sort_unstable();
        first.dedup();
        first
    };
    let direct_detours = detour_tags
        .iter()
        .map(|tag| {
            first_hops(tag).iter().any(|index| {
                matches!(
                    validated_outbounds[*index],
                    ClientOutboundConfig::Direct { .. }
                )
            })
        })
        .collect();
    let mut physical_first_hops = ordinary_roots
        .iter()
        .map(String::as_str)
        .chain(detour_tags.iter().copied())
        .flat_map(first_hops)
        .collect::<Vec<_>>();
    physical_first_hops.sort_unstable();
    physical_first_hops.dedup();
    Ok((
        validated_inbounds,
        validated_outbounds,
        selector,
        detours,
        physical_first_hops,
        direct_detours,
    ))
}

fn validate_chains<'a>(
    chains: Option<&'a [RawChain]>,
    inbounds: &[RawClientInbound],
    outbounds: &[RawClientOutbound],
    validated_outbounds: &[ClientOutboundConfig],
    selectors: Option<&[RawSelector]>,
) -> Result<Vec<TaggedPlan<'a>>, ConfigError> {
    let Some(chains) = chains else {
        return Ok(Vec::new());
    };
    validate_count(chains.len(), ConfigField::Chains)?;
    let mut plans = Vec::with_capacity(chains.len());
    for (index, chain) in chains.iter().enumerate() {
        let tag = chain
            .tag
            .as_deref()
            .ok_or_else(|| ConfigError::semantic(ConfigField::Chains))?;
        let chain_hops = chain
            .hops
            .as_deref()
            .ok_or_else(|| ConfigError::semantic(ConfigField::Chains))?;
        validate_tag(tag, ConfigField::ChainsTag)?;
        if inbounds.iter().any(|inbound| inbound.tag == tag)
            || outbounds.iter().any(|outbound| outbound.tag == tag)
            || chains[..index]
                .iter()
                .any(|other| other.tag.as_deref() == Some(tag))
            || selectors
                .is_some_and(|selectors| selectors.iter().any(|selector| selector.tag == tag))
        {
            return Err(ConfigError::semantic(ConfigField::ChainsTag));
        }
        if !(2..=8).contains(&chain_hops.len()) {
            return Err(ConfigError::semantic(ConfigField::ChainsHops));
        }
        let mut hops = Vec::with_capacity(chain_hops.len());
        for (hop, outbound_tag) in chain_hops.iter().enumerate() {
            validate_tag(outbound_tag, ConfigField::ChainsHops)?;
            if chain_hops[..hop].contains(outbound_tag) {
                return Err(ConfigError::semantic(ConfigField::ChainsHops));
            }
            let outbound = outbounds
                .iter()
                .position(|outbound| outbound.tag == *outbound_tag)
                .ok_or_else(|| ConfigError::semantic(ConfigField::ChainsHops))?;
            if matches!(
                validated_outbounds[outbound],
                ClientOutboundConfig::Direct { .. }
            ) {
                return Err(ConfigError::semantic(ConfigField::ChainsHops));
            }
            hops.push(outbound);
        }
        plans.push(TaggedPlan::new(tag, hops));
    }
    Ok(plans)
}

type ValidatedServerGraph = (
    Vec<ServerInboundConfig>,
    Vec<ServerOutboundConfig>,
    SelectorControl,
    Vec<EgressPlanHandle>,
);

fn validate_server_graph(
    tagged_inbounds: Option<Vec<RawServerInbound>>,
    tagged_outbounds: Option<Vec<RawServerOutbound>>,
    selectors: Option<Vec<RawSelector>>,
    direct_domain_resolvers: &[DirectDomainResolver],
    validation: GraphValidation<'_>,
) -> Result<ValidatedServerGraph, ConfigError> {
    let GraphValidation {
        route_roots,
        detour_tags,
        retained_client_inbounds: _,
        explicit_route,
    } = validation;
    let inbounds = tagged_inbounds.ok_or_else(|| ConfigError::semantic(ConfigField::Inbounds))?;
    let outbounds =
        tagged_outbounds.ok_or_else(|| ConfigError::semantic(ConfigField::Outbounds))?;
    if selectors.as_deref().is_some_and(<[RawSelector]>::is_empty) {
        return Err(ConfigError::semantic(ConfigField::Selectors));
    }
    validate_count(inbounds.len(), ConfigField::Inbounds)?;
    validate_count(outbounds.len(), ConfigField::Outbounds)?;

    let mut listens = Vec::with_capacity(inbounds.len());
    for (index, inbound) in inbounds.iter().enumerate() {
        validate_tag(&inbound.tag, ConfigField::InboundsTag)?;
        if inbounds[..index]
            .iter()
            .any(|other| other.tag == inbound.tag)
        {
            return Err(ConfigError::semantic(ConfigField::InboundsTag));
        }
        let listen = parse_endpoint(&inbound.listen, ConfigField::InboundsListen)?;
        if listens.contains(&listen) {
            return Err(ConfigError::semantic(ConfigField::InboundsListen));
        }
        listens.push(listen);
    }
    for (index, outbound) in outbounds.iter().enumerate() {
        validate_tag(&outbound.tag, ConfigField::OutboundsTag)?;
        if inbounds.iter().any(|inbound| inbound.tag == outbound.tag)
            || outbounds[..index]
                .iter()
                .any(|other| other.tag == outbound.tag)
        {
            return Err(ConfigError::semantic(ConfigField::OutboundsTag));
        }
    }

    for (index, tag) in route_roots.iter().copied().enumerate() {
        if !outbounds.iter().any(|outbound| outbound.tag == tag)
            && !selectors
                .as_deref()
                .is_some_and(|selectors| selectors.iter().any(|selector| selector.tag == tag))
        {
            return Err(ConfigError::semantic(if !explicit_route {
                ConfigField::InboundsOutbound
            } else if index == 0 {
                ConfigField::RouteFinal
            } else {
                ConfigField::RouteRulesOutbound
            }));
        }
    }
    if detour_tags.iter().any(|tag| {
        !outbounds.iter().any(|outbound| outbound.tag == **tag)
            && !selectors
                .as_deref()
                .is_some_and(|selectors| selectors.iter().any(|selector| selector.tag == **tag))
    }) {
        return Err(ConfigError::semantic(ConfigField::DnsServersDetour));
    }
    let graph_roots = route_roots
        .iter()
        .copied()
        .chain(detour_tags.iter().copied())
        .collect::<Vec<_>>();
    let detour_tags = graph_roots.as_slice();
    let (selector, detours) = compile_graph_roots(
        &inbounds
            .iter()
            .map(|inbound| inbound.tag.as_str())
            .collect::<Vec<_>>(),
        &outbounds
            .iter()
            .map(|outbound| outbound.tag.as_str())
            .collect::<Vec<_>>(),
        selectors.as_deref().unwrap_or(&[]),
        &[],
        detour_tags,
        explicit_route,
    )?;
    let validated_inbounds = listens
        .into_iter()
        .map(|listen| ServerInboundConfig { listen })
        .collect::<Vec<_>>();
    Ok((
        validated_inbounds,
        outbounds
            .iter()
            .zip(direct_domain_resolvers.iter().copied())
            .map(|(outbound, domain_resolver)| {
                Ok(ServerOutboundConfig {
                    domain_resolver,
                    dial_options: validate_outbound_dial_options(
                        outbound.bind_interface.as_deref(),
                        outbound.inet4_bind_address.as_deref(),
                        outbound.inet6_bind_address.as_deref(),
                    )?,
                })
            })
            .collect::<Result<Vec<_>, ConfigError>>()?,
        selector,
        detours,
    ))
}

fn compile_graph_roots(
    inbounds: &[&str],
    outbounds: &[&str],
    selectors: &[RawSelector],
    plans: &[TaggedPlan<'_>],
    roots: &[&str],
    explicit_route: bool,
) -> Result<(SelectorControl, Vec<EgressPlanHandle>), ConfigError> {
    let tagged_inbounds = inbounds
        .iter()
        .enumerate()
        .map(|(index, tag)| TaggedInbound::new(tag, index))
        .collect::<Vec<_>>();
    let tagged_outbounds = outbounds
        .iter()
        .enumerate()
        .map(|(index, tag)| TaggedOutbound::new(tag, index))
        .collect::<Vec<_>>();
    let definitions = selectors
        .iter()
        .map(|selector| {
            SelectorDefinition::new(
                &selector.tag,
                selector.outbounds.iter().map(String::as_str).collect(),
                selector.default.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    compile_egress_plans_with_roots(
        &tagged_inbounds,
        &tagged_outbounds,
        plans,
        &definitions,
        roots,
    )
    .map_err(|error| match error {
        SelectorCompileError::Allocation => ConfigError::rule_allocation(ConfigField::RouteRules),
        SelectorCompileError::RuleCompile => ConfigError::rule_compile(ConfigField::RouteRules),
        SelectorCompileError::ExtraRoot => ConfigError::semantic(ConfigField::DnsServersDetour),
        _ => ConfigError::semantic(selector_error_field(error, explicit_route)),
    })
}

const fn selector_error_field(error: SelectorCompileError, routed: bool) -> ConfigField {
    match error {
        SelectorCompileError::Allocation | SelectorCompileError::RuleCompile => {
            ConfigField::RouteRules
        }
        SelectorCompileError::Inbounds => ConfigField::InboundsTag,
        SelectorCompileError::Outbounds => ConfigField::OutboundsTag,
        SelectorCompileError::Plans => ConfigField::Chains,
        SelectorCompileError::PlanTag | SelectorCompileError::UnreachablePlan => {
            ConfigField::ChainsTag
        }
        SelectorCompileError::PlanHops => ConfigField::ChainsHops,
        SelectorCompileError::Selectors => ConfigField::Selectors,
        SelectorCompileError::SelectorTag | SelectorCompileError::UnreachableSelector => {
            ConfigField::SelectorsTag
        }
        SelectorCompileError::SelectorOutbounds => ConfigField::SelectorsOutbounds,
        SelectorCompileError::SelectorDefault => ConfigField::SelectorsDefault,
        SelectorCompileError::StaticBinding => ConfigField::InboundsOutbound,
        SelectorCompileError::RouteRules => ConfigField::RouteRules,
        SelectorCompileError::RouteRuleInbound => ConfigField::RouteRulesInbound,
        SelectorCompileError::RouteRuleOutbound => ConfigField::RouteRulesOutbound,
        SelectorCompileError::ExtraRoot => ConfigField::RouteRulesOutbound,
        SelectorCompileError::RouteFinal => ConfigField::RouteFinal,
        SelectorCompileError::UnreachableOutbound if routed => ConfigField::RouteRulesOutbound,
        SelectorCompileError::UnreachableOutbound => ConfigField::OutboundsTag,
    }
}

fn validate_count(count: usize, field: ConfigField) -> Result<(), ConfigError> {
    if (1..=64).contains(&count) {
        Ok(())
    } else {
        Err(ConfigError::semantic(field))
    }
}

pub(super) fn validate_tag(tag: &str, field: ConfigField) -> Result<(), ConfigError> {
    if (1..=64).contains(&tag.len())
        && tag
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        Ok(())
    } else {
        Err(ConfigError::semantic(field))
    }
}

fn parse_endpoint(value: &str, field: ConfigField) -> Result<SocketAddrV4, ConfigError> {
    let endpoint: SocketAddrV4 = value.parse().map_err(|_| ConfigError::semantic(field))?;
    if endpoint.port() == 0 {
        return Err(ConfigError::semantic(field));
    }
    Ok(endpoint)
}

fn parse_method(value: &str, field: ConfigField) -> Result<MethodProfile, ConfigError> {
    match value {
        "2022-blake3-aes-128-gcm" => Ok(MethodProfile::Blake3Aes128Gcm2022),
        "2022-blake3-aes-256-gcm" => Ok(MethodProfile::Blake3Aes256Gcm2022),
        "2022-blake3-chacha20-poly1305" => Ok(MethodProfile::Blake3ChaCha20Poly13052022),
        _ => Err(ConfigError::semantic(field)),
    }
}

fn parse_psk(
    method: MethodProfile,
    value: &SecretString,
    field: ConfigField,
) -> Result<MethodPsk, ConfigError> {
    let token = value.as_str();
    let expected_bytes = method.key_bytes();
    let expected_encoded_bytes = expected_bytes.div_ceil(3) * 4;
    if token.len() != expected_encoded_bytes {
        return Err(ConfigError::semantic(field));
    }

    let mut decoded = Zeroizing::new([0_u8; 32]);
    let decoded_len = STANDARD
        .decode_slice(token.as_bytes(), decoded.as_mut())
        .map_err(|_| ConfigError::semantic(field))?;
    if decoded_len != expected_bytes {
        return Err(ConfigError::semantic(field));
    }

    let mut canonical = Zeroizing::new([0_u8; 44]);
    let encoded_len = STANDARD
        .encode_slice(&decoded[..decoded_len], canonical.as_mut())
        .map_err(|_| ConfigError::semantic(field))?;
    if encoded_len != token.len() || &canonical[..encoded_len] != token.as_bytes() {
        return Err(ConfigError::semantic(field));
    }

    let psk = MethodPsk::try_from_slice(method, &decoded[..decoded_len])
        .map_err(|_| ConfigError::semantic(field))?;
    decoded.zeroize();
    canonical.zeroize();
    Ok(psk)
}

fn validate_runtime(raw: RawRuntime) -> Result<RuntimeConfig, ConfigError> {
    let max_connections =
        bounded_nonzero_u16(raw.max_connections, ConfigField::RuntimeMaxConnections)?;
    let listen_backlog =
        bounded_nonzero_u16(raw.listen_backlog, ConfigField::RuntimeListenBacklog)?;
    let handshake_timeout = bounded_duration(
        raw.handshake_timeout_ms,
        100,
        60_000,
        ConfigField::RuntimeHandshakeTimeout,
    )?;
    let connect_timeout = bounded_duration(
        raw.connect_timeout_ms,
        100,
        120_000,
        ConfigField::RuntimeConnectTimeout,
    )?;
    let idle_timeout = bounded_duration(
        raw.idle_timeout_ms,
        1_000,
        86_400_000,
        ConfigField::RuntimeIdleTimeout,
    )?;
    let shutdown_grace = bounded_duration(
        raw.shutdown_grace_ms,
        0,
        300_000,
        ConfigField::RuntimeShutdownGrace,
    )?;
    Ok(RuntimeConfig {
        max_connections,
        listen_backlog,
        handshake_timeout,
        connect_timeout,
        idle_timeout,
        shutdown_grace,
    })
}

fn bounded_nonzero_u16(value: u32, field: ConfigField) -> Result<NonZeroU16, ConfigError> {
    let value = u16::try_from(value).map_err(|_| ConfigError::semantic(field))?;
    NonZeroU16::new(value).ok_or_else(|| ConfigError::semantic(field))
}

fn bounded_duration(
    value: u64,
    minimum: u64,
    maximum: u64,
    field: ConfigField,
) -> Result<Duration, ConfigError> {
    if (minimum..=maximum).contains(&value) {
        Ok(Duration::from_millis(value))
    } else {
        Err(ConfigError::semantic(field))
    }
}

fn validate_replay(raw: RawReplay) -> Result<ReplayConfig, ConfigError> {
    if (1_024..=1_048_576).contains(&raw.capacity) {
        Ok(ReplayConfig {
            capacity: raw.capacity,
        })
    } else {
        Err(ConfigError::semantic(ConfigField::ReplayCapacity))
    }
}

fn validate_udp(raw: RawUdp) -> Result<UdpConfig, ConfigError> {
    if !(1..=65_535).contains(&raw.max_sessions) {
        return Err(ConfigError::semantic(ConfigField::UdpMaxSessions));
    }
    if !((1024 * 1024)..=(256 * 1024 * 1024)).contains(&raw.max_buffered_bytes) {
        return Err(ConfigError::semantic(ConfigField::UdpMaxBufferedBytes));
    }
    let idle_timeout = bounded_duration(
        raw.idle_timeout_ms,
        60_000,
        86_400_000,
        ConfigField::UdpIdleTimeout,
    )?;
    Ok(UdpConfig {
        enabled: raw.enabled,
        max_sessions: raw.max_sessions,
        max_buffered_bytes: raw.max_buffered_bytes,
        idle_timeout,
    })
}

fn validate_logging(raw: RawLogging) -> Result<LoggingConfig, ConfigError> {
    let level = match raw.level.as_str() {
        "error" => LoggingLevel::Error,
        "warn" => LoggingLevel::Warn,
        "info" => LoggingLevel::Info,
        "debug" => LoggingLevel::Debug,
        "trace" => LoggingLevel::Trace,
        _ => return Err(ConfigError::semantic(ConfigField::LoggingLevel)),
    };
    Ok(LoggingConfig { level })
}

fn validate_metrics(
    raw: Option<RawMetrics>,
    proxy_listens: &[SocketAddrV4],
) -> Result<Option<MetricsConfig>, ConfigError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let listen = parse_endpoint(&raw.listen, ConfigField::MetricsListen)?;
    if !listen.ip().is_loopback() || proxy_listens.contains(&listen) {
        return Err(ConfigError::semantic(ConfigField::MetricsListen));
    }
    Ok(Some(MetricsConfig { listen }))
}
