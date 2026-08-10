use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::num::NonZeroU16;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ferrum2_core::TargetAddr;
use ferrum2_core::route::{
    ActionRule, ActionTable, EgressPlanHandle, MAX_ROUTE_RULES, Network, RouteRule, RouteTable,
    compile_selector_plans_with_roots,
};
use ferrum2_core::selector::{
    SelectorCompileError, SelectorDefinition, TaggedInbound, TaggedOutbound, TaggedPlan,
    TaggedRoute, TaggedRouteRule, TaggedStaticBinding,
};
use ferrum2_crypto::{MethodPsk, TcpMethodProfile};
use ipnet::{Ipv4Net, Ipv6Net};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{ConfigError, ConfigErrorKind, ConfigField};
use crate::model::{
    ClientInboundConfig, ClientOutboundConfig, DnsConfig, DnsInboundConfig, DnsServerConfig,
    DnsTransport, LoggingConfig, LoggingLevel, MetricsConfig, ReplayConfig, RuntimeConfig,
    SchemaVersion, ServerInboundConfig, ServerOutboundConfig, TunConfig, UdpConfig,
    ValidatedClientConfig, ValidatedServerConfig,
};
use crate::raw::{
    RawChain, RawClient, RawClientInbound, RawClientOutbound, RawClientRoot, RawDns, RawLogging,
    RawMetrics, RawReplay, RawRoute, RawRouteTarget, RawRuntime, RawSelector, RawServer,
    RawServerInbound, RawServerOutbound, RawServerRoot, RawShadowsocks, RawTun, RawUdp,
    ScalarOrList, SecretString,
};

mod v2;

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
    schema_version: SchemaVersion,
    global_tags: &'a [String],
    context_inbounds: &'a [String],
    ordinary_listens: &'a [SocketAddr],
    outbound_servers: &'a [SocketAddr],
}

struct GraphValidation<'a> {
    route_roots: &'a [&'a str],
    detour_tags: &'a [&'a str],
    source: &'a str,
    retained_client_inbounds: usize,
}

fn validate_dns(
    raw: Option<RawDns>,
    context: DnsValidationContext<'_>,
    detours: Vec<EgressPlanHandle>,
    source: &str,
) -> Result<Option<DnsConfig>, ConfigError> {
    let Some(raw) = raw else {
        debug_assert!(detours.is_empty());
        return Ok(None);
    };
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
            address,
            server_name,
            path,
            detour,
        });
    }
    debug_assert!(detours.next().is_none());

    let route = raw
        .route
        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRoute))?;
    if route.rules.len() > MAX_ROUTE_RULES {
        return Err(ConfigError::semantic(ConfigField::DnsRouteRules));
    }
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
    let mut rules = Vec::with_capacity(route.rules.len());
    for rule in route.rules {
        if rule.outbound.is_some() {
            return Err(ConfigError::semantic(ConfigField::DnsRouteRulesServer));
        }
        let (inbound, network, target) = if context.schema_version == SchemaVersion::V1 {
            let inbound = scalar_string(rule.inbound.as_ref(), ConfigField::DnsRouteRulesInbound)?
                .map(|tag| {
                    validate_tag(tag, ConfigField::DnsRouteRulesInbound)?;
                    match context.role {
                        DnsRole::Client => raw_inbounds.iter().position(|item| item.tag == tag),
                        DnsRole::Server => {
                            context.context_inbounds.iter().position(|item| item == tag)
                        }
                    }
                    .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteRulesInbound))
                })
                .transpose()?;
            let network = validate_network(
                scalar_string(rule.network.as_ref(), ConfigField::DnsRouteRulesNetwork)?,
                ConfigField::DnsRouteRulesNetwork,
            )?;
            let target = rule
                .target
                .as_ref()
                .map(|target| {
                    validate_route_target(target, source, ConfigField::DnsRouteRulesTarget)
                })
                .transpose()?;
            (inbound, network, target)
        } else {
            (None, None, None)
        };
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
        if context.schema_version == SchemaVersion::V1 {
            rules.push(ActionRule::new(inbound, network, target, server));
        }
    }
    if reached.contains(&false) {
        return Err(ConfigError::semantic(ConfigField::DnsRouteRulesServer));
    }
    let route = ActionTable::new(rules, final_server)
        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteRules))?;
    Ok(Some(DnsConfig {
        inbounds,
        servers,
        route,
        timeout,
        max_inflight,
    }))
}

fn validate_network(
    value: Option<&str>,
    field: ConfigField,
) -> Result<Option<Network>, ConfigError> {
    value
        .map(|network| match network {
            "tcp" => Ok(Network::Tcp),
            "udp" => Ok(Network::Udp),
            _ => Err(ConfigError::semantic(field)),
        })
        .transpose()
}

fn scalar_string(
    value: Option<&ScalarOrList<String>>,
    field: ConfigField,
) -> Result<Option<&str>, ConfigError> {
    value
        .map(|value| {
            value
                .scalar()
                .map(String::as_str)
                .ok_or_else(|| ConfigError::semantic(field))
        })
        .transpose()
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
    let ipv4_address: Ipv4Net = raw
        .ipv4_address
        .parse()
        .map_err(|_| ConfigError::semantic(ConfigField::TunIpv4Address))?;
    let ipv4 = ipv4_address.addr();
    if ipv4.is_unspecified()
        || ipv4.is_loopback()
        || ipv4.is_multicast()
        || ipv4 == ipv4_address.network()
        || ipv4 == ipv4_address.broadcast()
    {
        return Err(ConfigError::semantic(ConfigField::TunIpv4Address));
    }
    let ipv6_address: Ipv6Net = raw
        .ipv6_address
        .parse()
        .map_err(|_| ConfigError::semantic(ConfigField::TunIpv6Address))?;
    let ipv6 = ipv6_address.addr();
    if ipv6.is_unspecified() || ipv6.is_loopback() || ipv6.is_multicast() {
        return Err(ConfigError::semantic(ConfigField::TunIpv6Address));
    }
    let capture_routes = compile_capture_routes(
        raw.auto_route,
        raw.route_address.as_deref(),
        raw.route_exclude_address.as_deref(),
    )?;
    if raw.auto_dns && !raw.auto_route {
        return Err(ConfigError::semantic(ConfigField::TunAutoDns));
    }
    if raw.ipv6_dns_address.is_some() {
        return Err(ConfigError::semantic(ConfigField::TunIpv6DnsAddress));
    }
    let ipv4_dns_address = match (raw.auto_dns, raw.ipv4_dns_address.as_deref()) {
        (false, None) => None,
        (false, Some(_)) | (true, None) => {
            return Err(ConfigError::semantic(ConfigField::TunIpv4DnsAddress));
        }
        (true, Some(address)) => {
            let address: Ipv4Addr = address
                .parse()
                .map_err(|_| ConfigError::semantic(ConfigField::TunIpv4DnsAddress))?;
            if address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || !ipv4_address.contains(&address)
                || address == ipv4
                || address == ipv4_address.network()
                || address == ipv4_address.broadcast()
            {
                return Err(ConfigError::semantic(ConfigField::TunIpv4DnsAddress));
            }
            Some(address)
        }
    };
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
    if !(65_536..=134_217_728).contains(&raw.max_udp_buffered_bytes) {
        return Err(ConfigError::semantic(ConfigField::TunMaxUdpBufferedBytes));
    }
    let owned_buffer_bytes = checked_tun_memory(
        raw.mtu,
        raw.ring_capacity,
        raw.max_tcp_flows,
        raw.tcp_buffer_bytes,
        raw.max_udp_mappings,
        raw.max_udp_buffered_bytes,
    )
    .ok_or_else(|| ConfigError::semantic(ConfigField::TunMemory))?;
    if owned_buffer_bytes > 268_435_456 {
        return Err(ConfigError::semantic(ConfigField::TunMemory));
    }

    Ok(ValidatedTun {
        tag: raw.tag,
        outbound: raw.outbound,
        config: TunConfig {
            adapter_name: raw.adapter_name.into_boxed_str(),
            ipv4_address,
            ipv6_address,
            auto_route: raw.auto_route,
            capture_routes,
            auto_dns: raw.auto_dns,
            ipv4_dns_address,
            physical_endpoints: Vec::new(),
            mtu: raw.mtu as u16,
            ring_capacity: raw.ring_capacity as u32,
            ready_timeout: Duration::from_millis(raw.ready_timeout_ms),
            max_tcp_flows: raw.max_tcp_flows as usize,
            tcp_buffer_bytes: raw.tcp_buffer_bytes as usize,
            max_udp_mappings: raw.max_udp_mappings as usize,
            max_udp_buffered_bytes: raw.max_udp_buffered_bytes as usize,
            owned_buffer_bytes,
        },
    })
}

fn compile_capture_routes(
    auto_route: bool,
    includes: Option<&[String]>,
    excludes: Option<&[String]>,
) -> Result<Vec<Ipv4Net>, ConfigError> {
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
                let network: Ipv4Net = value.parse().map_err(|_| ConfigError::semantic(field))?;
                if network.addr() != network.network() {
                    return Err(ConfigError::semantic(field));
                }
                Ok(network)
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
        vec!["0.0.0.0/0".parse().expect("fixed IPv4 prefix")]
    } else {
        parse(includes, ConfigField::TunRouteAddress)?
    };
    let excludes = excludes.unwrap_or(&[]);
    if excludes.len() > 64 {
        return Err(ConfigError::semantic(ConfigField::TunRouteExcludeAddress));
    }
    let excludes = Ipv4Net::aggregate(&parse(excludes, ConfigField::TunRouteExcludeAddress)?);
    includes = Ipv4Net::aggregate(&includes);

    fn subtract(route: Ipv4Net, exclude: Ipv4Net, output: &mut Vec<Ipv4Net>) {
        if !route.contains(&exclude.network()) && !exclude.contains(&route.network()) {
            output.push(route);
        } else if !exclude.contains(&route.broadcast()) {
            for child in route
                .subnets(route.prefix_len() + 1)
                .expect("an intersecting non-contained IPv4 prefix can split")
            {
                subtract(child, exclude, output);
            }
        }
    }

    for exclude in excludes {
        let mut next = Vec::new();
        for route in includes {
            subtract(route, exclude, &mut next);
        }
        includes = next;
    }
    includes = Ipv4Net::aggregate(&includes);
    if includes.len() == 1 && includes[0].prefix_len() == 0 {
        includes = includes[0]
            .subnets(1)
            .expect("IPv4 default route has /1 children")
            .collect();
    }
    if !(1..=256).contains(&includes.len()) {
        return Err(ConfigError::semantic(ConfigField::TunRouteAddress));
    }
    Ok(includes)
}

fn checked_tun_memory(
    mtu: u64,
    ring_capacity: u64,
    max_tcp_flows: u64,
    tcp_buffer_bytes: u64,
    max_udp_mappings: u64,
    max_udp_buffered_bytes: u64,
) -> Option<u64> {
    [
        ring_capacity.checked_mul(2),
        max_tcp_flows
            .checked_mul(tcp_buffer_bytes)
            .and_then(|value| value.checked_mul(2)),
        Some(max_udp_buffered_bytes),
        max_tcp_flows.checked_mul(mtu.checked_add(1_024)?),
        max_udp_mappings.checked_mul(mtu.checked_add(512)?),
        mtu.checked_mul(8),
        Some(1_048_576),
    ]
    .into_iter()
    .try_fold(0_u64, |total, term| total.checked_add(term?))
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
            match server {
                SocketAddr::V4(server) => tun.physical_endpoints.push(*server),
                SocketAddr::V6(_) => {
                    return Err(ConfigError::semantic(ConfigField::OutboundsServer));
                }
            }
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
                match server.address {
                    SocketAddr::V4(server) => tun.physical_endpoints.push(server),
                    SocketAddr::V6(_) => {
                        return Err(ConfigError::semantic(ConfigField::DnsServersAddress));
                    }
                }
            }
        }
    }
    tun.physical_endpoints.sort_unstable();
    tun.physical_endpoints.dedup();
    if tun
        .physical_endpoints
        .iter()
        .any(|endpoint| tun.ipv4_address.contains(endpoint.ip()))
    {
        return Err(ConfigError::semantic(ConfigField::TunIpv4Address));
    }
    Ok(())
}

pub(super) fn validate_client(
    mut raw: RawClientRoot,
    source: &str,
) -> Result<ValidatedClientConfig, ConfigError> {
    let schema_version = v2::validate_version(raw.schema_version)?;
    if raw.tun.is_some() && schema_version != SchemaVersion::V2 {
        return Err(ConfigError::semantic(ConfigField::Tun));
    }
    if raw.tun.is_some() && raw.client.is_some() {
        return Err(ConfigError::semantic(ConfigField::Tun));
    }
    if schema_version == SchemaVersion::V1
        && raw.route.is_some()
        && raw.udp.as_ref().is_some_and(|udp| udp.enabled)
    {
        return Err(ConfigError::semantic(ConfigField::SchemaVersion));
    }
    if schema_version == SchemaVersion::V1 {
        v2::reject_v1_fields(raw.route.as_ref(), raw.dns.as_ref())?;
    }
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
    let outbound_credentials = validate_client_credentials(
        schema_version,
        raw.client.is_some(),
        raw.outbounds.as_deref(),
        raw.shadowsocks.as_ref(),
    )?;
    let route_draft = if schema_version == SchemaVersion::V2 {
        v2::compile_route_draft(
            raw.route.as_ref(),
            &context_inbounds,
            v2::Role::Client,
            tun.as_ref().map(|_| socks_inbound_count),
            raw.dns.is_some(),
            raw.runtime.max_connections,
            source,
        )?
    } else {
        None
    };
    let route_roots = route_draft
        .as_ref()
        .map(v2::RouteDraft::root_tags)
        .unwrap_or_default();
    let detour_tags = raw.dns.as_ref().map(dns_detour_tags).unwrap_or_default();
    let graph_route = if schema_version == SchemaVersion::V2 {
        raw.route.as_ref().map(v2_graph_route)
    } else {
        raw.route.clone()
    };
    let (listen, inbounds, outbounds, route, mut roots, physical_first_hops, direct_detours) =
        validate_client_graph(
            raw.client,
            raw.inbounds,
            raw.outbounds,
            outbound_credentials,
            raw.chains,
            raw.selectors,
            graph_route,
            GraphValidation {
                route_roots: &route_roots,
                detour_tags: &detour_tags,
                source,
                retained_client_inbounds: socks_inbound_count,
            },
        )?;
    let detours = roots.split_off(route_roots.len());
    let route_program = route_draft.map(|draft| draft.finish(roots)).transpose()?;
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
            schema_version,
            global_tags: &global_tags,
            context_inbounds: &[],
            ordinary_listens: &ordinary_listens,
            outbound_servers: &outbound_servers,
        },
        detours,
        source,
    )?;
    if let Some(tun) = &mut tun {
        if tun.config.auto_dns && dns.is_none() {
            return Err(ConfigError::semantic(ConfigField::TunAutoDns));
        }
        validate_tun_targets(
            &mut tun.config,
            &outbounds,
            &physical_first_hops,
            &direct_detours,
            dns.as_ref(),
        )?;
    }
    let dns_route = if schema_version == SchemaVersion::V2 {
        dns_route_raw
            .as_ref()
            .map(|dns| v2::compile_client_dns(dns, &context_inbounds, source))
            .transpose()?
    } else {
        None
    };
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
    Ok(ValidatedClientConfig {
        schema_version,
        listen,
        inbounds,
        outbounds,
        route,
        route_program,
        tun: tun.map(|tun| tun.config),
        dns,
        dns_route,
        runtime,
        udp,
        logging,
        metrics,
    })
}

pub(super) fn validate_server(
    raw: RawServerRoot,
    source: &str,
) -> Result<ValidatedServerConfig, ConfigError> {
    if raw.tun.is_some() {
        return Err(ConfigError::semantic(ConfigField::Tun));
    }
    let schema_version = v2::validate_version(raw.schema_version)?;
    if schema_version == SchemaVersion::V1 {
        v2::reject_v1_fields(raw.route.as_ref(), raw.dns.as_ref())?;
    }
    let global_tags = server_global_tags(&raw);
    let context_inbounds = raw
        .inbounds
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|inbound| inbound.tag.clone())
        .collect::<Vec<_>>();
    if raw.chains.is_some() {
        return Err(ConfigError::semantic(ConfigField::Chains));
    }
    let route_draft = if schema_version == SchemaVersion::V2 {
        v2::compile_route_draft(
            raw.route.as_ref(),
            &context_inbounds,
            v2::Role::Server,
            None,
            raw.dns.is_some(),
            raw.runtime.max_connections,
            source,
        )?
    } else {
        None
    };
    let route_roots = route_draft
        .as_ref()
        .map(v2::RouteDraft::root_tags)
        .unwrap_or_default();
    let detour_tags = raw.dns.as_ref().map(dns_detour_tags).unwrap_or_default();
    let graph_route = if schema_version == SchemaVersion::V2 {
        raw.route.as_ref().map(v2_graph_route)
    } else {
        raw.route.clone()
    };
    let (listen, inbounds, outbounds, route, mut roots) = validate_server_graph(
        raw.server,
        raw.inbounds,
        raw.outbounds,
        raw.selectors,
        graph_route,
        GraphValidation {
            route_roots: &route_roots,
            detour_tags: &detour_tags,
            source,
            retained_client_inbounds: 0,
        },
    )?;
    let detours = roots.split_off(route_roots.len());
    let route_program = route_draft.map(|draft| draft.finish(roots)).transpose()?;
    let dns_route_raw = raw.dns.clone();
    let dns = validate_dns(
        raw.dns,
        DnsValidationContext {
            role: DnsRole::Server,
            schema_version,
            global_tags: &global_tags,
            context_inbounds: &context_inbounds,
            ordinary_listens: &[],
            outbound_servers: &[],
        },
        detours,
        source,
    )?;
    let dns_route = if schema_version == SchemaVersion::V2 {
        dns_route_raw
            .as_ref()
            .map(|dns| v2::compile_server_dns(dns, &context_inbounds, source))
            .transpose()?
    } else {
        None
    };
    let method = parse_method(&raw.shadowsocks.method, ConfigField::ShadowsocksMethod)?;
    let psk = parse_psk(method, &raw.shadowsocks.psk, ConfigField::ShadowsocksPsk)?;
    let runtime = validate_runtime(raw.runtime)?;
    let replay = validate_replay(raw.replay)?;
    let udp = validate_udp(raw.udp)?;
    let logging = validate_logging(raw.logging)?;
    let listens: Vec<_> = inbounds.iter().map(|inbound| inbound.listen).collect();
    let metrics = validate_metrics(raw.metrics, &listens)?;
    Ok(ValidatedServerConfig {
        schema_version,
        listen,
        inbounds,
        outbounds,
        route,
        route_program,
        dns,
        dns_route,
        psk,
        runtime,
        replay,
        udp,
        logging,
        metrics,
    })
}

fn v2_graph_route(route: &RawRoute) -> RawRoute {
    RawRoute {
        final_outbound: route.final_outbound.clone(),
        sniff: None,
        rules: Vec::new(),
    }
}

type ValidatedClientGraph = (
    SocketAddrV4,
    Vec<ClientInboundConfig>,
    Vec<ClientOutboundConfig>,
    RouteTable,
    Vec<EgressPlanHandle>,
    Vec<usize>,
    Vec<bool>,
);

fn validate_client_graph(
    legacy: Option<RawClient>,
    tagged_inbounds: Option<Vec<RawClientInbound>>,
    tagged_outbounds: Option<Vec<RawClientOutbound>>,
    outbound_credentials: Vec<Option<MethodPsk>>,
    chains: Option<Vec<RawChain>>,
    selectors: Option<Vec<RawSelector>>,
    route: Option<RawRoute>,
    validation: GraphValidation<'_>,
) -> Result<ValidatedClientGraph, ConfigError> {
    let GraphValidation {
        route_roots,
        detour_tags,
        source,
        retained_client_inbounds: socks_inbound_count,
    } = validation;
    if chains.is_some()
        && (legacy.is_some() || tagged_inbounds.is_none() || tagged_outbounds.is_none())
    {
        return Err(ConfigError::semantic(ConfigField::Chains));
    }
    if selectors.is_some()
        && (legacy.is_some() || tagged_inbounds.is_none() || tagged_outbounds.is_none())
    {
        return Err(ConfigError::semantic(ConfigField::Selectors));
    }
    if route.is_some()
        && (legacy.is_some() || tagged_inbounds.is_none() || tagged_outbounds.is_none())
    {
        return Err(ConfigError::semantic(ConfigField::Route));
    }
    match (legacy, tagged_inbounds, tagged_outbounds) {
        (Some(legacy), None, None) => {
            let listen = parse_endpoint(&legacy.listen, ConfigField::ClientListen)?;
            let server = parse_endpoint(&legacy.server, ConfigField::ClientServer)?;
            if listen == server {
                return Err(ConfigError::semantic(ConfigField::ClientServer));
            }
            Ok((
                listen,
                vec![ClientInboundConfig { listen }],
                vec![ClientOutboundConfig::Shadowsocks {
                    server: SocketAddr::V4(server),
                    psk: outbound_credentials
                        .into_iter()
                        .next()
                        .flatten()
                        .expect("legacy credential was validated"),
                }],
                RouteTable::static_bindings(vec![0])
                    .ok_or_else(|| ConfigError::semantic(ConfigField::Inbounds))?,
                if route_roots.is_empty() && detour_tags.is_empty() {
                    Vec::new()
                } else if !route_roots.is_empty() {
                    return Err(ConfigError::semantic(ConfigField::RouteFinal));
                } else {
                    return Err(ConfigError::semantic(ConfigField::DnsServersDetour));
                },
                vec![0],
                Vec::new(),
            ))
        }
        (None, Some(inbounds), Some(outbounds)) => {
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
            for (index, (outbound, psk)) in outbounds.iter().zip(outbound_credentials).enumerate() {
                validate_tag(&outbound.tag, ConfigField::OutboundsTag)?;
                if inbounds.iter().any(|inbound| inbound.tag == outbound.tag)
                    || outbounds[..index]
                        .iter()
                        .any(|other| other.tag == outbound.tag)
                {
                    return Err(ConfigError::semantic(ConfigField::OutboundsTag));
                }
                match psk {
                    Some(psk) => {
                        let server = parse_socket(
                            outbound.server.as_deref().ok_or_else(|| {
                                ConfigError::semantic(ConfigField::OutboundsServer)
                            })?,
                            ConfigField::OutboundsServer,
                        )?;
                        if listens
                            .iter()
                            .any(|listen| SocketAddr::V4(*listen) == server)
                        {
                            return Err(ConfigError::semantic(ConfigField::OutboundsServer));
                        }
                        validated_outbounds.push(ClientOutboundConfig::Shadowsocks { server, psk });
                    }
                    None => validated_outbounds.push(ClientOutboundConfig::Direct),
                }
            }

            let plans = validate_chains(
                chains.as_deref(),
                &inbounds,
                &outbounds,
                selectors.as_deref(),
            )?;
            for (index, tag) in route_roots.iter().copied().enumerate() {
                if !outbounds.iter().any(|outbound| outbound.tag == tag)
                    && !chains.as_deref().is_some_and(|chains| {
                        chains.iter().any(|chain| chain.tag.as_deref() == Some(tag))
                    })
                    && !selectors.as_deref().is_some_and(|selectors| {
                        selectors.iter().any(|selector| selector.tag == tag)
                    })
                {
                    return Err(ConfigError::semantic(if index == 0 {
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
                    && !selectors.as_deref().is_some_and(|selectors| {
                        selectors.iter().any(|selector| selector.tag == **tag)
                    })
            }) {
                return Err(ConfigError::semantic(ConfigField::DnsServersDetour));
            }
            let graph_roots = route_roots
                .iter()
                .copied()
                .chain(detour_tags.iter().copied())
                .collect::<Vec<_>>();
            let extra_roots = graph_roots.as_slice();
            let ordinary_roots: Vec<String> = if !route_roots.is_empty() {
                route_roots.iter().map(|tag| (*tag).to_owned()).collect()
            } else if let Some(route) = route.as_ref() {
                route
                    .final_outbound
                    .iter()
                    .chain(route.rules.iter().filter_map(|rule| rule.outbound.as_ref()))
                    .cloned()
                    .collect()
            } else {
                inbounds
                    .iter()
                    .filter_map(|inbound| inbound.outbound.clone())
                    .collect()
            };
            let (route, detours) = validate_route(
                route,
                inbounds
                    .iter()
                    .map(|inbound| (inbound.tag.as_str(), inbound.outbound.as_deref()))
                    .collect(),
                outbounds
                    .iter()
                    .map(|outbound| outbound.tag.as_str())
                    .collect(),
                selectors.as_deref(),
                &plans,
                extra_roots,
                source,
            )?;
            let validated_inbounds = listens
                .into_iter()
                .take(socks_inbound_count)
                .map(|listen| ClientInboundConfig { listen })
                .collect::<Vec<_>>();
            let compatibility_listen = validated_inbounds.first().map_or(
                SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0),
                |inbound| inbound.listen,
            );
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
                                    Some(&outbound.tag)
                                        == chain.hops.as_ref().and_then(|hops| hops.first())
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
                        matches!(validated_outbounds[*index], ClientOutboundConfig::Direct)
                    })
                })
                .collect();
            let mut physical_first_hops = ordinary_roots
                .iter()
                .map(String::as_str)
                .chain(detour_tags.iter().map(|tag| *tag))
                .flat_map(|tag| first_hops(tag))
                .collect::<Vec<_>>();
            physical_first_hops.sort_unstable();
            physical_first_hops.dedup();
            Ok((
                compatibility_listen,
                validated_inbounds,
                validated_outbounds,
                route,
                detours,
                physical_first_hops,
                direct_detours,
            ))
        }
        (None, None, None) => Err(ConfigError::new(
            ConfigErrorKind::Syntax,
            ConfigField::Config,
        )),
        (Some(_), Some(_), _) | (None, None, Some(_)) => {
            Err(ConfigError::semantic(ConfigField::Inbounds))
        }
        (Some(_), None, Some(_)) | (None, Some(_), None) => {
            Err(ConfigError::semantic(ConfigField::Outbounds))
        }
    }
}

fn validate_client_credentials(
    schema_version: SchemaVersion,
    legacy: bool,
    outbounds: Option<&[RawClientOutbound]>,
    global: Option<&RawShadowsocks>,
) -> Result<Vec<Option<MethodPsk>>, ConfigError> {
    if let Some(global) = global {
        let method = parse_method(&global.method, ConfigField::ShadowsocksMethod)?;
        let _ = parse_psk(method, &global.psk, ConfigField::ShadowsocksPsk)?;
    }
    if legacy {
        let global =
            global.ok_or_else(|| ConfigError::new(ConfigErrorKind::Syntax, ConfigField::Config))?;
        let method = parse_method(&global.method, ConfigField::ShadowsocksMethod)?;
        return Ok(vec![Some(parse_psk(
            method,
            &global.psk,
            ConfigField::ShadowsocksPsk,
        )?)]);
    }

    outbounds
        .unwrap_or(&[])
        .iter()
        .map(|outbound| {
            if schema_version == SchemaVersion::V1 && outbound.outbound_type.is_some() {
                return Err(ConfigError::semantic(ConfigField::OutboundsType));
            }
            match outbound.outbound_type.as_deref().unwrap_or("shadowsocks") {
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
                    Ok(None)
                }
                "shadowsocks" => {
                    let global = global.ok_or_else(|| {
                        ConfigError::new(ConfigErrorKind::Syntax, ConfigField::Config)
                    })?;
                    let psk = match (&outbound.method, &outbound.psk) {
                        (None, None) => {
                            let method =
                                parse_method(&global.method, ConfigField::ShadowsocksMethod)?;
                            parse_psk(method, &global.psk, ConfigField::ShadowsocksPsk)?
                        }
                        (Some(_), None) => {
                            return Err(ConfigError::semantic(ConfigField::OutboundsPsk));
                        }
                        (None, Some(_)) => {
                            return Err(ConfigError::semantic(ConfigField::OutboundsMethod));
                        }
                        (Some(method), Some(psk)) => {
                            let method = parse_method(method, ConfigField::OutboundsMethod)?;
                            parse_psk(method, psk, ConfigField::OutboundsPsk)?
                        }
                    };
                    Ok(Some(psk))
                }
                _ => Err(ConfigError::semantic(ConfigField::OutboundsType)),
            }
        })
        .collect()
}

fn validate_chains<'a>(
    chains: Option<&'a [RawChain]>,
    inbounds: &[RawClientInbound],
    outbounds: &[RawClientOutbound],
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
            if outbounds[outbound].outbound_type.as_deref() == Some("direct") {
                return Err(ConfigError::semantic(ConfigField::ChainsHops));
            }
            hops.push(outbound);
        }
        plans.push(TaggedPlan::new(tag, hops));
    }
    Ok(plans)
}

type ValidatedServerGraph = (
    SocketAddrV4,
    Vec<ServerInboundConfig>,
    Vec<ServerOutboundConfig>,
    RouteTable,
    Vec<EgressPlanHandle>,
);

fn validate_server_graph(
    legacy: Option<RawServer>,
    tagged_inbounds: Option<Vec<RawServerInbound>>,
    tagged_outbounds: Option<Vec<RawServerOutbound>>,
    selectors: Option<Vec<RawSelector>>,
    route: Option<RawRoute>,
    validation: GraphValidation<'_>,
) -> Result<ValidatedServerGraph, ConfigError> {
    let GraphValidation {
        route_roots,
        detour_tags,
        source,
        retained_client_inbounds: _,
    } = validation;
    if selectors.is_some()
        && (legacy.is_some() || tagged_inbounds.is_none() || tagged_outbounds.is_none())
    {
        return Err(ConfigError::semantic(ConfigField::Selectors));
    }
    if route.is_some()
        && (legacy.is_some() || tagged_inbounds.is_none() || tagged_outbounds.is_none())
    {
        return Err(ConfigError::semantic(ConfigField::Route));
    }
    match (legacy, tagged_inbounds, tagged_outbounds) {
        (Some(legacy), None, None) => {
            let listen = parse_endpoint(&legacy.listen, ConfigField::ServerListen)?;
            Ok((
                listen,
                vec![ServerInboundConfig { listen }],
                vec![ServerOutboundConfig],
                RouteTable::static_bindings(vec![0])
                    .ok_or_else(|| ConfigError::semantic(ConfigField::Inbounds))?,
                if route_roots.is_empty() && detour_tags.is_empty() {
                    Vec::new()
                } else if !route_roots.is_empty() {
                    return Err(ConfigError::semantic(ConfigField::RouteFinal));
                } else {
                    return Err(ConfigError::semantic(ConfigField::DnsServersDetour));
                },
            ))
        }
        (None, Some(inbounds), Some(outbounds)) => {
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
                    && !selectors.as_deref().is_some_and(|selectors| {
                        selectors.iter().any(|selector| selector.tag == tag)
                    })
                {
                    return Err(ConfigError::semantic(if index == 0 {
                        ConfigField::RouteFinal
                    } else {
                        ConfigField::RouteRulesOutbound
                    }));
                }
            }
            if detour_tags
                .iter()
                .any(|tag| !outbounds.iter().any(|outbound| outbound.tag == **tag))
            {
                return Err(ConfigError::semantic(ConfigField::DnsServersDetour));
            }
            let graph_roots = route_roots
                .iter()
                .copied()
                .chain(detour_tags.iter().copied())
                .collect::<Vec<_>>();
            let detour_tags = graph_roots.as_slice();
            let (route, detours) = validate_route(
                route,
                inbounds
                    .iter()
                    .map(|inbound| (inbound.tag.as_str(), inbound.outbound.as_deref()))
                    .collect(),
                outbounds
                    .iter()
                    .map(|outbound| outbound.tag.as_str())
                    .collect(),
                selectors.as_deref(),
                &[],
                detour_tags,
                source,
            )?;
            let validated_inbounds = listens
                .into_iter()
                .map(|listen| ServerInboundConfig { listen })
                .collect::<Vec<_>>();
            Ok((
                validated_inbounds[0].listen,
                validated_inbounds,
                vec![ServerOutboundConfig; outbounds.len()],
                route,
                detours,
            ))
        }
        (None, None, None) => Err(ConfigError::new(
            ConfigErrorKind::Syntax,
            ConfigField::Config,
        )),
        (Some(_), Some(_), _) | (None, None, Some(_)) => {
            Err(ConfigError::semantic(ConfigField::Inbounds))
        }
        (Some(_), None, Some(_)) | (None, Some(_), None) => {
            Err(ConfigError::semantic(ConfigField::Outbounds))
        }
    }
}

fn validate_route(
    route: Option<RawRoute>,
    inbounds: Vec<(&str, Option<&str>)>,
    outbounds: Vec<&str>,
    selectors: Option<&[RawSelector]>,
    plans: &[TaggedPlan<'_>],
    extra_roots: &[&str],
    source: &str,
) -> Result<(RouteTable, Vec<EgressPlanHandle>), ConfigError> {
    if selectors.is_some_and(<[RawSelector]>::is_empty) {
        return Err(ConfigError::semantic(ConfigField::Selectors));
    }
    if selectors.is_some() || !plans.is_empty() {
        return validate_selector_route(
            route,
            &inbounds,
            &outbounds,
            selectors.unwrap_or(&[]),
            plans,
            extra_roots,
            source,
        );
    }
    let Some(route) = route else {
        let mut referenced = vec![false; outbounds.len()];
        let mut bindings = Vec::with_capacity(inbounds.len());
        for (_, outbound) in inbounds {
            let outbound =
                outbound.ok_or_else(|| ConfigError::semantic(ConfigField::InboundsOutbound))?;
            validate_tag(outbound, ConfigField::InboundsOutbound)?;
            let index = outbounds
                .iter()
                .position(|tag| *tag == outbound)
                .ok_or_else(|| ConfigError::semantic(ConfigField::InboundsOutbound))?;
            referenced[index] = true;
            bindings.push(index);
        }
        if referenced.contains(&false) {
            for tag in extra_roots {
                let index = outbounds
                    .iter()
                    .position(|outbound| outbound == tag)
                    .ok_or_else(|| ConfigError::semantic(ConfigField::DnsServersDetour))?;
                referenced[index] = true;
            }
        }
        if referenced.contains(&false) {
            return Err(ConfigError::semantic(ConfigField::OutboundsTag));
        }
        let route = RouteTable::static_bindings(bindings)
            .ok_or_else(|| ConfigError::semantic(ConfigField::Inbounds))?;
        let detours = extra_roots
            .iter()
            .map(|tag| {
                let outbound = outbounds
                    .iter()
                    .position(|candidate| candidate == tag)
                    .expect("validated direct detour");
                EgressPlanHandle::direct(outbound)
            })
            .collect();
        return Ok((route, detours));
    };

    if inbounds.iter().any(|(_, outbound)| outbound.is_some()) {
        return Err(ConfigError::semantic(ConfigField::Route));
    }
    if route.rules.len() > MAX_ROUTE_RULES {
        return Err(ConfigError::semantic(ConfigField::RouteRules));
    }

    let final_tag = route
        .final_outbound
        .as_deref()
        .ok_or_else(|| ConfigError::semantic(ConfigField::RouteFinal))?;
    validate_tag(final_tag, ConfigField::RouteFinal)?;
    let final_outbound = outbounds
        .iter()
        .position(|tag| *tag == final_tag)
        .ok_or_else(|| ConfigError::semantic(ConfigField::RouteFinal))?;
    let mut referenced = vec![false; outbounds.len()];
    referenced[final_outbound] = true;
    let mut rules = Vec::with_capacity(route.rules.len());
    for rule in route.rules {
        if rule.server.is_some() {
            return Err(ConfigError::semantic(ConfigField::RouteRulesOutbound));
        }
        if rule.inbound.is_none() && rule.network.is_none() && rule.target.is_none() {
            return Err(ConfigError::semantic(ConfigField::RouteRules));
        }
        let inbound = scalar_string(rule.inbound.as_ref(), ConfigField::RouteRulesInbound)?
            .map(|tag| {
                validate_tag(tag, ConfigField::RouteRulesInbound)?;
                inbounds
                    .iter()
                    .position(|(inbound, _)| *inbound == tag)
                    .ok_or_else(|| ConfigError::semantic(ConfigField::RouteRulesInbound))
            })
            .transpose()?;
        let network = validate_network(
            scalar_string(rule.network.as_ref(), ConfigField::RouteRulesNetwork)?,
            ConfigField::RouteRulesNetwork,
        )?;
        let target = rule
            .target
            .as_ref()
            .map(|target| validate_route_target(target, source, ConfigField::RouteRulesTarget))
            .transpose()?;
        let outbound_tag = rule
            .outbound
            .as_deref()
            .ok_or_else(|| ConfigError::semantic(ConfigField::RouteRulesOutbound))?;
        validate_tag(outbound_tag, ConfigField::RouteRulesOutbound)?;
        let outbound = outbounds
            .iter()
            .position(|tag| *tag == outbound_tag)
            .ok_or_else(|| ConfigError::semantic(ConfigField::RouteRulesOutbound))?;
        referenced[outbound] = true;
        rules.push(RouteRule::new(inbound, network, target, outbound));
    }
    if referenced.contains(&false) {
        for tag in extra_roots {
            let index = outbounds
                .iter()
                .position(|outbound| outbound == tag)
                .ok_or_else(|| ConfigError::semantic(ConfigField::DnsServersDetour))?;
            referenced[index] = true;
        }
    }
    if referenced.contains(&false) {
        return Err(ConfigError::semantic(ConfigField::RouteRulesOutbound));
    }
    let route = RouteTable::routed(rules, final_outbound)
        .ok_or_else(|| ConfigError::semantic(ConfigField::RouteRules))?;
    let detours = extra_roots
        .iter()
        .map(|tag| {
            let outbound = outbounds
                .iter()
                .position(|candidate| candidate == tag)
                .expect("validated direct detour");
            EgressPlanHandle::direct(outbound)
        })
        .collect();
    Ok((route, detours))
}

fn validate_selector_route(
    route: Option<RawRoute>,
    inbounds: &[(&str, Option<&str>)],
    outbounds: &[&str],
    selectors: &[RawSelector],
    plans: &[TaggedPlan<'_>],
    extra_roots: &[&str],
    source: &str,
) -> Result<(RouteTable, Vec<EgressPlanHandle>), ConfigError> {
    let tagged_inbounds = inbounds
        .iter()
        .enumerate()
        .map(|(index, (tag, _))| TaggedInbound::new(tag, index))
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

    let (tagged_route, routed) = match route.as_ref() {
        None => {
            let bindings = inbounds
                .iter()
                .map(|(inbound, outbound)| {
                    outbound
                        .map(|outbound| TaggedStaticBinding::new(inbound, outbound))
                        .ok_or_else(|| ConfigError::semantic(ConfigField::InboundsOutbound))
                })
                .collect::<Result<Vec<_>, _>>()?;
            (TaggedRoute::Static(bindings), false)
        }
        Some(route) => {
            if inbounds.iter().any(|(_, outbound)| outbound.is_some()) {
                return Err(ConfigError::semantic(ConfigField::Route));
            }
            if route.rules.len() > MAX_ROUTE_RULES {
                return Err(ConfigError::semantic(ConfigField::RouteRules));
            }
            let mut rules = Vec::with_capacity(route.rules.len());
            for rule in &route.rules {
                if rule.server.is_some() {
                    return Err(ConfigError::semantic(ConfigField::RouteRulesOutbound));
                }
                let network = validate_network(
                    scalar_string(rule.network.as_ref(), ConfigField::RouteRulesNetwork)?,
                    ConfigField::RouteRulesNetwork,
                )?;
                let target = rule
                    .target
                    .as_ref()
                    .map(|target| {
                        validate_route_target(target, source, ConfigField::RouteRulesTarget)
                    })
                    .transpose()?;
                rules.push(TaggedRouteRule::new(
                    scalar_string(rule.inbound.as_ref(), ConfigField::RouteRulesInbound)?,
                    network,
                    target,
                    rule.outbound.as_deref(),
                ));
            }
            (
                TaggedRoute::Routed {
                    rules,
                    final_outbound: route.final_outbound.as_deref(),
                },
                true,
            )
        }
    };

    compile_selector_plans_with_roots(
        &tagged_inbounds,
        &tagged_outbounds,
        plans,
        &definitions,
        tagged_route,
        extra_roots,
    )
    .map(|(route, _, roots)| (route, roots))
    .map_err(|error| {
        if matches!(error, SelectorCompileError::ExtraRoot) {
            ConfigError::semantic(ConfigField::DnsServersDetour)
        } else {
            ConfigError::semantic(selector_error_field(error, routed))
        }
    })
}

const fn selector_error_field(error: SelectorCompileError, routed: bool) -> ConfigField {
    match error {
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

fn validate_route_target(
    raw: &toml::Spanned<RawRouteTarget>,
    source: &str,
    field: ConfigField,
) -> Result<TargetAddr, ConfigError> {
    if !source
        .get(raw.span())
        .is_some_and(|value| value.trim_start().starts_with('{'))
    {
        return Err(ConfigError::semantic(field));
    }
    let raw = raw.get_ref();
    let host = raw
        .host
        .as_deref()
        .ok_or_else(|| ConfigError::semantic(field))?;
    let port = raw
        .port
        .and_then(|port| u16::try_from(port).ok())
        .ok_or_else(|| ConfigError::semantic(field))?;
    match host.parse::<IpAddr>() {
        Ok(ip) => TargetAddr::ip(SocketAddr::new(ip, port)),
        Err(_) => TargetAddr::domain(host, port),
    }
    .map_err(|_| ConfigError::semantic(field))
}

fn validate_count(count: usize, field: ConfigField) -> Result<(), ConfigError> {
    if (1..=64).contains(&count) {
        Ok(())
    } else {
        Err(ConfigError::semantic(field))
    }
}

fn validate_tag(tag: &str, field: ConfigField) -> Result<(), ConfigError> {
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

fn parse_method(value: &str, field: ConfigField) -> Result<TcpMethodProfile, ConfigError> {
    match value {
        "2022-blake3-aes-128-gcm" => Ok(TcpMethodProfile::Blake3Aes128Gcm2022),
        "2022-blake3-aes-256-gcm" => Ok(TcpMethodProfile::Blake3Aes256Gcm2022),
        "2022-blake3-chacha20-poly1305" => Ok(TcpMethodProfile::Blake3ChaCha20Poly13052022),
        _ => Err(ConfigError::semantic(field)),
    }
}

fn parse_psk(
    method: TcpMethodProfile,
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

#[cfg(test)]
mod tests {
    use super::checked_tun_memory;

    #[test]
    fn tun_memory_formula_is_exact_and_every_overflow_fails_closed() {
        assert_eq!(
            checked_tun_memory(1420, 8_388_608, 256, 32_768, 1024, 16_777_216),
            Some(53_995_616)
        );
        for (name, values) in [
            ("MTU staging", [u64::MAX, 1, 1, 1, 1, 1]),
            ("ring product", [1, u64::MAX, 1, 1, 1, 1]),
            ("flow count product", [1, 1, u64::MAX, 2, 1, 1]),
            ("flow buffer product", [1, 1, 2, u64::MAX, 1, 1]),
            ("mapping product", [1, 1, 1, 1, u64::MAX, 1]),
            ("sum", [1, 1, 1, 1, 1, u64::MAX]),
        ] {
            assert_eq!(
                checked_tun_memory(
                    values[0], values[1], values[2], values[3], values[4], values[5]
                ),
                None,
                "{name}"
            );
        }
    }
}
