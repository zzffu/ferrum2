use std::net::{SocketAddr, SocketAddrV4};
use std::num::NonZeroU16;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ferrum2_core::TargetAddr;
use ferrum2_crypto::{MethodProfile, MethodPsk};
use ferrum2_rule::EgressPlanHandle;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{ConfigError, ConfigField};
use crate::model::{
    DirectDomainResolver, DnsCacheConfig, DnsConfig, DnsEndpointMode, DnsInboundConfig,
    DnsRuntimeConfig, DnsServerConfig, DnsStrategy, DnsTransport, LoggingConfig, LoggingLevel,
    MetricsConfig, ReplayConfig, RuntimeConfig, UdpConfig,
};
use crate::raw::{RawDns, RawLogging, RawMetrics, RawReplay, RawRuntime, RawUdp, SecretString};

pub(super) fn dns_detour_tags(raw: &RawDns) -> Vec<&str> {
    raw.servers
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .filter_map(|server| server.detour.as_deref())
        .collect()
}

#[derive(Clone, Copy)]
pub(super) enum DnsRole {
    Client,
    Server,
}

pub(super) struct DnsValidationContext<'a> {
    pub(super) role: DnsRole,
    pub(super) global_tags: &'a [String],
    pub(super) ordinary_listens: &'a [SocketAddr],
    pub(super) outbound_servers: &'a [SocketAddr],
    pub(super) dependency_servers: &'a [usize],
}

pub(super) struct GraphValidation<'a> {
    pub(super) route_roots: &'a [&'a str],
    pub(super) detour_tags: &'a [&'a str],
    pub(super) retained_client_inbounds: usize,
    pub(super) explicit_route: bool,
}

pub(super) fn validate_dns(
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

pub(super) fn validate_dns_runtime(raw: &RawDns) -> Result<DnsRuntimeConfig, ConfigError> {
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

pub(crate) fn validate_direct_domain_resolver(
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

pub(super) fn parse_socket(value: &str, field: ConfigField) -> Result<SocketAddr, ConfigError> {
    let address: SocketAddr = value.parse().map_err(|_| ConfigError::semantic(field))?;
    if address.port() == 0 {
        Err(ConfigError::semantic(field))
    } else {
        Ok(address)
    }
}

pub(super) fn sockets_alias(left: SocketAddr, right: SocketAddr) -> bool {
    left.port() == right.port()
        && left.is_ipv4() == right.is_ipv4()
        && (left.ip() == right.ip() || left.ip().is_unspecified() || right.ip().is_unspecified())
}

pub(super) fn valid_tls_name(name: &str) -> bool {
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

pub(super) fn valid_doh_path(path: &str) -> bool {
    (1..=1_024).contains(&path.len())
        && path.is_ascii()
        && path.starts_with('/')
        && !path.starts_with("//")
        && path
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'?' | b'#'))
}

pub(super) fn validate_count(count: usize, field: ConfigField) -> Result<(), ConfigError> {
    if (1..=64).contains(&count) {
        Ok(())
    } else {
        Err(ConfigError::semantic(field))
    }
}

pub(crate) fn validate_tag(tag: &str, field: ConfigField) -> Result<(), ConfigError> {
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

pub(super) fn parse_endpoint(value: &str, field: ConfigField) -> Result<SocketAddrV4, ConfigError> {
    let endpoint: SocketAddrV4 = value.parse().map_err(|_| ConfigError::semantic(field))?;
    if endpoint.port() == 0 {
        return Err(ConfigError::semantic(field));
    }
    Ok(endpoint)
}

pub(super) fn parse_method(value: &str, field: ConfigField) -> Result<MethodProfile, ConfigError> {
    match value {
        "2022-blake3-aes-128-gcm" => Ok(MethodProfile::Blake3Aes128Gcm2022),
        "2022-blake3-aes-256-gcm" => Ok(MethodProfile::Blake3Aes256Gcm2022),
        "2022-blake3-chacha20-poly1305" => Ok(MethodProfile::Blake3ChaCha20Poly13052022),
        _ => Err(ConfigError::semantic(field)),
    }
}

pub(super) fn parse_psk(
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

pub(super) fn validate_runtime(raw: RawRuntime) -> Result<RuntimeConfig, ConfigError> {
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

pub(super) fn bounded_nonzero_u16(
    value: u32,
    field: ConfigField,
) -> Result<NonZeroU16, ConfigError> {
    let value = u16::try_from(value).map_err(|_| ConfigError::semantic(field))?;
    NonZeroU16::new(value).ok_or_else(|| ConfigError::semantic(field))
}

pub(super) fn bounded_duration(
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

pub(super) fn validate_replay(raw: RawReplay) -> Result<ReplayConfig, ConfigError> {
    if (1_024..=1_048_576).contains(&raw.capacity) {
        Ok(ReplayConfig {
            capacity: raw.capacity,
        })
    } else {
        Err(ConfigError::semantic(ConfigField::ReplayCapacity))
    }
}

pub(super) fn validate_udp(raw: RawUdp) -> Result<UdpConfig, ConfigError> {
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

pub(super) fn validate_logging(raw: RawLogging) -> Result<LoggingConfig, ConfigError> {
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

pub(super) fn validate_metrics(
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
