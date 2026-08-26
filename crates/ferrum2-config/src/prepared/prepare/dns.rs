use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU16;

use ferrum2_core::{CanonicalDomain, TargetAddr};

use crate::error::{ConfigError, ConfigField};
use crate::model::{DnsCacheConfig, DnsStrategy, ResolverRef};
use crate::raw::RawDns;
use crate::validation::validate_tag;

use super::super::model::{DialEndpoint, PreparedDnsEndpoint, PreparedDnsEndpointMode};

pub(crate) struct PreparedDnsDraft {
    pub(crate) strategy: Option<DnsStrategy>,
    pub(crate) cache: Option<DnsCacheConfig>,
    pub(crate) endpoints: Vec<PreparedDnsEndpoint>,
}

pub(super) fn prepare_dns(raw: Option<&RawDns>) -> Result<PreparedDnsDraft, ConfigError> {
    let Some(raw) = raw else {
        return Ok(PreparedDnsDraft {
            strategy: None,
            cache: None,
            endpoints: Vec::new(),
        });
    };
    let strategy = parse_strategy(raw.strategy.as_deref(), ConfigField::DnsStrategy)?;
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
    let servers = raw.servers.as_deref().unwrap_or(&[]);
    for (index, server) in servers.iter().enumerate() {
        validate_tag(&server.tag, ConfigField::DnsServersTag)?;
        if server.tag == "system" {
            return Err(ConfigError::dns_reserved_resolver_name(
                ConfigField::DnsServersTag,
            ));
        }
        if servers[..index].iter().any(|other| other.tag == server.tag) {
            return Err(ConfigError::semantic(ConfigField::DnsServersTag));
        }
    }
    let mut endpoints = Vec::new();
    endpoints
        .try_reserve_exact(servers.len())
        .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
    for server in servers {
        endpoints.push(parse_dns_endpoint(
            &server.address,
            server.domain_resolver.as_deref(),
            server.domain_strategy.as_deref(),
            server.detour.is_some(),
            strategy,
            servers,
        )?);
    }
    Ok(PreparedDnsDraft {
        strategy: Some(strategy),
        cache: Some(cache),
        endpoints,
    })
}

pub(super) fn parse_dns_endpoint(
    value: &str,
    resolver: Option<&str>,
    strategy: Option<&str>,
    has_detour: bool,
    default_strategy: DnsStrategy,
    dns_servers: &[crate::raw::RawDnsServer],
) -> Result<PreparedDnsEndpoint, ConfigError> {
    if let Ok(address) = value.parse::<SocketAddr>() {
        if address.port() == 0 {
            return Err(ConfigError::semantic(ConfigField::DnsServersAddress));
        }
        if resolver.is_some() {
            return Err(ConfigError::semantic(ConfigField::DnsServersDomainResolver));
        }
        if strategy.is_some() {
            return Err(ConfigError::semantic(ConfigField::DnsServersDomainStrategy));
        }
        return Ok(PreparedDnsEndpoint {
            target: TargetAddr::ip(address)
                .map_err(|_| ConfigError::semantic(ConfigField::DnsServersAddress))?,
            mode: PreparedDnsEndpointMode::Numeric,
            fixed_endpoint: Some(DialEndpoint::Ip(address)),
        });
    }
    let (host, port) = parse_domain_endpoint(value, ConfigField::DnsServersAddress)?;
    let target = TargetAddr::domain(host.as_str(), port.get())
        .map_err(|_| ConfigError::semantic(ConfigField::DnsServersAddress))?;
    let Some(resolver) = resolver else {
        if strategy.is_some() {
            return Err(ConfigError::semantic(ConfigField::DnsServersDomainStrategy));
        }
        if !has_detour {
            return Err(ConfigError::dns_resolver_required(
                ConfigField::DnsServersDomainResolver,
            ));
        }
        return Ok(PreparedDnsEndpoint {
            target,
            mode: PreparedDnsEndpointMode::DeferredToDetour,
            fixed_endpoint: None,
        });
    };
    let resolver = parse_resolver(resolver, dns_servers, ConfigField::DnsServersDomainResolver)?;
    let strategy = strategy.map_or(Ok(default_strategy), |strategy| {
        parse_strategy(Some(strategy), ConfigField::DnsServersDomainStrategy)
    })?;
    Ok(PreparedDnsEndpoint {
        target,
        mode: PreparedDnsEndpointMode::ClientResolved { resolver, strategy },
        fixed_endpoint: Some(DialEndpoint::Domain {
            host,
            port,
            resolver,
            strategy,
        }),
    })
}

pub(super) fn parse_domain_endpoint(
    value: &str,
    field: ConfigField,
) -> Result<(CanonicalDomain, NonZeroU16), ConfigError> {
    let (host, port) = value
        .rsplit_once(':')
        .filter(|(host, _)| !host.is_empty() && !host.contains(':'))
        .ok_or_else(|| ConfigError::semantic(field))?;
    let port = port
        .parse::<u16>()
        .ok()
        .and_then(NonZeroU16::new)
        .ok_or_else(|| ConfigError::semantic(field))?;
    if host.parse::<IpAddr>().is_ok() || !valid_domain(host) {
        return Err(ConfigError::semantic(field));
    }
    let host = CanonicalDomain::new(host).map_err(|_| ConfigError::semantic(field))?;
    Ok((host, port))
}

pub(super) struct EndpointValidation<'a> {
    pub(super) default_strategy: DnsStrategy,
    pub(super) dns_servers: &'a [crate::raw::RawDnsServer],
    pub(super) endpoint_field: ConfigField,
    pub(super) resolver_field: ConfigField,
    pub(super) strategy_field: ConfigField,
}

pub(super) fn parse_endpoint(
    value: &str,
    resolver: Option<&str>,
    strategy: Option<&str>,
    validation: EndpointValidation<'_>,
) -> Result<DialEndpoint, ConfigError> {
    let EndpointValidation {
        default_strategy,
        dns_servers,
        endpoint_field,
        resolver_field,
        strategy_field,
    } = validation;
    if let Ok(address) = value.parse::<SocketAddr>() {
        if address.port() == 0 {
            return Err(ConfigError::semantic(endpoint_field));
        }
        if resolver.is_some() {
            return Err(ConfigError::semantic(resolver_field));
        }
        if strategy.is_some() {
            return Err(ConfigError::semantic(strategy_field));
        }
        return Ok(DialEndpoint::Ip(address));
    }
    let (host, port) = parse_domain_endpoint(value, endpoint_field)?;
    let resolver = parse_resolver(
        resolver.ok_or_else(|| ConfigError::dns_resolver_required(resolver_field))?,
        dns_servers,
        resolver_field,
    )?;
    let strategy = strategy.map_or(Ok(default_strategy), |strategy| {
        parse_strategy(Some(strategy), strategy_field)
    })?;
    Ok(DialEndpoint::Domain {
        host,
        port,
        resolver,
        strategy,
    })
}

pub(super) fn parse_resolver(
    value: &str,
    dns_servers: &[crate::raw::RawDnsServer],
    field: ConfigField,
) -> Result<ResolverRef, ConfigError> {
    if value == "system" {
        return Ok(ResolverRef::System);
    }
    validate_tag(value, field)?;
    dns_servers
        .iter()
        .position(|server| server.tag == value)
        .map(ResolverRef::DnsServer)
        .ok_or_else(|| ConfigError::semantic(field))
}

pub(super) fn parse_strategy(
    value: Option<&str>,
    field: ConfigField,
) -> Result<DnsStrategy, ConfigError> {
    match value.unwrap_or("prefer_ipv4") {
        "prefer_ipv4" => Ok(DnsStrategy::PreferIpv4),
        "prefer_ipv6" => Ok(DnsStrategy::PreferIpv6),
        "ipv4_only" => Ok(DnsStrategy::Ipv4Only),
        "ipv6_only" => Ok(DnsStrategy::Ipv6Only),
        _ => Err(ConfigError::semantic(field)),
    }
}

pub(super) fn valid_domain(value: &str) -> bool {
    (1..=253).contains(&value.len())
        && value.is_ascii()
        && value
            .strip_suffix('.')
            .unwrap_or(value)
            .split('.')
            .all(|label| {
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
