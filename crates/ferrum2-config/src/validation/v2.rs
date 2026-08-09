use std::net::IpAddr;
use std::num::NonZeroU16;
use std::time::Duration;

use ferrum2_core::DomainName;
use ferrum2_core::route::{
    EgressPlanHandle, MAX_ROUTE_RULES, Network, OrderedRouteProgram, OrderedRouteRule, PortRange,
    RouteMatchField, RouteMatcher, RouteRuleAction,
};

use super::validate_route_target;
use crate::error::{ConfigError, ConfigField};
use crate::model::{
    ClientDnsRoute, CompiledRoute, DnsQueryType, RouteAction, RouteProtocol, RouteSniffConfig,
    SchemaVersion, ServerDnsRoute, Sniffers,
};
use crate::raw::{RawDns, RawDnsRouteRule, RawRoute, RawRouteRule, ScalarOrList};

#[derive(Clone, Copy)]
pub(super) enum Role {
    Client,
    Server,
}

pub(super) fn validate_version(version: u32) -> Result<SchemaVersion, ConfigError> {
    match version {
        1 => Ok(SchemaVersion::V1),
        2 => Ok(SchemaVersion::V2),
        _ => Err(ConfigError::semantic(ConfigField::SchemaVersion)),
    }
}

pub(super) fn reject_v1_fields(
    route: Option<&RawRoute>,
    dns: Option<&RawDns>,
) -> Result<(), ConfigError> {
    if let Some(route) = route {
        if route.sniff.is_some() {
            return Err(ConfigError::semantic(ConfigField::RouteSniff));
        }
        for rule in &route.rules {
            let field = if rule.inbound.as_ref().is_some_and(ScalarOrList::is_list) {
                Some(ConfigField::RouteRulesInbound)
            } else if rule.network.as_ref().is_some_and(ScalarOrList::is_list) {
                Some(ConfigField::RouteRulesNetwork)
            } else if rule.protocol.is_some() {
                Some(ConfigField::RouteRulesProtocol)
            } else if rule.domain.is_some() {
                Some(ConfigField::RouteRulesDomain)
            } else if rule.domain_suffix.is_some() {
                Some(ConfigField::RouteRulesDomainSuffix)
            } else if rule.ip.is_some() {
                Some(ConfigField::RouteRulesIp)
            } else if rule.ip_cidr.is_some() {
                Some(ConfigField::RouteRulesIpCidr)
            } else if rule.port.is_some() {
                Some(ConfigField::RouteRulesPort)
            } else if rule.port_range.is_some() {
                Some(ConfigField::RouteRulesPortRange)
            } else if rule.action.is_some() {
                Some(ConfigField::RouteRulesAction)
            } else if rule.sniffers.is_some() {
                Some(ConfigField::RouteRulesSniffers)
            } else {
                None
            };
            if let Some(field) = field {
                return Err(ConfigError::semantic(field));
            }
        }
    }
    if let Some(route) = dns.and_then(|dns| dns.route.as_ref()) {
        for rule in &route.rules {
            let field = if rule.inbound.as_ref().is_some_and(ScalarOrList::is_list) {
                Some(ConfigField::DnsRouteRulesInbound)
            } else if rule.network.as_ref().is_some_and(ScalarOrList::is_list) {
                Some(ConfigField::DnsRouteRulesNetwork)
            } else if rule.qname.is_some() {
                Some(ConfigField::DnsRouteRulesQname)
            } else if rule.qname_suffix.is_some() {
                Some(ConfigField::DnsRouteRulesQnameSuffix)
            } else if rule.qtype.is_some() {
                Some(ConfigField::DnsRouteRulesQtype)
            } else if rule.domain.is_some() {
                Some(ConfigField::DnsRouteRulesDomain)
            } else if rule.domain_suffix.is_some() {
                Some(ConfigField::DnsRouteRulesDomainSuffix)
            } else if rule.port.is_some() {
                Some(ConfigField::DnsRouteRulesPort)
            } else if rule.port_range.is_some() {
                Some(ConfigField::DnsRouteRulesPortRange)
            } else {
                None
            };
            if let Some(field) = field {
                return Err(ConfigError::semantic(field));
            }
        }
    }
    Ok(())
}

pub(super) struct RouteDraft {
    rules: Vec<(RouteMatcher<RouteProtocol>, DraftAction)>,
    roots: Vec<String>,
    sniff: RouteSniffConfig,
}

enum DraftAction {
    Route(usize),
    Sniff(Sniffers),
    HijackDns,
    Reject,
}

struct Coverage {
    inbound: Option<Vec<usize>>,
    network: Option<Vec<Network>>,
    protocols: Option<Vec<RouteProtocol>>,
    sniffers: Option<SniffersCoverage>,
    target: TargetCoverage,
}

struct TargetCoverage {
    domain: Option<Vec<String>>,
    domain_suffix: Option<Vec<String>>,
    ip: Option<Vec<String>>,
    ip_cidr: Option<Vec<String>>,
    port: Option<Vec<NonZeroU16>>,
    port_range: Option<Vec<String>>,
    legacy: Option<ferrum2_core::TargetAddr>,
}

enum SniffersCoverage {
    Default,
    Explicit(Vec<RouteProtocol>),
}

impl RouteDraft {
    pub(super) fn root_tags(&self) -> Vec<&str> {
        self.roots.iter().map(String::as_str).collect()
    }

    pub(super) fn finish(
        self,
        handles: Vec<EgressPlanHandle>,
    ) -> Result<CompiledRoute, ConfigError> {
        if handles.len() != self.roots.len() {
            return Err(ConfigError::semantic(ConfigField::RouteRulesOutbound));
        }
        let final_action = RouteAction::Route(handles[0].clone());
        let rules = self
            .rules
            .into_iter()
            .map(|(matcher, action)| {
                let action = match action {
                    DraftAction::Route(root) => {
                        RouteRuleAction::Terminal(RouteAction::Route(handles[root].clone()))
                    }
                    DraftAction::Sniff(sniffers) => {
                        RouteRuleAction::Continue(RouteAction::Sniff(sniffers))
                    }
                    DraftAction::HijackDns => RouteRuleAction::Terminal(RouteAction::HijackDns),
                    DraftAction::Reject => RouteRuleAction::Terminal(RouteAction::Reject),
                };
                OrderedRouteRule::new(matcher, action)
            })
            .collect();
        let program = OrderedRouteProgram::new(rules, final_action)
            .ok_or_else(|| ConfigError::semantic(ConfigField::RouteRules))?;
        Ok(CompiledRoute {
            program,
            sniff: self.sniff,
        })
    }
}

pub(super) fn compile_route_draft(
    raw: Option<&RawRoute>,
    inbounds: &[String],
    role: Role,
    tun_inbound: Option<usize>,
    has_dns: bool,
    max_connections: u32,
    source: &str,
) -> Result<Option<RouteDraft>, ConfigError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    if raw.rules.len() > MAX_ROUTE_RULES {
        return Err(ConfigError::semantic(ConfigField::RouteRules));
    }
    let final_outbound = raw
        .final_outbound
        .as_ref()
        .ok_or_else(|| ConfigError::semantic(ConfigField::RouteFinal))?;
    let sniff = raw.sniff.as_ref();
    let timeout_ms = sniff.map_or(300, |sniff| sniff.timeout_ms);
    if !(10..=2_000).contains(&timeout_ms) {
        return Err(ConfigError::semantic(ConfigField::RouteSniffTimeout));
    }
    let max_bytes = sniff.map_or(8_192, |sniff| sniff.max_bytes);
    if !(512..=16_384).contains(&max_bytes) {
        return Err(ConfigError::semantic(ConfigField::RouteSniffMaxBytes));
    }
    let max_aggregate_bytes = usize::try_from(max_connections)
        .ok()
        .and_then(|connections| connections.checked_mul(max_bytes))
        .ok_or_else(|| ConfigError::semantic(ConfigField::RouteSniffMaxBytes))?;

    let mut roots = vec![final_outbound.clone()];
    let mut rules = Vec::with_capacity(raw.rules.len());
    let mut coverage = Vec::with_capacity(raw.rules.len());
    for rule in &raw.rules {
        if rule.server.is_some() {
            return Err(ConfigError::semantic(ConfigField::RouteRulesOutbound));
        }
        let (matcher, mut current) = compile_route_matcher(rule, inbounds, source)?;
        let action = rule
            .action
            .as_deref()
            .unwrap_or_else(|| if rule.outbound.is_some() { "route" } else { "" });
        let action = match action {
            "route" => {
                if rule.sniffers.is_some() {
                    return Err(ConfigError::semantic(ConfigField::RouteRulesSniffers));
                }
                let outbound = rule
                    .outbound
                    .as_ref()
                    .ok_or_else(|| ConfigError::semantic(ConfigField::RouteRulesOutbound))?;
                roots.push(outbound.clone());
                DraftAction::Route(roots.len() - 1)
            }
            "sniff" => {
                if rule.outbound.is_some() {
                    return Err(ConfigError::semantic(ConfigField::RouteRulesOutbound));
                }
                let sniffers = compile_sniffers(rule.sniffers.as_ref())?;
                validate_sniff_capability(
                    role,
                    current.inbound.as_deref(),
                    current.network.as_deref(),
                    tun_inbound,
                    &sniffers,
                )?;
                current.sniffers = Some(match &sniffers {
                    Sniffers::Default => SniffersCoverage::Default,
                    Sniffers::Explicit(values) => SniffersCoverage::Explicit(values.clone()),
                });
                DraftAction::Sniff(sniffers)
            }
            "hijack-dns" => {
                if rule.outbound.is_some() {
                    return Err(ConfigError::semantic(ConfigField::RouteRulesOutbound));
                }
                if rule.sniffers.is_some() {
                    return Err(ConfigError::semantic(ConfigField::RouteRulesSniffers));
                }
                if !matches!(role, Role::Client) || !has_dns {
                    return Err(ConfigError::semantic(ConfigField::RouteRulesAction));
                }
                DraftAction::HijackDns
            }
            "reject" => {
                if rule.outbound.is_some() {
                    return Err(ConfigError::semantic(ConfigField::RouteRulesOutbound));
                }
                if rule.sniffers.is_some() {
                    return Err(ConfigError::semantic(ConfigField::RouteRulesSniffers));
                }
                DraftAction::Reject
            }
            _ => return Err(ConfigError::semantic(ConfigField::RouteRulesAction)),
        };
        if !matches!(action, DraftAction::Sniff(_)) && matcher_value_count(rule) == 0 {
            return Err(ConfigError::semantic(ConfigField::RouteRules));
        }
        coverage.push(current);
        rules.push((matcher, action));
    }
    validate_protocol_coverage(&coverage, role)?;
    Ok(Some(RouteDraft {
        rules,
        roots,
        sniff: RouteSniffConfig {
            timeout: Duration::from_millis(timeout_ms),
            max_bytes,
            max_aggregate_bytes,
        },
    }))
}

fn compile_route_matcher(
    raw: &RawRouteRule,
    inbounds: &[String],
    source: &str,
) -> Result<(RouteMatcher<RouteProtocol>, Coverage), ConfigError> {
    if raw.target.is_some()
        && (raw.domain.is_some()
            || raw.domain_suffix.is_some()
            || raw.ip.is_some()
            || raw.ip_cidr.is_some()
            || raw.port.is_some()
            || raw.port_range.is_some())
    {
        return Err(ConfigError::semantic(ConfigField::RouteRulesTarget));
    }
    if matcher_value_count(raw) > 64 {
        return Err(ConfigError::semantic(ConfigField::RouteRules));
    }
    let mut fields = Vec::new();
    let inbound = raw
        .inbound
        .as_ref()
        .map(|values| {
            parse_values(values, ConfigField::RouteRulesInbound, |tag| {
                inbounds
                    .iter()
                    .position(|candidate| candidate == tag)
                    .ok_or_else(|| ConfigError::semantic(ConfigField::RouteRulesInbound))
            })
        })
        .transpose()?;
    if let Some(values) = &inbound {
        fields.push(RouteMatchField::Inbound(values.clone()));
    }
    let network = raw
        .network
        .as_ref()
        .map(|values| {
            parse_values(values, ConfigField::RouteRulesNetwork, |value| {
                parse_network(value)
            })
        })
        .transpose()?;
    if let Some(values) = &network {
        fields.push(RouteMatchField::Network(values.clone()));
    }
    let protocols = raw
        .protocol
        .as_ref()
        .map(|values| {
            parse_values(values, ConfigField::RouteRulesProtocol, |value| {
                parse_protocol_field(value, ConfigField::RouteRulesProtocol)
            })
        })
        .transpose()?;
    if let Some(values) = &protocols {
        fields.push(RouteMatchField::Protocol(values.clone()));
    }
    push_domains(
        &mut fields,
        raw.domain.as_ref(),
        ConfigField::RouteRulesDomain,
        false,
    )?;
    push_domains(
        &mut fields,
        raw.domain_suffix.as_ref(),
        ConfigField::RouteRulesDomainSuffix,
        true,
    )?;
    if let Some(values) = &raw.ip {
        fields.push(RouteMatchField::Ip(parse_values(
            values,
            ConfigField::RouteRulesIp,
            |value| {
                value
                    .parse::<IpAddr>()
                    .map_err(|_| ConfigError::semantic(ConfigField::RouteRulesIp))
            },
        )?));
    }
    if let Some(values) = &raw.ip_cidr {
        let checked = RouteMatchField::Cidr(parse_values(
            values,
            ConfigField::RouteRulesIpCidr,
            |value| {
                value
                    .parse()
                    .map_err(|_| ConfigError::semantic(ConfigField::RouteRulesIpCidr))
            },
        )?);
        if RouteMatcher::<RouteProtocol>::new(vec![checked]).is_none() {
            return Err(ConfigError::semantic(ConfigField::RouteRulesIpCidr));
        }
        fields.push(RouteMatchField::Cidr(parse_values(
            values,
            ConfigField::RouteRulesIpCidr,
            |value| {
                value
                    .parse()
                    .map_err(|_| ConfigError::semantic(ConfigField::RouteRulesIpCidr))
            },
        )?));
    }
    let port = raw
        .port
        .as_ref()
        .map(|values| {
            parse_values(values, ConfigField::RouteRulesPort, |value| {
                u16::try_from(*value)
                    .ok()
                    .and_then(NonZeroU16::new)
                    .ok_or_else(|| ConfigError::semantic(ConfigField::RouteRulesPort))
            })
        })
        .transpose()?;
    if let Some(values) = &port {
        fields.push(RouteMatchField::Port(values.clone()));
    }
    if let Some(values) = &raw.port_range {
        fields.push(RouteMatchField::PortRange(parse_values(
            values,
            ConfigField::RouteRulesPortRange,
            |value| parse_port_range(value, ConfigField::RouteRulesPortRange),
        )?));
    }
    let legacy_target = raw
        .target
        .as_ref()
        .map(|target| validate_route_target(target, source, ConfigField::RouteRulesTarget))
        .transpose()?;
    if let Some(target) = &legacy_target {
        fields.push(RouteMatchField::Target(vec![target.clone()]));
    }
    let matcher =
        RouteMatcher::new(fields).ok_or_else(|| ConfigError::semantic(ConfigField::RouteRules))?;
    Ok((
        matcher,
        Coverage {
            inbound,
            network,
            protocols,
            sniffers: None,
            target: TargetCoverage {
                domain: normalized_strings(raw.domain.as_ref()),
                domain_suffix: normalized_strings(raw.domain_suffix.as_ref()),
                ip: normalized_strings(raw.ip.as_ref()),
                ip_cidr: normalized_strings(raw.ip_cidr.as_ref()),
                port,
                port_range: normalized_strings(raw.port_range.as_ref()),
                legacy: legacy_target,
            },
        },
    ))
}

fn normalized_strings(raw: Option<&ScalarOrList<String>>) -> Option<Vec<String>> {
    raw.map(|values| {
        values
            .iter()
            .map(|value| {
                value
                    .strip_suffix('.')
                    .unwrap_or(value)
                    .to_ascii_lowercase()
            })
            .collect()
    })
}

fn push_domains<P: Eq>(
    fields: &mut Vec<RouteMatchField<P>>,
    raw: Option<&ScalarOrList<String>>,
    field: ConfigField,
    suffix: bool,
) -> Result<(), ConfigError> {
    let Some(raw) = raw else {
        return Ok(());
    };
    validate_values_by(raw, field, |value| {
        value
            .strip_suffix('.')
            .unwrap_or(value)
            .to_ascii_lowercase()
    })?;
    if raw
        .iter()
        .any(|value| value.strip_suffix('.').unwrap_or(value).is_empty())
    {
        return Err(ConfigError::semantic(field));
    }
    let values = raw
        .iter()
        .map(|value| DomainName::new(value).map_err(|_| ConfigError::semantic(field)))
        .collect::<Result<Vec<_>, _>>()?;
    fields.push(if suffix {
        RouteMatchField::DomainSuffix(values)
    } else {
        RouteMatchField::Domain(values)
    });
    Ok(())
}

fn compile_sniffers(raw: Option<&ScalarOrList<String>>) -> Result<Sniffers, ConfigError> {
    raw.map(|values| {
        parse_values(values, ConfigField::RouteRulesSniffers, |value| {
            parse_protocol_field(value, ConfigField::RouteRulesSniffers)
        })
        .map(Sniffers::Explicit)
    })
    .transpose()
    .map(|value| value.unwrap_or(Sniffers::Default))
}

fn validate_sniff_capability(
    role: Role,
    inbounds: Option<&[usize]>,
    networks: Option<&[Network]>,
    tun_inbound: Option<usize>,
    sniffers: &Sniffers,
) -> Result<(), ConfigError> {
    let includes_tcp = networks.is_none_or(|values| values.contains(&Network::Tcp));
    let includes_udp = networks.is_none_or(|values| values.contains(&Network::Udp));
    let tun_only_tcp = matches!(role, Role::Client)
        && tun_inbound.is_some_and(|tun| inbounds == Some(&[tun][..]))
        && networks == Some(&[Network::Tcp][..]);
    if matches!(role, Role::Client) && includes_tcp && !tun_only_tcp {
        return Err(ConfigError::semantic(ConfigField::RouteRulesAction));
    }
    if let Sniffers::Explicit(values) = sniffers {
        if matches!(role, Role::Client)
            && !tun_only_tcp
            && values.iter().any(|value| *value != RouteProtocol::Dns)
        {
            return Err(ConfigError::semantic(ConfigField::RouteRulesSniffers));
        }
        if matches!(role, Role::Server)
            && includes_udp
            && values.iter().any(|value| *value != RouteProtocol::Dns)
        {
            return Err(ConfigError::semantic(ConfigField::RouteRulesSniffers));
        }
    }
    Ok(())
}

fn validate_protocol_coverage(rows: &[Coverage], role: Role) -> Result<(), ConfigError> {
    for (index, row) in rows.iter().enumerate() {
        let Some(protocols) = &row.protocols else {
            continue;
        };
        for protocol in protocols {
            // Only typed match values prove disjointness; textual target aliases stay overlapping.
            let covered = rows[..index]
                .iter()
                .find(|earlier| {
                    earlier.sniffers.is_some()
                        && !disjoint(earlier.inbound.as_deref(), row.inbound.as_deref())
                        && !disjoint(earlier.network.as_deref(), row.network.as_deref())
                        && !disjoint(earlier.target.port.as_deref(), row.target.port.as_deref())
                })
                .is_some_and(|earlier| {
                    earlier.sniffers.as_ref().is_some_and(|sniffers| {
                        earlier.protocols.is_none()
                            && earlier.target.domain.is_none()
                            && earlier.target.domain_suffix.is_none()
                            && covers(earlier.inbound.as_deref(), row.inbound.as_deref())
                            && covers(earlier.network.as_deref(), row.network.as_deref())
                            && covers(earlier.target.ip.as_deref(), row.target.ip.as_deref())
                            && covers(
                                earlier.target.ip_cidr.as_deref(),
                                row.target.ip_cidr.as_deref(),
                            )
                            && covers(earlier.target.port.as_deref(), row.target.port.as_deref())
                            && covers(
                                earlier.target.port_range.as_deref(),
                                row.target.port_range.as_deref(),
                            )
                            && covers_one(
                                earlier.target.legacy.as_ref(),
                                row.target.legacy.as_ref(),
                            )
                            && sniffer_covers(sniffers, *protocol, row.network.as_deref(), role)
                    })
                });
            if !covered {
                return Err(ConfigError::semantic(ConfigField::RouteRulesProtocol));
            }
        }
    }
    Ok(())
}

fn disjoint<T: Eq>(left: Option<&[T]>, right: Option<&[T]>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => !left.iter().any(|value| right.contains(value)),
        _ => false,
    }
}

fn covers_one<T: Eq>(wider: Option<&T>, narrower: Option<&T>) -> bool {
    match (wider, narrower) {
        (None, _) => true,
        (Some(wider), Some(narrower)) => wider == narrower,
        (Some(_), None) => false,
    }
}

fn covers<T: Eq>(wider: Option<&[T]>, narrower: Option<&[T]>) -> bool {
    match (wider, narrower) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(wider), Some(narrower)) => narrower.iter().all(|value| wider.contains(value)),
    }
}

fn sniffer_covers(
    sniffers: &SniffersCoverage,
    protocol: RouteProtocol,
    networks: Option<&[Network]>,
    role: Role,
) -> bool {
    match sniffers {
        SniffersCoverage::Explicit(values) => values.contains(&protocol),
        SniffersCoverage::Default => {
            let includes_udp = networks.is_none_or(|values| values.contains(&Network::Udp));
            protocol == RouteProtocol::Dns || (matches!(role, Role::Server) && !includes_udp)
        }
    }
}

fn matcher_value_count(rule: &RawRouteRule) -> usize {
    [
        rule.inbound.as_ref().map_or(0, ScalarOrList::len),
        rule.network.as_ref().map_or(0, ScalarOrList::len),
        rule.protocol.as_ref().map_or(0, ScalarOrList::len),
        rule.domain.as_ref().map_or(0, ScalarOrList::len),
        rule.domain_suffix.as_ref().map_or(0, ScalarOrList::len),
        rule.ip.as_ref().map_or(0, ScalarOrList::len),
        rule.ip_cidr.as_ref().map_or(0, ScalarOrList::len),
        rule.port.as_ref().map_or(0, ScalarOrList::len),
        rule.port_range.as_ref().map_or(0, ScalarOrList::len),
        usize::from(rule.target.is_some()),
    ]
    .into_iter()
    .sum()
}

fn parse_network(value: &str) -> Result<Network, ConfigError> {
    match value {
        "tcp" => Ok(Network::Tcp),
        "udp" => Ok(Network::Udp),
        _ => Err(ConfigError::semantic(ConfigField::RouteRulesNetwork)),
    }
}

fn parse_protocol_field(value: &str, field: ConfigField) -> Result<RouteProtocol, ConfigError> {
    match value {
        "dns" => Ok(RouteProtocol::Dns),
        "tls" => Ok(RouteProtocol::Tls),
        "http" => Ok(RouteProtocol::Http),
        _ => Err(ConfigError::semantic(field)),
    }
}

fn parse_port_range(value: &str, field: ConfigField) -> Result<PortRange, ConfigError> {
    let (first, last) = value
        .split_once(':')
        .ok_or_else(|| ConfigError::semantic(field))?;
    let first = first
        .parse::<u16>()
        .map_err(|_| ConfigError::semantic(field))?;
    let last = last
        .parse::<u16>()
        .map_err(|_| ConfigError::semantic(field))?;
    PortRange::new(first, last).ok_or_else(|| ConfigError::semantic(field))
}

fn parse_values<T, U, F>(
    raw: &ScalarOrList<T>,
    field: ConfigField,
    mut parse: F,
) -> Result<Vec<U>, ConfigError>
where
    U: Eq,
    F: FnMut(&T) -> Result<U, ConfigError>,
{
    validate_values(raw, field)?;
    let values = raw.iter().map(&mut parse).collect::<Result<Vec<_>, _>>()?;
    if values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
    {
        return Err(ConfigError::semantic(field));
    }
    Ok(values)
}

fn validate_values<T>(raw: &ScalarOrList<T>, field: ConfigField) -> Result<(), ConfigError> {
    if raw.len() == 0 {
        Err(ConfigError::semantic(field))
    } else {
        Ok(())
    }
}

fn validate_values_by<T, K: Eq, F>(
    raw: &ScalarOrList<T>,
    field: ConfigField,
    mut key: F,
) -> Result<(), ConfigError>
where
    F: FnMut(&T) -> K,
{
    validate_values(raw, field)?;
    let keys = raw.iter().map(&mut key).collect::<Vec<_>>();
    if keys
        .iter()
        .enumerate()
        .any(|(index, value)| keys[..index].contains(value))
    {
        Err(ConfigError::semantic(field))
    } else {
        Ok(())
    }
}

pub(super) fn compile_client_dns(
    raw: &RawDns,
    ordinary_inbounds: &[String],
    source: &str,
) -> Result<ClientDnsRoute, ConfigError> {
    let listeners = raw
        .inbounds
        .as_deref()
        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsInbounds))?;
    let servers = raw
        .servers
        .as_deref()
        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsServers))?;
    let route = raw
        .route
        .as_ref()
        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRoute))?;
    let final_server = resolve_dns_final(route.final_server.as_deref(), servers)?;
    let mut rules = Vec::with_capacity(route.rules.len());
    for rule in &route.rules {
        if rule.domain.is_some()
            || rule.domain_suffix.is_some()
            || rule.port.is_some()
            || rule.port_range.is_some()
        {
            let field = if rule.domain.is_some() {
                ConfigField::DnsRouteRulesDomain
            } else if rule.domain_suffix.is_some() {
                ConfigField::DnsRouteRulesDomainSuffix
            } else if rule.port.is_some() {
                ConfigField::DnsRouteRulesPort
            } else {
                ConfigField::DnsRouteRulesPortRange
            };
            return Err(ConfigError::semantic(field));
        }
        if dns_matcher_value_count(rule) > 64 {
            return Err(ConfigError::semantic(ConfigField::DnsRouteRules));
        }
        if rule.target.is_some()
            && (rule.qname.is_some() || rule.qname_suffix.is_some() || rule.qtype.is_some())
        {
            return Err(ConfigError::semantic(ConfigField::DnsRouteRulesTarget));
        }
        let mut fields = Vec::new();
        if let Some(values) = &rule.inbound {
            let values = parse_values(values, ConfigField::DnsRouteRulesInbound, |tag| {
                listeners
                    .iter()
                    .position(|candidate| candidate.tag == *tag)
                    .or_else(|| {
                        ordinary_inbounds
                            .iter()
                            .position(|candidate| candidate == tag)
                            .map(|index| listeners.len() + index)
                    })
                    .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteRulesInbound))
            })?;
            fields.push(RouteMatchField::Inbound(values));
        }
        if let Some(values) = &rule.network {
            fields.push(RouteMatchField::Network(parse_values(
                values,
                ConfigField::DnsRouteRulesNetwork,
                |value| parse_network_field(value, ConfigField::DnsRouteRulesNetwork),
            )?));
        }
        push_domains(
            &mut fields,
            rule.qname.as_ref(),
            ConfigField::DnsRouteRulesQname,
            false,
        )?;
        push_domains(
            &mut fields,
            rule.qname_suffix.as_ref(),
            ConfigField::DnsRouteRulesQnameSuffix,
            true,
        )?;
        if let Some(values) = &rule.qtype {
            fields.push(RouteMatchField::Protocol(parse_values(
                values,
                ConfigField::DnsRouteRulesQtype,
                |value| parse_qtype(value),
            )?));
        }
        if let Some(target) = &rule.target {
            fields.push(RouteMatchField::Target(vec![validate_route_target(
                target,
                source,
                ConfigField::DnsRouteRulesTarget,
            )?]));
        }
        let matcher = RouteMatcher::new(fields)
            .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteRules))?;
        let server = resolve_dns_server(rule, servers)?;
        rules.push(OrderedRouteRule::new(
            matcher,
            RouteRuleAction::Terminal(server),
        ));
    }
    let program = OrderedRouteProgram::new(rules, final_server)
        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteRules))?;
    Ok(ClientDnsRoute {
        program,
        listener_count: listeners.len(),
        ordinary_count: ordinary_inbounds.len(),
    })
}

pub(super) fn compile_server_dns(
    raw: &RawDns,
    inbounds: &[String],
    source: &str,
) -> Result<ServerDnsRoute, ConfigError> {
    let servers = raw
        .servers
        .as_deref()
        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsServers))?;
    let route = raw
        .route
        .as_ref()
        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRoute))?;
    let final_server = resolve_dns_final(route.final_server.as_deref(), servers)?;
    let mut rules = Vec::with_capacity(route.rules.len());
    for rule in &route.rules {
        if rule.qname.is_some() || rule.qname_suffix.is_some() || rule.qtype.is_some() {
            let field = if rule.qname.is_some() {
                ConfigField::DnsRouteRulesQname
            } else if rule.qname_suffix.is_some() {
                ConfigField::DnsRouteRulesQnameSuffix
            } else {
                ConfigField::DnsRouteRulesQtype
            };
            return Err(ConfigError::semantic(field));
        }
        if dns_matcher_value_count(rule) > 64 {
            return Err(ConfigError::semantic(ConfigField::DnsRouteRules));
        }
        if rule.target.is_some()
            && (rule.domain.is_some()
                || rule.domain_suffix.is_some()
                || rule.port.is_some()
                || rule.port_range.is_some())
        {
            return Err(ConfigError::semantic(ConfigField::DnsRouteRulesTarget));
        }
        let mut fields = Vec::new();
        if let Some(values) = &rule.inbound {
            fields.push(RouteMatchField::Inbound(parse_values(
                values,
                ConfigField::DnsRouteRulesInbound,
                |tag| {
                    inbounds
                        .iter()
                        .position(|candidate| candidate == tag)
                        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteRulesInbound))
                },
            )?));
        }
        if let Some(values) = &rule.network {
            fields.push(RouteMatchField::Network(parse_values(
                values,
                ConfigField::DnsRouteRulesNetwork,
                |value| parse_network_field(value, ConfigField::DnsRouteRulesNetwork),
            )?));
        }
        push_domains(
            &mut fields,
            rule.domain.as_ref(),
            ConfigField::DnsRouteRulesDomain,
            false,
        )?;
        push_domains(
            &mut fields,
            rule.domain_suffix.as_ref(),
            ConfigField::DnsRouteRulesDomainSuffix,
            true,
        )?;
        if let Some(values) = &rule.port {
            fields.push(RouteMatchField::Port(parse_values(
                values,
                ConfigField::DnsRouteRulesPort,
                |value| {
                    u16::try_from(*value)
                        .ok()
                        .and_then(NonZeroU16::new)
                        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteRulesPort))
                },
            )?));
        }
        if let Some(values) = &rule.port_range {
            fields.push(RouteMatchField::PortRange(parse_values(
                values,
                ConfigField::DnsRouteRulesPortRange,
                |value| parse_port_range(value, ConfigField::DnsRouteRulesPortRange),
            )?));
        }
        if let Some(target) = &rule.target {
            fields.push(RouteMatchField::Target(vec![validate_route_target(
                target,
                source,
                ConfigField::DnsRouteRulesTarget,
            )?]));
        }
        let matcher = RouteMatcher::new(fields)
            .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteRules))?;
        let server = resolve_dns_server(rule, servers)?;
        rules.push(OrderedRouteRule::new(
            matcher,
            RouteRuleAction::Terminal(server),
        ));
    }
    let program = OrderedRouteProgram::new(rules, final_server)
        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteRules))?;
    Ok(ServerDnsRoute { program })
}

fn resolve_dns_final(
    tag: Option<&str>,
    servers: &[crate::raw::RawDnsServer],
) -> Result<usize, ConfigError> {
    tag.and_then(|tag| servers.iter().position(|server| server.tag == tag))
        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteFinal))
}

fn resolve_dns_server(
    rule: &RawDnsRouteRule,
    servers: &[crate::raw::RawDnsServer],
) -> Result<usize, ConfigError> {
    rule.server
        .as_deref()
        .and_then(|tag| servers.iter().position(|server| server.tag == tag))
        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteRulesServer))
}

fn parse_network_field(value: &str, field: ConfigField) -> Result<Network, ConfigError> {
    match value {
        "tcp" => Ok(Network::Tcp),
        "udp" => Ok(Network::Udp),
        _ => Err(ConfigError::semantic(field)),
    }
}

fn parse_qtype(value: &str) -> Result<DnsQueryType, ConfigError> {
    match value.to_ascii_uppercase().as_str() {
        "A" => Ok(DnsQueryType::A),
        "AAAA" => Ok(DnsQueryType::Aaaa),
        "CNAME" => Ok(DnsQueryType::Cname),
        "MX" => Ok(DnsQueryType::Mx),
        "NS" => Ok(DnsQueryType::Ns),
        "PTR" => Ok(DnsQueryType::Ptr),
        "SOA" => Ok(DnsQueryType::Soa),
        "SRV" => Ok(DnsQueryType::Srv),
        "TXT" => Ok(DnsQueryType::Txt),
        "CAA" => Ok(DnsQueryType::Caa),
        "SVCB" => Ok(DnsQueryType::Svcb),
        "HTTPS" => Ok(DnsQueryType::Https),
        "ANY" => Ok(DnsQueryType::Any),
        _ => Err(ConfigError::semantic(ConfigField::DnsRouteRulesQtype)),
    }
}

fn dns_matcher_value_count(rule: &RawDnsRouteRule) -> usize {
    [
        rule.inbound.as_ref().map_or(0, ScalarOrList::len),
        rule.network.as_ref().map_or(0, ScalarOrList::len),
        rule.qname.as_ref().map_or(0, ScalarOrList::len),
        rule.qname_suffix.as_ref().map_or(0, ScalarOrList::len),
        rule.qtype.as_ref().map_or(0, ScalarOrList::len),
        rule.domain.as_ref().map_or(0, ScalarOrList::len),
        rule.domain_suffix.as_ref().map_or(0, ScalarOrList::len),
        rule.port.as_ref().map_or(0, ScalarOrList::len),
        rule.port_range.as_ref().map_or(0, ScalarOrList::len),
        usize::from(rule.target.is_some()),
    ]
    .into_iter()
    .sum()
}
