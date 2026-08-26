use std::num::NonZeroU16;
use std::sync::Arc;

use ferrum2_core::DomainName;
use ferrum2_rule::{CompiledMatchSet, MatchSetBuilder, Network, PortRange, RuleCompileError};

use crate::error::{ConfigError, ConfigField};
use crate::model::{DnsQueryType, DnsStrategy};
use crate::raw::{RawDns, RawDnsRouteRule, ScalarOrList};
use crate::validation::validate_tag;

use super::super::model::{
    PreparedDnsAction, PreparedDnsMatcherDraft, PreparedDnsRule, PreparedRuleSet,
};
use super::dns::parse_strategy;

#[derive(Clone, Copy)]
pub(super) enum PreparedDnsRole {
    Client,
    Server,
}

pub(super) struct PreparedDnsPolicyDraft {
    pub(super) rules: Vec<PreparedDnsRule>,
    pub(super) final_server: Option<usize>,
}

pub(super) fn prepare_dns_rules(
    dns: Option<&RawDns>,
    rule_sets: &[PreparedRuleSet],
    strategy: Option<DnsStrategy>,
    role: PreparedDnsRole,
    ordinary_inbounds: &[&str],
) -> Result<PreparedDnsPolicyDraft, ConfigError> {
    let Some(dns) = dns else {
        return Ok(PreparedDnsPolicyDraft {
            rules: Vec::new(),
            final_server: None,
        });
    };
    let servers = dns.servers.as_deref().unwrap_or(&[]);
    let route = dns
        .route
        .as_ref()
        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRoute))?;
    let final_server = route
        .final_server
        .as_deref()
        .and_then(|tag| servers.iter().position(|server| server.tag == tag))
        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteFinal))?;
    let default_strategy = strategy.unwrap_or(DnsStrategy::PreferIpv4);
    let mut prepared = Vec::new();
    prepared
        .try_reserve_exact(route.rules.len())
        .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
    for (rule_index, rule) in route.rules.iter().enumerate() {
        if !dns_matcher_present(rule) {
            return Err(ConfigError::semantic(ConfigField::DnsRouteRules));
        }
        let matcher = prepare_dns_matcher(rule, dns, role, ordinary_inbounds)?;
        let rule_sets = rule
            .rule_set
            .as_ref()
            .map(|raw| resolve_rule_set_refs(raw, rule_sets, ConfigField::DnsRouteRulesRuleSet))
            .transpose()?
            .unwrap_or_default();
        let action = match rule
            .action
            .as_deref()
            .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteRulesAction))?
        {
            "route" => {
                if rule.outbound.is_some() {
                    return Err(ConfigError::semantic(ConfigField::DnsRouteRulesServer));
                }
                let server = rule
                    .server
                    .as_deref()
                    .and_then(|tag| servers.iter().position(|server| server.tag == tag))
                    .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteRulesServer))?;
                PreparedDnsAction::Route { server }
            }
            "reject" => {
                if rule.server.is_some() || rule.outbound.is_some() {
                    return Err(ConfigError::semantic(ConfigField::DnsRouteRulesServer));
                }
                if rule.strategy.is_some() {
                    return Err(ConfigError::semantic(ConfigField::DnsRouteRulesStrategy));
                }
                PreparedDnsAction::Reject
            }
            _ => return Err(ConfigError::semantic(ConfigField::DnsRouteRulesAction)),
        };
        let strategy = match action {
            PreparedDnsAction::Reject => default_strategy,
            PreparedDnsAction::Route { .. } => rule
                .strategy
                .as_deref()
                .map_or(Ok(default_strategy), |value| {
                    parse_strategy(Some(value), ConfigField::DnsRouteRulesStrategy)
                })?,
        };
        prepared.push(PreparedDnsRule {
            rule_index,
            rule_sets,
            action,
            strategy,
            matcher,
        });
    }
    Ok(PreparedDnsPolicyDraft {
        rules: prepared,
        final_server: Some(final_server),
    })
}

pub(super) fn prepare_dns_matcher(
    rule: &RawDnsRouteRule,
    dns: &RawDns,
    role: PreparedDnsRole,
    ordinary_inbounds: &[&str],
) -> Result<PreparedDnsMatcherDraft, ConfigError> {
    match role {
        PreparedDnsRole::Client => {
            if rule.domain.is_some() {
                return Err(ConfigError::semantic(ConfigField::DnsRouteRulesDomain));
            }
            if rule.domain_suffix.is_some() {
                return Err(ConfigError::semantic(
                    ConfigField::DnsRouteRulesDomainSuffix,
                ));
            }
            if rule.port.is_some() {
                return Err(ConfigError::semantic(ConfigField::DnsRouteRulesPort));
            }
            if rule.port_range.is_some() {
                return Err(ConfigError::semantic(ConfigField::DnsRouteRulesPortRange));
            }
        }
        PreparedDnsRole::Server => {
            if rule.qname.is_some() {
                return Err(ConfigError::semantic(ConfigField::DnsRouteRulesQname));
            }
            if rule.qname_suffix.is_some() {
                return Err(ConfigError::semantic(ConfigField::DnsRouteRulesQnameSuffix));
            }
            if rule.qtype.is_some() {
                return Err(ConfigError::semantic(ConfigField::DnsRouteRulesQtype));
            }
        }
    }

    let mut query_fields = Vec::new();
    query_fields
        .try_reserve_exact(4)
        .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
    let (exact, suffix) = match role {
        PreparedDnsRole::Client => (
            (rule.qname.as_ref(), ConfigField::DnsRouteRulesQname),
            (
                rule.qname_suffix.as_ref(),
                ConfigField::DnsRouteRulesQnameSuffix,
            ),
        ),
        PreparedDnsRole::Server => (
            (rule.domain.as_ref(), ConfigField::DnsRouteRulesDomain),
            (
                rule.domain_suffix.as_ref(),
                ConfigField::DnsRouteRulesDomainSuffix,
            ),
        ),
    };
    push_prepared_dns_domain_field(
        &mut query_fields,
        exact.0,
        exact.1,
        PreparedDomainField::Exact,
    )?;
    push_prepared_dns_domain_field(
        &mut query_fields,
        suffix.0,
        suffix.1,
        PreparedDomainField::Suffix,
    )?;
    push_prepared_dns_domain_field(
        &mut query_fields,
        rule.domain_keyword.as_ref(),
        ConfigField::DnsRouteRulesDomainKeyword,
        PreparedDomainField::Keyword,
    )?;

    let listeners = dns.inbounds.as_deref().unwrap_or(&[]);
    let inbounds = rule
        .inbound
        .as_ref()
        .map(|values| {
            prepare_dns_values(
                values,
                ConfigField::DnsRouteRulesInbound,
                |tag| match role {
                    PreparedDnsRole::Client => listeners
                        .iter()
                        .position(|candidate| candidate.tag == *tag)
                        .or_else(|| {
                            ordinary_inbounds
                                .iter()
                                .position(|candidate| *candidate == tag)
                                .map(|index| listeners.len() + index)
                        })
                        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteRulesInbound)),
                    PreparedDnsRole::Server => ordinary_inbounds
                        .iter()
                        .position(|candidate| *candidate == tag)
                        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteRulesInbound)),
                },
            )
        })
        .transpose()?
        .unwrap_or_default();
    let networks = rule
        .network
        .as_ref()
        .map(|values| {
            prepare_dns_values(
                values,
                ConfigField::DnsRouteRulesNetwork,
                |value| match value.as_str() {
                    "tcp" => Ok(Network::Tcp),
                    "udp" => Ok(Network::Udp),
                    _ => Err(ConfigError::semantic(ConfigField::DnsRouteRulesNetwork)),
                },
            )
        })
        .transpose()?
        .unwrap_or_default();
    let qtypes = rule
        .qtype
        .as_ref()
        .map(|values| {
            prepare_dns_values(values, ConfigField::DnsRouteRulesQtype, |value| {
                parse_dns_record_type(value)
            })
        })
        .transpose()?
        .unwrap_or_default();
    let ports = rule
        .port
        .as_ref()
        .map(|values| {
            prepare_dns_values(values, ConfigField::DnsRouteRulesPort, |value| {
                u16::try_from(*value)
                    .ok()
                    .and_then(NonZeroU16::new)
                    .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteRulesPort))
            })
        })
        .transpose()?
        .unwrap_or_default();
    let port_ranges = rule
        .port_range
        .as_ref()
        .map(|values| {
            prepare_dns_values(values, ConfigField::DnsRouteRulesPortRange, |value| {
                parse_dns_port_range(value)
            })
        })
        .transpose()?
        .unwrap_or_default();

    Ok(PreparedDnsMatcherDraft {
        query_fields,
        inbounds,
        networks,
        qtypes,
        ports,
        port_ranges,
    })
}

#[derive(Clone, Copy)]
pub(super) enum PreparedDomainField {
    Exact,
    Suffix,
    Keyword,
}

pub(super) fn push_prepared_dns_domain_field(
    fields: &mut Vec<Arc<CompiledMatchSet>>,
    raw: Option<&ScalarOrList<String>>,
    field: ConfigField,
    kind: PreparedDomainField,
) -> Result<(), ConfigError> {
    let Some(raw) = raw else {
        return Ok(());
    };
    if raw.len() == 0 {
        return Err(ConfigError::semantic(field));
    }
    let mut builder = MatchSetBuilder::new();
    for value in raw.iter() {
        let domain = DomainName::new(value).map_err(|_| ConfigError::semantic(field))?;
        let result = match kind {
            PreparedDomainField::Exact => builder.add_domain(&domain),
            PreparedDomainField::Suffix => builder.add_domain_suffix_name(&domain),
            PreparedDomainField::Keyword => builder.add_domain_keyword(value),
        };
        result.map_err(|error| map_match_set_error(error, field))?;
    }
    let compiled = builder
        .build()
        .map_err(|error| map_match_set_error(error, field))?;
    fields
        .try_reserve(1)
        .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
    fields.push(Arc::new(compiled));
    Ok(())
}

pub(super) fn map_match_set_error(error: RuleCompileError, field: ConfigField) -> ConfigError {
    ConfigError::from_rule_compile(error, field)
}

pub(super) fn prepare_dns_values<T, U: Eq>(
    raw: &ScalarOrList<T>,
    field: ConfigField,
    mut parse: impl FnMut(&T) -> Result<U, ConfigError>,
) -> Result<Vec<U>, ConfigError> {
    if raw.len() == 0 {
        return Err(ConfigError::semantic(field));
    }
    let mut values = Vec::new();
    values
        .try_reserve_exact(raw.len())
        .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
    for raw in raw.iter() {
        let value = parse(raw)?;
        if values.contains(&value) {
            return Err(ConfigError::semantic(field));
        }
        values.push(value);
    }
    Ok(values)
}

pub(super) fn parse_dns_port_range(value: &str) -> Result<PortRange, ConfigError> {
    let (first, last) = value
        .split_once(':')
        .ok_or_else(|| ConfigError::semantic(ConfigField::DnsRouteRulesPortRange))?;
    let first = first
        .parse::<u16>()
        .map_err(|_| ConfigError::semantic(ConfigField::DnsRouteRulesPortRange))?;
    let last = last
        .parse::<u16>()
        .map_err(|_| ConfigError::semantic(ConfigField::DnsRouteRulesPortRange))?;
    PortRange::try_new(first, last)
        .map_err(|_| ConfigError::semantic(ConfigField::DnsRouteRulesPortRange))
}

pub(super) fn parse_dns_record_type(value: &str) -> Result<u16, ConfigError> {
    match value.to_ascii_uppercase().as_str() {
        "A" => Ok(DnsQueryType::A as u16),
        "AAAA" => Ok(DnsQueryType::Aaaa as u16),
        "CNAME" => Ok(DnsQueryType::Cname as u16),
        "MX" => Ok(DnsQueryType::Mx as u16),
        "NS" => Ok(DnsQueryType::Ns as u16),
        "PTR" => Ok(DnsQueryType::Ptr as u16),
        "SOA" => Ok(DnsQueryType::Soa as u16),
        "SRV" => Ok(DnsQueryType::Srv as u16),
        "TXT" => Ok(DnsQueryType::Txt as u16),
        "CAA" => Ok(DnsQueryType::Caa as u16),
        "SVCB" => Ok(DnsQueryType::Svcb as u16),
        "HTTPS" => Ok(DnsQueryType::Https as u16),
        "ANY" => Ok(DnsQueryType::Any as u16),
        _ => Err(ConfigError::semantic(ConfigField::DnsRouteRulesQtype)),
    }
}

pub(super) fn resolve_rule_set_refs(
    raw: &ScalarOrList<String>,
    rule_sets: &[PreparedRuleSet],
    field: ConfigField,
) -> Result<Vec<usize>, ConfigError> {
    if raw.len() == 0 {
        return Err(ConfigError::semantic(field));
    }
    let mut resolved = Vec::new();
    resolved
        .try_reserve_exact(raw.len())
        .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
    for tag in raw.iter() {
        validate_tag(tag, field)?;
        let index = rule_sets
            .iter()
            .position(|rule_set| rule_set.tag() == tag)
            .ok_or_else(|| ConfigError::semantic(field))?;
        if resolved.contains(&index) {
            return Err(ConfigError::semantic(field));
        }
        resolved.push(index);
    }
    Ok(resolved)
}

pub(super) fn dns_matcher_present(rule: &RawDnsRouteRule) -> bool {
    rule.inbound.is_some()
        || rule.network.is_some()
        || rule.qname.is_some()
        || rule.qname_suffix.is_some()
        || rule.qtype.is_some()
        || rule.domain.is_some()
        || rule.domain_suffix.is_some()
        || rule.domain_keyword.is_some()
        || rule.rule_set.is_some()
        || rule.port.is_some()
        || rule.port_range.is_some()
}
