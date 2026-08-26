use std::net::IpAddr;
use std::num::NonZeroU16;
use std::path::PathBuf;
use std::time::Duration;

use crate::error::{ConfigError, ConfigField};
use crate::raw::{RawChain, RawDns, RawRoute, RawRuleSet, RawRuleSetLoader, RawSelector};
use crate::validation::validate_tag;

use super::super::model::{
    PreparedDnsEndpoint, PreparedDnsEndpointMode, PreparedEgressCapabilities, PreparedEgressRef,
    PreparedRouteRuleSets, PreparedRuleSet, PreparedRuleSetDownloadMode, RuleSetLoaderConfig,
};
use super::super::{
    DEFAULT_RULE_SET_CACHE_DIR, DEFAULT_RULE_SET_DOWNLOAD_TIMEOUT_MS,
    DEFAULT_RULE_SET_MAX_REDIRECTS,
};
use super::dns::{parse_resolver, valid_domain};
use super::dns_policy::resolve_rule_set_refs;
use super::graph::egress_node;

pub(super) fn prepare_rule_set_loader(
    raw: Option<&RawRuleSetLoader>,
) -> Result<RuleSetLoaderConfig, ConfigError> {
    let cache_dir = raw
        .and_then(|raw| raw.cache_dir.clone())
        .unwrap_or_else(|| PathBuf::from(DEFAULT_RULE_SET_CACHE_DIR));
    if cache_dir.as_os_str().is_empty() {
        return Err(ConfigError::semantic(ConfigField::RuleSetLoaderCacheDir));
    }
    let timeout_ms = raw
        .and_then(|raw| raw.download_timeout_ms)
        .unwrap_or(DEFAULT_RULE_SET_DOWNLOAD_TIMEOUT_MS);
    if !(100..=300_000).contains(&timeout_ms) {
        return Err(ConfigError::semantic(
            ConfigField::RuleSetLoaderDownloadTimeout,
        ));
    }
    let max_redirects = raw
        .and_then(|raw| raw.max_redirects)
        .unwrap_or(DEFAULT_RULE_SET_MAX_REDIRECTS);
    if max_redirects > 20 {
        return Err(ConfigError::semantic(
            ConfigField::RuleSetLoaderMaxRedirects,
        ));
    }
    Ok(RuleSetLoaderConfig {
        cache_dir,
        download_timeout: Duration::from_millis(timeout_ms),
        max_redirects,
    })
}

pub(super) fn prepare_rule_sets(
    raw_rule_sets: &[RawRuleSet],
    dns_servers: &[crate::raw::RawDnsServer],
    outbound_tags: &[&str],
    selectors: &[RawSelector],
    chains: &[RawChain],
    capabilities: &PreparedEgressCapabilities,
) -> Result<Vec<PreparedRuleSet>, ConfigError> {
    let mut prepared = Vec::new();
    prepared
        .try_reserve_exact(raw_rule_sets.len())
        .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
    for (index, raw) in raw_rule_sets.iter().enumerate() {
        let tag = raw
            .tag
            .as_deref()
            .ok_or_else(|| ConfigError::semantic(ConfigField::RouteRuleSetTag))?;
        validate_tag(tag, ConfigField::RouteRuleSetTag)?;
        if matches!(tag, "." | "..") {
            return Err(ConfigError::semantic(ConfigField::RouteRuleSetTag));
        }
        if raw_rule_sets[..index]
            .iter()
            .any(|other| other.tag.as_deref() == Some(tag))
        {
            return Err(ConfigError::semantic(ConfigField::RouteRuleSetTag));
        }
        if raw.rule_set_type.as_deref() != Some("remote") {
            return Err(ConfigError::semantic(ConfigField::RouteRuleSetType));
        }
        if raw
            .format
            .as_deref()
            .is_some_and(|format| format != "binary")
        {
            return Err(ConfigError::semantic(ConfigField::RouteRuleSetFormat));
        }
        let url = raw
            .url
            .as_deref()
            .ok_or_else(|| ConfigError::semantic(ConfigField::RouteRuleSetUrl))?;
        validate_https_srs_url(url, raw.format.is_none())?;
        let download_detour = raw
            .download_detour
            .as_deref()
            .map(|tag| {
                resolve_egress(
                    tag,
                    outbound_tags,
                    selectors,
                    chains,
                    ConfigField::RouteRuleSetDownloadDetour,
                )
            })
            .transpose()?;
        let download_mode = match raw.download_resolver.as_deref() {
            Some(resolver) => PreparedRuleSetDownloadMode::ClientResolved {
                resolver: parse_resolver(
                    resolver,
                    dns_servers,
                    ConfigField::RouteRuleSetDownloadResolver,
                )?,
            },
            None if download_detour.is_some() => PreparedRuleSetDownloadMode::DeferredToDetour,
            None => {
                return Err(ConfigError::dns_resolver_required(
                    ConfigField::RouteRuleSetDownloadResolver,
                ));
            }
        };
        if download_mode == PreparedRuleSetDownloadMode::DeferredToDetour
            && download_detour.and_then(|detour| capabilities.get(detour)) != Some(true)
        {
            return Err(ConfigError::semantic(
                ConfigField::RouteRuleSetDownloadDetour,
            ));
        }
        let update_interval = raw
            .update_interval_seconds
            .map(|seconds| {
                if seconds == 0 {
                    Err(ConfigError::semantic(
                        ConfigField::RouteRuleSetUpdateInterval,
                    ))
                } else {
                    Ok(Duration::from_secs(seconds))
                }
            })
            .transpose()?;
        prepared.push(PreparedRuleSet {
            tag: tag.into(),
            url: url.into(),
            download_mode,
            download_detour,
            update_interval,
        });
    }
    Ok(prepared)
}

pub(super) fn validate_https_srs_url(url: &str, infer_format: bool) -> Result<(), ConfigError> {
    if url.len() > 8_192 || url.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(ConfigError::semantic(ConfigField::RouteRuleSetUrl));
    }
    let remainder = url
        .strip_prefix("https://")
        .ok_or_else(|| ConfigError::semantic(ConfigField::RouteRuleSetUrl))?;
    if remainder.contains('#') {
        return Err(ConfigError::semantic(ConfigField::RouteRuleSetUrl));
    }
    let authority_end = remainder.find(['/', '?']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    if authority.is_empty() || authority.contains('@') || authority.starts_with('[') {
        return Err(ConfigError::semantic(ConfigField::RouteRuleSetUrl));
    }
    let host = if let Some((host, port)) = authority.rsplit_once(':') {
        port.parse::<u16>()
            .ok()
            .and_then(NonZeroU16::new)
            .ok_or_else(|| ConfigError::semantic(ConfigField::RouteRuleSetUrl))?;
        host
    } else {
        authority
    };
    if host.parse::<IpAddr>().is_ok() || !valid_domain(host) {
        return Err(ConfigError::semantic(ConfigField::RouteRuleSetUrl));
    }
    let path = remainder[authority_end..]
        .split_once('?')
        .map_or(&remainder[authority_end..], |(path, _)| path);
    if infer_format && !path.ends_with(".srs") {
        return Err(ConfigError::semantic(ConfigField::RouteRuleSetFormat));
    }
    Ok(())
}

pub(super) fn resolve_egress(
    tag: &str,
    outbound_tags: &[&str],
    selectors: &[RawSelector],
    chains: &[RawChain],
    field: ConfigField,
) -> Result<PreparedEgressRef, ConfigError> {
    validate_tag(tag, field)?;
    if let Some(index) = outbound_tags.iter().position(|candidate| *candidate == tag) {
        return Ok(PreparedEgressRef::Outbound(index));
    }
    if let Some(index) = selectors.iter().position(|candidate| candidate.tag == tag) {
        return Ok(PreparedEgressRef::Selector(index));
    }
    if let Some(index) = chains
        .iter()
        .position(|candidate| candidate.tag.as_deref() == Some(tag))
    {
        return Ok(PreparedEgressRef::Chain(index));
    }
    Err(ConfigError::semantic(field))
}

pub(super) fn prepare_egress_capabilities(
    outbound_tags: &[&str],
    selectors: &[RawSelector],
    chains: &[RawChain],
) -> Result<PreparedEgressCapabilities, ConfigError> {
    let mut evaluator = EgressCapabilityEvaluator::new(outbound_tags, selectors, chains);
    for index in 0..selectors.len() {
        evaluator.evaluate(PreparedEgressRef::Selector(index))?;
        debug_assert!(evaluator.stack.is_empty());
    }
    for index in 0..chains.len() {
        evaluator.evaluate(PreparedEgressRef::Chain(index))?;
        debug_assert!(evaluator.stack.is_empty());
    }
    Ok(evaluator.capabilities)
}

struct EgressCapabilityEvaluator<'a> {
    outbound_tags: &'a [&'a str],
    selectors: &'a [RawSelector],
    chains: &'a [RawChain],
    capabilities: PreparedEgressCapabilities,
    selector_state: Vec<u8>,
    chain_state: Vec<u8>,
    stack: Vec<PreparedEgressRef>,
}

impl<'a> EgressCapabilityEvaluator<'a> {
    fn new(
        outbound_tags: &'a [&'a str],
        selectors: &'a [RawSelector],
        chains: &'a [RawChain],
    ) -> Self {
        Self {
            outbound_tags,
            selectors,
            chains,
            capabilities: PreparedEgressCapabilities {
                outbounds: vec![true; outbound_tags.len()],
                selectors: vec![false; selectors.len()],
                chains: vec![false; chains.len()],
            },
            selector_state: vec![0_u8; selectors.len()],
            chain_state: vec![0_u8; chains.len()],
            stack: Vec::new(),
        }
    }

    fn evaluate(&mut self, egress: PreparedEgressRef) -> Result<bool, ConfigError> {
        match egress {
            PreparedEgressRef::Outbound(index) => self
                .capabilities
                .outbounds
                .get(index)
                .copied()
                .ok_or_else(|| ConfigError::semantic(ConfigField::ResourceMaterialization)),
            PreparedEgressRef::Selector(index) => {
                match self.selector_state.get(index).copied() {
                    Some(2) => return Ok(self.capabilities.selectors[index]),
                    Some(1) => {
                        return Err(capability_cycle_error(&self.stack, egress)?);
                    }
                    Some(0) => {}
                    _ => {
                        return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
                    }
                }
                self.selector_state[index] = 1;
                self.stack
                    .try_reserve(1)
                    .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
                self.stack.push(egress);
                let member_count = self.selectors[index].outbounds.len();
                if member_count == 0 {
                    return Err(ConfigError::semantic(ConfigField::SelectorsOutbounds));
                }
                let mut accepts_domain_target = true;
                for member_index in 0..member_count {
                    let member = resolve_egress(
                        &self.selectors[index].outbounds[member_index],
                        self.outbound_tags,
                        self.selectors,
                        self.chains,
                        ConfigField::SelectorsOutbounds,
                    )?;
                    accepts_domain_target &= self.evaluate(member)?;
                }
                if self.stack.pop() != Some(egress) {
                    return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
                }
                self.capabilities.selectors[index] = accepts_domain_target;
                self.selector_state[index] = 2;
                Ok(accepts_domain_target)
            }
            PreparedEgressRef::Chain(index) => {
                match self.chain_state.get(index).copied() {
                    Some(2) => return Ok(self.capabilities.chains[index]),
                    Some(1) => {
                        return Err(capability_cycle_error(&self.stack, egress)?);
                    }
                    Some(0) => {}
                    _ => {
                        return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
                    }
                }
                self.chain_state[index] = 1;
                self.stack
                    .try_reserve(1)
                    .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
                self.stack.push(egress);
                let terminal = self.chains[index]
                    .hops
                    .as_deref()
                    .and_then(<[String]>::last)
                    .ok_or_else(|| ConfigError::semantic(ConfigField::ChainsHops))?;
                let terminal = resolve_egress(
                    terminal,
                    self.outbound_tags,
                    self.selectors,
                    self.chains,
                    ConfigField::ChainsHops,
                )?;
                let accepts_domain_target = self.evaluate(terminal)?;
                if self.stack.pop() != Some(egress) {
                    return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
                }
                self.capabilities.chains[index] = accepts_domain_target;
                self.chain_state[index] = 2;
                Ok(accepts_domain_target)
            }
        }
    }
}

pub(super) fn capability_cycle_error(
    stack: &[PreparedEgressRef],
    repeated: PreparedEgressRef,
) -> Result<ConfigError, ConfigError> {
    let start = stack
        .iter()
        .position(|candidate| *candidate == repeated)
        .ok_or_else(|| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
    let cycle_len = stack
        .len()
        .checked_sub(start)
        .and_then(|length| length.checked_add(1))
        .ok_or_else(|| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
    let mut path = Vec::new();
    path.try_reserve_exact(cycle_len)
        .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
    for egress in &stack[start..] {
        path.push(egress_node(*egress)?);
    }
    path.push(egress_node(repeated)?);
    Ok(ConfigError::dependency_cycle(path))
}

pub(super) fn validate_deferred_dns_detours(
    dns: Option<&RawDns>,
    endpoints: &[PreparedDnsEndpoint],
    outbound_tags: &[&str],
    selectors: &[RawSelector],
    chains: &[RawChain],
    capabilities: &PreparedEgressCapabilities,
) -> Result<(), ConfigError> {
    let servers = dns.and_then(|dns| dns.servers.as_deref()).unwrap_or(&[]);
    if servers.len() != endpoints.len() {
        return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
    }
    for (index, server) in servers.iter().enumerate() {
        let endpoint = &endpoints[index];
        if endpoint.mode() != PreparedDnsEndpointMode::DeferredToDetour {
            continue;
        }
        let detour = resolve_egress(
            server
                .detour
                .as_deref()
                .ok_or_else(|| ConfigError::semantic(ConfigField::DnsServersDetour))?,
            outbound_tags,
            selectors,
            chains,
            ConfigField::DnsServersDetour,
        )?;
        if capabilities.get(detour) != Some(true) {
            return Err(ConfigError::semantic(ConfigField::DnsServersDetour));
        }
    }
    Ok(())
}

pub(super) fn prepare_route_rule_sets(
    route: Option<&RawRoute>,
    rule_sets: &[PreparedRuleSet],
) -> Result<Vec<PreparedRouteRuleSets>, ConfigError> {
    let Some(route) = route else {
        return Ok(Vec::new());
    };
    let mut prepared = Vec::new();
    for (rule_index, rule) in route.rules.iter().enumerate() {
        let Some(raw_refs) = rule.rule_set.as_ref() else {
            continue;
        };
        if matches!(rule.action.as_deref(), Some("sniff" | "hijack-dns")) {
            return Err(ConfigError::semantic(ConfigField::RouteRulesRuleSet));
        }
        prepared
            .try_reserve(1)
            .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
        prepared.push(PreparedRouteRuleSets {
            rule_index,
            rule_sets: resolve_rule_set_refs(raw_refs, rule_sets, ConfigField::RouteRulesRuleSet)?,
        });
    }
    Ok(prepared)
}
