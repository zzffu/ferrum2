use std::path::Path;

use crate::error::{ConfigError, ConfigField};
use crate::load::{parse_v2_toml, read_bounded_utf8};
#[cfg(feature = "fuzzing")]
use crate::model::{ValidatedClientConfig, ValidatedServerConfig};
use crate::raw::{RawChain, RawClientRoot, RawSelector, RawServerRoot};
#[cfg(feature = "fuzzing")]
use crate::validation::finish_client_tun_targets;
use crate::validation::{validate_client_prepared, validate_server_prepared};

#[cfg(feature = "fuzzing")]
use super::super::model::{DialEndpoint, PreparedDnsEndpoint};
use super::super::model::{PreparedClientV2, PreparedEgressRef, PreparedRuleSet, PreparedServerV2};
use super::dns_policy::{PreparedDnsRole, prepare_dns_rules};
use super::draft::{ClientPreparationDraft, ServerPreparationDraft};
use super::graph::{DependencyGraphInput, build_dependency_plan, sanitize_client, sanitize_server};
use super::rule_egress::{
    prepare_egress_capabilities, prepare_route_rule_sets, prepare_rule_set_loader,
    prepare_rule_sets, validate_deferred_dns_detours,
};

/// Reads and prepares a client schema-v2 config without external I/O.
pub fn prepare_client(path: impl AsRef<Path>) -> Result<PreparedClientV2, ConfigError> {
    let source = read_bounded_utf8(path.as_ref())?;
    prepare_client_source(&source)
}

pub(super) fn prepare_client_source(source: &str) -> Result<PreparedClientV2, ConfigError> {
    let raw: RawClientRoot = parse_v2_toml(source)?;
    prepare_client_inner(raw)
}

/// Reads and prepares a server schema-v2 config without external I/O.
pub fn prepare_server(path: impl AsRef<Path>) -> Result<PreparedServerV2, ConfigError> {
    let source = read_bounded_utf8(path.as_ref())?;
    prepare_server_source(&source)
}

pub(super) fn prepare_server_source(source: &str) -> Result<PreparedServerV2, ConfigError> {
    let raw: RawServerRoot = parse_v2_toml(source)?;
    prepare_server_inner(raw)
}

#[cfg(feature = "fuzzing")]
pub(crate) fn validate_client_source(source: &str) -> Result<ValidatedClientConfig, ConfigError> {
    let mut prepared = prepare_client_source(source)?;
    let has_deferred_endpoint = prepared
        .outbound_endpoints
        .iter()
        .flatten()
        .any(DialEndpoint::is_domain)
        || prepared
            .dns_endpoints
            .iter()
            .any(PreparedDnsEndpoint::is_domain);
    if !has_deferred_endpoint {
        finish_client_tun_targets(
            &mut prepared.validated,
            &prepared.physical_first_hops,
            &prepared.direct_detours,
        )?;
    }
    Ok(prepared.validated)
}

#[cfg(feature = "fuzzing")]
pub(crate) fn validate_server_source(source: &str) -> Result<ValidatedServerConfig, ConfigError> {
    prepare_server_source(source).map(|prepared| prepared.validated)
}

pub(super) fn prepared_rule_set_tags(
    rule_sets: &[PreparedRuleSet],
) -> Result<Vec<&str>, ConfigError> {
    let mut tags = Vec::new();
    tags.try_reserve_exact(rule_sets.len())
        .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
    tags.extend(rule_sets.iter().map(PreparedRuleSet::tag));
    Ok(tags)
}

pub(super) struct PreparedEgressDependencies {
    pub(super) tags: Vec<String>,
    pub(super) rule_set_plans: Vec<Option<usize>>,
}

pub(super) fn prepared_dependency_egress(
    rule_sets: &[PreparedRuleSet],
    outbounds: &[&str],
    selectors: &[RawSelector],
    chains: &[RawChain],
) -> Result<PreparedEgressDependencies, ConfigError> {
    let mut tags = Vec::new();
    tags.try_reserve_exact(rule_sets.len())
        .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
    let mut rule_set_plans = Vec::new();
    rule_set_plans
        .try_reserve_exact(rule_sets.len())
        .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
    for rule_set in rule_sets {
        let Some(detour) = rule_set.download_detour() else {
            rule_set_plans.push(None);
            continue;
        };
        let tag = match detour {
            PreparedEgressRef::Outbound(index) => outbounds.get(index).copied(),
            PreparedEgressRef::Selector(index) => {
                selectors.get(index).map(|selector| selector.tag.as_str())
            }
            PreparedEgressRef::Chain(index) => {
                chains.get(index).and_then(|chain| chain.tag.as_deref())
            }
        }
        .ok_or_else(|| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
        let plan = if let Some(plan) = tags.iter().position(|candidate| candidate == tag) {
            plan
        } else {
            tags.push(tag.to_owned());
            tags.len() - 1
        };
        rule_set_plans.push(Some(plan));
    }
    Ok(PreparedEgressDependencies {
        tags,
        rule_set_plans,
    })
}

pub(super) fn prepare_client_inner(raw: RawClientRoot) -> Result<PreparedClientV2, ConfigError> {
    let mut draft = ClientPreparationDraft::new(raw)?;
    let outbound_tags = draft.outbound_tags();
    let selectors = draft.raw.selectors.as_deref().unwrap_or(&[]);
    let chains = draft.raw.chains.as_deref().unwrap_or(&[]);
    let egress_domain_capabilities =
        prepare_egress_capabilities(&outbound_tags, selectors, chains)?;
    let rule_set_loader = prepare_rule_set_loader(draft.raw.rule_set_loader.as_ref())?;
    validate_deferred_dns_detours(
        draft.raw.dns.as_ref(),
        &draft.dns.endpoints,
        &outbound_tags,
        selectors,
        chains,
        &egress_domain_capabilities,
    )?;
    let raw_rule_sets = draft
        .raw
        .route
        .as_ref()
        .map(|route| route.rule_set.as_slice())
        .unwrap_or(&[]);
    let dns_servers = draft
        .raw
        .dns
        .as_ref()
        .and_then(|dns| dns.servers.as_deref())
        .unwrap_or(&[]);
    let rule_sets = prepare_rule_sets(
        raw_rule_sets,
        dns_servers,
        &outbound_tags,
        selectors,
        chains,
        &egress_domain_capabilities,
    )?;
    let route_rule_sets = prepare_route_rule_sets(draft.raw.route.as_ref(), &rule_sets)?;
    let dependency_plan = build_dependency_plan(DependencyGraphInput::client(&draft, &rule_sets))?;
    let ordinary_inbounds = draft
        .raw
        .inbounds
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|inbound| inbound.tag.as_str())
        .chain(draft.raw.tun.as_ref().map(|tun| tun.tag.as_str()))
        .collect::<Vec<_>>();
    let dns_policy = prepare_dns_rules(
        draft.raw.dns.as_ref(),
        &rule_sets,
        draft.dns.strategy,
        PreparedDnsRole::Client,
        &ordinary_inbounds,
    )?;
    let rule_set_tags = prepared_rule_set_tags(&rule_sets)?;
    let dependency_egress =
        prepared_dependency_egress(&rule_sets, &outbound_tags, selectors, chains)?;
    let dependency_egress_tags = dependency_egress
        .tags
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    sanitize_client(&mut draft);
    let validation = validate_client_prepared(
        draft,
        &rule_set_tags,
        &dependency_egress_tags,
        dependency_plan.dns_servers(),
    )?;
    let dependency_order = dependency_plan.into_order();
    Ok(PreparedClientV2 {
        validated: validation.config,
        physical_first_hops: validation.physical_first_hops,
        direct_detours: validation.direct_detours,
        dependency_egress_plans: validation.dependency_egress_plans,
        dependency_egress_direct: validation.dependency_egress_direct,
        rule_set_detour_plans: dependency_egress.rule_set_plans,
        rule_set_loader,
        rule_sets,
        route_rule_sets,
        dns_rules: dns_policy.rules,
        dns_final_server: dns_policy.final_server,
        dns_strategy: validation.dns.strategy,
        dns_cache: validation.dns.cache,
        outbound_endpoints: validation.outbound_endpoints,
        dns_endpoints: validation.dns.endpoints,
        egress_domain_capabilities,
        dependency_order,
    })
}

pub(super) fn prepare_server_inner(raw: RawServerRoot) -> Result<PreparedServerV2, ConfigError> {
    let mut draft = ServerPreparationDraft::new(raw)?;
    let outbound_tags = draft.outbound_tags();
    let selectors = draft.raw.selectors.as_deref().unwrap_or(&[]);
    let egress_domain_capabilities = prepare_egress_capabilities(&outbound_tags, selectors, &[])?;
    let rule_set_loader = prepare_rule_set_loader(draft.raw.rule_set_loader.as_ref())?;
    validate_deferred_dns_detours(
        draft.raw.dns.as_ref(),
        &draft.dns.endpoints,
        &outbound_tags,
        selectors,
        &[],
        &egress_domain_capabilities,
    )?;
    let raw_rule_sets = draft
        .raw
        .route
        .as_ref()
        .map(|route| route.rule_set.as_slice())
        .unwrap_or(&[]);
    let dns_servers = draft
        .raw
        .dns
        .as_ref()
        .and_then(|dns| dns.servers.as_deref())
        .unwrap_or(&[]);
    let rule_sets = prepare_rule_sets(
        raw_rule_sets,
        dns_servers,
        &outbound_tags,
        selectors,
        &[],
        &egress_domain_capabilities,
    )?;
    let route_rule_sets = prepare_route_rule_sets(draft.raw.route.as_ref(), &rule_sets)?;
    let dependency_plan = build_dependency_plan(DependencyGraphInput::server(&draft, &rule_sets))?;
    let ordinary_inbounds = draft
        .raw
        .inbounds
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|inbound| inbound.tag.as_str())
        .collect::<Vec<_>>();
    let dns_policy = prepare_dns_rules(
        draft.raw.dns.as_ref(),
        &rule_sets,
        draft.dns.strategy,
        PreparedDnsRole::Server,
        &ordinary_inbounds,
    )?;
    let rule_set_tags = prepared_rule_set_tags(&rule_sets)?;
    let dependency_egress = prepared_dependency_egress(&rule_sets, &outbound_tags, selectors, &[])?;
    let dependency_egress_tags = dependency_egress
        .tags
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    sanitize_server(&mut draft);
    let validation = validate_server_prepared(
        draft,
        &rule_set_tags,
        &dependency_egress_tags,
        dependency_plan.dns_servers(),
    )?;
    let dependency_order = dependency_plan.into_order();
    Ok(PreparedServerV2 {
        validated: validation.config,
        dependency_egress_plans: validation.dependency_egress_plans,
        dependency_egress_direct: validation.dependency_egress_direct,
        rule_set_detour_plans: dependency_egress.rule_set_plans,
        rule_set_loader,
        rule_sets,
        route_rule_sets,
        dns_rules: dns_policy.rules,
        dns_final_server: dns_policy.final_server,
        dns_strategy: validation.dns.strategy,
        dns_cache: validation.dns.cache,
        dns_endpoints: validation.dns.endpoints,
        egress_domain_capabilities,
        dependency_order,
    })
}
