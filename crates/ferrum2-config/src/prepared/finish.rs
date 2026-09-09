use std::net::SocketAddr;
use std::sync::Arc;

use ferrum2_rule::{
    DnsPolicyActionDescriptor, DnsPolicyAddressStrategy, DnsPolicyBlueprint,
    DnsPolicyBlueprintError, DnsPolicyMatcherDescriptor, DnsPolicyRouteDescriptor,
    DnsPolicyRuleDescriptor, RuleEngineRegistry, RuleEngineSnapshotBuilder, RuleSetId,
};

use crate::error::{ConfigError, ConfigField};
use crate::model::{
    ClientOutboundConfig, DnsEndpointMode, DnsStrategy, ValidatedClientConfig,
    ValidatedServerConfig,
};
use crate::validation::{finish_client_tun_targets, validate_finished_client_endpoints};

use super::MAX_RESOLVED_DNS_CANDIDATES;
use super::model::{
    DialEndpoint, PreparedClientV2, PreparedDnsAction, PreparedDnsEndpoint,
    PreparedDnsEndpointMode, PreparedDnsRule, PreparedRuleSet, PreparedServerV2,
};
use super::prepare::checked_u32;
use super::resources::{
    ClientV2Resources, CompiledRuleSetResource, ResolvedDnsEndpoint, ResolvedOutboundEndpoint,
    ServerV2Resources,
};

/// Finishes a prepared client using only already materialized resources.
///
/// This function performs no DNS, filesystem, socket, task, or listener I/O.
pub fn finish_client_v2(
    mut prepared: PreparedClientV2,
    resources: ClientV2Resources,
) -> Result<ValidatedClientConfig, ConfigError> {
    apply_outbound_resources(
        &mut prepared.validated.outbounds,
        &prepared.outbound_endpoints,
        &resources.outbound_endpoints,
    )?;
    apply_dns_resources(
        prepared.validated.dns.as_mut(),
        &prepared.dns_endpoints,
        &resources.dns_endpoints,
    )?;
    validate_finished_client_endpoints(&prepared.validated, &prepared.direct_detours)?;
    let registry = build_rule_registry(&prepared.rule_sets, resources.rule_sets)?;
    attach_rule_registry(&mut prepared.validated, registry.clone())?;
    attach_client_dns_blueprint(
        &mut prepared.validated,
        &prepared.dns_rules,
        prepared.dns_final_server,
        prepared.dns_strategy,
        registry,
    )?;
    finish_client_tun_targets(
        &mut prepared.validated,
        &prepared.physical_first_hops,
        &prepared.direct_detours,
    )?;
    Ok(prepared.validated)
}

/// Finishes a prepared server using only already materialized resources.
///
/// This function performs no DNS, filesystem, socket, task, or listener I/O.
pub fn finish_server_v2(
    mut prepared: PreparedServerV2,
    resources: ServerV2Resources,
) -> Result<ValidatedServerConfig, ConfigError> {
    apply_dns_resources(
        prepared.validated.dns.as_mut(),
        &prepared.dns_endpoints,
        &resources.dns_endpoints,
    )?;
    let registry = build_rule_registry(&prepared.rule_sets, resources.rule_sets)?;
    attach_rule_registry(&mut prepared.validated, registry.clone())?;
    attach_server_dns_blueprint(
        &mut prepared.validated,
        &prepared.dns_rules,
        prepared.dns_final_server,
        prepared.dns_strategy,
        registry,
    )?;
    Ok(prepared.validated)
}

pub(super) fn attach_client_dns_blueprint(
    validated: &mut ValidatedClientConfig,
    rules: &[PreparedDnsRule],
    final_server: Option<usize>,
    strategy: Option<DnsStrategy>,
    registry: Option<Arc<RuleEngineRegistry>>,
) -> Result<(), ConfigError> {
    let (route, final_server) = match (validated.dns_route.as_mut(), final_server) {
        (None, None) if rules.is_empty() => return Ok(()),
        (Some(route), Some(final_server)) => (route, final_server),
        _ => return Err(ConfigError::semantic(ConfigField::ResourceMaterialization)),
    };
    let registry = registry.map_or_else(empty_rule_registry, Ok)?;
    let blueprint = build_dns_policy_blueprint(
        rules,
        final_server,
        strategy.unwrap_or(DnsStrategy::PreferIpv4),
        &registry,
    )?;
    route.attach_policy_blueprint(blueprint, registry);
    Ok(())
}

pub(super) fn attach_server_dns_blueprint(
    validated: &mut ValidatedServerConfig,
    rules: &[PreparedDnsRule],
    final_server: Option<usize>,
    strategy: Option<DnsStrategy>,
    registry: Option<Arc<RuleEngineRegistry>>,
) -> Result<(), ConfigError> {
    let (route, final_server) = match (validated.dns_route.as_mut(), final_server) {
        (None, None) if rules.is_empty() => return Ok(()),
        (Some(route), Some(final_server)) => (route, final_server),
        _ => return Err(ConfigError::semantic(ConfigField::ResourceMaterialization)),
    };
    let registry = registry.map_or_else(empty_rule_registry, Ok)?;
    let blueprint = build_dns_policy_blueprint(
        rules,
        final_server,
        strategy.unwrap_or(DnsStrategy::PreferIpv4),
        &registry,
    )?;
    route.attach_policy_blueprint(blueprint, registry);
    Ok(())
}

pub(super) fn empty_rule_registry() -> Result<Arc<RuleEngineRegistry>, ConfigError> {
    let snapshot = RuleEngineSnapshotBuilder::new(0).build().map_err(|error| {
        ConfigError::from_rule_compile(error, ConfigField::ResourceMaterialization)
    })?;
    Ok(Arc::new(RuleEngineRegistry::new(snapshot)))
}

pub(super) fn build_dns_policy_blueprint(
    prepared: &[PreparedDnsRule],
    final_server: usize,
    final_strategy: DnsStrategy,
    registry: &Arc<RuleEngineRegistry>,
) -> Result<DnsPolicyBlueprint, ConfigError> {
    let snapshot = registry.snapshot();
    let mut rules = Vec::new();
    rules
        .try_reserve_exact(prepared.len())
        .map_err(|_| ConfigError::rule_allocation(ConfigField::DnsRouteRules))?;
    for prepared in prepared {
        let mut rule_sets = Vec::new();
        rule_sets
            .try_reserve_exact(prepared.rule_sets.len())
            .map_err(|_| ConfigError::rule_allocation(ConfigField::DnsRouteRulesRuleSet))?;
        for &rule_set in &prepared.rule_sets {
            let rule_set = RuleSetId::from_raw(checked_u32(rule_set)?);
            if snapshot.rule_set(rule_set).is_none() {
                return Err(ConfigError::semantic(ConfigField::DnsRouteRulesRuleSet));
            }
            rule_sets.push(rule_set);
        }
        let matcher = DnsPolicyMatcherDescriptor::try_new(
            prepared.matcher.query_fields.clone(),
            rule_sets,
            prepared.matcher.inbounds.clone(),
            prepared.matcher.networks.clone(),
            prepared.matcher.qtypes.clone(),
            prepared.matcher.ports.clone(),
            prepared.matcher.port_ranges.clone(),
        )
        .map_err(map_dns_policy_blueprint_error)?;
        let action = match prepared.action {
            PreparedDnsAction::Route { server } => {
                DnsPolicyActionDescriptor::Route(DnsPolicyRouteDescriptor::new(
                    checked_u32(server)?,
                    dns_policy_strategy(prepared.strategy),
                ))
            }
            PreparedDnsAction::Reject => DnsPolicyActionDescriptor::Reject,
        };
        rules.push(DnsPolicyRuleDescriptor::new(matcher, action));
    }
    let final_route = DnsPolicyRouteDescriptor::new(
        checked_u32(final_server)?,
        dns_policy_strategy(final_strategy),
    );
    DnsPolicyBlueprint::try_new(rules, final_route, &snapshot)
        .map_err(map_dns_policy_blueprint_error)
}

pub(super) const fn dns_policy_strategy(strategy: DnsStrategy) -> DnsPolicyAddressStrategy {
    match strategy {
        DnsStrategy::PreferIpv4 => DnsPolicyAddressStrategy::PreferIpv4,
        DnsStrategy::PreferIpv6 => DnsPolicyAddressStrategy::PreferIpv6,
        DnsStrategy::Ipv4Only => DnsPolicyAddressStrategy::Ipv4Only,
        DnsStrategy::Ipv6Only => DnsPolicyAddressStrategy::Ipv6Only,
    }
}

pub(super) fn map_dns_policy_blueprint_error(error: DnsPolicyBlueprintError) -> ConfigError {
    match error {
        DnsPolicyBlueprintError::UnknownRuleSet => {
            ConfigError::semantic(ConfigField::DnsRouteRulesRuleSet)
        }
        DnsPolicyBlueprintError::ResponseDependentReject => {
            ConfigError::semantic(ConfigField::DnsRouteRulesAction)
        }
        DnsPolicyBlueprintError::EmptyRule
        | DnsPolicyBlueprintError::InvalidQueryMatchSet
        | DnsPolicyBlueprintError::DuplicateConstraint => {
            ConfigError::semantic(ConfigField::DnsRouteRules)
        }
        DnsPolicyBlueprintError::IndexOverflow => {
            ConfigError::rule_allocation(ConfigField::DnsRouteRules)
        }
    }
}

pub(super) fn attach_rule_registry<T: ValidatedRoute>(
    validated: &mut T,
    registry: Option<Arc<RuleEngineRegistry>>,
) -> Result<(), ConfigError> {
    let Some(registry) = registry else {
        return Ok(());
    };
    validated.route_mut().attach_rule_registry(registry);
    Ok(())
}

pub(super) trait ValidatedRoute {
    fn route_mut(&mut self) -> &mut crate::model::CompiledRoute;
}

impl ValidatedRoute for ValidatedClientConfig {
    fn route_mut(&mut self) -> &mut crate::model::CompiledRoute {
        &mut self.route
    }
}

impl ValidatedRoute for ValidatedServerConfig {
    fn route_mut(&mut self) -> &mut crate::model::CompiledRoute {
        &mut self.route
    }
}

pub(super) fn build_rule_registry(
    declarations: &[PreparedRuleSet],
    resource: Option<CompiledRuleSetResource>,
) -> Result<Option<Arc<RuleEngineRegistry>>, ConfigError> {
    let Some(resource) = resource else {
        return if declarations.is_empty() {
            Ok(None)
        } else {
            Err(ConfigError::semantic(ConfigField::ResourceMaterialization))
        };
    };
    if declarations.len() != resource.rule_set_ids.len() {
        return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
    }
    let snapshot = resource.registry.snapshot();
    for (index, declaration) in declarations.iter().enumerate() {
        let rule_set = resource.rule_set_ids[index];
        let expected = checked_u32(index)?;
        let Some(descriptor) = snapshot.rule_set(rule_set) else {
            return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
        };
        if rule_set.raw() != expected || descriptor.tag() != declaration.tag() {
            return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
        }
    }
    Ok(Some(resource.registry))
}

pub(super) fn apply_outbound_resources(
    validated: &mut [ClientOutboundConfig],
    expected: &[Option<DialEndpoint>],
    resources: &[ResolvedOutboundEndpoint],
) -> Result<(), ConfigError> {
    if validated.len() != expected.len()
        || resources.len()
            != expected
                .iter()
                .filter(|endpoint| endpoint.as_ref().is_some_and(DialEndpoint::is_domain))
                .count()
    {
        return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
    }
    let mut resources = resources.iter();
    for (index, expected) in expected.iter().enumerate() {
        let validated = &mut validated[index];
        match (validated, expected) {
            (ClientOutboundConfig::Direct { .. }, None) => {}
            (
                ClientOutboundConfig::Shadowsocks { server, .. },
                Some(DialEndpoint::Ip(expected)),
            ) if server == expected => {}
            (
                ClientOutboundConfig::Shadowsocks { server, .. },
                Some(endpoint @ DialEndpoint::Domain { .. }),
            ) => {
                let resource = resources
                    .next()
                    .ok_or_else(|| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
                if resource.outbound != checked_u32(index)? {
                    return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
                }
                validate_selected_endpoint(endpoint, resource.address)?;
                *server = resource.address;
            }
            _ => return Err(ConfigError::semantic(ConfigField::ResourceMaterialization)),
        }
    }
    if resources.next().is_some() {
        return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
    }
    Ok(())
}

pub(super) fn apply_dns_resources(
    validated: Option<&mut crate::model::DnsConfig>,
    expected: &[PreparedDnsEndpoint],
    resources: &[ResolvedDnsEndpoint],
) -> Result<(), ConfigError> {
    let validated = match (validated, expected.is_empty()) {
        (None, true) => {
            if resources.is_empty() {
                return Ok(());
            }
            return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
        }
        (Some(validated), _) => validated,
        (None, false) => {
            return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
        }
    };
    if validated.servers.len() != expected.len()
        || resources.len()
            != expected
                .iter()
                .filter(|endpoint| {
                    matches!(
                        endpoint.mode(),
                        PreparedDnsEndpointMode::ClientResolved { .. }
                    )
                })
                .count()
    {
        return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
    }
    let mut resources = resources.iter();
    for (index, expected) in expected.iter().enumerate() {
        let validated = &mut validated.servers[index];
        match expected.mode() {
            PreparedDnsEndpointMode::Numeric if validated.target == *expected.target() => {
                validated.resolved_targets = Box::new([]);
                validated.endpoint_mode = DnsEndpointMode::Numeric;
            }
            PreparedDnsEndpointMode::ClientResolved { .. } => {
                let resource = resources
                    .next()
                    .ok_or_else(|| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
                if resource.server != checked_u32(index)? {
                    return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
                }
                let fixed_endpoint = expected
                    .fixed_endpoint()
                    .ok_or_else(|| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
                if resource.addresses.is_empty()
                    || resource.addresses.len() > MAX_RESOLVED_DNS_CANDIDATES
                {
                    return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
                }
                for &address in &resource.addresses {
                    validate_selected_endpoint(fixed_endpoint, address)?;
                }
                validated.target = expected.target().clone();
                validated.resolved_targets = resource.addresses.clone();
                let PreparedDnsEndpointMode::ClientResolved { resolver, strategy } =
                    expected.mode()
                else {
                    unreachable!("matched client-resolved DNS endpoint")
                };
                validated.endpoint_mode = DnsEndpointMode::ClientResolved { resolver, strategy };
            }
            PreparedDnsEndpointMode::DeferredToDetour => {
                validated.target = expected.target().clone();
                validated.resolved_targets = Box::new([]);
                validated.endpoint_mode = DnsEndpointMode::DeferredToDetour;
            }
            PreparedDnsEndpointMode::Numeric => {
                return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
            }
        }
    }
    if resources.next().is_some() {
        return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
    }
    Ok(())
}

pub(super) fn validate_selected_endpoint(
    expected: &DialEndpoint,
    selected: SocketAddr,
) -> Result<(), ConfigError> {
    let DialEndpoint::Domain { port, strategy, .. } = expected else {
        return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
    };
    if selected.port() != port.get()
        || matches!(strategy, DnsStrategy::Ipv4Only) && !selected.is_ipv4()
        || matches!(strategy, DnsStrategy::Ipv6Only) && !selected.is_ipv6()
    {
        return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
    }
    Ok(())
}
