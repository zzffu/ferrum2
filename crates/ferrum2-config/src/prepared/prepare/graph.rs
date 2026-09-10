use std::net::SocketAddr;

use crate::dependency::{DependencyGraph, DependencyGraphError, DependencyNode, DependencySource};
use crate::error::{ConfigError, ConfigField};
use crate::model::{DirectDomainResolver, ResolverRef};
use crate::raw::{RawDns, RawRoute};

use super::super::PLACEHOLDER_ENDPOINT;
use super::super::model::{
    DialEndpoint, PreparedDependencyNode, PreparedDnsEndpoint, PreparedEgressRef, PreparedRuleSet,
    PreparedRuleSetDownloadMode,
};
use super::draft::{ClientPreparationDraft, ServerPreparationDraft};
use crate::validation::AdmittedEgressGraph;

pub(super) struct DependencyOutboundInput<'a> {
    endpoint: Option<&'a DialEndpoint>,
    direct_domain_resolver: Option<DirectDomainResolver>,
}

pub(super) struct DependencyGraphInput<'a> {
    dns: Option<&'a RawDns>,
    dns_endpoints: &'a [PreparedDnsEndpoint],
    outbounds: Vec<DependencyOutboundInput<'a>>,
    egress: &'a AdmittedEgressGraph,
    rule_sets: &'a [PreparedRuleSet],
}

impl<'a> DependencyGraphInput<'a> {
    pub(super) fn client(
        draft: &'a ClientPreparationDraft,
        rule_sets: &'a [PreparedRuleSet],
    ) -> Self {
        Self {
            dns: draft.raw.dns.as_ref(),
            dns_endpoints: &draft.dns.endpoints,
            outbounds: draft
                .outbounds()
                .iter()
                .map(|outbound| DependencyOutboundInput {
                    endpoint: outbound.endpoint.as_ref(),
                    direct_domain_resolver: outbound.direct_domain_resolver,
                })
                .collect(),
            egress: &draft.egress,
            rule_sets,
        }
    }

    pub(super) fn server(
        draft: &'a ServerPreparationDraft,
        rule_sets: &'a [PreparedRuleSet],
    ) -> Self {
        Self {
            dns: draft.raw.dns.as_ref(),
            dns_endpoints: &draft.dns.endpoints,
            outbounds: draft
                .outbounds()
                .iter()
                .map(|outbound| DependencyOutboundInput {
                    endpoint: None,
                    direct_domain_resolver: Some(outbound.direct_domain_resolver),
                })
                .collect(),
            egress: &draft.egress,
            rule_sets,
        }
    }
}

pub(super) struct DependencyGraphPlan {
    order: Vec<PreparedDependencyNode>,
    dns_servers: Vec<usize>,
}

impl DependencyGraphPlan {
    pub(super) fn dns_servers(&self) -> &[usize] {
        &self.dns_servers
    }

    pub(super) fn into_order(self) -> Vec<PreparedDependencyNode> {
        self.order
    }
}

pub(super) fn build_dependency_plan(
    input: DependencyGraphInput<'_>,
) -> Result<DependencyGraphPlan, ConfigError> {
    let DependencyGraphInput {
        dns,
        dns_endpoints,
        outbounds,
        egress,
        rule_sets,
    } = input;
    let mut graph = DependencyGraph::new();
    let mut dependency_dns_servers = Vec::new();
    graph
        .try_add_node(DependencyNode::system_resolver())
        .map_err(map_dependency_error)?;
    for index in 0..dns_endpoints.len() {
        graph
            .try_add_node(dns_node(index)?)
            .map_err(map_dependency_error)?;
    }
    for index in 0..outbounds.len() {
        graph
            .try_add_node(outbound_node(index)?)
            .map_err(map_dependency_error)?;
    }
    for index in 0..egress.selector_members().len() {
        graph
            .try_add_node(selector_node(index)?)
            .map_err(map_dependency_error)?;
    }
    for index in 0..egress.chain_hops().len() {
        graph
            .try_add_node(chain_node(index)?)
            .map_err(map_dependency_error)?;
    }
    for index in 0..rule_sets.len() {
        graph
            .try_add_node(rule_set_node(index)?)
            .map_err(map_dependency_error)?;
    }

    let raw_dns_servers = dns.and_then(|dns| dns.servers.as_deref()).unwrap_or(&[]);
    if raw_dns_servers.len() != dns_endpoints.len() {
        return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
    }
    for (index, endpoint) in dns_endpoints.iter().enumerate() {
        let from = dns_node(index)?;
        if let Some(resolver) = endpoint.resolver() {
            record_dns_server(resolver, &mut dependency_dns_servers)?;
            graph
                .try_add_edge(
                    from,
                    resolver_node(resolver)?,
                    DependencySource::DnsServerDomainResolver {
                        server: checked_u32(index)?,
                    },
                )
                .map_err(map_dependency_error)?;
        }
        if let Some(detour) = raw_dns_servers
            .get(index)
            .and_then(|server| server.detour.as_deref())
        {
            let detour = egress.resolve(detour, ConfigField::DnsServersDetour)?;
            graph
                .try_add_edge(
                    from,
                    egress_node(detour)?,
                    DependencySource::DnsServerDetour {
                        server: checked_u32(index)?,
                    },
                )
                .map_err(map_dependency_error)?;
        }
    }
    for (index, outbound) in outbounds.iter().enumerate() {
        if let Some(resolver) = outbound.endpoint.and_then(DialEndpoint::resolver) {
            record_dns_server(resolver, &mut dependency_dns_servers)?;
            graph
                .try_add_edge(
                    outbound_node(index)?,
                    resolver_node(resolver)?,
                    DependencySource::OutboundDomainResolver {
                        outbound: checked_u32(index)?,
                    },
                )
                .map_err(map_dependency_error)?;
        }
    }
    for (index, outbound) in outbounds.iter().enumerate() {
        let Some(DirectDomainResolver::DnsServer { server, .. }) = outbound.direct_domain_resolver
        else {
            continue;
        };
        record_dns_server(ResolverRef::DnsServer(server), &mut dependency_dns_servers)?;
        graph
            .try_add_edge(
                outbound_node(index)?,
                dns_node(server)?,
                DependencySource::OutboundDomainResolver {
                    outbound: checked_u32(index)?,
                },
            )
            .map_err(map_dependency_error)?;
    }
    for (index, members) in egress.selector_members().iter().enumerate() {
        let members = members
            .iter()
            .copied()
            .map(egress_node)
            .collect::<Result<Vec<_>, _>>()?;
        graph
            .try_add_selector_members(checked_u64(index)?, members)
            .map_err(map_dependency_error)?;
    }
    for (index, hops) in egress.chain_hops().iter().enumerate() {
        let targets = hops
            .iter()
            .copied()
            .map(outbound_node)
            .collect::<Result<Vec<_>, _>>()?;
        graph
            .try_add_chain_hops(checked_u64(index)?, targets)
            .map_err(map_dependency_error)?;
    }
    for (index, rule_set) in rule_sets.iter().enumerate() {
        let from = rule_set_node(index)?;
        if let PreparedRuleSetDownloadMode::ClientResolved { resolver } = rule_set.download_mode() {
            record_dns_server(resolver, &mut dependency_dns_servers)?;
            graph
                .try_add_edge(
                    from,
                    resolver_node(resolver)?,
                    DependencySource::RuleSetDownloadResolver {
                        rule_set: checked_u32(index)?,
                    },
                )
                .map_err(map_dependency_error)?;
        }
        if let Some(detour) = rule_set.download_detour() {
            graph
                .try_add_edge(
                    from,
                    egress_node(detour)?,
                    DependencySource::RuleSetDownloadDetour {
                        rule_set: checked_u32(index)?,
                    },
                )
                .map_err(map_dependency_error)?;
        }
    }
    let order = graph.topological_order().map_err(map_dependency_error)?;
    Ok(DependencyGraphPlan {
        order: prepare_dependency_order(order)?,
        dns_servers: dependency_dns_servers,
    })
}

fn record_dns_server(resolver: ResolverRef, servers: &mut Vec<usize>) -> Result<(), ConfigError> {
    let ResolverRef::DnsServer(server) = resolver else {
        return Ok(());
    };
    if !servers.contains(&server) {
        servers
            .try_reserve(1)
            .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
        servers.push(server);
    }
    Ok(())
}

pub(super) fn prepare_dependency_order(
    raw: Vec<DependencyNode>,
) -> Result<Vec<PreparedDependencyNode>, ConfigError> {
    let mut prepared = Vec::new();
    prepared
        .try_reserve_exact(raw.len())
        .map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
    prepared.extend(raw.into_iter().map(PreparedDependencyNode::from));
    Ok(prepared)
}

pub(super) fn map_dependency_error(error: DependencyGraphError) -> ConfigError {
    match error {
        DependencyGraphError::Cycle(cycle) => ConfigError::dependency_cycle(cycle.into_path()),
        _ => ConfigError::semantic(ConfigField::ResourceMaterialization),
    }
}

pub(super) fn resolver_node(resolver: ResolverRef) -> Result<DependencyNode, ConfigError> {
    match resolver {
        ResolverRef::System => Ok(DependencyNode::system_resolver()),
        ResolverRef::DnsServer(index) => dns_node(index),
    }
}

pub(super) fn egress_node(egress: PreparedEgressRef) -> Result<DependencyNode, ConfigError> {
    match egress {
        PreparedEgressRef::Outbound(index) => outbound_node(index),
        PreparedEgressRef::Selector(index) => selector_node(index),
        PreparedEgressRef::Chain(index) => chain_node(index),
    }
}

pub(super) fn dns_node(index: usize) -> Result<DependencyNode, ConfigError> {
    DependencyNode::try_dns_server(checked_u64(index)?).map_err(map_dependency_error)
}

pub(super) fn outbound_node(index: usize) -> Result<DependencyNode, ConfigError> {
    DependencyNode::try_outbound(checked_u64(index)?).map_err(map_dependency_error)
}

pub(super) fn selector_node(index: usize) -> Result<DependencyNode, ConfigError> {
    DependencyNode::try_selector(checked_u64(index)?).map_err(map_dependency_error)
}

pub(super) fn chain_node(index: usize) -> Result<DependencyNode, ConfigError> {
    DependencyNode::try_chain(checked_u64(index)?).map_err(map_dependency_error)
}

pub(super) fn rule_set_node(index: usize) -> Result<DependencyNode, ConfigError> {
    DependencyNode::try_rule_set(checked_u64(index)?).map_err(map_dependency_error)
}

pub(super) fn checked_u64(index: usize) -> Result<u64, ConfigError> {
    u64::try_from(index).map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))
}

pub(in crate::prepared) fn checked_u32(index: usize) -> Result<u32, ConfigError> {
    u32::try_from(index).map_err(|_| ConfigError::semantic(ConfigField::ResourceMaterialization))
}

pub(super) fn sanitize_client(draft: &mut ClientPreparationDraft) {
    if let Some(outbounds) = &mut draft.outbounds {
        for outbound in outbounds {
            if outbound
                .raw
                .server
                .as_deref()
                .is_some_and(|server| server.parse::<SocketAddr>().is_err())
            {
                outbound.raw.server = Some(PLACEHOLDER_ENDPOINT.to_owned());
            }
        }
    }
    sanitize_route(draft.raw.route.as_mut());
    sanitize_dns(draft.raw.dns.as_mut());
}

pub(super) fn sanitize_server(draft: &mut ServerPreparationDraft) {
    sanitize_route(draft.raw.route.as_mut());
    sanitize_dns(draft.raw.dns.as_mut());
}

pub(super) fn sanitize_route(route: Option<&mut RawRoute>) {
    let Some(route) = route else {
        return;
    };
    route.rule_set.clear();
}

pub(super) fn sanitize_dns(dns: Option<&mut RawDns>) {
    let Some(dns) = dns else {
        return;
    };
    if let Some(servers) = &mut dns.servers {
        for server in servers {
            if server.address.parse::<SocketAddr>().is_err() {
                server.address = PLACEHOLDER_ENDPOINT.to_owned();
            }
        }
    }
    let Some(route) = &mut dns.route else {
        return;
    };
    for rule in &mut route.rules {
        rule.rule_set = None;
    }
}
