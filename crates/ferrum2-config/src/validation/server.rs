use ferrum2_rule::{EgressPlanHandle, SelectorControl};

use crate::error::{ConfigError, ConfigField};
use crate::model::{
    ServerDnsRoute, ServerInboundConfig, ServerOutboundConfig, ValidatedServerConfig,
};
use crate::prepared::{PreparedDnsDraft, ServerOutboundDraft, ServerPreparationDraft};
use crate::raw::{RawSelector, RawServerInbound};

use super::common::{
    DnsRole, DnsValidationContext, GraphValidation, dns_detour_tags, parse_endpoint, parse_method,
    parse_psk, validate_count, validate_dns, validate_logging, validate_metrics, validate_replay,
    validate_runtime, validate_tag, validate_udp,
};
use super::graph::{compile_graph_roots, validate_outbound_dial_options, validate_route_network};
use super::v2;

pub(crate) struct PreparedServerValidation {
    pub(crate) config: ValidatedServerConfig,
    pub(crate) dependency_egress_plans: Vec<EgressPlanHandle>,
    pub(crate) dependency_egress_direct: Vec<bool>,
    pub(crate) dns: PreparedDnsDraft,
}

pub(crate) fn validate_server_prepared(
    draft: ServerPreparationDraft,
    rule_set_tags: &[&str],
    dependency_egress_tags: &[&str],
    dependency_dns_servers: &[usize],
) -> Result<PreparedServerValidation, ConfigError> {
    let global_tags = draft.global_tags();
    let ServerPreparationDraft {
        raw,
        dns: prepared_dns,
        outbounds: prepared_outbounds,
    } = draft;
    if raw.tun.is_some() {
        return Err(ConfigError::semantic(ConfigField::Tun));
    }
    let schema_version = v2::validate_version(raw.schema_version)?;
    let route_network = validate_route_network(raw.route.as_ref())?;
    let route_inbounds = raw
        .inbounds
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|inbound| v2::RouteInboundDraft {
            tag: inbound.tag.clone(),
            outbound: inbound.outbound.clone(),
        })
        .collect::<Vec<_>>();
    if raw.chains.is_some() {
        return Err(ConfigError::semantic(ConfigField::Chains));
    }
    let explicit_route = raw.route.is_some();
    let route_draft = v2::compile_route_draft(v2::RouteDraftInput {
        raw: raw.route.as_ref(),
        inbounds: &route_inbounds,
        rule_set_tags,
        role: v2::Role::Server,
        tun_inbound: None,
        has_dns: raw.dns.is_some(),
        max_connections: raw.runtime.max_connections,
    })?;
    let route_roots = route_draft.root_tags();
    let dns_detour_tags = raw.dns.as_ref().map(dns_detour_tags).unwrap_or_default();
    let detour_tags = dependency_egress_tags
        .iter()
        .copied()
        .chain(dns_detour_tags.iter().copied())
        .collect::<Vec<_>>();
    let ValidatedServerGraph {
        inbounds,
        outbounds,
        selector,
        mut roots,
    } = validate_server_graph(ServerGraphInput {
        tagged_inbounds: raw.inbounds,
        tagged_outbounds: prepared_outbounds,
        selectors: raw.selectors,
        validation: GraphValidation {
            route_roots: &route_roots,
            detour_tags: &detour_tags,
            retained_client_inbounds: 0,
            explicit_route,
        },
    })?;
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
        ordinary_count: route_inbounds.len(),
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
        dns: prepared_dns,
    })
}

pub(super) struct ServerGraphInput<'a> {
    tagged_inbounds: Option<Vec<RawServerInbound>>,
    tagged_outbounds: Option<Vec<ServerOutboundDraft>>,
    selectors: Option<Vec<RawSelector>>,
    validation: GraphValidation<'a>,
}

pub(super) struct ValidatedServerGraph {
    inbounds: Vec<ServerInboundConfig>,
    outbounds: Vec<ServerOutboundConfig>,
    selector: SelectorControl,
    roots: Vec<EgressPlanHandle>,
}

pub(super) fn validate_server_graph(
    input: ServerGraphInput<'_>,
) -> Result<ValidatedServerGraph, ConfigError> {
    let ServerGraphInput {
        tagged_inbounds,
        tagged_outbounds,
        selectors,
        validation,
    } = input;
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
    let validated_outbounds = outbounds
        .iter()
        .map(|outbound| {
            Ok(ServerOutboundConfig {
                domain_resolver: outbound.direct_domain_resolver,
                dial_options: validate_outbound_dial_options(
                    outbound.raw.bind_interface.as_deref(),
                    outbound.raw.inet4_bind_address.as_deref(),
                    outbound.raw.inet6_bind_address.as_deref(),
                )?,
            })
        })
        .collect::<Result<Vec<_>, ConfigError>>()?;
    Ok(ValidatedServerGraph {
        inbounds: validated_inbounds,
        outbounds: validated_outbounds,
        selector,
        roots: detours,
    })
}
