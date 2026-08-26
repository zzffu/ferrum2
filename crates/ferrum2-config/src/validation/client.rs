use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Arc;

use ferrum2_rule::{EgressPlanHandle, SelectorControl};

use crate::error::{ConfigError, ConfigField};
use crate::model::{
    ClientDnsRoute, ClientInboundConfig, ClientOutboundConfig, ValidatedClientConfig,
};
use crate::prepared::{ClientOutboundDraft, ClientPreparationDraft, PreparedDnsDraft};
use crate::raw::{RawChain, RawClientInbound, RawSelector};

use super::common::{
    DnsRole, DnsValidationContext, GraphValidation, dns_detour_tags, parse_endpoint, parse_method,
    parse_psk, parse_socket, validate_count, validate_dns, validate_logging, validate_metrics,
    validate_runtime, validate_tag, validate_udp,
};
use super::graph::{
    compile_graph_roots, validate_chains, validate_outbound_dial_options, validate_route_network,
};
use super::tun::validate_tun;
use super::v2;

pub(crate) struct PreparedClientValidation {
    pub(crate) config: ValidatedClientConfig,
    pub(crate) physical_first_hops: Vec<usize>,
    pub(crate) direct_detours: Vec<bool>,
    pub(crate) dependency_egress_plans: Vec<EgressPlanHandle>,
    pub(crate) dependency_egress_direct: Vec<bool>,
    pub(crate) outbound_endpoints: Vec<Option<crate::prepared::DialEndpoint>>,
    pub(crate) dns: PreparedDnsDraft,
}

pub(crate) fn validate_client_prepared(
    draft: ClientPreparationDraft,
    rule_set_tags: &[&str],
    dependency_egress_tags: &[&str],
    dependency_dns_servers: &[usize],
) -> Result<PreparedClientValidation, ConfigError> {
    let global_tags = draft.global_tags();
    let ClientPreparationDraft {
        mut raw,
        dns: prepared_dns,
        outbounds: prepared_outbounds,
    } = draft;
    let schema_version = v2::validate_version(raw.schema_version)?;
    let route_network = validate_route_network(raw.route.as_ref())?;
    let socks_inbound_count = raw.inbounds.as_deref().map_or(0, <[RawClientInbound]>::len);
    let tun = raw.tun.take().map(validate_tun).transpose()?;
    if let Some(tun) = &tun {
        raw.inbounds
            .get_or_insert_with(Vec::new)
            .push(RawClientInbound {
                tag: tun.tag.clone(),
                listen: "0.0.0.0:0".to_owned(),
                outbound: tun.outbound.clone(),
            });
    }
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
    let explicit_route = raw.route.is_some();
    let route_draft = v2::compile_route_draft(v2::RouteDraftInput {
        raw: raw.route.as_ref(),
        inbounds: &route_inbounds,
        rule_set_tags,
        role: v2::Role::Client,
        tun_inbound: tun.as_ref().map(|_| socks_inbound_count),
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
    let ValidatedClientGraph {
        inbounds,
        outbounds,
        selector,
        mut roots,
        physical_first_hops,
        mut direct_detours,
        outbound_endpoints,
    } = validate_client_graph(ClientGraphInput {
        tagged_inbounds: raw.inbounds,
        tagged_outbounds: prepared_outbounds,
        chains: raw.chains,
        selectors: raw.selectors,
        validation: GraphValidation {
            route_roots: &route_roots,
            detour_tags: &detour_tags,
            retained_client_inbounds: socks_inbound_count,
            explicit_route,
        },
    })?;
    if roots.len() < route_roots.len()
        || direct_detours.len() != detour_tags.len()
        || roots.len() - route_roots.len() != detour_tags.len()
    {
        return Err(ConfigError::semantic(ConfigField::ResourceMaterialization));
    }
    let dns_direct_detours = direct_detours.split_off(dependency_egress_tags.len());
    let mut detours = roots.split_off(route_roots.len());
    let dns_detours = detours.split_off(dependency_egress_tags.len());
    let route = route_draft.finish(roots, selector)?;
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
            global_tags: &global_tags,
            ordinary_listens: &ordinary_listens,
            outbound_servers: &outbound_servers,
            dependency_servers: dependency_dns_servers,
        },
        dns_detours,
    )?;
    if tun.as_ref().is_some_and(|tun| tun.config.auto_dns) && dns.is_none() {
        return Err(ConfigError::semantic(ConfigField::TunAutoDns));
    }
    let dns_route = dns_route_raw.as_ref().map(|dns| ClientDnsRoute {
        listener_count: dns.inbounds.as_deref().map_or(0, <[_]>::len),
        ordinary_count: route_inbounds.len(),
        rule_count: dns.route.as_ref().map_or(0, |route| route.rules.len()),
        policy_blueprint: None,
    });
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
    Ok(PreparedClientValidation {
        config: ValidatedClientConfig {
            schema_version,
            inbounds,
            outbounds,
            route,
            route_network,
            tun: tun.map(|tun| tun.config),
            dns,
            dns_route,
            runtime,
            udp,
            logging,
            metrics,
        },
        physical_first_hops,
        direct_detours: dns_direct_detours,
        dependency_egress_plans: detours,
        dependency_egress_direct: direct_detours,
        outbound_endpoints,
        dns: prepared_dns,
    })
}

pub(super) struct ClientGraphInput<'a> {
    tagged_inbounds: Option<Vec<RawClientInbound>>,
    tagged_outbounds: Option<Vec<ClientOutboundDraft>>,
    chains: Option<Vec<RawChain>>,
    selectors: Option<Vec<RawSelector>>,
    validation: GraphValidation<'a>,
}

pub(super) struct ValidatedClientGraph {
    inbounds: Vec<ClientInboundConfig>,
    outbounds: Vec<ClientOutboundConfig>,
    selector: SelectorControl,
    roots: Vec<EgressPlanHandle>,
    physical_first_hops: Vec<usize>,
    direct_detours: Vec<bool>,
    outbound_endpoints: Vec<Option<crate::prepared::DialEndpoint>>,
}

pub(super) fn validate_client_graph(
    input: ClientGraphInput<'_>,
) -> Result<ValidatedClientGraph, ConfigError> {
    let ClientGraphInput {
        tagged_inbounds,
        tagged_outbounds,
        chains,
        selectors,
        validation,
    } = input;
    let GraphValidation {
        route_roots,
        detour_tags,
        retained_client_inbounds: socks_inbound_count,
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
    for (index, outbound) in outbounds.iter().enumerate() {
        validate_tag(&outbound.tag, ConfigField::OutboundsTag)?;
        if inbounds.iter().any(|inbound| inbound.tag == outbound.tag)
            || outbounds[..index]
                .iter()
                .any(|other| other.tag == outbound.tag)
        {
            return Err(ConfigError::semantic(ConfigField::OutboundsTag));
        }
        let dial_options = validate_outbound_dial_options(
            outbound.raw.bind_interface.as_deref(),
            outbound.raw.inet4_bind_address.as_deref(),
            outbound.raw.inet6_bind_address.as_deref(),
        )?;
        match outbound
            .raw
            .outbound_type
            .as_deref()
            .ok_or_else(|| ConfigError::semantic(ConfigField::OutboundsType))?
        {
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
                let domain_resolver = outbound
                    .direct_domain_resolver
                    .ok_or_else(|| ConfigError::semantic(ConfigField::ResourceMaterialization))?;
                validated_outbounds.push(ClientOutboundConfig::Direct {
                    domain_resolver,
                    dial_options,
                });
            }
            "shadowsocks" => {
                let method = outbound
                    .method
                    .as_deref()
                    .ok_or_else(|| ConfigError::semantic(ConfigField::OutboundsMethod))?;
                let psk = outbound
                    .psk
                    .as_ref()
                    .ok_or_else(|| ConfigError::semantic(ConfigField::OutboundsPsk))?;
                let method = parse_method(method, ConfigField::OutboundsMethod)?;
                let psk = Arc::new(parse_psk(method, psk, ConfigField::OutboundsPsk)?);
                let server = parse_socket(
                    outbound
                        .server
                        .as_deref()
                        .ok_or_else(|| ConfigError::semantic(ConfigField::OutboundsServer))?,
                    ConfigField::OutboundsServer,
                )?;
                if listens
                    .iter()
                    .any(|listen| SocketAddr::V4(*listen) == server)
                {
                    return Err(ConfigError::semantic(ConfigField::OutboundsServer));
                }
                validated_outbounds.push(ClientOutboundConfig::Shadowsocks {
                    server,
                    psk,
                    dial_options,
                });
            }
            _ => return Err(ConfigError::semantic(ConfigField::OutboundsType)),
        }
    }

    let plans = validate_chains(
        chains.as_deref(),
        &inbounds,
        &outbounds,
        &validated_outbounds,
        selectors.as_deref(),
    )?;
    for (index, tag) in route_roots.iter().copied().enumerate() {
        if !outbounds.iter().any(|outbound| outbound.tag == tag)
            && !chains
                .as_deref()
                .is_some_and(|chains| chains.iter().any(|chain| chain.tag.as_deref() == Some(tag)))
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
            && !chains.as_deref().is_some_and(|chains| {
                chains
                    .iter()
                    .any(|chain| chain.tag.as_deref() == Some(*tag))
            })
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
    let extra_roots = graph_roots.as_slice();
    let ordinary_roots = route_roots
        .iter()
        .map(|tag| (*tag).to_owned())
        .collect::<Vec<_>>();
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
        &plans,
        extra_roots,
        explicit_route,
    )?;
    let validated_inbounds = listens
        .into_iter()
        .take(socks_inbound_count)
        .map(|listen| ClientInboundConfig { listen })
        .collect::<Vec<_>>();
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
                            Some(&outbound.tag) == chain.hops.as_ref().and_then(|hops| hops.first())
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
                matches!(
                    validated_outbounds[*index],
                    ClientOutboundConfig::Direct { .. }
                )
            })
        })
        .collect();
    let mut physical_first_hops = ordinary_roots
        .iter()
        .map(String::as_str)
        .chain(detour_tags.iter().copied())
        .flat_map(first_hops)
        .collect::<Vec<_>>();
    physical_first_hops.sort_unstable();
    physical_first_hops.dedup();
    let outbound_endpoints = outbounds
        .into_iter()
        .map(|outbound| outbound.endpoint)
        .collect();
    Ok(ValidatedClientGraph {
        inbounds: validated_inbounds,
        outbounds: validated_outbounds,
        selector,
        roots: detours,
        physical_first_hops,
        direct_detours,
        outbound_endpoints,
    })
}
