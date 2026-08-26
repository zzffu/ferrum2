use std::ops::Deref;

use crate::error::{ConfigError, ConfigField};
use crate::model::{DirectDomainResolver, DnsStrategy};
use crate::raw::{RawClientOutbound, RawClientRoot, RawServerOutbound, RawServerRoot};
use crate::validation::validate_direct_domain_resolver;

use super::super::model::DialEndpoint;
use super::dns::{EndpointValidation, PreparedDnsDraft, parse_endpoint, prepare_dns};

pub(crate) struct ClientOutboundDraft {
    pub(crate) raw: RawClientOutbound,
    pub(crate) endpoint: Option<DialEndpoint>,
    pub(crate) direct_domain_resolver: Option<DirectDomainResolver>,
}

impl Deref for ClientOutboundDraft {
    type Target = RawClientOutbound;

    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}

pub(crate) struct ServerOutboundDraft {
    pub(crate) raw: RawServerOutbound,
    pub(crate) direct_domain_resolver: DirectDomainResolver,
}

impl Deref for ServerOutboundDraft {
    type Target = RawServerOutbound;

    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}

pub(crate) struct ClientPreparationDraft {
    pub(crate) raw: RawClientRoot,
    pub(crate) dns: PreparedDnsDraft,
    pub(crate) outbounds: Option<Vec<ClientOutboundDraft>>,
}

impl ClientPreparationDraft {
    pub(crate) fn new(mut raw: RawClientRoot) -> Result<Self, ConfigError> {
        let dns = prepare_dns(raw.dns.as_ref())?;
        let outbounds = raw
            .outbounds
            .take()
            .map(|outbounds| {
                outbounds
                    .into_iter()
                    .map(|outbound| {
                        prepare_client_outbound(outbound, raw.dns.as_ref(), dns.strategy)
                    })
                    .collect()
            })
            .transpose()?;
        Ok(Self {
            raw,
            dns,
            outbounds,
        })
    }

    pub(crate) fn outbounds(&self) -> &[ClientOutboundDraft] {
        self.outbounds.as_deref().unwrap_or(&[])
    }

    pub(crate) fn outbound_tags(&self) -> Vec<&str> {
        self.outbounds()
            .iter()
            .map(|outbound| outbound.tag.as_str())
            .collect()
    }

    pub(crate) fn global_tags(&self) -> Vec<String> {
        self.raw
            .inbounds
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|item| item.tag.clone())
            .chain(self.outbounds().iter().map(|item| item.tag.clone()))
            .chain(
                self.raw
                    .chains
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .filter_map(|item| item.tag.clone()),
            )
            .chain(
                self.raw
                    .selectors
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .map(|item| item.tag.clone()),
            )
            .chain(self.raw.tun.iter().map(|tun| tun.tag.clone()))
            .collect()
    }
}

pub(crate) struct ServerPreparationDraft {
    pub(crate) raw: RawServerRoot,
    pub(crate) dns: PreparedDnsDraft,
    pub(crate) outbounds: Option<Vec<ServerOutboundDraft>>,
}

impl ServerPreparationDraft {
    pub(crate) fn new(mut raw: RawServerRoot) -> Result<Self, ConfigError> {
        let dns = prepare_dns(raw.dns.as_ref())?;
        let outbounds = raw
            .outbounds
            .take()
            .map(|outbounds| {
                outbounds
                    .into_iter()
                    .map(|outbound| {
                        prepare_server_outbound(outbound, raw.dns.as_ref(), dns.strategy)
                    })
                    .collect()
            })
            .transpose()?;
        Ok(Self {
            raw,
            dns,
            outbounds,
        })
    }

    pub(crate) fn outbounds(&self) -> &[ServerOutboundDraft] {
        self.outbounds.as_deref().unwrap_or(&[])
    }

    pub(crate) fn outbound_tags(&self) -> Vec<&str> {
        self.outbounds()
            .iter()
            .map(|outbound| outbound.tag.as_str())
            .collect()
    }

    pub(crate) fn global_tags(&self) -> Vec<String> {
        self.raw
            .inbounds
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|item| item.tag.clone())
            .chain(self.outbounds().iter().map(|item| item.tag.clone()))
            .chain(
                self.raw
                    .selectors
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .map(|item| item.tag.clone()),
            )
            .collect()
    }
}

fn prepare_client_outbound(
    raw: RawClientOutbound,
    dns: Option<&crate::raw::RawDns>,
    default_strategy: Option<DnsStrategy>,
) -> Result<ClientOutboundDraft, ConfigError> {
    let servers = dns.and_then(|dns| dns.servers.as_deref()).unwrap_or(&[]);
    let default_strategy = default_strategy.unwrap_or(DnsStrategy::PreferIpv4);
    let (endpoint, direct_domain_resolver) = match raw.outbound_type.as_deref() {
        Some("direct") => (
            None,
            Some(validate_direct_domain_resolver(
                raw.domain_resolver.as_deref(),
                raw.domain_strategy.as_deref(),
                dns,
                default_strategy,
            )?),
        ),
        Some("shadowsocks") => (
            raw.server
                .as_deref()
                .map(|server| {
                    parse_endpoint(
                        server,
                        raw.domain_resolver.as_deref(),
                        raw.domain_strategy.as_deref(),
                        EndpointValidation {
                            default_strategy,
                            dns_servers: servers,
                            endpoint_field: ConfigField::OutboundsServer,
                            resolver_field: ConfigField::OutboundsDomainResolver,
                            strategy_field: ConfigField::OutboundsDomainStrategy,
                        },
                    )
                })
                .transpose()?,
            None,
        ),
        Some(_) | None => (None, None),
    };
    Ok(ClientOutboundDraft {
        raw,
        endpoint,
        direct_domain_resolver,
    })
}

fn prepare_server_outbound(
    raw: RawServerOutbound,
    dns: Option<&crate::raw::RawDns>,
    default_strategy: Option<DnsStrategy>,
) -> Result<ServerOutboundDraft, ConfigError> {
    let direct_domain_resolver = validate_direct_domain_resolver(
        raw.domain_resolver.as_deref(),
        raw.domain_strategy.as_deref(),
        dns,
        default_strategy.unwrap_or(DnsStrategy::PreferIpv4),
    )?;
    Ok(ServerOutboundDraft {
        raw,
        direct_domain_resolver,
    })
}
