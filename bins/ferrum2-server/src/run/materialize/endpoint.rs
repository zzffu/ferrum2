use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferrum2_config::{
    DialEndpoint, DirectDomainResolver, PreparedDnsEndpoint, PreparedDnsEndpointMode,
    PreparedFixedEndpointTarget, PreparedServerV2, ResolvedDnsEndpoint, ResolverRef,
};
use ferrum2_core::TargetAddr;
use ferrum2_dns::{
    DnsAddressRecords, DnsCache, DnsCacheLookup, DnsCacheQtype, DnsError, DnsServerId, DnsStrategy,
    DnsUpstreamSpec, DnsUpstreamTransport, FixedEndpointKind, FixedEndpointLookup,
    FixedEndpointMaterializeError, FixedEndpointPlanEntry, FixedEndpointResolveBackend,
    FixedEndpointResolveFuture, FixedEndpointResolveRequest, FixedEndpointSpec,
    MAX_APPLICATION_RESOLVED_CANDIDATES, MaterializedFixedEndpoint, TaggedResolver,
    TaggedResolverOwner,
};
use ferrum2_observability::{
    DnsQueryType, DnsResolvePurpose, DnsResolveResult, DnsResolverKind, Metrics,
};

use crate::run::dns_egress::{ServerDnsEgress, ServerPhysicalSocketContext};
use crate::run::tcp::ServerNetworkSocketService;
use crate::run::{RunError, runtime_dial_options, runtime_route_network};

use super::UNRESOLVED_ENDPOINT;

struct BootstrapDnsServer {
    transport: ferrum2_config::DnsTransport,
    server_name: Option<Box<str>>,
    path: Option<Box<str>>,
    detour: Option<ferrum2_core::route::EgressPlanHandle>,
    endpoint: PreparedDnsEndpoint,
}

pub(super) struct BootstrapBlueprint {
    dns_servers: Vec<BootstrapDnsServer>,
    timeout: Duration,
    max_inflight: std::num::NonZeroU16,
    strategy: DnsStrategy,
    outbounds: Vec<DirectDomainResolver>,
    physical: Arc<ServerPhysicalSocketContext>,
    metrics: Arc<Metrics>,
}

impl BootstrapBlueprint {
    pub(super) fn new(
        prepared: &PreparedServerV2,
        metrics: Arc<Metrics>,
        network_sockets: Arc<ServerNetworkSocketService>,
    ) -> Result<Self, RunError> {
        let mut dns_servers = Vec::new();
        dns_servers
            .try_reserve_exact(prepared.dns_server_count())
            .map_err(|_| RunError::RuleAllocation)?;
        let mut outbounds = Vec::new();
        outbounds
            .try_reserve_exact(prepared.outbound_count())
            .map_err(|_| RunError::RuleAllocation)?;
        let mut outbound_dial_options = Vec::new();
        outbound_dial_options
            .try_reserve_exact(prepared.outbound_count())
            .map_err(|_| RunError::RuleAllocation)?;
        for index in 0..prepared.outbound_count() {
            let descriptor = prepared
                .outbound(u32::try_from(index).map_err(|_| RunError::StartupProtocol)?)
                .ok_or(RunError::StartupProtocol)?;
            outbounds.push(descriptor.domain_resolver());
            outbound_dial_options.push(runtime_dial_options(descriptor.dial_options()));
        }
        for index in 0..prepared.dns_server_count() {
            let descriptor = prepared
                .dns_server(u32::try_from(index).map_err(|_| RunError::StartupProtocol)?)
                .ok_or(RunError::StartupProtocol)?;
            dns_servers.push(BootstrapDnsServer {
                transport: descriptor.transport(),
                server_name: descriptor.server_name().map(Into::into),
                path: descriptor.path().map(Into::into),
                detour: descriptor.detour().cloned(),
                endpoint: descriptor.endpoint().clone(),
            });
        }
        for (index, _) in prepared.rule_sets().iter().enumerate() {
            if prepared.download_detour_plan(index).is_some()
                && prepared.download_detour_is_direct(index) != Some(true)
            {
                return Err(RunError::StartupProtocol);
            }
        }
        let physical = Arc::new(ServerPhysicalSocketContext::new(
            network_sockets,
            outbound_dial_options.into(),
            Arc::new(runtime_route_network(prepared.route_network())),
            Arc::clone(&metrics),
        ));
        Ok(Self {
            dns_servers,
            timeout: prepared.dns_timeout().unwrap_or(Duration::from_secs(5)),
            max_inflight: prepared
                .dns_max_inflight()
                .unwrap_or(std::num::NonZeroU16::MIN),
            strategy: prepared
                .dns_runtime()
                .map_or(DnsStrategy::PreferIpv4, |runtime| {
                    dns_strategy(runtime.strategy())
                }),
            outbounds,
            physical,
            metrics,
        })
    }

    fn initial_addresses(&self) -> BootstrapAddresses {
        BootstrapAddresses {
            dns: self
                .dns_servers
                .iter()
                .map(|server| {
                    server
                        .endpoint
                        .target()
                        .as_socket_addr()
                        .map(|address| Arc::<[SocketAddr]>::from([address]))
                })
                .collect(),
        }
    }

    fn specs(&self, addresses: &BootstrapAddresses) -> Vec<DnsUpstreamSpec> {
        self.dns_servers
            .iter()
            .enumerate()
            .map(|(index, server)| DnsUpstreamSpec {
                transport: match server.transport {
                    ferrum2_config::DnsTransport::Udp => DnsUpstreamTransport::Udp,
                    ferrum2_config::DnsTransport::Tcp => DnsUpstreamTransport::Tcp,
                    ferrum2_config::DnsTransport::Dot => DnsUpstreamTransport::Dot {
                        server_name: server
                            .server_name
                            .clone()
                            .expect("validated bootstrap DoT name"),
                    },
                    ferrum2_config::DnsTransport::Doh => DnsUpstreamTransport::Doh {
                        server_name: server
                            .server_name
                            .clone()
                            .expect("validated bootstrap DoH name"),
                        path: server.path.clone().expect("validated bootstrap DoH path"),
                    },
                },
                target: bootstrap_dns_target(&server.endpoint, addresses.dns[index].as_deref()),
                resolved_targets: bootstrap_dns_resolved_targets(
                    &server.endpoint,
                    addresses.dns[index].as_deref(),
                ),
                detour: server.detour.clone(),
            })
            .collect()
    }

    fn tagged_resolver(
        &self,
        addresses: &BootstrapAddresses,
    ) -> Result<(Arc<TaggedResolver>, TaggedResolverOwner), RunError> {
        let tagged = Arc::new(std::sync::OnceLock::new());
        let direct_resolvers = self.direct_resolvers(Arc::clone(&tagged));
        self.tagged_resolver_with_slot(addresses, tagged, direct_resolvers)
    }

    pub(super) fn direct_resolvers(
        &self,
        tagged: Arc<std::sync::OnceLock<std::sync::Weak<TaggedResolver>>>,
    ) -> Vec<crate::run::dns_egress::ServerDnsResolver> {
        self.outbounds
            .iter()
            .copied()
            .map(|mode| {
                crate::run::dns_egress::ServerDnsResolver::for_direct_observed(
                    mode,
                    Arc::clone(&tagged),
                    Arc::clone(&self.metrics),
                )
            })
            .collect()
    }

    pub(super) fn tagged_resolver_with_slot(
        &self,
        addresses: &BootstrapAddresses,
        tagged: Arc<std::sync::OnceLock<std::sync::Weak<TaggedResolver>>>,
        direct_resolvers: Vec<crate::run::dns_egress::ServerDnsResolver>,
    ) -> Result<(Arc<TaggedResolver>, TaggedResolverOwner), RunError> {
        let (resolver, owner) = TaggedResolver::new(
            self.specs(addresses),
            self.timeout,
            self.max_inflight,
            Arc::new(
                ServerDnsEgress::new(Arc::clone(&self.physical))
                    .with_outbound_resolvers(direct_resolvers),
            ),
        )
        .map_err(|_| RunError::StartupProtocol)?;
        let resolver = Arc::new(resolver);
        tagged
            .set(Arc::downgrade(&resolver))
            .map_err(|_| RunError::StartupProtocol)?;
        Ok((resolver, owner))
    }

    pub(super) const fn strategy(&self) -> DnsStrategy {
        self.strategy
    }

    pub(super) fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    pub(super) fn physical(&self) -> &Arc<ServerPhysicalSocketContext> {
        &self.physical
    }

    pub(super) fn has_configured_direct_resolver(&self) -> bool {
        self.outbounds
            .iter()
            .any(|resolver| matches!(resolver, DirectDomainResolver::DnsServer { .. }))
    }
}

#[derive(Clone)]
pub(super) struct BootstrapAddresses {
    dns: Vec<Option<Arc<[SocketAddr]>>>,
}

pub(super) struct BootstrapEndpointBackend {
    blueprint: Arc<BootstrapBlueprint>,
    targets: Box<[PreparedFixedEndpointTarget]>,
    next_target: AtomicUsize,
    addresses: Mutex<BootstrapAddresses>,
    metrics: Arc<Metrics>,
}

impl BootstrapEndpointBackend {
    pub(super) fn new(
        blueprint: Arc<BootstrapBlueprint>,
        targets: Vec<PreparedFixedEndpointTarget>,
        metrics: Arc<Metrics>,
    ) -> Self {
        let addresses = blueprint.initial_addresses();
        Self {
            blueprint,
            targets: targets.into_boxed_slice(),
            next_target: AtomicUsize::new(0),
            addresses: Mutex::new(addresses),
            metrics,
        }
    }

    pub(super) fn addresses(&self) -> BootstrapAddresses {
        self.addresses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub(super) fn finished_resources(
        &self,
        prepared: &PreparedServerV2,
    ) -> Result<Vec<ResolvedDnsEndpoint>, RunError> {
        let addresses = self.addresses();
        let mut dns = Vec::new();
        for (index, endpoint) in prepared.dns_endpoints().iter().enumerate() {
            if matches!(
                endpoint.mode(),
                PreparedDnsEndpointMode::ClientResolved { .. }
            ) {
                dns.push(ResolvedDnsEndpoint::from_candidates(
                    u32::try_from(index).map_err(|_| RunError::StartupProtocol)?,
                    addresses.dns[index]
                        .as_deref()
                        .ok_or(RunError::StartupProtocol)?
                        .to_vec()
                        .into_boxed_slice(),
                ));
            }
        }
        Ok(dns)
    }
}

impl FixedEndpointResolveBackend for BootstrapEndpointBackend {
    fn resolve_system<'a>(
        &'a self,
        request: FixedEndpointResolveRequest<'a>,
    ) -> FixedEndpointResolveFuture<'a> {
        Box::pin(async move {
            self.metrics
                .dns_explicit_system_resolve(DnsResolvePurpose::FixedEndpoint);
            let result =
                tokio::time::timeout(self.blueprint.timeout, resolve_system_family(request))
                    .await
                    .map_err(|_| DnsError::Timeout)
                    .and_then(std::convert::identity);
            self.metrics.dns_resolve(
                DnsResolverKind::System,
                DnsResolvePurpose::FixedEndpoint,
                if result.is_ok() {
                    DnsResolveResult::Success
                } else {
                    DnsResolveResult::Failure
                },
            );
            result
        })
    }

    fn resolve_dns_server<'a>(
        &'a self,
        resolver: DnsServerId,
        _resolver_endpoint: &'a MaterializedFixedEndpoint,
        request: FixedEndpointResolveRequest<'a>,
    ) -> FixedEndpointResolveFuture<'a> {
        Box::pin(async move {
            let addresses = self.addresses();
            let (tagged, mut owner) = self
                .blueprint
                .tagged_resolver(&addresses)
                .map_err(|_| DnsError::Runtime)?;
            let result = match owner.ready().await {
                Ok(()) => {
                    tagged
                        .lookup_fixed_endpoint(
                            resolver.get() as usize,
                            request.domain().clone(),
                            request.qtype(),
                        )
                        .await
                }
                Err(error) => Err(error),
            };
            drop(tagged);
            let shutdown = owner.shutdown().await;
            let result = result.and_then(|lookup| shutdown.map(|_| lookup));
            self.metrics.dns_resolve(
                DnsResolverKind::Configured,
                DnsResolvePurpose::FixedEndpoint,
                if result.is_ok() {
                    DnsResolveResult::Success
                } else {
                    DnsResolveResult::Failure
                },
            );
            result
        })
    }

    fn endpoint_materialized(
        &self,
        endpoint: &MaterializedFixedEndpoint,
    ) -> Result<(), FixedEndpointMaterializeError> {
        let position = self.next_target.fetch_add(1, Ordering::AcqRel);
        let target = self
            .targets
            .get(position)
            .ok_or(FixedEndpointMaterializeError::InvalidDependencyOrder)?;
        let mut addresses = self
            .addresses
            .lock()
            .map_err(|_| FixedEndpointMaterializeError::Allocation)?;
        match *target {
            PreparedFixedEndpointTarget::DnsServer(index) => {
                let candidates = Arc::<[SocketAddr]>::from(endpoint.candidates());
                if candidates.is_empty() {
                    return Err(FixedEndpointMaterializeError::NoCandidates);
                }
                *addresses
                    .dns
                    .get_mut(index as usize)
                    .ok_or(FixedEndpointMaterializeError::InvalidDependencyOrder)? =
                    Some(candidates);
            }
            PreparedFixedEndpointTarget::Outbound(_) => {
                return Err(FixedEndpointMaterializeError::InvalidDependencyOrder);
            }
        }
        Ok(())
    }
}

async fn resolve_system_family(
    request: FixedEndpointResolveRequest<'_>,
) -> Result<FixedEndpointLookup, DnsError> {
    let resolved = tokio::net::lookup_host((request.domain().as_str().to_owned(), 0))
        .await
        .map_err(|_| DnsError::Runtime)?;
    match request.qtype() {
        DnsCacheQtype::A => {
            let mut addresses = Vec::new();
            for address in resolved.filter_map(|address| match address.ip() {
                IpAddr::V4(address) => Some(address),
                IpAddr::V6(_) => None,
            }) {
                if !addresses.contains(&address) {
                    addresses.push(address);
                    if addresses.len() == MAX_APPLICATION_RESOLVED_CANDIDATES {
                        break;
                    }
                }
            }
            if addresses.is_empty() {
                Err(DnsError::NoData)
            } else {
                Ok(FixedEndpointLookup::positive(
                    DnsAddressRecords::A(addresses.into()),
                    Duration::ZERO,
                ))
            }
        }
        DnsCacheQtype::Aaaa => {
            let mut addresses = Vec::new();
            for address in resolved.filter_map(|address| match address.ip() {
                IpAddr::V4(_) => None,
                IpAddr::V6(address) => Some(address),
            }) {
                if !addresses.contains(&address) {
                    addresses.push(address);
                    if addresses.len() == MAX_APPLICATION_RESOLVED_CANDIDATES {
                        break;
                    }
                }
            }
            if addresses.is_empty() {
                Err(DnsError::NoData)
            } else {
                Ok(FixedEndpointLookup::positive(
                    DnsAddressRecords::Aaaa(addresses.into()),
                    Duration::ZERO,
                ))
            }
        }
    }
}

pub(super) fn fixed_endpoint_plan(
    prepared: &PreparedServerV2,
) -> Result<
    (
        Vec<FixedEndpointPlanEntry>,
        Vec<PreparedFixedEndpointTarget>,
    ),
    RunError,
> {
    let mut plan = Vec::new();
    let mut targets = Vec::new();
    for &node in prepared.materialization_order() {
        let Some(descriptor) = prepared.fixed_endpoint_for_node(node) else {
            continue;
        };
        let PreparedFixedEndpointTarget::DnsServer(index) = descriptor.target() else {
            return Err(RunError::StartupProtocol);
        };
        plan.push(FixedEndpointPlanEntry::new(
            FixedEndpointKind::DnsServer(DnsServerId::new(index)),
            fixed_endpoint_spec(descriptor.endpoint())?,
        ));
        targets.push(descriptor.target());
    }
    Ok((plan, targets))
}

fn fixed_endpoint_spec(endpoint: &DialEndpoint) -> Result<FixedEndpointSpec, RunError> {
    match endpoint {
        DialEndpoint::Ip(address) => {
            FixedEndpointSpec::ip(*address).map_err(|_| RunError::StartupProtocol)
        }
        DialEndpoint::Domain {
            host,
            port,
            resolver,
            strategy,
        } => Ok(FixedEndpointSpec::domain(
            host.clone(),
            *port,
            match resolver {
                ResolverRef::System => ferrum2_dns::ResolverRef::System,
                ResolverRef::DnsServer(server) => {
                    ferrum2_dns::ResolverRef::DnsServer(DnsServerId::new(
                        u32::try_from(*server).map_err(|_| RunError::StartupProtocol)?,
                    ))
                }
            },
            dns_strategy(*strategy),
        )),
    }
}

fn bootstrap_dns_target(
    endpoint: &PreparedDnsEndpoint,
    materialized: Option<&[SocketAddr]>,
) -> TargetAddr {
    match endpoint.mode() {
        PreparedDnsEndpointMode::Numeric | PreparedDnsEndpointMode::DeferredToDetour => {
            endpoint.target().clone()
        }
        PreparedDnsEndpointMode::ClientResolved { .. } if materialized.is_some() => {
            endpoint.target().clone()
        }
        PreparedDnsEndpointMode::ClientResolved { .. } => {
            TargetAddr::ip(UNRESOLVED_ENDPOINT).expect("non-zero bootstrap placeholder")
        }
    }
}

fn bootstrap_dns_resolved_targets(
    endpoint: &PreparedDnsEndpoint,
    materialized: Option<&[SocketAddr]>,
) -> Box<[SocketAddr]> {
    match endpoint.mode() {
        PreparedDnsEndpointMode::ClientResolved { .. } => materialized.map_or_else(
            || Vec::new().into_boxed_slice(),
            |addresses| addresses.to_vec().into_boxed_slice(),
        ),
        PreparedDnsEndpointMode::Numeric | PreparedDnsEndpointMode::DeferredToDetour => {
            Vec::new().into_boxed_slice()
        }
    }
}

pub(super) fn materialization_cache(
    prepared: &PreparedServerV2,
    metrics: &Arc<Metrics>,
) -> Result<Option<DnsCache>, RunError> {
    let Some(config) = prepared.dns_cache().filter(|config| config.enabled) else {
        return Ok(None);
    };
    let capacity = NonZeroUsize::new(config.max_entries).ok_or(RunError::StartupProtocol)?;
    let metrics = Arc::clone(metrics);
    DnsCache::try_new(capacity)
        .and_then(|cache| {
            cache.try_with_observer(Arc::new(move |qtype, outcome| {
                let qtype = match qtype {
                    DnsCacheQtype::A => DnsQueryType::A,
                    DnsCacheQtype::Aaaa => DnsQueryType::Aaaa,
                };
                match outcome {
                    DnsCacheLookup::Hit => metrics.dns_cache_hit(qtype),
                    DnsCacheLookup::Miss => metrics.dns_cache_miss(qtype),
                }
            }))
        })
        .map(Some)
        .map_err(|_| RunError::StartupProtocol)
}
pub(super) const fn dns_strategy(strategy: ferrum2_config::DnsStrategy) -> DnsStrategy {
    match strategy {
        ferrum2_config::DnsStrategy::PreferIpv4 => DnsStrategy::PreferIpv4,
        ferrum2_config::DnsStrategy::PreferIpv6 => DnsStrategy::PreferIpv6,
        ferrum2_config::DnsStrategy::Ipv4Only => DnsStrategy::Ipv4Only,
        ferrum2_config::DnsStrategy::Ipv6Only => DnsStrategy::Ipv6Only,
    }
}
