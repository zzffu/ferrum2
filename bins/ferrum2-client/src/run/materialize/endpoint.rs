use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::UNRESOLVED_ENDPOINT;
use crate::run::dns_egress::ClientDnsEgress;
use crate::run::egress::{
    ClientEgressEngine, ClientOutboundContext, ClientShadowsocksContext, ClientUdpContext,
    runtime_dial_options, runtime_route_network,
};
use crate::run::{RunError, dns_strategy};
use ferrum2_config::{
    DialEndpoint, DirectDomainResolver, PreparedClientOutboundKind, PreparedClientV2,
    PreparedDnsEndpoint, PreparedDnsEndpointMode, PreparedFixedEndpointTarget, ResolvedDnsEndpoint,
    ResolvedOutboundEndpoint, ResolverRef,
};
use ferrum2_core::TargetAddr;
use ferrum2_core::route::EgressPlanHandle;
use ferrum2_crypto::{MethodPsk, MethodSinglePskProvider, SystemClock, SystemRandom};
use ferrum2_dns::{
    ApplicationResolver, ApplicationResolverAdapter, DnsAddressRecords, DnsCache, DnsCacheLookup,
    DnsCacheQtype, DnsError, DnsServerId, DnsStrategy, DnsUpstreamSpec, DnsUpstreamTransport,
    FixedEndpointKind, FixedEndpointLookup, FixedEndpointMaterializeError, FixedEndpointPlanEntry,
    FixedEndpointResolveBackend, FixedEndpointResolveFuture, FixedEndpointResolveRequest,
    FixedEndpointSpec, MAX_APPLICATION_RESOLVED_CANDIDATES, MaterializedFixedEndpoint,
    TaggedResolver, TaggedResolverOwner, TaggedServerApplicationResolveBackend,
};
use ferrum2_net::{DialOptions, RouteNetworkOptions};
use ferrum2_observability::{DnsResolvePurpose, DnsResolveResult, DnsResolverKind, Metrics};
use ferrum2_runtime::{OwnerRegistry, UdpRuntimeLimits, UdpSessionManager};
use ferrum2_shadowsocks::MethodKeyAdapter;
#[cfg(any(not(windows), test))]
use ferrum2_shadowsocks::tokio::TokioConnector;

pub(super) enum BootstrapOutbound {
    Direct {
        domain_resolver: DirectDomainResolver,
        dial_options: DialOptions,
    },
    Shadowsocks {
        psk: Arc<MethodPsk>,
        endpoint: DialEndpoint,
        dial_options: DialOptions,
    },
}

#[derive(Clone)]
pub(super) struct BootstrapDnsServer {
    transport: ferrum2_config::DnsTransport,
    server_name: Option<Box<str>>,
    path: Option<Box<str>>,
    detour: Option<EgressPlanHandle>,
    endpoint: PreparedDnsEndpoint,
}

pub(super) struct BootstrapBlueprint {
    outbounds: Vec<BootstrapOutbound>,
    route_network: RouteNetworkOptions,
    dns_servers: Vec<BootstrapDnsServer>,
    dns_timeout: Duration,
    dns_max_inflight: std::num::NonZeroU16,
    dns_strategy: DnsStrategy,
    runtime: ferrum2_config::RuntimeConfig,
}

pub(super) struct BootstrapEngine {
    pub(super) engine: Arc<ClientEgressEngine>,
    tagged: Arc<std::sync::OnceLock<std::sync::Weak<TaggedResolver>>>,
}

impl BootstrapBlueprint {
    pub(super) fn new(prepared: &PreparedClientV2) -> Result<Self, RunError> {
        let mut outbounds = Vec::new();
        outbounds
            .try_reserve_exact(prepared.outbound_count())
            .map_err(|_| RunError::RuleAllocation)?;
        for index in 0..prepared.outbound_count() {
            let descriptor = prepared
                .outbound(u32::try_from(index).map_err(|_| RunError::StartupProtocol)?)
                .ok_or(RunError::StartupProtocol)?;
            let dial_options = runtime_dial_options(descriptor.dial_options());
            outbounds.push(match descriptor.kind() {
                PreparedClientOutboundKind::Direct => BootstrapOutbound::Direct {
                    domain_resolver: descriptor
                        .domain_resolver()
                        .ok_or(RunError::StartupProtocol)?,
                    dial_options,
                },
                PreparedClientOutboundKind::Shadowsocks => BootstrapOutbound::Shadowsocks {
                    psk: Arc::clone(descriptor.psk().ok_or(RunError::StartupProtocol)?),
                    endpoint: descriptor
                        .endpoint()
                        .ok_or(RunError::StartupProtocol)?
                        .clone(),
                    dial_options,
                },
            });
        }
        let mut dns_servers = Vec::new();
        dns_servers
            .try_reserve_exact(prepared.dns_server_count())
            .map_err(|_| RunError::RuleAllocation)?;
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
        let dns_timeout = prepared.dns_timeout().unwrap_or(Duration::from_secs(5));
        let dns_max_inflight = prepared
            .dns_max_inflight()
            .unwrap_or(std::num::NonZeroU16::MIN);
        let dns_strategy = prepared
            .dns_runtime()
            .map_or(DnsStrategy::PreferIpv4, |runtime| {
                dns_strategy(runtime.strategy())
            });
        Ok(Self {
            outbounds,
            route_network: runtime_route_network(prepared.route_network()),
            dns_servers,
            dns_timeout,
            dns_max_inflight,
            dns_strategy,
            runtime: prepared.runtime(),
        })
    }

    fn build_outbounds(
        &self,
        addresses: &BootstrapAddresses,
    ) -> Result<Arc<[ClientOutboundContext]>, RunError> {
        let mut outbounds = Vec::new();
        outbounds
            .try_reserve_exact(self.outbounds.len())
            .map_err(|_| RunError::RuleAllocation)?;
        for (index, outbound) in self.outbounds.iter().enumerate() {
            outbounds.push(match outbound {
                BootstrapOutbound::Direct { dial_options, .. } => {
                    ClientOutboundContext::direct(dial_options.clone())
                }
                BootstrapOutbound::Shadowsocks {
                    psk,
                    endpoint,
                    dial_options,
                } => {
                    let address = addresses.outbounds[index]
                        .or_else(|| endpoint_address(endpoint))
                        .unwrap_or(UNRESOLVED_ENDPOINT);
                    ClientOutboundContext::Shadowsocks(ClientShadowsocksContext {
                        tcp_server: TargetAddr::ip(address)
                            .map_err(|_| RunError::StartupProtocol)?,
                        udp_server: address,
                        keys: MethodKeyAdapter::new(MethodSinglePskProvider::from_shared(
                            Arc::clone(psk),
                        )),
                        dial_options: dial_options.clone(),
                    })
                }
            });
        }
        Ok(outbounds.into())
    }

    pub(super) fn build_engine(
        &self,
        addresses: &BootstrapAddresses,
        #[cfg(all(windows, not(test)))] network_socket_service: Arc<
            crate::run::egress::ClientNetworkSocketService,
        >,
    ) -> Result<BootstrapEngine, RunError> {
        let outbounds = self.build_outbounds(addresses)?;
        let tagged = Arc::new(std::sync::OnceLock::new());
        let application_resolver = ApplicationResolverAdapter::new(
            Arc::new(ApplicationResolver::system_default()),
            0,
            DnsStrategy::PreferIpv4,
        );
        let direct_resolvers = self
            .outbounds
            .iter()
            .map(|outbound| match outbound {
                BootstrapOutbound::Direct {
                    domain_resolver, ..
                } => {
                    let (resolver, strategy) = match *domain_resolver {
                        DirectDomainResolver::System => (
                            ApplicationResolver::system_default(),
                            DnsStrategy::PreferIpv4,
                        ),
                        DirectDomainResolver::DnsServer { server, strategy } => (
                            ApplicationResolver::configured(Arc::new(
                                TaggedServerApplicationResolveBackend::new(
                                    Arc::clone(&tagged),
                                    server,
                                ),
                            )),
                            dns_strategy(strategy),
                        ),
                    };
                    Some(ApplicationResolverAdapter::new(
                        Arc::new(resolver),
                        0,
                        strategy,
                    ))
                }
                BootstrapOutbound::Shadowsocks { .. } => None,
            })
            .collect::<Vec<_>>()
            .into();
        #[cfg(all(windows, not(test)))]
        let connector =
            crate::run::egress::NetworkServiceConnector::new(Arc::clone(&network_socket_service));
        #[cfg(any(not(windows), test))]
        let connector =
            TokioConnector::new(ferrum2_runtime::TcpConnector::with_resolution_adapters(
                ferrum2_runtime::SystemSocketInspector,
                ferrum2_runtime::SystemTcpDialer,
                application_resolver.clone(),
                self.runtime.connect_timeout,
            ));
        let udp = ClientUdpContext {
            manager: UdpSessionManager::new(UdpRuntimeLimits::default(), OwnerRegistry::new()),
            live_ids: Arc::new(Mutex::new(std::collections::HashSet::new())),
        };
        let engine = ClientEgressEngine::new_with_direct_resolvers(
            outbounds,
            connector,
            SystemClock::new(),
            SystemRandom,
            (self.runtime.connect_timeout, self.runtime.handshake_timeout),
            Some(udp),
            application_resolver,
            direct_resolvers,
            #[cfg(test)]
            None,
        )
        .with_route_network(self.route_network.clone());
        #[cfg(all(windows, not(test)))]
        let engine = engine.with_shared_network_reset(&network_socket_service)?;
        let engine = Arc::new(engine);
        Ok(BootstrapEngine { engine, tagged })
    }

    fn dns_specs(&self, addresses: &BootstrapAddresses) -> Vec<DnsUpstreamSpec> {
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

    pub(super) fn tagged_resolver_with_addresses(
        &self,
        engine: &BootstrapEngine,
        addresses: &BootstrapAddresses,
    ) -> Result<(Arc<TaggedResolver>, TaggedResolverOwner), RunError> {
        let dns_egress = ClientDnsEgress::new(Arc::clone(&engine.engine))
            .map_err(|()| RunError::StartupProtocol)?;
        let (resolver, owner) = TaggedResolver::new(
            self.dns_specs(addresses),
            self.dns_timeout,
            self.dns_max_inflight,
            Arc::new(dns_egress),
        )
        .map_err(|_| RunError::StartupProtocol)?;
        let resolver = Arc::new(resolver);
        engine
            .tagged
            .set(Arc::downgrade(&resolver))
            .map_err(|_| RunError::StartupProtocol)?;
        Ok((resolver, owner))
    }

    pub(super) const fn dns_strategy(&self) -> DnsStrategy {
        self.dns_strategy
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
            outbounds: self
                .outbounds
                .iter()
                .map(|outbound| match outbound {
                    BootstrapOutbound::Direct { .. } => None,
                    BootstrapOutbound::Shadowsocks { endpoint, .. } => endpoint_address(endpoint),
                })
                .collect(),
        }
    }
}

#[derive(Clone)]
pub(super) struct BootstrapAddresses {
    dns: Vec<Option<Arc<[SocketAddr]>>>,
    outbounds: Vec<Option<SocketAddr>>,
}

pub(super) struct BootstrapEndpointBackend {
    blueprint: Arc<BootstrapBlueprint>,
    targets: Box<[PreparedFixedEndpointTarget]>,
    next_target: AtomicUsize,
    addresses: Mutex<BootstrapAddresses>,
    metrics: Arc<Metrics>,
    #[cfg(all(windows, not(test)))]
    network_socket_service: Arc<crate::run::egress::ClientNetworkSocketService>,
}

impl BootstrapEndpointBackend {
    pub(super) fn new(
        blueprint: Arc<BootstrapBlueprint>,
        targets: Vec<PreparedFixedEndpointTarget>,
        metrics: Arc<Metrics>,
        #[cfg(all(windows, not(test)))] network_socket_service: Arc<
            crate::run::egress::ClientNetworkSocketService,
        >,
    ) -> Self {
        let addresses = blueprint.initial_addresses();
        Self {
            blueprint,
            targets: targets.into_boxed_slice(),
            next_target: AtomicUsize::new(0),
            addresses: Mutex::new(addresses),
            metrics,
            #[cfg(all(windows, not(test)))]
            network_socket_service,
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
        prepared: &PreparedClientV2,
    ) -> Result<(Vec<ResolvedDnsEndpoint>, Vec<ResolvedOutboundEndpoint>), RunError> {
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
        let mut outbounds = Vec::new();
        for (index, endpoint) in prepared.outbound_endpoints().iter().enumerate() {
            if endpoint.as_ref().is_some_and(DialEndpoint::is_domain) {
                outbounds.push(ResolvedOutboundEndpoint::new(
                    u32::try_from(index).map_err(|_| RunError::StartupProtocol)?,
                    addresses.outbounds[index].ok_or(RunError::StartupProtocol)?,
                ));
            }
        }
        Ok((dns, outbounds))
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
                tokio::time::timeout(self.blueprint.dns_timeout, resolve_system_family(request))
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
            let engine = self
                .blueprint
                .build_engine(
                    &addresses,
                    #[cfg(all(windows, not(test)))]
                    Arc::clone(&self.network_socket_service),
                )
                .map_err(|_| DnsError::Runtime)?;
            let (tagged, mut owner) = self
                .blueprint
                .tagged_resolver_with_addresses(&engine, &addresses)
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
            let result = result.and_then(|result| shutdown.map(|_| result));
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
            PreparedFixedEndpointTarget::Outbound(index) => {
                let address = *endpoint
                    .candidates()
                    .first()
                    .ok_or(FixedEndpointMaterializeError::NoCandidates)?;
                *addresses
                    .outbounds
                    .get_mut(index as usize)
                    .ok_or(FixedEndpointMaterializeError::InvalidDependencyOrder)? = Some(address);
            }
        }
        Ok(())
    }
}

pub(super) async fn resolve_system_family(
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
    prepared: &PreparedClientV2,
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
        let kind = match descriptor.target() {
            PreparedFixedEndpointTarget::DnsServer(index) => {
                FixedEndpointKind::DnsServer(DnsServerId::new(index))
            }
            PreparedFixedEndpointTarget::Outbound(_) => FixedEndpointKind::Shadowsocks,
        };
        plan.push(FixedEndpointPlanEntry::new(
            kind,
            fixed_endpoint_spec(descriptor.endpoint())?,
        ));
        targets.push(descriptor.target());
    }
    Ok((plan, targets))
}

pub(super) fn fixed_endpoint_spec(endpoint: &DialEndpoint) -> Result<FixedEndpointSpec, RunError> {
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

pub(super) fn endpoint_address(endpoint: &DialEndpoint) -> Option<SocketAddr> {
    match endpoint {
        DialEndpoint::Ip(address) => Some(*address),
        DialEndpoint::Domain { .. } => None,
    }
}

pub(super) fn bootstrap_dns_target(
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

pub(super) fn bootstrap_dns_resolved_targets(
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
    prepared: &PreparedClientV2,
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
                    DnsCacheQtype::A => ferrum2_observability::DnsQueryType::A,
                    DnsCacheQtype::Aaaa => ferrum2_observability::DnsQueryType::Aaaa,
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
