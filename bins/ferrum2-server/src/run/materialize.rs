use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ferrum2_config::{
    CompiledRuleSetResource, DialEndpoint, DirectDomainResolver, PreparedDnsEndpoint,
    PreparedDnsEndpointMode, PreparedFixedEndpointTarget, PreparedServerV2, ResolvedDnsEndpoint,
    ResolverRef, ServerV2MaterializeFuture, ServerV2Resources,
};
use ferrum2_core::route::EgressPlanSnapshot;
use ferrum2_core::{TargetAddr, TargetHostRef};
use ferrum2_dns::{
    DnsAddressRecords, DnsCache, DnsCacheLookup, DnsCacheQtype, DnsError, DnsServerId, DnsStrategy,
    DnsUpstreamSpec, DnsUpstreamTransport, FixedEndpointKind, FixedEndpointLookup,
    FixedEndpointMaterializeError, FixedEndpointPlanEntry, FixedEndpointResolveBackend,
    FixedEndpointResolveFuture, FixedEndpointResolveRequest, FixedEndpointSpec,
    MAX_APPLICATION_RESOLVED_CANDIDATES, MaterializedFixedEndpoint, ResolverGeneration,
    TaggedResolver, TaggedResolverOwner, materialize_fixed_endpoints,
};
use ferrum2_observability::{
    CompiledMatchType, DnsQueryType, DnsResolvePurpose, DnsResolveResult, DnsResolverKind, Metrics,
    RuleSetResult, TargetResolutionComponent, TargetResolutionMode,
};
use ferrum2_rule::{RuleEngineRegistry, RuleEngineSnapshot, RuleSetId};
use ferrum2_runtime::{
    ExplicitRuleSetHostResolver, HttpsRuleSetDownloader, PreparedProcessRoot, ProcessCancellation,
    ProcessFuture, RuleSetCacheName, RuleSetDialTargets, RuleSetDialer, RuleSetDownloadError,
    RuleSetDownloadErrorKind, RuleSetDownloadMode, RuleSetDownloadResolver, RuleSetDownloader,
    RuleSetHostResolveOutcome, RuleSetHostResolverKind, RuleSetLoadDisposition, RuleSetLoadError,
    RuleSetLoadErrorKind, RuleSetLoader, RuleSetLoaderConfig, RuleSetRefreshOutcome,
    RuleSetRefreshService, RuleSetRemoteSource, TcpResolver, materialize_rule_set_snapshot,
};
use tokio::time::Instant;

use super::dns_egress::{ServerDnsEgress, ServerPhysicalSocketContext};
use super::tcp::{ServerNetworkSocketService, ServerPhysicalTcpStream};
use super::{RunError, runtime_dial_options, runtime_route_network};

const INITIAL_RULESET_GENERATION: u64 = 1;

const fn initial_resolver_generation(has_rule_sets: bool) -> ResolverGeneration {
    ResolverGeneration::new(if has_rule_sets {
        INITIAL_RULESET_GENERATION
    } else {
        0
    })
}
const UNRESOLVED_ENDPOINT: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 254)), 9);

/// Single-use schema-v2 materialization context. Initial resolver owners are
/// joined before the finished config becomes visible. Only a pure refresh
/// construction plan is retained until it is transferred to the supervisor.
pub(super) struct ServerV2MaterializeContext {
    metrics: Arc<Metrics>,
    network_sockets: Arc<ServerNetworkSocketService>,
    downloader: Option<Arc<dyn RuleSetDownloader>>,
    pending: Mutex<Option<PendingServerV2Runtime>>,
    cache: Mutex<Option<DnsCache>>,
    failure: Mutex<Option<RunError>>,
    used: AtomicBool,
}

impl ServerV2MaterializeContext {
    #[cfg(test)]
    pub(super) fn new(metrics: Arc<Metrics>) -> Self {
        let registry = ferrum2_runtime::OwnerRegistry::new();
        let network_sockets =
            super::tcp::prepare_server_network_socket_service(&registry, &metrics)
                .expect("test materialization network socket service");
        Self::with_network_sockets(metrics, network_sockets)
    }

    pub(super) fn with_network_sockets(
        metrics: Arc<Metrics>,
        network_sockets: Arc<ServerNetworkSocketService>,
    ) -> Self {
        Self {
            metrics,
            network_sockets,
            downloader: None,
            pending: Mutex::new(None),
            cache: Mutex::new(None),
            failure: Mutex::new(None),
            used: AtomicBool::new(false),
        }
    }

    #[cfg(test)]
    fn with_downloader(metrics: Arc<Metrics>, downloader: Arc<dyn RuleSetDownloader>) -> Self {
        let registry = ferrum2_runtime::OwnerRegistry::new();
        let network_sockets =
            super::tcp::prepare_server_network_socket_service(&registry, &metrics)
                .expect("test materialization network socket service");
        Self {
            metrics,
            network_sockets,
            downloader: Some(downloader),
            pending: Mutex::new(None),
            cache: Mutex::new(None),
            failure: Mutex::new(None),
            used: AtomicBool::new(false),
        }
    }

    fn take_pending(&self) -> Option<PendingServerV2Runtime> {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    fn take_cache(&self) -> Option<DnsCache> {
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    fn take_failure(&self) -> Option<RunError> {
        self.failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    async fn materialize_inner(
        &self,
        prepared: &PreparedServerV2,
    ) -> Result<ServerV2Resources, RunError> {
        if self.used.swap(true, Ordering::AcqRel) {
            return Err(RunError::StartupProtocol);
        }
        record_target_resolution_modes(prepared, &self.metrics);

        let blueprint = Arc::new(BootstrapBlueprint::new(
            prepared,
            Arc::clone(&self.metrics),
            Arc::clone(&self.network_sockets),
        )?);
        let (plan, targets) = fixed_endpoint_plan(prepared)?;
        let cache = materialization_cache(prepared, &self.metrics)?;
        *self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = cache.clone();
        let backend = BootstrapEndpointBackend::new(
            Arc::clone(&blueprint),
            targets,
            Arc::clone(&self.metrics),
        );
        materialize_fixed_endpoints(
            &plan,
            &backend,
            cache.as_ref(),
            initial_resolver_generation(!prepared.rule_sets().is_empty()),
        )
        .await
        .map_err(classify_fixed_endpoint_error)?;
        let dns_endpoints = backend.finished_resources(prepared)?;

        let sources = rule_set_sources(prepared)?;
        if sources.is_empty() {
            return Ok(ServerV2Resources::new(dns_endpoints, Vec::new()));
        }

        let loader_config = runtime_loader_config(prepared)?;
        let needs_tagged = prepared.rule_sets().iter().any(|rule_set| {
            matches!(
                rule_set.download_resolver(),
                Some(ResolverRef::DnsServer(_))
            )
        }) || blueprint
            .outbounds
            .iter()
            .any(|resolver| matches!(resolver, DirectDomainResolver::DnsServer { .. }));
        let addresses = backend.addresses();
        let pending_transport = match self.downloader.as_ref() {
            Some(downloader) => PendingRuleSetTransport::Injected {
                loader_config: loader_config.clone(),
                downloader: Arc::clone(downloader),
            },
            None => PendingRuleSetTransport::Production(ProductionRuleSetTransport {
                blueprint: Arc::clone(&blueprint),
                addresses: addresses.clone(),
                loader_config: loader_config.clone(),
                cache: cache.clone(),
                needs_tagged,
            }),
        };
        let initial_transport = match self.downloader.as_ref() {
            Some(downloader) => {
                ActiveRuleSetTransport::injected(loader_config, Arc::clone(downloader))
            }
            None => {
                ProductionRuleSetTransport {
                    blueprint,
                    addresses,
                    loader_config,
                    cache: cache.clone(),
                    needs_tagged,
                }
                .activate(INITIAL_RULESET_GENERATION)
                .await?
            }
        };
        let initial = match materialize_rule_set_snapshot(
            initial_transport.loader.as_ref(),
            &sources,
            INITIAL_RULESET_GENERATION,
        )
        .await
        {
            Ok(initial) => initial,
            Err(error) => {
                self.metrics.ruleset_load(RuleSetResult::Failure);
                initial_transport.shutdown().await?;
                return Err(classify_rule_set_load_error(error));
            }
        };
        let (snapshot, rule_set_ids, dispositions, degraded_failures) = initial.into_parts();
        for (disposition, degraded_failure) in dispositions.into_iter().zip(degraded_failures) {
            self.metrics
                .ruleset_load(initial_rule_set_result(disposition, degraded_failure));
        }
        self.metrics
            .set_ruleset_generation(INITIAL_RULESET_GENERATION);
        record_rule_set_snapshot_metrics(&self.metrics, &snapshot, &rule_set_ids);
        self.metrics
            .set_ruleset_last_success_timestamp(unix_timestamp_now());
        let rule_sets = match compiled_rule_set_resources(&snapshot, &rule_set_ids) {
            Ok(rule_sets) => rule_sets,
            Err(error) => {
                initial_transport.shutdown().await?;
                return Err(error);
            }
        };
        initial_transport.shutdown().await?;

        let pending = PendingServerV2Runtime {
            transport: pending_transport,
            sources,
            rule_set_ids: rule_set_ids.into_vec(),
            metrics: Arc::clone(&self.metrics),
        };
        let duplicate = {
            let mut slot = self
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if slot.is_none() {
                slot.replace(pending);
                None
            } else {
                Some(pending)
            }
        };
        if let Some(duplicate) = duplicate {
            duplicate.shutdown().await?;
            return Err(RunError::StartupProtocol);
        }
        Ok(ServerV2Resources::new(dns_endpoints, rule_sets))
    }
}

impl ferrum2_config::ServerV2MaterializeContext for ServerV2MaterializeContext {
    fn materialize_server<'a>(
        &'a self,
        prepared: &'a PreparedServerV2,
    ) -> ServerV2MaterializeFuture<'a> {
        Box::pin(async move {
            match self.materialize_inner(prepared).await {
                Ok(resources) => Ok(resources),
                Err(error) => {
                    self.failure
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .replace(error);
                    Err(ferrum2_config::ConfigError::resource_materialization())
                }
            }
        })
    }
}

pub(super) struct PendingServerV2Runtime {
    transport: PendingRuleSetTransport,
    sources: Vec<RuleSetRemoteSource>,
    rule_set_ids: Vec<RuleSetId>,
    metrics: Arc<Metrics>,
}

impl PendingServerV2Runtime {
    async fn into_prepared_root(
        self,
        registry: Arc<RuleEngineRegistry>,
    ) -> Result<ServerV2RuntimeRoot, RunError> {
        let Self {
            transport,
            sources,
            rule_set_ids,
            metrics,
        } = self;
        let mut active = transport.activate(registry.generation()).await?;
        let observer_metrics = Arc::clone(&metrics);
        let observer_registry = Arc::clone(&registry);
        let observer_rule_sets = rule_set_ids.clone();
        let observer = Arc::new(move |outcome| {
            if let RuleSetRefreshOutcome::Updated { generation, .. } = outcome {
                observer_metrics.set_ruleset_generation(generation);
                let snapshot = observer_registry.snapshot();
                record_rule_set_snapshot_metrics(&observer_metrics, &snapshot, &observer_rule_sets);
                observer_metrics.set_ruleset_last_success_timestamp(unix_timestamp_now());
            }
            observer_metrics.ruleset_refresh(refresh_rule_set_result(outcome));
        });
        let service = match RuleSetRefreshService::new(
            Arc::clone(&active.loader),
            registry,
            sources,
            rule_set_ids,
        ) {
            Ok(service) => service.with_observer(observer),
            Err(error) => {
                active.shutdown().await?;
                return Err(classify_rule_set_load_error(error));
            }
        };
        Ok(ServerV2RuntimeRoot {
            service: Some(Arc::new(service)),
            tagged: active.tagged.take(),
            owner: active.owner.take(),
        })
    }

    async fn shutdown(self) -> Result<(), RunError> {
        // The initial resolver/downloader was fully joined before this pure
        // refresh construction plan was stored.
        drop(self);
        Ok(())
    }
}

enum PendingRuleSetTransport {
    Injected {
        loader_config: RuleSetLoaderConfig,
        downloader: Arc<dyn RuleSetDownloader>,
    },
    Production(ProductionRuleSetTransport),
}

impl PendingRuleSetTransport {
    async fn activate(self, generation: u64) -> Result<ActiveRuleSetTransport, RunError> {
        match self {
            Self::Injected {
                loader_config,
                downloader,
            } => Ok(ActiveRuleSetTransport::injected(loader_config, downloader)),
            Self::Production(transport) => transport.activate(generation).await,
        }
    }
}

struct ProductionRuleSetTransport {
    blueprint: Arc<BootstrapBlueprint>,
    addresses: BootstrapAddresses,
    loader_config: RuleSetLoaderConfig,
    cache: Option<DnsCache>,
    needs_tagged: bool,
}

impl ProductionRuleSetTransport {
    async fn activate(self, generation: u64) -> Result<ActiveRuleSetTransport, RunError> {
        let tagged_slot = Arc::new(std::sync::OnceLock::new());
        let direct_resolvers = self.blueprint.direct_resolvers(Arc::clone(&tagged_slot));
        let (tagged, owner) = if self.needs_tagged {
            let (resolver, mut owner) = self.blueprint.tagged_resolver_with_slot(
                &self.addresses,
                tagged_slot,
                direct_resolvers.clone(),
            )?;
            if owner.ready().await.is_err() {
                drop(resolver);
                let _ = owner.shutdown().await;
                return Err(RunError::StartupProtocol);
            }
            (Some(resolver), Some(owner))
        } else {
            (None, None)
        };
        let mut resolver = ExplicitRuleSetHostResolver::new(
            tagged.as_ref().map(Arc::clone),
            self.blueprint.strategy,
        );
        if let Some(cache) = self.cache {
            resolver = resolver.with_cache(cache, ResolverGeneration::new(generation));
        }
        let metrics = Arc::clone(&self.blueprint.metrics);
        resolver = resolver.with_observer(Arc::new(move |kind, outcome| {
            let resolver = match kind {
                RuleSetHostResolverKind::System => {
                    metrics.dns_explicit_system_resolve(DnsResolvePurpose::RuleSetDownload);
                    DnsResolverKind::System
                }
                RuleSetHostResolverKind::Configured => DnsResolverKind::Configured,
            };
            let result = match outcome {
                RuleSetHostResolveOutcome::Success => DnsResolveResult::Success,
                RuleSetHostResolveOutcome::Failure => DnsResolveResult::Failure,
            };
            metrics.dns_resolve(resolver, DnsResolvePurpose::RuleSetDownload, result);
        }));
        let downloader: Arc<dyn RuleSetDownloader> = Arc::new(HttpsRuleSetDownloader::new(
            resolver,
            ServerRuleSetDialer::new(direct_resolvers, Arc::clone(&self.blueprint.physical)),
        ));
        Ok(ActiveRuleSetTransport {
            loader: Arc::new(RuleSetLoader::new(self.loader_config, downloader)),
            tagged,
            owner,
        })
    }
}

struct ActiveRuleSetTransport {
    loader: Arc<RuleSetLoader<Arc<dyn RuleSetDownloader>>>,
    tagged: Option<Arc<TaggedResolver>>,
    owner: Option<TaggedResolverOwner>,
}

impl ActiveRuleSetTransport {
    fn injected(
        loader_config: RuleSetLoaderConfig,
        downloader: Arc<dyn RuleSetDownloader>,
    ) -> Self {
        Self {
            loader: Arc::new(RuleSetLoader::new(loader_config, downloader)),
            tagged: None,
            owner: None,
        }
    }

    async fn shutdown(self) -> Result<(), RunError> {
        let Self {
            loader,
            tagged,
            mut owner,
        } = self;
        let loader_cleanup = loader
            .shutdown()
            .await
            .map_err(classify_rule_set_load_error);
        drop(loader);
        drop(tagged);
        let owner_cleanup = if let Some(owner) = owner.as_mut() {
            owner
                .shutdown()
                .await
                .map(|_| ())
                .map_err(|_| RunError::ShutdownCleanup)
        } else {
            Ok(())
        };
        loader_cleanup.and(owner_cleanup)
    }
}

pub(super) struct ServerV2RuntimeRoot {
    service: Option<Arc<RuleSetRefreshService<Arc<dyn RuleSetDownloader>>>>,
    tagged: Option<Arc<TaggedResolver>>,
    owner: Option<TaggedResolverOwner>,
}

impl ServerV2RuntimeRoot {
    pub(super) async fn cleanup(&mut self) -> Result<(), RunError> {
        let service_cleanup = match self.service.take() {
            Some(service) => service
                .shutdown()
                .await
                .map_err(classify_rule_set_load_error),
            None => Ok(()),
        };
        self.tagged.take();
        let owner_cleanup = if let Some(owner) = self.owner.as_mut() {
            owner
                .shutdown()
                .await
                .map(|_| ())
                .map_err(|_| RunError::ShutdownCleanup)
        } else {
            Ok(())
        };
        self.owner.take();
        service_cleanup.and(owner_cleanup)
    }
}

impl PreparedProcessRoot<RunError> for ServerV2RuntimeRoot {
    fn activate(&mut self) -> Result<(), RunError> {
        Ok(())
    }

    fn run(
        mut self: Box<Self>,
        cancellation: ProcessCancellation,
    ) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async move {
            let service = Arc::clone(self.service.as_ref().expect("prepared refresh service"));
            let result = service
                .run(cancellation)
                .await
                .map_err(classify_rule_set_load_error);
            drop(service);
            let cleanup = self.cleanup().await;
            result.and(cleanup)
        })
    }

    fn rollback(mut self: Box<Self>) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async move { self.cleanup().await })
    }
}

struct BootstrapDnsServer {
    transport: ferrum2_config::DnsTransport,
    server_name: Option<Box<str>>,
    path: Option<Box<str>>,
    detour: Option<ferrum2_core::route::EgressPlanHandle>,
    endpoint: PreparedDnsEndpoint,
}

struct BootstrapBlueprint {
    dns_servers: Vec<BootstrapDnsServer>,
    timeout: Duration,
    max_inflight: std::num::NonZeroU16,
    strategy: DnsStrategy,
    outbounds: Vec<DirectDomainResolver>,
    physical: Arc<ServerPhysicalSocketContext>,
    metrics: Arc<Metrics>,
}

impl BootstrapBlueprint {
    fn new(
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

    fn direct_resolvers(
        &self,
        tagged: Arc<std::sync::OnceLock<std::sync::Weak<TaggedResolver>>>,
    ) -> Vec<super::dns_egress::ServerDnsResolver> {
        self.outbounds
            .iter()
            .copied()
            .map(|mode| {
                super::dns_egress::ServerDnsResolver::for_direct_observed(
                    mode,
                    Arc::clone(&tagged),
                    Arc::clone(&self.metrics),
                )
            })
            .collect()
    }

    fn tagged_resolver_with_slot(
        &self,
        addresses: &BootstrapAddresses,
        tagged: Arc<std::sync::OnceLock<std::sync::Weak<TaggedResolver>>>,
        direct_resolvers: Vec<super::dns_egress::ServerDnsResolver>,
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
}

#[derive(Clone)]
struct BootstrapAddresses {
    dns: Vec<Option<Arc<[SocketAddr]>>>,
}

struct BootstrapEndpointBackend {
    blueprint: Arc<BootstrapBlueprint>,
    targets: Box<[PreparedFixedEndpointTarget]>,
    next_target: AtomicUsize,
    addresses: Mutex<BootstrapAddresses>,
    metrics: Arc<Metrics>,
}

impl BootstrapEndpointBackend {
    fn new(
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

    fn addresses(&self) -> BootstrapAddresses {
        self.addresses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn finished_resources(
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

/// Server RuleSet downloads use the resolver owned by the exact Direct detour.
/// Resolved targets use the default physical policy or the exact Direct
/// detour, while deferred domains never escape through an ambient resolver.
#[derive(Clone)]
struct ServerRuleSetDialer {
    direct_resolvers: Arc<[super::dns_egress::ServerDnsResolver]>,
    physical: Arc<ServerPhysicalSocketContext>,
}

impl ServerRuleSetDialer {
    fn new(
        direct_resolvers: Vec<super::dns_egress::ServerDnsResolver>,
        physical: Arc<ServerPhysicalSocketContext>,
    ) -> Self {
        Self {
            direct_resolvers: direct_resolvers.into(),
            physical,
        }
    }
}

impl RuleSetDialer for ServerRuleSetDialer {
    type Io = ServerPhysicalTcpStream;

    fn connect(
        &self,
        targets: &RuleSetDialTargets,
        detour: Option<&EgressPlanSnapshot>,
        deadline: Instant,
    ) -> impl Future<Output = Result<Self::Io, RuleSetDownloadError>> + Send {
        let targets = targets.clone();
        let direct_resolvers = Arc::clone(&self.direct_resolvers);
        let physical = Arc::clone(&self.physical);
        let detour = detour.map(|plan| plan.hops().to_vec());
        async move {
            let (candidates, outbound) = match targets {
                RuleSetDialTargets::Resolved(candidates) => {
                    if detour.as_deref().is_some_and(
                        |hops| !matches!(hops, [outbound] if *outbound < direct_resolvers.len()),
                    ) {
                        return Err(RuleSetDownloadError::new(RuleSetDownloadErrorKind::Connect));
                    }
                    let outbound = detour.as_deref().and_then(|hops| match hops {
                        [outbound] => Some(*outbound),
                        _ => None,
                    });
                    (candidates.into_vec(), outbound)
                }
                RuleSetDialTargets::Domain(target) => {
                    let [outbound] = detour.as_deref().unwrap_or(&[]) else {
                        return Err(RuleSetDownloadError::new(RuleSetDownloadErrorKind::Connect));
                    };
                    let resolver = direct_resolvers.get(*outbound).ok_or_else(|| {
                        RuleSetDownloadError::new(RuleSetDownloadErrorKind::Connect)
                    })?;
                    let TargetHostRef::Domain(host) = target.host() else {
                        return Err(RuleSetDownloadError::new(RuleSetDownloadErrorKind::Connect));
                    };
                    let candidates = tokio::time::timeout_at(
                        deadline,
                        TcpResolver::resolve(resolver, host, target.port().get()),
                    )
                    .await
                    .map_err(|_| RuleSetDownloadError::new(RuleSetDownloadErrorKind::Timeout))?
                    .map_err(|_| RuleSetDownloadError::new(RuleSetDownloadErrorKind::Connect))?;
                    (candidates, Some(*outbound))
                }
            };
            for candidate in candidates
                .into_iter()
                .take(ferrum2_runtime::MAX_RESOLVED_CANDIDATES)
            {
                match physical.connect_tcp(candidate, outbound, deadline).await {
                    Ok(stream) => return Ok(stream),
                    Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                        return Err(RuleSetDownloadError::new(RuleSetDownloadErrorKind::Timeout));
                    }
                    Err(_) => {}
                }
            }
            Err(RuleSetDownloadError::new(RuleSetDownloadErrorKind::Connect))
        }
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

fn fixed_endpoint_plan(
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

fn materialization_cache(
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

fn compiled_rule_set_resources(
    snapshot: &RuleEngineSnapshot,
    rule_set_ids: &[RuleSetId],
) -> Result<Vec<CompiledRuleSetResource>, RunError> {
    let mut resources = Vec::new();
    resources
        .try_reserve_exact(rule_set_ids.len())
        .map_err(|_| RunError::RuleAllocation)?;
    for (index, &rule_set_id) in rule_set_ids.iter().enumerate() {
        let descriptor = snapshot
            .rule_set(rule_set_id)
            .ok_or(RunError::StartupProtocol)?;
        let match_set = snapshot
            .shared_match_set(descriptor.match_set())
            .ok_or(RunError::StartupProtocol)?;
        resources.push(CompiledRuleSetResource::new(
            u32::try_from(index).map_err(|_| RunError::StartupProtocol)?,
            Arc::clone(match_set),
            snapshot.generation(),
        ));
    }
    Ok(resources)
}

const fn initial_rule_set_result(
    disposition: RuleSetLoadDisposition,
    degraded_failure: Option<RuleSetLoadErrorKind>,
) -> RuleSetResult {
    if degraded_failure.is_some() {
        return RuleSetResult::Failure;
    }
    match disposition {
        RuleSetLoadDisposition::Downloaded => RuleSetResult::Success,
        RuleSetLoadDisposition::NotModified
        | RuleSetLoadDisposition::OfflineCache
        | RuleSetLoadDisposition::StaleCache => RuleSetResult::Unchanged,
    }
}

const fn refresh_rule_set_result(outcome: RuleSetRefreshOutcome) -> RuleSetResult {
    match outcome {
        RuleSetRefreshOutcome::Updated { .. } => RuleSetResult::Success,
        RuleSetRefreshOutcome::NotModified => RuleSetResult::Unchanged,
        RuleSetRefreshOutcome::RetainedCache(_) | RuleSetRefreshOutcome::Failed(_) => {
            RuleSetResult::Failure
        }
    }
}

fn record_rule_set_snapshot_metrics(
    metrics: &Metrics,
    snapshot: &RuleEngineSnapshot,
    rule_set_ids: &[RuleSetId],
) {
    let mut exact_domain = 0_usize;
    let mut domain_suffix = 0_usize;
    let mut domain_keyword = 0_usize;
    let mut ip_cidr = 0_usize;
    for &rule_set_id in rule_set_ids {
        let Some(descriptor) = snapshot.rule_set(rule_set_id) else {
            continue;
        };
        let Some(match_set) = snapshot.match_set(descriptor.match_set()) else {
            continue;
        };
        let counts = match_set.entry_counts();
        exact_domain = exact_domain.saturating_add(counts.exact_domain);
        domain_suffix = domain_suffix.saturating_add(counts.domain_suffix);
        domain_keyword = domain_keyword.saturating_add(counts.domain_keyword);
        ip_cidr = ip_cidr.saturating_add(counts.ip_cidr);
    }
    metrics.set_ruleset_compiled_entries(CompiledMatchType::Domain, exact_domain);
    metrics.set_ruleset_compiled_entries(CompiledMatchType::DomainSuffix, domain_suffix);
    metrics.set_ruleset_compiled_entries(CompiledMatchType::DomainKeyword, domain_keyword);
    metrics.set_ruleset_compiled_entries(CompiledMatchType::IpCidr, ip_cidr);
}

fn unix_timestamp_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn runtime_loader_config(prepared: &PreparedServerV2) -> Result<RuleSetLoaderConfig, RunError> {
    let config = prepared.rule_set_loader();
    RuleSetLoaderConfig::new(
        config.cache_dir.clone(),
        config.download_timeout,
        config.max_redirects,
    )
    .map_err(|_| RunError::StartupProtocol)
}

fn rule_set_sources(prepared: &PreparedServerV2) -> Result<Vec<RuleSetRemoteSource>, RunError> {
    let mut sources = Vec::new();
    sources
        .try_reserve_exact(prepared.rule_sets().len())
        .map_err(|_| RunError::RuleAllocation)?;
    for (index, rule_set) in prepared.rule_sets().iter().enumerate() {
        let mode = match rule_set.download_mode() {
            ferrum2_config::PreparedRuleSetDownloadMode::ClientResolved { resolver } => {
                RuleSetDownloadMode::ClientResolved(match resolver {
                    ResolverRef::System => RuleSetDownloadResolver::System,
                    ResolverRef::DnsServer(server) => {
                        RuleSetDownloadResolver::DnsServer(DnsServerId::new(
                            u32::try_from(server).map_err(|_| RunError::StartupProtocol)?,
                        ))
                    }
                })
            }
            ferrum2_config::PreparedRuleSetDownloadMode::DeferredToDetour => {
                RuleSetDownloadMode::DeferredToDetour
            }
        };
        let detour = prepared.download_detour_plan(index).cloned();
        if detour.is_some() && prepared.download_detour_is_direct(index) != Some(true) {
            return Err(RunError::StartupProtocol);
        }
        sources.push(
            RuleSetRemoteSource::new(
                RuleSetCacheName::new(rule_set.tag()).map_err(|_| RunError::StartupProtocol)?,
                rule_set.url(),
                mode,
                detour,
                rule_set.update_interval(),
            )
            .map_err(|_| RunError::StartupProtocol)?,
        );
    }
    Ok(sources)
}

fn record_target_resolution_modes(prepared: &PreparedServerV2, metrics: &Metrics) {
    for endpoint in prepared.dns_endpoints() {
        let mode = match endpoint.mode() {
            PreparedDnsEndpointMode::Numeric => TargetResolutionMode::Numeric,
            PreparedDnsEndpointMode::ClientResolved {
                resolver: ResolverRef::System,
                ..
            } => TargetResolutionMode::ClientResolvedSystem,
            PreparedDnsEndpointMode::ClientResolved {
                resolver: ResolverRef::DnsServer(_),
                ..
            } => TargetResolutionMode::ClientResolvedConfigured,
            PreparedDnsEndpointMode::DeferredToDetour => TargetResolutionMode::DeferredToDetour,
        };
        metrics.target_resolution(TargetResolutionComponent::DnsUpstream, mode);
    }
    for rule_set in prepared.rule_sets() {
        let mode = match rule_set.download_mode() {
            ferrum2_config::PreparedRuleSetDownloadMode::ClientResolved {
                resolver: ResolverRef::System,
            } => TargetResolutionMode::ClientResolvedSystem,
            ferrum2_config::PreparedRuleSetDownloadMode::ClientResolved {
                resolver: ResolverRef::DnsServer(_),
            } => TargetResolutionMode::ClientResolvedConfigured,
            ferrum2_config::PreparedRuleSetDownloadMode::DeferredToDetour => {
                TargetResolutionMode::DeferredToDetour
            }
        };
        metrics.target_resolution(TargetResolutionComponent::RuleSetDownload, mode);
    }
}

pub(super) struct MaterializedServerV2 {
    config: Option<ferrum2_config::ValidatedServerConfig>,
    pending: Option<PendingServerV2Runtime>,
    cache: Option<DnsCache>,
}

impl MaterializedServerV2 {
    pub(super) fn config(&self) -> &ferrum2_config::ValidatedServerConfig {
        self.config.as_ref().expect("materialized server config")
    }

    pub(super) async fn validate_only_shutdown(
        mut self,
    ) -> Result<ferrum2_config::ValidatedServerConfig, RunError> {
        let policy_validation =
            validate_dns_policy_adapter(self.config.as_ref().expect("materialized server config"));
        shutdown_pending(self.pending.take()).await?;
        policy_validation?;
        Ok(self.config.take().expect("materialized server config"))
    }

    pub(super) async fn into_run_parts(
        mut self,
    ) -> Result<
        (
            ferrum2_config::ValidatedServerConfig,
            Option<ServerV2RuntimeRoot>,
            Option<DnsCache>,
        ),
        RunError,
    > {
        let config = self.config.take().expect("materialized server config");
        let root = prepare_runtime_root(&config, self.pending.take()).await?;
        Ok((config, root, self.cache.take()))
    }
}

fn validate_dns_policy_adapter(
    config: &ferrum2_config::ValidatedServerConfig,
) -> Result<(), RunError> {
    let Some(binding) = config
        .dns_route
        .as_ref()
        .and_then(ferrum2_config::ServerDnsRoute::policy_blueprint)
    else {
        return Ok(());
    };
    let registry = binding.registry();
    ferrum2_dns::DnsPolicyProgram::try_from_blueprint(
        binding.blueprint().clone(),
        &registry.snapshot(),
    )
    .map(drop)
    .map_err(super::run_error_for_dns_policy_compile)
}

pub(super) async fn materialize_prepared(
    prepared: PreparedServerV2,
    context: &ServerV2MaterializeContext,
) -> Result<MaterializedServerV2, RunError> {
    let config = match ferrum2_config::materialize_server_v2(prepared, context).await {
        Ok(config) => config,
        Err(error) => {
            shutdown_pending(context.take_pending()).await?;
            return Err(context
                .take_failure()
                .unwrap_or_else(|| classify_config_materialization_error(error)));
        }
    };
    Ok(MaterializedServerV2 {
        config: Some(config),
        pending: context.take_pending(),
        cache: context.take_cache(),
    })
}

fn classify_config_materialization_error(error: ferrum2_config::ConfigError) -> RunError {
    match error.kind() {
        ferrum2_config::ConfigErrorKind::RuleCompile => RunError::RuleCompile,
        ferrum2_config::ConfigErrorKind::RuleAllocation => RunError::RuleAllocation,
        ferrum2_config::ConfigErrorKind::Io
        | ferrum2_config::ConfigErrorKind::TooLarge
        | ferrum2_config::ConfigErrorKind::Syntax
        | ferrum2_config::ConfigErrorKind::Semantic
        | ferrum2_config::ConfigErrorKind::DnsResolverRequired
        | ferrum2_config::ConfigErrorKind::DnsReservedResolverName
        | ferrum2_config::ConfigErrorKind::DnsDependencyCycle
        | ferrum2_config::ConfigErrorKind::ResourceMaterialization => {
            RunError::ConfigResourceMaterialization
        }
    }
}

const fn classify_fixed_endpoint_error(error: FixedEndpointMaterializeError) -> RunError {
    match error {
        FixedEndpointMaterializeError::Resolve(_)
        | FixedEndpointMaterializeError::InvalidAnswer
        | FixedEndpointMaterializeError::NoCandidates
        | FixedEndpointMaterializeError::Cache(_) => RunError::DnsResolve,
        FixedEndpointMaterializeError::Allocation => RunError::RuleAllocation,
        FixedEndpointMaterializeError::DuplicateDnsServer
        | FixedEndpointMaterializeError::MissingResolver
        | FixedEndpointMaterializeError::InvalidDependencyOrder => {
            RunError::ConfigResourceMaterialization
        }
    }
}

const fn classify_rule_set_load_error(error: RuleSetLoadError) -> RunError {
    classify_rule_set_load_error_kind(error.kind())
}

const fn classify_rule_set_load_error_kind(kind: RuleSetLoadErrorKind) -> RunError {
    match kind {
        RuleSetLoadErrorKind::InvalidCacheName
        | RuleSetLoadErrorKind::InvalidSource
        | RuleSetLoadErrorKind::InvalidLoaderConfig => RunError::ConfigResourceMaterialization,
        RuleSetLoadErrorKind::CacheDirectory
        | RuleSetLoadErrorKind::CacheRead
        | RuleSetLoadErrorKind::CacheMetadata
        | RuleSetLoadErrorKind::CacheDigest
        | RuleSetLoadErrorKind::CacheWrite
        | RuleSetLoadErrorKind::NotModifiedWithoutCache => RunError::RuleSetCache,
        RuleSetLoadErrorKind::Download(_)
        | RuleSetLoadErrorKind::DownloadTimeout
        | RuleSetLoadErrorKind::DownloadBody
        | RuleSetLoadErrorKind::DownloadOverflow
        | RuleSetLoadErrorKind::Task => RunError::RuleSetDownload,
        RuleSetLoadErrorKind::Allocation => RunError::RuleAllocation,
        RuleSetLoadErrorKind::Decode(kind) => match kind {
            ferrum2_rule::srs::SrsErrorKind::UnsupportedMatcher => {
                RunError::RuleSetUnsupportedMatcher
            }
            ferrum2_rule::srs::SrsErrorKind::Allocation => RunError::RuleAllocation,
            ferrum2_rule::srs::SrsErrorKind::Compile => RunError::RuleSetCompile,
            _ => RunError::RuleSetFormat,
        },
        RuleSetLoadErrorKind::RegistryCompile | RuleSetLoadErrorKind::RegistryPublish => {
            RunError::RuleSetCompile
        }
    }
}

async fn prepare_runtime_root(
    config: &ferrum2_config::ValidatedServerConfig,
    pending: Option<PendingServerV2Runtime>,
) -> Result<Option<ServerV2RuntimeRoot>, RunError> {
    let Some(pending) = pending else {
        return Ok(None);
    };
    let registry = config
        .route_program
        .as_ref()
        .and_then(ferrum2_config::CompiledRoute::rule_registry)
        .or_else(|| {
            config
                .dns_route
                .as_ref()
                .and_then(ferrum2_config::ServerDnsRoute::policy_blueprint)
                .map(ferrum2_config::DnsPolicyBlueprintBinding::registry)
        });
    let Some(registry) = registry else {
        pending.shutdown().await?;
        return Err(RunError::StartupProtocol);
    };
    pending.into_prepared_root(registry).await.map(Some)
}

async fn shutdown_pending(pending: Option<PendingServerV2Runtime>) -> Result<(), RunError> {
    if let Some(pending) = pending {
        pending.shutdown().await?;
    }
    Ok(())
}

const fn dns_strategy(strategy: ferrum2_config::DnsStrategy) -> DnsStrategy {
    match strategy {
        ferrum2_config::DnsStrategy::PreferIpv4 => DnsStrategy::PreferIpv4,
        ferrum2_config::DnsStrategy::PreferIpv6 => DnsStrategy::PreferIpv6,
        ferrum2_config::DnsStrategy::Ipv4Only => DnsStrategy::Ipv4Only,
        ferrum2_config::DnsStrategy::Ipv6Only => DnsStrategy::Ipv6Only,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, TcpListener};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ferrum2_runtime::{
        RuleSetDownloadFuture, RuleSetDownloadMode, RuleSetDownloadRequest, RuleSetDownloadResponse,
    };
    use hickory_proto::op::{Message, OpCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{RData, Record, RecordType};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener as TokioTcpListener, UdpSocket};
    use tokio::sync::oneshot;

    use super::*;

    const ADS_SRS: &[u8] = include_bytes!("../../../../tests/fixtures/srs/ads.srs");
    static NEXT_TEMP: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn refresh_allocation_and_retained_cache_keep_failure_categories() {
        assert_eq!(
            classify_rule_set_load_error_kind(RuleSetLoadErrorKind::Allocation),
            RunError::RuleAllocation
        );
        assert_eq!(
            refresh_rule_set_result(RuleSetRefreshOutcome::RetainedCache(
                RuleSetLoadDisposition::OfflineCache,
            )),
            RuleSetResult::Failure
        );
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct SeenDownload {
        mode: RuleSetDownloadMode,
        detour: Option<Vec<usize>>,
    }

    struct RecordingDownloader {
        fail_after: Option<usize>,
        calls: AtomicUsize,
        seen: Mutex<Vec<SeenDownload>>,
    }

    impl RecordingDownloader {
        fn success() -> Self {
            Self {
                fail_after: None,
                calls: AtomicUsize::new(0),
                seen: Mutex::new(Vec::new()),
            }
        }

        fn failure() -> Self {
            Self {
                fail_after: Some(0),
                calls: AtomicUsize::new(0),
                seen: Mutex::new(Vec::new()),
            }
        }

        fn success_then_failure() -> Self {
            Self {
                fail_after: Some(1),
                calls: AtomicUsize::new(0),
                seen: Mutex::new(Vec::new()),
            }
        }

        fn seen(&self) -> Vec<SeenDownload> {
            self.seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    impl RuleSetDownloader for RecordingDownloader {
        fn fetch(&self, request: RuleSetDownloadRequest) -> RuleSetDownloadFuture<'_> {
            self.seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(SeenDownload {
                    mode: request.mode(),
                    detour: request.detour().map(|plan| plan.hops().to_vec()),
                });
            let call = self.calls.fetch_add(1, Ordering::AcqRel);
            let fail = self.fail_after.is_some_and(|threshold| call >= threshold);
            Box::pin(async move {
                if fail {
                    Err(RuleSetDownloadError::new(RuleSetDownloadErrorKind::Connect))
                } else {
                    Ok(RuleSetDownloadResponse::downloaded(
                        Box::new(ADS_SRS),
                        None,
                        None,
                    ))
                }
            })
        }
    }

    struct TestConfig {
        path: PathBuf,
        cache_dir: PathBuf,
    }

    impl TestConfig {
        fn new(source: impl FnOnce(&str) -> String) -> Self {
            let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let base = std::env::temp_dir().join(format!(
                "ferrum2-server-materialize-{}-{id}",
                std::process::id()
            ));
            let path = base.with_extension("toml");
            let cache_dir = base.with_extension("cache");
            let cache = cache_dir.to_string_lossy().replace('\\', "/");
            std::fs::write(&path, source(&cache)).expect("write server materializer config");
            Self { path, cache_dir }
        }
    }

    impl Drop for TestConfig {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_dir_all(&self.cache_dir);
        }
    }

    fn reserve_address() -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve address");
        listener.local_addr().expect("reserved address")
    }

    #[tokio::test]
    async fn deferred_ruleset_domain_uses_the_selected_direct_resolver() {
        let listener = TokioTcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("deferred RuleSet listener");
        let address = listener.local_addr().expect("deferred RuleSet address");
        let unavailable = super::super::dns_egress::ServerDnsResolver::for_direct(
            DirectDomainResolver::DnsServer {
                server: 0,
                strategy: ferrum2_config::DnsStrategy::Ipv4Only,
            },
            Arc::new(std::sync::OnceLock::new()),
        );
        let system = super::super::dns_egress::ServerDnsResolver::for_direct(
            DirectDomainResolver::System,
            Arc::new(std::sync::OnceLock::new()),
        );
        let dialer = ServerRuleSetDialer::new(
            vec![unavailable, system],
            ServerPhysicalSocketContext::test(2, Arc::new(Metrics::new())),
        );
        let target = RuleSetDialTargets::Domain(
            TargetAddr::domain("localhost", address.port()).expect("deferred RuleSet target"),
        );
        let detour = ferrum2_core::route::EgressPlanHandle::direct(1).snapshot_owned();
        let accepted =
            tokio::spawn(async move { listener.accept().await.expect("deferred RuleSet accept") });

        let stream = dialer
            .connect(
                &target,
                Some(&detour),
                Instant::now() + Duration::from_secs(1),
            )
            .await
            .expect("selected Direct domain dial");
        drop(stream);
        let _ = accepted.await.expect("deferred RuleSet accept join");
    }

    fn old_v2_source(listen: SocketAddr) -> String {
        format!(
            r#"schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "{listen}"

[[outbounds]]
tag = "direct"

[route]
final = "direct"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#
        )
    }

    fn remote_v2_source(listen: SocketAddr, cache: &str, update_interval: bool) -> String {
        let update = if update_interval {
            "update_interval_seconds = 60\n"
        } else {
            ""
        };
        format!(
            r#"schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "{listen}"

[[outbounds]]
tag = "direct"

[route]
final = "direct"

[[route.rule_set]]
tag = "ads"
type = "remote"
url = "https://rules.example.invalid/ads.srs"
download_resolver = "system"
download_detour = "direct"
{update}
[[route.rules]]
rule_set = "ads"
action = "reject"

[rule_set_loader]
cache_dir = "{cache}"
download_timeout_ms = 1000
max_redirects = 0

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#
        )
    }

    fn cached_dns_v2_source(listen: SocketAddr, upstream: SocketAddr) -> String {
        format!(
            r#"schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "{listen}"

[[outbounds]]
tag = "direct"

[route]
final = "direct"

[dns]
strategy = "ipv4_only"

[dns.cache]
enabled = true
max_entries = 8

[[dns.servers]]
tag = "configured"
transport = "udp"
address = "{upstream}"

[dns.route]
final = "configured"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#
        )
    }

    #[tokio::test]
    async fn old_v2_materializes_without_network_or_refresh_owner() {
        let listen = reserve_address();
        let file = TestConfig::new(|_| old_v2_source(listen));
        let prepared = ferrum2_config::prepare_server_v2(&file.path).expect("prepare old V2");
        let downloader = Arc::new(RecordingDownloader::failure());
        let context = ServerV2MaterializeContext::with_downloader(
            Arc::new(Metrics::new()),
            downloader.clone(),
        );

        let materialized = materialize_prepared(prepared, &context)
            .await
            .expect("materialize old V2");
        assert!(downloader.seen().is_empty());
        assert!(materialized.pending.is_none());
        let config = materialized
            .validate_only_shutdown()
            .await
            .expect("validation-only cleanup");
        assert_eq!(SocketAddr::V4(config.inbounds[0].listen), listen);
    }

    #[tokio::test]
    async fn numeric_bootstrap_materializes_domain_dns_upstream_in_dependency_order() {
        let listen = reserve_address();
        let resolved_upstream = reserve_address();
        let bootstrap = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("numeric bootstrap DNS");
        let bootstrap_address = bootstrap.local_addr().expect("bootstrap DNS address");
        let observed = Arc::new(Mutex::new(Vec::new()));
        let worker_observed = Arc::clone(&observed);
        let (stop, mut stopped) = oneshot::channel();
        let worker = tokio::spawn(async move {
            let mut wire = [0_u8; 4096];
            loop {
                let received = tokio::select! {
                    _ = &mut stopped => break,
                    received = bootstrap.recv_from(&mut wire) => received,
                };
                let (length, peer) = received.expect("bootstrap DNS receive");
                let request = Message::from_vec(&wire[..length]).expect("bootstrap DNS decode");
                let [query] = request.queries.as_slice() else {
                    panic!("one bootstrap DNS question");
                };
                worker_observed
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push((query.name().to_ascii(), query.query_type()));
                let mut response = Message::response(request.id, OpCode::Query);
                response.metadata.recursion_available = true;
                response.add_query(query.clone());
                response.add_answer(Record::from_rdata(
                    query.name().clone(),
                    60,
                    RData::A(A(Ipv4Addr::LOCALHOST)),
                ));
                bootstrap
                    .send_to(&response.to_vec().expect("bootstrap DNS encode"), peer)
                    .await
                    .expect("bootstrap DNS response");
            }
        });
        let file = TestConfig::new(|_| {
            format!(
                r#"schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "{listen}"

[[outbounds]]
tag = "direct"

[route]
final = "direct"

[dns]
timeout_ms = 1000
max_inflight = 8
strategy = "ipv4_only"

[[dns.servers]]
tag = "bootstrap"
transport = "udp"
address = "{bootstrap_address}"

[[dns.servers]]
tag = "resolved"
transport = "udp"
address = "upstream.test:{}"
domain_resolver = "bootstrap"
domain_strategy = "ipv4_only"

[dns.route]
final = "resolved"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#,
                resolved_upstream.port()
            )
        });
        let prepared =
            ferrum2_config::prepare_server_v2(&file.path).expect("prepare domain DNS upstream V2");
        let order = prepared.materialization_order();
        let bootstrap_position = order
            .iter()
            .position(|node| *node == ferrum2_config::PreparedDependencyNode::DnsServer(0))
            .expect("bootstrap dependency node");
        let resolved_position = order
            .iter()
            .position(|node| *node == ferrum2_config::PreparedDependencyNode::DnsServer(1))
            .expect("resolved dependency node");
        assert!(bootstrap_position < resolved_position);

        let metrics = Arc::new(Metrics::new());
        let context = ServerV2MaterializeContext::new(Arc::clone(&metrics));
        let materialized = materialize_prepared(prepared, &context)
            .await
            .expect("materialize domain DNS upstream through numeric bootstrap");
        assert!(materialized.pending.is_none());
        let dns = materialized
            .config()
            .dns
            .as_ref()
            .expect("materialized DNS");
        assert_eq!(
            dns.servers[0].target.as_socket_addr(),
            Some(bootstrap_address)
        );
        assert_eq!(
            dns.servers[1].target.canonical_domain().unwrap().as_str(),
            "upstream.test"
        );
        assert_eq!(
            dns.servers[1].resolved_targets.as_ref(),
            &[SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                resolved_upstream.port()
            )]
        );
        assert_eq!(
            *observed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            [("upstream.test.".to_owned(), RecordType::A)],
            "materialization issued anything other than the single bootstrap query"
        );
        let encoded = metrics.encode_text().expect("bootstrap DNS metrics");
        for expected in [
            "ferrum2_dns_resolve_total{resolver=\"configured\",purpose=\"fixed_endpoint\",result=\"success\"} 1",
            "ferrum2_dns_implicit_system_fallback_total 0",
        ] {
            assert!(
                encoded.contains(expected),
                "missing `{expected}`\n{encoded}"
            );
        }
        assert!(
            !encoded
                .contains("ferrum2_dns_explicit_system_resolve_total{purpose=\"fixed_endpoint\"}")
        );
        materialized
            .validate_only_shutdown()
            .await
            .expect("domain DNS upstream validation-only cleanup");
        let rebound = TcpListener::bind(listen).expect("server inbound remained unbound");
        drop(rebound);
        let _ = stop.send(());
        worker.await.expect("bootstrap DNS worker");
    }

    #[tokio::test]
    async fn production_ruleset_transport_uses_tagged_dns_and_reaps_failed_tls_path() {
        let listen = reserve_address();
        let bootstrap = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("RuleSet tagged DNS");
        let bootstrap_address = bootstrap.local_addr().expect("RuleSet DNS address");
        let observed = Arc::new(Mutex::new(Vec::new()));
        let worker_observed = Arc::clone(&observed);
        let (stop, mut stopped) = oneshot::channel();
        let dns_worker = tokio::spawn(async move {
            let mut wire = [0_u8; 4096];
            loop {
                let received = tokio::select! {
                    _ = &mut stopped => break,
                    received = bootstrap.recv_from(&mut wire) => received,
                };
                let (length, peer) = received.expect("RuleSet DNS receive");
                let request = Message::from_vec(&wire[..length]).expect("RuleSet DNS decode");
                let [query] = request.queries.as_slice() else {
                    panic!("one RuleSet DNS question");
                };
                worker_observed
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push((query.name().to_ascii(), query.query_type()));
                let mut response = Message::response(request.id, OpCode::Query);
                response.metadata.recursion_available = true;
                response.add_query(query.clone());
                response.add_answer(Record::from_rdata(
                    query.name().clone(),
                    60,
                    RData::A(A(Ipv4Addr::LOCALHOST)),
                ));
                bootstrap
                    .send_to(&response.to_vec().expect("RuleSet DNS encode"), peer)
                    .await
                    .expect("RuleSet DNS response");
            }
        });
        let tls_listener = TokioTcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("controlled RuleSet TLS endpoint");
        let tls_address = tls_listener.local_addr().expect("RuleSet TLS address");
        let tls_worker = tokio::spawn(async move {
            let (mut stream, _) =
                tokio::time::timeout(Duration::from_secs(3), tls_listener.accept())
                    .await
                    .expect("RuleSet TCP connect timeout")
                    .expect("RuleSet TCP connect");
            let mut client_hello = [0_u8; 4096];
            let received =
                tokio::time::timeout(Duration::from_secs(3), stream.read(&mut client_hello))
                    .await
                    .expect("RuleSet TLS ClientHello timeout")
                    .expect("RuleSet TLS ClientHello read");
            assert!(
                received > 0,
                "production downloader sent no TLS ClientHello"
            );
            stream
                .write_all(&[0, 0, 0, 0, 0])
                .await
                .expect("write controlled invalid TLS record");
            let mut drain = [0_u8; 256];
            loop {
                let length = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut drain))
                    .await
                    .expect("production RuleSet bridge did not close")
                    .expect("read RuleSet bridge shutdown");
                if length == 0 {
                    break;
                }
            }
            received
        });
        let file = TestConfig::new(|cache| {
            format!(
                r#"schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "{listen}"

[[outbounds]]
tag = "direct"
bind_interface = "test-loopback"

[route]
final = "direct"

[[route.rule_set]]
tag = "private-rule-tag"
type = "remote"
url = "https://rules.test:{}/ads.srs"
download_resolver = "bootstrap"
download_detour = "direct"

[[route.rules]]
rule_set = "private-rule-tag"
action = "reject"

[rule_set_loader]
cache_dir = "{cache}"
download_timeout_ms = 2000
max_redirects = 0

[dns]
timeout_ms = 1000
max_inflight = 8
strategy = "ipv4_only"

[[dns.servers]]
tag = "bootstrap"
transport = "udp"
address = "{bootstrap_address}"

[dns.route]
final = "bootstrap"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#,
                tls_address.port()
            )
        });
        let prepared = ferrum2_config::prepare_server_v2(&file.path)
            .expect("prepare production tagged RuleSet V2");
        let order = prepared.materialization_order();
        let resolver_position = order
            .iter()
            .position(|node| *node == ferrum2_config::PreparedDependencyNode::DnsServer(0))
            .expect("RuleSet resolver dependency node");
        let rule_set_position = order
            .iter()
            .position(|node| *node == ferrum2_config::PreparedDependencyNode::RuleSet(0))
            .expect("RuleSet dependency node");
        assert!(resolver_position < rule_set_position);
        let metrics = Arc::new(Metrics::new());
        let context = ServerV2MaterializeContext::new(Arc::clone(&metrics));
        let error = match materialize_prepared(prepared, &context).await {
            Ok(_) => panic!("controlled TLS endpoint unexpectedly materialized"),
            Err(error) => error,
        };
        assert_eq!(error, RunError::RuleSetDownload);
        for rendered in [error.to_string(), format!("{error:?}")] {
            assert!(!rendered.contains("private-rule-tag"));
            assert!(!rendered.contains("rules.test"));
        }
        assert_eq!(
            *observed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            [("rules.test.".to_owned(), RecordType::A)],
            "RuleSet resolution escaped its selected tagged resolver"
        );
        assert!(context.take_pending().is_none());
        let tls_bytes = tls_worker.await.expect("controlled RuleSet TLS worker");
        assert!(tls_bytes > 0);
        let rebound = TcpListener::bind(listen).expect("server inbound remained unbound");
        drop(rebound);
        let encoded = metrics
            .encode_text()
            .expect("production RuleSet DNS metrics");
        for expected in [
            "ferrum2_dns_resolve_total{resolver=\"configured\",purpose=\"ruleset_download\",result=\"success\"} 1",
            "ferrum2_dns_implicit_system_fallback_total 0",
            "ferrum2_outbound_interface_resolution_total{source=\"outbound_explicit\",result=\"success\"} 1",
            "ferrum2_outbound_interface_resolution_total{source=\"system_best_route\",result=\"success\"} 1",
        ] {
            assert!(
                encoded.contains(expected),
                "missing `{expected}`\n{encoded}"
            );
        }
        assert!(
            !encoded.contains(
                "ferrum2_dns_explicit_system_resolve_total{purpose=\"ruleset_download\"}"
            )
        );
        let _ = stop.send(());
        dns_worker.await.expect("RuleSet DNS worker");
        let rebound = UdpSocket::bind(bootstrap_address)
            .await
            .expect("test DNS endpoint fully reaped");
        drop(rebound);
    }

    #[test]
    fn validate_only_entrypoint_never_binds_listener() {
        let listen = reserve_address();
        let file = TestConfig::new(|_| old_v2_source(listen));
        let prepared = ferrum2_config::prepare_server_v2(&file.path).expect("prepare old V2");
        super::super::materialize_only(prepared).expect("materialized validation");
        let rebound = TcpListener::bind(listen).expect("validate-only did not bind listener");
        drop(rebound);
    }

    #[tokio::test]
    async fn real_srs_initial_snapshot_finishes_before_listener_bind() {
        let listen = reserve_address();
        let file = TestConfig::new(|cache| remote_v2_source(listen, cache, false));
        let prepared = ferrum2_config::prepare_server_v2(&file.path).expect("prepare remote V2");
        let downloader = Arc::new(RecordingDownloader::success());
        let metrics = Arc::new(Metrics::new());
        let context =
            ServerV2MaterializeContext::with_downloader(Arc::clone(&metrics), downloader.clone());

        let materialized = materialize_prepared(prepared, &context)
            .await
            .expect("materialize real SRS");
        let registry = materialized
            .config()
            .route_program
            .as_ref()
            .and_then(ferrum2_config::CompiledRoute::rule_registry)
            .expect("materialized registry");
        let snapshot = registry.snapshot();
        let rule_set = snapshot.rule_set_id("ads").expect("compiled ads RuleSet");
        let descriptor = snapshot.rule_set(rule_set).expect("ads descriptor");
        assert!(
            snapshot
                .match_set(descriptor.match_set())
                .expect("ads match set")
                .entry_counts()
                .total()
                > 0
        );
        assert_eq!(snapshot.generation(), INITIAL_RULESET_GENERATION);
        assert_eq!(
            downloader.seen(),
            [SeenDownload {
                mode: RuleSetDownloadMode::ClientResolved(RuleSetDownloadResolver::System),
                detour: Some(vec![0]),
            }]
        );
        let rebound =
            TcpListener::bind(listen).expect("listener was not opened during materialize");
        drop(rebound);
        let encoded = metrics.encode_text().expect("metrics encode");
        assert!(encoded.contains("ferrum2_ruleset_generation 1"));
        materialized
            .validate_only_shutdown()
            .await
            .expect("drop refresh plan");
    }

    #[tokio::test]
    async fn initial_ruleset_failure_returns_before_listener_bind() {
        let listen = reserve_address();
        let file = TestConfig::new(|cache| remote_v2_source(listen, cache, false));
        let prepared = ferrum2_config::prepare_server_v2(&file.path).expect("prepare remote V2");
        let downloader = Arc::new(RecordingDownloader::failure());
        let context = ServerV2MaterializeContext::with_downloader(
            Arc::new(Metrics::new()),
            downloader.clone(),
        );

        assert!(matches!(
            materialize_prepared(prepared, &context).await,
            Err(RunError::RuleSetDownload)
        ));
        assert_eq!(downloader.seen().len(), 1);
        let rebound = TcpListener::bind(listen).expect("failed materialize never bound listener");
        drop(rebound);
    }

    #[tokio::test]
    async fn refresh_failure_retains_generation_and_root_cleanup_is_explicit() {
        let listen = reserve_address();
        let file = TestConfig::new(|cache| remote_v2_source(listen, cache, true));
        let prepared = ferrum2_config::prepare_server_v2(&file.path).expect("prepare refresh V2");
        let downloader = Arc::new(RecordingDownloader::success_then_failure());
        let context = ServerV2MaterializeContext::with_downloader(
            Arc::new(Metrics::new()),
            downloader.clone(),
        );
        let materialized = materialize_prepared(prepared, &context)
            .await
            .expect("strict initial snapshot");
        let (config, root, _cache) = materialized
            .into_run_parts()
            .await
            .expect("transfer refresh ownership");
        let registry = config
            .route_program
            .as_ref()
            .and_then(ferrum2_config::CompiledRoute::rule_registry)
            .expect("route registry");
        let mut root = root.expect("refresh root");
        let outcome = root
            .service
            .as_ref()
            .expect("refresh service")
            .refresh_once(0)
            .await;
        assert!(matches!(
            outcome,
            RuleSetRefreshOutcome::Failed(_) | RuleSetRefreshOutcome::RetainedCache(_)
        ));
        assert_eq!(registry.generation(), INITIAL_RULESET_GENERATION);
        assert_eq!(downloader.seen().len(), 2);
        root.cleanup().await.expect("refresh owner cleanup");
        assert!(root.service.is_none());
        assert!(root.tagged.is_none());
        assert!(root.owner.is_none());
    }

    #[tokio::test]
    async fn composition_failure_before_supervisor_joins_materialization_owner() {
        let listen = reserve_address();
        let upstream = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("owner probe upstream");
        let upstream_address = upstream.local_addr().expect("probe upstream address");
        let file = TestConfig::new(|_| cached_dns_v2_source(listen, upstream_address));
        let prepared = ferrum2_config::prepare_server_v2(&file.path).expect("prepare cached V2");
        let context = ServerV2MaterializeContext::with_downloader(
            Arc::new(Metrics::new()),
            Arc::new(RecordingDownloader::failure()),
        );
        let config = materialize_prepared(prepared, &context)
            .await
            .expect("materialize cached V2")
            .validate_only_shutdown()
            .await
            .expect("finish cached V2");
        let dns_specs = config
            .dns
            .as_ref()
            .map(|dns| super::super::dns_egress::dns_runtime_specs(&dns.servers));

        let (resolver, mut owner) = TaggedResolver::direct(
            vec![DnsUpstreamSpec {
                transport: DnsUpstreamTransport::Udp,
                target: TargetAddr::ip(upstream_address).expect("numeric upstream"),
                resolved_targets: Box::new([]),
                detour: None,
            }],
            Duration::from_secs(1),
            std::num::NonZeroU16::MIN,
        )
        .expect("owner probe resolver");
        owner.ready().await.expect("owner probe ready");
        let probe = Arc::new(resolver);
        let root = ServerV2RuntimeRoot {
            service: None,
            tagged: Some(Arc::clone(&probe)),
            owner: Some(owner),
        };
        let result = super::super::run_with_registry_prepared(
            config,
            ferrum2_runtime::OwnerRegistry::new(),
            std::future::pending(),
            Arc::new(Metrics::new()),
            super::super::ServerRunResources {
                materialization_root: Some(root),
                // Strict V2 composition rejects this missing shared cache.
                materialized_cache: None,
                dns_specs,
                materialized: true,
                network_sockets: None,
            },
        )
        .await;
        assert_eq!(result, Err(RunError::StartupProtocol));
        let domain = ferrum2_core::CanonicalDomain::new("joined.example").expect("probe domain");
        assert!(matches!(
            probe
                .lookup_fixed_endpoint(0, domain, DnsCacheQtype::A)
                .await,
            Err(DnsError::Shutdown)
        ));
    }
}
