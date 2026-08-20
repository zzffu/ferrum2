use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ferrum2_config::{
    ClientV2MaterializeFuture, ClientV2Resources, CompiledRuleSetResource, DialEndpoint,
    PreparedClientOutboundKind, PreparedClientV2, PreparedFixedEndpointTarget, ResolvedDnsEndpoint,
    ResolvedOutboundEndpoint, ResolverRef,
};
use ferrum2_core::TargetAddr;
use ferrum2_core::route::{EgressPlanHandle, EgressPlanSnapshot};
use ferrum2_crypto::{MethodPsk, MethodSinglePskProvider, SystemClock, SystemRandom};
use ferrum2_dns::{
    ApplicationResolver, DnsAddressRecords, DnsCache, DnsCacheLookup, DnsCacheQtype, DnsError,
    DnsServerId, DnsStrategy, DnsUpstreamSpec, DnsUpstreamTransport, FixedEndpointKind,
    FixedEndpointLookup, FixedEndpointMaterializeError, FixedEndpointPlanEntry,
    FixedEndpointResolveBackend, FixedEndpointResolveFuture, FixedEndpointResolveRequest,
    FixedEndpointSpec, MAX_APPLICATION_RESOLVED_CANDIDATES, MaterializedFixedEndpoint,
    ResolverGeneration, TaggedResolver, TaggedResolverOwner, materialize_fixed_endpoints,
};
use ferrum2_observability::{
    CompiledMatchType, DnsResolvePurpose, DnsResolveResult, DnsResolverKind, Metrics, RuleSetResult,
};
use ferrum2_rule::{RuleEngineRegistry, RuleEngineSnapshot, RuleSetId};
use ferrum2_runtime::{
    ApplicationResolverAdapter, ExplicitRuleSetHostResolver, HttpsRuleSetDownloader, OwnerRegistry,
    PreparedProcessRoot, ProcessCancellation, ProcessFuture, RuleSetCacheName, RuleSetDialer,
    RuleSetDownloadError, RuleSetDownloadErrorKind, RuleSetDownloadResolver, RuleSetDownloader,
    RuleSetHostResolveObserver, RuleSetHostResolveOutcome, RuleSetHostResolverKind,
    RuleSetLoadDisposition, RuleSetLoadError, RuleSetLoadErrorKind, RuleSetLoader,
    RuleSetLoaderConfig, RuleSetRefreshOutcome, RuleSetRefreshService, RuleSetRemoteSource,
    UdpRuntimeLimits, UdpSessionManager, materialize_rule_set_snapshot,
};
use ferrum2_shadowsocks::MethodKeyAdapter;
use tokio::io::DuplexStream;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::dns_egress::ClientDnsEgress;
use super::egress::{
    ClientEgressEngine, ClientOutboundContext, ClientRequestOrigin, ClientShadowsocksContext,
    ClientUdpContext,
};
use super::tokio_io::{TokioConnector, TokioFramed};
use super::{RunError, dns_strategy};

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

/// Production schema-v2 materializer. The context is single-use because a
/// successful materialization transfers its resolver and refresh ownership to
/// exactly one client process root.
pub(super) struct ClientV2MaterializeContext {
    metrics: Arc<Metrics>,
    downloader: Option<Arc<dyn RuleSetDownloader>>,
    pending: Mutex<Option<PendingClientV2Runtime>>,
    cache: Mutex<Option<DnsCache>>,
    failure: Mutex<Option<RunError>>,
    underlay: ferrum2_tun::UnderlayPublisher,
    used: AtomicBool,
}

impl ClientV2MaterializeContext {
    pub(super) fn new(metrics: Arc<Metrics>, underlay: ferrum2_tun::UnderlayPublisher) -> Self {
        Self {
            metrics,
            downloader: None,
            pending: Mutex::new(None),
            cache: Mutex::new(None),
            failure: Mutex::new(None),
            underlay,
            used: AtomicBool::new(false),
        }
    }

    #[cfg(test)]
    fn with_downloader(metrics: Arc<Metrics>, downloader: Arc<dyn RuleSetDownloader>) -> Self {
        Self {
            metrics,
            downloader: Some(downloader),
            pending: Mutex::new(None),
            cache: Mutex::new(None),
            failure: Mutex::new(None),
            underlay: ferrum2_tun::UnderlayPublisher::new(),
            used: AtomicBool::new(false),
        }
    }

    fn take_pending(&self) -> Option<PendingClientV2Runtime> {
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
        prepared: &PreparedClientV2,
    ) -> Result<ClientV2Resources, RunError> {
        if self.used.swap(true, Ordering::AcqRel) {
            return Err(RunError::StartupProtocol);
        }

        let blueprint = Arc::new(BootstrapBlueprint::new(prepared)?);
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
        let (dns_endpoints, outbound_endpoints) = backend.finished_resources(prepared)?;

        let sources = rule_set_sources(prepared)?;
        if sources.is_empty() {
            return Ok(ClientV2Resources::new(
                dns_endpoints,
                outbound_endpoints,
                Vec::new(),
            ));
        }

        let loader_config = runtime_loader_config(prepared)?;
        let needs_tagged = prepared
            .rule_sets()
            .iter()
            .any(|rule_set| matches!(rule_set.download_resolver(), ResolverRef::DnsServer(_)));
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
                underlay: self.underlay.clone(),
                auto_route: prepared.tun_auto_route(),
                needs_tagged,
                metrics: Arc::clone(&self.metrics),
            }),
        };
        // Initial materialization is deliberately isolated from the eventual
        // TUN route. It is completely joined before the prepared config is
        // exposed; the refresh transport is rebuilt only when the process root
        // is transferred to the supervisor.
        let initial_transport = match self.downloader.as_ref() {
            Some(downloader) => {
                ActiveRuleSetTransport::injected(loader_config, Arc::clone(downloader))
            }
            None => {
                ProductionRuleSetTransport {
                    blueprint: Arc::clone(&blueprint),
                    addresses,
                    loader_config,
                    cache: cache.clone(),
                    underlay: self.underlay.clone(),
                    auto_route: false,
                    needs_tagged,
                    metrics: Arc::clone(&self.metrics),
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
        let pending = PendingClientV2Runtime {
            transport: pending_transport,
            sources,
            rule_set_ids: rule_set_ids.into_vec(),
            metrics: Arc::clone(&self.metrics),
        };
        let pending = {
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
        if let Some(pending) = pending {
            pending.shutdown().await?;
            return Err(RunError::StartupProtocol);
        }
        Ok(ClientV2Resources::new(
            dns_endpoints,
            outbound_endpoints,
            rule_sets,
        ))
    }
}

impl ferrum2_config::ClientV2MaterializeContext for ClientV2MaterializeContext {
    fn materialize_client<'a>(
        &'a self,
        prepared: &'a PreparedClientV2,
    ) -> ClientV2MaterializeFuture<'a> {
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

pub(super) struct PendingClientV2Runtime {
    transport: PendingRuleSetTransport,
    sources: Vec<RuleSetRemoteSource>,
    rule_set_ids: Vec<RuleSetId>,
    metrics: Arc<Metrics>,
}

impl PendingClientV2Runtime {
    async fn into_prepared_root(
        self,
        registry: Arc<RuleEngineRegistry>,
    ) -> Result<ClientV2RuntimeRoot, RunError> {
        let PendingClientV2Runtime {
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
        Ok(ClientV2RuntimeRoot {
            service: Some(Arc::new(service)),
            tagged: active.tagged.take(),
            owner: active.owner.take(),
            bridges: Arc::clone(&active.bridges),
        })
    }

    async fn shutdown(self) -> Result<(), RunError> {
        // The initial transport is joined before PendingClientV2Runtime is
        // stored. Until `into_prepared_root`, this value is a pure construction
        // plan and owns no task or resolver thread.
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
    underlay: ferrum2_tun::UnderlayPublisher,
    auto_route: bool,
    needs_tagged: bool,
    metrics: Arc<Metrics>,
}

impl ProductionRuleSetTransport {
    async fn activate(self, generation: u64) -> Result<ActiveRuleSetTransport, RunError> {
        let bridges = Arc::new(RuleSetBridgeTasks::default());
        let engine =
            self.blueprint
                .build_engine(&self.addresses, self.underlay, self.auto_route)?;
        let (tagged, owner) = if self.needs_tagged {
            let (resolver, mut owner) = self
                .blueprint
                .tagged_resolver_with_addresses(Arc::clone(&engine), &self.addresses)?;
            if owner.ready().await.is_err() {
                drop(resolver);
                let _ = owner.shutdown().await;
                bridges.shutdown().await;
                return Err(RunError::StartupProtocol);
            }
            (Some(Arc::new(resolver)), Some(owner))
        } else {
            (None, None)
        };
        let mut resolver = ExplicitRuleSetHostResolver::new(
            tagged.as_ref().map(Arc::clone),
            self.blueprint.dns_strategy,
        );
        if let Some(cache) = self.cache {
            resolver = resolver.with_cache(cache, ResolverGeneration::new(generation));
        }
        resolver = resolver.with_observer(rule_set_host_resolve_observer(&self.metrics));
        let dialer = ClientRuleSetDialer {
            engine,
            bridges: Arc::clone(&bridges),
        };
        let downloader: Arc<dyn RuleSetDownloader> =
            Arc::new(HttpsRuleSetDownloader::new(resolver, dialer));
        Ok(ActiveRuleSetTransport {
            loader: Arc::new(RuleSetLoader::new(self.loader_config, downloader)),
            tagged,
            owner,
            bridges,
        })
    }
}

struct ActiveRuleSetTransport {
    loader: Arc<RuleSetLoader<Arc<dyn RuleSetDownloader>>>,
    tagged: Option<Arc<TaggedResolver>>,
    owner: Option<TaggedResolverOwner>,
    bridges: Arc<RuleSetBridgeTasks>,
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
            bridges: Arc::new(RuleSetBridgeTasks::default()),
        }
    }

    async fn shutdown(self) -> Result<(), RunError> {
        // Stop its blocking work, then drop the loader so the downloader can
        // release every engine and resolver clone before transport owners join.
        let Self {
            loader,
            tagged,
            owner,
            bridges,
        } = self;
        let loader_cleanup = loader
            .shutdown()
            .await
            .map_err(classify_rule_set_load_error);
        drop(loader);
        let transport_cleanup = cleanup_materialization(tagged, owner, &bridges).await;
        loader_cleanup.and(transport_cleanup)
    }
}

pub(super) struct ClientV2RuntimeRoot {
    service: Option<Arc<RuleSetRefreshService<Arc<dyn RuleSetDownloader>>>>,
    tagged: Option<Arc<TaggedResolver>>,
    owner: Option<TaggedResolverOwner>,
    bridges: Arc<RuleSetBridgeTasks>,
}

impl ClientV2RuntimeRoot {
    pub(super) async fn cleanup(&mut self) -> Result<(), RunError> {
        let service_cleanup = match self.service.take() {
            Some(service) => service
                .shutdown()
                .await
                .map_err(classify_rule_set_load_error),
            None => Ok(()),
        };
        self.bridges.shutdown().await;
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

impl PreparedProcessRoot<RunError> for ClientV2RuntimeRoot {
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

#[derive(Clone)]
enum BootstrapOutbound {
    Direct,
    Shadowsocks {
        psk: Arc<MethodPsk>,
        endpoint: DialEndpoint,
    },
}

#[derive(Clone)]
struct BootstrapDnsServer {
    transport: ferrum2_config::DnsTransport,
    server_name: Option<Box<str>>,
    path: Option<Box<str>>,
    detour: Option<EgressPlanHandle>,
    endpoint: DialEndpoint,
}

struct BootstrapBlueprint {
    outbounds: Vec<BootstrapOutbound>,
    dns_servers: Vec<BootstrapDnsServer>,
    dns_timeout: Duration,
    dns_max_inflight: std::num::NonZeroU16,
    dns_strategy: DnsStrategy,
    runtime: ferrum2_config::RuntimeConfig,
}

impl BootstrapBlueprint {
    fn new(prepared: &PreparedClientV2) -> Result<Self, RunError> {
        let mut outbounds = Vec::new();
        outbounds
            .try_reserve_exact(prepared.outbound_count())
            .map_err(|_| RunError::RuleAllocation)?;
        for index in 0..prepared.outbound_count() {
            let descriptor = prepared
                .outbound(u32::try_from(index).map_err(|_| RunError::StartupProtocol)?)
                .ok_or(RunError::StartupProtocol)?;
            outbounds.push(match descriptor.kind() {
                PreparedClientOutboundKind::Direct => BootstrapOutbound::Direct,
                PreparedClientOutboundKind::Shadowsocks => BootstrapOutbound::Shadowsocks {
                    psk: Arc::clone(descriptor.psk().ok_or(RunError::StartupProtocol)?),
                    endpoint: descriptor
                        .endpoint()
                        .ok_or(RunError::StartupProtocol)?
                        .clone(),
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
                BootstrapOutbound::Direct => ClientOutboundContext::Direct,
                BootstrapOutbound::Shadowsocks { psk, endpoint } => {
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
                    })
                }
            });
        }
        Ok(outbounds.into())
    }

    fn build_engine(
        &self,
        addresses: &BootstrapAddresses,
        underlay: ferrum2_tun::UnderlayPublisher,
        auto_route: bool,
    ) -> Result<Arc<ClientEgressEngine>, RunError> {
        let outbounds = self.build_outbounds(addresses)?;
        let application_resolver = ApplicationResolverAdapter::new(
            Arc::new(ApplicationResolver::system_default()),
            0,
            self.dns_strategy,
        );
        #[cfg(all(windows, not(test)))]
        let connector =
            TokioConnector::new(ferrum2_runtime::TcpConnector::with_resolution_adapters(
                ferrum2_runtime::SystemSocketInspector,
                super::egress::ManagedTcpDialer::new(underlay.clone()),
                application_resolver.clone(),
                self.runtime.connect_timeout,
            ));
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
        Ok(Arc::new(
            ClientEgressEngine::new_with_application_resolver(
                outbounds,
                connector,
                SystemClock::new(),
                SystemRandom,
                (self.runtime.connect_timeout, self.runtime.handshake_timeout),
                Some(udp),
                application_resolver,
                #[cfg(test)]
                None,
            )
            .with_underlay(underlay, auto_route),
        ))
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
                address: addresses.dns[index]
                    .or_else(|| endpoint_address(&server.endpoint))
                    .unwrap_or(UNRESOLVED_ENDPOINT),
                detour: server.detour.clone(),
            })
            .collect()
    }

    fn tagged_resolver_with_addresses(
        &self,
        engine: Arc<ClientEgressEngine>,
        addresses: &BootstrapAddresses,
    ) -> Result<(TaggedResolver, TaggedResolverOwner), RunError> {
        TaggedResolver::new(
            self.dns_specs(addresses),
            self.dns_timeout,
            self.dns_max_inflight,
            Arc::new(ClientDnsEgress::new(engine)),
        )
        .map_err(|_| RunError::StartupProtocol)
    }

    fn initial_addresses(&self) -> BootstrapAddresses {
        BootstrapAddresses {
            dns: self
                .dns_servers
                .iter()
                .map(|server| endpoint_address(&server.endpoint))
                .collect(),
            outbounds: self
                .outbounds
                .iter()
                .map(|outbound| match outbound {
                    BootstrapOutbound::Direct => None,
                    BootstrapOutbound::Shadowsocks { endpoint, .. } => endpoint_address(endpoint),
                })
                .collect(),
        }
    }
}

#[derive(Clone)]
struct BootstrapAddresses {
    dns: Vec<Option<SocketAddr>>,
    outbounds: Vec<Option<SocketAddr>>,
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
        prepared: &PreparedClientV2,
    ) -> Result<(Vec<ResolvedDnsEndpoint>, Vec<ResolvedOutboundEndpoint>), RunError> {
        let addresses = self.addresses();
        let mut dns = Vec::new();
        for (index, endpoint) in prepared.dns_endpoints().iter().enumerate() {
            if endpoint.is_domain() {
                dns.push(ResolvedDnsEndpoint::new(
                    u32::try_from(index).map_err(|_| RunError::StartupProtocol)?,
                    addresses.dns[index].ok_or(RunError::StartupProtocol)?,
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
                .build_engine(&addresses, ferrum2_tun::UnderlayPublisher::new(), false)
                .map_err(|_| DnsError::Runtime)?;
            let (tagged, mut owner) = self
                .blueprint
                .tagged_resolver_with_addresses(engine, &addresses)
                .map_err(|_| DnsError::Runtime)?;
            let tagged = Arc::new(tagged);
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
        let address = *endpoint
            .candidates()
            .first()
            .ok_or(FixedEndpointMaterializeError::NoCandidates)?;
        let mut addresses = self
            .addresses
            .lock()
            .map_err(|_| FixedEndpointMaterializeError::Allocation)?;
        match *target {
            PreparedFixedEndpointTarget::DnsServer(index) => {
                *addresses
                    .dns
                    .get_mut(index as usize)
                    .ok_or(FixedEndpointMaterializeError::InvalidDependencyOrder)? = Some(address);
            }
            PreparedFixedEndpointTarget::Outbound(index) => {
                *addresses
                    .outbounds
                    .get_mut(index as usize)
                    .ok_or(FixedEndpointMaterializeError::InvalidDependencyOrder)? = Some(address);
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

fn fixed_endpoint_plan(
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

fn endpoint_address(endpoint: &DialEndpoint) -> Option<SocketAddr> {
    match endpoint {
        DialEndpoint::Ip(address) => Some(*address),
        DialEndpoint::Domain { .. } => None,
    }
}

fn materialization_cache(
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

fn rule_set_host_resolve_observer(metrics: &Arc<Metrics>) -> Arc<dyn RuleSetHostResolveObserver> {
    let metrics = Arc::clone(metrics);
    Arc::new(move |resolver, outcome| {
        let resolver = match resolver {
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
    })
}

fn runtime_loader_config(prepared: &PreparedClientV2) -> Result<RuleSetLoaderConfig, RunError> {
    let config = prepared.rule_set_loader();
    RuleSetLoaderConfig::new(
        config.cache_dir.clone(),
        config.download_timeout,
        config.max_redirects,
    )
    .map_err(|_| RunError::StartupProtocol)
}

fn rule_set_sources(prepared: &PreparedClientV2) -> Result<Vec<RuleSetRemoteSource>, RunError> {
    let mut sources = Vec::new();
    sources
        .try_reserve_exact(prepared.rule_sets().len())
        .map_err(|_| RunError::RuleAllocation)?;
    for (index, rule_set) in prepared.rule_sets().iter().enumerate() {
        let resolver = match rule_set.download_resolver() {
            ResolverRef::System => RuleSetDownloadResolver::System,
            ResolverRef::DnsServer(server) => RuleSetDownloadResolver::DnsServer(DnsServerId::new(
                u32::try_from(server).map_err(|_| RunError::StartupProtocol)?,
            )),
        };
        sources.push(
            RuleSetRemoteSource::new(
                RuleSetCacheName::new(rule_set.tag()).map_err(|_| RunError::StartupProtocol)?,
                rule_set.url(),
                resolver,
                prepared.download_detour_plan(index).cloned(),
                rule_set.update_interval(),
            )
            .map_err(|_| RunError::StartupProtocol)?,
        );
    }
    Ok(sources)
}

struct RuleSetBridgeTasks {
    accepting: AtomicBool,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl Default for RuleSetBridgeTasks {
    fn default() -> Self {
        Self {
            accepting: AtomicBool::new(true),
            tasks: Mutex::new(Vec::new()),
        }
    }
}

impl RuleSetBridgeTasks {
    fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) -> Result<(), ()> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(());
        }
        let handle = tokio::spawn(task);
        let mut tasks = match self.tasks.lock() {
            Ok(tasks) => tasks,
            Err(_) => {
                handle.abort();
                return Err(());
            }
        };
        if !self.accepting.load(Ordering::Acquire) {
            handle.abort();
            return Err(());
        }
        tasks.retain(|task| !task.is_finished());
        tasks.push(handle);
        Ok(())
    }

    async fn shutdown(&self) {
        self.accepting.store(false, Ordering::Release);
        let tasks = self
            .tasks
            .lock()
            .map(|mut tasks| std::mem::take(&mut *tasks))
            .unwrap_or_default();
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            let _ = task.await;
        }
    }
}

impl Drop for RuleSetBridgeTasks {
    fn drop(&mut self) {
        if let Ok(tasks) = self.tasks.get_mut() {
            for task in tasks.drain(..) {
                task.abort();
            }
        }
    }
}

struct ClientRuleSetDialer {
    engine: Arc<ClientEgressEngine>,
    bridges: Arc<RuleSetBridgeTasks>,
}

impl RuleSetDialer for ClientRuleSetDialer {
    type Io = DuplexStream;

    fn connect(
        &self,
        candidates: &[SocketAddr],
        detour: Option<&EgressPlanSnapshot>,
        deadline: Instant,
    ) -> impl Future<Output = Result<Self::Io, RuleSetDownloadError>> + Send {
        let candidates = candidates.to_vec();
        let detour = detour.cloned();
        let engine = Arc::clone(&self.engine);
        let bridges = Arc::clone(&self.bridges);
        async move {
            for candidate in candidates {
                if Instant::now() >= deadline {
                    return Err(RuleSetDownloadError::new(RuleSetDownloadErrorKind::Timeout));
                }
                let target = TargetAddr::ip(candidate)
                    .map_err(|_| RuleSetDownloadError::new(RuleSetDownloadErrorKind::Connect))?;
                let remaining = deadline.saturating_duration_since(Instant::now());
                let (client, mut bridge) = tokio::io::duplex(8 * 1024);
                let (ready, opened) = tokio::sync::oneshot::channel();
                let attempt_engine = Arc::clone(&engine);
                let attempt_detour = detour.clone();
                bridges
                    .spawn(async move {
                        let flow = attempt_engine
                            .open_tcp(
                                ClientRequestOrigin::Dns,
                                attempt_detour,
                                &target,
                                Some(remaining),
                                #[cfg(test)]
                                None,
                            )
                            .await;
                        let Ok(flow) = flow else {
                            let _ = ready.send(Err(()));
                            return;
                        };
                        if ready.send(Ok(())).is_err() {
                            return;
                        }
                        let mut flow = TokioFramed::new(flow);
                        let _ = tokio::io::copy_bidirectional(&mut bridge, &mut flow).await;
                    })
                    .map_err(|_| RuleSetDownloadError::new(RuleSetDownloadErrorKind::Connect))?;
                match tokio::time::timeout_at(deadline, opened).await {
                    Ok(Ok(Ok(()))) => return Ok(client),
                    Ok(Ok(Err(())) | Err(_)) => {}
                    Err(_) => {
                        return Err(RuleSetDownloadError::new(RuleSetDownloadErrorKind::Timeout));
                    }
                }
            }
            Err(RuleSetDownloadError::new(RuleSetDownloadErrorKind::Connect))
        }
    }
}

async fn cleanup_materialization(
    tagged: Option<Arc<TaggedResolver>>,
    mut owner: Option<TaggedResolverOwner>,
    bridges: &RuleSetBridgeTasks,
) -> Result<(), RunError> {
    bridges.shutdown().await;
    drop(tagged);
    if let Some(owner) = owner.as_mut() {
        owner
            .shutdown()
            .await
            .map_err(|_| RunError::ShutdownCleanup)?;
    }
    Ok(())
}

pub(super) struct MaterializedClientV2 {
    config: Option<ferrum2_config::ValidatedClientConfig>,
    pending: Option<PendingClientV2Runtime>,
    cache: Option<DnsCache>,
    underlay: ferrum2_tun::UnderlayPublisher,
}

impl MaterializedClientV2 {
    pub(super) fn config(&self) -> &ferrum2_config::ValidatedClientConfig {
        self.config.as_ref().expect("materialized client config")
    }

    /// Completes materialized validation without transferring any background
    /// resource to the process supervisor.
    pub(super) async fn validate_only_shutdown(
        mut self,
    ) -> Result<ferrum2_config::ValidatedClientConfig, RunError> {
        let policy_validation =
            validate_dns_policy_adapter(self.config.as_ref().expect("materialized client config"));
        shutdown_pending(self.pending.take()).await?;
        policy_validation?;
        Ok(self.config.take().expect("materialized client config"))
    }

    pub(super) async fn into_run_parts(
        mut self,
    ) -> Result<
        (
            ferrum2_config::ValidatedClientConfig,
            Option<ClientV2RuntimeRoot>,
            Option<DnsCache>,
            ferrum2_tun::UnderlayPublisher,
        ),
        RunError,
    > {
        let config = self.config.take().expect("materialized client config");
        let root = prepare_runtime_root(&config, self.pending.take()).await?;
        Ok((config, root, self.cache.take(), self.underlay.clone()))
    }
}

fn validate_dns_policy_adapter(
    config: &ferrum2_config::ValidatedClientConfig,
) -> Result<(), RunError> {
    let Some(binding) = config
        .dns_route
        .as_ref()
        .and_then(ferrum2_config::ClientDnsRoute::policy_blueprint)
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
    prepared: PreparedClientV2,
    context: &ClientV2MaterializeContext,
) -> Result<MaterializedClientV2, RunError> {
    let config = match ferrum2_config::materialize_client_v2(prepared, context).await {
        Ok(config) => config,
        Err(error) => {
            if let Some(pending) = context.take_pending() {
                pending.shutdown().await?;
            }
            return Err(context
                .take_failure()
                .unwrap_or_else(|| classify_config_materialization_error(error)));
        }
    };
    Ok(MaterializedClientV2 {
        config: Some(config),
        pending: context.take_pending(),
        cache: context.take_cache(),
        underlay: context.underlay.clone(),
    })
}

const fn classify_config_materialization_error(error: ferrum2_config::ConfigError) -> RunError {
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

pub(super) async fn prepare_runtime_root(
    config: &ferrum2_config::ValidatedClientConfig,
    pending: Option<PendingClientV2Runtime>,
) -> Result<Option<ClientV2RuntimeRoot>, RunError> {
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
                .and_then(ferrum2_config::ClientDnsRoute::policy_blueprint)
                .map(ferrum2_config::DnsPolicyBlueprintBinding::registry)
        });
    let Some(registry) = registry else {
        pending.shutdown().await?;
        return Err(RunError::StartupProtocol);
    };
    pending.into_prepared_root(registry).await.map(Some)
}

pub(super) async fn shutdown_pending(
    pending: Option<PendingClientV2Runtime>,
) -> Result<(), RunError> {
    if let Some(pending) = pending {
        pending.shutdown().await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, TcpListener};
    use std::path::PathBuf;
    use std::str::FromStr as _;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use ferrum2_config::RouteAction;
    use ferrum2_dns::{DnsPolicyQuery, DnsPolicyStep};
    use ferrum2_rule::{Network, RouteMetadata, RouteProgramAction};
    use ferrum2_runtime::{
        RuleSetDownloadFuture, RuleSetDownloadRequest, RuleSetDownloadResolver,
        RuleSetDownloadResponse,
    };
    use hickory_proto::op::{Message, MessageType, OpCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener as TokioTcpListener, UdpSocket};
    use tokio::sync::oneshot;

    use super::*;

    const ADS_SRS: &[u8] = include_bytes!("../../../../tests/fixtures/srs/ads.srs");
    const AI_SRS: &[u8] = include_bytes!("../../../../tests/fixtures/srs/ai.srs");
    const CN_SRS: &[u8] = include_bytes!("../../../../tests/fixtures/srs/cn.srs");
    const CNIP_SRS: &[u8] = include_bytes!("../../../../tests/fixtures/srs/cnip.srs");
    static NEXT_TEMP: AtomicUsize = AtomicUsize::new(0);

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct SeenDownload {
        resolver: RuleSetDownloadResolver,
        detour: Option<Vec<usize>>,
    }

    struct RecordingDownloader {
        fail: bool,
        fixture_set: bool,
        seen: Mutex<Vec<SeenDownload>>,
    }

    impl RecordingDownloader {
        fn success() -> Self {
            Self {
                fail: false,
                fixture_set: false,
                seen: Mutex::new(Vec::new()),
            }
        }

        fn failure() -> Self {
            Self {
                fail: true,
                fixture_set: false,
                seen: Mutex::new(Vec::new()),
            }
        }

        fn fixture_set() -> Self {
            Self {
                fail: false,
                fixture_set: true,
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
            let body = if self.fixture_set {
                match request.url().rsplit('/').next() {
                    Some("ads.srs") => ADS_SRS,
                    Some("ai.srs") => AI_SRS,
                    Some("cn.srs") => CN_SRS,
                    Some("cnip.srs") => CNIP_SRS,
                    _ => &[],
                }
            } else {
                ADS_SRS
            };
            self.seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(SeenDownload {
                    resolver: request.resolver(),
                    detour: request.detour().map(|plan| plan.hops().to_vec()),
                });
            let fail = self.fail;
            Box::pin(async move {
                if fail {
                    Err(RuleSetDownloadError::new(RuleSetDownloadErrorKind::Connect))
                } else {
                    Ok(RuleSetDownloadResponse::downloaded(
                        Box::new(body),
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
                "ferrum2-client-materialize-{}-{id}",
                std::process::id()
            ));
            let path = base.with_extension("toml");
            let cache_dir = base.with_extension("cache");
            let cache = cache_dir.to_string_lossy().replace('\\', "/");
            std::fs::write(&path, source(&cache)).expect("write materializer test config");
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

    #[test]
    fn fixed_endpoints_share_the_final_empty_or_ruleset_registry_generation() {
        assert_eq!(initial_resolver_generation(false).get(), 0);
        assert_eq!(
            initial_resolver_generation(true).get(),
            INITIAL_RULESET_GENERATION
        );
    }

    #[tokio::test]
    async fn old_v2_materializes_without_network_or_background_owner() {
        let address = reserve_address();
        let file = TestConfig::new(|_| {
            format!(
                r#"schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "{address}"

[[outbounds]]
tag = "direct"
type = "direct"

[route]
final = "direct"
"#
            )
        });
        let prepared = ferrum2_config::prepare_client_v2(&file.path).expect("prepare old V2");
        let downloader = Arc::new(RecordingDownloader::failure());
        let context = ClientV2MaterializeContext::with_downloader(
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
        assert!(
            config
                .route_program
                .as_ref()
                .is_some_and(|route| route.rule_registry().is_none())
        );
    }

    #[tokio::test]
    async fn compatibility_proxy_v2_materializes_without_network_or_background_owner() {
        let listen = reserve_address();
        let server = reserve_address();
        let file = TestConfig::new(|_| {
            format!(
                r#"schema_version = 2

[client]
listen = "{listen}"
server = "{server}"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#
            )
        });
        let prepared =
            ferrum2_config::prepare_client_v2(&file.path).expect("prepare compatibility proxy V2");
        let downloader = Arc::new(RecordingDownloader::failure());
        let context = ClientV2MaterializeContext::with_downloader(
            Arc::new(Metrics::new()),
            downloader.clone(),
        );

        let materialized = materialize_prepared(prepared, &context)
            .await
            .expect("materialize compatibility proxy V2");
        assert!(materialized.pending.is_none());
        let config = materialized
            .validate_only_shutdown()
            .await
            .expect("finish compatibility proxy V2");
        assert!(downloader.seen().is_empty());
        assert_eq!(config.outbounds.len(), 1);
        assert!(context.take_pending().is_none());
    }

    #[tokio::test]
    async fn numeric_bootstrap_materializes_domain_dns_upstream_in_dependency_order() {
        let listen = reserve_address();
        let dns_listen = reserve_address();
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
type = "direct"

[route]
final = "direct"

[dns]
timeout_ms = 1000
max_inflight = 8
strategy = "ipv4_only"

[[dns.inbounds]]
tag = "dns-in"
listen = "{dns_listen}"

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
"#,
                resolved_upstream.port()
            )
        });
        let prepared =
            ferrum2_config::prepare_client_v2(&file.path).expect("prepare domain DNS upstream V2");
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
        let context = ClientV2MaterializeContext::new(
            Arc::clone(&metrics),
            ferrum2_tun::UnderlayPublisher::new(),
        );
        let materialized = materialize_prepared(prepared, &context)
            .await
            .expect("materialize domain DNS upstream through numeric bootstrap");
        assert!(materialized.pending.is_none());
        let dns = materialized
            .config()
            .dns
            .as_ref()
            .expect("materialized DNS");
        assert_eq!(dns.servers[0].address, bootstrap_address);
        assert_eq!(
            dns.servers[1].address,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), resolved_upstream.port())
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
        let rebound = TcpListener::bind(listen).expect("client inbound remained unbound");
        drop(rebound);
        let _ = stop.send(());
        worker.await.expect("bootstrap DNS worker");
    }

    #[tokio::test]
    async fn production_ruleset_transport_uses_tagged_dns_and_reaps_failed_tls_path() {
        let listen = reserve_address();
        let dns_listen = reserve_address();
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
type = "direct"

[route]
final = "direct"

[[route.rule_set]]
tag = "private-rule-tag"
type = "remote"
url = "https://rules.test:{}/ads.srs"
download_resolver = "bootstrap"

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

[[dns.inbounds]]
tag = "dns-in"
listen = "{dns_listen}"

[[dns.servers]]
tag = "bootstrap"
transport = "udp"
address = "{bootstrap_address}"

[dns.route]
final = "bootstrap"
"#,
                tls_address.port()
            )
        });
        let prepared = ferrum2_config::prepare_client_v2(&file.path)
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
        let context = ClientV2MaterializeContext::new(
            Arc::clone(&metrics),
            ferrum2_tun::UnderlayPublisher::new(),
        );
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
        let rebound = TcpListener::bind(listen).expect("client inbound remained unbound");
        drop(rebound);
        let encoded = metrics
            .encode_text()
            .expect("production RuleSet DNS metrics");
        for expected in [
            "ferrum2_dns_resolve_total{resolver=\"configured\",purpose=\"ruleset_download\",result=\"success\"} 1",
            "ferrum2_dns_implicit_system_fallback_total 0",
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

    #[tokio::test]
    async fn fixed_endpoint_and_tcp_udp_application_share_generation_zero_cache() {
        let listen = reserve_address();
        let dns_listen = reserve_address();
        let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("tagged DNS upstream");
        let upstream_address = upstream.local_addr().expect("tagged DNS address");
        let observed = Arc::new(Mutex::new(Vec::new()));
        let worker_observed = Arc::clone(&observed);
        let (stop, mut stopped) = oneshot::channel();
        let worker = tokio::spawn(async move {
            let mut wire = [0_u8; 4096];
            loop {
                let received = tokio::select! {
                    _ = &mut stopped => break,
                    received = upstream.recv_from(&mut wire) => received,
                };
                let (length, peer) = received.expect("tagged DNS receive");
                let request = Message::from_vec(&wire[..length]).expect("tagged DNS decode");
                let [query] = request.queries.as_slice() else {
                    panic!("one tagged DNS question");
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
                    RData::A(A(Ipv4Addr::new(203, 0, 113, 19))),
                ));
                upstream
                    .send_to(&response.to_vec().expect("tagged DNS encode"), peer)
                    .await
                    .expect("tagged DNS response");
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
type = "direct"

[[outbounds]]
tag = "fixed-domain"
type = "shadowsocks"
server = "shared-cache.test:8388"
domain_resolver = "local"
domain_strategy = "ipv4_only"

[route]
final = "direct"

[[route.rules]]
domain_keyword = "fixed-only"
action = "route"
outbound = "fixed-domain"

[dns]
timeout_ms = 1000
max_inflight = 8
strategy = "ipv4_only"

[dns.cache]
enabled = true
max_entries = 16

[[dns.inbounds]]
tag = "dns-in"
listen = "{dns_listen}"

[[dns.servers]]
tag = "local"
transport = "udp"
address = "{upstream_address}"

[dns.route]
final = "local"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#
            )
        });
        let prepared =
            ferrum2_config::prepare_client_v2(&file.path).expect("prepare fixed endpoint cache V2");
        assert!(prepared.rule_sets().is_empty());
        let metrics = Arc::new(Metrics::new());
        let context = ClientV2MaterializeContext::new(
            Arc::clone(&metrics),
            ferrum2_tun::UnderlayPublisher::new(),
        );
        let materialized = materialize_prepared(prepared, &context)
            .await
            .expect("materialize fixed domain endpoint");
        assert!(materialized.pending.is_none());
        assert_eq!(
            materialized.config().outbounds[1].server(),
            Some("203.0.113.19:8388".parse().expect("resolved endpoint"))
        );
        assert_eq!(
            *observed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            [("shared-cache.test.".to_owned(), RecordType::A)]
        );

        let (mut config, root, cache, _underlay) = materialized
            .into_run_parts()
            .await
            .expect("materialized cache handoff");
        assert!(root.is_none(), "no RuleSet refresh root");
        let cache = cache.expect("materialization cache");
        assert!(
            config
                .route_program
                .as_ref()
                .is_some_and(|route| route.rule_registry().is_none())
        );
        let dns = config.dns.take().expect("materialized DNS graph");
        let runtime = crate::run::ClientDnsProxyRuntime::try_new(
            config.dns_route.as_mut(),
            dns.runtime,
            Some(cache),
            &metrics,
        )
        .expect("application DNS runtime");
        assert_eq!(runtime.generation, ResolverGeneration::new(0));
        assert!(runtime.policy.is_some(), "materialized ordinary DNS policy");
        let (resolver, mut owner) = TaggedResolver::new(
            crate::run::dns_egress::dns_runtime_specs(&dns.servers),
            dns.timeout,
            dns.max_inflight,
            Arc::new(ferrum2_dns::SystemDnsEgress),
        )
        .expect("application tagged resolver");
        owner.ready().await.expect("application DNS ready");
        let proxy = Arc::new(runtime.bind(ferrum2_dns::DnsProxy::new(
            Arc::new(resolver),
            |_, _, _, _| panic!("ordinary application lookup used legacy DNS selection"),
        )));
        let proxy_slot = Arc::new(OnceLock::new());
        assert!(proxy_slot.set(proxy).is_ok());
        let application = ApplicationResolverAdapter::new(
            Arc::new(ApplicationResolver::configured(Arc::new(
                crate::run::dns_egress::ClientConfiguredApplicationBackend::new(proxy_slot),
            ))),
            0,
            DnsStrategy::Ipv4Only,
        );
        assert_eq!(
            application.mode(),
            ferrum2_dns::ApplicationResolverMode::Configured
        );

        assert_eq!(
            ferrum2_runtime::TcpResolver::resolve(&application, "shared-cache.test", 443)
                .await
                .expect("TCP application cache hit"),
            ["203.0.113.19:443".parse().expect("TCP candidate")]
        );
        assert_eq!(
            ferrum2_runtime::UdpResolver::resolve(&application, "shared-cache.test", 53)
                .await
                .expect("UDP application cache hit"),
            ["203.0.113.19:53".parse().expect("UDP candidate")]
        );
        assert_eq!(
            *observed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            [("shared-cache.test.".to_owned(), RecordType::A)],
            "application lookup missed the generation-zero materialization cache"
        );
        let encoded = metrics.encode_text().expect("cache metrics");
        for expected in [
            "ferrum2_dns_cache_miss_total{qtype=\"a\"} 1",
            "ferrum2_dns_cache_hit_total{qtype=\"a\"} 2",
        ] {
            assert!(
                encoded.contains(expected),
                "missing `{expected}`\n{encoded}"
            );
        }

        owner.shutdown().await.expect("application DNS shutdown");
        let _ = stop.send(());
        worker.await.expect("tagged DNS worker");
    }

    #[tokio::test]
    async fn initial_ruleset_failure_returns_before_listener_bind() {
        let address = reserve_address();
        let file = TestConfig::new(|cache| {
            format!(
                r#"schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "{address}"

[[outbounds]]
tag = "direct"
type = "direct"

[route]
final = "direct"

[[route.rule_set]]
tag = "ads"
type = "remote"
url = "https://rules.example.invalid/ads.srs"
download_resolver = "system"

[[route.rules]]
rule_set = "ads"
action = "reject"

[rule_set_loader]
cache_dir = "{cache}"
download_timeout_ms = 1000
max_redirects = 0
"#
            )
        });
        let prepared = ferrum2_config::prepare_client_v2(&file.path).expect("prepare remote V2");
        let downloader = Arc::new(RecordingDownloader::failure());
        let context = ClientV2MaterializeContext::with_downloader(
            Arc::new(Metrics::new()),
            downloader.clone(),
        );

        assert!(matches!(
            materialize_prepared(prepared, &context).await,
            Err(RunError::RuleSetDownload)
        ));
        assert_eq!(downloader.seen().len(), 1);
        let rebound = TcpListener::bind(address).expect("materialization never bound inbound");
        drop(rebound);
    }

    #[tokio::test]
    async fn refresh_uses_live_detour_snapshot_and_is_explicitly_cleaned() {
        let address = reserve_address();
        let file = TestConfig::new(|cache| {
            format!(
                r#"schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "{address}"

[[outbounds]]
tag = "first"
type = "direct"

[[outbounds]]
tag = "second"
type = "direct"

[[selectors]]
tag = "download"
outbounds = ["first", "second"]
default = "first"

[route]
final = "download"

[[route.rule_set]]
tag = "ads"
type = "remote"
url = "https://rules.example.invalid/ads.srs"
download_resolver = "system"
download_detour = "download"
update_interval_seconds = 60

[[route.rules]]
rule_set = "ads"
action = "reject"

[rule_set_loader]
cache_dir = "{cache}"
download_timeout_ms = 1000
max_redirects = 0
"#
            )
        });
        let prepared = ferrum2_config::prepare_client_v2(&file.path).expect("prepare refresh V2");
        let downloader = Arc::new(RecordingDownloader::success());
        let context = ClientV2MaterializeContext::with_downloader(
            Arc::new(Metrics::new()),
            downloader.clone(),
        );
        let materialized = materialize_prepared(prepared, &context)
            .await
            .expect("strict initial snapshot");
        assert_eq!(
            downloader.seen(),
            [SeenDownload {
                resolver: RuleSetDownloadResolver::System,
                detour: Some(vec![0]),
            }]
        );
        materialized
            .config()
            .selector_control()
            .switch("download", "second")
            .expect("switch download selector");

        let (config, root, _cache, _underlay) = materialized
            .into_run_parts()
            .await
            .expect("transfer refresh ownership");
        let mut root = root.expect("refresh root");
        let outcome = root
            .service
            .as_ref()
            .expect("refresh service")
            .refresh_once(0)
            .await;
        assert!(matches!(outcome, RuleSetRefreshOutcome::Updated { .. }));
        assert_eq!(
            downloader.seen(),
            [
                SeenDownload {
                    resolver: RuleSetDownloadResolver::System,
                    detour: Some(vec![0]),
                },
                SeenDownload {
                    resolver: RuleSetDownloadResolver::System,
                    detour: Some(vec![1]),
                },
            ]
        );
        let registry = config
            .route_program
            .as_ref()
            .and_then(ferrum2_config::CompiledRoute::rule_registry)
            .expect("route registry");
        assert_eq!(registry.generation(), 2);
        root.cleanup().await.expect("refresh owner cleanup");
        assert!(root.service.is_none());
    }

    #[tokio::test]
    async fn four_real_srs_load_finish_into_one_materialized_route_and_dns_snapshot() {
        let address = reserve_address();
        let file = TestConfig::new(|cache| {
            format!(
                r#"schema_version = 2

[[inbounds]]
tag = "proxy"
listen = "{address}"

[[outbounds]]
tag = "direct"
type = "direct"

[[outbounds]]
tag = "ai"
type = "direct"

[dns]
timeout_ms = 1000
max_inflight = 16

[[dns.inbounds]]
tag = "dns-in"
listen = "127.0.0.1:5353"

[[dns.servers]]
tag = "local"
transport = "udp"
address = "192.0.2.53:53"

[[dns.servers]]
tag = "google"
transport = "udp"
address = "198.51.100.53:53"

[dns.route]
final = "google"

[[dns.route.rules]]
rule_set = "ads"
action = "reject"

[[dns.route.rules]]
rule_set = "ai"
action = "route"
server = "google"

[[dns.route.rules]]
rule_set = "cn"
action = "route"
server = "local"

[[dns.route.rules]]
rule_set = "cnip"
action = "route"
server = "local"

[route]
final = "direct"

[[route.rule_set]]
tag = "ads"
type = "remote"
url = "https://rules.example.invalid/ads.srs"
download_resolver = "system"

[[route.rule_set]]
tag = "ai"
type = "remote"
url = "https://rules.example.invalid/ai.srs"
download_resolver = "system"

[[route.rule_set]]
tag = "cn"
type = "remote"
url = "https://rules.example.invalid/cn.srs"
download_resolver = "system"

[[route.rule_set]]
tag = "cnip"
type = "remote"
url = "https://rules.example.invalid/cnip.srs"
download_resolver = "system"

[[route.rules]]
rule_set = "ads"
action = "reject"

[[route.rules]]
rule_set = "ai"
action = "route"
outbound = "ai"

[[route.rules]]
rule_set = "cn"
action = "route"
outbound = "direct"

[[route.rules]]
rule_set = "cnip"
action = "route"
outbound = "direct"

[rule_set_loader]
cache_dir = "{cache}"
download_timeout_ms = 1000
max_redirects = 0
"#
            )
        });
        let prepared =
            ferrum2_config::prepare_client_v2(&file.path).expect("prepare four real RuleSets");
        let downloader = Arc::new(RecordingDownloader::fixture_set());
        let context = ClientV2MaterializeContext::with_downloader(
            Arc::new(Metrics::new()),
            downloader.clone(),
        );
        let materialized = materialize_prepared(prepared, &context)
            .await
            .expect("one strict four-RuleSet snapshot");
        assert_eq!(downloader.seen().len(), 4);
        assert!(
            downloader
                .seen()
                .iter()
                .all(|request| request.resolver == RuleSetDownloadResolver::System)
        );
        let registry = materialized
            .config()
            .route_program
            .as_ref()
            .and_then(ferrum2_config::CompiledRoute::rule_registry)
            .expect("shared route registry");
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.generation(), INITIAL_RULESET_GENERATION);
        assert_eq!(snapshot.rule_set_count(), 4);
        let match_set = |tag| {
            let id = snapshot.rule_set_id(tag).expect("RuleSet tag");
            let descriptor = snapshot.rule_set(id).expect("RuleSet descriptor");
            snapshot
                .match_set(descriptor.match_set())
                .expect("compiled MatchSet")
        };
        assert!(match_set("ads").matches_domain(
            &ferrum2_core::CanonicalDomain::new("x.0.myikas.com").expect("ads probe")
        ));
        assert!(match_set("ai").matches_domain(
            &ferrum2_core::CanonicalDomain::new("api.openai.example").expect("ai probe")
        ));
        assert!(
            match_set("cn")
                .matches_domain(&ferrum2_core::CanonicalDomain::new("x.0.zone").expect("cn probe"))
        );
        assert!(match_set("cnip").matches_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 8, 8))));
        assert!(!match_set("cnip").matches_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));

        let config = materialized.config();
        let route = config
            .route_program
            .as_ref()
            .expect("ordinary route program");
        let terminal_hops = |target: &TargetAddr| {
            let mut evaluation = route.evaluate(0, Network::Tcp, target);
            match evaluation.next(RouteMetadata::new(None, None)) {
                Some(RouteProgramAction::Terminal(RouteAction::Route(plan))) => {
                    Some(plan.snapshot_owned().hops().to_vec())
                }
                Some(RouteProgramAction::Terminal(RouteAction::Reject)) => None,
                _ => panic!("unexpected ordinary route action"),
            }
        };
        let ads_target = TargetAddr::domain("x.0.myikas.com", 443).expect("ads target");
        let mut ads_route = route.evaluate(0, Network::Tcp, &ads_target);
        assert!(matches!(
            ads_route.next(RouteMetadata::new(None, None)),
            Some(RouteProgramAction::Terminal(RouteAction::Reject))
        ));
        assert_eq!(
            terminal_hops(&TargetAddr::domain("api.openai.example", 443).expect("AI target")),
            Some(vec![1])
        );
        assert_eq!(
            terminal_hops(&TargetAddr::domain("x.0.zone", 443).expect("CN target")),
            Some(vec![0])
        );
        assert_eq!(
            terminal_hops(
                &TargetAddr::ip("1.1.8.8:443".parse().expect("CN IP address"))
                    .expect("CN IP target")
            ),
            Some(vec![0])
        );

        let binding = config
            .dns_route
            .as_ref()
            .and_then(ferrum2_config::ClientDnsRoute::policy_blueprint)
            .expect("DNS policy blueprint");
        let dns_registry = binding.registry();
        assert!(Arc::ptr_eq(&registry, &dns_registry));
        assert_eq!(
            binding.resolve_ingress(ferrum2_config::DnsIngressId::Listener(0)),
            Some(0)
        );
        let policy = ferrum2_dns::DnsPolicyProgram::try_from_blueprint(
            binding.blueprint().clone(),
            &dns_registry.snapshot(),
        )
        .expect("compile DNS execution program from blueprint");
        let query = |name: &str| {
            DnsPolicyQuery::new(
                0,
                Network::Udp,
                Name::from_str(name).expect("DNS query name"),
                RecordType::A,
            )
        };
        let mut ads_dns = policy.evaluate(query("x.0.myikas.com."), &dns_registry);
        assert_eq!(
            ads_dns.next_step().expect("ads DNS rule"),
            Some(DnsPolicyStep::Reject)
        );
        let mut ai_dns = policy.evaluate(query("api.openai.example."), &dns_registry);
        assert!(matches!(
            ai_dns.next_step().expect("AI DNS rule"),
            Some(DnsPolicyStep::RouteImmediately { server, .. }) if server.get() == 1
        ));
        let mut cn_dns = policy.evaluate(query("x.0.zone."), &dns_registry);
        assert!(matches!(
            cn_dns.next_step().expect("CN DNS rule"),
            Some(DnsPolicyStep::RouteImmediately { server, .. }) if server.get() == 0
        ));
        let response_name = "response-only.invalid.";
        let mut cnip_dns = policy.evaluate(query(response_name), &dns_registry);
        assert!(matches!(
            cnip_dns.next_step().expect("CNIP response rule"),
            Some(DnsPolicyStep::EvaluateResponse { server, .. }) if server.get() == 0
        ));
        let mut response = Message::new(9, MessageType::Response, OpCode::Query);
        response.add_answer(Record::from_rdata(
            Name::from_str(response_name).expect("DNS response name"),
            60,
            RData::A(A(Ipv4Addr::new(1, 1, 8, 8))),
        ));
        assert!(matches!(
            cnip_dns.evaluate_response(&response).expect("CNIP response hit"),
            DnsPolicyStep::AcceptResponse { server, .. } if server.get() == 0
        ));

        let mut cnip_miss = policy.evaluate(query(response_name), &dns_registry);
        assert!(matches!(
            cnip_miss.next_step().expect("CNIP response rule"),
            Some(DnsPolicyStep::EvaluateResponse { server, .. }) if server.get() == 0
        ));
        let mut response = Message::new(10, MessageType::Response, OpCode::Query);
        response.add_answer(Record::from_rdata(
            Name::from_str(response_name).expect("DNS response name"),
            60,
            RData::A(A(Ipv4Addr::new(8, 8, 8, 8))),
        ));
        assert!(matches!(
            cnip_miss
                .evaluate_response(&response)
                .expect("CNIP response miss"),
            DnsPolicyStep::Final { server, .. } if server.get() == 1
        ));
        materialized
            .validate_only_shutdown()
            .await
            .expect("four-RuleSet cleanup");
    }

    #[test]
    fn ruleset_host_observer_records_closed_resolver_outcomes_without_fallback() {
        let metrics = Arc::new(Metrics::new());
        let observer = rule_set_host_resolve_observer(&metrics);
        observer.record(
            RuleSetHostResolverKind::System,
            RuleSetHostResolveOutcome::Success,
        );
        observer.record(
            RuleSetHostResolverKind::Configured,
            RuleSetHostResolveOutcome::Failure,
        );

        let encoded = metrics.encode_text().expect("encode RuleSet DNS metrics");
        for expected in [
            "ferrum2_dns_resolve_total{resolver=\"system\",purpose=\"ruleset_download\",result=\"success\"} 1",
            "ferrum2_dns_resolve_total{resolver=\"configured\",purpose=\"ruleset_download\",result=\"failure\"} 1",
            "ferrum2_dns_explicit_system_resolve_total{purpose=\"ruleset_download\"} 1",
            "ferrum2_dns_implicit_system_fallback_total 0",
        ] {
            assert!(
                encoded.contains(expected),
                "missing `{expected}`\n{encoded}"
            );
        }
    }

    #[test]
    fn degraded_initial_and_retained_refresh_emit_failure_metrics() {
        let metrics = Metrics::new();
        metrics.ruleset_load(initial_rule_set_result(
            RuleSetLoadDisposition::OfflineCache,
            Some(RuleSetLoadErrorKind::Download(
                RuleSetDownloadErrorKind::Resolution,
            )),
        ));
        metrics.ruleset_refresh(refresh_rule_set_result(
            RuleSetRefreshOutcome::RetainedCache(RuleSetLoadDisposition::StaleCache),
        ));

        let encoded = metrics.encode_text().expect("encode RuleSet metrics");
        for expected in [
            "ferrum2_ruleset_load_total{result=\"failure\"} 1",
            "ferrum2_ruleset_refresh_total{result=\"failure\"} 1",
        ] {
            assert!(
                encoded.contains(expected),
                "missing `{expected}`\n{encoded}"
            );
        }
        assert_eq!(
            refresh_rule_set_result(RuleSetRefreshOutcome::NotModified),
            RuleSetResult::Unchanged
        );
    }

    #[test]
    fn materialization_failures_keep_closed_operator_categories() {
        let cases = [
            (
                RuleSetLoadErrorKind::Allocation,
                RunError::RuleAllocation,
                "error[rule.allocation]",
            ),
            (
                RuleSetLoadErrorKind::Download(RuleSetDownloadErrorKind::Connect),
                RunError::RuleSetDownload,
                "error[ruleset.download]",
            ),
            (
                RuleSetLoadErrorKind::CacheDigest,
                RunError::RuleSetCache,
                "error[ruleset.cache]",
            ),
            (
                RuleSetLoadErrorKind::Decode(ferrum2_rule::srs::SrsErrorKind::InvalidMagic),
                RunError::RuleSetFormat,
                "error[ruleset.format]",
            ),
            (
                RuleSetLoadErrorKind::Decode(ferrum2_rule::srs::SrsErrorKind::UnsupportedMatcher),
                RunError::RuleSetUnsupportedMatcher,
                "error[ruleset.unsupported_matcher]",
            ),
            (
                RuleSetLoadErrorKind::RegistryCompile,
                RunError::RuleSetCompile,
                "error[ruleset.compile]",
            ),
        ];
        for (kind, expected, code) in cases {
            let classified = classify_rule_set_load_error_kind(kind);
            assert_eq!(classified, expected);
            let rendered = classified.to_string();
            assert!(rendered.starts_with(code));
            assert!(!rendered.contains("secret.invalid"));
        }
        assert_eq!(
            classify_fixed_endpoint_error(FixedEndpointMaterializeError::Resolve(DnsError::NoData)),
            RunError::DnsResolve
        );
    }

    #[tokio::test]
    async fn bridge_shutdown_aborts_and_joins_every_spawned_task() {
        struct RunningGuard(Arc<AtomicBool>);

        impl Drop for RunningGuard {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }

        let bridges = RuleSetBridgeTasks::default();
        let running = Arc::new(AtomicBool::new(false));
        let task_running = Arc::clone(&running);
        bridges
            .spawn(async move {
                task_running.store(true, Ordering::Release);
                let _guard = RunningGuard(Arc::clone(&task_running));
                std::future::pending::<()>().await;
            })
            .expect("bridge task accepted");
        while !running.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }

        bridges.shutdown().await;
        assert!(!running.load(Ordering::Acquire));
        assert!(bridges.spawn(async {}).is_err());
        assert!(
            bridges
                .tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty()
        );
    }
}
