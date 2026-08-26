use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ferrum2_config::{PreparedClientV2, PreparedDnsEndpointMode, ResolverRef};
use ferrum2_core::TargetAddr;
use ferrum2_core::route::EgressPlanSnapshot;
use ferrum2_dns::{DnsCache, DnsServerId, ResolverGeneration, TaggedResolver, TaggedResolverOwner};
use ferrum2_observability::{
    CompiledMatchType, DnsResolvePurpose, DnsResolveResult, DnsResolverKind, Metrics,
    RuleSetResult, TargetResolutionComponent, TargetResolutionMode,
};
use ferrum2_rule::{RuleEngineRegistry, RuleEngineSnapshot, RuleSetId};
use ferrum2_ruleset::{
    ExplicitRuleSetHostResolver, HttpsRuleSetDownloader, MaterializedRuleSets, RuleSetCacheName,
    RuleSetDialTargets, RuleSetDialer, RuleSetDownloadError, RuleSetDownloadErrorKind,
    RuleSetDownloadMode, RuleSetDownloadResolver, RuleSetDownloader, RuleSetHostResolveObserver,
    RuleSetHostResolveOutcome, RuleSetHostResolverKind, RuleSetLoadDisposition,
    RuleSetLoadErrorKind, RuleSetLoader, RuleSetLoaderConfig, RuleSetRefreshOutcome,
    RuleSetRefreshService, RuleSetRemoteSource,
};
use ferrum2_runtime::{PreparedProcessRoot, ProcessCancellation, ProcessFuture};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::task::{AbortHandle, JoinHandle};
use tokio::time::Instant;

use super::endpoint::{BootstrapAddresses, BootstrapBlueprint};
use super::outcome::classify_rule_set_load_error;
use crate::run::RunError;
use crate::run::egress::{ClientEgressEngine, ClientRequestOrigin};
use ferrum2_shadowsocks::tokio::TokioFramed;

pub(super) struct PendingClientV2Runtime {
    transport: PendingRuleSetTransport,
    materialized: MaterializedRuleSets,
    metrics: Arc<Metrics>,
}

impl PendingClientV2Runtime {
    pub(super) fn new(
        transport: PendingRuleSetTransport,
        materialized: MaterializedRuleSets,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            transport,
            materialized,
            metrics,
        }
    }

    pub(super) async fn into_prepared_root(
        self,
        registry: Arc<RuleEngineRegistry>,
    ) -> Result<ClientV2RuntimeRoot, RunError> {
        let PendingClientV2Runtime {
            transport,
            materialized,
            metrics,
        } = self;
        if !Arc::ptr_eq(materialized.registry(), &registry) {
            return Err(RunError::StartupProtocol);
        }
        let active = transport.activate(registry.generation()).await?;
        let observer_metrics = Arc::clone(&metrics);
        let observer_registry = Arc::clone(&registry);
        let observer_rule_sets = materialized.shared_rule_set_ids();
        let observer = Arc::new(move |outcome| {
            if let RuleSetRefreshOutcome::Updated { generation, .. } = outcome {
                observer_metrics.set_ruleset_generation(generation);
                let snapshot = observer_registry.snapshot();
                record_rule_set_snapshot_metrics(&observer_metrics, &snapshot, &observer_rule_sets);
                observer_metrics.set_ruleset_last_success_timestamp(unix_timestamp_now());
            }
            observer_metrics.ruleset_refresh(refresh_rule_set_result(outcome));
        });
        let service = match materialized.into_refresh_service(Arc::clone(&active.loader)) {
            Ok(service) => service.with_observer(observer),
            Err(error) => {
                active.shutdown().await?;
                return Err(classify_rule_set_load_error(error));
            }
        };
        Ok(ClientV2RuntimeRoot::prepared(
            Arc::new(service),
            active.into_runtime_owners(),
        ))
    }
}

pub(super) enum PendingRuleSetTransport {
    Injected {
        loader_config: RuleSetLoaderConfig,
        downloader: Arc<dyn RuleSetDownloader>,
    },
    Production(ProductionRuleSetTransport),
}

enum TaggedTransport {
    Absent,
    Owned {
        resolver: Arc<TaggedResolver>,
        owner: TaggedResolverOwner,
    },
}

impl TaggedTransport {
    fn resolver(&self) -> Option<Arc<TaggedResolver>> {
        match self {
            Self::Absent => None,
            Self::Owned { resolver, .. } => Some(Arc::clone(resolver)),
        }
    }

    async fn shutdown(self) -> Result<(), RunError> {
        let Self::Owned {
            resolver,
            mut owner,
        } = self
        else {
            return Ok(());
        };
        drop(resolver);
        owner
            .shutdown()
            .await
            .map(|_| ())
            .map_err(|_| RunError::ShutdownCleanup)
    }
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

pub(super) struct ProductionRuleSetTransport {
    pub(super) blueprint: Arc<BootstrapBlueprint>,
    pub(super) addresses: BootstrapAddresses,
    pub(super) loader_config: RuleSetLoaderConfig,
    pub(super) cache: Option<DnsCache>,
    #[cfg(all(windows, not(test)))]
    pub(super) network_socket_service: Arc<crate::run::egress::ClientNetworkSocketService>,
    pub(super) needs_tagged: bool,
    pub(super) metrics: Arc<Metrics>,
}

impl ProductionRuleSetTransport {
    pub(super) async fn activate(
        self,
        generation: u64,
    ) -> Result<ActiveRuleSetTransport, RunError> {
        let bridges = Arc::new(RuleSetBridgeTasks::default());
        let engine = self.blueprint.build_engine(
            &self.addresses,
            #[cfg(all(windows, not(test)))]
            Arc::clone(&self.network_socket_service),
        )?;
        let tagged = if self.needs_tagged {
            let (resolver, mut owner) = self
                .blueprint
                .tagged_resolver_with_addresses(&engine, &self.addresses)?;
            if owner.ready().await.is_err() {
                drop(resolver);
                let _ = owner.shutdown().await;
                bridges.shutdown().await;
                return Err(RunError::StartupProtocol);
            }
            TaggedTransport::Owned { resolver, owner }
        } else {
            TaggedTransport::Absent
        };
        let mut resolver =
            ExplicitRuleSetHostResolver::new(tagged.resolver(), self.blueprint.dns_strategy());
        if let Some(cache) = self.cache {
            resolver = resolver.with_cache(cache, ResolverGeneration::new(generation));
        }
        resolver = resolver.with_observer(rule_set_host_resolve_observer(&self.metrics));
        let dialer = ClientRuleSetDialer {
            engine: Arc::clone(&engine.engine),
            bridges: Arc::clone(&bridges),
        };
        let downloader: Arc<dyn RuleSetDownloader> =
            Arc::new(HttpsRuleSetDownloader::new(resolver, dialer));
        Ok(ActiveRuleSetTransport {
            loader: Arc::new(RuleSetLoader::new(self.loader_config, downloader)),
            tagged,
            bridges,
        })
    }
}

pub(super) struct ActiveRuleSetTransport {
    pub(super) loader: Arc<RuleSetLoader<Arc<dyn RuleSetDownloader>>>,
    tagged: TaggedTransport,
    bridges: Arc<RuleSetBridgeTasks>,
}

impl ActiveRuleSetTransport {
    pub(super) fn injected(
        loader_config: RuleSetLoaderConfig,
        downloader: Arc<dyn RuleSetDownloader>,
    ) -> Self {
        Self {
            loader: Arc::new(RuleSetLoader::new(loader_config, downloader)),
            tagged: TaggedTransport::Absent,
            bridges: Arc::new(RuleSetBridgeTasks::default()),
        }
    }

    pub(super) async fn shutdown(self) -> Result<(), RunError> {
        // Stop its blocking work, then drop the loader so the downloader can
        // release every engine and resolver clone before transport owners join.
        let Self {
            loader,
            tagged,
            bridges,
        } = self;
        let loader_cleanup = loader
            .shutdown()
            .await
            .map_err(classify_rule_set_load_error);
        drop(loader);
        bridges.shutdown().await;
        let transport_cleanup = tagged.shutdown().await;
        loader_cleanup.and(transport_cleanup)
    }

    fn into_runtime_owners(self) -> ClientRuntimeOwners {
        let Self {
            loader,
            tagged,
            bridges,
        } = self;
        drop(loader);
        ClientRuntimeOwners { tagged, bridges }
    }
}

struct ClientRuntimeOwners {
    tagged: TaggedTransport,
    bridges: Arc<RuleSetBridgeTasks>,
}

enum ClientRuntimeRootState {
    Prepared {
        service: Arc<RuleSetRefreshService<Arc<dyn RuleSetDownloader>>>,
        owners: ClientRuntimeOwners,
    },
    Cleaned,
}

pub(in crate::run) struct ClientV2RuntimeRoot {
    state: ClientRuntimeRootState,
}

impl ClientV2RuntimeRoot {
    fn prepared(
        service: Arc<RuleSetRefreshService<Arc<dyn RuleSetDownloader>>>,
        owners: ClientRuntimeOwners,
    ) -> Self {
        Self {
            state: ClientRuntimeRootState::Prepared { service, owners },
        }
    }

    fn service(&self) -> Result<Arc<RuleSetRefreshService<Arc<dyn RuleSetDownloader>>>, RunError> {
        match &self.state {
            ClientRuntimeRootState::Prepared { service, .. } => Ok(Arc::clone(service)),
            ClientRuntimeRootState::Cleaned => Err(RunError::StartupProtocol),
        }
    }

    pub(in crate::run) async fn cleanup(&mut self) -> Result<(), RunError> {
        let state = std::mem::replace(&mut self.state, ClientRuntimeRootState::Cleaned);
        let ClientRuntimeRootState::Prepared { service, owners } = state else {
            return Ok(());
        };
        let service_cleanup = service
            .shutdown()
            .await
            .map_err(classify_rule_set_load_error);
        drop(service);
        owners.bridges.shutdown().await;
        service_cleanup.and(owners.tagged.shutdown().await)
    }

    #[cfg(test)]
    pub(super) async fn refresh_once(&self, index: usize) -> RuleSetRefreshOutcome {
        match &self.state {
            ClientRuntimeRootState::Prepared { service, .. } => service.refresh_once(index).await,
            ClientRuntimeRootState::Cleaned => panic!("cleaned refresh root"),
        }
    }

    #[cfg(test)]
    pub(super) fn is_cleaned(&self) -> bool {
        matches!(&self.state, ClientRuntimeRootState::Cleaned)
    }
}

impl PreparedProcessRoot<RunError> for ClientV2RuntimeRoot {
    fn activate(&mut self) -> Result<(), RunError> {
        match &self.state {
            ClientRuntimeRootState::Prepared { .. } => Ok(()),
            ClientRuntimeRootState::Cleaned => Err(RunError::StartupProtocol),
        }
    }

    fn run(
        mut self: Box<Self>,
        mut cancellation: ProcessCancellation,
    ) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async move {
            let service = self.service()?;
            let result = service
                .run_until(cancellation.cancelled())
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

pub(super) const fn initial_rule_set_result(
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

pub(super) const fn refresh_rule_set_result(outcome: RuleSetRefreshOutcome) -> RuleSetResult {
    match outcome {
        RuleSetRefreshOutcome::Updated { .. } => RuleSetResult::Success,
        RuleSetRefreshOutcome::NotModified => RuleSetResult::Unchanged,
        RuleSetRefreshOutcome::RetainedCache(_) | RuleSetRefreshOutcome::Failed(_) => {
            RuleSetResult::Failure
        }
    }
}

pub(super) fn record_rule_set_snapshot_metrics(
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

pub(super) fn unix_timestamp_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

pub(super) fn rule_set_host_resolve_observer(
    metrics: &Arc<Metrics>,
) -> Arc<dyn RuleSetHostResolveObserver> {
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

pub(super) fn runtime_loader_config(
    prepared: &PreparedClientV2,
) -> Result<RuleSetLoaderConfig, RunError> {
    let config = prepared.rule_set_loader();
    RuleSetLoaderConfig::new(
        config.cache_dir.clone(),
        config.download_timeout,
        config.max_redirects,
    )
    .map_err(|_| RunError::StartupProtocol)
}

pub(super) fn rule_set_sources(
    prepared: &PreparedClientV2,
) -> Result<Vec<RuleSetRemoteSource>, RunError> {
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
        sources.push(
            RuleSetRemoteSource::new(
                RuleSetCacheName::new(rule_set.tag()).map_err(|_| RunError::StartupProtocol)?,
                rule_set.url(),
                mode,
                prepared.download_detour_plan(index).cloned(),
                rule_set.update_interval(),
            )
            .map_err(|_| RunError::StartupProtocol)?,
        );
    }
    Ok(sources)
}

pub(super) fn record_target_resolution_modes(prepared: &PreparedClientV2, metrics: &Metrics) {
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

pub(super) struct RuleSetBridgeTasks {
    accepting: AtomicBool,
    pub(super) tasks: Mutex<Vec<JoinHandle<()>>>,
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
    pub(super) fn spawn(
        &self,
        task: impl Future<Output = ()> + Send + 'static,
    ) -> Result<AbortHandle, ()> {
        let mut tasks = self.tasks.lock().map_err(|_| ())?;
        if !self.accepting.load(Ordering::Acquire) {
            return Err(());
        }
        tasks.retain(|task| !task.is_finished());
        let handle = tokio::spawn(task);
        let abort = handle.abort_handle();
        tasks.push(handle);
        Ok(abort)
    }

    pub(super) async fn shutdown(&self) {
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

pub(super) struct AbortRuleSetBridge(Option<AbortHandle>);

impl AbortRuleSetBridge {
    pub(super) fn new(handle: AbortHandle) -> Self {
        Self(Some(handle))
    }

    fn into_handle(mut self) -> AbortHandle {
        self.0
            .take()
            .expect("rule-set bridge guard always contains its handle")
    }
}

impl Drop for AbortRuleSetBridge {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
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

pub(super) struct ClientRuleSetDialer {
    engine: Arc<ClientEgressEngine>,
    bridges: Arc<RuleSetBridgeTasks>,
}

pub(super) struct RuleSetBridgeIo {
    pub(super) inner: DuplexStream,
    pub(super) bridge: AbortHandle,
}

impl AsyncRead for RuleSetBridgeIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for RuleSetBridgeIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Drop for RuleSetBridgeIo {
    fn drop(&mut self) {
        self.bridge.abort();
    }
}

impl RuleSetDialer for ClientRuleSetDialer {
    type Io = RuleSetBridgeIo;

    fn connect(
        &self,
        targets: &RuleSetDialTargets,
        detour: Option<&EgressPlanSnapshot>,
        deadline: Instant,
    ) -> impl Future<Output = Result<Self::Io, RuleSetDownloadError>> + Send {
        let targets = match targets {
            RuleSetDialTargets::Resolved(candidates) => candidates
                .iter()
                .filter_map(|candidate| TargetAddr::ip(*candidate).ok())
                .collect::<Vec<_>>(),
            RuleSetDialTargets::Domain(target) => vec![target.clone()],
        };
        let detour = detour.cloned();
        let engine = Arc::clone(&self.engine);
        let bridges = Arc::clone(&self.bridges);
        async move {
            for target in targets {
                if Instant::now() >= deadline {
                    return Err(RuleSetDownloadError::new(RuleSetDownloadErrorKind::Timeout));
                }
                let (client, mut bridge) = tokio::io::duplex(8 * 1024);
                let (ready, opened) = tokio::sync::oneshot::channel();
                let attempt_engine = Arc::clone(&engine);
                let attempt_detour = detour.clone();
                let abort = bridges
                    .spawn(async move {
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        if remaining.is_zero() {
                            let _ = ready.send(Err(()));
                            return;
                        }
                        let flow = attempt_engine
                            .open_tcp_for_ingress(
                                ClientRequestOrigin::RuleSet,
                                0,
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
                        let _ = tokio::time::timeout_at(
                            deadline,
                            tokio::io::copy_bidirectional(&mut bridge, &mut flow),
                        )
                        .await;
                    })
                    .map_err(|_| RuleSetDownloadError::new(RuleSetDownloadErrorKind::Connect))?;
                let abort = AbortRuleSetBridge::new(abort);
                match tokio::time::timeout_at(deadline, opened).await {
                    Ok(Ok(Ok(()))) => {
                        return Ok(RuleSetBridgeIo {
                            inner: client,
                            bridge: abort.into_handle(),
                        });
                    }
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
