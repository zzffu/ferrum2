use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ferrum2_config::{PreparedDnsEndpointMode, PreparedServerV2, ResolverRef};
use ferrum2_core::TargetHostRef;
use ferrum2_core::route::EgressPlanSnapshot;
use ferrum2_dns::{DnsCache, DnsServerId, ResolverGeneration, TaggedResolver, TaggedResolverOwner};
use ferrum2_net::TcpResolver;
use ferrum2_observability::{
    CompiledMatchType, DnsResolvePurpose, DnsResolveResult, DnsResolverKind, Metrics,
    RuleSetResult, TargetResolutionComponent, TargetResolutionMode,
};
use ferrum2_rule::{RuleEngineRegistry, RuleEngineSnapshot, RuleSetId};
use ferrum2_ruleset::{
    ExplicitRuleSetHostResolver, HttpsRuleSetDownloader, MaterializedRuleSets, RuleSetCacheName,
    RuleSetDialTargets, RuleSetDialer, RuleSetDownloadError, RuleSetDownloadErrorKind,
    RuleSetDownloadMode, RuleSetDownloadResolver, RuleSetDownloader, RuleSetHostResolveOutcome,
    RuleSetHostResolverKind, RuleSetLoadDisposition, RuleSetLoadErrorKind, RuleSetLoader,
    RuleSetLoaderConfig, RuleSetRefreshOutcome, RuleSetRefreshService, RuleSetRemoteSource,
};
use ferrum2_runtime::{PreparedProcessRoot, ProcessCancellation, ProcessFuture};
use tokio::time::Instant;

use crate::run::RunError;
use crate::run::dns_egress::ServerPhysicalSocketContext;
use crate::run::tcp::ServerPhysicalTcpStream;

use super::endpoint::{BootstrapAddresses, BootstrapBlueprint};
use super::outcome::classify_rule_set_load_error;

pub(super) struct PendingServerV2Runtime {
    transport: PendingRuleSetTransport,
    materialized: MaterializedRuleSets,
    metrics: Arc<Metrics>,
}

impl PendingServerV2Runtime {
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
    ) -> Result<ServerV2RuntimeRoot, RunError> {
        let Self {
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
        Ok(ServerV2RuntimeRoot::prepared(
            Arc::new(service),
            active.into_tagged_transport(),
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

pub(super) enum TaggedTransport {
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

    pub(super) async fn shutdown(self) -> Result<(), RunError> {
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
    blueprint: Arc<BootstrapBlueprint>,
    addresses: BootstrapAddresses,
    loader_config: RuleSetLoaderConfig,
    cache: Option<DnsCache>,
    needs_tagged: bool,
}

impl ProductionRuleSetTransport {
    pub(super) fn new(
        blueprint: Arc<BootstrapBlueprint>,
        addresses: BootstrapAddresses,
        loader_config: RuleSetLoaderConfig,
        cache: Option<DnsCache>,
        needs_tagged: bool,
    ) -> Self {
        Self {
            blueprint,
            addresses,
            loader_config,
            cache,
            needs_tagged,
        }
    }

    pub(super) async fn activate(
        self,
        generation: u64,
    ) -> Result<ActiveRuleSetTransport, RunError> {
        let tagged_slot = Arc::new(std::sync::OnceLock::new());
        let direct_resolvers = self.blueprint.direct_resolvers(Arc::clone(&tagged_slot));
        let tagged = if self.needs_tagged {
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
            TaggedTransport::Owned { resolver, owner }
        } else {
            TaggedTransport::Absent
        };
        let mut resolver =
            ExplicitRuleSetHostResolver::new(tagged.resolver(), self.blueprint.strategy());
        if let Some(cache) = self.cache {
            resolver = resolver.with_cache(cache, ResolverGeneration::new(generation));
        }
        let metrics = Arc::clone(self.blueprint.metrics());
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
            ServerRuleSetDialer::new(direct_resolvers, Arc::clone(self.blueprint.physical())),
        ));
        Ok(ActiveRuleSetTransport {
            loader: Arc::new(RuleSetLoader::new(self.loader_config, downloader)),
            tagged,
        })
    }
}

pub(super) struct ActiveRuleSetTransport {
    loader: Arc<RuleSetLoader<Arc<dyn RuleSetDownloader>>>,
    tagged: TaggedTransport,
}

impl ActiveRuleSetTransport {
    pub(super) fn injected(
        loader_config: RuleSetLoaderConfig,
        downloader: Arc<dyn RuleSetDownloader>,
    ) -> Self {
        Self {
            loader: Arc::new(RuleSetLoader::new(loader_config, downloader)),
            tagged: TaggedTransport::Absent,
        }
    }

    pub(super) fn loader(&self) -> &RuleSetLoader<Arc<dyn RuleSetDownloader>> {
        self.loader.as_ref()
    }

    pub(super) async fn shutdown(self) -> Result<(), RunError> {
        let Self { loader, tagged } = self;
        let loader_cleanup = loader
            .shutdown()
            .await
            .map_err(classify_rule_set_load_error);
        drop(loader);
        loader_cleanup.and(tagged.shutdown().await)
    }

    fn into_tagged_transport(self) -> TaggedTransport {
        let Self { loader, tagged } = self;
        drop(loader);
        tagged
    }
}

enum ServerRuntimeRootState {
    Prepared {
        service: Arc<RuleSetRefreshService<Arc<dyn RuleSetDownloader>>>,
        tagged: TaggedTransport,
    },
    Cleaned,
}

pub(in crate::run) struct ServerV2RuntimeRoot {
    state: ServerRuntimeRootState,
}

impl ServerV2RuntimeRoot {
    fn prepared(
        service: Arc<RuleSetRefreshService<Arc<dyn RuleSetDownloader>>>,
        tagged: TaggedTransport,
    ) -> Self {
        Self {
            state: ServerRuntimeRootState::Prepared { service, tagged },
        }
    }

    fn service(&self) -> Result<Arc<RuleSetRefreshService<Arc<dyn RuleSetDownloader>>>, RunError> {
        match &self.state {
            ServerRuntimeRootState::Prepared { service, .. } => Ok(Arc::clone(service)),
            ServerRuntimeRootState::Cleaned => Err(RunError::StartupProtocol),
        }
    }

    pub(in crate::run) async fn cleanup(&mut self) -> Result<(), RunError> {
        let state = std::mem::replace(&mut self.state, ServerRuntimeRootState::Cleaned);
        let ServerRuntimeRootState::Prepared { service, tagged } = state else {
            return Ok(());
        };
        let service_cleanup = service
            .shutdown()
            .await
            .map_err(classify_rule_set_load_error);
        drop(service);
        service_cleanup.and(tagged.shutdown().await)
    }

    #[cfg(test)]
    pub(super) async fn refresh_once(&self, index: usize) -> RuleSetRefreshOutcome {
        match &self.state {
            ServerRuntimeRootState::Prepared { service, .. } => service.refresh_once(index).await,
            ServerRuntimeRootState::Cleaned => panic!("cleaned refresh root"),
        }
    }

    #[cfg(test)]
    pub(super) fn is_cleaned(&self) -> bool {
        matches!(&self.state, ServerRuntimeRootState::Cleaned)
    }
}

impl PreparedProcessRoot<RunError> for ServerV2RuntimeRoot {
    fn activate(&mut self) -> Result<(), RunError> {
        match &self.state {
            ServerRuntimeRootState::Prepared { .. } => Ok(()),
            ServerRuntimeRootState::Cleaned => Err(RunError::StartupProtocol),
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

/// Server RuleSet downloads use the resolver owned by the exact Direct detour.
/// Resolved targets use the default physical policy or the exact Direct
/// detour, while deferred domains never escape through an ambient resolver.
#[derive(Clone)]
pub(super) struct ServerRuleSetDialer {
    direct_resolvers: Arc<[crate::run::dns_egress::ServerDnsResolver]>,
    physical: Arc<ServerPhysicalSocketContext>,
}

impl ServerRuleSetDialer {
    pub(super) fn new(
        direct_resolvers: Vec<crate::run::dns_egress::ServerDnsResolver>,
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

pub(super) fn runtime_loader_config(
    prepared: &PreparedServerV2,
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
    prepared: &PreparedServerV2,
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

pub(super) fn record_target_resolution_modes(prepared: &PreparedServerV2, metrics: &Metrics) {
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
