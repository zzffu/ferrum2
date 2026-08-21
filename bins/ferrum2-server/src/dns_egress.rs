#![forbid(unsafe_code)]

//! Server adapters for the shared tagged DNS resolver.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use ferrum2_config::{
    DirectDomainResolver, DnsRuntimeConfig, DnsServerConfig, DnsTransport, ServerDnsRoute,
};
use ferrum2_core::route::{EgressPlanSnapshot, Network};
use ferrum2_core::{TargetAddr, TargetHostRef};
use ferrum2_dns::{
    ApplicationResolveBackend, ApplicationResolveFuture, ApplicationResolveOutcome,
    ApplicationResolveRequest, ApplicationResolver, ApplicationResolverMode, BoxedDnsDatagramIo,
    BoxedDnsTcpIo, DnsAddressRecords, DnsCache, DnsCacheAnswer, DnsCacheError, DnsCacheKey,
    DnsCacheQtype, DnsEgress, DnsError, DnsIoFuture, DnsPolicyCompileError, DnsPolicyMatchResult,
    DnsPolicyMatchSource, DnsPolicyMatchType, DnsPolicyObservation, DnsPolicyObserver,
    DnsPolicyProgram, DnsPolicyStage, DnsProxy, DnsServerId, DnsStrategy, DnsTaskRegistrar,
    DnsUpstreamSpec, DnsUpstreamTransport, FixedEndpointLookup, ResolverGeneration,
    SystemDnsEgress, TaggedResolver, TaggedServerApplicationResolveBackend,
};
use ferrum2_observability::{
    DnsResolvePurpose, DnsResolveResult, DnsResolverKind, Metrics, RuleMatchResult, RuleMatchType,
    RuleProgram, RuleSource,
};
use ferrum2_rule::{ActionTable, RuleCompileError, RuleEngineRegistry, RuleEvaluationScratch};
use ferrum2_runtime::{
    ApplicationResolverAdapter, MAX_RESOLVED_CANDIDATES, TcpResolver, UdpResolver,
};
use tokio::time::Instant as TokioInstant;

pub(super) fn dns_runtime_specs(servers: &[DnsServerConfig]) -> Vec<DnsUpstreamSpec> {
    servers
        .iter()
        .map(|server| {
            let transport = match server.transport {
                DnsTransport::Udp => DnsUpstreamTransport::Udp,
                DnsTransport::Tcp => DnsUpstreamTransport::Tcp,
                DnsTransport::Dot => DnsUpstreamTransport::Dot {
                    server_name: server
                        .server_name
                        .clone()
                        .expect("validated DoT server name"),
                },
                DnsTransport::Doh => DnsUpstreamTransport::Doh {
                    server_name: server
                        .server_name
                        .clone()
                        .expect("validated DoH server name"),
                    path: server.path.clone().expect("validated DoH path"),
                },
            };
            DnsUpstreamSpec {
                transport,
                target: server.target.clone(),
                resolved_targets: server.resolved_targets.clone(),
                detour: server.detour.clone(),
            }
        })
        .collect()
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct ServerDnsState {
    route: ActionTable<usize>,
    policy: Option<ServerDnsRoute>,
    policy_scratch: Option<Mutex<RuleEvaluationScratch>>,
    strategy: DnsStrategy,
    proxy_runtime: Option<ServerProxyRuntime>,
    policy_observer: Option<Arc<dyn DnsPolicyObserver>>,
    installed: Mutex<Option<InstalledServerDns>>,
}

struct ServerProxyPolicy {
    program: Arc<DnsPolicyProgram>,
    registry: Arc<RuleEngineRegistry>,
    listener_count: usize,
    ordinary_count: usize,
}

struct ServerProxyRuntime {
    policy: Option<ServerProxyPolicy>,
    cache: Option<DnsCache>,
    generation: ResolverGeneration,
}

#[cfg_attr(not(test), allow(dead_code))]
struct InstalledServerDns {
    resolver: Arc<TaggedResolver>,
    proxy: Option<Arc<DnsProxy>>,
}

/// Closed construction failures for server DNS state. Keeping the rule error
/// intact lets the composition root distinguish scratch allocation/capacity
/// failures from compiler consistency failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ServerDnsStateBuildError {
    CacheAllocation,
    InvalidRuntime,
    Rule(RuleCompileError),
    DnsPolicy(DnsPolicyCompileError),
}

impl From<RuleCompileError> for ServerDnsStateBuildError {
    fn from(error: RuleCompileError) -> Self {
        Self::Rule(error)
    }
}

#[cfg_attr(not(test), allow(dead_code))]
impl ServerDnsState {
    pub(super) fn try_new(
        route: ActionTable<usize>,
        policy: Option<ServerDnsRoute>,
        runtime: DnsRuntimeConfig,
    ) -> Result<Self, ServerDnsStateBuildError> {
        let cache_config = runtime.cache();
        let cache = if cache_config.enabled {
            Some(
                DnsCache::try_new(
                    std::num::NonZeroUsize::new(cache_config.max_entries)
                        .ok_or(ServerDnsStateBuildError::InvalidRuntime)?,
                )
                .map_err(|error| match error {
                    DnsCacheError::Allocation => ServerDnsStateBuildError::CacheAllocation,
                    DnsCacheError::Unavailable
                    | DnsCacheError::TtlOverflow
                    | DnsCacheError::AddressFamily => ServerDnsStateBuildError::InvalidRuntime,
                })?,
            )
        } else {
            None
        };
        Self::try_new_with_cache(route, policy, runtime, cache)
    }

    pub(super) fn try_new_with_cache(
        route: ActionTable<usize>,
        mut policy: Option<ServerDnsRoute>,
        runtime: DnsRuntimeConfig,
        cache: Option<DnsCache>,
    ) -> Result<Self, ServerDnsStateBuildError> {
        let cache_config = runtime.cache();
        if cache_config.enabled != cache.is_some() {
            return Err(ServerDnsStateBuildError::InvalidRuntime);
        }
        let proxy_policy = policy
            .as_mut()
            .and_then(ServerDnsRoute::take_policy_blueprint)
            .map(|binding| {
                let (blueprint, registry, listener_count, ordinary_count) = binding.into_parts();
                let snapshot = registry.snapshot();
                let program = DnsPolicyProgram::try_from_blueprint(blueprint, &snapshot)
                    .map_err(ServerDnsStateBuildError::DnsPolicy)?;
                Ok::<ServerProxyPolicy, ServerDnsStateBuildError>(ServerProxyPolicy {
                    program: Arc::new(program),
                    registry,
                    listener_count,
                    ordinary_count,
                })
            })
            .transpose()?;
        if policy
            .as_ref()
            .is_some_and(|policy| !policy.has_compatibility_program())
        {
            policy = None;
        }
        let policy_scratch = policy
            .as_ref()
            .map(ServerDnsRoute::evaluation_scratch)
            .transpose()
            .map_err(ServerDnsStateBuildError::from)?
            .map(Mutex::new);
        let generation = proxy_policy
            .as_ref()
            .map_or(ResolverGeneration::new(0), |policy| {
                ResolverGeneration::new(policy.registry.generation())
            });
        let proxy_runtime =
            (proxy_policy.is_some() || cache.is_some()).then_some(ServerProxyRuntime {
                policy: proxy_policy,
                cache,
                generation,
            });
        Ok(Self {
            route,
            policy,
            policy_scratch,
            strategy: dns_strategy(runtime.strategy()),
            proxy_runtime,
            policy_observer: None,
            installed: Mutex::new(None),
        })
    }

    pub(super) fn with_policy_observer(mut self, observer: Arc<dyn DnsPolicyObserver>) -> Self {
        self.policy_observer = Some(observer);
        self
    }

    pub(super) fn select(
        &self,
        inbound: usize,
        network: Network,
        target: &TargetAddr,
    ) -> Option<usize> {
        let Some(policy) = self.policy.as_ref() else {
            return Some(self.route.select(inbound, network, target));
        };
        let mut scratch = self
            .policy_scratch
            .as_ref()?
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Some(policy.select_with_scratch(inbound, network, target, &mut scratch))
    }

    pub(super) fn install(self: &Arc<Self>, resolver: Arc<TaggedResolver>) -> Result<(), ()> {
        let proxy = self.proxy_runtime.as_ref().and_then(|runtime| {
            let policy = runtime.policy.as_ref()?;
            let mut proxy = DnsProxy::new(Arc::clone(&resolver), |_, _, _, _| None);
            proxy = proxy.with_policy(
                Arc::clone(&policy.program),
                Arc::clone(&policy.registry),
                policy.listener_count,
                policy.ordinary_count,
            );
            if let Some(observer) = &self.policy_observer {
                proxy = proxy.with_policy_observer(Arc::clone(observer));
            }
            if let Some(cache) = &runtime.cache {
                proxy = proxy.with_cache(cache.clone(), runtime.generation);
            }
            Some(Arc::new(proxy))
        });
        let mut current = self.installed.lock().map_err(|_| ())?;
        if current.is_some() {
            return Err(());
        }
        *current = Some(InstalledServerDns { resolver, proxy });
        Ok(())
    }

    pub(super) fn take(&self) -> Option<Arc<TaggedResolver>> {
        self.installed.lock().ok()?.take().map(|dns| dns.resolver)
    }

    fn resolver(&self) -> io::Result<Arc<TaggedResolver>> {
        self.installed
            .lock()
            .map_err(|_| io::Error::other("DNS resolver state unavailable"))?
            .as_ref()
            .map(|dns| Arc::clone(&dns.resolver))
            .ok_or_else(|| io::Error::other("DNS resolver is not active"))
    }

    fn proxy(&self) -> io::Result<Option<Arc<DnsProxy>>> {
        Ok(self
            .installed
            .lock()
            .map_err(|_| io::Error::other("DNS resolver state unavailable"))?
            .as_ref()
            .and_then(|dns| dns.proxy.as_ref().map(Arc::clone)))
    }

    async fn lookup_application_family(
        &self,
        resolver: &TaggedResolver,
        server: usize,
        domain: &ferrum2_core::CanonicalDomain,
        qtype: DnsCacheQtype,
    ) -> Result<Option<DnsAddressRecords>, DnsError> {
        let server_id =
            DnsServerId::new(u32::try_from(server).map_err(|_| DnsError::InvalidServer)?);
        let cached = self.proxy_runtime.as_ref().and_then(|runtime| {
            runtime.cache.as_ref().map(|cache| {
                (
                    cache,
                    DnsCacheKey::new(server_id, domain.clone(), qtype, runtime.generation),
                )
            })
        });
        if let Some((cache, key)) = cached.as_ref() {
            match cache
                .get(key, Instant::now())
                .map_err(|_| DnsError::Runtime)?
            {
                Some(DnsCacheAnswer::Positive(records)) => return Ok(Some(records)),
                Some(DnsCacheAnswer::Negative) => return Ok(None),
                None => {}
            }
        }
        let lookup = resolver
            .lookup_fixed_endpoint(server, domain.clone(), qtype)
            .await?;
        match lookup {
            FixedEndpointLookup::Positive { records, ttl } => {
                if let Some((cache, key)) = cached {
                    cache
                        .insert_positive(key, records.clone(), ttl, Instant::now())
                        .map_err(|_| DnsError::Runtime)?;
                }
                Ok(Some(records))
            }
            FixedEndpointLookup::Negative { ttl } => {
                if let Some((cache, key)) = cached {
                    cache
                        .insert_negative(key, ttl, Instant::now())
                        .map_err(|_| DnsError::Runtime)?;
                }
                Ok(None)
            }
        }
    }

    const fn strategy(&self) -> DnsStrategy {
        self.strategy
    }
}

#[derive(Clone)]
pub(super) struct ServerDnsResolver {
    adapter: ApplicationResolverAdapter,
}

#[cfg_attr(not(test), allow(dead_code))]
impl ServerDnsResolver {
    #[cfg(test)]
    pub(super) fn new(state: Option<Arc<ServerDnsState>>) -> Self {
        Self::new_inner(state, None)
    }

    pub(super) fn new_observed(state: Option<Arc<ServerDnsState>>, metrics: Arc<Metrics>) -> Self {
        Self::new_inner(state, Some(metrics))
    }

    pub(super) fn for_direct(
        mode: DirectDomainResolver,
        tagged: Arc<OnceLock<std::sync::Weak<TaggedResolver>>>,
    ) -> Self {
        Self::for_direct_inner(mode, tagged, None)
    }

    pub(super) fn for_direct_observed(
        mode: DirectDomainResolver,
        tagged: Arc<OnceLock<std::sync::Weak<TaggedResolver>>>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self::for_direct_inner(mode, tagged, Some(metrics))
    }

    fn new_inner(state: Option<Arc<ServerDnsState>>, metrics: Option<Arc<Metrics>>) -> Self {
        let strategy = state
            .as_ref()
            .map_or(DnsStrategy::PreferIpv4, |state| state.strategy());
        let mut resolver = match state {
            Some(state) => {
                ApplicationResolver::configured(Arc::new(ServerConfiguredApplicationBackend {
                    state,
                }))
            }
            None => ApplicationResolver::system_default(),
        };
        if let Some(metrics) = metrics {
            resolver = observed_application_resolver(resolver, metrics);
        }
        Self {
            adapter: ApplicationResolverAdapter::new(Arc::new(resolver), 0, strategy),
        }
    }

    fn for_direct_inner(
        mode: DirectDomainResolver,
        tagged: Arc<OnceLock<std::sync::Weak<TaggedResolver>>>,
        metrics: Option<Arc<Metrics>>,
    ) -> Self {
        let (mut resolver, strategy) = match mode {
            DirectDomainResolver::System => (
                ApplicationResolver::system_default(),
                DnsStrategy::PreferIpv4,
            ),
            DirectDomainResolver::DnsServer { server, strategy } => (
                ApplicationResolver::configured(Arc::new(
                    TaggedServerApplicationResolveBackend::new(tagged, server),
                )),
                dns_strategy(strategy),
            ),
        };
        if let Some(metrics) = metrics {
            resolver = observed_application_resolver(resolver, metrics);
        }
        Self {
            adapter: ApplicationResolverAdapter::new(Arc::new(resolver), 0, strategy),
        }
    }

    pub(super) fn for_inbound(&self, inbound: usize) -> Self {
        Self {
            adapter: self.adapter.for_ingress(inbound),
        }
    }

    #[cfg(test)]
    pub(super) fn mode(&self) -> ApplicationResolverMode {
        self.adapter.mode()
    }

    #[cfg(test)]
    pub(super) fn shares_application_resolver_with(&self, other: &Self) -> bool {
        self.adapter.shares_resolver_with(&other.adapter)
    }
}

fn observed_application_resolver(
    resolver: ApplicationResolver,
    metrics: Arc<Metrics>,
) -> ApplicationResolver {
    resolver.with_observer(Arc::new(move |mode, outcome| {
        let resolver = match mode {
            ApplicationResolverMode::System => {
                metrics.dns_explicit_system_resolve(DnsResolvePurpose::Application);
                DnsResolverKind::System
            }
            ApplicationResolverMode::Configured => DnsResolverKind::Configured,
        };
        let result = match outcome {
            ApplicationResolveOutcome::Success => DnsResolveResult::Success,
            ApplicationResolveOutcome::Failure => DnsResolveResult::Failure,
        };
        metrics.dns_resolve(resolver, DnsResolvePurpose::Application, result);
    }))
}

pub(super) fn dns_policy_observer(metrics: &Arc<Metrics>) -> Arc<dyn DnsPolicyObserver> {
    let metrics = Arc::clone(metrics);
    Arc::new(move |observation| observe_dns_policy(&metrics, observation))
}

fn observe_dns_policy(metrics: &Metrics, observation: DnsPolicyObservation) {
    if observation.query_evaluated() {
        metrics.observe_rule_program_candidate_count(
            RuleProgram::DnsQuery,
            observation.query_candidates(),
        );
        metrics.observe_rule_program_match_ns(RuleProgram::DnsQuery, observation.query_match_ns());
    }
    if observation.response_evaluated() {
        metrics.observe_rule_program_candidate_count(
            RuleProgram::DnsResponse,
            observation.response_candidates(),
        );
        metrics.observe_rule_program_match_ns(
            RuleProgram::DnsResponse,
            observation.response_match_ns(),
        );
    }
    for stage in DnsPolicyStage::ALL {
        for source in DnsPolicyMatchSource::ALL {
            for r#type in DnsPolicyMatchType::ALL {
                for result in DnsPolicyMatchResult::ALL {
                    let count = observation.match_count(stage, source, r#type, result);
                    if count == 0 {
                        continue;
                    }
                    let source = match source {
                        DnsPolicyMatchSource::Inline => RuleSource::Inline,
                        DnsPolicyMatchSource::RuleSet => RuleSource::RuleSet,
                    };
                    let r#type = match r#type {
                        DnsPolicyMatchType::Domain => RuleMatchType::Domain,
                        DnsPolicyMatchType::DomainSuffix => RuleMatchType::DomainSuffix,
                        DnsPolicyMatchType::DomainKeyword => RuleMatchType::DomainKeyword,
                        DnsPolicyMatchType::IpCidr => RuleMatchType::IpCidr,
                        DnsPolicyMatchType::Scalar => RuleMatchType::Scalar,
                    };
                    let result = match result {
                        DnsPolicyMatchResult::Matched => RuleMatchResult::Matched,
                        DnsPolicyMatchResult::Missed => RuleMatchResult::Missed,
                    };
                    match stage {
                        DnsPolicyStage::Query => {
                            metrics.dns_rule_query_matches(source, r#type, result, count);
                        }
                        DnsPolicyStage::Response => {
                            metrics.dns_rule_response_matches(source, r#type, result, count);
                        }
                    }
                }
            }
        }
    }
}

impl TcpResolver for ServerDnsResolver {
    type Candidates = Vec<SocketAddr>;

    async fn resolve(&self, host: &str, port: u16) -> io::Result<Self::Candidates> {
        TcpResolver::resolve(&self.adapter, host, port).await
    }
}

impl UdpResolver for ServerDnsResolver {
    type Candidates = Vec<SocketAddr>;

    async fn resolve(&self, host: &str, port: u16) -> io::Result<Self::Candidates> {
        UdpResolver::resolve(&self.adapter, host, port).await
    }
}

#[cfg_attr(not(test), allow(dead_code))]
struct ServerConfiguredApplicationBackend {
    state: Arc<ServerDnsState>,
}

impl ApplicationResolveBackend for ServerConfiguredApplicationBackend {
    fn resolve<'a>(
        &'a self,
        request: ApplicationResolveRequest<'a>,
    ) -> ApplicationResolveFuture<'a> {
        Box::pin(async move {
            if let Some(proxy) = self.state.proxy().map_err(|_| DnsError::Runtime)? {
                return proxy.resolve_application(request).await;
            }
            let context = request.context();
            let target = TargetAddr::domain(request.domain().as_str(), request.port().get())
                .map_err(|_| DnsError::Protocol)?;
            let selected = self
                .state
                .select(context.ingress(), context.network(), &target)
                .ok_or(DnsError::Runtime)?;
            let resolver = self.state.resolver().map_err(|_| DnsError::Runtime)?;
            let mut ipv4 = Vec::new();
            let mut ipv6 = Vec::new();
            let qtypes: &[DnsCacheQtype] = match request.strategy() {
                DnsStrategy::PreferIpv4 | DnsStrategy::PreferIpv6 => {
                    &[DnsCacheQtype::A, DnsCacheQtype::Aaaa]
                }
                DnsStrategy::Ipv4Only => &[DnsCacheQtype::A],
                DnsStrategy::Ipv6Only => &[DnsCacheQtype::Aaaa],
            };
            for &qtype in qtypes {
                let answer = self
                    .state
                    .lookup_application_family(&resolver, selected, request.domain(), qtype)
                    .await?;
                match answer {
                    Some(DnsAddressRecords::A(records)) => ipv4.extend(records.iter().copied()),
                    Some(DnsAddressRecords::Aaaa(records)) => ipv6.extend(records.iter().copied()),
                    None => {}
                }
            }
            let mut candidates = request
                .strategy()
                .socket_candidates(request.port(), &ipv4, &ipv6);
            candidates.truncate(MAX_RESOLVED_CANDIDATES);
            Ok(candidates)
        })
    }
}

const fn dns_strategy(strategy: ferrum2_config::DnsStrategy) -> DnsStrategy {
    match strategy {
        ferrum2_config::DnsStrategy::PreferIpv4 => DnsStrategy::PreferIpv4,
        ferrum2_config::DnsStrategy::PreferIpv6 => DnsStrategy::PreferIpv6,
        ferrum2_config::DnsStrategy::Ipv4Only => DnsStrategy::Ipv4Only,
        ferrum2_config::DnsStrategy::Ipv6Only => DnsStrategy::Ipv6Only,
    }
}

pub(super) struct ServerDnsEgress {
    outbound_count: usize,
    outbound_resolvers: Arc<[Option<ServerDnsResolver>]>,
}

impl ServerDnsEgress {
    pub(super) fn new(outbound_count: usize) -> Self {
        Self {
            outbound_count,
            outbound_resolvers: vec![None; outbound_count].into(),
        }
    }

    pub(super) fn with_outbound_resolvers(mut self, resolvers: Vec<ServerDnsResolver>) -> Self {
        debug_assert_eq!(resolvers.len(), self.outbound_count);
        self.outbound_resolvers = resolvers.into_iter().map(Some).collect();
        self
    }

    fn selected_outbound(&self, plan: &Option<EgressPlanSnapshot>) -> io::Result<Option<usize>> {
        match plan {
            None => Ok(None),
            Some(plan) if matches!(plan.hops(), [outbound] if *outbound < self.outbound_count) => {
                Ok(Some(plan.hops()[0]))
            }
            Some(_) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid server DNS detour",
            )),
        }
    }

    fn resolver(&self, outbound: usize) -> io::Result<ServerDnsResolver> {
        self.outbound_resolvers
            .get(outbound)
            .and_then(Option::as_ref)
            .cloned()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "server Direct resolver is unavailable",
                )
            })
    }
}

impl DnsEgress for ServerDnsEgress {
    fn connect_tcp(
        &self,
        target: TargetAddr,
        plan: Option<EgressPlanSnapshot>,
        timeout: Duration,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsTcpIo> {
        let outbound = match self.selected_outbound(&plan) {
            Ok(outbound) => outbound,
            Err(error) => return Box::pin(async move { Err(error) }),
        };
        let TargetHostRef::Domain(host) = target.host() else {
            return SystemDnsEgress.connect_tcp(target, None, timeout, tasks);
        };
        let Some(outbound) = outbound else {
            return Box::pin(async {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "server DNS domain target requires a Direct detour",
                ))
            });
        };
        let resolver = match self.resolver(outbound) {
            Ok(resolver) => resolver,
            Err(error) => return Box::pin(async move { Err(error) }),
        };
        let host = host.to_owned();
        let port = target.port().get();
        Box::pin(async move {
            let deadline = TokioInstant::now() + timeout;
            let candidates =
                tokio::time::timeout_at(deadline, TcpResolver::resolve(&resolver, &host, port))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "server DNS resolve timeout")
                    })??;
            let mut last_error = None;
            for candidate in candidates {
                let remaining = deadline.saturating_duration_since(TokioInstant::now());
                if remaining.is_zero() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "server DNS connect timeout",
                    ));
                }
                let candidate = TargetAddr::ip(candidate).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid resolved DNS target")
                })?;
                let connect =
                    SystemDnsEgress.connect_tcp(candidate, None, remaining, tasks.clone());
                match tokio::time::timeout_at(deadline, connect).await {
                    Ok(Ok(stream)) => return Ok(stream),
                    Ok(Err(error)) => last_error = Some(error),
                    Err(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "server DNS connect timeout",
                        ));
                    }
                }
            }
            Err(last_error.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "server Direct resolver returned no candidates",
                )
            }))
        })
    }

    fn bind_udp(
        &self,
        target: TargetAddr,
        plan: Option<EgressPlanSnapshot>,
        tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsDatagramIo> {
        let outbound = match self.selected_outbound(&plan) {
            Ok(outbound) => outbound,
            Err(error) => return Box::pin(async move { Err(error) }),
        };
        let TargetHostRef::Domain(host) = target.host() else {
            return SystemDnsEgress.bind_udp(target, None, tasks);
        };
        let Some(outbound) = outbound else {
            return Box::pin(async {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "server DNS domain target requires a Direct detour",
                ))
            });
        };
        let resolver = match self.resolver(outbound) {
            Ok(resolver) => resolver,
            Err(error) => return Box::pin(async move { Err(error) }),
        };
        let host = host.to_owned();
        let port = target.port().get();
        Box::pin(async move {
            let candidates = UdpResolver::resolve(&resolver, &host, port).await?;
            let candidate = candidates.into_iter().next().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "server Direct resolver returned no candidates",
                )
            })?;
            let candidate = TargetAddr::ip(candidate).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid resolved DNS target")
            })?;
            SystemDnsEgress.bind_udp(candidate, None, tasks).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ferrum2_config::{
        CompiledRuleSetResource, DnsEndpointMode, ServerV2Resources, finish_server_v2,
        prepare_server_v2,
    };
    use ferrum2_core::route::EgressPlanHandle;
    use ferrum2_rule::MatchSetBuilder;
    use hickory_proto::op::{Message, MessageType, OpCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use crate::run::test_support::{
        Ipv4Addr, UdpSocket, assert_pending, recv_udp, reserve_address, server_test_config_source,
    };

    #[test]
    fn dns_state_constructor_retains_closed_failure_kind() {
        let route = ActionTable::try_new(Vec::new(), 0).expect("empty compatibility route");
        assert!(matches!(
            ServerDnsState::try_new_with_cache(route, None, DnsRuntimeConfig::default(), None,),
            Err(ServerDnsStateBuildError::InvalidRuntime)
        ));
        assert_eq!(
            ServerDnsStateBuildError::from(RuleCompileError::Allocation),
            ServerDnsStateBuildError::Rule(RuleCompileError::Allocation)
        );
    }

    #[tokio::test]
    async fn application_observer_separates_system_and_configured_without_fallback() {
        let system_metrics = Arc::new(Metrics::new());
        let system = ServerDnsResolver::new_observed(None, Arc::clone(&system_metrics));
        assert!(
            !TcpResolver::resolve(&system, "localhost", 443)
                .await
                .expect("explicit system localhost")
                .is_empty()
        );
        let encoded = system_metrics.encode_text().expect("system metrics");
        assert!(encoded.contains(
            "ferrum2_dns_resolve_total{resolver=\"system\",purpose=\"application\",result=\"success\"} 1"
        ));
        assert!(
            encoded
                .contains("ferrum2_dns_explicit_system_resolve_total{purpose=\"application\"} 1")
        );
        assert!(encoded.contains("ferrum2_dns_implicit_system_fallback_total 0"));

        let listen = reserve_address();
        let upstream = reserve_address();
        let source = format!(
            r#"schema_version = 2

[[inbounds]]
tag = "app"
listen = "{listen}"

[[outbounds]]
tag = "direct"

[route]
final = "direct"

[dns]
strategy = "ipv4_only"

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
        );
        let (path, mut config) = server_test_config_source("dns-observer", &source);
        let dns = config.dns.take().expect("configured DNS");
        let state = Arc::new(
            ServerDnsState::try_new(dns.route, config.dns_route.take(), dns.runtime)
                .expect("configured state"),
        );
        let configured_metrics = Arc::new(Metrics::new());
        let configured =
            ServerDnsResolver::new_observed(Some(state), Arc::clone(&configured_metrics));
        assert!(
            TcpResolver::resolve(&configured, "failure.example", 443)
                .await
                .is_err()
        );
        let encoded = configured_metrics
            .encode_text()
            .expect("configured metrics");
        assert!(encoded.contains(
            "ferrum2_dns_resolve_total{resolver=\"configured\",purpose=\"application\",result=\"failure\"} 1"
        ));
        assert!(
            !encoded
                .contains("ferrum2_dns_explicit_system_resolve_total{purpose=\"application\"} 1")
        );
        assert!(encoded.contains("ferrum2_dns_implicit_system_fallback_total 0"));
        std::fs::remove_file(path).expect("remove observer config");
    }

    #[tokio::test]
    async fn caller_owned_cache_is_used_without_a_ruleset_policy() {
        let listen = reserve_address();
        let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("cache test upstream");
        let source = format!(
            r#"schema_version = 2

[[inbounds]]
tag = "app"
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
address = "{}"

[dns.route]
final = "configured"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#,
            upstream.local_addr().expect("upstream address")
        );
        let (path, mut config) = server_test_config_source("dns-shared-cache", &source);
        let dns = config.dns.take().expect("configured DNS");
        let specs = dns_runtime_specs(&dns.servers);
        let cache =
            DnsCache::try_new(std::num::NonZeroUsize::new(8).unwrap()).expect("caller cache");
        let domain = ferrum2_core::CanonicalDomain::new("cached.example").expect("cache domain");
        cache
            .insert_positive(
                DnsCacheKey::new(
                    DnsServerId::new(0),
                    domain,
                    DnsCacheQtype::A,
                    ResolverGeneration::new(0),
                ),
                DnsAddressRecords::A(Arc::from([Ipv4Addr::new(203, 0, 113, 44)])),
                Duration::from_secs(60),
                Instant::now(),
            )
            .expect("seed shared cache");
        let state = Arc::new(
            ServerDnsState::try_new_with_cache(
                dns.route,
                config.dns_route.take(),
                dns.runtime,
                Some(cache),
            )
            .expect("state with caller cache"),
        );
        let (tagged, mut owner) = TaggedResolver::new(
            specs,
            dns.timeout,
            dns.max_inflight,
            Arc::new(ServerDnsEgress::new(config.outbounds.len())),
        )
        .expect("tagged resolver");
        owner.ready().await.expect("tagged ready");
        state.install(Arc::new(tagged)).expect("install resolver");
        let resolver = ServerDnsResolver::new(Some(Arc::clone(&state)));
        assert_eq!(
            TcpResolver::resolve(&resolver, "cached.example", 443)
                .await
                .expect("cached application lookup"),
            [SocketAddr::from((Ipv4Addr::new(203, 0, 113, 44), 443))]
        );
        assert_pending(
            upstream.recv_from(&mut [0_u8; 1]),
            "caller cache was not shared with final application resolver",
        )
        .await;
        drop(resolver);
        drop(state.take());
        owner.shutdown().await.expect("tagged shutdown");
        std::fs::remove_file(path).expect("remove shared cache config");
    }

    #[test]
    fn dns_runtime_specs_preserve_validated_server_values() {
        let cases = [
            (DnsTransport::Udp, 5300, None, None, false),
            (DnsTransport::Udp, 5301, None, None, true),
            (DnsTransport::Tcp, 5302, None, None, false),
            (DnsTransport::Tcp, 5303, None, None, true),
            (
                DnsTransport::Dot,
                8530,
                Some("dot-direct.test"),
                None,
                false,
            ),
            (DnsTransport::Dot, 8531, Some("dot-detour.test"), None, true),
            (
                DnsTransport::Doh,
                4430,
                Some("doh-direct.test"),
                Some("/dns-query/direct"),
                false,
            ),
            (
                DnsTransport::Doh,
                4431,
                Some("doh-detour.test"),
                Some("/dns-query/detour"),
                true,
            ),
        ];
        let servers: Vec<_> = cases
            .iter()
            .enumerate()
            .map(
                |(index, &(transport, port, server_name, path, detoured))| DnsServerConfig {
                    transport,
                    target: TargetAddr::ip(SocketAddr::from(([192, 0, 2, 53], port)))
                        .expect("non-zero DNS target"),
                    resolved_targets: Box::new([]),
                    endpoint_mode: DnsEndpointMode::Numeric,
                    server_name: server_name.map(Into::into),
                    path: path.map(Into::into),
                    detour: detoured.then(|| EgressPlanHandle::direct(index)),
                },
            )
            .collect();
        let configured_plan_ptrs: Vec<_> = servers
            .iter()
            .map(|server| {
                server
                    .detour
                    .as_ref()
                    .map(|detour| detour.snapshot_owned().hops().as_ptr())
            })
            .collect();

        for (
            index,
            ((spec, (transport, port, server_name, path, detoured)), configured_plan_ptr),
        ) in dns_runtime_specs(&servers)
            .into_iter()
            .zip(cases)
            .zip(configured_plan_ptrs)
            .enumerate()
        {
            assert_eq!(
                spec.target,
                TargetAddr::ip(SocketAddr::from(([192, 0, 2, 53], port)))
                    .expect("non-zero DNS target")
            );
            match (detoured, spec.detour.as_ref()) {
                (true, Some(detour)) => {
                    let converted = detour.snapshot_owned();
                    assert_eq!(converted.hops(), &[index]);
                    assert_eq!(Some(converted.hops().as_ptr()), configured_plan_ptr);
                }
                (false, None) => {}
                _ => panic!("DNS runtime detour mapping drift"),
            }
            match (transport, spec.transport) {
                (DnsTransport::Udp, DnsUpstreamTransport::Udp)
                | (DnsTransport::Tcp, DnsUpstreamTransport::Tcp) => {
                    assert_eq!((server_name, path), (None, None));
                }
                (
                    DnsTransport::Dot,
                    DnsUpstreamTransport::Dot {
                        server_name: actual,
                    },
                ) => {
                    assert_eq!(actual.as_ref(), server_name.expect("DoT name"));
                    assert!(path.is_none());
                }
                (
                    DnsTransport::Doh,
                    DnsUpstreamTransport::Doh {
                        server_name: actual_name,
                        path: actual_path,
                    },
                ) => {
                    assert_eq!(actual_name.as_ref(), server_name.expect("DoH name"));
                    assert_eq!(actual_path.as_ref(), path.expect("DoH path"));
                }
                _ => panic!("DNS runtime transport mapping drift"),
            }
        }
    }

    async fn answer_a(socket: &UdpSocket, expected: &str, address: Ipv4Addr) {
        let mut wire = [0_u8; 4096];
        let (length, peer) = recv_udp(socket, &mut wire).await;
        let request = Message::from_vec(&wire[..length]).expect("DNS query decode");
        let [query] = request.queries.as_slice() else {
            panic!("one DNS query");
        };
        assert_eq!(query.name().to_ascii(), expected);
        assert_eq!(query.query_type(), RecordType::A);
        let mut response = Message::response(request.id, OpCode::Query);
        response.metadata.recursion_available = true;
        response.add_query(query.clone());
        response.add_answer(Record::from_rdata(
            query.name().clone(),
            60,
            RData::A(A(address)),
        ));
        socket
            .send_to(&response.to_vec().expect("DNS response encode"), peer)
            .await
            .expect("DNS response send");
    }

    fn a_response(request: &Message, addresses: &[Ipv4Addr]) -> Vec<u8> {
        let [query] = request.queries.as_slice() else {
            panic!("one DNS query");
        };
        let mut response = Message::response(request.id, OpCode::Query);
        response.metadata.recursion_available = true;
        response.add_query(query.clone());
        for &address in addresses {
            response.add_answer(Record::from_rdata(
                query.name().clone(),
                60,
                RData::A(A(address)),
            ));
        }
        response.to_vec().expect("DNS response encode")
    }

    async fn answer_udp_queries(
        socket: UdpSocket,
        expected: &'static str,
        answer_sets: Vec<Vec<Ipv4Addr>>,
    ) {
        let mut wire = [0_u8; 4096];
        for addresses in answer_sets {
            let (length, peer) = recv_udp(&socket, &mut wire).await;
            let request = Message::from_vec(&wire[..length]).expect("UDP DNS query decode");
            assert_eq!(request.queries[0].name().to_ascii(), expected);
            assert_eq!(request.queries[0].query_type(), RecordType::A);
            socket
                .send_to(&a_response(&request, &addresses), peer)
                .await
                .expect("UDP DNS response");
        }
    }

    async fn answer_tcp_query(
        listener: TcpListener,
        expected: &'static str,
        addresses: Vec<Ipv4Addr>,
    ) {
        let (mut stream, _) = listener.accept().await.expect("TCP DNS accept");
        let length = stream.read_u16().await.expect("TCP DNS length");
        let mut wire = vec![0_u8; usize::from(length)];
        stream.read_exact(&mut wire).await.expect("TCP DNS query");
        let request = Message::from_vec(&wire).expect("TCP DNS query decode");
        assert_eq!(request.queries[0].name().to_ascii(), expected);
        assert_eq!(request.queries[0].query_type(), RecordType::A);
        let response = a_response(&request, &addresses);
        stream
            .write_u16(u16::try_from(response.len()).expect("bounded DNS response"))
            .await
            .expect("TCP DNS response length");
        stream.write_all(&response).await.expect("TCP DNS response");
    }

    async fn paired_upstream() -> (SocketAddr, UdpSocket, TcpListener) {
        loop {
            let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("paired TCP bind");
            let address = tcp.local_addr().expect("paired address");
            if let Ok(udp) = UdpSocket::bind(address).await {
                return (address, udp, tcp);
            }
        }
    }

    fn upstream_spec(
        target: TargetAddr,
        transport: DnsUpstreamTransport,
        detoured: bool,
    ) -> DnsUpstreamSpec {
        DnsUpstreamSpec {
            transport,
            target,
            resolved_targets: Box::new([]),
            detour: detoured.then(|| EgressPlanHandle::direct(0)),
        }
    }

    #[tokio::test]
    async fn direct_exact_server_resolves_domain_tcp_and_udp_without_policy_fallback() {
        let bootstrap = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bootstrap DNS bind");
        let bootstrap_address = bootstrap.local_addr().expect("bootstrap DNS address");
        let bootstrap_task = tokio::spawn(answer_udp_queries(
            bootstrap,
            "exact-upstream.test.",
            vec![
                vec![Ipv4Addr::LOCALHOST, Ipv4Addr::new(127, 0, 0, 2)],
                vec![Ipv4Addr::LOCALHOST],
            ],
        ));
        let (upstream_address, udp, tcp) = paired_upstream().await;
        let udp_task = tokio::spawn(answer_udp_queries(
            udp,
            "payload.test.",
            vec![vec![Ipv4Addr::new(192, 0, 2, 81)]],
        ));
        let tcp_task = tokio::spawn(answer_tcp_query(
            tcp,
            "payload.test.",
            vec![Ipv4Addr::new(192, 0, 2, 82)],
        ));

        let tagged = Arc::new(OnceLock::new());
        let direct = ServerDnsResolver::for_direct(
            DirectDomainResolver::DnsServer {
                server: 0,
                strategy: ferrum2_config::DnsStrategy::Ipv4Only,
            },
            Arc::clone(&tagged),
        );
        let logical = TargetAddr::domain("exact-upstream.test", upstream_address.port())
            .expect("logical upstream");
        let egress = Arc::new(ServerDnsEgress::new(1).with_outbound_resolvers(vec![direct]));
        let (resolver, mut owner) = TaggedResolver::new(
            vec![
                upstream_spec(
                    TargetAddr::ip(bootstrap_address).expect("numeric bootstrap target"),
                    DnsUpstreamTransport::Udp,
                    false,
                ),
                upstream_spec(logical.clone(), DnsUpstreamTransport::Tcp, true),
                upstream_spec(logical, DnsUpstreamTransport::Udp, true),
            ],
            Duration::from_secs(1),
            std::num::NonZeroU16::new(4).expect("nested query admission"),
            egress,
        )
        .expect("domain upstream resolver");
        owner.ready().await.expect("domain upstream ready");
        let resolver = Arc::new(resolver);
        tagged
            .set(Arc::downgrade(&resolver))
            .map_err(|_| ())
            .expect("install shared exact resolver");

        let tcp_lookup = resolver
            .lookup(
                1,
                "payload.test.".parse().expect("TCP payload query name"),
                RecordType::A,
            )
            .await
            .expect("exact-server TCP lookup");
        assert!(
            tcp_lookup
                .answers()
                .iter()
                .any(|record| record.data == RData::A(A(Ipv4Addr::new(192, 0, 2, 82))))
        );
        let udp_lookup = resolver
            .lookup(
                2,
                "payload.test.".parse().expect("UDP payload query name"),
                RecordType::A,
            )
            .await
            .expect("exact-server UDP lookup");
        assert!(
            udp_lookup
                .answers()
                .iter()
                .any(|record| record.data == RData::A(A(Ipv4Addr::new(192, 0, 2, 81))))
        );

        bootstrap_task.await.expect("bootstrap DNS join");
        tcp_task.await.expect("TCP upstream join");
        udp_task.await.expect("UDP upstream join");
        drop(resolver);
        owner.shutdown().await.expect("domain upstream shutdown");
        drop(tagged);
    }

    #[tokio::test]
    async fn direct_system_resolver_connects_domain_tcp() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("system target bind");
        let address = listener.local_addr().expect("system target address");
        let upstream = tokio::spawn(answer_tcp_query(
            listener,
            "system-payload.test.",
            vec![Ipv4Addr::new(192, 0, 2, 83)],
        ));
        let unavailable = ServerDnsResolver::for_direct(
            DirectDomainResolver::DnsServer {
                server: 0,
                strategy: ferrum2_config::DnsStrategy::Ipv4Only,
            },
            Arc::new(OnceLock::new()),
        );
        let system =
            ServerDnsResolver::for_direct(DirectDomainResolver::System, Arc::new(OnceLock::new()));
        let egress =
            Arc::new(ServerDnsEgress::new(2).with_outbound_resolvers(vec![unavailable, system]));
        let (resolver, mut owner) = TaggedResolver::new(
            vec![DnsUpstreamSpec {
                target: TargetAddr::domain("localhost", address.port()).expect("localhost target"),
                transport: DnsUpstreamTransport::Tcp,
                resolved_targets: Box::new([]),
                detour: Some(EgressPlanHandle::direct(1)),
            }],
            Duration::from_secs(1),
            std::num::NonZeroU16::new(1).expect("query admission"),
            egress,
        )
        .expect("system domain resolver");
        owner.ready().await.expect("system domain ready");

        let lookup = resolver
            .lookup(
                0,
                "system-payload.test.".parse().expect("system payload name"),
                RecordType::A,
            )
            .await
            .expect("system-resolved TCP lookup");
        assert!(
            lookup
                .answers()
                .iter()
                .any(|record| record.data == RData::A(A(Ipv4Addr::new(192, 0, 2, 83))))
        );
        upstream.await.expect("system upstream join");
        drop(resolver);
        owner.shutdown().await.expect("system domain shutdown");
    }

    #[tokio::test]
    async fn numeric_target_bypasses_uninitialized_exact_resolver() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("numeric target bind");
        let address = listener.local_addr().expect("numeric target address");
        let upstream = tokio::spawn(answer_tcp_query(
            listener,
            "numeric-payload.test.",
            vec![Ipv4Addr::new(192, 0, 2, 84)],
        ));
        let direct = ServerDnsResolver::for_direct(
            DirectDomainResolver::DnsServer {
                server: 0,
                strategy: ferrum2_config::DnsStrategy::Ipv4Only,
            },
            Arc::new(OnceLock::new()),
        );
        let egress = Arc::new(ServerDnsEgress::new(1).with_outbound_resolvers(vec![direct]));
        let (resolver, mut owner) = TaggedResolver::new(
            vec![upstream_spec(
                TargetAddr::ip(address).expect("numeric target"),
                DnsUpstreamTransport::Tcp,
                true,
            )],
            Duration::from_secs(1),
            std::num::NonZeroU16::new(1).expect("query admission"),
            egress,
        )
        .expect("numeric resolver");
        owner.ready().await.expect("numeric resolver ready");

        let lookup = resolver
            .lookup(
                0,
                "numeric-payload.test."
                    .parse()
                    .expect("numeric payload name"),
                RecordType::A,
            )
            .await
            .expect("numeric lookup");
        assert!(
            lookup
                .answers()
                .iter()
                .any(|record| record.data == RData::A(A(Ipv4Addr::new(192, 0, 2, 84))))
        );
        upstream.await.expect("numeric upstream join");
        drop(resolver);
        owner.shutdown().await.expect("numeric resolver shutdown");
    }

    #[tokio::test]
    async fn domain_target_without_plan_fails_closed_before_connect() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("no-plan target bind");
        let address = listener.local_addr().expect("no-plan target address");
        let direct =
            ServerDnsResolver::for_direct(DirectDomainResolver::System, Arc::new(OnceLock::new()));
        let egress = Arc::new(ServerDnsEgress::new(1).with_outbound_resolvers(vec![direct]));
        let (resolver, mut owner) = TaggedResolver::new(
            vec![upstream_spec(
                TargetAddr::domain("localhost", address.port()).expect("no-plan domain target"),
                DnsUpstreamTransport::Tcp,
                false,
            )],
            Duration::from_millis(100),
            std::num::NonZeroU16::new(1).expect("query admission"),
            egress,
        )
        .expect("no-plan resolver");
        owner.ready().await.expect("no-plan resolver ready");

        assert!(
            resolver
                .lookup(
                    0,
                    "no-plan.test.".parse().expect("no-plan query name"),
                    RecordType::A,
                )
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err(),
            "domain target connected without a detour plan"
        );
        drop(resolver);
        owner.shutdown().await.expect("no-plan resolver shutdown");
    }

    #[tokio::test]
    async fn materialized_policy_proxy_composes_reject_cnip_cache_generation_and_no_fallback() {
        let listen = reserve_address();
        let local = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("local DNS upstream");
        let fallback = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("fallback DNS upstream");
        let dead = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("dead DNS upstream");
        let mut source = format!(
            r#"schema_version = 2

[[inbounds]]
tag = "app"
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

[[route.rule_set]]
tag = "cnip"
type = "remote"
url = "https://rules.example.invalid/cnip.srs"
download_resolver = "system"

[dns]
timeout_ms = 100
max_inflight = 8
strategy = "ipv4_only"

[dns.cache]
enabled = true
max_entries = 16

[[dns.servers]]
tag = "local"
transport = "udp"
address = "{}"

[[dns.servers]]
tag = "dead"
transport = "udp"
address = "{}"

[[dns.servers]]
tag = "fallback"
transport = "udp"
address = "{}"

[dns.route]
final = "fallback"

[[dns.route.rules]]
inbound = "app"
rule_set = "ads"
action = "reject"

[[dns.route.rules]]
inbound = "app"
network = "tcp"
domain = "dead.example"
port = 443
action = "route"
server = "dead"

[[dns.route.rules]]
inbound = "app"
network = ["tcp", "udp"]
rule_set = "cnip"
port = 443
action = "route"
server = "local"
strategy = "ipv4_only"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="
"#,
            local.local_addr().unwrap(),
            dead.local_addr().unwrap(),
            fallback.local_addr().unwrap(),
        );
        for index in 0..62 {
            source.push_str(&format!(
                "\n[[dns.route.rules]]\ndomain = [\"unused-{index}.indexed.invalid\"]\naction = \"reject\"\n"
            ));
        }
        let path = std::env::temp_dir().join(format!(
            "ferrum2-server-policy-composition-{}-{}.toml",
            std::process::id(),
            listen.port()
        ));
        std::fs::write(&path, source).expect("write V2 server config");
        let prepared = prepare_server_v2(&path).expect("prepare V2 server config");
        let mut ads = MatchSetBuilder::new();
        ads.add_exact_domain("ads.example").unwrap();
        let mut cnip = MatchSetBuilder::new();
        cnip.add_ip("203.0.113.7".parse().unwrap()).unwrap();
        let mut config = finish_server_v2(
            prepared,
            ServerV2Resources::new(
                Vec::new(),
                vec![
                    CompiledRuleSetResource::new(0, Arc::new(ads.build().unwrap()), 17),
                    CompiledRuleSetResource::new(1, Arc::new(cnip.build().unwrap()), 17),
                ],
            ),
        )
        .expect("finish V2 server config");
        let _ = std::fs::remove_file(path);
        let metrics = Arc::new(Metrics::new());
        crate::run::publish_rule_program_metadata(&config, &metrics);
        let dns = config.dns.take().expect("materialized DNS graph");
        let specs = dns_runtime_specs(&dns.servers);
        let state = Arc::new(
            ServerDnsState::try_new(dns.route, config.dns_route.take(), dns.runtime)
                .expect("policy DNS state")
                .with_policy_observer(dns_policy_observer(&metrics)),
        );
        let proxy = state.proxy_runtime.as_ref().expect("policy proxy binding");
        assert!(proxy.policy.is_some());
        assert_eq!(proxy.generation, ResolverGeneration::new(17));
        assert_eq!(proxy.cache.as_ref().unwrap().capacity().unwrap(), 16);
        let (tagged, mut owner) = TaggedResolver::new(
            specs,
            dns.timeout,
            dns.max_inflight,
            Arc::new(ServerDnsEgress::new(config.outbounds.len())),
        )
        .expect("tagged DNS resolver");
        owner.ready().await.expect("tagged DNS ready");
        state
            .install(Arc::new(tagged))
            .expect("install policy DNS proxy");
        let tcp = ServerDnsResolver::new_observed(Some(Arc::clone(&state)), Arc::clone(&metrics))
            .for_inbound(0);
        let udp = tcp.for_inbound(0);
        assert_eq!(tcp.mode(), ApplicationResolverMode::Configured);
        assert!(tcp.shares_application_resolver_with(&udp));
        assert_eq!(tcp.adapter.strategy(), DnsStrategy::Ipv4Only);

        assert!(
            TcpResolver::resolve(&tcp, "ads.example", 443)
                .await
                .is_err()
        );
        assert_pending(
            local.recv_from(&mut [0_u8; 1]),
            "ads reached local upstream",
        )
        .await;
        assert_pending(
            fallback.recv_from(&mut [0_u8; 1]),
            "ads reached fallback upstream",
        )
        .await;

        let hit = TcpResolver::resolve(&tcp, "hit.example", 443);
        let response = answer_a(&local, "hit.example.", Ipv4Addr::new(203, 0, 113, 7));
        let (hit, ()) = tokio::join!(hit, response);
        assert_eq!(
            hit.unwrap(),
            [SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 443))]
        );
        assert_eq!(
            UdpResolver::resolve(&udp, "hit.example", 443)
                .await
                .unwrap(),
            [SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 443))]
        );
        assert_pending(
            local.recv_from(&mut [0_u8; 1]),
            "TCP/UDP shared cache missed",
        )
        .await;

        let miss = TcpResolver::resolve(&tcp, "miss.example", 443);
        let responses = async {
            answer_a(&local, "miss.example.", Ipv4Addr::new(198, 51, 100, 9)).await;
            answer_a(&fallback, "miss.example.", Ipv4Addr::new(192, 0, 2, 9)).await;
        };
        let (miss, ()) = tokio::join!(miss, responses);
        assert_eq!(
            miss.unwrap(),
            [SocketAddr::from((Ipv4Addr::new(192, 0, 2, 9), 443))]
        );

        let failure = TcpResolver::resolve(&tcp, "dead.example", 443);
        let observed_dead = async {
            let mut wire = [0_u8; 4096];
            let (length, _) = recv_udp(&dead, &mut wire).await;
            let request = Message::from_vec(&wire[..length]).unwrap();
            assert_eq!(request.queries[0].name().to_ascii(), "dead.example.");
        };
        let (failure, ()) = tokio::join!(failure, observed_dead);
        assert!(failure.is_err(), "selected failure must be terminal");
        assert_pending(
            fallback.recv_from(&mut [0_u8; 1]),
            "selected failure reached fallback",
        )
        .await;

        let encoded = metrics.encode_text().expect("server DNS policy metrics");
        for expected in [
            "ferrum2_rule_program_mode{program=\"dns_query\",mode=\"indexed\"} 1",
            "ferrum2_rule_program_mode{program=\"dns_response\",mode=\"indexed\"} 1",
            "ferrum2_rule_program_rules{program=\"dns_query\"} 65",
            "ferrum2_rule_program_rules{program=\"dns_response\"} 1",
            "ferrum2_dns_rule_query_match_total{source=\"rule_set\",type=\"domain\",result=\"matched\"} 1",
            "ferrum2_dns_rule_response_match_total{source=\"rule_set\",type=\"ip_cidr\",result=\"matched\"} 2",
            "ferrum2_dns_rule_response_match_total{source=\"rule_set\",type=\"ip_cidr\",result=\"missed\"} 1",
            "ferrum2_dns_implicit_system_fallback_total 0",
        ] {
            assert!(
                encoded.contains(expected),
                "missing `{expected}`\n{encoded}"
            );
        }
        for identity in [
            "ferrum2_rule_program_candidate_count_sum{program=\"dns_query\"}",
            "ferrum2_rule_program_candidate_count_count{program=\"dns_query\"}",
            "ferrum2_rule_program_match_ns_sum{program=\"dns_query\"}",
            "ferrum2_rule_program_match_ns_count{program=\"dns_query\"}",
            "ferrum2_rule_program_candidate_count_sum{program=\"dns_response\"}",
            "ferrum2_rule_program_candidate_count_count{program=\"dns_response\"}",
            "ferrum2_rule_program_match_ns_sum{program=\"dns_response\"}",
            "ferrum2_rule_program_match_ns_count{program=\"dns_response\"}",
        ] {
            assert!(
                encoded
                    .lines()
                    .any(|line| line.starts_with(identity) && !line.ends_with(" 0")),
                "zero or missing `{identity}`\n{encoded}"
            );
        }

        drop(tcp);
        drop(udp);
        drop(state.take());
        owner.shutdown().await.expect("tagged DNS shutdown");
    }

    #[tokio::test]
    async fn tagged_dns_selection_uses_authenticated_original_context_and_final() {
        let listen = reserve_address();
        let selected_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("selected DNS upstream");
        let selected_address = selected_socket.local_addr().expect("selected DNS address");
        let final_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("final DNS upstream");
        let final_address = final_socket.local_addr().expect("final DNS address");
        let dead_address = reserve_address();
        let source = format!(
            "schema_version = 2\n\
             [[inbounds]]\n\
             tag = \"i0\"\n\
             listen = \"{listen}\"\n\
             [[outbounds]]\n\
             tag = \"direct\"\n\
             [route]\n\
             final = \"direct\"\n\
             [shadowsocks]\n\
             method = \"2022-blake3-aes-128-gcm\"\n\
             psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n\
             [dns]\n\
             timeout_ms = 100\n\
             [[dns.servers]]\n\
             tag = \"selected\"\n\
             transport = \"udp\"\n\
             address = \"{selected_address}\"\n\
             [[dns.servers]]\n\
             tag = \"dead\"\n\
             transport = \"udp\"\n\
             address = \"{dead_address}\"\n\
             [[dns.servers]]\n\
             tag = \"final\"\n\
             transport = \"udp\"\n\
             address = \"{final_address}\"\n\
             [dns.route]\n\
             final = \"final\"\n\
             [[dns.route.rules]]\n\
             inbound = \"i0\"\n\
             network = \"tcp\"\n\
             domain = \"exact.test\"\n\
             port = 53\n\
             server = \"selected\"\n\
             [[dns.route.rules]]\n\
             inbound = \"i0\"\n\
             network = \"tcp\"\n\
             domain = \"dead.example.com\"\n\
             port = 443\n\
             server = \"dead\"\n\
             [[dns.route.rules]]\n\
             inbound = \"i0\"\n\
             network = [\"tcp\", \"udp\"]\n\
             domain_suffix = \"example.com\"\n\
             port_range = \"443:8443\"\n\
             server = \"selected\"\n"
        );
        let (path, config) = server_test_config_source("dns-policy", &source);
        let dns = config.dns.expect("server DNS config");
        let specs = dns_runtime_specs(&dns.servers);
        let state = Arc::new(
            ServerDnsState::try_new(dns.route, config.dns_route, dns.runtime)
                .expect("server DNS state"),
        );
        let exact = TargetAddr::domain("EXACT.TEST.", 53).expect("exact target");
        let suffix_low = TargetAddr::domain("api.example.com.", 443).expect("range low target");
        let suffix_high =
            TargetAddr::domain("deep.api.example.com", 8443).expect("range high target");
        let dead = TargetAddr::domain("dead.example.com", 443).expect("dead target");
        let below = TargetAddr::domain("api.example.com", 442).expect("below range target");
        let above = TargetAddr::domain("api.example.com", 8444).expect("above range target");
        let other = TargetAddr::domain("other.test", 443).expect("final target");

        let selected_task = tokio::spawn(async move {
            let mut wire = [0_u8; 4096];
            for expected_qtype in [
                RecordType::A,
                RecordType::AAAA,
                RecordType::A,
                RecordType::AAAA,
            ] {
                let (length, peer) = recv_udp(&selected_socket, &mut wire).await;
                let request =
                    Message::from_vec(&wire[..length]).expect("selected DNS query decode");
                assert_eq!(request.metadata.message_type, MessageType::Query);
                assert_eq!(request.metadata.op_code, OpCode::Query);
                let [query] = request.queries.as_slice() else {
                    panic!("selected upstream must receive one DNS query");
                };
                assert_eq!(query.query_class(), DNSClass::IN);
                assert_eq!(query.query_type(), expected_qtype);
                let mut response = Message::response(request.id, OpCode::Query);
                response.metadata.recursion_available = true;
                response.add_query(query.clone());
                let response = response.to_vec().expect("selected DNS response encode");
                selected_socket
                    .send_to(&response, peer)
                    .await
                    .expect("selected DNS response");
            }
        });
        let (check_final, start_final_check) = tokio::sync::oneshot::channel();
        let final_task = tokio::spawn(async move {
            let mut wire = [0_u8; 4096];
            for expected_qtype in [RecordType::A, RecordType::AAAA] {
                let (length, peer) = recv_udp(&final_socket, &mut wire).await;
                let request = Message::from_vec(&wire[..length]).expect("final DNS query decode");
                assert_eq!(request.metadata.message_type, MessageType::Query);
                assert_eq!(request.metadata.op_code, OpCode::Query);
                let [query] = request.queries.as_slice() else {
                    panic!("final upstream must receive one DNS query");
                };
                assert_eq!(query.query_class(), DNSClass::IN);
                assert_eq!(query.query_type(), expected_qtype);
                let mut response = Message::response(request.id, OpCode::Query);
                response.metadata.recursion_available = true;
                response.add_query(query.clone());
                let response = response.to_vec().expect("final DNS response encode");
                final_socket
                    .send_to(&response, peer)
                    .await
                    .expect("final DNS response");
            }
            start_final_check.await.expect("start no-fallback check");
            assert_pending(
                final_socket.recv_from(&mut wire),
                "selected DNS failure reached the healthy final server",
            )
            .await;
        });
        let egress = Arc::new(ServerDnsEgress::new(config.outbounds.len()));
        let (resolver, mut owner) =
            TaggedResolver::new(specs, dns.timeout, dns.max_inflight, egress)
                .expect("server DNS resolver");
        owner.ready().await.expect("server DNS resolver ready");
        state
            .install(Arc::new(resolver))
            .expect("install server DNS resolver");
        let resolver = ServerDnsResolver::new(Some(Arc::clone(&state))).for_inbound(0);
        let udp_resolver = resolver.for_inbound(0);

        assert_eq!(resolver.mode(), ApplicationResolverMode::Configured);
        assert!(resolver.shares_application_resolver_with(&udp_resolver));

        assert_eq!(
            TcpResolver::resolve(&resolver, "EXACT.TEST.", 53)
                .await
                .expect("exact DNS resolution"),
            []
        );
        assert_eq!(
            TcpResolver::resolve(&resolver, "api.example.com.", 443)
                .await
                .expect("suffix DNS resolution"),
            []
        );
        assert_eq!(
            TcpResolver::resolve(&resolver, "other.test.", 443)
                .await
                .expect("final DNS resolution"),
            []
        );
        check_final.send(()).expect("arm no-fallback check");
        assert!(
            TcpResolver::resolve(&resolver, "dead.example.com.", 443)
                .await
                .is_err(),
            "selected DNS failure must remain terminal"
        );

        selected_task.await.expect("selected DNS upstream join");
        final_task.await.expect("final DNS upstream join");
        assert_eq!(state.select(0, Network::Tcp, &exact), Some(0));
        assert_eq!(state.select(0, Network::Tcp, &suffix_low), Some(0));
        assert_eq!(state.select(0, Network::Udp, &suffix_high), Some(0));
        assert_eq!(state.select(0, Network::Tcp, &dead), Some(1));
        assert_eq!(state.select(1, Network::Tcp, &exact), Some(2));
        assert_eq!(state.select(0, Network::Udp, &exact), Some(2));
        assert_eq!(state.select(0, Network::Tcp, &below), Some(2));
        assert_eq!(state.select(0, Network::Tcp, &above), Some(2));
        assert_eq!(state.select(0, Network::Tcp, &other), Some(2));
        drop(resolver);
        drop(state.take());
        assert_eq!(
            owner
                .shutdown()
                .await
                .expect("server DNS resolver shutdown")
                .stats,
            ferrum2_dns::RuntimeStats::default()
        );
        std::fs::remove_file(path).expect("remove server DNS policy config");
    }
}
