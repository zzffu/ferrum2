#![forbid(unsafe_code)]

//! Server adapters for the shared tagged DNS resolver.

use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use bytes::BytesMut;
use ferrum2_config::{
    DirectDomainResolver, DnsRuntimeConfig, DnsServerConfig, DnsTransport, ServerDnsRoute,
};
use ferrum2_core::route::EgressPlanSnapshot;
use ferrum2_core::{TargetAddr, TargetHostRef};
use ferrum2_dns::ApplicationResolverAdapter;
use ferrum2_dns::{
    ApplicationResolveBackend, ApplicationResolveFuture, ApplicationResolveOutcome,
    ApplicationResolveRequest, ApplicationResolver, ApplicationResolverMode, BoxedDnsDatagramIo,
    BoxedDnsTcpIo, ChannelDnsDatagram, DnsCache, DnsCacheError, DnsEgress, DnsEgressResourceKind,
    DnsEgressTaskKind, DnsError, DnsIoFuture, DnsPolicyCompileError, DnsPolicyMatchResult,
    DnsPolicyMatchSource, DnsPolicyMatchType, DnsPolicyObservation, DnsPolicyObserver,
    DnsPolicyProgram, DnsPolicyStage, DnsProxy, DnsStrategy, DnsTaskRegistrar, DnsUpstreamSpec,
    DnsUpstreamTransport, TaggedResolver, TaggedServerApplicationResolveBackend,
};
use ferrum2_net::{DialOptions, RouteNetworkOptions, TcpResolver, UdpResolver};
use ferrum2_observability::{
    DnsResolvePurpose, DnsResolveResult, DnsResolverKind, Metrics, RuleMatchResult, RuleMatchType,
    RuleProgram, RuleSource,
};
use ferrum2_rule::RuleEngineRegistry;
use ferrum2_runtime::MAX_RESOLVED_CANDIDATES;
#[cfg(all(not(windows), not(test)))]
use ferrum2_runtime::RuntimeTcpStream;
#[cfg(any(windows, test))]
use ferrum2_runtime::{DirectUdpSocket, GenerationBoundUdpSocket};
use tokio::net::UdpSocket;
use tokio::time::Instant as TokioInstant;

use super::network::{ServerNetworkSocketService, ServerPhysicalTcpStream};
#[cfg(any(windows, test))]
use super::network::{
    interface_resolution_result, interface_resolution_source, record_interface_resolution_success,
};

const MAX_DNS_UDP_DATAGRAM_BYTES: usize = 65_535;

#[cfg(any(windows, test))]
type ServerPhysicalUdpSocket = GenerationBoundUdpSocket<UdpSocket>;
#[cfg(all(not(windows), not(test)))]
type ServerPhysicalUdpSocket = UdpSocket;

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
    strategy: DnsStrategy,
    proxy_runtime: ServerProxyRuntime,
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
    policy: ServerProxyPolicy,
    cache: Option<DnsCache>,
}

#[cfg_attr(not(test), allow(dead_code))]
struct InstalledServerDns {
    resolver: Arc<TaggedResolver>,
    proxy: Arc<DnsProxy>,
}

/// Closed construction failures for server DNS state. Keeping the rule error
/// intact lets the composition root distinguish scratch allocation/capacity
/// failures from compiler consistency failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ServerDnsStateBuildError {
    CacheAllocation,
    InvalidRuntime,
    DnsPolicy(DnsPolicyCompileError),
}

#[cfg_attr(not(test), allow(dead_code))]
impl ServerDnsState {
    pub(super) fn try_new(
        policy: ServerDnsRoute,
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
        Self::try_new_with_cache(policy, runtime, cache)
    }

    pub(super) fn try_new_with_cache(
        mut policy: ServerDnsRoute,
        runtime: DnsRuntimeConfig,
        cache: Option<DnsCache>,
    ) -> Result<Self, ServerDnsStateBuildError> {
        let cache_config = runtime.cache();
        if cache_config.enabled != cache.is_some() {
            return Err(ServerDnsStateBuildError::InvalidRuntime);
        }
        let binding = policy
            .take_policy_blueprint()
            .ok_or(ServerDnsStateBuildError::InvalidRuntime)?;
        let (blueprint, registry, listener_count, ordinary_count) = binding.into_parts();
        let snapshot = registry.snapshot();
        let program = DnsPolicyProgram::try_from_blueprint(blueprint, &snapshot)
            .map_err(ServerDnsStateBuildError::DnsPolicy)?;
        let proxy_runtime = ServerProxyRuntime {
            policy: ServerProxyPolicy {
                program: Arc::new(program),
                registry,
                listener_count,
                ordinary_count,
            },
            cache,
        };
        Ok(Self {
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

    pub(super) fn install(self: &Arc<Self>, resolver: Arc<TaggedResolver>) -> Result<(), ()> {
        let runtime = &self.proxy_runtime;
        let policy = &runtime.policy;
        let mut proxy = DnsProxy::new(
            Arc::clone(&resolver),
            Arc::clone(&policy.program),
            Arc::clone(&policy.registry),
            policy.listener_count,
            policy.ordinary_count,
        );
        if let Some(observer) = &self.policy_observer {
            proxy = proxy.with_policy_observer(Arc::clone(observer));
        }
        if let Some(cache) = &runtime.cache {
            proxy = proxy.with_cache(cache.clone());
        }
        let proxy = Arc::new(proxy);
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

    fn proxy(&self) -> io::Result<Arc<DnsProxy>> {
        self.installed
            .lock()
            .map_err(|_| io::Error::other("DNS resolver state unavailable"))?
            .as_ref()
            .map(|dns| Arc::clone(&dns.proxy))
            .ok_or_else(|| io::Error::other("DNS proxy is not active"))
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
            self.state
                .proxy()
                .map_err(|_| DnsError::Runtime)?
                .resolve_application(request)
                .await
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

#[derive(Clone)]
pub(super) struct ServerPhysicalSocketContext {
    sockets: Arc<ServerNetworkSocketService>,
    outbound_dial_options: Arc<[DialOptions]>,
    route_network: Arc<RouteNetworkOptions>,
    default_dial_options: DialOptions,
    metrics: Arc<Metrics>,
}

impl ServerPhysicalSocketContext {
    pub(super) fn new(
        sockets: Arc<ServerNetworkSocketService>,
        outbound_dial_options: Arc<[DialOptions]>,
        route_network: Arc<RouteNetworkOptions>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            sockets,
            outbound_dial_options,
            route_network,
            default_dial_options: DialOptions::default(),
            metrics,
        }
    }

    pub(super) fn outbound_count(&self) -> usize {
        self.outbound_dial_options.len()
    }

    fn dial_options(&self, outbound: Option<usize>) -> io::Result<&DialOptions> {
        match outbound {
            Some(outbound) => self
                .outbound_dial_options
                .get(outbound)
                .ok_or_else(closed_physical_socket_error),
            None => Ok(&self.default_dial_options),
        }
    }

    pub(super) async fn connect_tcp(
        &self,
        destination: SocketAddr,
        outbound: Option<usize>,
        deadline: TokioInstant,
    ) -> io::Result<ServerPhysicalTcpStream> {
        let dial_options = self.dial_options(outbound)?;
        #[cfg(all(not(windows), not(test)))]
        {
            let _ = (
                &self.sockets,
                dial_options,
                &self.route_network,
                &self.metrics,
            );
            let stream =
                tokio::time::timeout_at(deadline, tokio::net::TcpStream::connect(destination))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "physical TCP connect timeout")
                    })??;
            RuntimeTcpStream::from_connected(stream)
        }

        #[cfg(any(windows, test))]
        {
            let result = tokio::time::timeout_at(
                deadline,
                self.sockets
                    .connect_tcp(dial_options, self.route_network.as_ref(), destination),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "physical TCP connect timeout"))?;
            match result {
                Ok(stream) => {
                    record_interface_resolution_success(&self.metrics, stream.resolved_interface());
                    Ok(stream)
                }
                Err(error) => {
                    self.metrics.outbound_interface_resolution(
                        interface_resolution_source(error.attempted_source()),
                        interface_resolution_result(&error),
                    );
                    Err(closed_physical_socket_error())
                }
            }
        }
    }

    async fn connect_udp(
        &self,
        destination: SocketAddr,
        outbound: Option<usize>,
    ) -> io::Result<ServerPhysicalUdpSocket> {
        let dial_options = self.dial_options(outbound)?;
        #[cfg(all(not(windows), not(test)))]
        {
            let _ = (
                &self.sockets,
                dial_options,
                &self.route_network,
                &self.metrics,
            );
            let local = match destination {
                SocketAddr::V4(_) => SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)),
                SocketAddr::V6(_) => SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)),
            };
            UdpSocket::bind(local).await
        }

        #[cfg(any(windows, test))]
        {
            let result = self
                .sockets
                .connect_udp(dial_options, self.route_network.as_ref(), destination)
                .await;
            match result {
                Ok(socket) => {
                    record_interface_resolution_success(&self.metrics, socket.resolved_interface());
                    Ok(socket)
                }
                Err(error) => {
                    self.metrics.outbound_interface_resolution(
                        interface_resolution_source(error.attempted_source()),
                        interface_resolution_result(&error),
                    );
                    Err(closed_physical_socket_error())
                }
            }
        }
    }

    #[cfg(test)]
    pub(super) fn test(outbound_count: usize, metrics: Arc<Metrics>) -> Arc<Self> {
        let registry = ferrum2_runtime::OwnerRegistry::new();
        let sockets = super::tcp::prepare_server_network_socket_service(&registry, &metrics)
            .expect("test network socket service");
        Arc::new(Self::new(
            sockets,
            vec![DialOptions::default(); outbound_count].into(),
            Arc::new(RouteNetworkOptions::default()),
            metrics,
        ))
    }
}

fn closed_physical_socket_error() -> io::Error {
    io::Error::other("generation-bound physical socket unavailable")
}

pub(super) struct ServerDnsEgress {
    outbound_count: usize,
    outbound_resolvers: Arc<[Option<ServerDnsResolver>]>,
    physical: Arc<ServerPhysicalSocketContext>,
}

impl ServerDnsEgress {
    pub(super) fn new(physical: Arc<ServerPhysicalSocketContext>) -> Self {
        let outbound_count = physical.outbound_count();
        Self {
            outbound_count,
            outbound_resolvers: vec![None; outbound_count].into(),
            physical,
        }
    }

    #[cfg(test)]
    fn test(outbound_count: usize) -> Self {
        let metrics = Arc::new(Metrics::new());
        Self::new(ServerPhysicalSocketContext::test(outbound_count, metrics))
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
        _tasks: DnsTaskRegistrar,
    ) -> DnsIoFuture<BoxedDnsTcpIo> {
        let outbound = match self.selected_outbound(&plan) {
            Ok(outbound) => outbound,
            Err(error) => return Box::pin(async move { Err(error) }),
        };
        let physical = Arc::clone(&self.physical);
        let resolved = target.as_socket_addr();
        let domain = match target.host() {
            TargetHostRef::Domain(host) => Some((host.to_owned(), target.port().get())),
            TargetHostRef::Ip(_) => None,
        };
        let resolver = match (resolved, outbound) {
            (Some(_), _) => None,
            (None, Some(outbound)) => match self.resolver(outbound) {
                Ok(resolver) => Some(resolver),
                Err(error) => return Box::pin(async move { Err(error) }),
            },
            (None, None) => {
                return Box::pin(async {
                    Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "server DNS domain target requires a Direct detour",
                    ))
                });
            }
        };
        Box::pin(async move {
            let deadline = TokioInstant::now() + timeout;
            let candidates = match (resolved, resolver, domain) {
                (Some(destination), None, None) => vec![destination],
                (None, Some(resolver), Some((host, port))) => {
                    tokio::time::timeout_at(deadline, TcpResolver::resolve(&resolver, &host, port))
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "server DNS resolve timeout")
                        })??
                }
                _ => return Err(closed_physical_socket_error()),
            };
            let mut last_error = None;
            for candidate in candidates.into_iter().take(MAX_RESOLVED_CANDIDATES) {
                match physical.connect_tcp(candidate, outbound, deadline).await {
                    Ok(stream) => return Ok(Box::new(stream) as BoxedDnsTcpIo),
                    Err(error) if error.kind() == io::ErrorKind::TimedOut => return Err(error),
                    Err(error) => last_error = Some(error),
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
        let physical = Arc::clone(&self.physical);
        let resolved = target.as_socket_addr();
        let domain = match target.host() {
            TargetHostRef::Domain(host) => Some((host.to_owned(), target.port().get())),
            TargetHostRef::Ip(_) => None,
        };
        let resolver = match (resolved, outbound) {
            (Some(_), _) => None,
            (None, Some(outbound)) => match self.resolver(outbound) {
                Ok(resolver) => Some(resolver),
                Err(error) => return Box::pin(async move { Err(error) }),
            },
            (None, None) => {
                return Box::pin(async {
                    Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "server DNS domain target requires a Direct detour",
                    ))
                });
            }
        };
        Box::pin(async move {
            let candidate = match (resolved, resolver, domain) {
                (Some(destination), None, None) => destination,
                (None, Some(resolver), Some((host, port))) => {
                    UdpResolver::resolve(&resolver, &host, port)
                        .await?
                        .into_iter()
                        .take(MAX_RESOLVED_CANDIDATES)
                        .next()
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::AddrNotAvailable,
                                "server Direct resolver returned no candidates",
                            )
                        })?
                }
                _ => return Err(closed_physical_socket_error()),
            };
            let socket = physical.connect_udp(candidate, outbound).await?;
            Ok(server_dns_datagram(socket, candidate, tasks))
        })
    }
}

fn server_dns_datagram(
    socket: ServerPhysicalUdpSocket,
    target: SocketAddr,
    tasks: DnsTaskRegistrar,
) -> BoxedDnsDatagramIo {
    let (io, mut outgoing_packets, incoming_packets) = ChannelDnsDatagram::bounded(
        NonZeroUsize::new(MAX_DNS_UDP_DATAGRAM_BYTES).expect("non-zero DNS UDP datagram limit"),
    )
    .into_parts();
    let outgoing_queue = tasks.own(DnsEgressResourceKind::Queue);
    let incoming_queue = tasks.own(DnsEgressResourceKind::Queue);
    let buffer = tasks.own(DnsEgressResourceKind::Buffer);
    tasks.spawn(DnsEgressTaskKind::Session, async move {
        let (_outgoing_queue, _incoming_queue, _buffer) = (outgoing_queue, incoming_queue, buffer);
        let mut response = BytesMut::with_capacity(MAX_DNS_UDP_DATAGRAM_BYTES);
        while let Some(packet) = outgoing_packets.recv().await {
            let sent = socket.send_to(&packet, target).await;
            if !matches!(sent, Ok(length) if length == packet.len()) {
                break;
            }
            response.clear();
            let Ok((length, source)) = socket.recv_buf_from(&mut response).await else {
                break;
            };
            if source != target || length > MAX_DNS_UDP_DATAGRAM_BYTES {
                break;
            }
            if incoming_packets
                .send(response[..length].to_vec())
                .await
                .is_err()
            {
                break;
            }
        }
    });
    io
}

#[cfg(test)]
#[path = "dns_egress/tests/mod.rs"]
mod tests;
