use std::collections::HashSet;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use ferrum2_config::{DnsConfig, PreparedClientV2, ValidatedClientConfig};
#[cfg(test)]
use ferrum2_crypto::MethodProfile;
#[cfg(test)]
use ferrum2_crypto::MethodSinglePskProvider;
use ferrum2_crypto::{SecureRandom, SystemClock, SystemRandom};
use ferrum2_dns::{
    ApplicationResolver, ApplicationResolverAdapter, DnsCache, DnsProxySockets, DnsStrategy,
    TaggedResolver,
};
use ferrum2_net::NetworkSnapshot;
use ferrum2_observability::{Metrics, Role, json_subscriber};
use ferrum2_rule::RuleCompileError;
use ferrum2_runtime::{
    BoundedSupervisor, ConnectionRuntimeDispatcher, ConnectionRuntimePool,
    MAX_UDP_MAX_BUFFERED_BYTES, MIN_UDP_IDLE_TIMEOUT, MIN_UDP_MAX_BUFFERED_BYTES, OwnerRegistry,
    ProcessCause, ProcessReport, ProcessRoot, ProcessRootExit, ProcessSupervisor, UdpRuntimeLimits,
    UdpSessionManager,
};
use ferrum2_shadowsocks::MAX_UDP_WIRE_LEN;
#[cfg(test)]
use ferrum2_shadowsocks::MethodKeyAdapter;
use ferrum2_socks5::Socks5Inbound;
#[cfg(feature = "structural-metrics")]
use ferrum2_structural::StructuralHub;

mod egress;

mod context;
mod dns;
#[path = "dns_egress.rs"]
mod dns_egress;
mod materialize;
mod observation;
mod routing;
mod shutdown_diagnostic;
mod socks;
#[path = "run/io.rs"]
mod tokio_io;
#[path = "run/tun/mod.rs"]
mod tun;

use context::{ClientContext, ClientRouting};
use dns::{
    ClientDnsProxyRuntime, ClientDnsRoot, client_direct_resolvers, observed_application_resolver,
};
#[cfg(any(not(windows), test))]
use ferrum2_shadowsocks::tokio::TokioConnector;
use observation::{ClientMetricsRoot, log_level, publish_rule_program_metadata};
use shutdown_diagnostic::{ClientRootName, ClientRootNames, ShutdownDiagnostic};
use socks::{ClientTcpListeners, ClientTcpRoot};
use tokio_io::{bind_listener, shutdown_signal};

#[cfg(test)]
use egress::IdSequenceRandom;
use egress::{
    ClientEgressEngine, ClientUdpContext, prepare_client_outbounds, runtime_route_network,
};

fn initial_network_snapshot() -> Result<Arc<NetworkSnapshot>, RunError> {
    #[cfg(windows)]
    {
        let catalog = ferrum2_platform_windows::WindowsNetworkInterfaceCatalog::system();
        NetworkSnapshot::capture(1, &catalog)
            .map(Arc::new)
            .map_err(|_| RunError::StartupProtocol)
    }
    #[cfg(not(windows))]
    {
        NetworkSnapshot::new(1, None, None)
            .map(Arc::new)
            .map_err(|_| RunError::StartupProtocol)
    }
}

#[cfg(all(windows, not(test)))]
fn client_network_runtime(
    network_generation: ferrum2_config::NetworkGenerationMode,
    registry: OwnerRegistry,
    metrics: Arc<Metrics>,
) -> Result<
    (
        ferrum2_runtime::NetworkResetCoordinator,
        ferrum2_platform_windows::WindowsNetworkInterfaceCatalog,
        Arc<egress::ClientNetworkSocketService>,
    ),
    RunError,
> {
    let catalog = ferrum2_platform_windows::WindowsNetworkInterfaceCatalog::system();
    let snapshot = NetworkSnapshot::capture(1, &catalog)
        .map(Arc::new)
        .map_err(|_| RunError::StartupProtocol)?;
    let coordinator = tun::network_reset_coordinator(snapshot, registry);
    metrics.set_network_generation(coordinator.status().published_generation());
    let mode = match network_generation {
        ferrum2_config::NetworkGenerationMode::Dynamic => {
            ferrum2_runtime::NetworkSocketMode::Dynamic
        }
        ferrum2_config::NetworkGenerationMode::Static => ferrum2_runtime::NetworkSocketMode::Static,
    };
    let service = Arc::new(egress::ClientNetworkSocketService::new(
        mode,
        coordinator.clone(),
        catalog.clone(),
        metrics,
    ));
    Ok((coordinator, catalog, service))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RunError {
    StartupObservability,
    StartupRuntime,
    StartupBind,
    StartupProtocol,
    ConfigResourceMaterialization,
    DnsResolve,
    RuleCompile,
    RuleAllocation,
    RuleSetDownload,
    RuleSetCache,
    RuleSetFormat,
    RuleSetUnsupportedMatcher,
    RuleSetCompile,
    RuntimeListener,
    RuntimeChild,
    RuntimeRoot,
    ShutdownCleanup,
}

fn dns_only_udp_buffered_bytes(max_inflight: usize) -> Result<usize, RunError> {
    // A DNS UDP query routed through a multi-hop detour can keep two
    // association wires live while response materialization additionally owns
    // one MAX_UDP_WIRE_LEN-bounded AccountedDatagram. The DNS admission
    // semaphore caps all three populations at max_inflight.
    let fixed_wires = max_inflight
        .checked_mul(2)
        .and_then(|count| count.checked_mul(MAX_UDP_WIRE_LEN))
        .ok_or(RunError::StartupProtocol)?;
    let response_headroom = max_inflight
        .checked_mul(MAX_UDP_WIRE_LEN)
        .ok_or(RunError::StartupProtocol)?;
    let required = fixed_wires
        .checked_add(response_headroom)
        .filter(|required| *required <= MAX_UDP_MAX_BUFFERED_BYTES)
        .ok_or(RunError::StartupProtocol)?;
    Ok(required.max(MIN_UDP_MAX_BUFFERED_BYTES))
}

impl std::fmt::Display for RunError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::StartupObservability => {
                "error[startup.observability] process: unable to initialize diagnostics"
            }
            Self::StartupRuntime => {
                "error[startup.runtime] process: unable to create asynchronous runtime"
            }
            Self::StartupBind => "error[startup.bind] process: unable to prepare required endpoint",
            Self::StartupProtocol => {
                "error[startup.protocol] process: unable to prepare protocol resources"
            }
            Self::ConfigResourceMaterialization => {
                "error[config.resource_materialization] configuration: supplied resources are invalid"
            }
            Self::DnsResolve => {
                "error[dns.resolve] materialization: fixed endpoint resolution failed"
            }
            Self::RuleCompile => {
                "error[rule.compile] materialization: rule compilation failed"
            }
            Self::RuleAllocation => {
                "error[rule.allocation] materialization: rule allocation failed"
            }
            Self::RuleSetDownload => {
                "error[ruleset.download] materialization: RuleSet download failed"
            }
            Self::RuleSetCache => {
                "error[ruleset.cache] materialization: RuleSet cache failed"
            }
            Self::RuleSetFormat => {
                "error[ruleset.format] materialization: RuleSet format is invalid"
            }
            Self::RuleSetUnsupportedMatcher => {
                "error[ruleset.unsupported_matcher] materialization: RuleSet matcher is unsupported"
            }
            Self::RuleSetCompile => {
                "error[ruleset.compile] materialization: RuleSet compilation failed"
            }
            Self::RuntimeListener => "error[runtime.listener] process: required listener failed",
            Self::RuntimeChild => "error[runtime.child] process: required child failed",
            Self::RuntimeRoot => "error[runtime.root] process: required root stopped",
            Self::ShutdownCleanup => {
                "error[shutdown.cleanup] process: unable to reap all process owners"
            }
        })
    }
}

impl RunError {
    const fn diagnostic_category(self) -> &'static str {
        match self {
            Self::StartupObservability => "startup.observability",
            Self::StartupRuntime => "startup.runtime",
            Self::StartupBind => "startup.bind",
            Self::StartupProtocol => "startup.protocol",
            Self::ConfigResourceMaterialization => "config.resource_materialization",
            Self::DnsResolve => "dns.resolve",
            Self::RuleCompile => "rule.compile",
            Self::RuleAllocation => "rule.allocation",
            Self::RuleSetDownload => "ruleset.download",
            Self::RuleSetCache => "ruleset.cache",
            Self::RuleSetFormat => "ruleset.format",
            Self::RuleSetUnsupportedMatcher => "ruleset.unsupported_matcher",
            Self::RuleSetCompile => "ruleset.compile",
            Self::RuntimeListener => "runtime.listener",
            Self::RuntimeChild => "runtime.child",
            Self::RuntimeRoot => "runtime.root",
            Self::ShutdownCleanup => "shutdown.cleanup",
        }
    }
}

/// Classifies rule scratch construction failures after configuration has
/// already passed semantic validation. Allocation and index-capacity failures
/// retain their operator-visible category; every other closed compiler failure
/// is an internal compilation failure at this production boundary.
const fn run_error_for_rule_compile(error: RuleCompileError) -> RunError {
    match error {
        RuleCompileError::Allocation | RuleCompileError::IndexOverflow => RunError::RuleAllocation,
        RuleCompileError::EmptyMatcher
        | RuleCompileError::EmptyField
        | RuleCompileError::DuplicateField
        | RuleCompileError::DuplicateValue
        | RuleCompileError::ConflictingFields
        | RuleCompileError::InvalidDomain
        | RuleCompileError::NonCanonicalCidr
        | RuleCompileError::InvalidId
        | RuleCompileError::InvalidTag
        | RuleCompileError::DuplicateRuleSet
        | RuleCompileError::InvalidGeneration
        | RuleCompileError::Internal => RunError::RuleCompile,
    }
}

#[derive(Debug, Default)]
struct ClientProcessRoots {
    roots: Vec<ProcessRoot<RunError>>,
    names: Vec<ClientRootName>,
}

impl ClientProcessRoots {
    fn push(&mut self, name: ClientRootName, root: ProcessRoot<RunError>) {
        self.names.push(name);
        self.roots.push(root);
    }

    fn into_parts(self) -> (Vec<ProcessRoot<RunError>>, ClientRootNames) {
        debug_assert_eq!(self.roots.len(), self.names.len());
        (self.roots, ClientRootNames::new(self.names))
    }
}

fn build_run_runtime(connection_sharded: bool) -> Result<tokio::runtime::Runtime, RunError> {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    if connection_sharded {
        // Connection work runs on dedicated shards; one control worker avoids
        // duplicating the host CPU count with otherwise idle scheduler workers.
        builder.worker_threads(1);
    }
    builder
        .enable_all()
        .build()
        .map_err(|_| RunError::StartupRuntime)
}

/// Fully materializes a prepared schema-v2 client before any listener or TUN
/// root is allowed to prepare. The returned process owns the bootstrap DNS,
/// RuleSet refresh, and egress bridge lifecycle for its entire run.
pub(crate) fn run_prepared(prepared: PreparedClientV2) -> Result<(), RunError> {
    // Keep managed TUN and public UDP on their existing runtime path. The direct
    // TCP profile instead assigns each accepted SOCKS connection to one stable
    // current-thread shard while retaining cross-connection parallelism.
    let connection_runtimes = if prepared.has_tun() || prepared.udp().is_some_and(|udp| udp.enabled)
    {
        None
    } else {
        Some(
            ConnectionRuntimePool::new(tcp_connection_shard_count(usize::from(
                prepared.runtime().max_connections.get(),
            )))
            .map_err(|_| RunError::StartupRuntime)?,
        )
    };
    let connection_runtime = connection_runtimes
        .as_ref()
        .map(ConnectionRuntimePool::dispatcher);
    let runtime = build_run_runtime(connection_runtimes.is_some())?;
    let result = runtime.block_on(async move {
        let metrics = Arc::new(Metrics::new());
        let registry = OwnerRegistry::new();
        #[cfg(all(windows, not(test)))]
        let network_generation = prepared.runtime().network_generation;
        #[cfg(all(windows, not(test)))]
        let mut network_change_monitor = if prepared.has_tun()
            || network_generation == ferrum2_config::NetworkGenerationMode::Static
        {
            None
        } else {
            Some(
                ferrum2_platform_windows::WindowsNetworkChangeMonitor::new()
                    .map_err(|_| RunError::StartupRuntime)?,
            )
        };
        #[cfg(all(windows, not(test)))]
        let (network_reset_coordinator, network_interface_catalog, network_socket_service) =
            match client_network_runtime(network_generation, registry.clone(), Arc::clone(&metrics))
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    if let Some(monitor) = network_change_monitor.take() {
                        monitor.close().map_err(|_| RunError::ShutdownCleanup)?;
                    }
                    return Err(error);
                }
            };
        #[cfg(not(all(windows, not(test))))]
        let network_reset_coordinator =
            tun::network_reset_coordinator(initial_network_snapshot()?, registry.clone());
        let underlay = ferrum2_tun::UnderlayPublisher::new();
        let materializer = materialize::ClientV2Materializer::new(
            Arc::clone(&metrics),
            #[cfg(all(windows, not(test)))]
            Arc::clone(&network_socket_service),
        );
        let materialized = match materializer.materialize(prepared).await {
            Ok(materialized) => materialized,
            Err(error) => {
                #[cfg(all(windows, not(test)))]
                if let Some(monitor) = network_change_monitor.take() {
                    monitor.close().map_err(|_| RunError::ShutdownCleanup)?;
                }
                return Err(error);
            }
        };
        let subscriber = json_subscriber(
            std::io::stderr,
            log_level(materialized.config().logging.level),
        );
        if tracing::subscriber::set_global_default(subscriber).is_err() {
            let materialized_cleanup = materialized.validate_only();
            #[cfg(all(windows, not(test)))]
            let network_cleanup = match network_change_monitor.take() {
                Some(monitor) => monitor.close().map_err(|_| RunError::ShutdownCleanup),
                None => Ok(()),
            };
            materialized_cleanup?;
            #[cfg(all(windows, not(test)))]
            network_cleanup?;
            return Err(RunError::StartupObservability);
        }
        let materialize::MaterializedRunParts {
            config,
            materialization_root,
            cache: materialized_cache,
        } = match materialized.into_run_parts().await {
            Ok(parts) => parts,
            Err(error) => {
                #[cfg(all(windows, not(test)))]
                if let Some(monitor) = network_change_monitor.take() {
                    monitor.close().map_err(|_| RunError::ShutdownCleanup)?;
                }
                return Err(error);
            }
        };
        let dns_specs = config
            .dns
            .as_ref()
            .map(|dns| dns_egress::dns_runtime_specs(&dns.servers));
        run_with_registry_and_metrics_inner(
            config,
            registry,
            shutdown_signal(),
            metrics,
            None,
            #[cfg(test)]
            None,
            ClientRunResources {
                materialization_root,
                materialized_cache,
                materialized_underlay: Some(underlay),
                dns_specs,
                network_reset_coordinator: Some(network_reset_coordinator),
                #[cfg(all(windows, not(test)))]
                network_interface_catalog: Some(network_interface_catalog),
                #[cfg(all(windows, not(test)))]
                network_socket_service: Some(network_socket_service),
                #[cfg(all(windows, not(test)))]
                network_change_monitor,
                tcp_connection_runtime: connection_runtime,
            },
        )
        .await
    });
    drop(runtime);
    drop(connection_runtimes);
    result
}

fn tcp_connection_shard_count(max_connections: usize) -> NonZeroUsize {
    let available = std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN);
    NonZeroUsize::new(available.get().min(max_connections))
        .expect("validated connection limit is non-zero")
}

/// Performs the opt-in networked validation pass, then explicitly joins every
/// bootstrap owner without constructing a listener, TUN, or refresh root.
pub(crate) fn validate_prepared_materialization(
    prepared: PreparedClientV2,
) -> Result<(), RunError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| RunError::StartupRuntime)?;
    runtime.block_on(async move {
        let metrics = Arc::new(Metrics::new());
        #[cfg(all(windows, not(test)))]
        let network_socket_service = {
            let registry = OwnerRegistry::new();
            let (_, _, service) = client_network_runtime(
                prepared.runtime().network_generation,
                registry,
                Arc::clone(&metrics),
            )?;
            service
        };
        let materializer = materialize::ClientV2Materializer::new(
            metrics,
            #[cfg(all(windows, not(test)))]
            network_socket_service,
        );
        let materialized = materializer.materialize(prepared).await?;
        materialized.validate_only().map(|_| ())
    })
}

struct ClientRunResources {
    materialization_root: Option<materialize::ClientV2RuntimeRoot>,
    materialized_cache: Option<DnsCache>,
    materialized_underlay: Option<ferrum2_tun::UnderlayPublisher>,
    dns_specs: Option<Vec<ferrum2_dns::DnsUpstreamSpec>>,
    network_reset_coordinator: Option<ferrum2_runtime::NetworkResetCoordinator>,
    #[cfg(all(windows, not(test)))]
    network_interface_catalog: Option<ferrum2_platform_windows::WindowsNetworkInterfaceCatalog>,
    #[cfg(all(windows, not(test)))]
    network_socket_service: Option<Arc<egress::ClientNetworkSocketService>>,
    #[cfg(all(windows, not(test)))]
    network_change_monitor: Option<ferrum2_platform_windows::WindowsNetworkChangeMonitor>,
    tcp_connection_runtime: Option<ConnectionRuntimeDispatcher>,
}

impl ClientRunResources {
    #[cfg(test)]
    const fn test_unmaterialized(dns_specs: Option<Vec<ferrum2_dns::DnsUpstreamSpec>>) -> Self {
        Self {
            materialization_root: None,
            materialized_cache: None,
            materialized_underlay: None,
            dns_specs,
            network_reset_coordinator: None,
            #[cfg(all(windows, not(test)))]
            network_interface_catalog: None,
            #[cfg(all(windows, not(test)))]
            network_socket_service: None,
            #[cfg(all(windows, not(test)))]
            network_change_monitor: None,
            tcp_connection_runtime: None,
        }
    }
}

#[cfg(test)]
async fn run_with_registry<S>(
    config: ValidatedClientConfig,
    registry: OwnerRegistry,
    shutdown: S,
) -> Result<(), RunError>
where
    S: std::future::Future<Output = ()> + Send,
{
    run_with_registry_and_metrics(config, registry, shutdown, Arc::new(Metrics::new())).await
}

#[cfg(test)]
async fn run_with_registry_and_metrics<S>(
    config: ValidatedClientConfig,
    registry: OwnerRegistry,
    shutdown: S,
    metrics: Arc<Metrics>,
) -> Result<(), RunError>
where
    S: std::future::Future<Output = ()> + Send,
{
    let dns_specs = config
        .dns
        .as_ref()
        .map(|dns| dns_egress::dns_runtime_specs(&dns.servers));
    run_with_registry_and_metrics_inner(
        config,
        registry,
        shutdown,
        metrics,
        None,
        #[cfg(test)]
        None,
        ClientRunResources::test_unmaterialized(dns_specs),
    )
    .await
}

async fn run_with_registry_and_metrics_inner<S>(
    config: ValidatedClientConfig,
    registry: OwnerRegistry,
    shutdown: S,
    metrics: Arc<Metrics>,
    _udp_id_random: Option<Arc<dyn SecureRandom>>,
    #[cfg(test)] mut dns_observer: Option<
        tokio::sync::oneshot::Sender<(Arc<ClientContext>, Arc<TaggedResolver>)>,
    >,
    resources: ClientRunResources,
) -> Result<(), RunError>
where
    S: std::future::Future<Output = ()> + Send,
{
    #[cfg(feature = "structural-metrics")]
    let structural = StructuralHub::new();
    let ClientRunResources {
        mut materialization_root,
        materialized_cache,
        materialized_underlay,
        dns_specs,
        network_reset_coordinator,
        #[cfg(all(windows, not(test)))]
        network_interface_catalog,
        #[cfg(all(windows, not(test)))]
        network_socket_service,
        #[cfg(all(windows, not(test)))]
        mut network_change_monitor,
        tcp_connection_runtime,
    } = resources;
    let network_reset_coordinator = match network_reset_coordinator {
        Some(coordinator) => coordinator,
        None => tun::network_reset_coordinator(initial_network_snapshot()?, registry.clone()),
    };
    #[cfg(all(windows, not(test)))]
    let network_interface_catalog = match network_interface_catalog {
        Some(catalog) => catalog,
        None => {
            if let Some(monitor) = network_change_monitor.take() {
                monitor.close().map_err(|_| RunError::ShutdownCleanup)?;
            }
            return Err(RunError::StartupProtocol);
        }
    };
    #[cfg(all(windows, not(test)))]
    let network_socket_service = match network_socket_service {
        Some(service) => service,
        None => {
            if let Some(monitor) = network_change_monitor.take() {
                monitor.close().map_err(|_| RunError::ShutdownCleanup)?;
            }
            return Err(RunError::StartupProtocol);
        }
    };
    #[cfg(any(not(windows), test))]
    let network_interface_catalog =
        ferrum2_platform_windows::WindowsNetworkInterfaceCatalog::system();
    let result = async {
        publish_rule_program_metadata(&config, &metrics);
        #[cfg(all(windows, not(test)))]
        let network_generation = config.runtime.network_generation;
        let selector = config.selector_control();
        let tun_config = config.tun;
        let tun_direct = tun_config.is_some()
            && config.outbounds.iter().any(|outbound| {
                matches!(
                    outbound,
                    ferrum2_config::ClientOutboundConfig::Direct { .. }
                )
            });
        let underlay = materialized_underlay.unwrap_or_default();
        let mut dns = match (config.dns, config.dns_route, dns_specs) {
            (
                Some(DnsConfig {
                    inbounds,
                    servers,
                    timeout,
                    max_inflight,
                    runtime,
                }),
                Some(policy),
                Some(specs),
            ) => {
                let internal_udp_needed = servers
                    .iter()
                    .any(|server| server.transport == ferrum2_config::DnsTransport::Udp);
                Some((
                    inbounds,
                    specs,
                    policy,
                    timeout,
                    max_inflight,
                    runtime,
                    internal_udp_needed,
                ))
            }
            (None, None, None) => None,
            _ => return Err(RunError::StartupProtocol),
        };
        let dns_proxy_runtime = dns
            .as_mut()
            .map(|dns| {
                ClientDnsProxyRuntime::try_new(&mut dns.2, dns.5, materialized_cache, &metrics)
            })
            .transpose()?;
        let ordinary_dns = dns.as_ref().map(|_| Arc::new(std::sync::OnceLock::new()));
        let tagged_dns = Arc::new(std::sync::OnceLock::new());
        let application_resolver = ApplicationResolver::system_default();
        let application_resolver = ApplicationResolverAdapter::new(
            Arc::new(observed_application_resolver(
                application_resolver,
                &metrics,
            )),
            0,
            DnsStrategy::PreferIpv4,
        );
        let direct_resolvers =
            client_direct_resolvers(&config.outbounds, Arc::clone(&tagged_dns), &metrics);
        metrics.set_udp_sessions_active(Role::Client, 0);
        metrics.set_udp_buffered_bytes(Role::Client, 0);
        let configured_udp = config.udp;
        let public_udp_enabled = configured_udp.is_some_and(|udp| udp.enabled);
        let public_udp_slots = configured_udp
            .filter(|udp| udp.enabled)
            .map(|udp| Arc::new(tokio::sync::Semaphore::new(udp.max_sessions)));
        let tun_udp_defaults = tun_config.as_ref().map(|_| {
            let defaults = UdpRuntimeLimits::default();
            (
                defaults.max_sessions(),
                defaults.max_buffered_bytes(),
                defaults.idle_timeout(),
            )
        });
        let internal_udp_needed =
            dns.as_ref().is_some_and(|dns| dns.6) || tun_udp_defaults.is_some();
        let udp_limits = if let Some(udp) = configured_udp {
            Some((udp.max_sessions, udp.max_buffered_bytes, udp.idle_timeout))
        } else if let Some(defaults) = tun_udp_defaults {
            Some(defaults)
        } else if let Some(dns) = dns.as_ref().filter(|dns| dns.6) {
            let sessions = usize::from(dns.4.get());
            let bytes = dns_only_udp_buffered_bytes(sessions)?;
            Some((sessions, bytes, dns.3.max(MIN_UDP_IDLE_TIMEOUT)))
        } else {
            None
        };
        let tun_udp_idle_timeout = tun_config
            .as_ref()
            .map(|_| udp_limits.expect("TUN UDP requires internal limits").2);
        let runtime = config.runtime;
        let outbounds = prepare_client_outbounds(config.outbounds)?;
        let shutdown_grace = config.runtime.shutdown_grace;
        let listen_backlog = u32::from(config.runtime.listen_backlog.get());
        let max_connections = usize::from(config.runtime.max_connections.get());
        let udp = if public_udp_enabled || internal_udp_needed {
            let (max_sessions, max_buffered_bytes, idle_timeout) =
                udp_limits.expect("enabled UDP requires validated limits");
            Some(ClientUdpContext {
                manager: UdpSessionManager::new(
                    UdpRuntimeLimits::new(max_sessions, max_buffered_bytes, idle_timeout)
                        .map_err(|_| RunError::StartupProtocol)?,
                    registry.clone(),
                ),
                live_ids: Arc::new(std::sync::Mutex::new(HashSet::new())),
            })
        } else {
            None
        };
        #[cfg(all(windows, not(test)))]
        let connector = egress::NetworkServiceConnector::new(Arc::clone(&network_socket_service));
        #[cfg(any(not(windows), test))]
        let connector =
            TokioConnector::new(ferrum2_runtime::TcpConnector::with_resolution_adapters(
                ferrum2_runtime::SystemSocketInspector,
                ferrum2_runtime::SystemTcpDialer,
                application_resolver.clone(),
                config.runtime.connect_timeout,
            ));
        let egress = ClientEgressEngine::new_with_direct_resolvers(
            Arc::clone(&outbounds),
            connector,
            SystemClock::new(),
            SystemRandom,
            (
                config.runtime.connect_timeout,
                config.runtime.handshake_timeout,
            ),
            udp,
            application_resolver,
            direct_resolvers,
            #[cfg(test)]
            _udp_id_random,
        )
        .with_route_network(runtime_route_network(&config.route_network));
        #[cfg(feature = "structural-metrics")]
        let egress = egress.with_structural(structural.local());
        #[cfg(all(windows, not(test)))]
        let egress = if network_generation == ferrum2_config::NetworkGenerationMode::Dynamic {
            egress.with_shared_network_reset(&network_socket_service)?
        } else {
            egress
        };
        let egress = Arc::new(egress);
        let context = Arc::new(ClientContext {
            inbound: Socks5Inbound::new(),
            egress: Arc::clone(&egress),
            #[cfg(test)]
            keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(
                test_support::default_test_psk(),
            )),
            runtime: config.runtime,
            public_udp_slots,
            registry: registry.clone(),
            metrics: Arc::clone(&metrics),
            #[cfg(feature = "structural-metrics")]
            structural: structural.local(),
            dns: ordinary_dns.as_ref().map(Arc::clone),
        });
        let mut listens = Vec::with_capacity(config.inbounds.len());
        let tun_inbound = config.inbounds.len();
        let routing = Arc::new(ClientRouting {
            program: config.route,
            outbounds,
            selector,
        });
        // Probe caller-owned route scratch before any listener is prepared so
        // an allocation/capacity failure has a stable process-level category.
        let _ = routing
            .route_scratch()
            .map_err(run_error_for_rule_compile)?;
        #[cfg(test)]
        let dns_context = Arc::clone(&context);
        let dns_egress = Arc::clone(&egress);
        for inbound in &config.inbounds {
            listens.push(inbound.listen);
        }
        let tcp_registry = registry.clone();
        let tcp_context = Arc::clone(&context);
        let tcp_routing = Arc::clone(&routing);
        let mut roots = ClientProcessRoots::default();
        #[cfg(all(windows, not(test)))]
        if tun_config.is_none()
            && network_generation == ferrum2_config::NetworkGenerationMode::Dynamic
        {
            let monitor = network_change_monitor
                .take()
                .ok_or(RunError::StartupProtocol)?;
            roots.push(
                ClientRootName::Network,
                tun::network_change_process_root(
                    Arc::clone(&context),
                    network_reset_coordinator.clone(),
                    network_interface_catalog.clone(),
                    monitor,
                ),
            );
        }
        if let Some(prepared) = materialization_root.take() {
            roots.push(
                ClientRootName::Bootstrap,
                ProcessRoot::new(move || async move { Ok(prepared) }),
            );
        }
        if !listens.is_empty() {
            roots.push(
                ClientRootName::Socks,
                ProcessRoot::new(move || async move {
                    let mut listeners = Vec::with_capacity(listens.len());
                    for listen in listens {
                        listeners.push(bind_listener(listen, listen_backlog)?);
                    }
                    let listeners = ClientTcpListeners {
                        listeners,
                        next: AtomicUsize::new(0),
                        #[cfg(test)]
                        accept_errors: None,
                    };
                    let reregister_accepted_stream = tcp_connection_runtime.is_some();
                    let supervisor = match tcp_connection_runtime {
                        Some(connection_runtime) => BoundedSupervisor::new_on_connection_runtime(
                            listeners,
                            max_connections,
                            shutdown_grace,
                            tcp_registry,
                            connection_runtime,
                        ),
                        None => BoundedSupervisor::new(
                            listeners,
                            max_connections,
                            shutdown_grace,
                            tcp_registry,
                        ),
                    }
                    .map_err(|_| RunError::StartupProtocol)?;
                    Ok(ClientTcpRoot {
                        supervisor: Some(supervisor),
                        context: tcp_context,
                        routing: tcp_routing,
                        reregister_accepted_stream,
                    })
                }),
            );
        }
        if let Some((inbounds, servers, _policy, timeout, max_inflight, _, _)) = dns {
            let ordinary_dns = ordinary_dns.expect("validated DNS graph has an ordinary handle");
            let tagged_dns = Arc::clone(&tagged_dns);
            let addresses = inbounds.into_iter().map(|inbound| inbound.listen).collect();
            roots.push(
                ClientRootName::Dns,
                ProcessRoot::new(move || async move {
                    let sockets = DnsProxySockets::bind(
                        addresses,
                        listen_backlog,
                        runtime.max_connections,
                        runtime.idle_timeout,
                    )
                    .await
                    .map_err(|_| RunError::StartupBind)?;
                    let egress = Arc::new(
                        dns_egress::ClientDnsEgress::new(Arc::clone(&dns_egress))
                            .map_err(|()| RunError::StartupProtocol)?,
                    );
                    let (resolver, owner) =
                        TaggedResolver::new(servers, timeout, max_inflight, egress)
                            .map_err(|_| RunError::StartupProtocol)?;
                    let resolver = Arc::new(resolver);
                    tagged_dns
                        .set(Arc::downgrade(&resolver))
                        .map_err(|_| RunError::StartupProtocol)?;
                    #[cfg(test)]
                    if let Some(observer) = dns_observer.take() {
                        let _ = observer.send((Arc::clone(&dns_context), Arc::clone(&resolver)));
                    }
                    let proxy = dns_proxy_runtime
                        .ok_or(RunError::StartupProtocol)?
                        .bind(Arc::clone(&resolver));
                    let proxy = Arc::new(proxy);
                    ordinary_dns
                        .set(Arc::clone(&proxy))
                        .map_err(|_| RunError::StartupProtocol)?;
                    Ok(ClientDnsRoot {
                        listeners: Some(sockets.with_proxy(proxy)),
                        resolver: Some(resolver),
                        owner: Some(owner),
                        #[cfg(test)]
                        readiness_gate: None,
                    })
                }),
            );
        }
        if let Some(metrics_config) = config.metrics {
            let metrics_registry = registry.clone();
            #[cfg(feature = "structural-metrics")]
            let metrics_structural = structural.clone();
            roots.push(
                ClientRootName::Metrics,
                ProcessRoot::new(move || async move {
                    let listener = bind_listener(metrics_config.listen, 16)?;
                    Ok(ClientMetricsRoot {
                        listener: Some(listener),
                        metrics,
                        registry: metrics_registry,
                        #[cfg(feature = "structural-metrics")]
                        structural: metrics_structural,
                    })
                }),
            );
        }
        if let Some(tun_config) = tun_config {
            roots.push(
                ClientRootName::Tun,
                tun::process_root(
                    tun_config,
                    tun_udp_idle_timeout.expect("TUN UDP idle retained"),
                    Arc::clone(&context),
                    routing,
                    tun_inbound,
                    tun::TunNetworkServices {
                        coordinator: network_reset_coordinator,
                        underlay,
                        network_interface_catalog,
                    },
                    tun_direct,
                ),
            );
        }
        let (roots, root_names) = roots.into_parts();
        let owner_baseline = registry.snapshot();
        let supervisor = ProcessSupervisor::new(roots, shutdown_grace, registry.clone())
            .map_err(|_| RunError::StartupProtocol)?;
        let report = supervisor.run_until(shutdown).await;
        let owner_stopped = registry.snapshot();
        let diagnostic = ShutdownDiagnostic::classify(
            &report,
            &root_names,
            shutdown_grace,
            owner_baseline,
            owner_stopped,
        );
        // This record is closed over client enums, monotonic durations, and owner
        // counters: no config, addresses, payloads, keys, or error text can enter it.
        // Diagnostics must never replace the process result when stderr is closed.
        let mut stderr = std::io::stderr().lock();
        let _ = std::io::Write::write_fmt(&mut stderr, format_args!("{diagnostic}\n"));
        report_result(report)
    }
    .await;
    #[cfg(all(windows, not(test)))]
    let result = match network_change_monitor {
        Some(monitor) => result.and(monitor.close().map_err(|_| RunError::ShutdownCleanup)),
        None => result,
    };
    if let Some(mut root) = materialization_root {
        let cleanup = root.cleanup().await;
        return result.and(cleanup);
    }
    result
}

const fn dns_strategy(strategy: ferrum2_config::DnsStrategy) -> DnsStrategy {
    match strategy {
        ferrum2_config::DnsStrategy::PreferIpv4 => DnsStrategy::PreferIpv4,
        ferrum2_config::DnsStrategy::PreferIpv6 => DnsStrategy::PreferIpv6,
        ferrum2_config::DnsStrategy::Ipv4Only => DnsStrategy::Ipv4Only,
        ferrum2_config::DnsStrategy::Ipv6Only => DnsStrategy::Ipv6Only,
    }
}

fn report_result(report: ProcessReport<RunError>) -> Result<(), RunError> {
    if report.cleanup_failure().is_some() {
        return Err(RunError::ShutdownCleanup);
    }
    match report.cause() {
        ProcessCause::ExternalShutdown => Ok(()),
        ProcessCause::PreparationFailed { error, .. }
        | ProcessCause::ActivationFailed { error, .. } => Err(*error),
        ProcessCause::PreparationPanicked { .. } | ProcessCause::ActivationPanicked { .. } => {
            Err(RunError::StartupProtocol)
        }
        ProcessCause::RootStopped { exit, .. } => match exit {
            ProcessRootExit::Failed(error) => Err(*error),
            ProcessRootExit::Panicked | ProcessRootExit::JoinFailed => Err(RunError::RuntimeChild),
            ProcessRootExit::Completed => Err(RunError::RuntimeRoot),
        },
    }
}

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;

#[cfg(test)]
mod runtime_build_tests {
    use super::*;

    #[test]
    fn connection_shards_use_one_multi_thread_control_worker() {
        let runtime = build_run_runtime(true).expect("run runtime");
        assert_eq!(
            runtime.handle().runtime_flavor(),
            tokio::runtime::RuntimeFlavor::MultiThread
        );
        assert_eq!(runtime.metrics().num_workers(), 1);
    }

    #[test]
    fn unsharded_runtime_keeps_the_existing_multi_thread_builder() {
        let runtime = build_run_runtime(false).expect("run runtime");
        assert_eq!(
            runtime.handle().runtime_flavor(),
            tokio::runtime::RuntimeFlavor::MultiThread
        );
        assert!(runtime.metrics().num_workers() >= 1);
    }
}
