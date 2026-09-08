use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use ferrum2_config::{DnsConfig, PreparedClientV2, ValidatedClientConfig};
#[cfg(test)]
use ferrum2_crypto::MethodProfile;
#[cfg(test)]
use ferrum2_crypto::MethodSinglePskProvider;
#[cfg(test)]
use ferrum2_crypto::SecureRandom;
use ferrum2_crypto::{SystemClock, SystemRandom};
use ferrum2_dns::{
    ApplicationResolver, ApplicationResolverAdapter, DnsCache, DnsProxySockets, DnsStrategy,
    TaggedResolver,
};
#[cfg(any(not(windows), test))]
use ferrum2_net::NetworkSnapshot;
use ferrum2_observability::{Metrics, Role, json_subscriber};
use ferrum2_runtime::{
    AffineConnectionExecutor, MAX_UDP_MAX_BUFFERED_BYTES, MIN_UDP_IDLE_TIMEOUT,
    MIN_UDP_MAX_BUFFERED_BYTES, OwnerRegistry, ProcessCause, ProcessReport, ProcessRoot,
    ProcessRootExit, ProcessSupervisor, UdpRuntimeLimits, UdpSessionManager,
};
use ferrum2_shadowsocks::MAX_UDP_WIRE_LEN;
#[cfg(test)]
use ferrum2_shadowsocks::MethodKeyAdapter;
use ferrum2_socks5::Socks5Inbound;

mod egress;

mod context;
pub(crate) mod dashboard_control;
mod dns;
#[path = "dns_egress.rs"]
mod dns_egress;
mod error;
mod generation;
pub(crate) mod management;
mod materialize;
#[cfg(all(windows, not(test)))]
mod network_owner;
#[cfg(any(windows, test))]
mod network_wait;
mod observation;
mod routing;
mod shutdown_diagnostic;
mod socks;
#[path = "run/io.rs"]
mod tokio_io;
#[path = "run/tun/mod.rs"]
mod tun;
pub(crate) use error::RunError;
use error::run_error_for_rule_compile;
pub(crate) use generation::{run_generation, run_prepared};

use context::{ClientContext, ClientRouting};
use dns::{
    ClientDnsProxyRuntime, ClientDnsRoot, client_direct_resolvers, observed_application_resolver,
};
#[cfg(any(not(windows), test))]
use ferrum2_shadowsocks::tokio::TokioConnector;
use observation::{ClientMetricsRoot, log_level, publish_rule_program_metadata};
use shutdown_diagnostic::{ClientRootName, ClientRootNames, ShutdownDiagnostic};
use socks::{ClientTcpListeners, ClientTcpRoot};
use tokio_io::bind_listener;
pub(crate) use tokio_io::shutdown_signal;

#[cfg(test)]
use egress::IdSequenceRandom;
use egress::{
    ClientEgressEngine, ClientUdpContext, prepare_client_outbounds, runtime_route_network,
};

#[cfg(any(not(windows), test))]
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
        let (system, mut system_owner) = ferrum2_dns::SystemResolution::start(
            prepared.dns_max_inflight().unwrap_or_else(|| {
                std::num::NonZeroU16::new(prepared.runtime().max_connections.get().min(4096))
                    .expect("validated positive connection limit")
            }),
            prepared.runtime().connect_timeout,
        )
        .map_err(|_| RunError::StartupRuntime)?;
        let result = async {
            let metrics = Arc::new(Metrics::new());
            #[cfg(all(windows, not(test)))]
            let mut network = network_owner::ClientNetworkRuntime::prepare(
                OwnerRegistry::new(),
                Arc::clone(&metrics),
                None,
            )?;
            let result = async {
                let materializer = materialize::ClientV2Materializer::new(
                    system.clone(),
                    metrics,
                    #[cfg(all(windows, not(test)))]
                    Arc::clone(&network.sockets),
                );
                let materialized = materializer.materialize(prepared).await?;
                materialized.validate_only().map(|_| ())
            }
            .await;
            #[cfg(all(windows, not(test)))]
            network.shutdown().await?;
            result
        }
        .await;
        system_owner
            .shutdown()
            .await
            .map_err(|_| RunError::ShutdownCleanup)?;
        result
    })
}

struct ClientNetworkResources {
    process: ferrum2_runtime::ProcessResources<RunError>,
    coordinator: ferrum2_runtime::NetworkResetCoordinator,
    catalog: ferrum2_platform_windows::WindowsNetworkInterfaceCatalog,
    #[cfg(all(windows, not(test)))]
    sockets: Arc<egress::ClientNetworkSocketService>,
    #[cfg(all(windows, not(test)))]
    change_monitor: Option<network_wait::NativeNetworkChangeWait>,
}

impl ClientNetworkResources {
    #[cfg(any(not(windows), test))]
    fn prepare(registry: &OwnerRegistry) -> Result<Self, RunError> {
        // Capture before bootstrap or process roots can acquire owners.
        let baseline = registry.snapshot();
        let catalog = ferrum2_platform_windows::WindowsNetworkInterfaceCatalog::system();
        let coordinator =
            tun::network_reset_coordinator(initial_network_snapshot()?, registry.clone());
        Ok(Self {
            process: ferrum2_runtime::ProcessResources {
                baseline,
                cleanup: Box::pin(async { Ok(()) }),
            },
            coordinator,
            catalog,
        })
    }
}

struct ClientRunResources {
    management: Option<management::Management>,
    network: ClientNetworkResources,
    materialization_root: Option<materialize::ClientV2RuntimeRoot>,
    materialized_cache: Option<DnsCache>,
    underlay: ferrum2_tun::UnderlayPublisher,
}

impl ClientRunResources {
    fn new(network: ClientNetworkResources) -> Self {
        Self {
            management: None,
            network,
            materialization_root: None,
            materialized_cache: None,
            underlay: ferrum2_tun::UnderlayPublisher::new(),
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
    let resources = ClientRunResources::new(ClientNetworkResources::prepare(&registry)?);
    run_with_registry_and_metrics_inner(
        config,
        registry,
        shutdown,
        metrics,
        None,
        #[cfg(test)]
        None,
        resources,
    )
    .await
}

async fn run_with_registry_and_metrics_inner_using_system<S>(
    system: ferrum2_dns::SystemResolver,
    config: ValidatedClientConfig,
    registry: OwnerRegistry,
    shutdown: S,
    metrics: Arc<Metrics>,
    #[cfg(test)] overrides: ClientTestOverrides,
    resources: ClientRunResources,
) -> Result<(), RunError>
where
    S: std::future::Future<Output = ()> + Send,
{
    #[cfg(test)]
    let ClientTestOverrides {
        udp_id_random,
        mut dns_observer,
    } = overrides;
    let ClientRunResources {
        management,
        network:
            ClientNetworkResources {
                process: process_resources,
                coordinator: network_reset_coordinator,
                catalog: network_interface_catalog,
                #[cfg(all(windows, not(test)))]
                    sockets: network_socket_service,
                #[cfg(all(windows, not(test)))]
                    change_monitor: network_change_monitor,
            },
        mut materialization_root,
        materialized_cache,
        underlay,
    } = resources;
    let mut recording = None;
    let result = async {
        recording = config
            .rocom
            .as_ref()
            .map(|settings| {
                ferrum2_rocom::Recording::start(&settings.record_path, settings.max_bytes)
                    .map_err(|_| RunError::StartupRecording)
            })
            .transpose()?;
        publish_rule_program_metadata(&config, &metrics);
        let selector = config.selector_control();
        let control_cache = management.as_ref().and(materialized_cache.clone());
        let control_refresh = if management.is_some() {
            materialization_root
                .as_ref()
                .map(|root| root.service())
                .transpose()?
        } else {
            None
        };
        let tun_config = config.tun;
        let tun_direct = tun_config.is_some()
            && config.outbounds.iter().any(|outbound| {
                matches!(
                    outbound,
                    ferrum2_config::ClientOutboundConfig::Direct { .. }
                )
            });
        let dns_specs = config
            .dns
            .as_ref()
            .map(|dns| dns_egress::dns_runtime_specs(&dns.servers));
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
        let application_resolver = ApplicationResolver::system(Arc::new(system.clone()));
        let application_resolver = ApplicationResolverAdapter::new(
            Arc::new(observed_application_resolver(
                application_resolver,
                &metrics,
            )),
            0,
            DnsStrategy::PreferIpv4,
        );
        let direct_resolvers = client_direct_resolvers(
            system.clone(),
            &config.outbounds,
            Arc::clone(&tagged_dns),
            &metrics,
        );
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
            let bytes = sessions
                .checked_mul(3 * MAX_UDP_WIRE_LEN)
                .ok_or(RunError::StartupProtocol)?
                .clamp(MIN_UDP_MAX_BUFFERED_BYTES, MAX_UDP_MAX_BUFFERED_BYTES);
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
                tun_budget: ferrum2_runtime::UdpBufferBudget::new_tun(
                    tun_config
                        .as_ref()
                        .map_or(0, |tun| tun.udp_buffered_bytes_limit),
                    registry.clone(),
                ),
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
            udp_id_random,
        )
        .with_route_network(runtime_route_network(&config.route_network));
        #[cfg(all(windows, not(test)))]
        let egress = egress.with_shared_network_reset(&network_socket_service)?;
        let egress = Arc::new(egress);
        let context = Arc::new(ClientContext {
            inbound: Socks5Inbound::new(),
            dashboard: management
                .as_ref()
                .map(|management| management.dashboard.clone()),
            recorder: recording.as_ref().map(ferrum2_rocom::Recording::recorder),
            egress: Arc::clone(&egress),
            #[cfg(test)]
            keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(
                test_support::default_test_psk(),
            )),
            runtime: config.runtime,
            public_udp_slots,
            registry: registry.clone(),
            metrics: Arc::clone(&metrics),
            dns: ordinary_dns.as_ref().map(Arc::clone),
        });
        let mut listens = Vec::with_capacity(config.inbounds.len());
        let tun_inbound = config.inbounds.len();
        let routing = Arc::new(ClientRouting {
            program: config.route,
            outbounds,
            selector,
        });
        let management_root = management.map(|management| management::ManagementRoot {
            management,
            control: Arc::new(dashboard_control::ClientDashboardControl::new(
                Arc::clone(&routing),
                Arc::clone(&egress),
                ordinary_dns.as_ref().map(Arc::clone),
                Arc::clone(&tagged_dns),
                control_cache,
                control_refresh,
                Arc::clone(&metrics),
                registry.clone(),
                config.inbounds.len() + usize::from(tun_config.is_some()),
            )),
            registry: registry.clone(),
            socks_count: config.inbounds.len(),
            dns_enabled: ordinary_dns.is_some(),
            tun_enabled: tun_config.is_some(),
            recording_max_bytes: config.rocom.as_ref().map(|settings| settings.max_bytes),
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
        if let Some(monitor) = network_change_monitor {
            roots.push(
                ClientRootName::Network,
                tun::network_change_process_root(
                    Arc::clone(&context),
                    network_reset_coordinator.clone(),
                    Arc::clone(&network_socket_service),
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
                        listeners.push(bind_listener(listen.into(), listen_backlog)?);
                    }
                    let executor = AffineConnectionExecutor::new(
                        ClientTcpListeners {
                            listeners,
                            next: AtomicUsize::new(0),
                            #[cfg(test)]
                            accept_errors: None,
                        },
                        max_connections,
                        shutdown_grace,
                        tcp_registry,
                    )
                    .map_err(|_| RunError::StartupProtocol)?;
                    Ok(ClientTcpRoot {
                        executor: Some(executor),
                        context: tcp_context,
                        routing: tcp_routing,
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
            roots.push(
                ClientRootName::Metrics,
                ProcessRoot::new(move || async move {
                    let listener = bind_listener(metrics_config.listen, 16)?;
                    Ok(ClientMetricsRoot {
                        listener: Some(listener),
                        metrics,
                        registry: metrics_registry,
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
                        #[cfg(all(windows, not(test)))]
                        network_socket_service: Arc::clone(&network_socket_service),
                    },
                    tun_direct,
                ),
            );
        }
        if let Some(root) = management_root {
            roots.push(
                ClientRootName::Dashboard,
                ProcessRoot::new(move || async move { Ok(root) }),
            );
        }
        let (roots, root_names) = roots.into_parts();
        let owner_baseline = process_resources.baseline;
        let supervisor = ProcessSupervisor::new(roots, shutdown_grace, registry.clone())
            .map_err(|_| RunError::StartupProtocol)?;
        let cleanup_outbounds = Arc::clone(&egress.outbounds);
        let supervisor = supervisor.with_process_resources(ferrum2_runtime::ProcessResources {
            baseline: owner_baseline,
            cleanup: Box::pin(async move {
                let mut protocol_result = Ok(());
                for outbound in cleanup_outbounds.iter() {
                    if let egress::ClientOutboundContext::F2p(outbound) = outbound {
                        protocol_result = protocol_result.and(outbound.shutdown().await);
                    }
                }
                let native_result = process_resources.cleanup.await;
                protocol_result.and(native_result)
            }),
        });
        let report = supervisor.run_until(shutdown).await;
        let owner_stopped = registry.snapshot();
        let diagnostic = ShutdownDiagnostic::classify(
            &report,
            &root_names,
            shutdown_grace,
            owner_baseline,
            owner_stopped,
        );
        if let Some(dashboard) = &context.dashboard
            && let Ok(mut event) =
                serde_json::from_str::<serde_json::Value>(&diagnostic.to_string())
        {
            event["level"] = serde_json::json!(if report.cleanup_failure().is_some() {
                "ERROR"
            } else {
                "INFO"
            });
            dashboard.record_log(event);
        }
        // This record is closed over client enums, monotonic durations, and owner
        // counters: no config, addresses, payloads, keys, or error text can enter it.
        // Diagnostics must never replace the process result when stderr is closed.
        let mut stderr = std::io::stderr().lock();
        let _ = std::io::Write::write_fmt(&mut stderr, format_args!("{diagnostic}\n"));
        report_result(report)
    }
    .await;
    let result = if let Some(mut root) = materialization_root {
        result.and(root.cleanup().await)
    } else {
        result
    };
    let recording_result = match recording.as_mut() {
        Some(recording) => match recording.shutdown() {
            Ok(report) if report.complete => Ok(()),
            Ok(_) | Err(_) => Err(RunError::RecordingIncomplete),
        },
        None => Ok(()),
    };
    result.and(recording_result)
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
async fn run_with_registry_and_metrics_inner<S>(
    config: ValidatedClientConfig,
    registry: OwnerRegistry,
    shutdown: S,
    metrics: Arc<Metrics>,
    udp_id_random: Option<Arc<dyn SecureRandom>>,
    dns_observer: Option<tokio::sync::oneshot::Sender<(Arc<ClientContext>, Arc<TaggedResolver>)>>,
    resources: ClientRunResources,
) -> Result<(), RunError>
where
    S: std::future::Future<Output = ()> + Send,
{
    let (system, mut owner) = ferrum2_dns::SystemResolution::start(
        config.dns.as_ref().map_or_else(
            || {
                std::num::NonZeroU16::new(config.runtime.max_connections.get().min(4096))
                    .expect("validated positive connection limit")
            },
            |dns| dns.max_inflight,
        ),
        config.runtime.connect_timeout,
    )
    .map_err(|_| RunError::StartupRuntime)?;
    let result = run_with_registry_and_metrics_inner_using_system(
        system,
        config,
        registry,
        shutdown,
        metrics,
        ClientTestOverrides {
            udp_id_random,
            dns_observer,
        },
        resources,
    )
    .await;
    owner
        .shutdown()
        .await
        .map_err(|_| RunError::ShutdownCleanup)?;
    result
}

#[cfg(test)]
#[derive(Default)]
struct ClientTestOverrides {
    udp_id_random: Option<Arc<dyn SecureRandom>>,
    dns_observer: Option<tokio::sync::oneshot::Sender<(Arc<ClientContext>, Arc<TaggedResolver>)>>,
}
