use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use ferrum2_config::{DnsConfig, ValidatedServerConfig};
use ferrum2_core::route::Network;
use ferrum2_crypto::{MethodSinglePskProvider, SystemClock, SystemRandom};
use ferrum2_dns::TaggedResolver;
use ferrum2_observability::{Metrics, json_subscriber};
use ferrum2_runtime::{
    BoundedSupervisor, OwnerRegistry, ProcessCause, ProcessReport, ProcessRoot, ProcessRootExit,
    ProcessSupervisor, UdpSessionManager,
};
use ferrum2_shadowsocks::{MethodKeyAdapter, TcpReplayStore, UdpServer};
use tokio::net::UdpSocket;

mod dns;
#[path = "dns_egress.rs"]
mod dns_egress;
mod observation;
mod tcp;
#[path = "run/io.rs"]
mod tokio_io;
mod udp;

use dns::ServerDnsRoot;
use observation::{ServerMetricsRoot, log_level};
use tcp::{ServerContext, ServerRouting, ServerTcpListeners, ServerTcpRoot};
use tokio_io::{bind_listener, shutdown_signal};
use udp::{ServerUdpShared, UdpMappings, prepare_udp_server, udp_runtime_limits};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RunError {
    StartupObservability,
    StartupRuntime,
    StartupBind,
    StartupProtocol,
    RuntimeListener,
    RuntimeChild,
    RuntimeRoot,
    ShutdownCleanup,
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
            Self::RuntimeListener => "error[runtime.listener] process: required listener failed",
            Self::RuntimeChild => "error[runtime.child] process: required child failed",
            Self::RuntimeRoot => "error[runtime.root] process: required root stopped",
            Self::ShutdownCleanup => {
                "error[shutdown.cleanup] process: unable to reap all process owners"
            }
        })
    }
}

pub(crate) fn run(config: ValidatedServerConfig) -> Result<(), RunError> {
    let dns_specs = config
        .dns
        .as_ref()
        .map(|dns| dns_egress::dns_runtime_specs(&dns.servers));
    let subscriber = json_subscriber(std::io::stderr, log_level(config.logging.level));
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|_| RunError::StartupObservability)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| RunError::StartupRuntime)?;
    runtime.block_on(run_async(config, dns_specs))
}

async fn run_async(
    config: ValidatedServerConfig,
    dns_specs: Option<Vec<ferrum2_dns::DnsUpstreamSpec>>,
) -> Result<(), RunError> {
    run_with_registry_prepared(config, OwnerRegistry::new(), shutdown_signal(), dns_specs).await
}

#[cfg(test)]
async fn run_with_registry<S>(
    config: ValidatedServerConfig,
    registry: OwnerRegistry,
    shutdown: S,
) -> Result<(), RunError>
where
    S: std::future::Future<Output = ()> + Send,
{
    let dns_specs = config
        .dns
        .as_ref()
        .map(|dns| dns_egress::dns_runtime_specs(&dns.servers));
    run_with_registry_prepared(config, registry, shutdown, dns_specs).await
}

async fn run_with_registry_prepared<S>(
    config: ValidatedServerConfig,
    registry: OwnerRegistry,
    shutdown: S,
    dns_specs: Option<Vec<ferrum2_dns::DnsUpstreamSpec>>,
) -> Result<(), RunError>
where
    S: std::future::Future<Output = ()> + Send,
{
    let dns = match (config.dns, dns_specs) {
        (
            Some(DnsConfig {
                inbounds: _,
                servers: _,
                route,
                timeout,
                max_inflight,
            }),
            Some(servers),
        ) => Some((servers, route, timeout, max_inflight)),
        (None, None) => None,
        _ => return Err(RunError::StartupProtocol),
    };
    let metrics = Arc::new(Metrics::new());
    let replay = Arc::new(
        TcpReplayStore::new(config.replay.capacity).map_err(|_| RunError::StartupProtocol)?,
    );
    let keys = Arc::new(MethodKeyAdapter::new(MethodSinglePskProvider::new(
        config.psk,
    )));
    let udp_protocol = if config.udp.enabled {
        Some(Arc::new(
            UdpServer::new(keys.as_ref()).map_err(|_| RunError::StartupProtocol)?,
        ))
    } else {
        None
    };
    let listen_backlog = u32::from(config.runtime.listen_backlog.get());
    let max_connections = usize::from(config.runtime.max_connections.get());
    let shutdown_grace = config.runtime.shutdown_grace;
    let connect_timeout = config.runtime.connect_timeout;
    let udp_config = config.udp;
    let clock = Arc::new(SystemClock::new());
    let routing = Arc::new(ServerRouting {
        route: config.route,
        outbound_count: config.outbounds.len(),
    });
    let mut roots = Vec::with_capacity(
        config.inbounds.len() * usize::from(config.udp.enabled)
            + 1
            + usize::from(dns.is_some())
            + usize::from(config.metrics.is_some()),
    );
    let dns = match dns {
        Some((servers, route, timeout, max_inflight)) => {
            let state = Arc::new(dns_egress::ServerDnsState::new(route));
            let root_state = Arc::clone(&state);
            let outbound_count = routing.outbound_count;
            roots.push(ProcessRoot::new(move || async move {
                let egress = Arc::new(dns_egress::ServerDnsEgress::new(outbound_count));
                let (resolver, owner) = TaggedResolver::new(servers, timeout, max_inflight, egress)
                    .map_err(|_| RunError::StartupProtocol)?;
                root_state
                    .install(Arc::new(resolver))
                    .map_err(|_| RunError::StartupProtocol)?;
                Ok(ServerDnsRoot {
                    state: root_state,
                    owner,
                })
            }));
            Some(state)
        }
        None => None,
    };
    let mut tcp_listens = Vec::with_capacity(config.inbounds.len());
    let mut tcp_contexts = Vec::with_capacity(config.inbounds.len());
    for (inbound_id, inbound) in config.inbounds.iter().enumerate() {
        let listen = inbound.listen;
        tcp_listens.push(listen);
        let context = Arc::new(ServerContext {
            inbound: inbound_id,
            routing: Arc::clone(&routing),
            keys: Arc::clone(&keys),
            clock: Arc::clone(&clock),
            random: SystemRandom,
            replay: Arc::clone(&replay),
            runtime: config.runtime,
            dns: dns_egress::ServerDnsResolver::new(
                dns.as_ref().map(Arc::clone),
                inbound_id,
                Network::Tcp,
            ),
            registry: registry.clone(),
            metrics: Arc::clone(&metrics),
        });
        tcp_contexts.push(context);
    }
    let tcp_registry = registry.clone();
    roots.push(ProcessRoot::new(move || async move {
        let mut listeners = Vec::with_capacity(tcp_listens.len());
        for listen in tcp_listens {
            listeners.push(bind_listener(listen, listen_backlog)?);
        }
        let supervisor = BoundedSupervisor::new(
            ServerTcpListeners {
                listeners,
                next: AtomicUsize::new(0),
            },
            max_connections,
            shutdown_grace,
            tcp_registry,
        )
        .map_err(|_| RunError::StartupProtocol)?;
        Ok(ServerTcpRoot {
            supervisor: Some(supervisor),
            contexts: Arc::new(tcp_contexts),
        })
    }));
    if let Some(protocol) = udp_protocol {
        let limits = udp_runtime_limits(&udp_config).ok_or(RunError::StartupProtocol)?;
        let sessions = UdpSessionManager::new(limits, registry.clone());
        let mappings = Arc::new(UdpMappings::new(udp_config.max_sessions));
        let admission = Arc::new(tokio::sync::Mutex::new(()));
        let shared = ServerUdpShared {
            routing: Arc::clone(&routing),
            protocol,
            clock: Arc::clone(&clock),
            config: udp_config,
            sessions,
            mappings,
            admission,
            connect_timeout,
            dns: dns.as_ref().map(Arc::clone),
            registry: registry.clone(),
            metrics: Arc::clone(&metrics),
        };
        for (inbound_id, inbound) in config.inbounds.iter().enumerate() {
            let listen = inbound.listen;
            let shared = shared.clone();
            roots.push(ProcessRoot::new(move || async move {
                let listener = Arc::new(
                    UdpSocket::bind(SocketAddr::V4(listen))
                        .await
                        .map_err(|_| RunError::StartupBind)?,
                );
                prepare_udp_server(inbound_id, listener, shared)
            }));
        }
    }
    if let Some(metrics_config) = config.metrics {
        let metrics_registry = registry.clone();
        roots.push(ProcessRoot::new(move || async move {
            let listener = bind_listener(metrics_config.listen, 16)?;
            Ok(ServerMetricsRoot {
                listener: Some(listener),
                metrics,
                registry: metrics_registry,
            })
        }));
    }
    let supervisor = ProcessSupervisor::new(roots, shutdown_grace, registry)
        .map_err(|_| RunError::StartupProtocol)?;
    report_result(supervisor.run_until(shutdown).await)
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
