use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use ferrum2_config::{DnsConfig, LoggingLevel, RuntimeConfig, ValidatedClientConfig};
use ferrum2_core::route::Network;
use ferrum2_core::{
    AbortiveClose, ConnectError, ConnectErrorKind, Connector, Datagram, Inbound as _,
    LocalEndpoint, SessionReply as _, TargetAddr,
};
#[cfg(test)]
use ferrum2_crypto::Clock;
#[cfg(test)]
use ferrum2_crypto::MethodProfile;
#[cfg(test)]
use ferrum2_crypto::MethodSinglePskProvider;
use ferrum2_crypto::{SecureRandom, SystemClock, SystemRandom};
use ferrum2_dns::{
    DnsProxy, DnsProxyListeners, DnsProxySockets, ProxyTransport, TaggedResolver,
    TaggedResolverOwner,
};
use ferrum2_observability::{
    Direction, Event, Inbound, LogLevel, Metrics, Outcome, Reason, Role, Stage, TraceRecord, emit,
    json_subscriber,
};
use ferrum2_runtime::{
    AcceptListener, BoundedSupervisor, CancellationToken, MAX_UDP_MAX_BUFFERED_BYTES,
    MIN_UDP_IDLE_TIMEOUT, MIN_UDP_MAX_BUFFERED_BYTES, MetricsEndpoint, MetricsEndpointError,
    OwnerRegistry, PreparedProcessRoot, ProcessCancellation, ProcessCause, ProcessFuture,
    ProcessReport, ProcessRoot, ProcessRootExit, ProcessSupervisor, RelayFailure, RelayRunError,
    SupervisorError, TcpConnector, UdpDirection, UdpRuntimeError, UdpRuntimeLimits,
    UdpSessionManager, relay_lifecycle,
};
#[cfg(test)]
use ferrum2_shadowsocks::{
    BufferObserver, BufferRole, FlowObserver, MethodKeyAdapter, UdpClientSession, UdpPacketScratch,
};
use ferrum2_shadowsocks::{
    DetectionReason, FlowTerminal, MAX_UDP_WIRE_LEN, PlainDuplex, ProtocolReason, ShadowsocksError,
    TransportIo, UdpPacketError,
};
#[cfg(test)]
use ferrum2_socks5::MAX_SOCKS_UDP_DATAGRAM_BYTES;
use ferrum2_socks5::{
    Socks5Inbound, SocksCommand, SocksStream, SocksUdpAssociate, decode_udp_datagram,
    encode_udp_datagram,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpSocket, UdpSocket};
use tokio::time::Instant;

mod egress;

mod context;
mod dns;
#[path = "dns_egress.rs"]
mod dns_egress;
mod observation;
mod socks;
#[path = "run/io.rs"]
mod tokio_io;

use context::*;
use dns::*;
use observation::*;
use socks::*;
use tokio_io::*;

use egress::{
    ClientEgressEngine, ClientOpenFailure, ClientOutboundContext, ClientUdpAssociation,
    ClientUdpContext, UdpPlanResponseError, UdpSendError, composed_udp_plan_limit,
    prepare_client_outbounds, send_with_lifecycle,
};
#[cfg(test)]
use egress::{
    IdSequenceRandom, MAX_UDP_PLAN_HOPS, UdpIoFaultPlan, UdpIoOperation,
    composed_udp_request_limit, composed_udp_response_limit,
};

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

pub(crate) fn run(config: ValidatedClientConfig) -> Result<(), RunError> {
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
    config: ValidatedClientConfig,
    dns_specs: Option<Vec<ferrum2_dns::DnsUpstreamSpec>>,
) -> Result<(), RunError> {
    run_with_registry_and_metrics_inner(
        config,
        OwnerRegistry::new(),
        shutdown_signal(),
        Arc::new(Metrics::new()),
        None,
        #[cfg(test)]
        None,
        dns_specs,
    )
    .await
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
        dns_specs,
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
    dns_specs: Option<Vec<ferrum2_dns::DnsUpstreamSpec>>,
) -> Result<(), RunError>
where
    S: std::future::Future<Output = ()> + Send,
{
    #[cfg(test)]
    let method = config.method();
    let dns = match (config.dns, dns_specs) {
        (
            Some(DnsConfig {
                inbounds,
                servers,
                route,
                timeout,
                max_inflight,
            }),
            Some(specs),
        ) => {
            let internal_udp_needed = servers.iter().any(|server| {
                server.transport == ferrum2_config::DnsTransport::Udp && server.detour.is_some()
            });
            Some((
                inbounds,
                specs,
                route,
                timeout,
                max_inflight,
                internal_udp_needed,
            ))
        }
        (None, None) => None,
        _ => return Err(RunError::StartupProtocol),
    };
    metrics.set_udp_sessions_active(Role::Client, 0);
    metrics.set_udp_buffered_bytes(Role::Client, 0);
    let public_udp_enabled = config.udp.is_some_and(|udp| udp.enabled);
    let internal_udp_needed = dns.as_ref().is_some_and(|dns| dns.5);
    let runtime = config.runtime;
    let outbounds = prepare_client_outbounds(config.outbounds, config.outbound_psks)?;
    let shutdown_grace = config.runtime.shutdown_grace;
    let listen_backlog = u32::from(config.runtime.listen_backlog.get());
    let max_connections = usize::from(config.runtime.max_connections.get());
    let udp = if public_udp_enabled || internal_udp_needed {
        let (max_sessions, max_buffered_bytes, idle_timeout) = match config.udp {
            Some(udp) => (udp.max_sessions, udp.max_buffered_bytes, udp.idle_timeout),
            None => {
                let dns = dns.as_ref().expect("internal UDP requires DNS config");
                let sessions = usize::from(dns.4.get());
                let bytes = sessions
                    .checked_mul(3 * MAX_UDP_WIRE_LEN)
                    .ok_or(RunError::StartupProtocol)?
                    .clamp(MIN_UDP_MAX_BUFFERED_BYTES, MAX_UDP_MAX_BUFFERED_BYTES);
                (sessions, bytes, dns.3.max(MIN_UDP_IDLE_TIMEOUT))
            }
        };
        Some(ClientUdpContext {
            manager: UdpSessionManager::new(
                UdpRuntimeLimits::new(max_sessions, max_buffered_bytes, idle_timeout)
                    .map_err(|_| RunError::StartupProtocol)?,
                registry.clone(),
            ),
            live_ids: Arc::new(std::sync::Mutex::new(HashSet::new())),
            #[cfg(test)]
            method,
        })
    } else {
        None
    };
    let egress = Arc::new(ClientEgressEngine::new(
        Arc::clone(&outbounds),
        TokioConnector::new(TcpConnector::new(config.runtime.connect_timeout)),
        SystemClock::new(),
        SystemRandom,
        (
            config.runtime.connect_timeout,
            config.runtime.handshake_timeout,
        ),
        udp,
        #[cfg(test)]
        _udp_id_random,
    ));
    let context = Arc::new(ClientContext {
        inbound: Socks5Inbound::new(),
        egress: Arc::clone(&egress),
        #[cfg(test)]
        keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(config.psk)),
        runtime: config.runtime,
        udp_associate_enabled: public_udp_enabled,
        registry: registry.clone(),
        metrics: Arc::clone(&metrics),
        #[cfg(test)]
        test_udp_server: config.server,
    });
    let mut listens = Vec::with_capacity(config.inbounds.len());
    let routing = Arc::new(ClientRouting {
        route: config.route,
        outbounds,
    });
    #[cfg(test)]
    let dns_context = Arc::clone(&context);
    let dns_egress = Arc::clone(&egress);
    for inbound in &config.inbounds {
        listens.push(inbound.listen);
    }
    let tcp_registry = registry.clone();
    let tcp_context = Arc::clone(&context);
    let mut roots = vec![ProcessRoot::new(move || async move {
        let mut listeners = Vec::with_capacity(listens.len());
        for listen in listens {
            listeners.push(bind_listener(listen, listen_backlog)?);
        }
        let supervisor = BoundedSupervisor::new(
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
            supervisor: Some(supervisor),
            context: tcp_context,
            routing,
        })
    })];
    if let Some((inbounds, servers, route, timeout, max_inflight, _)) = dns {
        let addresses = inbounds.into_iter().map(|inbound| inbound.listen).collect();
        let route = Arc::new(route);
        roots.push(ProcessRoot::new(move || async move {
            let sockets = DnsProxySockets::bind(
                addresses,
                listen_backlog,
                runtime.max_connections,
                runtime.idle_timeout,
            )
            .await
            .map_err(|_| RunError::StartupBind)?;
            let egress = Arc::new(dns_egress::ClientDnsEgress::new(Arc::clone(&dns_egress)));
            let (resolver, owner) = TaggedResolver::new(servers, timeout, max_inflight, egress)
                .map_err(|_| RunError::StartupProtocol)?;
            let resolver = Arc::new(resolver);
            #[cfg(test)]
            if let Some(observer) = dns_observer.take() {
                let _ = observer.send((Arc::clone(&dns_context), Arc::clone(&resolver)));
            }
            let selection = Arc::clone(&route);
            let proxy = Arc::new(DnsProxy::new(
                Arc::clone(&resolver),
                move |inbound, transport, name| {
                    Some(match TargetAddr::domain(&name.to_ascii(), 53) {
                        Ok(target) => selection.select(
                            inbound,
                            match transport {
                                ProxyTransport::Udp => Network::Udp,
                                ProxyTransport::Tcp => Network::Tcp,
                            },
                            &target,
                        ),
                        Err(_) => selection.final_action(),
                    })
                },
            ));
            Ok(ClientDnsRoot {
                listeners: Some(sockets.with_proxy(proxy)),
                resolver: Some(resolver),
                owner: Some(owner),
                #[cfg(test)]
                readiness_gate: None,
            })
        }));
    }
    if let Some(metrics_config) = config.metrics {
        let metrics_registry = registry.clone();
        roots.push(ProcessRoot::new(move || async move {
            let listener = bind_listener(metrics_config.listen, 16)?;
            Ok(ClientMetricsRoot {
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
mod tests;
