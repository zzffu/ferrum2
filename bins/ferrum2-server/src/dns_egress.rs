#![forbid(unsafe_code)]

//! Server adapters for the shared tagged DNS resolver.

use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::BytesMut;
use ferrum2_config::{DirectDomainResolver, DnsServerConfig, DnsTransport};
use ferrum2_core::route::EgressPlanSnapshot;
use ferrum2_core::{TargetAddr, TargetHostRef};
use ferrum2_dns::ApplicationResolverAdapter;
use ferrum2_dns::{
    ApplicationResolveOutcome, ApplicationResolver, ApplicationResolverMode, BoxedDnsDatagramIo,
    BoxedDnsTcpIo, ChannelDnsDatagram, DnsEgress, DnsEgressResourceKind, DnsEgressTaskKind,
    DnsIoFuture, DnsStrategy, DnsTaskRegistrar, DnsUpstreamSpec, DnsUpstreamTransport,
    TaggedResolver, TaggedServerApplicationResolveBackend,
};
use ferrum2_net::{DialOptions, RouteNetworkOptions, TcpResolver, UdpResolver};
use ferrum2_observability::{DnsResolvePurpose, DnsResolveResult, DnsResolverKind, Metrics};
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

#[derive(Clone)]
pub(super) struct ServerDnsResolver {
    adapter: ApplicationResolverAdapter,
}

impl ServerDnsResolver {
    #[cfg(test)]
    pub(super) fn for_direct(
        mode: DirectDomainResolver,
        tagged: Arc<OnceLock<std::sync::Weak<TaggedResolver>>>,
    ) -> Self {
        Self::for_direct_inner(
            Arc::new(crate::run::test_support::TestApplicationBackend),
            mode,
            tagged,
            None,
        )
    }

    pub(super) fn for_direct_observed(
        system: ferrum2_dns::SystemResolver,
        mode: DirectDomainResolver,
        tagged: Arc<OnceLock<std::sync::Weak<TaggedResolver>>>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self::for_direct_inner(Arc::new(system), mode, tagged, Some(metrics))
    }

    fn for_direct_inner(
        system: Arc<dyn ferrum2_dns::ApplicationResolveBackend>,
        mode: DirectDomainResolver,
        tagged: Arc<OnceLock<std::sync::Weak<TaggedResolver>>>,
        metrics: Option<Arc<Metrics>>,
    ) -> Self {
        let (mut resolver, strategy) = match mode {
            DirectDomainResolver::System => {
                (ApplicationResolver::system(system), DnsStrategy::PreferIpv4)
            }
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
                    if let Some(source) = error.attempted_source() {
                        self.metrics.outbound_interface_resolution(
                            interface_resolution_source(source),
                            interface_resolution_result(&error),
                        );
                    }
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
                    if let Some(source) = error.attempted_source() {
                        self.metrics.outbound_interface_resolution(
                            interface_resolution_source(source),
                            interface_resolution_result(&error),
                        );
                    }
                    Err(closed_physical_socket_error())
                }
            }
        }
    }

    #[cfg(test)]
    pub(super) fn test(
        sockets: Arc<super::network::ServerNetworkSocketService>,
        outbound_count: usize,
        metrics: Arc<Metrics>,
    ) -> Arc<Self> {
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
    fn test(
        sockets: Arc<super::network::ServerNetworkSocketService>,
        outbound_count: usize,
    ) -> Self {
        let metrics = Arc::new(Metrics::new());
        Self::new(ServerPhysicalSocketContext::test(
            sockets,
            outbound_count,
            metrics,
        ))
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
            server_dns_datagram(socket, candidate, tasks)
        })
    }
}

fn server_dns_datagram(
    socket: ServerPhysicalUdpSocket,
    target: SocketAddr,
    tasks: DnsTaskRegistrar,
) -> io::Result<BoxedDnsDatagramIo> {
    let (io, mut outgoing_packets, incoming_packets) = ChannelDnsDatagram::bounded(
        NonZeroUsize::new(MAX_DNS_UDP_DATAGRAM_BYTES).expect("non-zero DNS UDP datagram limit"),
    )
    .into_parts();
    let outgoing_queue = tasks
        .own(DnsEgressResourceKind::Queue)
        .map_err(std::io::Error::other)?;
    let incoming_queue = tasks
        .own(DnsEgressResourceKind::Queue)
        .map_err(std::io::Error::other)?;
    let buffer = tasks
        .own(DnsEgressResourceKind::Buffer)
        .map_err(std::io::Error::other)?;
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
    Ok(io)
}

#[cfg(test)]
#[path = "dns_egress/tests/mod.rs"]
mod tests;
