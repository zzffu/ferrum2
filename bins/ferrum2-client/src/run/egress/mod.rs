mod tcp;
mod udp;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ferrum2_core::route::EgressPlanSnapshot;
use ferrum2_core::{Connector, LocalEndpoint, TargetAddr};
use ferrum2_crypto::{Clock, MethodSinglePskProvider, SecureRandom};
#[cfg(test)]
use ferrum2_dns::{ApplicationResolver, DnsStrategy};
use ferrum2_runtime::ApplicationResolverAdapter;
#[cfg(test)]
use ferrum2_shadowsocks::{BufferObserver, FlowObserver};
use ferrum2_shadowsocks::{MethodKeyAdapter, ShadowsocksError, TransportIo};

use super::RunError;
use super::tokio_io::TokioConnector;

pub(super) use udp::{
    ClientUdpAssociation, ClientUdpContext, UdpPlanResponseError, UdpSendError,
    composed_udp_plan_limit, send_with_lifecycle,
};
#[cfg(test)]
pub(super) use udp::{
    IdSequenceRandom, MAX_UDP_PLAN_HOPS, UdpIoFaultPlan, UdpIoOperation,
    composed_udp_request_limit, composed_udp_response_limit,
};

pub(super) enum ClientOutboundContext {
    Shadowsocks(ClientShadowsocksContext),
    Direct,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ClientRequestOrigin {
    Socks,
    Tun,
    Dns,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SelectedEgress {
    Direct,
    Shadowsocks { first_server: SocketAddr },
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TcpBinding {
    None,
    Fixed,
    DefaultIfIpv4,
    DefaultIpv4Only,
}

#[cfg(any(windows, test))]
const fn direct_tcp_binding(origin: ClientRequestOrigin, auto_route: bool) -> TcpBinding {
    match (origin, auto_route) {
        (ClientRequestOrigin::Tun, _) => TcpBinding::DefaultIpv4Only,
        (ClientRequestOrigin::Dns, true) => TcpBinding::Fixed,
        (ClientRequestOrigin::Socks, true) => TcpBinding::DefaultIfIpv4,
        (ClientRequestOrigin::Socks | ClientRequestOrigin::Dns, false) => TcpBinding::None,
    }
}

#[cfg(any(windows, test))]
const fn proxy_tcp_binding(auto_route: bool) -> TcpBinding {
    if auto_route {
        TcpBinding::Fixed
    } else {
        TcpBinding::None
    }
}

#[cfg(windows)]
const fn managed_direct_ipv6_is_unsupported(origin: ClientRequestOrigin, auto_route: bool) -> bool {
    matches!(origin, ClientRequestOrigin::Tun)
        || auto_route && matches!(origin, ClientRequestOrigin::Dns)
}

#[cfg(any(windows, test))]
tokio::task_local! {
    static TCP_BINDING: TcpBinding;
}

#[cfg(any(windows, test))]
trait ManagedTcpOperations {
    type Socket;
    type Stream;

    fn new_v4(&self) -> std::io::Result<Self::Socket>;
    fn new_v6(&self) -> std::io::Result<Self::Socket>;
    fn bind_fixed(
        &self,
        socket: &Self::Socket,
        endpoint: std::net::SocketAddrV4,
    ) -> std::io::Result<()>;
    fn bind_default(&self, socket: &Self::Socket) -> std::io::Result<()>;
    async fn connect(
        &self,
        socket: Self::Socket,
        address: SocketAddr,
    ) -> std::io::Result<Self::Stream>;
}

#[cfg(any(windows, test))]
async fn connect_managed_tcp<O: ManagedTcpOperations>(
    operations: &O,
    address: SocketAddr,
) -> std::io::Result<O::Stream> {
    let binding = TCP_BINDING
        .try_with(|binding| *binding)
        .map_err(|_| std::io::Error::other("managed TCP binding context missing"))?;
    let socket = match address {
        SocketAddr::V4(_) => operations.new_v4()?,
        SocketAddr::V6(_) if matches!(binding, TcpBinding::None | TcpBinding::DefaultIfIpv4) => {
            operations.new_v6()?
        }
        SocketAddr::V6(_) => return Err(std::io::Error::other("managed IPv4 required")),
    };
    match (binding, address) {
        (TcpBinding::Fixed, SocketAddr::V4(endpoint)) => {
            operations.bind_fixed(&socket, endpoint)?
        }
        (TcpBinding::DefaultIfIpv4 | TcpBinding::DefaultIpv4Only, SocketAddr::V4(_)) => {
            operations.bind_default(&socket)?
        }
        (TcpBinding::None, _) => {}
        (TcpBinding::DefaultIfIpv4, SocketAddr::V6(_)) => {}
        (_, SocketAddr::V6(_)) => unreachable!("managed IPv6 rejected before socket"),
    }
    operations.connect(socket, address).await
}

#[cfg(all(windows, not(test)))]
#[derive(Clone)]
pub(super) struct ManagedTcpDialer {
    underlay: ferrum2_tun::UnderlayPublisher,
}

#[cfg(all(windows, not(test)))]
impl ManagedTcpDialer {
    pub(super) const fn new(underlay: ferrum2_tun::UnderlayPublisher) -> Self {
        Self { underlay }
    }
}

#[cfg(all(windows, not(test)))]
impl ManagedTcpOperations for ManagedTcpDialer {
    type Socket = tokio::net::TcpSocket;
    type Stream = tokio::net::TcpStream;

    fn new_v4(&self) -> std::io::Result<Self::Socket> {
        tokio::net::TcpSocket::new_v4()
    }

    fn new_v6(&self) -> std::io::Result<Self::Socket> {
        tokio::net::TcpSocket::new_v6()
    }

    fn bind_fixed(
        &self,
        socket: &Self::Socket,
        endpoint: std::net::SocketAddrV4,
    ) -> std::io::Result<()> {
        self.underlay
            .bind_fixed(socket, endpoint)
            .map_err(|_| std::io::Error::other("managed TCP binding failed"))
    }

    fn bind_default(&self, socket: &Self::Socket) -> std::io::Result<()> {
        self.underlay
            .bind_default(socket)
            .map_err(|_| std::io::Error::other("managed TCP binding failed"))
    }

    async fn connect(
        &self,
        socket: Self::Socket,
        address: SocketAddr,
    ) -> std::io::Result<Self::Stream> {
        socket.connect(address).await
    }
}

#[cfg(all(windows, not(test)))]
impl ferrum2_runtime::TcpDialer for ManagedTcpDialer {
    async fn connect(&self, address: SocketAddr) -> std::io::Result<tokio::net::TcpStream> {
        connect_managed_tcp(self, address).await
    }
}

#[cfg(all(windows, not(test)))]
type DefaultClientConnector = TokioConnector<
    ferrum2_runtime::TcpConnector<
        ferrum2_runtime::SystemSocketInspector,
        ManagedTcpDialer,
        ApplicationResolverAdapter,
    >,
>;

#[cfg(any(not(windows), test))]
type DefaultClientConnector = TokioConnector<
    ferrum2_runtime::TcpConnector<
        ferrum2_runtime::SystemSocketInspector,
        ferrum2_runtime::SystemTcpDialer,
        ApplicationResolverAdapter,
    >,
>;

#[cfg(test)]
pub(super) fn system_application_resolver() -> ApplicationResolverAdapter {
    ApplicationResolverAdapter::new(
        Arc::new(ApplicationResolver::system_default()),
        0,
        DnsStrategy::PreferIpv4,
    )
}

pub(super) struct ClientShadowsocksContext {
    pub(super) tcp_server: TargetAddr,
    pub(super) udp_server: SocketAddr,
    pub(super) keys: MethodKeyAdapter<MethodSinglePskProvider>,
}

impl ClientOutboundContext {
    pub(super) fn shadowsocks(&self) -> Option<&ClientShadowsocksContext> {
        match self {
            Self::Shadowsocks(outbound) => Some(outbound),
            Self::Direct => None,
        }
    }
}

pub(super) fn prepare_client_outbounds(
    outbounds: Vec<ferrum2_config::ClientOutboundConfig>,
) -> Result<Arc<[ClientOutboundContext]>, RunError> {
    if outbounds.is_empty() {
        return Err(RunError::StartupProtocol);
    }
    outbounds
        .into_iter()
        .map(|outbound| {
            Ok(match outbound {
                ferrum2_config::ClientOutboundConfig::Shadowsocks { server, psk } => {
                    ClientOutboundContext::Shadowsocks(ClientShadowsocksContext {
                        tcp_server: TargetAddr::ip(server)
                            .map_err(|_| RunError::StartupProtocol)?,
                        udp_server: server,
                        keys: MethodKeyAdapter::new(MethodSinglePskProvider::from_shared(psk)),
                    })
                }
                ferrum2_config::ClientOutboundConfig::Direct => ClientOutboundContext::Direct,
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Arc::from)
}

pub(super) struct ClientEgressEngine<
    C = DefaultClientConnector,
    T = ferrum2_crypto::SystemClock,
    R = ferrum2_crypto::SystemRandom,
> {
    pub(super) outbounds: Arc<[ClientOutboundContext]>,
    connector: C,
    pub(super) clock: T,
    pub(super) random: R,
    phase_deadlines: (Duration, Duration),
    pub(super) udp: Option<ClientUdpContext>,
    pub(super) application_resolver: ApplicationResolverAdapter,
    underlay: ferrum2_tun::UnderlayPublisher,
    auto_route: bool,
    #[cfg(all(windows, test))]
    managed_udp_events: std::sync::Mutex<Vec<udp::ManagedUdpEvent>>,
    #[cfg(all(windows, test))]
    managed_udp_binding_fails: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    pub(super) udp_id_random: Option<Arc<dyn SecureRandom>>,
}

impl<C, T, R> ClientEgressEngine<C, T, R> {
    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub(super) fn new(
        outbounds: Arc<[ClientOutboundContext]>,
        connector: C,
        clock: T,
        random: R,
        phase_deadlines: (Duration, Duration),
        udp: Option<ClientUdpContext>,
        #[cfg(test)] udp_id_random: Option<Arc<dyn SecureRandom>>,
    ) -> Self {
        Self::new_with_application_resolver(
            outbounds,
            connector,
            clock,
            random,
            phase_deadlines,
            udp,
            system_application_resolver(),
            #[cfg(test)]
            udp_id_random,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn new_with_application_resolver(
        outbounds: Arc<[ClientOutboundContext]>,
        connector: C,
        clock: T,
        random: R,
        phase_deadlines: (Duration, Duration),
        udp: Option<ClientUdpContext>,
        application_resolver: ApplicationResolverAdapter,
        #[cfg(test)] udp_id_random: Option<Arc<dyn SecureRandom>>,
    ) -> Self {
        Self {
            outbounds,
            connector,
            clock,
            random,
            phase_deadlines,
            udp,
            application_resolver,
            underlay: ferrum2_tun::UnderlayPublisher::new(),
            auto_route: false,
            #[cfg(all(windows, test))]
            managed_udp_events: std::sync::Mutex::new(Vec::new()),
            #[cfg(all(windows, test))]
            managed_udp_binding_fails: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            udp_id_random,
        }
    }

    pub(super) fn with_underlay(
        mut self,
        underlay: ferrum2_tun::UnderlayPublisher,
        auto_route: bool,
    ) -> Self {
        self.underlay = underlay;
        self.auto_route = auto_route;
        self
    }

    #[cfg(all(windows, test))]
    fn record_managed_udp_event(&self, event: udp::ManagedUdpEvent) -> Result<(), ()> {
        self.managed_udp_events.lock().unwrap().push(event);
        if matches!(
            event,
            udp::ManagedUdpEvent::BindFixed(_) | udp::ManagedUdpEvent::BindDefault
        ) && self
            .managed_udp_binding_fails
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            Err(())
        } else {
            Ok(())
        }
    }

    #[cfg(all(windows, test))]
    pub(super) fn managed_binding_calls(&self) -> usize {
        self.managed_udp_events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    udp::ManagedUdpEvent::BindFixed(_) | udp::ManagedUdpEvent::BindDefault
                )
            })
            .count()
    }

    #[cfg(all(windows, test))]
    fn managed_udp_events(&self) -> Vec<udp::ManagedUdpEvent> {
        self.managed_udp_events.lock().unwrap().clone()
    }

    #[cfg(all(windows, test))]
    fn fail_managed_udp_binding(&self) {
        self.managed_udp_binding_fails
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn classify_selected(
        &self,
        origin: ClientRequestOrigin,
        plan: Option<&EgressPlanSnapshot>,
        target: Option<&TargetAddr>,
    ) -> Result<SelectedEgress, ClientPlanFailure> {
        if origin != ClientRequestOrigin::Socks && target.is_none() {
            return Err(ClientPlanFailure::Invalid);
        }
        let Some(plan) = plan else {
            return if origin == ClientRequestOrigin::Dns {
                Ok(SelectedEgress::Direct)
            } else {
                Err(ClientPlanFailure::Invalid)
            };
        };
        let hops = plan.hops();
        if hops.is_empty() || hops.len() > udp::MAX_UDP_PLAN_HOPS {
            return Err(ClientPlanFailure::Invalid);
        }
        let mut direct = 0;
        for hop in hops {
            match self.outbounds.get(*hop) {
                Some(ClientOutboundContext::Shadowsocks(_)) => {}
                Some(ClientOutboundContext::Direct) => direct += 1,
                None => return Err(ClientPlanFailure::Invalid),
            }
        }
        if direct == 1 && hops.len() == 1 {
            #[cfg(windows)]
            if managed_direct_ipv6_is_unsupported(origin, self.auto_route)
                && target
                    .and_then(TargetAddr::as_socket_addr)
                    .is_some_and(|target| target.is_ipv6())
            {
                return Err(ClientPlanFailure::DirectIpv6Unsupported);
            }
            return Ok(SelectedEgress::Direct);
        }
        if direct != 0 {
            return Err(ClientPlanFailure::Invalid);
        }
        Ok(SelectedEgress::Shadowsocks {
            first_server: self.outbounds[hops[0]]
                .shadowsocks()
                .expect("classified Shadowsocks plan")
                .udp_server,
        })
    }

    pub(super) async fn open_tcp<'a>(
        &'a self,
        origin: ClientRequestOrigin,
        plan: Option<EgressPlanSnapshot>,
        application_target: &TargetAddr,
        timeout_limit: Option<Duration>,
        #[cfg(test)] observers: Option<(&'a dyn BufferObserver, &'a dyn FlowObserver)>,
    ) -> Result<tcp::ClientTcpFlow<'a, C::Stream>, ClientOpenFailure>
    where
        C: Connector,
        C::Stream: TransportIo + LocalEndpoint + 'a,
        T: Clock + Sync,
        R: SecureRandom,
    {
        self.open_tcp_for_ingress(
            origin,
            0,
            plan,
            application_target,
            timeout_limit,
            #[cfg(test)]
            observers,
        )
        .await
    }

    pub(super) async fn open_tcp_for_ingress<'a>(
        &'a self,
        origin: ClientRequestOrigin,
        ingress: usize,
        plan: Option<EgressPlanSnapshot>,
        application_target: &TargetAddr,
        timeout_limit: Option<Duration>,
        #[cfg(test)] observers: Option<(&'a dyn BufferObserver, &'a dyn FlowObserver)>,
    ) -> Result<tcp::ClientTcpFlow<'a, C::Stream>, ClientOpenFailure>
    where
        C: Connector,
        C::Stream: TransportIo + LocalEndpoint + 'a,
        T: Clock + Sync,
        R: SecureRandom,
    {
        let selected = self
            .classify_selected(origin, plan.as_ref(), Some(application_target))
            .map_err(ClientOpenFailure::Plan)?;
        if selected == SelectedEgress::Direct {
            let deadline = timeout_limit
                .unwrap_or(self.phase_deadlines.0)
                .min(self.phase_deadlines.0);
            #[cfg(any(windows, test))]
            let connect = TCP_BINDING.scope(
                direct_tcp_binding(origin, self.auto_route),
                self.application_resolver
                    .scope_ingress(ingress, self.connector.connect(application_target)),
            );
            #[cfg(not(any(windows, test)))]
            let connect = self
                .application_resolver
                .scope_ingress(ingress, self.connector.connect(application_target));
            return match tokio::time::timeout(deadline, connect).await {
                Ok(Ok(stream)) => Ok(tcp::ClientTcpFlow::Direct(stream)),
                Ok(Err(error)) => Err(ClientOpenFailure::Connect(error.kind())),
                Err(_) => Err(ClientOpenFailure::Connect(
                    ferrum2_core::ConnectErrorKind::Timeout,
                )),
            };
        }
        let plan = plan.expect("classified proxy plan has a snapshot");
        let deadlines = timeout_limit.map_or(self.phase_deadlines, |limit| {
            (
                limit.min(self.phase_deadlines.0),
                limit.min(self.phase_deadlines.1),
            )
        });
        let open = tcp::open(
            &self.outbounds,
            plan.hops(),
            &self.connector,
            &self.clock,
            &self.random,
            application_target,
            deadlines,
            #[cfg(test)]
            observers,
        );
        #[cfg(any(windows, test))]
        let open = TCP_BINDING.scope(proxy_tcp_binding(self.auto_route), open);
        open.await.map(tcp::ClientTcpFlow::Proxy)
    }

    pub(super) async fn prepare_udp(
        &self,
        origin: ClientRequestOrigin,
        plan: Option<EgressPlanSnapshot>,
        target: Option<&TargetAddr>,
    ) -> Result<ClientUdpAssociation, ClientUdpPrepareFailure> {
        self.prepare_udp_for_ingress(origin, 0, plan, target).await
    }

    pub(super) async fn prepare_udp_for_ingress(
        &self,
        origin: ClientRequestOrigin,
        ingress: usize,
        plan: Option<EgressPlanSnapshot>,
        target: Option<&TargetAddr>,
    ) -> Result<ClientUdpAssociation, ClientUdpPrepareFailure> {
        let selected = self
            .classify_selected(origin, plan.as_ref(), target)
            .map_err(ClientUdpPrepareFailure::Plan)?;
        udp::prepare(
            self,
            origin,
            ingress,
            plan,
            selected,
            target,
            tokio::net::UdpSocket::bind,
        )
        .await
        .map_err(|()| ClientUdpPrepareFailure::Unavailable)
    }

    #[cfg(test)]
    pub(super) async fn prepare_udp_with<F, Fut>(
        &self,
        plan: EgressPlanSnapshot,
        bind: F,
    ) -> Result<ClientUdpAssociation, ClientUdpPrepareFailure>
    where
        F: FnMut(SocketAddr) -> Fut,
        Fut: std::future::Future<Output = std::io::Result<tokio::net::UdpSocket>>,
    {
        let selected = self
            .classify_selected(ClientRequestOrigin::Socks, Some(&plan), None)
            .map_err(ClientUdpPrepareFailure::Plan)?;
        udp::prepare(
            self,
            ClientRequestOrigin::Socks,
            0,
            Some(plan),
            selected,
            None,
            bind,
        )
        .await
        .map_err(|()| ClientUdpPrepareFailure::Unavailable)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ClientPlanFailure {
    #[cfg(windows)]
    DirectIpv6Unsupported,
    Invalid,
}

#[derive(Debug)]
pub(super) enum ClientOpenFailure {
    Plan(ClientPlanFailure),
    Connect(ferrum2_core::ConnectErrorKind),
    Protocol(ShadowsocksError),
    HandshakeTimeout,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ClientUdpPrepareFailure {
    Plan(ClientPlanFailure),
    Unavailable,
}

#[cfg(test)]
mod m16_tests {
    use super::*;
    use crate::run::test_support::*;

    #[derive(Default)]
    struct InjectedManagedTcp {
        events: std::sync::Mutex<Vec<&'static str>>,
        fail_binding: bool,
    }

    #[derive(Clone)]
    struct RecordedTcpDialer {
        events: Arc<std::sync::Mutex<Vec<&'static str>>>,
        fail_binding: bool,
    }

    impl ManagedTcpOperations for RecordedTcpDialer {
        type Socket = tokio::net::TcpSocket;
        type Stream = tokio::net::TcpStream;

        fn new_v4(&self) -> std::io::Result<Self::Socket> {
            self.events.lock().unwrap().push("socket-v4");
            tokio::net::TcpSocket::new_v4()
        }

        fn new_v6(&self) -> std::io::Result<Self::Socket> {
            self.events.lock().unwrap().push("socket-v6");
            tokio::net::TcpSocket::new_v6()
        }

        fn bind_fixed(
            &self,
            _socket: &Self::Socket,
            _endpoint: std::net::SocketAddrV4,
        ) -> std::io::Result<()> {
            self.events.lock().unwrap().push("bind-fixed");
            if self.fail_binding {
                Err(std::io::Error::other("injected binding failure"))
            } else {
                Ok(())
            }
        }

        fn bind_default(&self, _socket: &Self::Socket) -> std::io::Result<()> {
            self.events.lock().unwrap().push("bind-default");
            if self.fail_binding {
                Err(std::io::Error::other("injected binding failure"))
            } else {
                Ok(())
            }
        }

        async fn connect(
            &self,
            socket: Self::Socket,
            address: SocketAddr,
        ) -> std::io::Result<Self::Stream> {
            self.events.lock().unwrap().push("connect");
            socket.connect(address).await
        }
    }

    impl ferrum2_runtime::TcpDialer for RecordedTcpDialer {
        async fn connect(&self, address: SocketAddr) -> std::io::Result<tokio::net::TcpStream> {
            connect_managed_tcp(self, address).await
        }
    }

    impl ManagedTcpOperations for InjectedManagedTcp {
        type Socket = ();
        type Stream = ();

        fn new_v4(&self) -> std::io::Result<Self::Socket> {
            self.events.lock().unwrap().push("socket-v4");
            Ok(())
        }

        fn new_v6(&self) -> std::io::Result<Self::Socket> {
            self.events.lock().unwrap().push("socket-v6");
            Ok(())
        }

        fn bind_fixed(
            &self,
            _socket: &Self::Socket,
            _endpoint: std::net::SocketAddrV4,
        ) -> std::io::Result<()> {
            self.events.lock().unwrap().push("bind-fixed");
            if self.fail_binding {
                Err(std::io::Error::other("injected binding failure"))
            } else {
                Ok(())
            }
        }

        fn bind_default(&self, _socket: &Self::Socket) -> std::io::Result<()> {
            self.events.lock().unwrap().push("bind-default");
            if self.fail_binding {
                Err(std::io::Error::other("injected binding failure"))
            } else {
                Ok(())
            }
        }

        async fn connect(
            &self,
            _socket: Self::Socket,
            _address: SocketAddr,
        ) -> std::io::Result<Self::Stream> {
            self.events.lock().unwrap().push("connect");
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    struct ApplicationRoute {
        ingress: usize,
        network: ferrum2_core::route::Network,
        endpoint: SocketAddr,
    }

    struct RoutedApplicationBackend {
        routes: Vec<ApplicationRoute>,
        observed: Mutex<Vec<(usize, ferrum2_core::route::Network)>>,
    }

    impl ferrum2_dns::ApplicationResolveBackend for RoutedApplicationBackend {
        fn resolve<'a>(
            &'a self,
            request: ferrum2_dns::ApplicationResolveRequest<'a>,
        ) -> ferrum2_dns::ApplicationResolveFuture<'a> {
            let context = request.context();
            self.observed
                .lock()
                .expect("application observations")
                .push((context.ingress(), context.network()));
            let endpoint = self
                .routes
                .iter()
                .find(|route| {
                    route.ingress == context.ingress() && route.network == context.network()
                })
                .map(|route| route.endpoint);
            Box::pin(async move {
                endpoint
                    .map(|endpoint| vec![endpoint])
                    .ok_or(ferrum2_dns::DnsError::Timeout)
            })
        }
    }

    #[tokio::test]
    async fn application_dns_ingress_is_isolated_for_concurrent_tcp_and_udp() {
        let tcp_listener_3 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let tcp_listener_7 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let udp_listener_3 = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let udp_listener_7 = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let backend = Arc::new(RoutedApplicationBackend {
            routes: vec![
                ApplicationRoute {
                    ingress: 3,
                    network: ferrum2_core::route::Network::Tcp,
                    endpoint: tcp_listener_3.local_addr().unwrap(),
                },
                ApplicationRoute {
                    ingress: 7,
                    network: ferrum2_core::route::Network::Tcp,
                    endpoint: tcp_listener_7.local_addr().unwrap(),
                },
                ApplicationRoute {
                    ingress: 3,
                    network: ferrum2_core::route::Network::Udp,
                    endpoint: udp_listener_3.local_addr().unwrap(),
                },
                ApplicationRoute {
                    ingress: 7,
                    network: ferrum2_core::route::Network::Udp,
                    endpoint: udp_listener_7.local_addr().unwrap(),
                },
            ],
            observed: Mutex::new(Vec::new()),
        });
        let resolver = ApplicationResolverAdapter::new(
            Arc::new(ApplicationResolver::configured(backend.clone())),
            0,
            DnsStrategy::PreferIpv4,
        );
        let connector =
            TokioConnector::new(ferrum2_runtime::TcpConnector::with_resolution_adapters(
                ferrum2_runtime::SystemSocketInspector,
                ferrum2_runtime::SystemTcpDialer,
                resolver.clone(),
                Duration::from_secs(1),
            ));
        let registry = OwnerRegistry::new();
        let engine = ClientEgressEngine::new_with_application_resolver(
            vec![ClientOutboundContext::Direct].into(),
            connector,
            SystemClock::new(),
            SystemRandom,
            (Duration::from_secs(1), Duration::from_secs(1)),
            Some(ClientUdpContext {
                manager: UdpSessionManager::new(UdpRuntimeLimits::default(), registry),
                live_ids: Arc::new(Mutex::new(HashSet::new())),
            }),
            resolver,
            None,
        );
        let direct = ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned();
        let tcp_target = TargetAddr::domain("tcp-ingress.invalid", 443).unwrap();
        let udp_target = TargetAddr::domain("udp-ingress.invalid", 5353).unwrap();
        let mut association_3 = engine
            .prepare_udp_for_ingress(
                ClientRequestOrigin::Socks,
                3,
                Some(direct.clone()),
                Some(&udp_target),
            )
            .await
            .unwrap();
        let mut association_7 = engine
            .prepare_udp_for_ingress(
                ClientRequestOrigin::Socks,
                7,
                Some(direct.clone()),
                Some(&udp_target),
            )
            .await
            .unwrap();
        let wire_3 = association_3
            .prepare_application_request(
                &engine,
                &engine.outbounds,
                udp_target.clone(),
                b"ingress-3",
                Instant::now(),
            )
            .unwrap_or_else(|_| panic!("prepare ingress 3 datagram"));
        let wire_7 = association_7
            .prepare_application_request(
                &engine,
                &engine.outbounds,
                udp_target.clone(),
                b"ingress-7",
                Instant::now(),
            )
            .unwrap_or_else(|_| panic!("prepare ingress 7 datagram"));

        let receive_3 = async {
            let mut bytes = [0_u8; 32];
            let (length, _) = udp_listener_3.recv_from(&mut bytes).await.unwrap();
            bytes[..length].to_vec()
        };
        let receive_7 = async {
            let mut bytes = [0_u8; 32];
            let (length, _) = udp_listener_7.recv_from(&mut bytes).await.unwrap();
            bytes[..length].to_vec()
        };
        let (tcp_3, tcp_7, udp_3, udp_7, accepted_3, accepted_7, payload_3, payload_7) = tokio::join!(
            engine.open_tcp_for_ingress(
                ClientRequestOrigin::Socks,
                3,
                Some(direct.clone()),
                &tcp_target,
                None,
                None,
            ),
            engine.open_tcp_for_ingress(
                ClientRequestOrigin::Socks,
                7,
                Some(direct.clone()),
                &tcp_target,
                None,
                None,
            ),
            association_3.send_encoded_request(wire_3),
            association_7.send_encoded_request(wire_7),
            tcp_listener_3.accept(),
            tcp_listener_7.accept(),
            receive_3,
            receive_7,
        );
        drop(tcp_3.unwrap());
        drop(tcp_7.unwrap());
        drop(accepted_3.unwrap());
        drop(accepted_7.unwrap());
        assert_eq!(udp_3.unwrap(), b"ingress-3".len());
        assert_eq!(udp_7.unwrap(), b"ingress-7".len());
        assert_eq!(payload_3, b"ingress-3");
        assert_eq!(payload_7, b"ingress-7");

        for (association, ingress, payload) in [
            (&mut association_3, 3, b"again-3".as_slice()),
            (&mut association_7, 7, b"again-7".as_slice()),
        ] {
            let wire = association
                .prepare_application_request(
                    &engine,
                    &engine.outbounds,
                    udp_target.clone(),
                    payload,
                    Instant::now(),
                )
                .unwrap_or_else(|_| panic!("prepare repeated ingress {ingress} datagram"));
            association
                .send_encoded_request(wire)
                .await
                .unwrap_or_else(|_| panic!("send repeated ingress {ingress} datagram"));
        }

        assert!(
            engine
                .open_tcp_for_ingress(
                    ClientRequestOrigin::Socks,
                    13,
                    Some(direct.clone()),
                    &tcp_target,
                    None,
                    None,
                )
                .await
                .is_err(),
            "configured failure must not fall back"
        );
        assert!(
            engine
                .open_tcp(
                    ClientRequestOrigin::Socks,
                    Some(direct.clone()),
                    &tcp_target,
                    None,
                    None,
                )
                .await
                .is_err(),
            "compatibility entry point must retain ingress zero"
        );
        let mut failed_udp = engine
            .prepare_udp_for_ingress(
                ClientRequestOrigin::Socks,
                13,
                Some(direct),
                Some(&udp_target),
            )
            .await
            .unwrap();
        let failed_wire = failed_udp
            .prepare_application_request(
                &engine,
                &engine.outbounds,
                udp_target,
                b"no-fallback",
                Instant::now(),
            )
            .unwrap_or_else(|_| panic!("prepare failed-ingress datagram"));
        assert_eq!(
            failed_udp
                .send_encoded_request(failed_wire)
                .await
                .expect_err("configured UDP failure must not fall back")
                .kind(),
            io::ErrorKind::TimedOut
        );

        let observed = backend.observed.lock().unwrap();
        for (ingress, network, expected) in [
            (0, ferrum2_core::route::Network::Tcp, 1),
            (3, ferrum2_core::route::Network::Tcp, 1),
            (3, ferrum2_core::route::Network::Udp, 2),
            (7, ferrum2_core::route::Network::Tcp, 1),
            (7, ferrum2_core::route::Network::Udp, 2),
            (13, ferrum2_core::route::Network::Tcp, 1),
            (13, ferrum2_core::route::Network::Udp, 1),
        ] {
            assert_eq!(
                observed
                    .iter()
                    .filter(|actual| **actual == (ingress, network))
                    .count(),
                expected,
                "ingress {ingress} {network:?}"
            );
        }
        assert_eq!(observed.len(), 9);
    }

    #[tokio::test]
    async fn managed_tcp_binding_is_task_local_and_precedes_the_only_connect() {
        let target: SocketAddr = "198.51.100.8:443".parse().unwrap();
        let missing = InjectedManagedTcp::default();
        assert!(connect_managed_tcp(&missing, target).await.is_err());
        assert!(missing.events.lock().unwrap().is_empty());

        let fixed = InjectedManagedTcp::default();
        TCP_BINDING
            .scope(TcpBinding::Fixed, connect_managed_tcp(&fixed, target))
            .await
            .unwrap();
        assert_eq!(
            *fixed.events.lock().unwrap(),
            ["socket-v4", "bind-fixed", "connect"]
        );

        let failed = InjectedManagedTcp {
            fail_binding: true,
            ..Default::default()
        };
        assert!(
            TCP_BINDING
                .scope(
                    TcpBinding::DefaultIpv4Only,
                    connect_managed_tcp(&failed, target)
                )
                .await
                .is_err()
        );
        assert_eq!(
            *failed.events.lock().unwrap(),
            ["socket-v4", "bind-default"]
        );

        let default = InjectedManagedTcp::default();
        let none = InjectedManagedTcp::default();
        let (default_result, none_result) = tokio::join!(
            TCP_BINDING.scope(
                TcpBinding::DefaultIfIpv4,
                connect_managed_tcp(&default, target)
            ),
            TCP_BINDING.scope(TcpBinding::None, connect_managed_tcp(&none, target)),
        );
        default_result.unwrap();
        none_result.unwrap();
        assert_eq!(
            *default.events.lock().unwrap(),
            ["socket-v4", "bind-default", "connect"]
        );
        assert_eq!(*none.events.lock().unwrap(), ["socket-v4", "connect"]);
    }

    #[tokio::test]
    async fn managed_tcp_binding_runs_in_the_real_egress_connector_path() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let endpoint = listener.local_addr().unwrap();
        let target = TargetAddr::ip(endpoint).unwrap();
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let dialer = RecordedTcpDialer {
            events: events.clone(),
            fail_binding: false,
        };
        let connector = TokioConnector::new(ferrum2_runtime::TcpConnector::with_adapters(
            ferrum2_runtime::SystemSocketInspector,
            dialer,
            Duration::from_secs(1),
        ));
        let engine = ClientEgressEngine::new(
            vec![ClientOutboundContext::Direct].into(),
            connector,
            ferrum2_crypto::SystemClock::new(),
            ferrum2_crypto::SystemRandom,
            (Duration::from_secs(1), Duration::from_secs(1)),
            None,
            None,
        )
        .with_underlay(ferrum2_tun::UnderlayPublisher::new(), true);
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let flow = engine
            .open_tcp(ClientRequestOrigin::Dns, None, &target, None, None)
            .await
            .unwrap();
        drop(flow);
        drop(accept.await.unwrap());
        assert_eq!(
            *events.lock().unwrap(),
            ["socket-v4", "bind-fixed", "connect"]
        );

        let failed_events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let failed = RecordedTcpDialer {
            events: failed_events.clone(),
            fail_binding: true,
        };
        let connector = TokioConnector::new(ferrum2_runtime::TcpConnector::with_adapters(
            ferrum2_runtime::SystemSocketInspector,
            failed.clone(),
            Duration::from_secs(1),
        ));
        let engine = ClientEgressEngine::new(
            vec![ClientOutboundContext::Direct].into(),
            connector,
            ferrum2_crypto::SystemClock::new(),
            ferrum2_crypto::SystemRandom,
            (Duration::from_secs(1), Duration::from_secs(1)),
            None,
            None,
        )
        .with_underlay(ferrum2_tun::UnderlayPublisher::new(), true);
        assert!(
            engine
                .open_tcp(ClientRequestOrigin::Dns, None, &target, None, None)
                .await
                .is_err()
        );
        assert_eq!(*failed_events.lock().unwrap(), ["socket-v4", "bind-fixed"]);

        failed_events.lock().unwrap().clear();
        assert!(
            ferrum2_runtime::TcpDialer::connect(&failed, endpoint)
                .await
                .is_err()
        );
        assert!(failed_events.lock().unwrap().is_empty());
    }

    #[test]
    fn dns_direct_fixed_binding_maps_actual_bootstrap_as_fixed() {
        assert_eq!(
            direct_tcp_binding(ClientRequestOrigin::Dns, true),
            TcpBinding::Fixed
        );
        assert_eq!(
            direct_tcp_binding(ClientRequestOrigin::Dns, false),
            TcpBinding::None
        );
        assert_eq!(proxy_tcp_binding(true), TcpBinding::Fixed);
        assert_eq!(proxy_tcp_binding(false), TcpBinding::None);
        assert_eq!(
            direct_tcp_binding(ClientRequestOrigin::Socks, true),
            TcpBinding::DefaultIfIpv4
        );
        assert_eq!(
            direct_tcp_binding(ClientRequestOrigin::Tun, false),
            TcpBinding::DefaultIpv4Only
        );
    }

    #[derive(Clone, Default)]
    struct TraceCapture(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for &TraceCapture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("trace capture")
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn proxy() -> ferrum2_config::ClientOutboundConfig {
        ferrum2_config::ClientOutboundConfig::Shadowsocks {
            server: "198.51.100.222:62016".parse().unwrap(),
            psk: Arc::new(ferrum2_crypto::MethodPsk::aes128(*b"m16-secret-key!!")),
        }
    }

    fn selected(hops: Vec<usize>) -> EgressPlanSnapshot {
        let route = compile_selector_plans_with_roots(
            &[TaggedInbound::new("entry", 0)],
            &[
                TaggedOutbound::new("direct-a", 0),
                TaggedOutbound::new("direct-b", 1),
                TaggedOutbound::new("m16-tag-sentinel", 2),
            ],
            &[TaggedPlan::new("selected", hops)],
            &[],
            TaggedRoute::Static(vec![TaggedStaticBinding::new("entry", "selected")]),
            &["direct-a", "direct-b", "m16-tag-sentinel"],
        )
        .expect("selected plan")
        .0;
        route.select_plan_snapshot(
            0,
            ferrum2_core::route::Network::Tcp,
            &TargetAddr::domain("snapshot.invalid", 443).unwrap(),
        )
    }

    #[tokio::test]
    async fn m16_direct_pre_socket_and_m16_redaction_classify_without_side_effects() {
        assert_eq!(
            prepare_client_outbounds(Vec::new()).err().unwrap(),
            RunError::StartupProtocol
        );
        let outbounds = prepare_client_outbounds(vec![
            ferrum2_config::ClientOutboundConfig::Direct,
            ferrum2_config::ClientOutboundConfig::Direct,
            proxy(),
        ])
        .expect("closed outbound catalog");
        let connector_calls = Arc::new(AtomicUsize::new(0));
        let bind_calls = Arc::new(AtomicUsize::new(0));
        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let engine = ClientEgressEngine::new(
            outbounds,
            TokioConnector::new(FailingConnector {
                calls: Arc::clone(&connector_calls),
            }),
            SystemClock::new(),
            FixedRandom,
            (Duration::from_secs(1), Duration::from_secs(1)),
            Some(ClientUdpContext {
                manager: UdpSessionManager::new(UdpRuntimeLimits::default(), registry.clone()),
                live_ids: Arc::new(Mutex::new(HashSet::new())),
            }),
            None,
        );
        let target = TargetAddr::domain("m16-target-sentinel.invalid", 443).unwrap();
        for (name, plan, expected) in [
            ("mixed", selected(vec![0, 2]), ClientPlanFailure::Invalid),
            (
                "multi direct",
                selected(vec![0, 1]),
                ClientPlanFailure::Invalid,
            ),
            (
                "out of range",
                ferrum2_core::route::EgressPlanHandle::direct(3).snapshot_owned(),
                ClientPlanFailure::Invalid,
            ),
        ] {
            assert!(
                matches!(
                    engine
                        .open_tcp(
                            ClientRequestOrigin::Socks,
                            Some(plan.clone()),
                            &target,
                            None,
                            None,
                        )
                        .await,
                    Err(ClientOpenFailure::Plan(actual)) if actual == expected
                ),
                "TCP {name}"
            );
            let calls = Arc::clone(&bind_calls);
            assert_eq!(
                engine
                    .prepare_udp_with(plan, move |_| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        async { Err(io::Error::other("binder must not run")) }
                    })
                    .await
                    .err(),
                Some(ClientUdpPrepareFailure::Plan(expected)),
                "UDP {name}"
            );
            assert_eq!(connector_calls.load(Ordering::SeqCst), 0, "TCP {name}");
            assert_eq!(bind_calls.load(Ordering::SeqCst), 0, "UDP {name}");
            assert_eq!(registry.snapshot(), baseline, "owners {name}");
        }

        assert!(matches!(
            engine
                .open_tcp(ClientRequestOrigin::Socks, None, &target, None, None)
                .await,
            Err(ClientOpenFailure::Plan(ClientPlanFailure::Invalid))
        ));
        assert_eq!(connector_calls.load(Ordering::SeqCst), 0);

        let mixed = selected(vec![0, 2]);
        let redacted_tcp = format!(
            "{:?}",
            engine
                .open_tcp(
                    ClientRequestOrigin::Socks,
                    Some(mixed.clone()),
                    &target,
                    None,
                    None,
                )
                .await
                .err()
                .unwrap()
        );
        let redacted_udp = format!(
            "{:?}",
            engine
                .prepare_udp(ClientRequestOrigin::Socks, Some(mixed), Some(&target))
                .await
                .err()
                .unwrap()
        );
        let dns_target = TargetAddr::domain("m16-dns-sentinel.invalid", 53).unwrap();
        let direct = ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned();
        let packet_registry = OwnerRegistry::new();
        let packet_live_ids = Arc::new(Mutex::new(HashSet::new()));
        let packet_engine = ClientEgressEngine::new(
            prepare_client_outbounds(vec![ferrum2_config::ClientOutboundConfig::Direct])
                .expect("packet direct outbound"),
            TokioConnector::new(ferrum2_runtime::TcpConnector::new(Duration::from_secs(1))),
            ferrum2_crypto::SystemClock::new(),
            ferrum2_crypto::SystemRandom,
            (Duration::from_secs(1), Duration::from_secs(1)),
            Some(ClientUdpContext {
                manager: UdpSessionManager::new(
                    UdpRuntimeLimits::default(),
                    packet_registry.clone(),
                ),
                live_ids: Arc::clone(&packet_live_ids),
            }),
            None,
        );
        let mut association = packet_engine
            .prepare_udp(
                ClientRequestOrigin::Dns,
                Some(direct.clone()),
                Some(&dns_target),
            )
            .await
            .expect("redaction direct UDP association");
        let mut packet = vec![0_u8; ferrum2_runtime::MAX_UDP_WIRE_DATAGRAM_BYTES + 1];
        packet[..19].copy_from_slice(b"m16-packet-sentinel");
        let packet_error = match association.prepare_application_request(
            &packet_engine,
            &packet_engine.outbounds,
            dns_target.clone(),
            &packet,
            Instant::now(),
        ) {
            Err(UdpPlanResponseError::Packet(error)) => format!("{error:?}"),
            Err(UdpPlanResponseError::Runtime(_)) | Ok(_) => panic!("fixed packet bound error"),
        };
        drop(association);
        assert_eq!(packet_registry.snapshot(), OwnerSnapshot::default());
        assert!(
            packet_live_ids
                .lock()
                .expect("packet SIP022 IDs")
                .is_empty()
        );

        let connect_kind = match engine
            .open_tcp(
                ClientRequestOrigin::Dns,
                Some(direct),
                &dns_target,
                None,
                None,
            )
            .await
        {
            Err(ClientOpenFailure::Connect(kind)) => kind,
            _ => panic!("fixed direct connect failure"),
        };
        assert_eq!(connect_kind, ferrum2_core::ConnectErrorKind::Other);
        let reason = ferrum2_observability::Reason::RelayIo;
        let metrics = Metrics::new();
        metrics.failure(
            ferrum2_observability::Role::Client,
            ferrum2_observability::Stage::Relay,
            reason,
        );
        let trace = Arc::new(TraceCapture::default());
        let subscriber = ferrum2_observability::json_subscriber(
            Arc::clone(&trace),
            ferrum2_observability::LogLevel::Trace,
        );
        let dispatch = tracing::Dispatch::new(subscriber);
        tracing::dispatcher::with_default(&dispatch, || {
            ferrum2_observability::emit(
                ferrum2_observability::TraceRecord::new(
                    ferrum2_observability::LogLevel::Warn,
                    ferrum2_observability::Event::Failure,
                    ferrum2_observability::Role::Client,
                    ferrum2_observability::Stage::Relay,
                    ferrum2_observability::Outcome::Failed,
                )
                .with_reason(reason),
            );
        });
        let trace = String::from_utf8(trace.0.lock().expect("trace capture").clone()).unwrap();
        let metrics = metrics.encode_text().expect("closed metrics");
        assert_eq!(redacted_tcp, "Plan(Invalid)");
        assert_eq!(redacted_udp, "Plan(Invalid)");
        assert_eq!(packet_error, "Bounds");
        for sentinel in [
            "m16-target-sentinel.invalid",
            "198.51.100.222:62016",
            "m16-dns-sentinel.invalid",
            "m16-tag-sentinel",
            "m16-packet-sentinel",
            "m16-secret-key!!",
        ] {
            for output in [
                &redacted_tcp,
                &redacted_udp,
                &packet_error,
                &trace,
                &metrics,
            ] {
                assert!(!output.contains(sentinel), "leaked sentinel in {output}");
            }
        }
        assert_eq!(connector_calls.load(Ordering::SeqCst), 1);
        assert_eq!(registry.snapshot(), baseline);

        #[cfg(windows)]
        {
            assert_eq!(
                direct_tcp_binding(ClientRequestOrigin::Socks, true),
                TcpBinding::DefaultIfIpv4
            );
            assert_eq!(
                direct_tcp_binding(ClientRequestOrigin::Tun, false),
                TcpBinding::DefaultIpv4Only
            );
            assert_eq!(
                direct_tcp_binding(ClientRequestOrigin::Dns, true),
                TcpBinding::Fixed
            );
            assert_eq!(
                direct_tcp_binding(ClientRequestOrigin::Dns, false),
                TcpBinding::None
            );
            assert_eq!(proxy_tcp_binding(true), TcpBinding::Fixed);
            assert_eq!(proxy_tcp_binding(false), TcpBinding::None);
            assert!(managed_direct_ipv6_is_unsupported(
                ClientRequestOrigin::Tun,
                false
            ));
            assert!(managed_direct_ipv6_is_unsupported(
                ClientRequestOrigin::Dns,
                true
            ));
            assert!(!managed_direct_ipv6_is_unsupported(
                ClientRequestOrigin::Dns,
                false
            ));
            assert!(!managed_direct_ipv6_is_unsupported(
                ClientRequestOrigin::Socks,
                true
            ));
            assert!(super::udp::managed_direct_udp_ipv6_allowed(
                ClientRequestOrigin::Socks
            ));
            assert!(!super::udp::managed_direct_udp_ipv6_allowed(
                ClientRequestOrigin::Tun
            ));
            assert!(!super::udp::managed_direct_udp_ipv6_allowed(
                ClientRequestOrigin::Dns
            ));
            let ipv6 = TargetAddr::ip("[2001:db8::1]:443".parse().unwrap()).unwrap();
            let plan = ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned();
            let tcp = engine
                .open_tcp(
                    ClientRequestOrigin::Tun,
                    Some(plan.clone()),
                    &ipv6,
                    None,
                    None,
                )
                .await;
            assert!(
                matches!(
                    tcp,
                    Err(ClientOpenFailure::Plan(
                        ClientPlanFailure::DirectIpv6Unsupported
                    ))
                ),
                "TUN TCP direct IPv6"
            );
            assert_eq!(
                engine
                    .prepare_udp(ClientRequestOrigin::Tun, Some(plan), Some(&ipv6))
                    .await
                    .err(),
                Some(ClientUdpPrepareFailure::Plan(
                    ClientPlanFailure::DirectIpv6Unsupported
                )),
                "TUN UDP direct IPv6"
            );
            assert_eq!(connector_calls.load(Ordering::SeqCst), 1);
            assert_eq!(registry.snapshot(), baseline);
        }

        let direct = ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned();
        assert!(matches!(
            engine
                .open_tcp(
                    ClientRequestOrigin::Socks,
                    Some(direct),
                    &TargetAddr::ip("[::1]:443".parse().unwrap()).unwrap(),
                    None,
                    None,
                )
                .await,
            Err(ClientOpenFailure::Connect(
                ferrum2_core::ConnectErrorKind::Other
            ))
        ));
        assert_eq!(connector_calls.load(Ordering::SeqCst), 2);
    }
}
