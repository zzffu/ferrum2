use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;

use ferrum2_core::route::Network;
use ferrum2_core::{ConnectErrorKind, Inbound as _, LocalEndpoint, SessionReply as _, TargetAddr};
use ferrum2_dns::{DnsProxy, ProxyIngress, ProxyTransport};
use ferrum2_observability::{
    Direction, Event, Inbound, LogLevel, Outcome, Reason, Role, Stage, TraceRecord, emit,
};
use ferrum2_runtime::{
    AcceptListener, BoundedSupervisor, CancellationToken, PreparedProcessRoot, ProcessCancellation,
    ProcessFuture, relay_lifecycle,
};
use ferrum2_shadowsocks::ShadowsocksError;
use ferrum2_socks5::{
    MAX_SOCKS_UDP_DATAGRAM_BYTES, SocksCommand, SocksStream, SocksUdpAssociate, SocksUdpDatagram,
    decode_udp_datagram, encode_udp_datagram,
};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::Instant;

use super::RunError;
use super::context::{ClientContext, ClientRouting};
use super::egress::{
    ClientOpenFailure, ClientRequestOrigin, ClientUdpAssociation, UdpPlanResponseError,
    UdpSendError, composed_udp_plan_limit, send_with_lifecycle,
};
use super::observation::{
    UdpPacketPhase, finish_relay, observation_for_error, record_failure,
    record_forced_udp_sessions, record_udp_drop, record_udp_packet_error, record_udp_runtime_error,
    record_udp_terminal, run_error_for_supervisor,
};
use super::routing::{ClientTerminalRoute, relay_hijacked_tcp};
use super::tokio_io::TokioFramed;

#[cfg(test)]
use super::egress::{UdpIoFaultPlan, UdpIoOperation};
#[cfg(test)]
use super::tokio_io::TokioConnector;
#[cfg(test)]
use ferrum2_core::Connector;

struct SocksUdpEndpoint {
    socket: UdpSocket,
    peer_ip: IpAddr,
    port: Option<u16>,
    wire: Vec<u8>,
    last_valid: Instant,
    #[cfg(test)]
    io_fault: Option<Arc<UdpIoFaultPlan>>,
}

enum SocksUdpPacket<'a> {
    Valid {
        datagram: SocksUdpDatagram<'a>,
        source_port: u16,
    },
    WrongSource,
    InvalidWire,
}

impl SocksUdpEndpoint {
    async fn bind<F, Fut>(
        local_ip: Ipv4Addr,
        peer_ip: IpAddr,
        requested_port: u16,
        mut bind: F,
    ) -> io::Result<Self>
    where
        F: FnMut(SocketAddr) -> Fut,
        Fut: std::future::Future<Output = io::Result<UdpSocket>>,
    {
        Ok(Self {
            socket: bind(SocketAddrV4::new(local_ip, 0).into()).await?,
            peer_ip,
            port: (requested_port != 0).then_some(requested_port),
            wire: vec![0; MAX_SOCKS_UDP_DATAGRAM_BYTES],
            last_valid: Instant::now(),
            #[cfg(test)]
            io_fault: None,
        })
    }

    fn local_addr(&self) -> io::Result<SocketAddrV4> {
        match self.socket.local_addr()? {
            SocketAddr::V4(address) => Ok(address),
            SocketAddr::V6(_) => Err(io::Error::other("SOCKS UDP endpoint is not IPv4")),
        }
    }

    async fn receive(&mut self) -> io::Result<SocksUdpPacket<'_>> {
        #[cfg(test)]
        if self
            .io_fault
            .as_ref()
            .is_some_and(|plan| plan.fails(UdpIoOperation::ApplicationRecv))
        {
            return Err(io::Error::other("injected application receive failure"));
        }
        let (length, source) = self.socket.recv_from(&mut self.wire).await?;
        if source.ip() != self.peer_ip || self.port.is_some_and(|port| port != source.port()) {
            return Ok(SocksUdpPacket::WrongSource);
        }
        let Ok(datagram) = decode_udp_datagram(&self.wire[..length]) else {
            return Ok(SocksUdpPacket::InvalidWire);
        };
        Ok(SocksUdpPacket::Valid {
            datagram,
            source_port: source.port(),
        })
    }

    fn accept(&mut self, source_port: u16) {
        if self.port.is_none() {
            self.port = Some(source_port);
        }
        self.last_valid = Instant::now();
    }

    async fn send(&mut self, target: &TargetAddr, payload: &[u8]) -> io::Result<usize> {
        #[cfg(test)]
        if self
            .io_fault
            .as_ref()
            .is_some_and(|plan| plan.fails(UdpIoOperation::ApplicationSend))
        {
            return Err(io::Error::other("injected application send failure"));
        }
        let length = encode_udp_datagram(target, payload, &mut self.wire)
            .map_err(|_| io::Error::other("SOCKS UDP response encoding failed"))?;
        let port = self
            .port
            .ok_or_else(|| io::Error::other("SOCKS UDP source unset"))?;
        let sent = self
            .socket
            .send_to(&self.wire[..length], SocketAddr::new(self.peer_ip, port))
            .await?;
        if sent != length {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short SOCKS UDP response",
            ));
        }
        Ok(sent)
    }

    fn idle_deadline(&self, timeout: std::time::Duration) -> Instant {
        self.last_valid + timeout
    }

    #[cfg(test)]
    fn set_io_fault(&mut self, fault: Option<Arc<UdpIoFaultPlan>>) {
        self.io_fault = fault;
    }
}

pub(super) struct ClientTcpListeners {
    pub(super) listeners: Vec<TcpListener>,
    pub(super) next: AtomicUsize,
    #[cfg(test)]
    pub(super) accept_errors:
        Option<Arc<std::sync::Mutex<std::collections::VecDeque<io::ErrorKind>>>>,
}

impl AcceptListener for ClientTcpListeners {
    type Stream = (usize, tokio::net::TcpStream);

    async fn accept(&self) -> io::Result<Self::Stream> {
        let start = self.next.fetch_add(1, Ordering::Relaxed) % self.listeners.len();
        std::future::poll_fn(|task| {
            #[cfg(test)]
            if let Some(kind) = self
                .accept_errors
                .as_ref()
                .and_then(|errors| errors.lock().expect("accept error lock").pop_front())
            {
                return Poll::Ready(Err(io::Error::from(kind)));
            }
            for offset in 0..self.listeners.len() {
                let inbound = (start + offset) % self.listeners.len();
                match self.listeners[inbound].poll_accept(task) {
                    Poll::Ready(Ok((stream, _))) => {
                        if let Err(error) = stream.set_nodelay(true) {
                            return Poll::Ready(Err(error));
                        }
                        return Poll::Ready(Ok((inbound, stream)));
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => {}
                }
            }
            Poll::Pending
        })
        .await
    }
}

pub(super) struct ClientTcpRoot {
    pub(super) supervisor: Option<BoundedSupervisor<ClientTcpListeners>>,
    pub(super) context: Arc<ClientContext>,
    pub(super) routing: Arc<ClientRouting>,
}

impl PreparedProcessRoot<RunError> for ClientTcpRoot {
    fn activate(&mut self) -> Result<(), RunError> {
        Ok(())
    }

    fn run(
        mut self: Box<Self>,
        cancellation: ProcessCancellation,
    ) -> ProcessFuture<Result<(), RunError>> {
        let supervisor = self.supervisor.take().expect("prepared TCP root");
        let context = Arc::clone(&self.context);
        let routing = Arc::clone(&self.routing);
        let handler_context = Arc::clone(&context);
        let mut quiescing = cancellation.clone();
        let mut forced = cancellation.clone();
        Box::pin(async move {
            let running = supervisor.run_with_cancellation(
                move |(inbound, stream), cancellation| {
                    let context = Arc::clone(&handler_context);
                    let routing = Arc::clone(&routing);
                    async move {
                        client_connection(stream, cancellation, context, inbound, routing).await;
                    }
                },
                cancellation,
            );
            tokio::pin!(running);
            let result = tokio::select! {
                biased;
                _ = forced.forced() => {
                    record_forced_udp_sessions(&context);
                    if let Some(udp) = &context.egress.udp {
                        udp.cancel_all();
                    }
                    running.await
                }
                _ = quiescing.cancelled() => {
                    if context.runtime.shutdown_grace.is_zero() {
                        forced.forced().await;
                        record_forced_udp_sessions(&context);
                    }
                    if let Some(udp) = &context.egress.udp {
                        udp.cancel_all();
                    }
                    running.await
                }
                result = &mut running => result,
            };
            result.map_err(run_error_for_supervisor)
        })
    }

    fn rollback(self: Box<Self>) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async { Ok(()) })
    }
}

async fn client_connection(
    stream: tokio::net::TcpStream,
    mut cancellation: CancellationToken,
    context: Arc<ClientContext>,
    inbound: usize,
    routing: Arc<ClientRouting>,
) {
    let peer_ip = stream.peer_addr().ok().map(|peer| peer.ip());
    let local_addr = stream.local_addr().ok();
    let local_ip = match local_addr {
        Some(SocketAddr::V4(local)) if !local.ip().is_unspecified() => Some(*local.ip()),
        Some(SocketAddr::V4(_)) | Some(SocketAddr::V6(_)) | None => None,
    };
    let accepted = tokio::select! {
        _ = cancellation.cancelled() => return,
        result = tokio::time::timeout(
            context.runtime.handshake_timeout,
            async {
                if context.udp_associate_enabled {
                    context.inbound.accept_command(stream).await
                } else {
                    context.inbound.accept(stream).await.map(SocksCommand::Connect)
                }
            },
        ) => result,
    };
    let command = match accepted {
        Ok(Ok(command)) => command,
        Ok(Err(_)) => {
            record_failure(
                &context,
                Stage::Socks5,
                Reason::SocksProtocol,
                Outcome::Rejected,
            );
            return;
        }
        Err(_) => {
            record_failure(
                &context,
                Stage::Socks5,
                Reason::HandshakeTimeout,
                Outcome::Timeout,
            );
            return;
        }
    };
    let session = match command {
        SocksCommand::Connect(session) => session,
        SocksCommand::UdpAssociate(association) => {
            let (Some(peer_ip), Some(local_ip)) = (peer_ip, local_ip) else {
                let _ = association.reply.failed(ConnectErrorKind::Other).await;
                return;
            };
            run_udp_association(
                association,
                peer_ip,
                local_ip,
                &mut cancellation,
                Arc::clone(&context),
                (inbound, &routing),
                UdpSocket::bind,
            )
            .await;
            return;
        }
    };
    let ferrum2_core::Session {
        target,
        mut stream,
        initial_payload: _,
        reply,
    } = session;
    let terminal = routing.select_terminal(inbound, Network::Tcp, &target, None, &context.metrics);
    let plan = match terminal {
        ClientTerminalRoute::Route(plan) => plan,
        ClientTerminalRoute::Reject => {
            let _ = reply.failed(ConnectErrorKind::PolicyDenied).await;
            return;
        }
        ClientTerminalRoute::HijackDns => {
            let Some(proxy) = context
                .dns
                .as_ref()
                .and_then(|proxy| proxy.get())
                .map(Arc::clone)
            else {
                let _ = reply.failed(ConnectErrorKind::Other).await;
                return;
            };
            let Some(bound) = local_addr else {
                let _ = reply.failed(ConnectErrorKind::Other).await;
                return;
            };
            if reply.succeeded_socket(bound).await.is_err() {
                return;
            }
            relay_hijacked_tcp(
                &mut stream,
                inbound,
                &proxy,
                context.runtime.idle_timeout,
                cancellation.cancelled(),
            )
            .await;
            return;
        }
    };
    let opened = tokio::select! {
        _ = cancellation.cancelled() => return,
        result = context.egress.open_tcp(
            ClientRequestOrigin::Socks,
            Some(plan),
            &target,
            None,
            #[cfg(test)]
            None,
        ) => result,
    };
    let flow = match opened {
        Ok(flow) => flow,
        Err(ClientOpenFailure::Plan(failure)) => {
            let kind = match failure {
                #[cfg(windows)]
                super::egress::ClientPlanFailure::DirectIpv6Unsupported => ConnectErrorKind::Other,
                super::egress::ClientPlanFailure::Invalid => ConnectErrorKind::Other,
            };
            let _ = reply.failed(kind).await;
            return;
        }
        Err(ClientOpenFailure::Connect(kind)) => {
            record_failure(&context, Stage::Relay, Reason::RelayIo, Outcome::Failed);
            let _ = reply.failed(kind).await;
            return;
        }
        Err(ClientOpenFailure::Protocol(error)) => {
            let (stage, outcome, reason) = observation_for_error(error);
            record_failure(&context, stage, reason, outcome);
            let kind = match error {
                ShadowsocksError::Connect(kind) => kind,
                ShadowsocksError::Detection(_)
                | ShadowsocksError::Protocol(_)
                | ShadowsocksError::Transport(_) => ConnectErrorKind::Other,
            };
            let _ = reply.failed(kind).await;
            return;
        }
        Err(ClientOpenFailure::HandshakeTimeout) => {
            record_failure(
                &context,
                Stage::Shadowsocks,
                Reason::HandshakeTimeout,
                Outcome::Timeout,
            );
            let _ = reply.failed(ConnectErrorKind::Other).await;
            return;
        }
    };
    let bound = flow.local_socket_addr();
    if reply.succeeded_socket(bound).await.is_err() {
        record_failure(&context, Stage::Socks5, Reason::RelayIo, Outcome::Failed);
        return;
    }

    context
        .metrics
        .connection(Role::Client, Inbound::Socks5, Outcome::Accepted);
    context
        .metrics
        .active_connections_inc(Role::Client, Inbound::Socks5);
    emit(TraceRecord::new(
        LogLevel::Info,
        Event::Connection,
        Role::Client,
        Stage::Socks5,
        Outcome::Accepted,
    ));
    let mut framed = TokioFramed::new(flow);
    let relay = relay_lifecycle(
        &mut stream,
        &mut framed,
        context.runtime.idle_timeout,
        &context.registry,
        cancellation.cancelled(),
    )
    .await;
    context
        .metrics
        .active_connections_dec(Role::Client, Inbound::Socks5);
    finish_relay(&context, &framed, relay);
}

async fn run_udp_association<IO, F, Fut>(
    association: SocksUdpAssociate<IO>,
    peer_ip: IpAddr,
    local_ip: Ipv4Addr,
    cancellation: &mut CancellationToken,
    context: Arc<ClientContext>,
    route: (usize, &ClientRouting),
    mut bind: F,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    F: FnMut(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = io::Result<UdpSocket>>,
{
    let requested_port = association.source_port();
    let SocksUdpAssociate {
        mut control, reply, ..
    } = association;
    let (inbound, routing) = route;
    let static_plan = if routing.program.is_none() {
        let placeholder = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1))
            .expect("fixed valid route target");
        let plan = routing
            .legacy
            .select_plan_snapshot(inbound, Network::Udp, &placeholder);
        Some(plan)
    } else {
        None
    };
    if routing.program.is_none() && static_plan.is_none() {
        let _ = reply.failed(ConnectErrorKind::Other).await;
        return;
    }
    let endpoint = tokio::select! {
        _ = cancellation.cancelled() => return,
        endpoint = SocksUdpEndpoint::bind(local_ip, peer_ip, requested_port, &mut bind) => endpoint,
    };
    let mut endpoint = match endpoint {
        Ok(endpoint) => endpoint,
        Err(_) => {
            let _ = reply.failed(ConnectErrorKind::Other).await;
            return;
        }
    };
    let bound = match endpoint.local_addr() {
        Ok(bound) => bound,
        Err(_) => {
            let _ = reply.failed(ConnectErrorKind::Other).await;
            return;
        }
    };
    let mut static_association = if let Some(plan) = static_plan {
        let prepared = tokio::select! {
            _ = cancellation.cancelled() => return,
            prepared = context.egress.prepare_udp(
                ClientRequestOrigin::Socks,
                Some(plan),
                None,
            ) => prepared,
        };
        match prepared {
            Ok(prepared) => Some(prepared),
            Err(_) => {
                let _ = reply.failed(ConnectErrorKind::Other).await;
                return;
            }
        }
    } else {
        None
    };
    if reply.succeeded(bound).await.is_err() {
        return;
    }

    match static_association.as_mut() {
        Some(prepared) => {
            relay_udp_association(
                &mut endpoint,
                prepared,
                &mut control,
                cancellation,
                &context,
                routing,
                None,
            )
            .await;
        }
        None => {
            classify_udp_association(
                endpoint,
                &mut control,
                cancellation,
                &context,
                inbound,
                routing,
            )
            .await;
        }
    }
}

async fn relay_udp_association<IO>(
    endpoint: &mut SocksUdpEndpoint,
    prepared: &mut ClientUdpAssociation,
    control: &mut SocksStream<IO>,
    cancellation: &mut CancellationToken,
    context: &ClientContext,
    routing: &ClientRouting,
    first: Option<(TargetAddr, Vec<u8>)>,
) where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut session_cancellation = match prepared.cancellation() {
        Ok(cancellation) => cancellation,
        Err(_) => return,
    };
    let first = match first {
        Some(first) => first,
        None => {
            let mut control_byte = [0; 1];
            loop {
                let idle_deadline = match prepared.idle_deadline() {
                    Ok(deadline) => deadline,
                    Err(_) => return,
                };
                let received = tokio::select! {
                    _ = cancellation.cancelled() => return,
                    changed = session_cancellation.changed() => {
                        let _ = changed;
                        return;
                    }
                    _ = tokio::time::sleep_until(idle_deadline) => {
                        if prepared.idle_expired(idle_deadline) {
                            return;
                        }
                        continue;
                    }
                    read = control.read(&mut control_byte) => {
                        if !matches!(read, Ok(1)) {
                            return;
                        }
                        continue;
                    }
                    received = endpoint.receive() => received,
                };
                let (decoded, source_port) = match received {
                    Ok(SocksUdpPacket::Valid {
                        datagram,
                        source_port,
                    }) => (datagram, source_port),
                    Ok(SocksUdpPacket::WrongSource) => {
                        record_udp_drop(
                            context,
                            Direction::ClientToTarget,
                            Stage::Socks5,
                            Reason::Address,
                        );
                        continue;
                    }
                    Ok(SocksUdpPacket::InvalidWire) => {
                        record_udp_drop(
                            context,
                            Direction::ClientToTarget,
                            Stage::Socks5,
                            Reason::Bounds,
                        );
                        continue;
                    }
                    Err(_) => {
                        record_udp_terminal(
                            context,
                            Stage::Relay,
                            Reason::Receive,
                            Outcome::Failed,
                        );
                        return;
                    }
                };
                let encoded_target_len = decoded.encoded_target_len();
                if decoded.payload().len()
                    > prepared.payload_limit(&routing.outbounds, false, encoded_target_len)
                {
                    record_udp_drop(
                        context,
                        Direction::ClientToTarget,
                        Stage::Shadowsocks,
                        Reason::Bounds,
                    );
                    continue;
                }
                let target = decoded.to_target_addr();
                let payload = decoded.payload().to_vec();
                endpoint.accept(source_port);
                break (target, payload);
            }
        }
    };
    if prepared.activate(&context.egress).is_err() {
        record_udp_terminal(context, Stage::Shadowsocks, Reason::Random, Outcome::Failed);
        return;
    }
    if !forward_udp_request(
        prepared,
        cancellation,
        &mut session_cancellation,
        context,
        routing,
        first.0,
        first.1,
    )
    .await
    {
        return;
    }
    let mut control_byte = [0_u8; 1];
    loop {
        let idle_deadline = match prepared.idle_deadline() {
            Ok(deadline) => deadline,
            Err(_) => return,
        };
        tokio::select! {
            _ = cancellation.cancelled() => return,
            changed = session_cancellation.changed() => {
                let _ = changed;
                return;
            }
            _ = tokio::time::sleep_until(idle_deadline) => {
                if prepared.idle_expired(idle_deadline) {
                    return;
                }
            }
            read = control.read(&mut control_byte) => {
                if !matches!(read, Ok(1)) {
                    return;
                }
            }
            received = async {
                endpoint.receive().await
            } => {
                let (decoded, source_port) = match received {
                    Ok(SocksUdpPacket::Valid { datagram, source_port }) => {
                        (datagram, source_port)
                    }
                    Ok(SocksUdpPacket::WrongSource) => {
                        record_udp_drop(context, Direction::ClientToTarget, Stage::Socks5, Reason::Address);
                        continue;
                    }
                    Ok(SocksUdpPacket::InvalidWire) => {
                        record_udp_drop(context, Direction::ClientToTarget, Stage::Socks5, Reason::Bounds);
                        continue;
                    }
                    Err(_) => {
                        record_udp_terminal(context, Stage::Relay, Reason::Receive, Outcome::Failed);
                        return;
                    }
                };
                let encoded_target_len = decoded.encoded_target_len();
                if decoded.payload().len()
                    > prepared.payload_limit(&routing.outbounds, false, encoded_target_len)
                {
                    record_udp_drop(
                        context,
                        Direction::ClientToTarget,
                        Stage::Shadowsocks,
                        Reason::Bounds,
                    );
                    continue;
                }
                let target = decoded.to_target_addr();
                let payload = decoded.payload().to_vec();
                endpoint.accept(source_port);
                if !forward_udp_request(
                    prepared,
                    cancellation,
                    &mut session_cancellation,
                    context,
                    routing,
                    target,
                    payload,
                ).await {
                    return;
                }
            }
            received = async {
                prepared.receive_response_wire().await
            } => {
                let length = match received {
                    Ok(received) => received,
                    Err(_) => {
                        record_udp_terminal(context, Stage::Relay, Reason::Receive, Outcome::Failed);
                        return;
                    }
                };
                let response = match prepared.prepare_application_response(
                    &context.egress,
                    &routing.outbounds,
                    length,
                ) {
                    Ok(response) => response,
                    Err(UdpPlanResponseError::Packet(error)) => {
                        if record_udp_packet_error(
                            context,
                            Direction::TargetToClient,
                            UdpPacketPhase::ResponsePrepare,
                            error,
                        ) {
                            continue;
                        }
                        return;
                    }
                    Err(UdpPlanResponseError::Runtime(error)) => {
                        if record_udp_runtime_error(context, Direction::TargetToClient, error) {
                            continue;
                        }
                        return;
                    }
                };
                let target = response.datagram().target();
                let payload = response.datagram().payload();
                let Ok(send_deadline) = prepared.idle_deadline() else { return };
                match send_with_lifecycle(
                        endpoint.send(target, payload),
                        cancellation,
                        &mut session_cancellation,
                        send_deadline,
                    ).await {
                    Ok(_) => {}
                    Err(UdpSendError::Io) => {
                        record_udp_terminal(context, Stage::Relay, Reason::Send, Outcome::Failed);
                        return;
                    }
                    Err(UdpSendError::Cancelled) => {
                        record_udp_terminal(context, Stage::Relay, Reason::Cancelled, Outcome::Cancelled);
                        return;
                    }
                    Err(UdpSendError::Idle) => {
                        record_udp_terminal(context, Stage::Relay, Reason::Idle, Outcome::Timeout);
                        return;
                    }
                }
                context.metrics.udp_datagram(Role::Client, Direction::TargetToClient, Outcome::Accepted);
                context.metrics.add_udp_bytes(Role::Client, Direction::TargetToClient, payload.len() as u64);
                prepared.recycle_application_response(response);
            }
        }
    }
}

async fn classify_udp_association<IO>(
    mut endpoint: SocksUdpEndpoint,
    control: &mut SocksStream<IO>,
    cancellation: &mut CancellationToken,
    context: &ClientContext,
    inbound: usize,
    routing: &ClientRouting,
) where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut control_byte = [0; 1];
    let (target, payload, terminal) = loop {
        let idle_deadline = endpoint.idle_deadline(context.runtime.idle_timeout);
        let received = tokio::select! {
            _ = cancellation.cancelled() => return,
            _ = tokio::time::sleep_until(idle_deadline) => return,
            read = control.read(&mut control_byte) => {
                if !matches!(read, Ok(1)) {
                    return;
                }
                continue;
            }
            received = endpoint.receive() => received,
        };
        let (decoded, source_port) = match received {
            Ok(SocksUdpPacket::Valid {
                datagram,
                source_port,
            }) => (datagram, source_port),
            Ok(SocksUdpPacket::WrongSource) => {
                record_udp_drop(
                    context,
                    Direction::ClientToTarget,
                    Stage::Socks5,
                    Reason::Address,
                );
                continue;
            }
            Ok(SocksUdpPacket::InvalidWire) => {
                record_udp_drop(
                    context,
                    Direction::ClientToTarget,
                    Stage::Socks5,
                    Reason::Bounds,
                );
                continue;
            }
            Err(_) => {
                record_udp_terminal(context, Stage::Relay, Reason::Receive, Outcome::Failed);
                return;
            }
        };
        let target = decoded.to_target_addr();
        let terminal = routing.select_terminal(
            inbound,
            Network::Udp,
            &target,
            Some(decoded.payload()),
            &context.metrics,
        );
        if matches!(terminal, ClientTerminalRoute::Reject) {
            return;
        }
        let encoded_target_len = decoded.encoded_target_len();
        if let ClientTerminalRoute::Route(plan) = &terminal
            && decoded.payload().len()
                > composed_udp_plan_limit(
                    &routing.outbounds,
                    plan.hops(),
                    false,
                    encoded_target_len,
                )
        {
            record_udp_drop(
                context,
                Direction::ClientToTarget,
                Stage::Shadowsocks,
                Reason::Bounds,
            );
            continue;
        }
        let payload = decoded.payload().to_vec();
        endpoint.accept(source_port);
        break (target, payload, terminal);
    };

    match terminal {
        ClientTerminalRoute::Route(plan) => {
            let prepared = tokio::select! {
                _ = cancellation.cancelled() => return,
                prepared = context.egress.prepare_udp(
                    ClientRequestOrigin::Socks,
                    Some(plan),
                    Some(&target),
                ) => prepared,
            };
            let Ok(mut prepared) = prepared else {
                record_udp_terminal(context, Stage::Shadowsocks, Reason::Random, Outcome::Failed);
                return;
            };
            relay_udp_association(
                &mut endpoint,
                &mut prepared,
                control,
                cancellation,
                context,
                routing,
                Some((target, payload)),
            )
            .await;
        }
        ClientTerminalRoute::HijackDns => {
            let Some(proxy) = context
                .dns
                .as_ref()
                .and_then(|proxy| proxy.get())
                .map(Arc::clone)
            else {
                return;
            };
            relay_hijacked_udp(
                &mut endpoint,
                control,
                cancellation,
                context,
                inbound,
                &proxy,
                Some((target, payload)),
            )
            .await;
        }
        ClientTerminalRoute::Reject => unreachable!("reject terminates during classification"),
    }
}

#[allow(clippy::too_many_arguments)]
async fn forward_udp_request(
    prepared: &mut ClientUdpAssociation,
    cancellation: &mut CancellationToken,
    session_cancellation: &mut tokio::sync::watch::Receiver<bool>,
    context: &ClientContext,
    routing: &ClientRouting,
    target: TargetAddr,
    payload: Vec<u8>,
) -> bool {
    let payload_len = payload.len();
    let wire_len = match prepared.prepare_owned_application_request(
        &context.egress,
        &routing.outbounds,
        target,
        bytes::Bytes::from(payload).into(),
        Instant::now(),
    ) {
        Ok(length) => length,
        Err(UdpPlanResponseError::Packet(error)) => {
            return record_udp_packet_error(
                context,
                Direction::ClientToTarget,
                UdpPacketPhase::RequestEncode,
                error,
            );
        }
        Err(UdpPlanResponseError::Runtime(error)) => {
            return record_udp_runtime_error(context, Direction::ClientToTarget, error);
        }
    };
    let Ok(send_deadline) = prepared.idle_deadline() else {
        return false;
    };
    match send_with_lifecycle(
        prepared.send_encoded_request(wire_len),
        cancellation,
        session_cancellation,
        send_deadline,
    )
    .await
    {
        Ok(sent) if sent == wire_len => {}
        Ok(_) | Err(UdpSendError::Io) => {
            record_udp_terminal(context, Stage::Relay, Reason::Send, Outcome::Failed);
            return false;
        }
        Err(UdpSendError::Cancelled) => {
            record_udp_terminal(context, Stage::Relay, Reason::Cancelled, Outcome::Cancelled);
            return false;
        }
        Err(UdpSendError::Idle) => {
            record_udp_terminal(context, Stage::Relay, Reason::Idle, Outcome::Timeout);
            return false;
        }
    }
    context
        .metrics
        .udp_datagram(Role::Client, Direction::ClientToTarget, Outcome::Accepted);
    context
        .metrics
        .add_udp_bytes(Role::Client, Direction::ClientToTarget, payload_len as u64);
    true
}

async fn relay_hijacked_udp<IO>(
    endpoint: &mut SocksUdpEndpoint,
    control: &mut SocksStream<IO>,
    cancellation: &mut CancellationToken,
    context: &ClientContext,
    inbound: usize,
    proxy: &DnsProxy,
    first: Option<(TargetAddr, Vec<u8>)>,
) where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    if let Some((target, payload)) = first
        && !answer_hijacked_udp(endpoint, cancellation, inbound, proxy, &target, &payload).await
    {
        return;
    }
    let mut control_byte = [0; 1];
    loop {
        let idle_deadline = endpoint.idle_deadline(context.runtime.idle_timeout);
        let received = tokio::select! {
            _ = cancellation.cancelled() => return,
            _ = tokio::time::sleep_until(idle_deadline) => return,
            read = control.read(&mut control_byte) => {
                if !matches!(read, Ok(1)) {
                    return;
                }
                continue;
            }
            received = endpoint.receive() => received,
        };
        let (decoded, source_port) = match received {
            Ok(SocksUdpPacket::Valid {
                datagram,
                source_port,
            }) => (datagram, source_port),
            Ok(SocksUdpPacket::WrongSource) => {
                record_udp_drop(
                    context,
                    Direction::ClientToTarget,
                    Stage::Socks5,
                    Reason::Address,
                );
                continue;
            }
            Ok(SocksUdpPacket::InvalidWire) => {
                record_udp_drop(
                    context,
                    Direction::ClientToTarget,
                    Stage::Socks5,
                    Reason::Bounds,
                );
                continue;
            }
            Err(_) => return,
        };
        let target = decoded.to_target_addr();
        let payload = decoded.payload().to_vec();
        endpoint.accept(source_port);
        if !answer_hijacked_udp(endpoint, cancellation, inbound, proxy, &target, &payload).await {
            return;
        }
    }
}

async fn answer_hijacked_udp(
    endpoint: &mut SocksUdpEndpoint,
    cancellation: &mut CancellationToken,
    inbound: usize,
    proxy: &DnsProxy,
    target: &TargetAddr,
    request: &[u8],
) -> bool {
    let response = tokio::select! {
        _ = cancellation.cancelled() => return false,
        response = proxy.answer(
            ProxyIngress::Ordinary(inbound),
            ProxyTransport::Udp,
            request,
        ) => response,
    };
    let Some(response) = response else {
        return true;
    };
    tokio::select! {
        _ = cancellation.cancelled() => false,
        result = endpoint.send(target, &response) => result.is_ok(),
    }
}

#[cfg(test)]
pub(in crate::run) mod tests {
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::time::Duration;

    use tokio::io::AsyncWriteExt as _;

    use super::*;
    use crate::run::egress::{
        IdSequenceRandom, MAX_UDP_PLAN_HOPS, UdpIoFaultPlan, composed_udp_request_limit,
        composed_udp_response_limit,
    };
    use crate::run::test_support::*;
    use ferrum2_shadowsocks::{UdpPacketError, UdpPacketScratch};
    use ferrum2_socks5::MAX_SOCKS_UDP_DATAGRAM_BYTES;

    #[tokio::test]
    async fn local_endpoint_failure_sends_one_general_failure_and_has_no_transport() {
        let calls = Arc::new(AtomicUsize::new(0));
        let connector = TokioConnector::new(FailingConnector {
            calls: Arc::clone(&calls),
        });
        let target = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)).expect("target");
        assert!(connector.connect(&target).await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let (mut peer, application) = tokio::io::duplex(64);
        let peer_task = tokio::spawn(async move {
            peer.write_all(&[5, 1, 0]).await.expect("greeting");
            let mut method = [0_u8; 2];
            peer.read_exact(&mut method).await.expect("method");
            assert_eq!(method, [5, 0]);
            peer.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .expect("request");
            let mut reply = [0_u8; 10];
            peer.read_exact(&mut reply).await.expect("failure reply");
            reply
        });
        let session = Socks5Inbound::new()
            .accept(application)
            .await
            .expect("accepted SOCKS request");
        session
            .reply
            .failed(ConnectErrorKind::Other)
            .await
            .expect("failure reply");
        assert_eq!(
            peer_task.await.expect("peer task"),
            [5, 1, 0, 1, 0, 0, 0, 0, 0, 0]
        );
    }

    fn udp_test_context(registry: OwnerRegistry) -> (PathBuf, Arc<ClientContext>) {
        udp_test_context_for_server(registry, reserve_address())
    }

    async fn execute_test_udp_association<IO, F, Fut>(
        association: SocksUdpAssociate<IO>,
        context: Arc<ClientContext>,
        routing: Arc<ClientRouting>,
        bind: F,
    ) where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        F: FnMut(SocketAddr) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = io::Result<UdpSocket>> + Send + 'static,
    {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("token listener");
        let address = listener.local_addr().expect("token address");
        let supervisor = BoundedSupervisor::new(
            listener,
            1,
            Duration::from_secs(1),
            context.registry.clone(),
        )
        .expect("token supervisor");
        let association = Arc::new(Mutex::new(Some(association)));
        let bind = Arc::new(Mutex::new(Some(bind)));
        let (done_sender, done_receiver) = tokio::sync::oneshot::channel();
        let done_sender = Arc::new(Mutex::new(Some(done_sender)));
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();
        let run_task = tokio::spawn(supervisor.run_until(
            move |_stream, mut cancellation| {
                let association = association
                    .lock()
                    .expect("association")
                    .take()
                    .expect("one handler");
                let bind = bind.lock().expect("bind").take().expect("one binder");
                let context = Arc::clone(&context);
                let routing = Arc::clone(&routing);
                let done_sender = Arc::clone(&done_sender);
                async move {
                    run_udp_association(
                        association,
                        IpAddr::V4(Ipv4Addr::LOCALHOST),
                        Ipv4Addr::LOCALHOST,
                        &mut cancellation,
                        context,
                        (0, &routing),
                        bind,
                    )
                    .await;
                    done_sender
                        .lock()
                        .expect("done sender")
                        .take()
                        .expect("one completion")
                        .send(())
                        .expect("completion receiver");
                }
            },
            async {
                let _ = shutdown_receiver.await;
            },
        ));
        let _trigger = tokio::net::TcpStream::connect(address)
            .await
            .expect("token handler");
        done_receiver.await.expect("association completion");
        shutdown_sender.send(()).expect("token shutdown");
        assert_eq!(run_task.await.expect("token supervisor"), Ok(()));
    }

    #[tokio::test]
    async fn application_socket_setup_failure_replies_once_and_rolls_back() {
        for fail_at in 0..1 {
            let registry = OwnerRegistry::new();
            let baseline = registry.snapshot();
            let (path, context) = udp_test_context(registry.clone());
            let (association, mut peer) = parsed_udp_association().await;
            let calls = Arc::new(AtomicUsize::new(0));
            let bound = Arc::new(Mutex::new(Vec::new()));
            let bind_calls = Arc::clone(&calls);
            let bound_addresses = Arc::clone(&bound);
            tokio::time::timeout(
                Duration::from_secs(1),
                execute_test_udp_association(
                    association,
                    Arc::clone(&context),
                    Arc::new(test_routing(context.test_udp_server, default_test_psk())),
                    move |address| {
                        let call = bind_calls.fetch_add(1, Ordering::SeqCst);
                        let bound_addresses = Arc::clone(&bound_addresses);
                        async move {
                            if call == fail_at {
                                return Err(io::Error::other("injected bind failure"));
                            }
                            let socket = UdpSocket::bind(address).await?;
                            bound_addresses
                                .lock()
                                .expect("bound addresses")
                                .push(socket.local_addr()?);
                            Ok(socket)
                        }
                    },
                ),
            )
            .await
            .expect("setup failure must terminate before a UDP packet");
            let mut reply = [0; 10];
            peer.read_exact(&mut reply).await.expect("failure reply");
            assert_eq!(reply, [5, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
            assert_eq!(peer.read(&mut reply).await.expect("single reply EOF"), 0);
            assert_eq!(calls.load(Ordering::SeqCst), fail_at + 1);
            let udp = context.egress.udp.as_ref().expect("UDP context");
            assert_eq!(udp.manager.session_count(), 0);
            assert_eq!(udp.manager.buffer_budget().reserved_bytes(), 0);
            assert!(udp.live_ids.lock().expect("live IDs").is_empty());
            assert_eq!(registry.snapshot(), baseline);
            let bound = bound.lock().expect("bound addresses").clone();
            for address in bound {
                drop(UdpSocket::bind(address).await.expect("setup socket rebind"));
            }
            std::fs::remove_file(path).expect("remove config");
        }
    }

    #[tokio::test]
    async fn success_reply_write_failure_rolls_back_and_next_setup_rebinds() {
        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let (path, context) = udp_test_context(registry.clone());
        let (association, peer) = parsed_udp_association().await;
        drop(peer);
        execute_test_udp_association(
            association,
            Arc::clone(&context),
            Arc::new(test_routing(context.test_udp_server, default_test_psk())),
            UdpSocket::bind,
        )
        .await;
        let udp = context.egress.udp.as_ref().expect("UDP context");
        assert_eq!(udp.manager.session_count(), 0);
        assert_eq!(udp.manager.buffer_budget().reserved_bytes(), 0);
        assert!(udp.live_ids.lock().expect("live IDs").is_empty());
        assert_eq!(registry.snapshot(), baseline);

        let endpoint = SocksUdpEndpoint::bind(
            Ipv4Addr::LOCALHOST,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
            UdpSocket::bind,
        )
        .await
        .expect("next application endpoint");
        let application = endpoint.local_addr().expect("application address");
        let mut prepared = context
            .egress
            .prepare_udp_with(
                ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned(),
                UdpSocket::bind,
            )
            .await
            .expect("next setup");
        prepared.activate(&context.egress).expect("next activation");
        let upstream = prepared.upstream_local_addr().expect("upstream address");
        drop((endpoint, prepared));
        assert_eq!(registry.snapshot(), baseline);
        drop(
            UdpSocket::bind(application)
                .await
                .expect("application rebind"),
        );
        drop(UdpSocket::bind(upstream).await.expect("upstream rebind"));
        std::fs::remove_file(path).expect("remove config");
    }

    #[tokio::test]
    async fn application_binder_receives_the_accepted_concrete_local_ip() {
        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let (path, context) = udp_test_context(registry.clone());
        let calls = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&calls);
        let mut bind = move |address| {
            observed.lock().expect("bind calls").push(address);
            UdpSocket::bind(address)
        };
        let endpoint = SocksUdpEndpoint::bind(
            Ipv4Addr::new(127, 0, 0, 2),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
            &mut bind,
        )
        .await
        .expect("application setup");
        let mut prepared = context
            .egress
            .prepare_udp_with(
                ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned(),
                &mut bind,
            )
            .await
            .expect("setup");
        prepared.activate(&context.egress).expect("activation");
        assert_eq!(
            *calls.lock().expect("bind calls"),
            [
                SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 0).into(),
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into(),
            ]
        );
        assert_eq!(
            *endpoint.local_addr().expect("relay").ip(),
            Ipv4Addr::new(127, 0, 0, 2)
        );
        drop((endpoint, prepared));
        assert_eq!(registry.snapshot(), baseline);
        std::fs::remove_file(path).expect("remove config");
    }

    #[tokio::test(start_paused = true)]
    async fn active_idle_and_generation_cancel_return_every_owner_and_socket() {
        for terminal in ["idle", "generation-cancel"] {
            let registry = OwnerRegistry::new();
            let baseline = registry.snapshot();
            let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("upstream receiver");
            let server = match upstream.local_addr().expect("upstream address") {
                SocketAddr::V4(server) => server,
                SocketAddr::V6(_) => unreachable!("IPv4 upstream"),
            };
            let (path, context) = udp_test_context_for_server(registry.clone(), server);
            let (association, mut peer) = parsed_udp_association().await;
            let task = tokio::spawn(execute_test_udp_association(
                association,
                Arc::clone(&context),
                Arc::new(test_routing(context.test_udp_server, default_test_psk())),
                UdpSocket::bind,
            ));
            let mut reply = [0; 10];
            peer.read_exact(&mut reply).await.expect("success reply");
            assert_eq!(&reply[..4], &[5, 0, 0, 1]);
            tokio::time::resume();
            let relay = SocketAddrV4::new(
                Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
                u16::from_be_bytes([reply[8], reply[9]]),
            );
            let application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("application socket");
            let target = TargetAddr::ipv4("192.0.2.1:53".parse().expect("target")).expect("target");
            let mut request = [0; 64];
            let request_len =
                encode_udp_datagram(&target, b"committed", &mut request).expect("SOCKS request");
            application
                .send_to(&request[..request_len], relay)
                .await
                .expect("application send");
            let mut upstream_wire = [0; MAX_UDP_WIRE_LEN];
            tokio::time::timeout(Duration::from_secs(1), upstream.recv(&mut upstream_wire))
                .await
                .expect("committed request timeout")
                .expect("committed request");
            tokio::time::pause();
            let live = registry.snapshot();
            let actual = (
                live.udp_sessions,
                live.udp_buffered_bytes,
                live.udp_queued_datagrams,
                live.active_supervisor_children,
                live.connection_tasks,
            );
            let expected = (1, 3 * MAX_UDP_WIRE_LEN, 0, 1, 1);
            assert_eq!(actual, expected, "{terminal}");
            if terminal == "idle" {
                tokio::time::advance(Duration::from_secs(300)).await;
            } else {
                context
                    .egress
                    .udp
                    .as_ref()
                    .expect("UDP context")
                    .manager
                    .cancel_all();
            }
            task.await.expect("association task");
            assert_eq!(peer.read(&mut reply).await.expect("control EOF"), 0);
            assert!(
                context
                    .egress
                    .udp
                    .as_ref()
                    .expect("UDP context")
                    .live_ids
                    .lock()
                    .expect("live IDs")
                    .is_empty()
            );
            assert_eq!(registry.snapshot(), baseline, "{terminal}");
            drop(UdpSocket::bind(relay).await.expect("relay rebind"));
            std::fs::remove_file(path).expect("remove config");
        }
    }

    #[tokio::test]
    async fn udp_send_lifecycle_covers_socket_io_session_idle_and_process_cancel() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("listener");
        let address = listener.local_addr().expect("listener address");
        let supervisor =
            BoundedSupervisor::new(listener, 1, Duration::from_secs(1), OwnerRegistry::new())
                .expect("supervisor");
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();
        let (ready_sender, ready_receiver) = tokio::sync::oneshot::channel::<()>();
        let ready_sender = Arc::new(Mutex::new(Some(ready_sender)));
        let run_task = tokio::spawn(supervisor.run_until(
            move |_stream, mut cancellation| {
                let ready_sender = Arc::clone(&ready_sender);
                async move {
                    let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                        .await
                        .expect("UDP receiver");
                    let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                        .await
                        .expect("UDP sender");
                    let (_session_sender, mut session) = tokio::sync::watch::channel(false);
                    let sent = send_with_lifecycle(
                        sender.send_to(b"ok", receiver.local_addr().expect("receiver address")),
                        &mut cancellation,
                        &mut session,
                        Instant::now() + Duration::from_secs(5),
                    )
                    .await
                    .expect("send completed");
                    assert_eq!(sent, 2);
                    let mut received = [0; 2];
                    assert_eq!(receiver.recv(&mut received).await.expect("receive"), 2);

                    let unconnected = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                        .await
                        .expect("unconnected UDP");
                    assert_eq!(
                        send_with_lifecycle(
                            unconnected.send(b"failure"),
                            &mut cancellation,
                            &mut session,
                            Instant::now() + Duration::from_secs(5),
                        )
                        .await,
                        Err(UdpSendError::Io)
                    );

                    let (session_sender, mut session) = tokio::sync::watch::channel(false);
                    session_sender.send_replace(true);
                    assert_eq!(
                        send_with_lifecycle(
                            std::future::pending::<io::Result<usize>>(),
                            &mut cancellation,
                            &mut session,
                            Instant::now() + Duration::from_secs(5),
                        )
                        .await,
                        Err(UdpSendError::Cancelled)
                    );
                    let (_idle_sender, mut session) = tokio::sync::watch::channel(false);
                    assert_eq!(
                        send_with_lifecycle(
                            std::future::pending::<io::Result<usize>>(),
                            &mut cancellation,
                            &mut session,
                            Instant::now(),
                        )
                        .await,
                        Err(UdpSendError::Idle)
                    );

                    ready_sender
                        .lock()
                        .expect("ready sender")
                        .take()
                        .expect("one handler")
                        .send(())
                        .expect("ready");
                    let (_process_sender, mut session) = tokio::sync::watch::channel(false);
                    assert_eq!(
                        send_with_lifecycle(
                            std::future::pending::<io::Result<usize>>(),
                            &mut cancellation,
                            &mut session,
                            Instant::now() + Duration::from_secs(5),
                        )
                        .await,
                        Err(UdpSendError::Cancelled)
                    );
                }
            },
            async {
                let _ = shutdown_receiver.await;
            },
        ));
        let _client = tokio::net::TcpStream::connect(address)
            .await
            .expect("start handler");
        ready_receiver.await.expect("handler ready");
        shutdown_sender.send(()).expect("shutdown");
        assert_eq!(run_task.await.expect("supervisor task"), Ok(()));
    }

    struct RunningUdpRelay {
        task: tokio::task::JoinHandle<Result<(), SupervisorError>>,
        done: tokio::sync::oneshot::Receiver<()>,
        shutdown: tokio::sync::oneshot::Sender<()>,
        _trigger: tokio::net::TcpStream,
    }

    async fn start_udp_relay(
        endpoint: SocksUdpEndpoint,
        prepared: ClientUdpAssociation,
        control: SocksStream<tokio::io::DuplexStream>,
        context: Arc<ClientContext>,
        routing: Arc<ClientRouting>,
    ) -> RunningUdpRelay {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("relay owner listener");
        let address = listener.local_addr().expect("relay owner address");
        let supervisor = BoundedSupervisor::new(
            listener,
            1,
            Duration::from_secs(1),
            context.registry.clone(),
        )
        .expect("relay owner supervisor");
        let endpoint = Arc::new(Mutex::new(Some(endpoint)));
        let prepared = Arc::new(Mutex::new(Some(prepared)));
        let control = Arc::new(Mutex::new(Some(control)));
        let (done_sender, done) = tokio::sync::oneshot::channel();
        let done_sender = Arc::new(Mutex::new(Some(done_sender)));
        let (shutdown, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(supervisor.run_until(
            move |_stream, mut cancellation| {
                let mut endpoint = endpoint
                    .lock()
                    .expect("endpoint")
                    .take()
                    .expect("one endpoint");
                let mut prepared = prepared
                    .lock()
                    .expect("prepared")
                    .take()
                    .expect("one relay");
                let mut control = control
                    .lock()
                    .expect("control")
                    .take()
                    .expect("one control");
                let context = Arc::clone(&context);
                let routing = Arc::clone(&routing);
                let done_sender = Arc::clone(&done_sender);
                async move {
                    relay_udp_association(
                        &mut endpoint,
                        &mut prepared,
                        &mut control,
                        &mut cancellation,
                        &context,
                        &routing,
                        None,
                    )
                    .await;
                    let _ = done_sender
                        .lock()
                        .expect("done")
                        .take()
                        .expect("one done")
                        .send(());
                }
            },
            async {
                let _ = shutdown_receiver.await;
            },
        ));
        let trigger = tokio::net::TcpStream::connect(address)
            .await
            .expect("relay owner trigger");
        RunningUdpRelay {
            task,
            done,
            shutdown,
            _trigger: trigger,
        }
    }

    async fn finish_udp_relay(running: RunningUdpRelay) {
        tokio::time::timeout(Duration::from_secs(2), running.done)
            .await
            .expect("relay completion timeout")
            .expect("relay completion");
        running.shutdown.send(()).expect("relay owner shutdown");
        assert_eq!(running.task.await.expect("relay owner task"), Ok(()));
    }

    async fn receive_request_and_send_response(
        socket: &UdpSocket,
        server: &UdpServer,
        scratch: &mut UdpPacketScratch,
        payload: &[u8],
    ) -> SocketAddr {
        let (peer, wire, _) =
            receive_request_and_encode_response(socket, server, scratch, payload, 0).await;
        socket
            .send_to(&wire, peer)
            .await
            .expect("upstream response");
        peer
    }

    async fn receive_request_and_encode_response(
        socket: &UdpSocket,
        server: &UdpServer,
        scratch: &mut UdpPacketScratch,
        payload: &[u8],
        advance: u64,
    ) -> (SocketAddr, Vec<u8>, Vec<u8>) {
        let mut wire = [0; MAX_UDP_WIRE_LEN];
        let (length, peer) =
            tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut wire))
                .await
                .expect("upstream request timeout")
                .expect("upstream request");
        let clock = SystemClock::new();
        let random = SystemRandom;
        let pending = server
            .prepare_request(&clock, &wire[..length], scratch)
            .expect("authenticated request");
        let target = pending.datagram().target().clone();
        let (_, commit) = pending.into_parts();
        let accepted = server
            .commit_request(commit, peer, clock.monotonic_now(), &random)
            .expect("request commit");
        let response = test_datagram(target, payload);
        let mut first = Vec::new();
        let mut last = Vec::new();
        for index in 0..=advance {
            let encoded = server
                .encode_response(
                    accepted.capability(),
                    &clock,
                    &random,
                    &response,
                    0,
                    &mut wire,
                    scratch,
                )
                .expect("response encode");
            if index == 0 {
                first = wire[..encoded.wire_len()].to_vec();
            }
            if index == advance {
                last = wire[..encoded.wire_len()].to_vec();
            }
        }
        (peer, first, last)
    }
    #[tokio::test]
    async fn client_route_reject_hijack() {
        let listen = reserve_address();
        let dns_listen = reserve_address();
        let shadowsocks = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("Shadowsocks listener");
        let shadowsocks_address = match shadowsocks.local_addr().expect("Shadowsocks address") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!("IPv4 Shadowsocks listener"),
        };
        let shadowsocks_udp = UdpSocket::bind(shadowsocks_address)
            .await
            .expect("Shadowsocks UDP listener");
        let dns = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("DNS upstream");
        let dns_address = dns.local_addr().expect("DNS upstream address");
        let (path, _) = client_test_config(listen, shadowsocks_address);
        let source = format!(
            "schema_version = 2\n\
             [[inbounds]]\n\
             tag = \"i0\"\n\
             listen = \"{listen}\"\n\
             [[outbounds]]\n\
             tag = \"o0\"\n\
             server = \"{shadowsocks_address}\"\n\
             [route]\n\
             final = \"o0\"\n\
             [[route.rules]]\n\
             port = 9\n\
             action = \"reject\"\n\
             [[route.rules]]\n\
             port = 53\n\
             action = \"hijack-dns\"\n\
             [dns]\n\
             [[dns.inbounds]]\n\
             tag = \"d0\"\n\
             listen = \"{dns_listen}\"\n\
             [[dns.servers]]\n\
             tag = \"upstream\"\n\
             transport = \"udp\"\n\
             address = \"{dns_address}\"\n\
             [dns.route]\n\
             final = \"upstream\"\n\
             [shadowsocks]\n\
             method = \"2022-blake3-aes-128-gcm\"\n\
             psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n\
             [runtime]\n\
             shutdown_grace_ms = 0\n\
             [udp]\n\
             enabled = true\n\
             max_sessions = 1\n\
             max_buffered_bytes = 1048576\n"
        );
        std::fs::write(&path, source).expect("schema v2 client config");
        let config = ferrum2_config::load_client(&path).expect("client route actions");
        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let dns_task = tokio::spawn(async move {
            let mut wire = [0_u8; 4096];
            for answer in [
                Ipv4Addr::new(203, 0, 113, 70),
                Ipv4Addr::new(203, 0, 113, 71),
                Ipv4Addr::new(203, 0, 113, 72),
                Ipv4Addr::new(203, 0, 113, 73),
            ] {
                let (length, peer) = dns.recv_from(&mut wire).await.expect("DNS request");
                let request = Message::from_vec(&wire[..length]).expect("typed DNS request");
                let question = request.queries.first().expect("one question").clone();
                let mut response = Message::response(request.metadata.id, OpCode::Query);
                response
                    .add_query(question.clone())
                    .add_answer(Record::from_rdata(
                        question.name().clone(),
                        30,
                        RData::A(A(answer)),
                    ));
                dns.send_to(&response.to_vec().expect("DNS response"), peer)
                    .await
                    .expect("send DNS response");
            }
        });
        let (stop, task) = spawn_test_client(config, &registry);
        wait_until_bound(listen).await;

        let accepted = tokio::spawn(async move {
            shadowsocks
                .accept()
                .await
                .expect("route opened Shadowsocks")
                .0
        });
        let (route, reply) = socks_connect_port(listen, 80).await;
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
        let routed = accepted.await.expect("route accept task");
        drop((route, routed));

        let (mut rejected, reply) = socks_connect_port(listen, 9).await;
        assert_eq!(reply, [5, 2, 0, 1, 0, 0, 0, 0, 0, 0]);
        let mut closed = [0_u8; 1];
        assert_eq!(rejected.read(&mut closed).await.expect("reject close"), 0);

        let (mut hijacked, reply) = socks_connect_port(listen, 53).await;
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
        for id in [17, 18] {
            let mut query = Message::new(id, MessageType::Query, OpCode::Query);
            query.add_query(Query::query(
                Name::from_ascii("hijack.example.").expect("query name"),
                RecordType::A,
            ));
            let query = query.to_vec().expect("DNS query");
            hijacked
                .write_u16(u16::try_from(query.len()).expect("query frame"))
                .await
                .expect("DNS frame length");
            hijacked.write_all(&query).await.expect("DNS frame");
            let length = hijacked.read_u16().await.expect("response frame length");
            let mut response = vec![0_u8; usize::from(length)];
            hijacked
                .read_exact(&mut response)
                .await
                .expect("response frame");
            let response = Message::from_vec(&response).expect("typed DNS response");
            assert_eq!(response.metadata.id, id);
            assert_eq!(response.metadata.response_code, ResponseCode::NoError);
            assert_eq!(response.answers.len(), 1);
        }
        drop(hijacked);

        let (hijack_control, hijack_application, hijack_relay) = udp_association(listen).await;
        let hijack_target = TargetAddr::domain("hijack.example", 53).expect("UDP hijack target");
        let mut socks_wire = vec![0_u8; MAX_SOCKS_UDP_DATAGRAM_BYTES];
        for id in [19, 20] {
            let mut query = Message::new(id, MessageType::Query, OpCode::Query);
            query.add_query(Query::query(
                Name::from_ascii("hijack.example.").expect("query name"),
                RecordType::A,
            ));
            let query = query.to_vec().expect("UDP DNS query");
            let length = encode_udp_datagram(&hijack_target, &query, &mut socks_wire)
                .expect("UDP hijack request");
            hijack_application
                .send_to(&socks_wire[..length], hijack_relay)
                .await
                .expect("send UDP hijack request");
            let length = hijack_application
                .recv(&mut socks_wire)
                .await
                .expect("UDP hijack response");
            let response = decode_udp_datagram(&socks_wire[..length]).expect("SOCKS DNS response");
            assert_eq!(response.to_target_addr(), hijack_target);
            assert_eq!(
                Message::from_vec(response.payload())
                    .expect("typed response")
                    .metadata
                    .id,
                id
            );
        }
        let later = encode_udp_datagram(&hijack_target, b"not DNS", &mut socks_wire)
            .expect("later non-DNS packet");
        hijack_application
            .send_to(&socks_wire[..later], hijack_relay)
            .await
            .expect("later non-DNS packet");
        hijack_application
            .send_to(&[0, 0, 0, 9], hijack_relay)
            .await
            .expect("later malformed packet");
        tokio::task::yield_now().await;
        assert_eq!(registry.snapshot().udp_sessions, 0);
        let mut absent = [0_u8; 1];
        assert_eq!(
            shadowsocks_udp
                .try_recv(&mut absent)
                .expect_err("hijack never entered Shadowsocks")
                .kind(),
            io::ErrorKind::WouldBlock
        );
        drop(hijack_control);

        let (mut reject_control, reject_application, reject_relay) = udp_association(listen).await;
        let reject_target =
            TargetAddr::ipv4("192.0.2.9:9".parse().expect("reject target")).expect("target");
        let length =
            encode_udp_datagram(&reject_target, b"reject", &mut socks_wire).expect("reject packet");
        reject_application
            .send_to(&socks_wire[..length], reject_relay)
            .await
            .expect("send reject packet");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), reject_control.read(&mut absent))
                .await
                .expect("reject control close")
                .expect("reject control read"),
            0
        );
        assert_eq!(
            reject_application
                .try_recv(&mut absent)
                .expect_err("reject sends no UDP response")
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(registry.snapshot().udp_sessions, 0);
        assert_eq!(
            shadowsocks_udp
                .try_recv(&mut absent)
                .expect_err("reject never entered Shadowsocks")
                .kind(),
            io::ErrorKind::WouldBlock
        );

        dns_task.await.expect("DNS task");
        stop.send(()).expect("stop client");
        assert_eq!(task.await.expect("client task"), Ok(()));
        assert_eq!(active(registry.snapshot()), active(baseline));
        std::fs::remove_file(path).expect("remove config");
    }

    #[tokio::test]
    async fn routed_udp_first_valid_packet_selects_association_once() {
        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let mut upstreams = Vec::new();
        for _ in 0..5 {
            upstreams.push(
                UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                    .await
                    .expect("upstream"),
            );
        }
        let servers = upstreams
            .iter()
            .map(|socket| {
                let SocketAddr::V4(address) = socket.local_addr().expect("upstream address") else {
                    unreachable!("IPv4 upstream")
                };
                address
            })
            .collect::<Vec<_>>();
        let (path, mut context) = udp_test_context_for_server(registry.clone(), servers[0]);
        let source = format!(
            "schema_version = 2\n\
             [[inbounds]]\n\
             tag = \"i0\"\n\
             listen = \"{}\"\n\
             [[outbounds]]\n\
             tag = \"o0\"\n\
             server = \"{}\"\n\
             [[outbounds]]\n\
             tag = \"o1\"\n\
             server = \"{}\"\n\
             [[outbounds]]\n\
             tag = \"o2\"\n\
             server = \"{}\"\n\
             [[outbounds]]\n\
             tag = \"o3\"\n\
             server = \"{}\"\n\
             [[outbounds]]\n\
             tag = \"o4\"\n\
             server = \"{}\"\n\
             [[chains]]\n\
             tag = \"selected-a\"\n\
             hops = [\"o1\", \"o2\"]\n\
             [[chains]]\n\
             tag = \"selected-b\"\n\
             hops = [\"o3\", \"o4\"]\n\
             [[selectors]]\n\
             tag = \"manual\"\n\
             outbounds = [\"selected-a\", \"selected-b\"]\n\
             default = \"selected-a\"\n\
             [route]\n\
             final = \"o0\"\n\
             [[route.rules]]\n\
             inbound = \"i0\"\n\
             network = \"udp\"\n\
             action = \"sniff\"\n\
             sniffers = \"dns\"\n\
             [[route.rules]]\n\
             inbound = \"i0\"\n\
             network = \"udp\"\n\
             target = {{ host = \"query.example\", port = 53 }}\n\
             action = \"route\"\n\
             outbound = \"manual\"\n\
             [shadowsocks]\n\
             method = \"2022-blake3-aes-128-gcm\"\n\
             psk = \"AAECAwQFBgcICQoLDA0ODw==\"\n\
             [udp]\n\
             enabled = true\n\
             max_sessions = 1\n\
             max_buffered_bytes = 1048576\n",
            reserve_address(),
            servers[0],
            servers[1],
            servers[2],
            servers[3],
            servers[4],
        );
        std::fs::write(&path, source).expect("schema v2 client config");
        let config = ferrum2_config::load_client(&path).expect("schema v2 route");
        let selector = config.selector_control();
        let outbounds = prepare_client_outbounds(config.outbounds).expect("schema v2 outbounds");
        Arc::get_mut(&mut Arc::get_mut(&mut context).expect("unique context").egress)
            .expect("unique egress")
            .outbounds = Arc::clone(&outbounds);
        let routing = Arc::new(ClientRouting {
            legacy: config.route,
            program: config.route_program,
            outbounds,
        });

        let (association, mut peer) = parsed_udp_association().await;
        let task = tokio::spawn(execute_test_udp_association(
            association,
            Arc::clone(&context),
            Arc::clone(&routing),
            UdpSocket::bind,
        ));
        let mut reply = [0_u8; 10];
        peer.read_exact(&mut reply)
            .await
            .expect("UDP success reply");
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
        let relay = SocketAddrV4::new(
            Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
            u16::from_be_bytes([reply[8], reply[9]]),
        );
        let udp = context.egress.udp.as_ref().expect("UDP context");
        assert_eq!(udp.manager.session_count(), 0);
        assert_eq!(registry.snapshot().udp_buffered_bytes, 0);
        assert!(udp.live_ids.lock().expect("live IDs").is_empty());

        let application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("application");
        let wrong_source = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0))
            .await
            .expect("wrong source");
        let target = TargetAddr::domain("query.example", 53).expect("DNS target");
        let mut query = Message::new(7, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(
            Name::from_ascii("query.example.").expect("query name"),
            RecordType::A,
        ));
        let query = query.to_vec().expect("DNS query");
        let mut wire = vec![0_u8; MAX_SOCKS_UDP_DATAGRAM_BYTES];
        let valid = encode_udp_datagram(&target, &query, &mut wire).expect("valid request");

        wrong_source
            .send_to(&wire[..valid], relay)
            .await
            .expect("wrong-source request");
        wait_for_metric(
            &context.metrics,
            "ferrum2_udp_datagrams_total{role=\"client\",direction=\"client_to_target\",outcome=\"rejected\"} 1",
        )
        .await;
        assert_eq!(udp.manager.session_count(), 0);

        application
            .send_to(&[0, 0, 0, 9], relay)
            .await
            .expect("malformed request");
        wait_for_metric(
            &context.metrics,
            "ferrum2_udp_datagrams_total{role=\"client\",direction=\"client_to_target\",outcome=\"rejected\"} 2",
        )
        .await;
        wire[2] = 1;
        application
            .send_to(&wire[..valid], relay)
            .await
            .expect("fragmented request");
        wait_for_metric(
            &context.metrics,
            "ferrum2_udp_datagrams_total{role=\"client\",direction=\"client_to_target\",outcome=\"rejected\"} 3",
        )
        .await;
        assert_eq!(udp.manager.session_count(), 0);
        assert!(udp.live_ids.lock().expect("live IDs").is_empty());

        wire[2] = 0;
        let plan_limit = composed_udp_plan_limit(&routing.outbounds, &[1, 2], false, 17);
        let one_over = encode_udp_datagram(&target, &vec![0x5a; plan_limit + 1], &mut wire)
            .expect("SOCKS-valid selected-plan maximum+1");
        let unclassified = registry.snapshot();
        application
            .send_to(&wire[..one_over], relay)
            .await
            .expect("maximum+1 classification candidate");
        wait_for_metric(
            &context.metrics,
            "ferrum2_udp_datagrams_total{role=\"client\",direction=\"client_to_target\",outcome=\"rejected\"} 4",
        )
        .await;
        assert_eq!(registry.snapshot(), unclassified);
        assert_eq!(udp.manager.session_count(), 0);
        assert!(udp.live_ids.lock().expect("live IDs").is_empty());
        assert!(
            !context
                .metrics
                .encode_text()
                .expect("metrics")
                .contains("ferrum2_udp_datagrams_total{role=\"client\",direction=\"client_to_target\",outcome=\"accepted\"} 1"),
            "maximum+1 changed accepted activity"
        );
        let mut absent = [0_u8; 1];
        for upstream in &upstreams {
            assert_eq!(
                upstream
                    .try_recv(&mut absent)
                    .expect_err("maximum+1 emitted no wire")
                    .kind(),
                io::ErrorKind::WouldBlock
            );
        }

        selector
            .switch("manual", "selected-b")
            .expect("switch selector after rejected candidate");

        let accepted_application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("following valid source");
        let exact_payload = vec![0x6b; plan_limit];
        let exact = encode_udp_datagram(&target, &exact_payload, &mut wire)
            .expect("exact selected-plan maximum");
        accepted_application
            .send_to(&wire[..exact], relay)
            .await
            .expect("classification request");
        let protocol_server = UdpServer::new(&context.keys).expect("protocol server");
        let mut scratch = UdpPacketScratch::new();
        let clock = SystemClock::new();
        let random = SystemRandom;
        let (first_len, first_peer) =
            tokio::time::timeout(Duration::from_secs(2), upstreams[3].recv_from(&mut wire))
                .await
                .expect("selected first request timeout")
                .expect("selected first request");
        let outer = protocol_server
            .prepare_request(&clock, &wire[..first_len], &mut scratch)
            .expect("selected outer request");
        assert_eq!(
            outer.datagram().target(),
            &TargetAddr::ipv4(servers[4]).expect("selected inner target")
        );
        let inner_wire = outer.datagram().payload().to_vec();
        let (_, commit) = outer.into_parts();
        protocol_server
            .commit_request(commit, first_peer, clock.monotonic_now(), &random)
            .expect("selected outer commit");
        let inner = protocol_server
            .prepare_request(&clock, &inner_wire, &mut scratch)
            .expect("selected inner request");
        assert_eq!(inner.datagram().target(), &target);
        assert_eq!(inner.datagram().payload(), exact_payload);
        let (_, commit) = inner.into_parts();
        protocol_server
            .commit_request(commit, first_peer, clock.monotonic_now(), &random)
            .expect("selected inner commit");
        assert_eq!(udp.manager.session_count(), 1);
        assert_eq!(udp.live_ids.lock().expect("live IDs").len(), 2);

        selector
            .switch("manual", "selected-a")
            .expect("switch selector after terminal selection");

        let later_target =
            TargetAddr::ipv4("192.0.2.7:5353".parse().expect("later target")).expect("target");
        let later =
            encode_udp_datagram(&later_target, b"not DNS", &mut wire).expect("later request");
        accepted_application
            .send_to(&wire[..later], relay)
            .await
            .expect("later request");
        let (later_len, later_peer) =
            tokio::time::timeout(Duration::from_secs(2), upstreams[3].recv_from(&mut wire))
                .await
                .expect("selected later request timeout")
                .expect("selected later request");
        assert_eq!(later_peer, first_peer);
        let outer = protocol_server
            .prepare_request(&clock, &wire[..later_len], &mut scratch)
            .expect("selected later outer");
        assert_eq!(
            outer.datagram().target(),
            &TargetAddr::ipv4(servers[4]).expect("selected inner target")
        );
        let inner_wire = outer.datagram().payload().to_vec();
        let (_, commit) = outer.into_parts();
        protocol_server
            .commit_request(commit, later_peer, clock.monotonic_now(), &random)
            .expect("selected later outer commit");
        let inner = protocol_server
            .prepare_request(&clock, &inner_wire, &mut scratch)
            .expect("selected later inner");
        assert_eq!(inner.datagram().target(), &later_target);
        assert_eq!(inner.datagram().payload(), b"not DNS");
        let (_, commit) = inner.into_parts();
        protocol_server
            .commit_request(commit, later_peer, clock.monotonic_now(), &random)
            .expect("selected later inner commit");
        assert_eq!(udp.manager.session_count(), 1);
        assert_eq!(udp.live_ids.lock().expect("live IDs").len(), 2);
        for upstream in [&upstreams[0], &upstreams[1], &upstreams[2], &upstreams[4]] {
            assert_eq!(
                upstream
                    .try_recv(&mut absent)
                    .expect_err("ordinary route or switched selector was not entered")
                    .kind(),
                io::ErrorKind::WouldBlock
            );
        }

        drop(peer);
        task.await.expect("association task");
        assert_eq!(registry.snapshot(), baseline);
        std::fs::remove_file(path).expect("remove config");
    }
    #[tokio::test]
    async fn concrete_udp_socket_faults_release_every_owner_and_endpoint() {
        for (operation, fail_at) in [
            (UdpIoOperation::ApplicationRecv, 3),
            (UdpIoOperation::ApplicationSend, 2),
            (UdpIoOperation::UpstreamRecv, 3),
            (UdpIoOperation::UpstreamSend, 2),
        ] {
            let registry = OwnerRegistry::new();
            let baseline = registry.snapshot();
            let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("upstream server socket");
            let server_address = match upstream.local_addr().expect("upstream address") {
                SocketAddr::V4(address) => address,
                SocketAddr::V6(_) => unreachable!("IPv4 upstream"),
            };
            let (path, context) = udp_test_context_for_server(registry.clone(), server_address);
            let mut endpoint = SocksUdpEndpoint::bind(
                Ipv4Addr::LOCALHOST,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                0,
                UdpSocket::bind,
            )
            .await
            .expect("SOCKS endpoint");
            let relay = SocketAddr::V4(endpoint.local_addr().expect("relay address"));
            let mut prepared = context
                .egress
                .prepare_udp_with(
                    ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned(),
                    UdpSocket::bind,
                )
                .await
                .expect("prepared concrete relay");
            prepared
                .activate(&context.egress)
                .expect("concrete activation");
            let upstream_client = prepared.upstream_local_addr().expect("upstream client");
            let fault = Some(Arc::new(UdpIoFaultPlan::new(operation, fail_at)));
            if matches!(
                operation,
                UdpIoOperation::ApplicationRecv | UdpIoOperation::ApplicationSend
            ) {
                endpoint.set_io_fault(fault);
            } else {
                prepared.set_io_fault(fault);
            }
            let server = UdpServer::new(&context.keys).expect("protocol server");
            let (association, peer) = parsed_udp_association().await;
            let running = start_udp_relay(
                endpoint,
                prepared,
                association.control,
                Arc::clone(&context),
                Arc::new(test_routing(server_address, default_test_psk())),
            )
            .await;
            drop(association.reply);
            let application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("application socket");
            let target = TargetAddr::ipv4("192.0.2.1:53".parse().expect("target")).expect("target");
            let mut socks = [0; 128];
            let request_len =
                encode_udp_datagram(&target, b"first", &mut socks).expect("first request");
            application
                .send_to(&socks[..request_len], relay)
                .await
                .expect("first application send");
            let mut scratch = UdpPacketScratch::new();
            receive_request_and_send_response(&upstream, &server, &mut scratch, b"first-response")
                .await;
            let mut response = [0; 128];
            tokio::time::timeout(Duration::from_secs(2), application.recv(&mut response))
                .await
                .expect("first response timeout")
                .expect("first response");

            let request_len =
                encode_udp_datagram(&target, b"second", &mut socks).expect("second request");
            application
                .send_to(&socks[..request_len], relay)
                .await
                .expect("second application send");
            if operation == UdpIoOperation::ApplicationSend {
                receive_request_and_send_response(
                    &upstream,
                    &server,
                    &mut scratch,
                    b"second-response",
                )
                .await;
            }
            finish_udp_relay(running).await;
            drop(peer);
            let expected_reason = if matches!(
                operation,
                UdpIoOperation::ApplicationRecv | UdpIoOperation::UpstreamRecv
            ) {
                "receive"
            } else {
                "send"
            };
            let metrics = context.metrics.encode_text().expect("metrics");
            assert!(metrics.contains(&format!(
                "ferrum2_udp_failures_total{{role=\"client\",stage=\"relay\",reason=\"{expected_reason}\"}} 1"
            )), "{operation:?}: {metrics}");
            let udp = context.egress.udp.as_ref().expect("UDP context");
            assert_eq!(udp.manager.session_count(), 0, "{operation:?}");
            assert_eq!(
                udp.manager.buffer_budget().reserved_bytes(),
                0,
                "{operation:?}"
            );
            assert!(
                udp.live_ids.lock().expect("live IDs").is_empty(),
                "{operation:?}"
            );
            assert_eq!(registry.snapshot(), baseline, "{operation:?}");
            drop(UdpSocket::bind(relay).await.expect("relay rebind"));
            drop(
                UdpSocket::bind(upstream_client)
                    .await
                    .expect("upstream client rebind"),
            );
            std::fs::remove_file(path).expect("remove config");
        }
    }

    async fn wait_for_metric(metrics: &Metrics, needle: &str) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let text = metrics.encode_text().expect("metrics");
            if text.contains(needle) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "metric not observed: {needle}\n{text}"
            );
            tokio::task::yield_now().await;
        }
    }
    #[tokio::test]
    async fn composed_udp_boundaries_are_real_and_sequential_for_every_method_and_target() {
        let targets = [
            (
                "IPv4",
                TargetAddr::ipv4("192.0.2.1:53".parse().expect("IPv4")).expect("target"),
                7,
            ),
            (
                "IPv6",
                TargetAddr::ip("[2001:db8::1]:53".parse().expect("IPv6")).expect("target"),
                19,
            ),
            (
                "domain",
                TargetAddr::domain("example.test", 53).expect("domain"),
                16,
            ),
        ];
        for method in MethodProfile::ALL {
            for (kind, target, target_len) in &targets {
                let label = format!("{method:?}/{kind}");
                let registry = OwnerRegistry::new();
                let baseline = registry.snapshot();
                let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                    .await
                    .expect("upstream socket");
                let server_address = match upstream.local_addr().expect("upstream address") {
                    SocketAddr::V4(address) => address,
                    SocketAddr::V6(_) => unreachable!("IPv4 upstream"),
                };
                let (path, mut context) = udp_test_context_for_psk(
                    registry.clone(),
                    server_address,
                    Some(psk_for_method(method)),
                );
                let routing = Arc::new(test_routing(server_address, psk_for_method(method)));
                Arc::get_mut(
                    &mut Arc::get_mut(&mut context)
                        .expect("unique boundary context")
                        .egress,
                )
                .expect("unique boundary egress")
                .outbounds = Arc::clone(&routing.outbounds);
                let endpoint = SocksUdpEndpoint::bind(
                    Ipv4Addr::LOCALHOST,
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    0,
                    UdpSocket::bind,
                )
                .await
                .expect("SOCKS endpoint");
                let relay = SocketAddr::V4(endpoint.local_addr().expect("relay address"));
                let mut prepared = context
                    .egress
                    .prepare_udp_with(
                        ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned(),
                        UdpSocket::bind,
                    )
                    .await
                    .expect("prepared relay");
                prepared
                    .activate(&context.egress)
                    .expect("relay activation");
                let handle = prepared.handle();
                let manager = context.egress.udp.as_ref().expect("UDP").manager.clone();
                let (association, peer) = parsed_udp_association().await;
                let running = start_udp_relay(
                    endpoint,
                    prepared,
                    association.control,
                    Arc::clone(&context),
                    routing,
                )
                .await;
                drop(association.reply);
                let source_a = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                    .await
                    .expect("source A");
                let source_b = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                    .await
                    .expect("source B");
                let owner_deadline = Instant::now() + Duration::from_secs(2);
                while registry.snapshot().active_supervisor_children != 1 {
                    assert!(
                        Instant::now() < owner_deadline,
                        "relay owner startup: {label}"
                    );
                    tokio::task::yield_now().await;
                }
                let request_limit = composed_udp_request_limit(method, *target_len);
                assert_eq!(
                    request_limit,
                    max_udp_payload_len(method, false, target, 0).expect("request limit"),
                    "Shadowsocks is the request bound for {label}"
                );
                let stable_before = registry.snapshot();
                let deadline_before = manager.idle_deadline(handle).expect("pending deadline");
                let mut socks = vec![0; MAX_SOCKS_UDP_DATAGRAM_BYTES];
                let one_over =
                    encode_udp_datagram(target, &vec![0xa5; request_limit + 1], &mut socks)
                        .expect("SOCKS-valid one-over request");
                source_a
                    .send_to(&socks[..one_over], relay)
                    .await
                    .expect("one-over enters concrete relay socket");
                wait_for_metric(
                    &context.metrics,
                    "ferrum2_udp_datagrams_total{role=\"client\",direction=\"client_to_target\",outcome=\"rejected\"} 1",
                )
                .await;
                assert_eq!(
                    registry.snapshot(),
                    stable_before,
                    "one-over owners: {label}"
                );
                assert_eq!(manager.session_count(), 1, "one-over session: {label}");
                assert_eq!(
                    manager.idle_deadline(handle),
                    Ok(deadline_before),
                    "one-over activity: {label}"
                );
                let mut absent = [0; 1];
                assert_eq!(
                    upstream
                        .try_recv_from(&mut absent)
                        .expect_err("one-over not emitted")
                        .kind(),
                    io::ErrorKind::WouldBlock,
                    "{label}"
                );

                let exact_payload = vec![0x5a; request_limit];
                let exact = encode_udp_datagram(target, &exact_payload, &mut socks)
                    .expect("exact SOCKS request");
                source_a
                    .send_to(&socks[..exact], relay)
                    .await
                    .expect("exact pinned-source request");
                let mut request_wire = [0; MAX_UDP_WIRE_LEN];
                let (request_len, upstream_client) = tokio::time::timeout(
                    Duration::from_secs(2),
                    upstream.recv_from(&mut request_wire),
                )
                .await
                .expect("exact upstream timeout")
                .expect("exact upstream request");
                let server = UdpServer::new(&context.keys).expect("protocol server");
                let clock = SystemClock::new();
                let random = SystemRandom;
                let mut scratch = UdpPacketScratch::new();
                let pending = server
                    .prepare_request(&clock, &request_wire[..request_len], &mut scratch)
                    .expect("exact authenticated request");
                assert_eq!(pending.datagram().target(), target, "target: {label}");
                assert_eq!(
                    pending.datagram().payload(),
                    exact_payload,
                    "payload: {label}"
                );
                let (_, commit) = pending.into_parts();
                let request_activity = clock.monotonic_now();
                let accepted = server
                    .commit_request(commit, upstream_client, request_activity, &random)
                    .expect("exact request commit");
                let server_snapshot = server
                    .session_snapshot(accepted.capability())
                    .expect("server snapshot")
                    .expect("server session");
                assert_eq!(
                    server_snapshot.highest_packet_id(),
                    Some(0),
                    "packet ID: {label}"
                );
                assert_eq!(server_snapshot.peer(), upstream_client, "pin: {label}");
                assert_eq!(
                    server_snapshot.last_activity(),
                    request_activity,
                    "server activity: {label}"
                );
                let committed_deadline = manager.idle_deadline(handle).expect("committed deadline");
                assert!(
                    committed_deadline >= deadline_before,
                    "request activity: {label}"
                );
                assert_eq!(
                    registry.snapshot().udp_queued_datagrams,
                    0,
                    "request queue: {label}"
                );

                let response_limit = composed_udp_response_limit(method, *target_len);
                assert_eq!(
                    response_limit,
                    max_udp_payload_len(method, true, target, 0).expect("response limit"),
                    "Shadowsocks is the response bound for {label}"
                );
                let response_payload = vec![0x6b; response_limit];
                let response = test_datagram(target.clone(), &response_payload);
                let mut response_wire = vec![0; MAX_UDP_WIRE_LEN];
                let encoded = server
                    .encode_response(
                        accepted.capability(),
                        &clock,
                        &random,
                        &response,
                        0,
                        &mut response_wire,
                        &mut scratch,
                    )
                    .expect("exact response encode");
                let response_wire_len = encoded.wire_len();
                upstream
                    .send_to(&response_wire[..response_wire_len], encoded.peer())
                    .await
                    .expect("exact response send");
                let mut emitted = vec![0; MAX_SOCKS_UDP_DATAGRAM_BYTES];
                let emitted_len =
                    tokio::time::timeout(Duration::from_secs(2), source_a.recv(&mut emitted))
                        .await
                        .expect("SOCKS response timeout")
                        .expect("SOCKS response");
                let decoded =
                    decode_udp_datagram(&emitted[..emitted_len]).expect("SOCKS response decode");
                assert_eq!(
                    decoded.to_target_addr(),
                    *target,
                    "response target: {label}"
                );
                assert_eq!(
                    decoded.payload(),
                    response_payload,
                    "response payload: {label}"
                );
                assert_eq!(
                    emitted_len,
                    response_limit + 3 + target_len,
                    "emission bound: {label}"
                );
                if *kind == "IPv6" {
                    assert_eq!(emitted_len - response_limit, 22, "IPv6 SOCKS header");
                }
                assert_eq!(
                    source_b
                        .try_recv(&mut absent)
                        .expect_err("source B stays unpinned")
                        .kind(),
                    io::ErrorKind::WouldBlock,
                    "{label}"
                );
                wait_for_metric(
                    &context.metrics,
                    "ferrum2_udp_datagrams_total{role=\"client\",direction=\"target_to_client\",outcome=\"accepted\"} 1",
                )
                .await;
                let client_deadline = manager.idle_deadline(handle).expect("response activity");
                let client_state = registry.snapshot();
                assert_eq!(
                    client_state.udp_queued_datagrams, 0,
                    "response queue: {label}"
                );
                assert_eq!(
                    client_state.udp_buffered_bytes,
                    3 * MAX_UDP_WIRE_LEN,
                    "allocation: {label}"
                );

                let oversized = test_datagram(target.clone(), &vec![0x7c; response_limit + 1]);
                assert_eq!(
                    server
                        .encode_response(
                            accepted.capability(),
                            &clock,
                            &random,
                            &oversized,
                            0,
                            &mut response_wire,
                            &mut scratch,
                        )
                        .expect_err("SS response max+1 rejected before emission"),
                    UdpPacketError::Bounds,
                    "{label}"
                );
                assert_eq!(
                    registry.snapshot(),
                    client_state,
                    "max+1 client owners: {label}"
                );
                assert_eq!(
                    manager.idle_deadline(handle),
                    Ok(client_deadline),
                    "max+1 client activity: {label}"
                );
                assert_eq!(
                    source_a
                        .try_recv(&mut absent)
                        .expect_err("max+1 has no wire emission")
                        .kind(),
                    io::ErrorKind::WouldBlock,
                    "{label}"
                );

                upstream
                    .send_to(&response_wire[..response_wire_len], upstream_client)
                    .await
                    .expect("duplicate response send");
                wait_for_metric(
                    &context.metrics,
                    "ferrum2_udp_replay_rejections_total{role=\"client\",direction=\"target_to_client\",reason=\"duplicate\"} 1",
                )
                .await;
                assert_eq!(
                    manager.idle_deadline(handle),
                    Ok(client_deadline),
                    "replay activity: {label}"
                );
                assert_eq!(registry.snapshot(), client_state, "replay owners: {label}");
                assert_eq!(
                    source_a
                        .try_recv(&mut absent)
                        .expect_err("replay has no emission")
                        .kind(),
                    io::ErrorKind::WouldBlock,
                    "{label}"
                );

                drop(peer);
                finish_udp_relay(running).await;
                assert_eq!(registry.snapshot(), baseline, "closed: {label}");
                std::fs::remove_file(path).expect("remove config");
            }
        }
    }
    #[tokio::test]
    async fn udp_chain_layers_mixed_credentials_bounds_and_response_binding() {
        for methods in [
            [
                MethodProfile::Blake3Aes128Gcm2022,
                MethodProfile::Blake3Aes256Gcm2022,
            ],
            [
                MethodProfile::Blake3Aes256Gcm2022,
                MethodProfile::Blake3ChaCha20Poly13052022,
            ],
            [
                MethodProfile::Blake3ChaCha20Poly13052022,
                MethodProfile::Blake3Aes128Gcm2022,
            ],
        ] {
            stock_udp_chain_case(methods, false).await;
        }
    }
    #[tokio::test]
    async fn udp_chain_selector_snapshots_and_cross_plan_binding() {
        let upstreams = [
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("shared outer A"),
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("inner B"),
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("inner C"),
        ];
        let servers: [SocketAddrV4; 3] = upstreams.each_ref().map(|socket| {
            let SocketAddr::V4(address) = socket.local_addr().expect("upstream address") else {
                unreachable!("IPv4 upstream")
            };
            address
        });
        let methods = [
            MethodProfile::Blake3Aes128Gcm2022,
            MethodProfile::Blake3Aes256Gcm2022,
            MethodProfile::Blake3ChaCha20Poly13052022,
        ];
        let tagged = [
            TaggedOutbound::new("a", 0),
            TaggedOutbound::new("b", 1),
            TaggedOutbound::new("c", 2),
        ];
        let plans = [
            TaggedPlan::new("a-b", vec![0, 1]),
            TaggedPlan::new("a-c", vec![0, 2]),
        ];

        let static_listen = reserve_address();
        let (static_path, mut static_config) = client_udp_test_config(static_listen, servers[0]);
        static_config.outbounds = servers
            .into_iter()
            .zip(methods)
            .map(
                |(server, method)| ferrum2_config::ClientOutboundConfig::Shadowsocks {
                    server: server.into(),
                    psk: psk_for_method(method),
                },
            )
            .collect();
        let (static_route, static_selector) = compile_selector_plans(
            &[TaggedInbound::new("entry", 0)],
            &tagged,
            &plans,
            &[SelectorDefinition::new(
                "manual",
                vec!["a-b", "a-c"],
                Some("a-b"),
            )],
            TaggedRoute::Static(vec![TaggedStaticBinding::new("entry", "manual")]),
        )
        .expect("static chain selector");
        static_config.route = static_route;
        static_config.udp.as_mut().expect("UDP config").max_sessions = 2;
        let static_registry = OwnerRegistry::new();
        let (stop, task) = spawn_test_client(static_config, &static_registry);
        wait_until_bound(static_listen).await;
        let first = udp_association(static_listen).await;
        static_selector
            .switch("manual", "a-c")
            .expect("switch static chain");
        let second = udp_association(static_listen).await;
        let target = TargetAddr::ipv4("192.0.2.40:53".parse().expect("target")).expect("target");
        let mut socks = [0; 64];
        let length = encode_udp_datagram(&target, b"snapshot", &mut socks).expect("request");
        let outer_keys =
            MethodKeyAdapter::new(MethodSinglePskProvider::new(psk_for_method(methods[0])));
        let outer_server = UdpServer::new(&outer_keys).expect("outer protocol");
        let clock = SystemClock::new();
        let mut scratch = UdpPacketScratch::new();
        let mut wire = vec![0; MAX_UDP_WIRE_LEN];
        let mut relays = Vec::new();
        for ((control, application, relay), expected) in [(first, servers[1]), (second, servers[2])]
        {
            application
                .send_to(&socks[..length], relay)
                .await
                .expect("static chain send");
            let received =
                tokio::time::timeout(Duration::from_secs(2), upstreams[0].recv(&mut wire))
                    .await
                    .expect("static chain timeout")
                    .expect("static chain request");
            assert_eq!(
                outer_server
                    .prepare_request(&clock, &wire[..received], &mut scratch)
                    .expect("static outer")
                    .datagram()
                    .target(),
                &TargetAddr::ipv4(expected).expect("expected inner")
            );
            relays.push(relay);
            drop((control, application));
        }
        stop.send(()).expect("stop static selector client");
        assert_eq!(task.await.expect("static selector client"), Ok(()));
        for relay in relays {
            drop(UdpSocket::bind(relay).await.expect("static relay rebind"));
        }
        assert_eq!(active(static_registry.snapshot()), OwnerSnapshot::default());
        std::fs::remove_file(static_path).expect("remove static config");

        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let (path, mut context) = udp_test_context_for_psk(
            registry.clone(),
            servers[0],
            Some(psk_for_method(methods[0])),
        );
        let outbounds = prepare_client_outbounds(
            servers
                .into_iter()
                .zip(methods)
                .map(
                    |(server, method)| ferrum2_config::ClientOutboundConfig::Shadowsocks {
                        server: server.into(),
                        psk: psk_for_method(method),
                    },
                )
                .collect(),
        )
        .expect("routed chain outbounds");
        let (route, selector) = compile_selector_plans(
            &[TaggedInbound::new("entry", 0)],
            &tagged,
            &plans,
            &[SelectorDefinition::new(
                "manual",
                vec!["a-b", "a-c"],
                Some("a-b"),
            )],
            TaggedRoute::Routed {
                rules: vec![TaggedRouteRule::new(
                    Some("entry"),
                    Some(Network::Udp),
                    Some(target.clone()),
                    Some("manual"),
                )],
                final_outbound: Some("a-b"),
            },
        )
        .expect("routed chain selector");
        let selected = route.select_plan_snapshot(0, Network::Udp, &target);
        assert_eq!(selected.hops(), &[0, 1]);
        let egress = Arc::get_mut(
            &mut Arc::get_mut(&mut context)
                .expect("unique routed context")
                .egress,
        )
        .expect("unique routed egress");
        egress.outbounds = Arc::clone(&outbounds);
        egress.udp_id_random = Some(Arc::new(IdSequenceRandom::new([0x41, 0x42])));
        let routing = Arc::new(ClientRouting {
            legacy: route,
            program: None,
            outbounds,
        });
        let endpoint = SocksUdpEndpoint::bind(
            Ipv4Addr::LOCALHOST,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
            UdpSocket::bind,
        )
        .await
        .expect("routed SOCKS endpoint");
        let relay = endpoint.local_addr().expect("routed relay");
        let prepared = context
            .egress
            .prepare_udp_with(selected, UdpSocket::bind)
            .await
            .expect("routed chain preparation");
        let (association, peer) = parsed_udp_association().await;
        let running = start_udp_relay(
            endpoint,
            prepared,
            association.control,
            Arc::clone(&context),
            Arc::clone(&routing),
        )
        .await;
        drop(association.reply);
        let application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("routed application");
        let routed_outer = UdpServer::new(&routing.outbounds[0].shadowsocks().unwrap().keys)
            .expect("outer protocol");
        let random = SystemRandom;

        for label in ["before switch", "after switch"] {
            application
                .send_to(&socks[..length], relay)
                .await
                .expect("routed chain send");
            let (received, peer) = upstreams[0]
                .recv_from(&mut wire)
                .await
                .expect("routed chain request");
            let pending = routed_outer
                .prepare_request(&clock, &wire[..received], &mut scratch)
                .expect("routed outer");
            assert_eq!(
                pending.datagram().target(),
                &TargetAddr::ipv4(servers[1]).expect("captured B target"),
                "{label}"
            );
            let (_, commit) = pending.into_parts();
            routed_outer
                .commit_request(commit, peer, clock.monotonic_now(), &random)
                .expect("commit routed outer");
            if label == "before switch" {
                selector
                    .switch("manual", "a-c")
                    .expect("switch routed selector");
            }
        }
        assert_eq!(
            context
                .egress
                .udp
                .as_ref()
                .expect("UDP")
                .live_ids
                .lock()
                .expect("live IDs")
                .len(),
            2
        );
        drop(peer);
        finish_udp_relay(running).await;
        assert_eq!(registry.snapshot(), baseline);
        drop(UdpSocket::bind(relay).await.expect("routed relay rebind"));
        std::fs::remove_file(path).expect("remove routed config");
    }
    #[tokio::test]
    async fn udp_chain_invalid_inner_state_and_shutdown_are_atomic() {
        stock_udp_chain_case(
            [
                MethodProfile::Blake3Aes128Gcm2022,
                MethodProfile::Blake3Aes256Gcm2022,
            ],
            true,
        )
        .await;
        eight_hop_udp_chain_rejects_before_admission_and_uses_fixed_buffers().await;
    }

    async fn eight_hop_udp_chain_rejects_before_admission_and_uses_fixed_buffers() {
        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let mut upstreams = Vec::new();
        for _ in 0..MAX_UDP_PLAN_HOPS {
            upstreams.push(
                UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                    .await
                    .expect("eight-hop upstream"),
            );
        }
        let servers = upstreams
            .iter()
            .map(
                |socket| match socket.local_addr().expect("upstream address") {
                    SocketAddr::V4(address) => address,
                    SocketAddr::V6(_) => unreachable!("IPv4 upstream"),
                },
            )
            .collect::<Vec<_>>();
        let methods = (0..MAX_UDP_PLAN_HOPS)
            .map(|hop| MethodProfile::ALL[hop % MethodProfile::ALL.len()])
            .collect::<Vec<_>>();
        let outbounds = prepare_client_outbounds(
            servers
                .iter()
                .copied()
                .zip(methods.iter().copied())
                .map(
                    |(server, method)| ferrum2_config::ClientOutboundConfig::Shadowsocks {
                        server: server.into(),
                        psk: psk_for_method(method),
                    },
                )
                .collect(),
        )
        .expect("eight-hop outbounds");
        let tags = ["o0", "o1", "o2", "o3", "o4", "o5", "o6", "o7"];
        let tagged_outbounds = tags
            .iter()
            .enumerate()
            .map(|(hop, tag)| TaggedOutbound::new(tag, hop))
            .collect::<Vec<_>>();
        let hops = (0..MAX_UDP_PLAN_HOPS).collect::<Vec<_>>();
        let (route, _) = compile_selector_plans(
            &[TaggedInbound::new("entry", 0)],
            &tagged_outbounds,
            &[TaggedPlan::new("chain", hops.clone())],
            &[],
            TaggedRoute::Static(vec![TaggedStaticBinding::new("entry", "chain")]),
        )
        .expect("eight-hop route");
        let plan = route.select_plan_snapshot(
            0,
            Network::Udp,
            &TargetAddr::domain("eight-hop.test", 53).expect("eight-hop target"),
        );
        let routing = Arc::new(ClientRouting {
            legacy: route,
            program: None,
            outbounds,
        });
        let (path, mut context) = udp_test_context_for_psk(
            registry.clone(),
            servers[0],
            Some(psk_for_method(methods[0])),
        );
        Arc::get_mut(
            &mut Arc::get_mut(&mut context)
                .expect("unique eight-hop context")
                .egress,
        )
        .expect("unique eight-hop egress")
        .outbounds = Arc::clone(&routing.outbounds);
        let endpoint = SocksUdpEndpoint::bind(
            Ipv4Addr::LOCALHOST,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
            UdpSocket::bind,
        )
        .await
        .expect("eight-hop SOCKS endpoint");
        let relay = endpoint.local_addr().expect("relay");
        let prepared = context
            .egress
            .prepare_udp_with(plan, UdpSocket::bind)
            .await
            .expect("eight-hop preparation");
        let manager = context.egress.udp.as_ref().expect("UDP").manager.clone();
        let (association, peer) = parsed_udp_association().await;
        let running = start_udp_relay(
            endpoint,
            prepared,
            association.control,
            Arc::clone(&context),
            Arc::clone(&routing),
        )
        .await;
        drop(association.reply);
        let application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("application");
        while registry.snapshot().active_supervisor_children != 1 {
            tokio::task::yield_now().await;
        }
        let target =
            TargetAddr::ip("[2001:db8::1]:53".parse().expect("IPv6 target")).expect("target");
        let limit = composed_udp_plan_limit(&routing.outbounds, &hops, false, 19);
        let mut socks = vec![0; MAX_SOCKS_UDP_DATAGRAM_BYTES];
        let one_over = encode_udp_datagram(&target, &vec![0x5a; limit + 1], &mut socks)
            .expect("SOCKS-valid eight-hop maximum+1");
        let stable = registry.snapshot();
        application
            .send_to(&socks[..one_over], relay)
            .await
            .expect("maximum+1 send");
        wait_for_metric(
            &context.metrics,
            "ferrum2_udp_datagrams_total{role=\"client\",direction=\"client_to_target\",outcome=\"rejected\"} 1",
        )
        .await;
        assert_eq!(registry.snapshot(), stable);
        assert_eq!(
            manager.session_count(),
            1,
            "schema-v1 setup owner stays pending after an over-bound packet"
        );
        assert_eq!(
            context
                .egress
                .udp
                .as_ref()
                .expect("UDP")
                .live_ids
                .lock()
                .expect("live IDs")
                .len(),
            0
        );
        for socket in &upstreams {
            assert_eq!(
                socket
                    .try_recv(&mut [0])
                    .expect_err("maximum+1 emitted no hop")
                    .kind(),
                io::ErrorKind::WouldBlock
            );
        }

        let payload = vec![0x6b; limit];
        let exact =
            encode_udp_datagram(&target, &payload, &mut socks).expect("exact eight-hop maximum");
        application
            .send_to(&socks[..exact], relay)
            .await
            .expect("exact send");
        let mut wire = vec![0; MAX_UDP_WIRE_LEN];
        let (wire_len, request_peer) =
            tokio::time::timeout(Duration::from_secs(2), upstreams[0].recv_from(&mut wire))
                .await
                .expect("eight-hop request timeout")
                .expect("eight-hop request");
        assert_eq!(wire_len, MAX_UDP_WIRE_LEN);
        let clock = SystemClock::new();
        let random = SystemRandom;
        let mut nested = wire[..wire_len].to_vec();
        for layer in 0..MAX_UDP_PLAN_HOPS {
            let server = UdpServer::new(&routing.outbounds[layer].shadowsocks().unwrap().keys)
                .expect("hop server");
            let mut scratch = UdpPacketScratch::new();
            let pending = server
                .prepare_request(&clock, &nested, &mut scratch)
                .expect("hop credential");
            let expected = if layer + 1 == MAX_UDP_PLAN_HOPS {
                target.clone()
            } else {
                TargetAddr::ipv4(servers[layer + 1]).expect("next hop")
            };
            assert_eq!(pending.datagram().target(), &expected, "hop {layer}");
            let next = pending.datagram().payload().to_vec();
            let (_, commit) = pending.into_parts();
            let accepted = server
                .commit_request(commit, request_peer, clock.monotonic_now(), &random)
                .expect("hop commit");
            assert_eq!(
                server
                    .session_snapshot(accepted.capability())
                    .expect("hop snapshot")
                    .expect("hop session")
                    .highest_packet_id(),
                Some(0),
                "hop {layer} packet ID"
            );
            nested = next;
        }
        assert_eq!(nested, payload);
        for socket in upstreams.iter().skip(1) {
            assert_eq!(
                socket
                    .try_recv(&mut [0])
                    .expect_err("only hop A receives")
                    .kind(),
                io::ErrorKind::WouldBlock
            );
        }
        assert_eq!(
            context
                .egress
                .udp
                .as_ref()
                .expect("UDP")
                .live_ids
                .lock()
                .expect("live IDs")
                .len(),
            MAX_UDP_PLAN_HOPS
        );
        assert_eq!(registry.snapshot().udp_queued_datagrams, 0);

        drop(peer);
        finish_udp_relay(running).await;
        assert!(
            context
                .egress
                .udp
                .as_ref()
                .expect("UDP")
                .live_ids
                .lock()
                .expect("live IDs")
                .is_empty()
        );
        assert_eq!(registry.snapshot(), baseline);
        drop(UdpSocket::bind(relay).await.expect("relay rebind"));
        std::fs::remove_file(path).expect("remove config");
    }

    async fn stock_udp_chain_case(methods: [MethodProfile; 2], invalid_inner: bool) {
        let listen = reserve_address();
        let upstreams = [
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("outer upstream"),
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("inner upstream"),
        ];
        let servers: [SocketAddrV4; 2] = upstreams.each_ref().map(|socket| {
            let SocketAddr::V4(address) = socket.local_addr().expect("upstream address") else {
                unreachable!("IPv4 upstream")
            };
            address
        });
        let (path, config) = client_udp_chain_test_config(listen, servers, methods);
        let bound_outbounds = prepare_client_outbounds(
            servers
                .into_iter()
                .zip(methods)
                .map(
                    |(server, method)| ferrum2_config::ClientOutboundConfig::Shadowsocks {
                        server: server.into(),
                        psk: psk_for_method(method),
                    },
                )
                .collect(),
        )
        .expect("bound outbounds");
        let keys = methods.map(|method| {
            MethodKeyAdapter::new(MethodSinglePskProvider::new(psk_for_method(method)))
        });
        let protocols = keys
            .each_ref()
            .map(|keys| UdpServer::new(keys).expect("protocol server"));
        let registry = OwnerRegistry::new();
        let (stop, task) = spawn_test_client(config, &registry);
        wait_until_bound(listen).await;
        let (control, application, relay) = udp_association(listen).await;
        let target = TargetAddr::ipv4("192.0.2.1:53".parse().expect("target")).expect("target");
        let mut socks = vec![0; MAX_SOCKS_UDP_DATAGRAM_BYTES];
        let socks_len = encode_udp_datagram(&target, b"ping", &mut socks).expect("SOCKS request");
        application
            .send_to(&socks[..socks_len], relay)
            .await
            .expect("application send");

        let clock = SystemClock::new();
        let random = SystemRandom;
        let mut scratch = UdpPacketScratch::new();
        let mut wire = vec![0; MAX_UDP_WIRE_LEN];
        let (outer_len, peer) =
            tokio::time::timeout(Duration::from_secs(2), upstreams[0].recv_from(&mut wire))
                .await
                .expect("outer request timeout")
                .expect("outer request");
        let outer = protocols[0]
            .prepare_request(&clock, &wire[..outer_len], &mut scratch)
            .expect("outer credential");
        let wrong_outer_keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(
            other_psk_for_method(methods[0]),
        ));
        assert!(
            UdpServer::new(&wrong_outer_keys)
                .expect("wrong outer server")
                .prepare_request(&clock, &wire[..outer_len], &mut scratch)
                .is_err(),
            "wrong outer PSK authenticated"
        );
        assert_eq!(
            outer.datagram().target(),
            &TargetAddr::ipv4(servers[1]).expect("inner target")
        );
        let inner_wire = outer.datagram().payload().to_vec();
        let (_, outer_commit) = outer.into_parts();
        let outer_accepted = protocols[0]
            .commit_request(outer_commit, peer, clock.monotonic_now(), &random)
            .expect("outer commit");
        let inner = protocols[1]
            .prepare_request(&clock, &inner_wire, &mut scratch)
            .expect("inner credential");
        let wrong_inner_keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(
            other_psk_for_method(methods[1]),
        ));
        assert!(
            UdpServer::new(&wrong_inner_keys)
                .expect("wrong inner server")
                .prepare_request(&clock, &inner_wire, &mut scratch)
                .is_err(),
            "wrong inner PSK authenticated"
        );
        assert_eq!(inner.datagram().target(), &target);
        assert_eq!(inner.datagram().payload(), b"ping");
        assert_eq!(
            upstreams[1]
                .try_recv(&mut [0])
                .expect_err("only first hop receives network traffic")
                .kind(),
            io::ErrorKind::WouldBlock
        );
        let (_, inner_commit) = inner.into_parts();
        let inner_accepted = protocols[1]
            .commit_request(inner_commit, peer, clock.monotonic_now(), &random)
            .expect("inner commit");

        let inner_response = protocols[1]
            .encode_response(
                inner_accepted.capability(),
                &clock,
                &random,
                &test_datagram(target.clone(), b"pong"),
                0,
                &mut wire,
                &mut scratch,
            )
            .expect("inner response");
        let inner_wire = wire[..inner_response.wire_len()].to_vec();
        if invalid_inner {
            let stable = active(registry.snapshot());
            let wrong_intermediate = protocols[0]
                .encode_response(
                    outer_accepted.capability(),
                    &clock,
                    &random,
                    &test_datagram(target.clone(), &inner_wire),
                    0,
                    &mut wire,
                    &mut scratch,
                )
                .expect("wrong intermediate wrapper");
            upstreams[0]
                .send_to(&wire[..wrong_intermediate.wire_len()], peer)
                .await
                .expect("wrong intermediate send");
            assert!(
                tokio::time::timeout(Duration::from_millis(100), application.recv(&mut socks))
                    .await
                    .is_err(),
                "wrong intermediate reached the application"
            );
            assert_eq!(active(registry.snapshot()), stable);

            let mut tampered = inner_wire.clone();
            *tampered.last_mut().expect("inner wire") ^= 1;
            let invalid_outer = protocols[0]
                .encode_response(
                    outer_accepted.capability(),
                    &clock,
                    &random,
                    &test_datagram(
                        TargetAddr::ipv4(servers[1]).expect("inner target"),
                        &tampered,
                    ),
                    0,
                    &mut wire,
                    &mut scratch,
                )
                .expect("invalid inner wrapper");
            upstreams[0]
                .send_to(&wire[..invalid_outer.wire_len()], peer)
                .await
                .expect("invalid response send");
            assert!(
                tokio::time::timeout(Duration::from_millis(100), application.recv(&mut socks))
                    .await
                    .is_err(),
                "invalid inner reached the application"
            );
            assert_eq!(active(registry.snapshot()), stable);

            let outer_tamper = protocols[0]
                .encode_response(
                    outer_accepted.capability(),
                    &clock,
                    &random,
                    &test_datagram(
                        TargetAddr::ipv4(servers[1]).expect("inner target"),
                        &inner_wire,
                    ),
                    0,
                    &mut wire,
                    &mut scratch,
                )
                .expect("outer tamper wrapper");
            let mut outer_tamper = wire[..outer_tamper.wire_len()].to_vec();
            *outer_tamper.last_mut().expect("outer wire") ^= 1;
            upstreams[0]
                .send_to(&outer_tamper, peer)
                .await
                .expect("outer tamper send");
            assert!(
                tokio::time::timeout(Duration::from_millis(100), application.recv(&mut socks))
                    .await
                    .is_err(),
                "tampered outer reached the application"
            );
            assert_eq!(active(registry.snapshot()), stable);
        }
        let outer_response = protocols[0]
            .encode_response(
                outer_accepted.capability(),
                &clock,
                &random,
                &test_datagram(
                    TargetAddr::ipv4(servers[1]).expect("inner target"),
                    &inner_wire,
                ),
                0,
                &mut wire,
                &mut scratch,
            )
            .expect("outer response");
        upstreams[0]
            .send_to(&wire[..outer_response.wire_len()], peer)
            .await
            .expect("outer response send");
        let received = tokio::time::timeout(Duration::from_secs(2), application.recv(&mut socks))
            .await
            .expect("application response timeout")
            .expect("application response");
        let response = decode_udp_datagram(&socks[..received]).expect("SOCKS response");
        assert_eq!(response.to_target_addr(), target);
        assert_eq!(response.payload(), b"pong");

        if invalid_inner {
            let stable = active(registry.snapshot());
            upstreams[0]
                .send_to(&wire[..outer_response.wire_len()], peer)
                .await
                .expect("outer replay send");
            assert!(
                tokio::time::timeout(Duration::from_millis(100), application.recv(&mut socks))
                    .await
                    .is_err(),
                "outer replay reached the application"
            );
            assert_eq!(active(registry.snapshot()), stable);

            let fresh_outer = protocols[0]
                .encode_response(
                    outer_accepted.capability(),
                    &clock,
                    &random,
                    &test_datagram(
                        TargetAddr::ipv4(servers[1]).expect("inner target"),
                        &inner_wire,
                    ),
                    0,
                    &mut wire,
                    &mut scratch,
                )
                .expect("fresh outer replayed inner");
            upstreams[0]
                .send_to(&wire[..fresh_outer.wire_len()], peer)
                .await
                .expect("fresh outer send");
            assert!(
                tokio::time::timeout(Duration::from_millis(100), application.recv(&mut socks))
                    .await
                    .is_err(),
                "fresh outer replayed inner reached the application"
            );
            assert_eq!(active(registry.snapshot()), stable);

            let next_inner = protocols[1]
                .encode_response(
                    inner_accepted.capability(),
                    &clock,
                    &random,
                    &test_datagram(target.clone(), b"next"),
                    0,
                    &mut wire,
                    &mut scratch,
                )
                .expect("next inner response");
            let next_inner = wire[..next_inner.wire_len()].to_vec();
            let next_outer = protocols[0]
                .encode_response(
                    outer_accepted.capability(),
                    &clock,
                    &random,
                    &test_datagram(
                        TargetAddr::ipv4(servers[1]).expect("inner target"),
                        &next_inner,
                    ),
                    0,
                    &mut wire,
                    &mut scratch,
                )
                .expect("next outer response");
            upstreams[0]
                .send_to(&wire[..next_outer.wire_len()], peer)
                .await
                .expect("next response send");
            let received =
                tokio::time::timeout(Duration::from_secs(2), application.recv(&mut socks))
                    .await
                    .expect("next response timeout")
                    .expect("next response");
            assert_eq!(
                decode_udp_datagram(&socks[..received])
                    .expect("next SOCKS response")
                    .payload(),
                b"next"
            );
        }

        if !invalid_inner {
            for (case, (target, encoded_target_len)) in [
                (
                    TargetAddr::ipv4("192.0.2.2:53".parse().expect("IPv4")).expect("target"),
                    7,
                ),
                (TargetAddr::domain("example.test", 53).expect("domain"), 16),
                (
                    TargetAddr::ip("[2001:db8::1]:53".parse().expect("IPv6")).expect("target"),
                    19,
                ),
            ]
            .into_iter()
            .enumerate()
            {
                let limit =
                    composed_udp_plan_limit(&bound_outbounds, &[0, 1], false, encoded_target_len);
                let before = protocols[0]
                    .session_snapshot(outer_accepted.capability())
                    .expect("outer snapshot")
                    .expect("outer generation")
                    .highest_packet_id();
                let too_large = vec![0; limit + 1];
                let length = encode_udp_datagram(&target, &too_large, &mut socks)
                    .expect("SOCKS-valid nested maximum+1");
                application
                    .send_to(&socks[..length], relay)
                    .await
                    .expect("maximum+1 send");
                assert!(
                    tokio::time::timeout(Duration::from_millis(100), upstreams[0].recv(&mut wire))
                        .await
                        .is_err(),
                    "nested maximum+1 reached outer hop"
                );
                assert_eq!(
                    protocols[0]
                        .session_snapshot(outer_accepted.capability())
                        .expect("outer snapshot")
                        .expect("outer generation")
                        .highest_packet_id(),
                    before
                );

                let exact = vec![case as u8; limit];
                let length =
                    encode_udp_datagram(&target, &exact, &mut socks).expect("exact nested maximum");
                application
                    .send_to(&socks[..length], relay)
                    .await
                    .expect("exact send");
                let (length, request_peer) =
                    tokio::time::timeout(Duration::from_secs(2), upstreams[0].recv_from(&mut wire))
                        .await
                        .expect("exact request timeout")
                        .expect("exact request");
                let outer = protocols[0]
                    .prepare_request(&clock, &wire[..length], &mut scratch)
                    .expect("exact outer");
                assert_eq!(
                    outer.datagram().target(),
                    &TargetAddr::ipv4(servers[1]).expect("inner target")
                );
                let inner_wire = outer.datagram().payload().to_vec();
                let (_, commit) = outer.into_parts();
                protocols[0]
                    .commit_request(commit, request_peer, clock.monotonic_now(), &random)
                    .expect("exact outer commit");
                let inner = protocols[1]
                    .prepare_request(&clock, &inner_wire, &mut scratch)
                    .expect("exact inner");
                assert_eq!(inner.datagram().target(), &target);
                assert_eq!(inner.datagram().payload(), exact);
                let (_, commit) = inner.into_parts();
                protocols[1]
                    .commit_request(commit, request_peer, clock.monotonic_now(), &random)
                    .expect("exact inner commit");
                assert_eq!(
                    protocols[0]
                        .session_snapshot(outer_accepted.capability())
                        .expect("outer snapshot")
                        .expect("outer generation")
                        .highest_packet_id(),
                    Some(case as u64 + 1)
                );
            }
        }

        stop.send(()).expect("stop client");
        assert_eq!(task.await.expect("client"), Ok(()));
        drop((control, application));
        std::fs::remove_file(path).expect("remove chain config");
        assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
    }
}
