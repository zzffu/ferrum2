use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;

use ferrum2_core::route::Network;
use ferrum2_core::{
    ConnectErrorKind, Datagram, Inbound as _, LocalEndpoint, SessionReply as _, TargetAddr,
};
use ferrum2_observability::{
    Direction, Event, Inbound, LogLevel, Outcome, Reason, Role, Stage, TraceRecord, emit,
};
use ferrum2_runtime::{
    AcceptListener, BoundedSupervisor, CancellationToken, PreparedProcessRoot, ProcessCancellation,
    ProcessFuture, UdpDirection, relay_lifecycle,
};
use ferrum2_shadowsocks::ShadowsocksError;
use ferrum2_socks5::{
    SocksCommand, SocksStream, SocksUdpAssociate, decode_udp_datagram, encode_udp_datagram,
};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::Instant;

use super::RunError;
use super::context::{ClientContext, ClientRouting};
use super::egress::{
    ClientOpenFailure, ClientUdpAssociation, UdpPlanResponseError, UdpSendError,
    composed_udp_plan_limit, send_with_lifecycle,
};
use super::observation::{
    UdpPacketPhase, finish_relay, observation_for_error, record_failure,
    record_forced_udp_sessions, record_udp_drop, record_udp_packet_error, record_udp_runtime_error,
    record_udp_terminal, run_error_for_supervisor,
};
use super::tokio_io::TokioFramed;

#[cfg(test)]
use super::egress::UdpIoOperation;
#[cfg(test)]
use super::tokio_io::TokioConnector;
#[cfg(test)]
use ferrum2_core::Connector;

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
    let local_ip = match stream.local_addr() {
        Ok(SocketAddr::V4(local)) if !local.ip().is_unspecified() => Some(*local.ip()),
        Ok(SocketAddr::V4(_)) | Ok(SocketAddr::V6(_)) | Err(_) => None,
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
    let plan = routing
        .route
        .select_plan_snapshot(inbound, Network::Tcp, &target);
    let opened = tokio::select! {
        _ = cancellation.cancelled() => return,
        result = context.egress.open_tcp(
            plan,
            &target,
            None,
            #[cfg(test)]
            None,
        ) => result,
    };
    let flow = match opened {
        Ok(flow) => flow,
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
    bind: F,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    F: FnMut(SocketAddrV4) -> Fut,
    Fut: std::future::Future<Output = io::Result<UdpSocket>>,
{
    let requested_port = association.source_port();
    let SocksUdpAssociate {
        mut control, reply, ..
    } = association;
    let (inbound, routing) = route;
    let static_plan = if routing.route.is_routed() {
        None
    } else {
        let placeholder = TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1))
            .expect("fixed valid route target");
        let plan = routing
            .route
            .select_plan_snapshot(inbound, Network::Udp, &placeholder);
        let server = plan
            .hops()
            .first()
            .and_then(|hop| routing.outbounds.get(*hop))
            .map(|outbound| outbound.udp_server);
        server.map(|server| (plan, server))
    };
    if !routing.route.is_routed() && static_plan.is_none() {
        let _ = reply.failed(ConnectErrorKind::Other).await;
        return;
    }
    let prepared = tokio::select! {
        _ = cancellation.cancelled() => return,
        prepared = context.egress.prepare_udp(local_ip, static_plan, bind) => prepared,
    };
    let mut prepared = match prepared {
        Ok(prepared) => prepared,
        Err(()) => {
            let _ = reply.failed(ConnectErrorKind::Other).await;
            return;
        }
    };
    let bound = match prepared.application.local_addr() {
        Ok(SocketAddr::V4(bound)) => bound,
        Ok(SocketAddr::V6(_)) | Err(_) => {
            let _ = reply.failed(ConnectErrorKind::Other).await;
            return;
        }
    };
    if reply.succeeded(bound).await.is_err() {
        return;
    }

    relay_udp_association(
        &mut prepared,
        &mut control,
        peer_ip,
        requested_port,
        cancellation,
        &context,
        route,
    )
    .await;
}

async fn relay_udp_association<IO>(
    prepared: &mut ClientUdpAssociation,
    control: &mut SocksStream<IO>,
    peer_ip: IpAddr,
    requested_port: u16,
    cancellation: &mut CancellationToken,
    context: &ClientContext,
    route: (usize, &ClientRouting),
) where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let (inbound, routing) = route;
    let mut endpoint_port = (requested_port != 0).then_some(requested_port);
    let mut session_cancellation = match prepared.cancellation() {
        Ok(cancellation) => cancellation,
        Err(_) => return,
    };
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
                #[cfg(test)]
                if prepared.io_fault.as_ref().is_some_and(|plan| plan.fails(UdpIoOperation::ApplicationRecv)) {
                    return Err(io::Error::other("injected application receive failure"));
                }
                prepared.application.recv_from(&mut prepared.application_wire).await
            } => {
                let (length, source) = match received {
                    Ok(received) => received,
                    Err(_) => {
                        record_udp_terminal(context, Stage::Relay, Reason::Receive, Outcome::Failed);
                        return;
                    }
                };
                if source.ip() != peer_ip || endpoint_port.is_some_and(|port| port != source.port()) {
                    record_udp_drop(context, Direction::ClientToTarget, Stage::Socks5, Reason::Address);
                    continue;
                }
                let decoded = match decode_udp_datagram(&prepared.application_wire[..length]) {
                    Ok(decoded) => decoded,
                    Err(_) => {
                        record_udp_drop(context, Direction::ClientToTarget, Stage::Socks5, Reason::Bounds);
                        continue;
                    }
                };
                let payload_len = decoded.payload().len();
                let encoded_target_len = decoded.encoded_target_len();
                let target = decoded.to_target_addr();
                let plan = match &prepared.static_plan {
                    Some(plan) => plan.clone(),
                    None => routing
                        .route
                        .select_plan_snapshot(inbound, Network::Udp, &target),
                };
                let Some(server) = plan
                    .hops()
                    .first()
                    .and_then(|hop| routing.outbounds.get(*hop))
                    .map(|outbound| outbound.udp_server)
                else {
                    return;
                };
                if payload_len > composed_udp_plan_limit(
                    &routing.outbounds,
                    plan.hops(),
                    false,
                    encoded_target_len,
                ) {
                    record_udp_drop(context, Direction::ClientToTarget, Stage::Shadowsocks, Reason::Bounds);
                    continue;
                }
                let reservation = match prepared.reserve_application_datagram(payload_len) {
                    Ok(reservation) => reservation,
                    Err(error) => {
                        if record_udp_runtime_error(context, Direction::ClientToTarget, error) {
                            continue;
                        }
                        return;
                    }
                };
                let payload = decoded.payload().into();
                if prepared
                    .activate(&context.egress, &routing.outbounds, &plan)
                    .is_err()
                {
                    record_udp_terminal(context, Stage::Shadowsocks, Reason::Random, Outcome::Failed);
                    return;
                }
                let datagram = Datagram::new(target, payload, payload_len)
                    .expect("validated borrowed SOCKS payload");
                if let Err(error) = prepared.commit_application_datagram(
                    reservation,
                    datagram,
                    Instant::now(),
                ) {
                    if record_udp_runtime_error(context, Direction::ClientToTarget, error) {
                        continue;
                    }
                    return;
                }
                if endpoint_port.is_none() {
                    endpoint_port = Some(source.port());
                }
                let Some(datagram) = prepared.pop(UdpDirection::ToTarget).ok().flatten() else {
                    return;
                };
                let wire_len = match prepared.encode_request(
                    &context.egress,
                    &routing.outbounds,
                    &plan,
                    datagram.datagram(),
                ) {
                    Ok(length) => length,
                    Err(error) => {
                        if record_udp_packet_error(
                            context,
                            Direction::ClientToTarget,
                            UdpPacketPhase::RequestEncode,
                            error,
                        ) {
                            continue;
                        }
                        return;
                    }
                };
                let Ok(send_deadline) = prepared.idle_deadline() else { return };
                #[cfg(test)]
                if prepared.io_fault.as_ref().is_some_and(|plan| plan.fails(UdpIoOperation::UpstreamSend)) {
                    record_udp_terminal(context, Stage::Relay, Reason::Send, Outcome::Failed);
                    return;
                }
                match send_with_lifecycle(
                        async {
                            match prepared.static_server {
                                Some(_) => prepared.upstream.send(&prepared.upstream_wire[..wire_len]).await,
                                None => prepared.upstream.send_to(
                                    &prepared.upstream_wire[..wire_len],
                                    SocketAddr::V4(server),
                                ).await,
                            }
                        },
                        cancellation,
                        &mut session_cancellation,
                        send_deadline,
                    ).await {
                    Ok(sent) if sent == wire_len => {}
                    Ok(_) | Err(UdpSendError::Io) => {
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
                context.metrics.udp_datagram(Role::Client, Direction::ClientToTarget, Outcome::Accepted);
                context.metrics.add_udp_bytes(Role::Client, Direction::ClientToTarget, payload_len as u64);
            }
            received = async {
                #[cfg(test)]
                if prepared.io_fault.as_ref().is_some_and(|plan| plan.fails(UdpIoOperation::UpstreamRecv)) {
                    return Err(io::Error::other("injected upstream receive failure"));
                }
                match prepared.static_server {
                    Some(server) => prepared
                        .upstream
                        .recv(&mut prepared.upstream_wire)
                        .await
                        .map(|length| (length, SocketAddr::V4(server))),
                    None => prepared.upstream.recv_from(&mut prepared.upstream_wire).await,
                }
            } => {
                let (length, source) = match received {
                    Ok(received) => received,
                    Err(_) => {
                        record_udp_terminal(context, Stage::Relay, Reason::Receive, Outcome::Failed);
                        return;
                    }
                };
                let SocketAddr::V4(source) = source else {
                    record_udp_drop(context, Direction::TargetToClient, Stage::Shadowsocks, Reason::Address);
                    continue;
                };
                let payload_len = match prepared.accept_response(
                    &context.egress,
                    &routing.outbounds,
                    source,
                    length,
                ) {
                    Ok(Some(payload_len)) => payload_len,
                    Ok(None) => {
                        record_udp_drop(context, Direction::TargetToClient, Stage::Shadowsocks, Reason::Address);
                        continue;
                    }
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
                let Some(datagram) = prepared.pop(UdpDirection::ToClient).ok().flatten() else {
                    return;
                };
                let wire_len = match encode_udp_datagram(
                    datagram.datagram().target(),
                    datagram.datagram().payload(),
                    &mut prepared.application_wire,
                ) {
                    Ok(length) => length,
                    Err(_) => return,
                };
                let Some(port) = endpoint_port else { return };
                let endpoint = SocketAddr::new(peer_ip, port);
                let Ok(send_deadline) = prepared.idle_deadline() else { return };
                #[cfg(test)]
                if prepared.io_fault.as_ref().is_some_and(|plan| plan.fails(UdpIoOperation::ApplicationSend)) {
                    record_udp_terminal(context, Stage::Relay, Reason::Send, Outcome::Failed);
                    return;
                }
                match send_with_lifecycle(
                        prepared.application.send_to(&prepared.application_wire[..wire_len], endpoint),
                        cancellation,
                        &mut session_cancellation,
                        send_deadline,
                    ).await {
                    Ok(sent) if sent == wire_len => {}
                    Ok(_) | Err(UdpSendError::Io) => {
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
                context.metrics.add_udp_bytes(Role::Client, Direction::TargetToClient, payload_len as u64);
            }
        }
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
    use ferrum2_shadowsocks::{UdpClientSession, UdpPacketError, UdpPacketScratch};
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
        bind: F,
    ) where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        F: FnMut(SocketAddrV4) -> Fut + Send + 'static,
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
                let server = context.test_udp_server;
                let routing = test_routing(server, default_test_psk());
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
    async fn first_and_second_socket_setup_failures_reply_once_and_roll_back() {
        for fail_at in 0..2 {
            let registry = OwnerRegistry::new();
            let baseline = registry.snapshot();
            let (path, context) = udp_test_context(registry.clone());
            let (association, mut peer) = parsed_udp_association().await;
            let calls = Arc::new(AtomicUsize::new(0));
            let bound = Arc::new(Mutex::new(Vec::new()));
            let bind_calls = Arc::clone(&calls);
            let bound_addresses = Arc::clone(&bound);
            execute_test_udp_association(association, Arc::clone(&context), move |address| {
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
            })
            .await;
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
        execute_test_udp_association(association, Arc::clone(&context), |address| {
            UdpSocket::bind(address)
        })
        .await;
        let udp = context.egress.udp.as_ref().expect("UDP context");
        assert_eq!(udp.manager.session_count(), 0);
        assert_eq!(udp.manager.buffer_budget().reserved_bytes(), 0);
        assert!(udp.live_ids.lock().expect("live IDs").is_empty());
        assert_eq!(registry.snapshot(), baseline);

        let prepared = context
            .egress
            .prepare_udp(
                Ipv4Addr::LOCALHOST,
                Some((
                    ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned(),
                    context.test_udp_server,
                )),
                UdpSocket::bind,
            )
            .await
            .expect("next setup");
        let application = prepared
            .application
            .local_addr()
            .expect("application address");
        let upstream = prepared.upstream.local_addr().expect("upstream address");
        drop(prepared);
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
        let prepared = context
            .egress
            .prepare_udp(
                Ipv4Addr::new(127, 0, 0, 2),
                Some((
                    ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned(),
                    context.test_udp_server,
                )),
                move |address| {
                    observed.lock().expect("bind calls").push(address);
                    UdpSocket::bind(address)
                },
            )
            .await
            .expect("setup");
        assert_eq!(
            *calls.lock().expect("bind calls"),
            [
                SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 0),
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
            ]
        );
        assert_eq!(
            prepared.application.local_addr().expect("relay").ip(),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))
        );
        drop(prepared);
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
                UdpSocket::bind,
            ));
            let mut reply = [0; 10];
            peer.read_exact(&mut reply).await.expect("success reply");
            assert_eq!(&reply[..4], &[5, 0, 0, 1]);
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
        prepared: ClientUdpAssociation,
        control: SocksStream<tokio::io::DuplexStream>,
        context: Arc<ClientContext>,
        routing: Arc<ClientRouting>,
        inbound: usize,
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
        let prepared = Arc::new(Mutex::new(Some(prepared)));
        let control = Arc::new(Mutex::new(Some(control)));
        let (done_sender, done) = tokio::sync::oneshot::channel();
        let done_sender = Arc::new(Mutex::new(Some(done_sender)));
        let (shutdown, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(supervisor.run_until(
            move |_stream, mut cancellation| {
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
                        &mut prepared,
                        &mut control,
                        IpAddr::V4(Ipv4Addr::LOCALHOST),
                        0,
                        &mut cancellation,
                        &context,
                        (inbound, &routing),
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
    async fn routed_udp_uses_lazy_endpoint_legs_and_rejects_cross_leg_responses() {
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
        let servers: Vec<SocketAddrV4> = upstreams
            .iter()
            .map(|socket| match socket.local_addr().expect("upstream") {
                SocketAddr::V4(address) => address,
                SocketAddr::V6(_) => unreachable!("IPv4 upstream"),
            })
            .collect();
        let static_listen = reserve_address();
        let (static_path, mut static_config) = tagged_client_test_config(
            &[(static_listen, servers[0]), (reserve_address(), servers[1])],
            true,
        );
        static_config.inbounds.truncate(1);
        static_config.udp.as_mut().expect("UDP config").max_sessions = 2;
        let (route, _) = compile_selector_route(
            &[TaggedInbound::new("i0", 0)],
            &[TaggedOutbound::new("o0", 0), TaggedOutbound::new("o1", 1)],
            &[SelectorDefinition::new(
                "manual",
                vec!["o0", "o1"],
                Some("o0"),
            )],
            TaggedRoute::Static(vec![TaggedStaticBinding::new("i0", "manual")]),
        )
        .expect("static selector route");
        static_config.route = route;
        let selector = static_config.selector_control();
        let static_registry = OwnerRegistry::new();
        let (static_stop, static_task) = spawn_test_client(static_config, &static_registry);
        wait_until_bound(static_listen).await;
        let first = udp_association(static_listen).await;
        selector.switch("manual", "o1").expect("switch to B");
        let second = udp_association(static_listen).await;
        let static_target =
            TargetAddr::ipv4("192.0.2.1:53".parse().expect("target")).expect("target");
        let mut static_wire = [0; 64];
        let length = encode_udp_datagram(&static_target, b"snapshot", &mut static_wire)
            .expect("static request");
        let mut received = [0; MAX_UDP_WIRE_LEN];
        for ((control, application, relay), upstream) in
            [(first, &upstreams[0]), (second, &upstreams[1])]
        {
            application
                .send_to(&static_wire[..length], relay)
                .await
                .expect("static association send");
            tokio::time::timeout(Duration::from_secs(2), upstream.recv_from(&mut received))
                .await
                .expect("static association timeout")
                .expect("static association snapshot");
            drop(control);
        }
        static_stop.send(()).expect("stop static client");
        assert_eq!(static_task.await.expect("static client"), Ok(()));
        std::fs::remove_file(static_path).expect("remove static config");

        let (path, context) = udp_test_context_for_psk(
            registry.clone(),
            servers[0],
            Some(psk_for_method(MethodProfile::Blake3Aes128Gcm2022)),
        );
        let targets: Vec<TargetAddr> = (0..5)
            .map(|index| {
                TargetAddr::ipv4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 53 + index))
                    .expect("target")
            })
            .collect();
        let outbound = |server| ClientOutboundContext {
            tcp_server: TargetAddr::ipv4(server).expect("server"),
            udp_server: server,
            keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(psk_for_method(
                MethodProfile::Blake3Aes128Gcm2022,
            ))),
        };
        let tags = ["o0", "o1", "o2", "o3", "o4", "o5"];
        let outbounds: [_; 6] =
            std::array::from_fn(|index| TaggedOutbound::new(tags[index], index));
        let (route, selector) = compile_selector_route(
            &[TaggedInbound::new("i1", 1)],
            &outbounds,
            &[
                SelectorDefinition::new("manual", vec!["o4", "o5"], Some("o4")),
                SelectorDefinition::new("nested", vec!["manual"], Some("manual")),
            ],
            TaggedRoute::Routed {
                rules: targets
                    .iter()
                    .enumerate()
                    .map(|(index, target)| {
                        TaggedRouteRule::new(
                            Some("i1"),
                            Some(Network::Udp),
                            Some(target.clone()),
                            Some(if index == 4 {
                                "nested"
                            } else {
                                ["o0", "o1", "o2", "o3"][index]
                            }),
                        )
                    })
                    .collect(),
                final_outbound: Some("o5"),
            },
        )
        .expect("routed selector route");
        let routing = Arc::new(ClientRouting {
            route,
            outbounds: vec![
                outbound(servers[0]),
                outbound(servers[1]),
                outbound(servers[2]),
                outbound(servers[0]),
                outbound(servers[4]),
                outbound(servers[3]),
            ]
            .into(),
        });
        let prepared = context
            .egress
            .prepare_udp(Ipv4Addr::LOCALHOST, None, UdpSocket::bind)
            .await
            .expect("routed preparation");
        let relay = match prepared.application.local_addr().expect("relay") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!("IPv4 relay"),
        };
        let handle = prepared.handle;
        let (association, peer) = parsed_udp_association().await;
        let running = start_udp_relay(
            prepared,
            association.control,
            Arc::clone(&context),
            Arc::clone(&routing),
            1,
        )
        .await;
        drop(association.reply);
        let application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("application");
        while registry.snapshot().active_supervisor_children != 1 {
            tokio::task::yield_now().await;
        }
        let protocol_servers: Vec<UdpServer> = (0..5)
            .map(|_| UdpServer::new(&context.keys).expect("server protocol"))
            .collect();
        let udp = context.egress.udp.as_ref().expect("UDP");
        let state = || {
            (
                udp.manager.idle_deadline(handle).expect("deadline"),
                udp.live_ids.lock().expect("IDs").len(),
                registry.snapshot(),
            )
        };
        macro_rules! reject {
            ($direction:literal, $source:expr, $wire:expr, $peer:expr, $count:expr, $label:expr) => {{
                let before = state();
                $source.send_to($wire, $peer).await.expect($label);
                wait_for_metric(&context.metrics, &format!(
                    "ferrum2_udp_datagrams_total{{role=\"client\",direction=\"{}\",outcome=\"rejected\"}} {}",
                    $direction, $count,
                )).await;
                assert_eq!(state(), before, "{} mutated state", $label);
                for socket in [&application, &upstreams[4], &upstreams[3]] {
                    let mut byte = [0];
                    assert_eq!(socket.try_recv(&mut byte).expect_err($label).kind(), io::ErrorKind::WouldBlock);
                }
            }};
        }
        let application_wrong = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0))
            .await
            .expect("wrong source");
        let mut socks = vec![0; MAX_SOCKS_UDP_DATAGRAM_BYTES];
        let valid = encode_udp_datagram(&targets[4], b"invalid", &mut socks).expect("request");

        let request_limit =
            composed_udp_request_limit(context.egress.udp.as_ref().expect("UDP").method, 7);
        for (index, label) in [
            "wrong-source request",
            "fragment request",
            "over-bound request",
        ]
        .into_iter()
        .enumerate()
        {
            socks[2] = u8::from(index == 1);
            let length = if index == 2 {
                encode_udp_datagram(&targets[4], &vec![0; request_limit + 1], &mut socks)
                    .expect("SOCKS-valid over-bound request")
            } else {
                valid
            };
            let source = if index == 0 {
                &application_wrong
            } else {
                &application
            };
            reject!(
                "client_to_target",
                source,
                &socks[..length],
                relay,
                index + 1,
                label
            );
        }
        socks[2] = 0;

        let budget = udp.manager.buffer_budget();
        let mut saturation = Vec::new();
        let mut available = ferrum2_runtime::MIN_UDP_MAX_BUFFERED_BYTES - budget.reserved_bytes();
        while available != 0 {
            let capacity = available.min(MAX_UDP_WIRE_LEN);
            saturation.push(budget.reserve(capacity).expect("saturate byte budget"));
            available -= capacity;
        }
        let valid = encode_udp_datagram(&targets[4], b"saturated", &mut socks).expect("request");
        reject!(
            "client_to_target",
            &application,
            &socks[..valid],
            relay,
            4,
            "capacity rejection"
        );
        drop(saturation);

        let mut scratch: Vec<UdpPacketScratch> = (0..5).map(|_| UdpPacketScratch::new()).collect();
        for (index, target) in targets.iter().take(4).enumerate() {
            let length = encode_udp_datagram(target, &[index as u8], &mut socks).expect("request");
            application
                .send_to(&socks[..length], relay)
                .await
                .expect("send");
            let endpoint = if index == 3 { 0 } else { index };
            receive_request_and_send_response(
                &upstreams[endpoint],
                &protocol_servers[endpoint],
                &mut scratch[endpoint],
                &[index as u8],
            )
            .await;
            let received =
                tokio::time::timeout(Duration::from_secs(1), application.recv(&mut socks))
                    .await
                    .expect("response timeout")
                    .expect("response");
            assert_eq!(
                decode_udp_datagram(&socks[..received])
                    .expect("decode")
                    .payload(),
                &[index as u8]
            );
        }
        assert_eq!(
            udp.live_ids.lock().expect("IDs").len(),
            4,
            "different concrete plans keep isolated sessions"
        );

        for (count, (target, source, advance, pre_accept, restore, tamper, label)) in [
            (0, 4, 0, false, true, false, "inactive response"),
            (0, 0, 0, false, true, true, "tampered response"),
            (1, 0, 0, false, true, false, "wrong-leg response"),
            (1, 1, 0, true, false, false, "duplicate response"),
            (2, 2, UDP_REPLAY_LAG + 1, true, false, false, "stale"),
        ]
        .into_iter()
        .enumerate()
        {
            let length = encode_udp_datagram(&targets[target], label.as_bytes(), &mut socks)
                .expect("request");
            application
                .send_to(&socks[..length], relay)
                .await
                .expect("send");
            let (peer, mut rejected, newest) = receive_request_and_encode_response(
                &upstreams[target],
                &protocol_servers[target],
                &mut scratch[target],
                label.as_bytes(),
                advance,
            )
            .await;
            if tamper {
                rejected[0] ^= 1;
            }
            if pre_accept {
                let accepted = if advance == 0 { &rejected } else { &newest };
                upstreams[target]
                    .send_to(accepted, peer)
                    .await
                    .expect("response");
                application.recv(&mut socks).await.expect("response");
            }
            reject!(
                "target_to_client",
                &upstreams[source],
                &rejected,
                peer,
                count + 1,
                label
            );
            if restore {
                upstreams[target]
                    .send_to(&newest, peer)
                    .await
                    .expect("response");
                application.recv(&mut socks).await.expect("response");
            }
        }

        let length = encode_udp_datagram(&targets[4], b"before-switch", &mut socks)
            .expect("selector request");
        application
            .send_to(&socks[..length], relay)
            .await
            .expect("selector send A");
        let (peer_a, delayed_a, _) = receive_request_and_encode_response(
            &upstreams[4],
            &protocol_servers[4],
            &mut scratch[4],
            b"before-switch",
            0,
        )
        .await;
        selector.switch("manual", "o5").expect("switch UDP leg");
        let length = encode_udp_datagram(&targets[4], b"after-switch", &mut socks)
            .expect("selector request");
        application
            .send_to(&socks[..length], relay)
            .await
            .expect("selector send B");
        receive_request_and_send_response(
            &upstreams[3],
            &protocol_servers[3],
            &mut scratch[3],
            b"after-switch",
        )
        .await;
        application.recv(&mut socks).await.expect("B response");
        upstreams[4]
            .send_to(&delayed_a, peer_a)
            .await
            .expect("delayed A response");
        application
            .recv(&mut socks)
            .await
            .expect("captured A response");
        assert_eq!(udp.live_ids.lock().expect("IDs").len(), 6);

        drop(peer);
        finish_udp_relay(running).await;
        assert!(udp.live_ids.lock().expect("IDs").is_empty());
        assert_eq!(registry.snapshot(), baseline);
        drop(UdpSocket::bind(relay).await.expect("relay rebind"));
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
            let mut prepared = context
                .egress
                .prepare_udp(
                    Ipv4Addr::LOCALHOST,
                    Some((
                        ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned(),
                        server_address,
                    )),
                    UdpSocket::bind,
                )
                .await
                .expect("prepared concrete relay");
            let relay = prepared.application.local_addr().expect("relay address");
            let upstream_client = prepared.upstream.local_addr().expect("upstream client");
            prepared.io_fault = Some(Arc::new(UdpIoFaultPlan::new(operation, fail_at)));
            let server = UdpServer::new(&context.keys).expect("protocol server");
            let (association, peer) = parsed_udp_association().await;
            let running = start_udp_relay(
                prepared,
                association.control,
                Arc::clone(&context),
                Arc::new(test_routing(server_address, default_test_psk())),
                0,
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

            if matches!(
                operation,
                UdpIoOperation::ApplicationSend | UdpIoOperation::UpstreamSend
            ) {
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
                let (path, context) = udp_test_context_for_psk(
                    registry.clone(),
                    server_address,
                    Some(psk_for_method(method)),
                );
                let prepared = context
                    .egress
                    .prepare_udp(
                        Ipv4Addr::LOCALHOST,
                        Some((
                            ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned(),
                            server_address,
                        )),
                        UdpSocket::bind,
                    )
                    .await
                    .expect("prepared relay");
                let relay = prepared.application.local_addr().expect("relay address");
                let handle = prepared.handle;
                let manager = prepared.manager.clone();
                let (association, peer) = parsed_udp_association().await;
                let running = start_udp_relay(
                    prepared,
                    association.control,
                    Arc::clone(&context),
                    Arc::new(test_routing(server_address, psk_for_method(method))),
                    0,
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
                source_b
                    .send_to(&socks[..exact], relay)
                    .await
                    .expect("exact source B request");
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
                    tokio::time::timeout(Duration::from_secs(2), source_b.recv(&mut emitted))
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
                    source_a
                        .try_recv(&mut absent)
                        .expect_err("source A stays unpinned")
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
                    source_b
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
                    source_b
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
            .map(|server| ferrum2_config::ClientOutboundConfig { server })
            .into();
        static_config.outbound_psks = methods.map(psk_for_method).into();
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
        Arc::get_mut(
            &mut Arc::get_mut(&mut context)
                .expect("unique routed context")
                .egress,
        )
        .expect("unique routed egress")
        .udp_id_random = Some(Arc::new(IdSequenceRandom::new([0x41, 0x42, 0x43, 0x44])));
        let outbounds = prepare_client_outbounds(
            servers
                .map(|server| ferrum2_config::ClientOutboundConfig { server })
                .into(),
            methods.map(psk_for_method).into(),
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
        let routing = Arc::new(ClientRouting { route, outbounds });
        let selected_snapshot = routing.route.select_plan_snapshot(0, Network::Udp, &target);
        assert_eq!(selected_snapshot.hops(), &[0, 1]);
        let selected_allocation = selected_snapshot.hops().as_ptr();
        let mut prepared = context
            .egress
            .prepare_udp(Ipv4Addr::LOCALHOST, None, UdpSocket::bind)
            .await
            .expect("routed chain preparation");
        prepared
            .activate(&context.egress, &routing.outbounds, &selected_snapshot)
            .expect("selected snapshot activation");
        let active_plan = prepared
            .plans
            .keys()
            .find(|active| *active == &selected_snapshot)
            .expect("selected active plan");
        assert_eq!(
            active_plan.hops().as_ptr(),
            selected_allocation,
            "association copied the selected plan allocation"
        );
        let relay = match prepared.application.local_addr().expect("relay") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!("IPv4 relay"),
        };
        let handle = prepared.handle;
        let manager = prepared.manager.clone();
        let (association, peer) = parsed_udp_association().await;
        let running = start_udp_relay(
            prepared,
            association.control,
            Arc::clone(&context),
            Arc::clone(&routing),
            0,
        )
        .await;
        drop(association.reply);
        let application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("routed application");
        while registry.snapshot().active_supervisor_children != 1 {
            tokio::task::yield_now().await;
        }
        let protocol_servers = routing
            .outbounds
            .iter()
            .map(|outbound| UdpServer::new(&outbound.keys).expect("protocol server"))
            .collect::<Vec<_>>();
        let random = SystemRandom;

        application
            .send_to(&socks[..length], relay)
            .await
            .expect("routed AB send");
        let (ab_len, upstream_peer) = upstreams[0]
            .recv_from(&mut wire)
            .await
            .expect("routed AB request");
        let ab_outer = protocol_servers[0]
            .prepare_request(&clock, &wire[..ab_len], &mut scratch)
            .expect("AB outer");
        assert_eq!(
            ab_outer.datagram().target(),
            &TargetAddr::ipv4(servers[1]).expect("B target")
        );
        let ab_inner_wire = ab_outer.datagram().payload().to_vec();
        let (_, commit) = ab_outer.into_parts();
        let ab_outer = protocol_servers[0]
            .commit_request(commit, upstream_peer, clock.monotonic_now(), &random)
            .expect("AB outer commit");
        let ab_inner = protocol_servers[1]
            .prepare_request(&clock, &ab_inner_wire, &mut scratch)
            .expect("AB inner");
        let (_, commit) = ab_inner.into_parts();
        let ab_inner = protocol_servers[1]
            .commit_request(commit, upstream_peer, clock.monotonic_now(), &random)
            .expect("AB inner commit");

        selector
            .switch("manual", "a-c")
            .expect("switch routed chain");
        application
            .send_to(&socks[..length], relay)
            .await
            .expect("routed AC send");
        let (ac_len, _) = upstreams[0]
            .recv_from(&mut wire)
            .await
            .expect("routed AC request");
        let ac_outer = protocol_servers[0]
            .prepare_request(&clock, &wire[..ac_len], &mut scratch)
            .expect("AC outer");
        assert_eq!(
            ac_outer.datagram().target(),
            &TargetAddr::ipv4(servers[2]).expect("C target")
        );
        let ac_inner_wire = ac_outer.datagram().payload().to_vec();
        let (_, commit) = ac_outer.into_parts();
        let ac_outer = protocol_servers[0]
            .commit_request(commit, upstream_peer, clock.monotonic_now(), &random)
            .expect("AC outer commit");
        let ac_inner = protocol_servers[2]
            .prepare_request(&clock, &ac_inner_wire, &mut scratch)
            .expect("AC inner");
        let (_, commit) = ac_inner.into_parts();
        let ac_inner = protocol_servers[2]
            .commit_request(commit, upstream_peer, clock.monotonic_now(), &random)
            .expect("AC inner commit");

        let wrong_outer_keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(
            other_psk_for_method(methods[0]),
        ));
        let wrong_outer_id = IdSequenceRandom::new([0x43]);
        let mut wrong_outer_client =
            UdpClientSession::new(&wrong_outer_keys, &wrong_outer_id, |_| false)
                .expect("same-ID wrong-PSK outer client");
        let wrong_outer_server = UdpServer::new(&wrong_outer_keys).expect("wrong outer server");
        let wrong_request = wrong_outer_client
            .encode_request(
                &clock,
                &random,
                &test_datagram(target.clone(), b"wrong outer request"),
                0,
                &mut wire,
                &mut scratch,
            )
            .expect("wrong outer request");
        let wrong_request = wrong_outer_server
            .prepare_request(&clock, &wire[..wrong_request], &mut scratch)
            .expect("wrong outer request credential");
        let (_, commit) = wrong_request.into_parts();
        let wrong_outer_capability = wrong_outer_server
            .commit_request(commit, upstream_peer, clock.monotonic_now(), &random)
            .expect("wrong outer request commit");
        let wrong_outer = wrong_outer_server
            .encode_response(
                wrong_outer_capability.capability(),
                &clock,
                &random,
                &test_datagram(
                    TargetAddr::ipv4(servers[2]).expect("C target"),
                    b"wrong outer response",
                ),
                0,
                &mut wire,
                &mut scratch,
            )
            .expect("same-ID wrong-PSK outer response");
        let wrong_outer = wire[..wrong_outer.wire_len()].to_vec();

        let wrong_inner_keys = MethodKeyAdapter::new(MethodSinglePskProvider::new(
            other_psk_for_method(methods[2]),
        ));
        let wrong_inner_id = IdSequenceRandom::new([0x44]);
        let mut wrong_inner_client =
            UdpClientSession::new(&wrong_inner_keys, &wrong_inner_id, |_| false)
                .expect("same-ID wrong-PSK inner client");
        let wrong_inner_server = UdpServer::new(&wrong_inner_keys).expect("wrong inner server");
        let wrong_request = wrong_inner_client
            .encode_request(
                &clock,
                &random,
                &test_datagram(target.clone(), b"wrong inner request"),
                0,
                &mut wire,
                &mut scratch,
            )
            .expect("wrong inner request");
        let wrong_request = wrong_inner_server
            .prepare_request(&clock, &wire[..wrong_request], &mut scratch)
            .expect("wrong inner request credential");
        let (_, commit) = wrong_request.into_parts();
        let wrong_inner_capability = wrong_inner_server
            .commit_request(commit, upstream_peer, clock.monotonic_now(), &random)
            .expect("wrong inner request commit");
        let wrong_inner = wrong_inner_server
            .encode_response(
                wrong_inner_capability.capability(),
                &clock,
                &random,
                &test_datagram(target.clone(), b"wrong inner response"),
                0,
                &mut wire,
                &mut scratch,
            )
            .expect("same-ID wrong-PSK inner response");
        let wrong_inner = wire[..wrong_inner.wire_len()].to_vec();

        let stable = registry.snapshot();
        let deadline = manager.idle_deadline(handle).expect("deadline");
        let live_ids = context
            .egress
            .udp
            .as_ref()
            .expect("UDP")
            .live_ids
            .lock()
            .expect("live IDs")
            .len();
        upstreams[0]
            .send_to(&wrong_outer, upstream_peer)
            .await
            .expect("wrong outer response send");
        wait_for_metric(
            &context.metrics,
            "ferrum2_udp_datagrams_total{role=\"client\",direction=\"target_to_client\",outcome=\"rejected\"} 1",
        )
        .await;
        assert_eq!(registry.snapshot(), stable);
        assert_eq!(manager.idle_deadline(handle), Ok(deadline));
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
            live_ids
        );
        assert_eq!(
            application
                .try_recv(&mut [0])
                .expect_err("wrong outer response reached application")
                .kind(),
            io::ErrorKind::WouldBlock
        );

        let wrong_inner_outer = protocol_servers[0]
            .encode_response(
                ac_outer.capability(),
                &clock,
                &random,
                &test_datagram(
                    TargetAddr::ipv4(servers[2]).expect("C target"),
                    &wrong_inner,
                ),
                0,
                &mut wire,
                &mut scratch,
            )
            .expect("correct outer wrapping wrong-PSK inner");
        let wrong_inner_outer = wire[..wrong_inner_outer.wire_len()].to_vec();
        upstreams[0]
            .send_to(&wrong_inner_outer, upstream_peer)
            .await
            .expect("wrong inner response send");
        wait_for_metric(
            &context.metrics,
            "ferrum2_udp_datagrams_total{role=\"client\",direction=\"target_to_client\",outcome=\"rejected\"} 2",
        )
        .await;
        assert_eq!(registry.snapshot(), stable);
        assert_eq!(manager.idle_deadline(handle), Ok(deadline));
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
            live_ids
        );
        assert_eq!(
            application
                .try_recv(&mut [0])
                .expect_err("wrong inner response reached application")
                .kind(),
            io::ErrorKind::WouldBlock
        );

        let correct_inner = protocol_servers[2]
            .encode_response(
                ac_inner.capability(),
                &clock,
                &random,
                &test_datagram(target.clone(), b"AC valid after wrong PSKs"),
                0,
                &mut wire,
                &mut scratch,
            )
            .expect("fresh correct AC inner");
        let correct_inner = wire[..correct_inner.wire_len()].to_vec();
        let correct_outer = protocol_servers[0]
            .encode_response(
                ac_outer.capability(),
                &clock,
                &random,
                &test_datagram(
                    TargetAddr::ipv4(servers[2]).expect("C target"),
                    &correct_inner,
                ),
                0,
                &mut wire,
                &mut scratch,
            )
            .expect("fresh correct AC outer");
        let correct_outer = wire[..correct_outer.wire_len()].to_vec();
        upstreams[0]
            .send_to(&correct_outer, upstream_peer)
            .await
            .expect("valid-after wrong PSKs send");
        let received = tokio::time::timeout(Duration::from_secs(2), application.recv(&mut socks))
            .await
            .expect("valid-after wrong PSKs timeout")
            .expect("valid-after wrong PSKs response");
        assert_eq!(
            decode_udp_datagram(&socks[..received])
                .expect("valid-after wrong PSKs SOCKS response")
                .payload(),
            b"AC valid after wrong PSKs"
        );

        let encoded = protocol_servers[1]
            .encode_response(
                ab_inner.capability(),
                &clock,
                &random,
                &test_datagram(target.clone(), b"AB"),
                0,
                &mut wire,
                &mut scratch,
            )
            .expect("AB inner response");
        let ab_response = wire[..encoded.wire_len()].to_vec();
        let crossed = protocol_servers[0]
            .encode_response(
                ab_outer.capability(),
                &clock,
                &random,
                &test_datagram(
                    TargetAddr::ipv4(servers[2]).expect("crossed C target"),
                    &ab_response,
                ),
                0,
                &mut wire,
                &mut scratch,
            )
            .expect("cross-plan wrapper");
        let stable = registry.snapshot();
        let deadline = manager.idle_deadline(handle).expect("deadline");
        upstreams[0]
            .send_to(&wire[..crossed.wire_len()], upstream_peer)
            .await
            .expect("cross-plan response");
        wait_for_metric(
            &context.metrics,
            "ferrum2_udp_datagrams_total{role=\"client\",direction=\"target_to_client\",outcome=\"rejected\"} 3",
        )
        .await;
        assert_eq!(registry.snapshot(), stable);
        assert_eq!(manager.idle_deadline(handle), Ok(deadline));
        assert_eq!(
            application
                .try_recv(&mut [0])
                .expect_err("cross-plan response reached application")
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(selector.selected("manual"), Ok("a-c"));

        let selected_payload = b"AC remains selected after rejection";
        let selected_length = encode_udp_datagram(&target, selected_payload, &mut socks)
            .expect("post-rejection routed request");
        application
            .send_to(&socks[..selected_length], relay)
            .await
            .expect("post-rejection routed send");
        let (selected_wire_len, _) =
            tokio::time::timeout(Duration::from_secs(2), upstreams[0].recv_from(&mut wire))
                .await
                .expect("post-rejection outer A timeout")
                .expect("post-rejection outer A request");
        wait_for_metric(
            &context.metrics,
            "ferrum2_udp_datagrams_total{role=\"client\",direction=\"client_to_target\",outcome=\"accepted\"} 3",
        )
        .await;
        let selected_outer = protocol_servers[0]
            .prepare_request(&clock, &wire[..selected_wire_len], &mut scratch)
            .expect("post-rejection outer credential");
        assert_eq!(
            selected_outer.datagram().target(),
            &TargetAddr::ipv4(servers[2]).expect("C target")
        );
        let selected_inner_wire = selected_outer.datagram().payload().to_vec();
        drop(selected_outer);
        let selected_inner = protocol_servers[2]
            .prepare_request(&clock, &selected_inner_wire, &mut scratch)
            .expect("post-rejection inner credential");
        assert_eq!(selected_inner.datagram().target(), &target);
        assert_eq!(selected_inner.datagram().payload(), selected_payload);
        drop(selected_inner);
        for (socket, label) in [
            (&upstreams[0], "second outer A packet"),
            (&upstreams[1], "fallback B packet"),
            (&upstreams[2], "direct C packet"),
        ] {
            assert!(
                tokio::time::timeout(Duration::from_millis(100), socket.recv(&mut [0]))
                    .await
                    .is_err(),
                "{label} followed rejected response"
            );
        }

        for (outer, inner, next, payload) in [
            (&ab_outer, &ab_inner, servers[1], b"AB".as_slice()),
            (&ac_outer, &ac_inner, servers[2], b"AC".as_slice()),
        ] {
            let encoded = protocol_servers[if next == servers[1] { 1 } else { 2 }]
                .encode_response(
                    inner.capability(),
                    &clock,
                    &random,
                    &test_datagram(target.clone(), payload),
                    0,
                    &mut wire,
                    &mut scratch,
                )
                .expect("inner response");
            let inner_wire = wire[..encoded.wire_len()].to_vec();
            let encoded = protocol_servers[0]
                .encode_response(
                    outer.capability(),
                    &clock,
                    &random,
                    &test_datagram(
                        TargetAddr::ipv4(next).expect("intermediate target"),
                        &inner_wire,
                    ),
                    0,
                    &mut wire,
                    &mut scratch,
                )
                .expect("outer response");
            upstreams[0]
                .send_to(&wire[..encoded.wire_len()], upstream_peer)
                .await
                .expect("valid plan response");
            let received =
                tokio::time::timeout(Duration::from_secs(2), application.recv(&mut socks))
                    .await
                    .expect("plan response timeout")
                    .expect("plan response");
            assert_eq!(
                decode_udp_datagram(&socks[..received])
                    .expect("plan SOCKS response")
                    .payload(),
                payload
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
            4
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
                .map(|server| ferrum2_config::ClientOutboundConfig { server })
                .collect(),
            methods.iter().copied().map(psk_for_method).collect(),
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
        let routing = Arc::new(ClientRouting { route, outbounds });
        let (path, context) = udp_test_context_for_psk(
            registry.clone(),
            servers[0],
            Some(psk_for_method(methods[0])),
        );
        let prepared = context
            .egress
            .prepare_udp(
                Ipv4Addr::LOCALHOST,
                Some((plan, servers[0])),
                UdpSocket::bind,
            )
            .await
            .expect("eight-hop preparation");
        let relay = match prepared.application.local_addr().expect("relay") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!("IPv4 relay"),
        };
        assert!(prepared.plans.is_empty());
        assert!(prepared.pending_session.is_some());
        assert_eq!(prepared._fixed_capacity.len(), 3);
        assert_eq!(
            prepared.application_wire.len(),
            MAX_SOCKS_UDP_DATAGRAM_BYTES
        );
        assert_eq!(prepared.upstream_wire.len(), MAX_UDP_WIRE_LEN);
        assert_eq!(registry.snapshot().udp_buffered_bytes, 3 * MAX_UDP_WIRE_LEN);
        let handle = prepared.handle;
        let manager = prepared.manager.clone();
        let (association, peer) = parsed_udp_association().await;
        let running = start_udp_relay(
            prepared,
            association.control,
            Arc::clone(&context),
            Arc::clone(&routing),
            0,
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
        let deadline = manager.idle_deadline(handle).expect("pending deadline");
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
        assert_eq!(manager.idle_deadline(handle), Ok(deadline));
        assert_eq!(manager.session_count(), 1);
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
            let server = UdpServer::new(&routing.outbounds[layer].keys).expect("hop server");
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
                .map(|server| ferrum2_config::ClientOutboundConfig { server })
                .into(),
            methods.map(psk_for_method).into(),
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
