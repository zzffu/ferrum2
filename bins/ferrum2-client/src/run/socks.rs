use super::*;

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

pub(super) async fn client_connection(
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

pub(super) async fn run_udp_association<IO, F, Fut>(
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

pub(super) async fn relay_udp_association<IO>(
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
    use crate::run::tests::{
        client_udp_test_config, default_test_psk, reserve_address, test_routing,
    };
    use crate::run::tokio_io::tests::ScriptedIo;

    pub(in crate::run) struct FailingConnector {
        pub(in crate::run) calls: Arc<AtomicUsize>,
    }

    impl Connector for FailingConnector {
        type Stream = ScriptedIo;

        async fn connect(&self, _target: &TargetAddr) -> Result<Self::Stream, ConnectError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(ConnectError::new(ConnectErrorKind::Other))
        }
    }

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

    pub(in crate::run) fn udp_test_context_for_server(
        registry: OwnerRegistry,
        server: SocketAddrV4,
    ) -> (PathBuf, Arc<ClientContext>) {
        udp_test_context_for_psk(registry, server, None)
    }

    pub(in crate::run) fn udp_test_context_for_psk(
        registry: OwnerRegistry,
        server: SocketAddrV4,
        psk: Option<ferrum2_crypto::MethodPsk>,
    ) -> (PathBuf, Arc<ClientContext>) {
        let (path, mut config) = client_udp_test_config(reserve_address(), server);
        if let Some(psk) = psk {
            config.psk = psk;
        }
        let method = config.method();
        let udp = config.udp.expect("enabled UDP");
        let server = config.server;
        let runtime = config.runtime;
        let outbounds = prepare_client_outbounds(config.outbounds, config.outbound_psks)
            .expect("test outbounds");
        let udp = ClientUdpContext {
            manager: UdpSessionManager::new(
                UdpRuntimeLimits::new(udp.max_sessions, udp.max_buffered_bytes, udp.idle_timeout)
                    .expect("UDP limits"),
                registry.clone(),
            ),
            live_ids: Arc::new(Mutex::new(HashSet::new())),
            method,
        };
        let context = ClientContext {
            inbound: Socks5Inbound::new(),
            egress: Arc::new(ClientEgressEngine::new(
                outbounds,
                TokioConnector::new(TcpConnector::new(runtime.connect_timeout)),
                SystemClock::new(),
                SystemRandom,
                (runtime.connect_timeout, runtime.handshake_timeout),
                Some(udp),
                None,
            )),
            keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(config.psk)),
            runtime,
            udp_associate_enabled: true,
            registry,
            metrics: Arc::new(Metrics::new()),
            test_udp_server: server,
        };
        (path, Arc::new(context))
    }

    pub(in crate::run) async fn parsed_udp_association() -> (
        SocksUdpAssociate<tokio::io::DuplexStream>,
        tokio::io::DuplexStream,
    ) {
        let (mut peer, application) = tokio::io::duplex(128);
        let peer_task = tokio::spawn(async move {
            peer.write_all(&[5, 1, 0]).await.expect("greeting");
            let mut method = [0; 2];
            peer.read_exact(&mut method).await.expect("method");
            assert_eq!(method, [5, 0]);
            peer.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .expect("UDP request");
            peer
        });
        let command = Socks5Inbound::new()
            .accept_command(application)
            .await
            .expect("parsed command");
        let SocksCommand::UdpAssociate(association) = command else {
            panic!("UDP association")
        };
        (association, peer_task.await.expect("peer task"))
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
}
