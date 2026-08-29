use super::*;

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
            Arc::new(test_routing(server, default_test_psk())),
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
        let expected = (1, MAX_UDP_WIRE_LEN, 0, 1, 1);
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

pub(in crate::run) struct RunningUdpRelay {
    pub(in crate::run) task: tokio::task::JoinHandle<Result<(), SupervisorError>>,
    pub(in crate::run) done: tokio::sync::oneshot::Receiver<()>,
    pub(in crate::run) shutdown: tokio::sync::oneshot::Sender<()>,
    pub(in crate::run) _trigger: tokio::net::TcpStream,
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
            #[cfg(feature = "candidate-udp-owned-headroom")]
            context_udp_buffer_budget(&context),
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
            receive_request_and_send_response(&upstream, &server, &mut scratch, b"second-response")
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
