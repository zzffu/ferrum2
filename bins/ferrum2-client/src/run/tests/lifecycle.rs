use super::*;

#[tokio::test]
async fn udp_process_shutdown_drains_an_active_association_without_forcing() {
    let listens = [reserve_address(), reserve_address()];
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("upstream receiver");
    let server = match upstream.local_addr().expect("upstream address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 upstream"),
    };
    let (config_path, mut config) =
        tagged_client_test_config(&listens.map(|listen| (listen, server)), true);
    config.runtime.shutdown_grace = Duration::from_secs(1);
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let metrics = Arc::new(Metrics::new());
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();
    let task_registry = registry.clone();
    let task_metrics = Arc::clone(&metrics);
    let run_task = tokio::spawn(async move {
        run_with_registry_and_metrics(
            config,
            task_registry,
            async {
                let _ = shutdown_receiver.await;
            },
            task_metrics,
        )
        .await
    });
    for listen in listens {
        wait_until_bound(listen).await;
    }

    let mut control = tokio::net::TcpStream::connect(listens[0])
        .await
        .expect("SOCKS control");
    control.write_all(&[5, 1, 0]).await.expect("greeting");
    let mut method = [0_u8; 2];
    control.read_exact(&mut method).await.expect("method");
    assert_eq!(method, [5, 0]);
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .expect("UDP ASSOCIATE");
    let mut reply = [0_u8; 10];
    control.read_exact(&mut reply).await.expect("success reply");
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
        encode_udp_datagram(&target, b"graceful-active", &mut request).expect("request");
    application
        .send_to(&request[..request_len], relay)
        .await
        .expect("application send");
    let mut upstream_wire = [0; MAX_UDP_WIRE_LEN];
    let (_, upstream_client) = tokio::time::timeout(
        Duration::from_secs(2),
        upstream.recv_from(&mut upstream_wire),
    )
    .await
    .expect("committed request timeout")
    .expect("committed request");
    let live = registry.snapshot();
    assert_eq!(live.udp_sessions, baseline.udp_sessions + 1);
    assert_eq!(
        live.udp_buffered_bytes,
        baseline.udp_buffered_bytes + 3 * MAX_UDP_WIRE_LEN
    );
    assert_eq!(
        live.active_supervisor_children,
        baseline.active_supervisor_children + 1
    );
    assert_eq!(live.connection_tasks, baseline.connection_tasks + 1);
    let (_, saturated) = socks_command(listens[1], 3).await;
    assert_eq!(&saturated[..2], &[5, 1]);
    assert_eq!(registry.snapshot().udp_sessions, baseline.udp_sessions + 1);

    shutdown_sender
        .send(())
        .expect("request graceful shutdown first");
    let mut eof = [0; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), control.read(&mut eof))
            .await
            .expect("control EOF timeout")
            .expect("control EOF"),
        0
    );
    assert_eq!(run_task.await.expect("run task"), Ok(()));
    let closed = registry.snapshot();
    let actual = (
        closed.process_supervisors,
        closed.prepared_process_roots,
        closed.active_process_roots,
        closed.active_supervisor_children,
        closed.connection_tasks,
        closed.owned_permits,
        closed.listeners,
        closed.udp_sessions,
        closed.udp_queued_datagrams,
        closed.udp_buffered_bytes,
    );
    let expected = (
        baseline.process_supervisors,
        baseline.prepared_process_roots,
        baseline.active_process_roots,
        baseline.active_supervisor_children,
        baseline.connection_tasks,
        baseline.owned_permits,
        baseline.listeners,
        baseline.udp_sessions,
        baseline.udp_queued_datagrams,
        baseline.udp_buffered_bytes,
    );
    assert_eq!(actual, expected);
    assert!(
        !metrics
            .encode_text()
            .expect("metrics")
            .contains("ferrum2_udp_forced_shutdown_total{role=\"client\"}")
    );
    drop(application);
    drop(upstream);
    drop(UdpSocket::bind(relay).await.expect("relay rebind"));
    drop(
        UdpSocket::bind(upstream_client)
            .await
            .expect("upstream client rebind"),
    );
    for listen in listens {
        drop(TcpListener::bind(listen).await.expect("listener rebind"));
    }
    std::fs::remove_file(config_path).expect("remove client UDP test config");
}

#[tokio::test]
async fn zero_grace_counts_each_of_two_forced_udp_associations_once() {
    let listens = [reserve_address(), reserve_address()];
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("upstream receiver");
    let server = match upstream.local_addr().expect("upstream address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 upstream"),
    };
    let (config_path, mut config) =
        tagged_client_test_config(&listens.map(|listen| (listen, server)), true);
    config.runtime.shutdown_grace = Duration::ZERO;
    config.udp.as_mut().expect("UDP config").max_sessions = 2;
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let metrics = Arc::new(Metrics::new());
    let task_metrics = Arc::clone(&metrics);
    let task_registry = registry.clone();
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();
    let run_task = tokio::spawn(async move {
        run_with_registry_and_metrics(
            config,
            task_registry,
            async {
                let _ = shutdown_receiver.await;
            },
            task_metrics,
        )
        .await
    });
    for listen in listens {
        wait_until_bound(listen).await;
    }

    let mut controls = Vec::new();
    let mut relays = Vec::new();
    let mut applications = Vec::new();
    let mut upstream_clients = Vec::new();
    for (listen, payload) in listens
        .into_iter()
        .zip([b"active-one".as_slice(), b"active-two".as_slice()])
    {
        let mut control = tokio::net::TcpStream::connect(listen)
            .await
            .expect("SOCKS control");
        control.write_all(&[5, 1, 0]).await.expect("greeting");
        let mut method = [0; 2];
        control.read_exact(&mut method).await.expect("method");
        assert_eq!(method, [5, 0]);
        control
            .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .expect("UDP ASSOCIATE");
        let mut reply = [0; 10];
        control.read_exact(&mut reply).await.expect("success reply");
        let relay = SocketAddrV4::new(
            Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
            u16::from_be_bytes([reply[8], reply[9]]),
        );
        let application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("application");
        let target = TargetAddr::ipv4("192.0.2.1:53".parse().expect("target")).expect("target");
        let mut request = [0; 64];
        let length = encode_udp_datagram(&target, payload, &mut request).expect("request");
        application
            .send_to(&request[..length], relay)
            .await
            .expect("application send");
        let mut wire = [0; MAX_UDP_WIRE_LEN];
        let (_, upstream_client) =
            tokio::time::timeout(Duration::from_secs(2), upstream.recv_from(&mut wire))
                .await
                .expect("upstream timeout")
                .expect("upstream request");
        controls.push(control);
        relays.push(relay);
        applications.push(application);
        upstream_clients.push(upstream_client);
    }
    let active = registry.snapshot();
    assert_eq!(active.udp_sessions, baseline.udp_sessions + 2);
    assert_eq!(
        active.udp_buffered_bytes,
        baseline.udp_buffered_bytes + 6 * MAX_UDP_WIRE_LEN
    );
    assert_eq!(
        active.active_supervisor_children,
        baseline.active_supervisor_children + 2
    );
    assert_eq!(active.connection_tasks, baseline.connection_tasks + 2);

    shutdown_sender.send(()).expect("zero-grace shutdown");
    for control in &mut controls {
        let mut eof = [0; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), control.read(&mut eof))
                .await
                .expect("control EOF timeout")
                .expect("control EOF"),
            0
        );
    }
    assert_eq!(run_task.await.expect("run task"), Ok(()));
    assert!(
        metrics
            .encode_text()
            .expect("metrics")
            .contains("ferrum2_udp_forced_shutdown_total{role=\"client\"} 2")
    );
    let closed = registry.snapshot();
    let actual = (
        closed.process_supervisors,
        closed.prepared_process_roots,
        closed.active_process_roots,
        closed.active_supervisor_children,
        closed.connection_tasks,
        closed.owned_permits,
        closed.listeners,
        closed.udp_sessions,
        closed.udp_queued_datagrams,
        closed.udp_buffered_bytes,
    );
    let expected = (
        baseline.process_supervisors,
        baseline.prepared_process_roots,
        baseline.active_process_roots,
        baseline.active_supervisor_children,
        baseline.connection_tasks,
        baseline.owned_permits,
        baseline.listeners,
        baseline.udp_sessions,
        baseline.udp_queued_datagrams,
        baseline.udp_buffered_bytes,
    );
    assert_eq!(actual, expected);
    drop(controls);
    drop(applications);
    drop(upstream);
    for relay in relays {
        drop(UdpSocket::bind(relay).await.expect("relay rebind"));
    }
    for upstream_client in upstream_clients {
        drop(
            UdpSocket::bind(upstream_client)
                .await
                .expect("upstream client rebind"),
        );
    }
    for listen in listens {
        drop(TcpListener::bind(listen).await.expect("listener rebind"));
    }
    std::fs::remove_file(config_path).expect("remove config");
}

#[tokio::test]
async fn listener_fatal_cancels_udp_without_forced_shutdown() {
    let listens = [reserve_address(), reserve_address()];
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("upstream receiver");
    let server = match upstream.local_addr().expect("upstream address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 upstream"),
    };
    let (path, mut context) = udp_test_context_for_server(registry.clone(), server);
    Arc::get_mut(&mut context)
        .expect("unique test context")
        .runtime
        .shutdown_grace = Duration::from_secs(1);
    let metrics = Arc::clone(&context.metrics);
    let accept_errors = Arc::new(Mutex::new(VecDeque::from([io::ErrorKind::Interrupted])));
    let tcp_registry = registry.clone();
    let tcp_context = Arc::clone(&context);
    let tcp_accept_errors = Arc::clone(&accept_errors);
    let route_source = format!(
        "schema_version = 2\n\
         [[inbounds]]\n\
         tag = \"i0\"\n\
         listen = \"{}\"\n\
         outbound = \"o0\"\n\
         [[inbounds]]\n\
         tag = \"i1\"\n\
         listen = \"{}\"\n\
         outbound = \"o1\"\n\
         [[outbounds]]\n\
         tag = \"o0\"\n\
         type = \"direct\"\n\
         [[outbounds]]\n\
         tag = \"o1\"\n\
         type = \"direct\"\n",
        listens[0], listens[1]
    );
    let route_path = write_client_test_source(&route_source);
    let prepared = ferrum2_config::prepare_client(&route_path).expect("prepare test routes");
    let route_config =
        ferrum2_config::finish_client_v2(prepared, ferrum2_config::ClientV2Resources::default())
            .expect("finish test routes");
    std::fs::remove_file(route_path).expect("remove test route config");
    let selector = route_config.selector_control();
    let program = route_config.route;
    let tcp_root = ProcessRoot::new(move || async move {
        let listeners = listens
            .into_iter()
            .map(|listen| bind_listener(listen, 16))
            .collect::<Result<Vec<_>, _>>()?;
        let supervisor = BoundedSupervisor::new(
            ClientTcpListeners {
                listeners,
                next: AtomicUsize::new(0),
                accept_errors: Some(tcp_accept_errors),
            },
            4,
            Duration::from_secs(1),
            tcp_registry,
        )
        .map_err(|_| RunError::StartupProtocol)?;
        Ok(ClientTcpRoot {
            supervisor: Some(supervisor),
            context: tcp_context,
            routing: Arc::new(ClientRouting {
                program,
                outbounds: listens
                    .map(|_| {
                        ClientOutboundContext::Shadowsocks(ClientShadowsocksContext {
                            tcp_server: TargetAddr::ipv4(server).expect("server target"),
                            udp_server: server.into(),
                            keys: MethodKeyAdapter::new(MethodSinglePskProvider::new(
                                psk_for_method(MethodProfile::Blake3Aes128Gcm2022),
                            )),
                            dial_options: ferrum2_net::DialOptions::default(),
                        })
                    })
                    .into(),
                selector,
            }),
        })
    });
    let supervisor =
        ProcessSupervisor::new(vec![tcp_root], Duration::from_secs(1), registry.clone())
            .expect("process supervisor");
    let run_task = tokio::spawn(supervisor.run_until(std::future::pending::<()>()));
    for listen in listens {
        wait_until_bound(listen).await;
    }

    let mut control = tokio::net::TcpStream::connect(listens[0])
        .await
        .expect("SOCKS control");
    control.write_all(&[5, 1, 0]).await.expect("greeting");
    let mut method = [0; 2];
    control.read_exact(&mut method).await.expect("method");
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .expect("UDP ASSOCIATE");
    let mut reply = [0; 10];
    control.read_exact(&mut reply).await.expect("success reply");
    let relay = SocketAddrV4::new(
        Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
        u16::from_be_bytes([reply[8], reply[9]]),
    );
    let application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("application");
    let target = TargetAddr::ipv4("192.0.2.1:53".parse().expect("target")).expect("target");
    let mut request = [0; 64];
    let length = encode_udp_datagram(&target, b"sibling", &mut request).expect("request");
    application
        .send_to(&request[..length], relay)
        .await
        .expect("application send");
    let mut wire = [0; MAX_UDP_WIRE_LEN];
    let (_, upstream_client) =
        tokio::time::timeout(Duration::from_secs(1), upstream.recv_from(&mut wire))
            .await
            .expect("upstream timeout")
            .expect("committed upstream request");
    let live = registry.snapshot();
    assert_eq!(live.udp_sessions, baseline.udp_sessions + 1);
    assert_eq!(live.udp_buffered_bytes, 3 * MAX_UDP_WIRE_LEN);
    assert_eq!(live.active_supervisor_children, 1);
    assert_eq!(live.connection_tasks, 1);
    assert_eq!(live.owned_permits, 2);
    assert_eq!(
        context
            .egress
            .udp
            .as_ref()
            .expect("UDP")
            .manager
            .session_count(),
        1
    );

    accept_errors
        .lock()
        .expect("accept errors")
        .push_back(io::ErrorKind::PermissionDenied);
    drop(
        tokio::net::TcpStream::connect(listens[1])
            .await
            .expect("wake fatal listener"),
    );
    let mut eof = [0; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), control.read(&mut eof))
            .await
            .expect("control EOF timeout")
            .expect("control EOF"),
        0
    );
    let report = run_task.await.expect("process task");
    assert!(matches!(
        report.cause(),
        ProcessCause::RootStopped {
            root,
            exit: ProcessRootExit::Failed(RunError::RuntimeListener),
        } if root.get() == 0
    ));
    assert_eq!(report.forced_roots(), 0);
    let udp = context.egress.udp.as_ref().expect("UDP");
    assert_eq!(udp.manager.session_count(), 0);
    assert_eq!(udp.manager.buffer_budget().reserved_bytes(), 0);
    assert!(udp.live_ids.lock().expect("live IDs").is_empty());
    assert_eq!(active(registry.snapshot()), active(baseline));
    assert!(
        !metrics
            .encode_text()
            .expect("metrics")
            .contains("ferrum2_udp_forced_shutdown_total{role=\"client\"}")
    );
    drop(application);
    drop(upstream);
    drop(UdpSocket::bind(relay).await.expect("relay rebind"));
    drop(
        UdpSocket::bind(upstream_client)
            .await
            .expect("upstream client rebind"),
    );
    for listen in listens {
        drop(TcpListener::bind(listen).await.expect("listener rebind"));
    }
    std::fs::remove_file(path).expect("remove config");
}

#[tokio::test]
async fn lifecycle_composition_contract_production_registry_witnesses_live_then_baseline() {
    let shadowsocks_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("fake Shadowsocks listener");
    let server = match shadowsocks_listener.local_addr().expect("server address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 server"),
    };
    let listen = reserve_address();
    let (config_path, config) = client_test_config(listen, server);
    let registry = OwnerRegistry::new();
    let baseline = registry.snapshot();
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();
    let task_registry = registry.clone();
    let run_task = tokio::spawn(async move {
        run_with_registry(config, task_registry, async {
            let _ = shutdown_receiver.await;
        })
        .await
    });
    wait_until_bound(listen).await;

    let accept_task = tokio::spawn(async move {
        shadowsocks_listener
            .accept()
            .await
            .expect("fake Shadowsocks accept")
            .0
    });
    let mut socks = tokio::net::TcpStream::connect(listen)
        .await
        .expect("SOCKS client connect");
    socks.write_all(&[5, 1, 0]).await.expect("SOCKS greeting");
    let mut method = [0_u8; 2];
    socks.read_exact(&mut method).await.expect("SOCKS method");
    assert_eq!(method, [5, 0]);
    socks
        .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
        .await
        .expect("SOCKS request");
    let mut reply = [0_u8; 10];
    socks.read_exact(&mut reply).await.expect("SOCKS success");
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    let shadowsocks_stream = accept_task.await.expect("fake Shadowsocks task");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let live = registry.snapshot();
        if live.active_supervisor_children == 1
            && live.connection_tasks == 1
            && live.owned_buffers == 2
            && live.owned_permits >= 1
            && live.listeners == 1
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "registry never exposed the live production path: {live:?}"
        );
        tokio::task::yield_now().await;
    }

    shutdown_sender.send(()).expect("request shutdown");
    assert_eq!(
        run_task.await.expect("run task"),
        Ok(()),
        "production run_with_registry path"
    );
    drop(socks);
    drop(shadowsocks_stream);
    let final_snapshot = registry.snapshot();
    let actual = (
        final_snapshot.active_supervisor_children,
        final_snapshot.connection_tasks,
        final_snapshot.owned_buffers,
        final_snapshot.owned_permits,
        final_snapshot.listeners,
        final_snapshot.process_forced_roots,
        final_snapshot.forced_shutdowns,
    );
    let expected = (
        baseline.active_supervisor_children,
        baseline.connection_tasks,
        baseline.owned_buffers,
        baseline.owned_permits,
        baseline.listeners,
        baseline.process_forced_roots + 1,
        baseline.forced_shutdowns + 1,
    );
    assert_eq!(actual, expected, "TCP root cleanup");
    std::fs::remove_file(config_path).expect("remove client test config");
}
