use super::*;
use ferrum2_core::SessionReply as _;

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
    let command = Socks5Inbound::new()
        .accept_command(application)
        .await
        .expect("accepted SOCKS request");
    let SocksCommand::Connect(session) = command else {
        panic!("CONNECT request")
    };
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

#[tokio::test]
async fn application_socket_setup_failure_replies_once_and_rolls_back() {
    for fail_at in 0..1 {
        let registry = OwnerRegistry::new();
        let baseline = registry.snapshot();
        let (path, context, server) = udp_test_context(registry.clone());
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
                Arc::new(test_routing(server, default_test_psk())),
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
    let (path, context, server) = udp_test_context(registry.clone());
    let (association, peer) = parsed_udp_association().await;
    drop(peer);
    execute_test_udp_association(
        association,
        Arc::clone(&context),
        Arc::new(test_routing(server, default_test_psk())),
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
    let (path, context, _) = udp_test_context(registry.clone());
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
