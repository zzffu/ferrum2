use super::super::work::NewSessionWork;
use super::*;

#[tokio::test(start_paused = true)]
async fn cold_identity_fifo_count_bytes_deadline_and_drop_are_bounded() {
    let registry = OwnerRegistry::new();
    let baseline = active(registry.snapshot());
    let manager = UdpSessionManager::new(
        UdpRuntimeLimits::new(1, 1_048_576, Duration::from_secs(60)).unwrap(),
        registry.clone(),
    );
    let budget = manager.buffer_budget();
    let mut work = NewSessionWork::<()>::new(1, budget.clone());
    let keys = aes_keys();
    let protocol = UdpServer::new(&keys).unwrap();
    let clock = SystemClock::new();
    let mut client = UdpClientSession::new(&keys, &SystemRandom, |_| false).unwrap();
    let peer: SocketAddr = "127.0.0.1:40001".parse().unwrap();
    let target = TargetAddr::ip("127.0.0.1:9".parse().unwrap()).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut scratch = UdpPacketScratch::new();
    let mut occupied = Vec::new();
    while budget.reserved_bytes() < 1_048_576 {
        occupied.push(
            budget
                .reserve((1_048_576 - budget.reserved_bytes()).min(MAX_UDP_WIRE_DATAGRAM_BYTES))
                .unwrap(),
        );
    }
    let wire = encoded_udp_request(&mut client, &clock, target.clone(), b"budget-full");
    let pending = protocol
        .prepare_request(&clock, &wire, &mut scratch)
        .unwrap();
    assert!(matches!(
        work.account(pending, peer, wire.len(), deadline),
        Err(UdpRuntimeError::BufferLimit)
    ));
    assert_eq!(protocol.session_count().unwrap(), 0);
    drop(occupied);
    for packet in 0..=ferrum2_runtime::UDP_SESSION_QUEUE_DEPTH {
        let wire = encoded_udp_request(&mut client, &clock, target.clone(), &[packet as u8]);
        let pending = protocol
            .prepare_request(&clock, &wire, &mut scratch)
            .unwrap();
        let before = budget.reserved_bytes();
        let request = work.account(pending, peer, wire.len(), deadline).unwrap();
        let result = work.submit(request, std::future::pending());
        if packet == ferrum2_runtime::UDP_SESSION_QUEUE_DEPTH {
            assert_eq!(result, Err(UdpRuntimeError::QueueFull));
            assert_eq!(budget.reserved_bytes(), before);
        } else {
            result.unwrap();
        }
    }
    let mut other = UdpClientSession::new(&keys, &SystemRandom, |_| false).unwrap();
    let wire = encoded_udp_request(&mut other, &clock, target.clone(), b"other");
    let pending = protocol
        .prepare_request(&clock, &wire, &mut scratch)
        .unwrap();
    let before = budget.reserved_bytes();
    let request = work.account(pending, peer, wire.len(), deadline).unwrap();
    assert_eq!(
        work.submit(request, std::future::pending()),
        Err(UdpRuntimeError::SessionLimit)
    );
    assert_eq!(budget.reserved_bytes(), before);
    assert_eq!(protocol.session_count().unwrap(), 0);
    assert!(matches!(work.next().await, Err(UdpRuntimeError::Resolve)));
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(!work.has_work());

    let pending = protocol
        .prepare_request(&clock, &wire, &mut scratch)
        .unwrap();
    let request = work
        .account(pending, peer, wire.len(), deadline + Duration::from_secs(5))
        .unwrap();
    work.submit(request, std::future::pending()).unwrap();
    drop(work);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(protocol.session_count().unwrap(), 0);
    assert_eq!(active(registry.snapshot()), baseline);
}

struct SlowApplicationResolver {
    entered: AtomicUsize,
    changed: Notify,
    active: AtomicUsize,
    release: Semaphore,
}

struct ActiveResolution<'a>(&'a AtomicUsize);

impl Drop for ActiveResolution<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl ferrum2_dns::ApplicationResolveBackend for SlowApplicationResolver {
    fn resolve<'a>(
        &'a self,
        request: ferrum2_dns::ApplicationResolveRequest<'a>,
    ) -> ferrum2_dns::ApplicationResolveFuture<'a> {
        Box::pin(async move {
            self.active.fetch_add(1, Ordering::SeqCst);
            let _active = ActiveResolution(&self.active);
            self.entered.fetch_add(1, Ordering::SeqCst);
            self.changed.notify_waiters();
            self.release.acquire().await.unwrap().forget();
            Ok(vec![SocketAddr::from((
                Ipv4Addr::LOCALHOST,
                request.port().get(),
            ))])
        })
    }
}

#[tokio::test]
async fn slow_dns_identity_coalesces_without_blocking_established_listener_packets() {
    let listener = Arc::new(udp_loopback().await);
    let address = listener.local_addr().unwrap();
    let client_socket = udp_loopback().await;
    let target = udp_loopback().await;
    let target_address = target.local_addr().unwrap();
    let (path, config) = server_test_config(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1));
    let keys = aes_keys();
    let clock = Arc::new(SystemClock::new());
    let protocol = Arc::new(UdpServer::new(&keys).unwrap());
    let registry = OwnerRegistry::new();
    let baseline = active(registry.snapshot());
    let manager =
        UdpSessionManager::new(udp_runtime_limits(&config.udp).unwrap(), registry.clone());
    let budget = manager.buffer_budget();
    let backend = Arc::new(SlowApplicationResolver {
        entered: AtomicUsize::new(0),
        changed: Notify::new(),
        active: AtomicUsize::new(0),
        release: Semaphore::new(0),
    });
    let prepared = prepare_udp_server(
        0,
        listener,
        ServerUdpShared {
            routing: Arc::new(ServerRouting {
                program: config.route,
                outbound_count: config.outbounds.len(),
            }),
            protocol: Arc::clone(&protocol),
            clock: Arc::clone(&clock),
            config: config.udp,
            sessions: manager,
            mappings: Arc::new(UdpMappings::new(config.udp.max_sessions)),
            admission: Arc::new(tokio::sync::Mutex::new(())),
            connect_timeout: Duration::from_secs(10),
            direct_resolvers: vec![dns_egress::ServerDnsResolver::with_test_backend(
                backend.clone(),
            )]
            .into(),
            registry: registry.clone(),
            metrics: Arc::new(Metrics::new()),
        },
    )
    .unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(prepared.run_with_shutdown(
        async move {
            let _ = stopped.await;
        },
        |mut runtime| async move { runtime.shutdown(Duration::ZERO).await },
    ));
    let mut a = UdpClientSession::new(&keys, &SystemRandom, |_| false).unwrap();
    let mut b = UdpClientSession::new(&keys, &SystemRandom, |_| false).unwrap();
    let ip = TargetAddr::ip(target_address).unwrap();
    let wire = encoded_udp_request(&mut a, clock.as_ref(), ip.clone(), b"a-first");
    client_socket.send_to(&wire, address).await.unwrap();
    let mut buffer = [0_u8; 128];
    let (len, _) = recv_udp(&target, &mut buffer).await;
    assert_eq!(&buffer[..len], b"a-first");
    let domain = TargetAddr::domain("slow.example", target_address.port()).unwrap();
    let first_b = encoded_udp_request(&mut b, clock.as_ref(), domain, b"b-first");
    client_socket.send_to(&first_b, address).await.unwrap();
    wait_for_send_entries(&backend.entered, &backend.changed, 1).await;
    client_socket.send_to(&first_b, address).await.unwrap();
    let next_b = encoded_udp_request(&mut b, clock.as_ref(), ip.clone(), b"b-second");
    client_socket.send_to(&next_b, address).await.unwrap();
    let next_a = encoded_udp_request(&mut a, clock.as_ref(), ip, b"a-during-dns");
    client_socket.send_to(&next_a, address).await.unwrap();
    let (len, _) = recv_udp(&target, &mut buffer).await;
    assert_eq!(&buffer[..len], b"a-during-dns");
    assert_eq!(protocol.session_count().unwrap(), 1);
    assert_eq!(backend.entered.load(Ordering::SeqCst), 1);
    backend.release.add_permits(1);
    for expected in [b"b-first".as_slice(), b"b-second".as_slice()] {
        let (len, _) = recv_udp(&target, &mut buffer).await;
        assert_eq!(&buffer[..len], expected);
    }
    assert_eq!(protocol.session_count().unwrap(), 2);
    assert_eq!(backend.entered.load(Ordering::SeqCst), 1);
    stop.send(()).unwrap();
    assert_eq!(task.await.unwrap(), Ok(()));
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(active(registry.snapshot()), baseline);
    std::fs::remove_file(path).unwrap();
}

#[derive(Clone, Copy)]
enum ColdTermination {
    Shutdown,
    Deadline,
    Reset,
}

#[tokio::test]
async fn cold_dns_shutdown_deadline_and_reset_release_real_work_without_acceptance() {
    for termination in [
        ColdTermination::Shutdown,
        ColdTermination::Deadline,
        ColdTermination::Reset,
    ] {
        let listener = Arc::new(udp_loopback().await);
        let address = listener.local_addr().unwrap();
        let sender = udp_loopback().await;
        let target = udp_loopback().await;
        let (path, config) = server_test_config(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1));
        let keys = aes_keys();
        let clock = Arc::new(SystemClock::new());
        let protocol = Arc::new(UdpServer::new(&keys).unwrap());
        let registry = OwnerRegistry::new();
        let baseline = active(registry.snapshot());
        let manager =
            UdpSessionManager::new(udp_runtime_limits(&config.udp).unwrap(), registry.clone());
        let budget = manager.buffer_budget();
        let mappings = Arc::new(UdpMappings::new(config.udp.max_sessions));
        let admission = Arc::new(tokio::sync::Mutex::new(()));
        let reset = ServerUdpNetworkReset::new(
            1,
            manager.clone(),
            Arc::clone(&mappings),
            Arc::clone(&admission),
        );
        let backend = Arc::new(SlowApplicationResolver {
            entered: AtomicUsize::new(0),
            changed: Notify::new(),
            active: AtomicUsize::new(0),
            release: Semaphore::new(0),
        });
        let prepared = prepare_udp_server(
            0,
            listener,
            ServerUdpShared {
                routing: Arc::new(ServerRouting {
                    program: config.route,
                    outbound_count: config.outbounds.len(),
                }),
                protocol: Arc::clone(&protocol),
                clock: Arc::clone(&clock),
                config: config.udp,
                sessions: manager,
                mappings: Arc::clone(&mappings),
                admission,
                connect_timeout: match termination {
                    ColdTermination::Deadline => Duration::from_millis(100),
                    ColdTermination::Shutdown | ColdTermination::Reset => Duration::from_secs(10),
                },
                direct_resolvers: vec![dns_egress::ServerDnsResolver::with_test_backend(
                    backend.clone(),
                )]
                .into(),
                registry: registry.clone(),
                metrics: Arc::new(Metrics::new()),
            },
        )
        .unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(prepared.run_with_shutdown(
            async move {
                let _ = stopped.await;
            },
            |mut runtime| async move { runtime.shutdown(Duration::ZERO).await },
        ));
        let mut client = UdpClientSession::new(&keys, &SystemRandom, |_| false).unwrap();
        let domain =
            TargetAddr::domain("slow.example", target.local_addr().unwrap().port()).unwrap();
        let wire = encoded_udp_request(&mut client, clock.as_ref(), domain, b"must-not-commit");
        sender.send_to(&wire, address).await.unwrap();
        wait_for_send_entries(&backend.entered, &backend.changed, 1).await;
        assert_eq!(backend.active.load(Ordering::SeqCst), 1);
        match termination {
            ColdTermination::Shutdown => {}
            ColdTermination::Deadline => {
                tokio::time::timeout(Duration::from_secs(2), async {
                    while backend.active.load(Ordering::SeqCst) != 0 {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("whole admission deadline drops resolver");
            }
            ColdTermination::Reset => {
                ferrum2_runtime::ResetNetwork::reset_network(
                    &reset,
                    Arc::new(ferrum2_net::NetworkSnapshot::new(2, None, None).unwrap()),
                )
                .await
                .unwrap();
                backend.release.add_permits(1);
                tokio::time::timeout(Duration::from_secs(2), async {
                    while registry.snapshot().udp_sessions != 0
                        || backend.active.load(Ordering::SeqCst) != 0
                    {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("stale provisional generation retires");
                reset.finish_generation(2).await.unwrap();
            }
        }
        stop.send(()).unwrap();
        assert_eq!(task.await.unwrap(), Ok(()));
        assert_eq!(backend.active.load(Ordering::SeqCst), 0);
        assert_eq!(protocol.session_count().unwrap(), 0);
        assert!(mappings.state.lock().unwrap().by_capability.is_empty());
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(active(registry.snapshot()), baseline);
        assert_eq!(
            target.try_recv_from(&mut [0_u8; 64]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        // Re-preparing the exact packet demonstrates failed work did not consume replay.
        let mut scratch = UdpPacketScratch::new();
        let pending = protocol
            .prepare_request(clock.as_ref(), &wire, &mut scratch)
            .unwrap();
        assert!(protocol.existing_capability(&pending).unwrap().is_none());
        std::fs::remove_file(path).unwrap();
    }
}
