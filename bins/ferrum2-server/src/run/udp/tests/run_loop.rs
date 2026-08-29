use super::*;

#[tokio::test]
async fn listener_readiness_drain_yields_at_32_with_shutdown_priority() {
    let listen = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1);
    let (path, config) = server_test_config(listen);
    let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_100));
    let listener = Arc::new(BurstUdpListener {
        requests: Mutex::new((0..64).map(|_| (vec![0_u8], peer)).collect::<VecDeque<_>>()),
        awaited: AtomicUsize::new(0),
        tried: AtomicUsize::new(0),
        drain_cap_reached: Notify::new(),
    });
    let keys = aes_keys();
    let protocol = Arc::new(UdpServer::new(&keys).expect("server protocol"));
    let registry = OwnerRegistry::new();
    let baseline = active(registry.snapshot());
    let metrics = Arc::new(Metrics::new());
    let sessions = UdpSessionManager::new(
        udp_runtime_limits(&config.udp).expect("listener drain limits"),
        registry.clone(),
    );
    let prepared = prepare_udp_server(
        0,
        Arc::clone(&listener),
        ServerUdpShared {
            routing: Arc::new(ServerRouting {
                program: config.route,
                outbound_count: config.outbounds.len(),
            }),
            protocol: Arc::clone(&protocol),
            clock: Arc::new(SystemClock::new()),
            config: config.udp,
            sessions,
            mappings: Arc::new(UdpMappings::new(config.udp.max_sessions)),
            admission: Arc::new(tokio::sync::Mutex::new(())),
            connect_timeout: config.runtime.connect_timeout,
            direct_resolvers: vec![dns_egress::ServerDnsResolver::new(None)].into(),
            registry: registry.clone(),
            metrics: Arc::clone(&metrics),
        },
    )
    .expect("prepared listener drain root");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(prepared.run_with_shutdown(
        async move {
            let _ = stopped.await;
        },
        |runtime| async move { runtime.shutdown(Duration::ZERO).await },
    ));

    tokio::time::timeout(
        Duration::from_secs(1),
        listener.drain_cap_reached.notified(),
    )
    .await
    .expect("listener drain cap deadline");
    stop.send(()).expect("stop listener drain root");
    assert_eq!(task.await.expect("listener drain task"), Ok(()));
    assert_eq!(listener.awaited.load(Ordering::SeqCst), 1);
    assert_eq!(listener.tried.load(Ordering::SeqCst), 31);
    assert_eq!(
        listener
            .requests
            .lock()
            .expect("remaining burst requests")
            .len(),
        32,
        "shutdown wins immediately after the bounded batch yields"
    );
    assert_eq!(protocol.session_count().expect("protocol count"), 0);
    assert!(metrics.encode_text().expect("drain metrics").contains(
        "ferrum2_udp_failures_total{role=\"server\",stage=\"shadowsocks\",reason=\"bounds\"} 32"
    ));
    assert_eq!(active(registry.snapshot()), baseline);
    std::fs::remove_file(path).expect("remove listener drain config");
}

#[tokio::test]
async fn udp_shared_roots_drain_external_and_force_fatal_without_early_cleanup() {
    for fatal in [false, true] {
        let listen = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1);
        let (path, mut config) = server_test_config(listen);
        config.runtime.shutdown_grace = Duration::from_secs(u64::from(!fatal));
        let stalled_target = udp_loopback().await;
        let target = stalled_target.local_addr().expect("stalled target address");
        let keys = aes_keys();
        let mut c = UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("client");
        let wire = encoded_udp_request(
            &mut c,
            &SystemClock::new(),
            TargetAddr::ip(target).expect("target"),
            b"listener-failure",
        );
        let handler_entered = Arc::new(Notify::new());
        let response_gate = Arc::new(Notify::new());
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_089));
        let sent = Arc::new(Mutex::new(Vec::new()));
        let listener = Arc::new(ScriptedUdpListener {
            request: Mutex::new(Some((wire, peer))),
            terminal_gate: Arc::new(Notify::new()),
            handler_entered: Arc::clone(&handler_entered),
            response_gate: Arc::clone(&response_gate),
            sent: Arc::clone(&sent),
        });
        let fatal_gate = Arc::new(Notify::new());
        let fatal_listener = Arc::new(ScriptedUdpListener {
            request: Mutex::new(None),
            terminal_gate: Arc::clone(&fatal_gate),
            handler_entered: Arc::clone(&handler_entered),
            response_gate: Arc::clone(&response_gate),
            sent: Arc::clone(&sent),
        });
        let protocol = Arc::new(UdpServer::new(&keys).expect("server protocol"));
        let registry = OwnerRegistry::new();
        let baseline = active(registry.snapshot());
        let metrics = Arc::new(Metrics::new());
        let shutdown_grace = config.runtime.shutdown_grace;
        let limits = udp_runtime_limits(&config.udp).expect("validated UDP limits");
        let sessions = UdpSessionManager::new(limits, registry.clone());
        let mappings = Arc::new(UdpMappings::new(config.udp.max_sessions));
        let observed_mappings = Arc::clone(&mappings);
        let shared = ServerUdpShared {
            routing: Arc::new(ServerRouting {
                program: config.route,
                outbound_count: config.outbounds.len(),
            }),
            protocol,
            clock: Arc::new(SystemClock::new()),
            config: config.udp,
            sessions,
            mappings,
            admission: Arc::new(tokio::sync::Mutex::new(())),
            connect_timeout: config.runtime.connect_timeout,
            direct_resolvers: vec![dns_egress::ServerDnsResolver::new(None)].into(),
            registry: registry.clone(),
            metrics: Arc::clone(&metrics),
        };
        let fatal_shared = shared.clone();
        let active_root =
            ProcessRoot::new(move || async move { prepare_udp_server(0, listener, shared) });
        let failed =
            ProcessRoot::new(
                move || async move { prepare_udp_server(1, fatal_listener, fatal_shared) },
            );
        let supervisor =
            ProcessSupervisor::new(vec![active_root, failed], shutdown_grace, registry.clone())
                .expect("two required UDP roots");
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let mut process = tokio::spawn(supervisor.run_until(async {
            let _ = stopped.await;
        }));

        let mut target_buffer = [0_u8; 32];
        let (received, source) = recv_udp(&stalled_target, &mut target_buffer).await;
        assert_eq!(&target_buffer[..received], b"listener-failure");
        let live = registry.snapshot();
        assert_eq!(
            (live.active_process_roots, live.udp_sessions, live.udp_tasks),
            (2, 1, 1)
        );
        stalled_target
            .send_to(b"blocked-response", source)
            .await
            .expect("target response");
        handler_entered.notified().await;
        if fatal {
            fatal_gate.notify_one();
        } else {
            stop.send(()).expect("external stop");
            tokio::time::timeout(Duration::from_secs(1), async {
                while registry.snapshot().active_process_roots != 1 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("empty UDP root reap");
            let state = observed_mappings.snapshot();
            assert_eq!(state.by_capability.len(), 1);
            assert_eq!(state.by_capability.values().next().unwrap().inbound, 0);
            drop(state);
            response_gate.notify_one();
        }

        let report = match tokio::time::timeout(Duration::from_secs(2), &mut process).await {
            Ok(Ok(report)) => report,
            Ok(Err(error)) => panic!("process owner failed: {error}"),
            Err(_) => {
                process.abort();
                let _ = process.await;
                panic!("terminal UDP root waited for process Forced before returning");
            }
        };
        assert_eq!(report.cleanup_failure(), None);
        assert_eq!(active(registry.snapshot()), baseline);
        assert_eq!(report.forced_roots(), usize::from(fatal));
        assert_eq!(registry.snapshot().udp_forced_shutdowns, usize::from(fatal));
        if fatal {
            assert!(matches!(
                report.cause(),
                ProcessCause::RootStopped {
                    root,
                    exit: ProcessRootExit::Failed(RunError::RuntimeListener),
                } if root.get() == 1
            ));
            assert!(sent.lock().expect("scripted sends").is_empty());
            let encoded = metrics.encode_text().expect("metrics");
            assert!(encoded.contains("ferrum2_udp_forced_shutdown_total{role=\"server\"} 1"));
        } else {
            assert!(matches!(report.cause(), ProcessCause::ExternalShutdown));
            assert_eq!(&*sent.lock().expect("scripted sends"), &[peer]);
        }
        std::fs::remove_file(path).expect("remove terminal UDP config");
    }
}
