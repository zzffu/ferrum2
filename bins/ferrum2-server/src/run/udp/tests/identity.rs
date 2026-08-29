use super::*;

#[tokio::test]
async fn rejected_udp_identity_stays_rejected_and_shares_protocol_session_ceiling() {
    const REJECT_DNS_QUERY: &[u8] = &[
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, b'r', b'e',
        b'j', b'e', b'c', b't', 0x04, b't', b'e', b's', b't', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];
    let listener = Arc::new(udp_loopback().await);
    let listen = match listener.local_addr().expect("listener address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 listener"),
    };
    let route = "[route]\n\
        final = \"direct\"\n\
        [route.sniff]\n\
        max_bytes = 512\n\
        [[route.rules]]\n\
        network = \"udp\"\n\
        action = \"sniff\"\n\
        sniffers = \"dns\"\n\
        [[route.rules]]\n\
        network = \"udp\"\n\
        protocol = \"dns\"\n\
        domain = \"reject.test\"\n\
        action = \"reject\"\n";
    let (path, mut config) = server_v2_test_config(listen, route);
    config.udp.max_sessions = 1;
    let routing = ServerRouting {
        program: config.route,
        outbound_count: config.outbounds.len(),
    };
    let registry = OwnerRegistry::new();
    let sessions = UdpSessionManager::new(
        udp_runtime_limits(&config.udp).expect("capacity-one limits"),
        registry.clone(),
    );
    let mappings = Arc::new(UdpMappings::new(1));
    let keys = aes_keys();
    let protocol = Arc::new(UdpServer::new(&keys).expect("server protocol"));
    let clock = Arc::new(SystemClock::new());
    let metrics = Arc::new(Metrics::new());
    let prepared = prepare_udp_server(
        0,
        Arc::clone(&listener),
        ServerUdpShared {
            routing: Arc::new(routing),
            protocol: Arc::clone(&protocol),
            clock: Arc::clone(&clock),
            config: config.udp,
            sessions,
            mappings: Arc::clone(&mappings),
            admission: Arc::new(tokio::sync::Mutex::new(())),
            connect_timeout: config.runtime.connect_timeout,
            direct_resolvers: vec![dns_egress::ServerDnsResolver::new(None)].into(),
            registry: registry.clone(),
            metrics: Arc::clone(&metrics),
        },
    )
    .expect("prepare production UDP root");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(prepared.run_with_shutdown(
        async move {
            let _ = stopped.await;
        },
        |runtime| async move { runtime.shutdown(Duration::ZERO).await },
    ));

    let peer = udp_loopback().await;
    let target = udp_loopback().await;
    let target_address =
        TargetAddr::ip(target.local_addr().expect("target address")).expect("numeric target");
    let mut received = [0_u8; MAX_UDP_WIRE_DATAGRAM_BYTES];
    let mut first = UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("first identity");
    let rejected = encoded_udp_request(
        &mut first,
        clock.as_ref(),
        target_address.clone(),
        REJECT_DNS_QUERY,
    );
    peer.send_to(&rejected, listen)
        .await
        .expect("first typed reject");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if protocol.session_count().expect("first protocol count") == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first typed reject commit deadline");
    {
        let state = mappings.snapshot();
        assert_eq!((state.by_capability.len(), state.orphaned.len()), (0, 1));
        assert_eq!(
            state.orphaned.values().copied().next(),
            Some(FrozenUdpIdentity {
                inbound: 0,
                terminal: ServerTerminalRoute::Reject,
            })
        );
    }
    assert_eq!(registry.snapshot().udp_sessions, 0);
    assert_pending(target.recv_from(&mut received), "typed reject forwarded").await;

    peer.send_to(&rejected, listen)
        .await
        .expect("duplicate typed reject");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if metrics.encode_text().expect("duplicate metrics").contains(
                "ferrum2_udp_replay_rejections_total{role=\"server\",direction=\"client_to_target\",reason=\"duplicate\"} 1",
            ) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("duplicate rejection deadline");
    assert_eq!(protocol.session_count().expect("duplicate count"), 1);

    let first_direct = encoded_udp_request(
        &mut first,
        clock.as_ref(),
        target_address.clone(),
        b"first-direct",
    );
    peer.send_to(&first_direct, listen)
        .await
        .expect("send after frozen reject");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if metrics.encode_text().expect("frozen reject metrics").contains(
                "ferrum2_udp_datagrams_total{role=\"server\",direction=\"client_to_target\",outcome=\"rejected\"} 2",
            ) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("frozen reject commit deadline");
    assert_pending(
        target.recv_from(&mut received),
        "frozen reject upgraded to Direct",
    )
    .await;
    assert_eq!(protocol.session_count().expect("reject protocol count"), 1);
    assert_eq!(registry.snapshot().udp_sessions, 0);
    {
        let state = mappings.snapshot();
        assert_eq!((state.by_capability.len(), state.orphaned.len()), (0, 1));
    }

    let oversized_payload = vec![b'x'; 513];
    let oversized = encoded_udp_request(
        &mut first,
        clock.as_ref(),
        target_address.clone(),
        &oversized_payload,
    );
    peer.send_to(&oversized, listen)
        .await
        .expect("oversized authenticated datagram");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if metrics.encode_text().expect("oversized metrics").contains(
                "ferrum2_udp_datagrams_total{role=\"server\",direction=\"client_to_target\",outcome=\"rejected\"} 3",
            ) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("oversized frozen reject deadline");
    assert_pending(
        target.recv_from(&mut received),
        "oversized frozen reject was forwarded",
    )
    .await;
    assert!(!metrics.encode_text().expect("sniff metrics").contains(
        "ferrum2_sniff_total{role=\"server\",transport=\"udp\",stage=\"sniff\",outcome=\"limit\""
    ));

    let mut second =
        UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("second identity");
    let over_capacity = encoded_udp_request(
        &mut second,
        clock.as_ref(),
        target_address.clone(),
        REJECT_DNS_QUERY,
    );
    for expected_limits in 1..=2 {
        peer.send_to(&over_capacity, listen)
            .await
            .expect("over-capacity typed reject");
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if metrics.encode_text().expect("session limit metrics").contains(&format!(
                    "ferrum2_udp_failures_total{{role=\"server\",stage=\"relay\",reason=\"session_limit\"}} {expected_limits}"
                )) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("shared session ceiling deadline");
        assert_eq!(protocol.session_count().expect("shared ceiling count"), 1);
        assert_eq!(registry.snapshot().udp_sessions, 0);
        let state = mappings.snapshot();
        assert_eq!((state.by_capability.len(), state.orphaned.len()), (0, 1));
    }
    assert_pending(
        target.recv_from(&mut received),
        "over-capacity reject forwarded",
    )
    .await;
    assert!(metrics.encode_text().expect("replay metrics").contains(
        "ferrum2_udp_replay_rejections_total{role=\"server\",direction=\"client_to_target\",reason=\"duplicate\"} 1"
    ));

    let still_direct =
        encoded_udp_request(&mut first, clock.as_ref(), target_address, b"still-direct");
    peer.send_to(&still_direct, listen)
        .await
        .expect("existing rejected identity remains frozen");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if metrics.encode_text().expect("final reject metrics").contains(
                "ferrum2_udp_datagrams_total{role=\"server\",direction=\"client_to_target\",outcome=\"rejected\"} 4",
            ) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("final frozen reject deadline");
    assert_pending(
        target.recv_from(&mut received),
        "frozen reject later forwarded",
    )
    .await;

    stop.send(()).expect("stop production UDP root");
    assert_eq!(server.await.expect("production UDP task"), Ok(()));
    assert_eq!(active(registry.snapshot()), OwnerSnapshot::default());
    std::fs::remove_file(path).expect("remove typed reject config");
}

#[tokio::test]
async fn publishing_one_runtime_handle_never_wakes_another_and_cancelled_waiters_reclaim_owner() {
    let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9));
    let clock = SystemClock::new();
    let keys = aes_keys();
    let protocol = UdpServer::new(&keys).expect("publication server protocol");
    let registry = OwnerRegistry::new();
    let manager = UdpSessionManager::new(
        UdpRuntimeLimits::new(2, 1_048_576, Duration::from_secs(60)).expect("publication limits"),
        registry.clone(),
    );
    let mappings = Arc::new(UdpMappings::new(2));
    let now = tokio::time::Instant::now();

    let first = Datagram::new(
        TargetAddr::ip(target).expect("first publication target"),
        b"first".as_slice().into(),
        5,
    )
    .expect("first publication datagram");
    let first_session = manager
        .reserve_session(now)
        .expect("first publication session");
    let first_reserved = first_session
        .reserve_datagram(UdpDirection::ToTarget, first.allocated_capacity())
        .expect("first publication reservation");
    let handle_a = first_session
        .commit(first_reserved, first, now)
        .expect("first unpublished handle");
    drop(
        manager
            .pop(handle_a, UdpDirection::ToTarget)
            .expect("first publication queue")
            .expect("first publication datagram"),
    );

    let second = Datagram::new(
        TargetAddr::ip(target).expect("second publication target"),
        b"second".as_slice().into(),
        6,
    )
    .expect("second publication datagram");
    let second_session = manager
        .reserve_session(now)
        .expect("second publication session");
    let second_reserved = second_session
        .reserve_datagram(UdpDirection::ToTarget, second.allocated_capacity())
        .expect("second publication reservation");
    let handle_b = second_session
        .commit(second_reserved, second, now)
        .expect("second unpublished handle");
    drop(
        manager
            .pop(handle_b, UdpDirection::ToTarget)
            .expect("second publication queue")
            .expect("second publication datagram"),
    );

    let wait_a = tokio::spawn({
        let mappings = Arc::clone(&mappings);
        async move { mappings.capability(handle_a).await }
    });
    let wait_b = tokio::spawn({
        let mappings = Arc::clone(&mappings);
        async move { mappings.capability(handle_b).await }
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while mappings.publication_owner_count() != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("per-handle publication registration deadline");
    let signal_b = mappings
        .publication_signal(handle_b)
        .expect("handle B publication signal");

    let mut client =
        UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("publication client");
    let mut scratch = UdpPacketScratch::new();
    let wire = encoded_udp_request(
        &mut client,
        &clock,
        TargetAddr::ip(target).expect("publication request target"),
        b"publish-a",
    );
    let pending = protocol
        .prepare_request(&clock, &wire, &mut scratch)
        .expect("prepare publication request");
    let (_datagram, commit) = pending.into_parts();
    let capability_a = protocol
        .commit_request(
            commit,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_090)),
            clock.monotonic_now(),
            &SystemRandom,
        )
        .expect("commit publication request")
        .capability();
    assert_eq!(
        mappings.publish(capability_a, handle_a, 0, ServerTerminalRoute::Direct(0),),
        None
    );

    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), wait_a)
            .await
            .expect("handle A publication deadline")
            .expect("handle A waiter"),
        Some(capability_a)
    );
    tokio::task::yield_now().await;
    assert!(
        !wait_b.is_finished(),
        "publishing handle A completed handle B"
    );
    assert!(!*signal_b.borrow(), "handle B was signalled by A");
    assert!(
        !signal_b
            .has_changed()
            .expect("handle B publication channel remains open")
    );

    wait_b.abort();
    assert!(
        wait_b
            .await
            .expect_err("cancel handle B waiter")
            .is_cancelled()
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        while mappings.publication_owner_count() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelled publication owner cleanup deadline");
    assert!(manager.remove(handle_a));
    assert!(manager.remove(handle_b));
    assert_eq!(registry.snapshot().udp_sessions, 0);
}

#[test]
fn same_shard_tombstones_share_one_global_protection_window() {
    const TOMBSTONE_LIMIT: usize = 16;
    let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9));
    let registry = OwnerRegistry::new();
    let manager = UdpSessionManager::new(
        UdpRuntimeLimits::new(1, 1_048_576, Duration::from_secs(60))
            .expect("tombstone churn limits"),
        registry.clone(),
    );
    let mut by_shard: [Vec<UdpSessionHandle>; super::super::identity::UDP_MAPPING_SHARD_COUNT] =
        std::array::from_fn(|_| Vec::new());

    for _ in 0..4096 {
        let now = tokio::time::Instant::now();
        let datagram = Datagram::new(
            TargetAddr::ip(target).expect("tombstone target"),
            b"x".as_slice().into(),
            1,
        )
        .expect("tombstone datagram");
        let session = manager.reserve_session(now).expect("tombstone session");
        let reserved = session
            .reserve_datagram(UdpDirection::ToTarget, datagram.allocated_capacity())
            .expect("tombstone reservation");
        let handle = session
            .commit(reserved, datagram, now)
            .expect("tombstone handle");
        drop(
            manager
                .pop(handle, UdpDirection::ToTarget)
                .expect("tombstone queue")
                .expect("tombstone datagram queue entry"),
        );
        assert!(manager.remove(handle));
        let shard = UdpMappings::handle_shard_index(handle);
        by_shard[shard].push(handle);
        if by_shard[shard].len() == TOMBSTONE_LIMIT + 1 {
            break;
        }
    }
    let handles = by_shard
        .into_iter()
        .find(|handles| handles.len() == TOMBSTONE_LIMIT + 1)
        .expect("same-shard tombstone candidates");
    let mappings = UdpMappings::new(TOMBSTONE_LIMIT);

    for (index, handle) in handles[..TOMBSTONE_LIMIT].iter().copied().enumerate() {
        mappings.invalidate_handle(handle);
        assert_eq!(mappings.retired_handle_count(), index + 1);
    }
    mappings.invalidate_handle(handles[0]);
    assert_eq!(mappings.retired_handle_count(), TOMBSTONE_LIMIT);
    let state = mappings.snapshot();
    assert_eq!(state.retired.len(), TOMBSTONE_LIMIT);
    for handle in &handles[..TOMBSTONE_LIMIT] {
        assert!(state.retired.contains(handle));
        let mut lookup = std::pin::pin!(mappings.capability(*handle));
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert_eq!(
            std::future::Future::poll(lookup.as_mut(), &mut context),
            std::task::Poll::Ready(None)
        );
        assert_eq!(mappings.publication_owner_count(), 0);
    }

    mappings.invalidate_handle(handles[TOMBSTONE_LIMIT]);
    assert_eq!(mappings.retired_handle_count(), TOMBSTONE_LIMIT);
    assert_eq!(mappings.snapshot().retired.len(), TOMBSTONE_LIMIT);
    assert_eq!(mappings.reset_runtime(), 0);
    assert_eq!(mappings.retired_handle_count(), TOMBSTONE_LIMIT);
    assert_eq!(registry.snapshot().udp_sessions, 0);
}

#[tokio::test]
async fn invalidation_between_publish_phases_cannot_resurrect_a_handle() {
    let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9));
    let clock = SystemClock::new();
    let keys = aes_keys();
    let protocol = UdpServer::new(&keys).expect("publication race protocol");
    let mut client =
        UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("publication race client");
    let mut scratch = UdpPacketScratch::new();
    let wire = encoded_udp_request(
        &mut client,
        &clock,
        TargetAddr::ip(target).expect("publication race target"),
        b"publication-race",
    );
    let (_, commit) = protocol
        .prepare_request(&clock, &wire, &mut scratch)
        .expect("publication race prepare")
        .into_parts();
    let capability = protocol
        .commit_request(
            commit,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_094)),
            clock.monotonic_now(),
            &SystemRandom,
        )
        .expect("publication race commit")
        .capability();

    let registry = OwnerRegistry::new();
    let manager = UdpSessionManager::new(
        UdpRuntimeLimits::new(1, 1_048_576, Duration::from_secs(60))
            .expect("publication race limits"),
        registry.clone(),
    );
    let now = tokio::time::Instant::now();
    let datagram = Datagram::new(
        TargetAddr::ip(target).expect("publication runtime target"),
        b"runtime".as_slice().into(),
        7,
    )
    .expect("publication runtime datagram");
    let session = manager
        .reserve_session(now)
        .expect("publication runtime session");
    let reserved = session
        .reserve_datagram(UdpDirection::ToTarget, datagram.allocated_capacity())
        .expect("publication runtime reservation");
    let handle = session
        .commit(reserved, datagram, now)
        .expect("publication runtime handle");
    drop(
        manager
            .pop(handle, UdpDirection::ToTarget)
            .expect("publication runtime queue")
            .expect("publication runtime queue entry"),
    );

    let mappings = Arc::new(UdpMappings::new(1));
    let waiter = tokio::spawn({
        let mappings = Arc::clone(&mappings);
        async move { mappings.capability(handle).await }
    });
    while mappings.publication_owner_count() != 1 {
        tokio::task::yield_now().await;
    }

    let barrier = Arc::new(std::sync::Barrier::new(2));
    mappings.set_publish_phase_one_barrier(Some(Arc::clone(&barrier)));
    let publisher = std::thread::spawn({
        let mappings = Arc::clone(&mappings);
        move || mappings.publish(capability, handle, 0, ServerTerminalRoute::Direct(0))
    });
    barrier.wait();
    mappings.invalidate_handle(handle);
    barrier.wait();
    assert_eq!(
        publisher.join().expect("publication race thread"),
        Some(capability)
    );
    mappings.set_publish_phase_one_barrier(None);

    assert_eq!(waiter.await.expect("publication race waiter"), None);
    assert_eq!(mappings.handle(capability), None);
    let state = mappings.snapshot();
    assert!(!state.by_capability.contains_key(&capability));
    assert!(!state.by_handle.contains_key(&handle));
    assert!(state.retired.contains(&handle));
    assert_eq!(mappings.retired_handle_count(), 1);
    assert_eq!(mappings.publication_owner_count(), 0);
    assert!(manager.remove(handle));
    assert_eq!(registry.snapshot().udp_sessions, 0);
}

#[test]
fn different_udp_mapping_shards_publish_without_cross_shard_blocking() {
    assert_eq!(super::super::identity::UDP_MAPPING_SHARD_COUNT, 16);
    assert!(super::super::identity::UDP_MAPPING_SHARD_COUNT.is_power_of_two());

    let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9));
    let clock = SystemClock::new();
    let keys = aes_keys();
    let protocol = UdpServer::new(&keys).expect("sharded mapping protocol");
    let registry = OwnerRegistry::new();
    let manager = UdpSessionManager::new(
        UdpRuntimeLimits::new(64, 8_388_608, Duration::from_secs(60))
            .expect("sharded mapping limits"),
        registry.clone(),
    );
    let mappings = Arc::new(UdpMappings::new(64));
    let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_093));
    let mut scratch = UdpPacketScratch::new();
    let mut generations: Vec<(ServerResponseCapability, UdpSessionHandle)> = Vec::new();
    let mut pair = None;

    for _ in 0..64 {
        let mut client =
            UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("shard client");
        let generation = commit_lifecycle_generation(
            &mut client,
            &protocol,
            &manager,
            &mappings,
            &clock,
            target,
            peer,
            b"shard-generation",
            ferrum2_crypto::MonotonicInstant::ZERO,
            &mut scratch,
        );
        if let Some(first) = generations.first().copied()
            && UdpMappings::capability_shard_index(first.0)
                != UdpMappings::capability_shard_index(generation.0)
            && UdpMappings::handle_shard_index(first.1)
                != UdpMappings::handle_shard_index(generation.1)
        {
            pair = Some((first, generation));
        }
        generations.push(generation);
        if pair.is_some() {
            break;
        }
    }
    let ((capability_a, handle_a), (capability_b, handle_b)) =
        pair.expect("two generations mapped to different shards");

    let (capability_entered_tx, capability_entered_rx) = std::sync::mpsc::channel();
    let (capability_release_tx, capability_release_rx) = std::sync::mpsc::channel();
    let capability_holder = std::thread::spawn({
        let mappings = Arc::clone(&mappings);
        move || {
            mappings.with_capability_shard_locked(capability_a, || {
                capability_entered_tx
                    .send(())
                    .expect("signal held capability shard");
                capability_release_rx
                    .recv_timeout(Duration::from_secs(5))
                    .expect("release held capability shard");
            });
        }
    });
    capability_entered_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("capability shard lock deadline");
    let (capability_result_tx, capability_result_rx) = std::sync::mpsc::channel();
    let capability_publisher = std::thread::spawn({
        let mappings = Arc::clone(&mappings);
        move || {
            let result =
                mappings.publish(capability_b, handle_b, 0, ServerTerminalRoute::Direct(0));
            capability_result_tx
                .send(result)
                .expect("send capability-shard publish result");
        }
    });
    let capability_result = capability_result_rx.recv_timeout(Duration::from_secs(1));
    capability_release_tx
        .send(())
        .expect("release capability shard");
    capability_holder.join().expect("capability shard holder");
    capability_publisher
        .join()
        .expect("capability shard publisher");
    assert_eq!(
        capability_result.expect("different capability shard publish deadline"),
        None
    );

    let (handle_entered_tx, handle_entered_rx) = std::sync::mpsc::channel();
    let (handle_release_tx, handle_release_rx) = std::sync::mpsc::channel();
    let handle_holder = std::thread::spawn({
        let mappings = Arc::clone(&mappings);
        move || {
            mappings.with_handle_shard_locked(handle_a, || {
                handle_entered_tx
                    .send(())
                    .expect("signal held handle shard");
                handle_release_rx
                    .recv_timeout(Duration::from_secs(5))
                    .expect("release held handle shard");
            });
        }
    });
    handle_entered_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("handle shard lock deadline");
    let (handle_result_tx, handle_result_rx) = std::sync::mpsc::channel();
    let handle_publisher = std::thread::spawn({
        let mappings = Arc::clone(&mappings);
        move || {
            let result =
                mappings.publish(capability_b, handle_b, 0, ServerTerminalRoute::Direct(0));
            handle_result_tx
                .send(result)
                .expect("send handle-shard publish result");
        }
    });
    let handle_result = handle_result_rx.recv_timeout(Duration::from_secs(1));
    handle_release_tx.send(()).expect("release handle shard");
    handle_holder.join().expect("handle shard holder");
    handle_publisher.join().expect("handle shard publisher");
    assert_eq!(
        handle_result.expect("different handle shard publish deadline"),
        None
    );

    for (capability, handle) in generations {
        mappings.invalidate_handle(handle);
        assert_eq!(mappings.handle(capability), None);
        assert!(manager.remove(handle));
    }
    assert_eq!(registry.snapshot().udp_sessions, 0);
}

#[tokio::test]
async fn udp_generation_termination_retention_and_replacement_cleanup() {
    let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9));
    let client_clock = SystemClock::new();
    let lifecycle_keys = aes_keys();
    let lifecycle_protocol = UdpServer::new(&lifecycle_keys).expect("lifecycle server protocol");
    let manager_registry = OwnerRegistry::new();
    let manager = UdpSessionManager::new(
        UdpRuntimeLimits::new(1, 1_048_576, Duration::from_secs(60)).expect("capacity-one limits"),
        manager_registry.clone(),
    );
    let mappings = UdpMappings::new(1);
    let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_091));
    let protocol_zero = ferrum2_crypto::MonotonicInstant::ZERO;
    let mut lifecycle_scratch = UdpPacketScratch::new();
    let mut lifecycle_wire = vec![0_u8; MAX_UDP_WIRE_DATAGRAM_BYTES];
    let mut client_a =
        UdpClientSession::new(&lifecycle_keys, &SystemRandom, |_| false).expect("client A");
    let (capability_a, handle_a) = commit_lifecycle_generation(
        &mut client_a,
        &lifecycle_protocol,
        &manager,
        &mappings,
        &client_clock,
        target,
        peer,
        b"generation-a",
        protocol_zero,
        &mut lifecycle_scratch,
    );
    assert_eq!(
        lifecycle_protocol
            .session_count()
            .expect("protocol A count"),
        1
    );
    assert_eq!(manager_registry.snapshot().udp_sessions, 1);

    assert!(manager.remove(handle_a));
    mappings.reconcile_runtime(&manager);
    assert_eq!(mappings.handle(capability_a), None);
    assert_eq!(
        mappings.identity(capability_a),
        Some(FrozenUdpIdentity {
            inbound: 0,
            terminal: ServerTerminalRoute::Direct(0),
        })
    );
    assert_eq!(mappings.capability(handle_a).await, None);
    assert_eq!(manager_registry.snapshot().udp_sessions, 0);
    mappings.prune_protocol(
        &lifecycle_protocol,
        ferrum2_crypto::MonotonicInstant::from_duration(Duration::from_millis(59_999)),
    );
    assert_eq!(
        lifecycle_protocol
            .session_count()
            .expect("retained A count"),
        1
    );
    mappings.prune_protocol(
        &lifecycle_protocol,
        ferrum2_crypto::MonotonicInstant::from_duration(Duration::from_secs(60)),
    );
    assert_eq!(
        lifecycle_protocol.session_count().expect("retired A count"),
        0
    );
    assert_eq!(mappings.identity(capability_a), None);
    let late_response = Datagram::new(
        TargetAddr::ip(target).expect("late target"),
        b"late".as_slice().into(),
        4,
    )
    .expect("late response");
    assert_eq!(
        lifecycle_protocol
            .encode_response(
                capability_a,
                &client_clock,
                &SystemRandom,
                &late_response,
                0,
                &mut lifecycle_wire,
            )
            .expect_err("retired A capability"),
        UdpPacketError::Generation
    );

    let mut client_b =
        UdpClientSession::new(&lifecycle_keys, &SystemRandom, |_| false).expect("client B");
    let (capability_b, handle_b) = commit_lifecycle_generation(
        &mut client_b,
        &lifecycle_protocol,
        &manager,
        &mappings,
        &client_clock,
        target,
        peer,
        b"generation-b",
        ferrum2_crypto::MonotonicInstant::from_duration(Duration::from_secs(60)),
        &mut lifecycle_scratch,
    );
    assert_ne!(capability_b, capability_a);
    assert_eq!(
        lifecycle_protocol
            .session_count()
            .expect("protocol B count"),
        1
    );
    assert_eq!(manager_registry.snapshot().udp_sessions, 1);

    assert!(manager.remove(handle_b));
    mappings.reconcile_runtime(&manager);
    mappings.prune_protocol(
        &lifecycle_protocol,
        ferrum2_crypto::MonotonicInstant::from_duration(Duration::from_secs(120)),
    );
    assert_eq!(
        lifecycle_protocol.session_count().expect("retired B count"),
        0
    );
    assert_eq!(manager_registry.snapshot().udp_sessions, 0);
    assert_eq!(manager_registry.snapshot().udp_buffered_bytes, 0);
}

#[tokio::test]
async fn network_reset_immediately_retires_udp_runtime_mapping_and_allows_rebuild() {
    let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9));
    let clock = SystemClock::new();
    let keys = aes_keys();
    let protocol = UdpServer::new(&keys).expect("reset server protocol");
    let registry = OwnerRegistry::new();
    let manager = UdpSessionManager::new(
        UdpRuntimeLimits::new(1, 1_048_576, Duration::from_secs(60)).expect("reset limits"),
        registry.clone(),
    );
    let mappings = Arc::new(UdpMappings::new(1));
    let admission = Arc::new(tokio::sync::Mutex::new(()));
    let hook = ServerUdpNetworkReset::new(1, manager.clone(), Arc::clone(&mappings), admission);
    let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_092));
    let mut scratch = UdpPacketScratch::new();
    let mut client = UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("reset client");
    let (capability, old_handle) = commit_lifecycle_generation(
        &mut client,
        &protocol,
        &manager,
        &mappings,
        &clock,
        target,
        peer,
        b"before-reset",
        ferrum2_crypto::MonotonicInstant::ZERO,
        &mut scratch,
    );

    ferrum2_runtime::ResetNetwork::reset_network(
        &hook,
        Arc::new(
            ferrum2_net::NetworkSnapshot::new(2, None, None).expect("generation two snapshot"),
        ),
    )
    .await
    .expect("generation two reset");

    assert_eq!(registry.snapshot().udp_sessions, 0);
    assert_eq!(mappings.handle(capability), None);
    assert_eq!(
        mappings.identity(capability),
        Some(FrozenUdpIdentity {
            inbound: 0,
            terminal: ServerTerminalRoute::Direct(0),
        })
    );
    assert_eq!(mappings.capability(old_handle).await, None);
    assert_eq!(
        manager
            .reserve_datagram(old_handle, UdpDirection::ToTarget, 1)
            .expect_err("old runtime handle is retired"),
        UdpRuntimeError::Cancelled
    );
    {
        let state = mappings.snapshot();
        assert!(state.by_capability.is_empty());
        assert!(state.by_handle.is_empty());
        assert!(state.retired.contains(&old_handle));
    }

    let (rebuilt_capability, new_handle) = commit_lifecycle_generation(
        &mut client,
        &protocol,
        &manager,
        &mappings,
        &clock,
        target,
        peer,
        b"after-reset",
        ferrum2_crypto::MonotonicInstant::from_duration(Duration::from_secs(1)),
        &mut scratch,
    );
    assert_eq!(rebuilt_capability, capability);
    assert_ne!(new_handle, old_handle);
    assert_eq!(
        mappings.handle(capability).map(|binding| binding.handle),
        Some(new_handle)
    );

    ferrum2_runtime::ResetNetwork::reset_network(
        &hook,
        Arc::new(
            ferrum2_net::NetworkSnapshot::new(2, None, None)
                .expect("idempotent generation snapshot"),
        ),
    )
    .await
    .expect("same generation reset is idempotent");
    assert_eq!(registry.snapshot().udp_sessions, 1);
    assert_eq!(
        mappings.handle(capability).map(|binding| binding.handle),
        Some(new_handle)
    );

    ferrum2_runtime::ResetNetwork::reset_network(
        &hook,
        Arc::new(
            ferrum2_net::NetworkSnapshot::new(3, None, None).expect("generation three snapshot"),
        ),
    )
    .await
    .expect("generation three reset");
    assert_eq!(registry.snapshot().udp_sessions, 0);
    assert_eq!(mappings.handle(capability), None);
    assert_eq!(mappings.capability(new_handle).await, None);
    assert_eq!(
        mappings.identity(capability),
        Some(FrozenUdpIdentity {
            inbound: 0,
            terminal: ServerTerminalRoute::Direct(0),
        })
    );
}

#[tokio::test]
async fn udp_mapping_pins_first_direct_and_forwards_later_targets() {
    let listen = reserve_address();
    let first_target = udp_loopback().await;
    let second_target = udp_loopback().await;
    let first_address = first_target.local_addr().expect("first target address");
    let second_address = second_target.local_addr().expect("second target address");
    let source = format!(
        r#"schema_version = 2
[[inbounds]]
tag = "i0"
listen = "{listen}"

[[outbounds]]
tag = "o0"

[[outbounds]]
tag = "o1"

[route]
final = "o0"

[[route.rules]]
network = "udp"
port = {}
action = "route"
outbound = "o1"

[shadowsocks]
method = "2022-blake3-aes-128-gcm"
psk = "AAECAwQFBgcICQoLDA0ODw=="

[runtime]
shutdown_grace_ms = 0

[udp]
enabled = true
max_sessions = 1
"#,
        second_address.port()
    );
    let (path, config) = server_test_config_source("udp-direct-pin", &source);
    let registry = OwnerRegistry::new();
    let baseline = active(registry.snapshot());
    let (stop, mut server) = spawn_test_server(config, &registry);
    wait_until_bound(&mut server, listen).await;

    let keys = aes_keys();
    let clock = SystemClock::new();
    let mut client =
        UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("client protocol");
    let socket = udp_loopback().await;
    let first = encoded_udp_request(
        &mut client,
        &clock,
        TargetAddr::ip(first_address).expect("first target"),
        b"first outbound",
    );
    socket
        .send_to(&first, listen)
        .await
        .expect("send first outbound request");
    let mut received = [0_u8; 64];
    let (length, _) = tokio::time::timeout(
        Duration::from_secs(1),
        first_target.recv_from(&mut received),
    )
    .await
    .expect("first outbound receive deadline")
    .expect("first outbound receive");
    assert_eq!(&received[..length], b"first outbound");

    let later_target = encoded_udp_request(
        &mut client,
        &clock,
        TargetAddr::ip(second_address).expect("second target"),
        b"frozen outbound",
    );
    socket
        .send_to(&later_target, listen)
        .await
        .expect("send later target request");
    let (length, _) = tokio::time::timeout(
        Duration::from_secs(1),
        second_target.recv_from(&mut received),
    )
    .await
    .expect("later target receive deadline")
    .expect("later target receive");
    assert_eq!(&received[..length], b"frozen outbound");
    let pinned = encoded_udp_request(
        &mut client,
        &clock,
        TargetAddr::ip(first_address).expect("pinned target"),
        b"pinned outbound",
    );
    socket
        .send_to(&pinned, listen)
        .await
        .expect("send pinned outbound request");
    let (length, _) = tokio::time::timeout(
        Duration::from_secs(1),
        first_target.recv_from(&mut received),
    )
    .await
    .expect("pinned outbound receive deadline")
    .expect("pinned outbound receive");
    assert_eq!(&received[..length], b"pinned outbound");

    stop.send(()).expect("stop pinned UDP server");
    assert_eq!(server.await.expect("pinned UDP server task"), Ok(()));
    assert_eq!(active(registry.snapshot()), baseline);
    std::fs::remove_file(path).expect("remove pinned UDP config");
}
