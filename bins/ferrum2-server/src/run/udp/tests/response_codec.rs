use super::*;
use crate::run::udp::response_codec::{MAX_RESPONSE_CODEC_SHARDS, response_codec_shards};

#[tokio::test]
async fn response_codec_does_not_serialize_concurrent_sends() {
    let keys = aes_keys();
    let protocol = Arc::new(UdpServer::new(&keys).expect("server protocol"));
    let clock = Arc::new(SystemClock::new());
    let registry = OwnerRegistry::new();
    let baseline = active(registry.snapshot());
    let manager = UdpSessionManager::new(
        UdpRuntimeLimits::new(2, 1024 * 1024, Duration::from_secs(60)).expect("response limits"),
        registry.clone(),
    );
    let mappings = Arc::new(UdpMappings::new(2));
    let mut first_client =
        UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("first client");
    let mut second_client =
        UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("second client");
    let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53));
    let first_peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_001));
    let second_peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_002));
    let mut request_scratch = UdpPacketScratch::new();
    let (_, first_handle) = commit_lifecycle_generation(
        &mut first_client,
        &protocol,
        &manager,
        &mappings,
        &clock,
        target,
        first_peer,
        b"first request",
        ferrum2_crypto::MonotonicInstant::from_duration(Duration::ZERO),
        &mut request_scratch,
    );
    let (_, second_handle) = commit_lifecycle_generation(
        &mut second_client,
        &protocol,
        &manager,
        &mappings,
        &clock,
        target,
        second_peer,
        b"second request",
        ferrum2_crypto::MonotonicInstant::from_duration(Duration::ZERO),
        &mut request_scratch,
    );
    let first_response = accounted_response(
        &mut first_client,
        &protocol,
        &manager,
        &clock,
        first_handle,
        (target, b"first response"),
        &mut request_scratch,
    );
    let second_response = accounted_response(
        &mut second_client,
        &protocol,
        &manager,
        &clock,
        second_handle,
        (target, b"second response"),
        &mut request_scratch,
    );
    let entered = Arc::new(AtomicUsize::new(0));
    let entry_changed = Arc::new(Notify::new());
    let send_gate = Arc::new(Semaphore::new(0));
    let sent = Arc::new(Mutex::new(Vec::new()));
    let listener = Arc::new(ConcurrentSendListener {
        entered: Arc::clone(&entered),
        entry_changed: Arc::clone(&entry_changed),
        send_gate: Arc::clone(&send_gate),
        sent: Arc::clone(&sent),
    });
    #[cfg(feature = "structural-metrics")]
    let structural = ferrum2_structural::StructuralHub::new();
    let handler = Arc::new(ServerUdpResponseHandler {
        listener,
        protocol: Arc::clone(&protocol),
        mappings,
        clock: Arc::clone(&clock),
        codec: Arc::new(
            ResponseCodecPool::new(manager.buffer_budget(), 2).expect("response codec"),
        ),
        metrics: Arc::new(Metrics::new()),
        #[cfg(feature = "structural-metrics")]
        structural: structural.local(),
    });

    let first_task = tokio::spawn({
        let handler = Arc::clone(&handler);
        async move {
            handler
                .handle_target_response(first_handle, first_response)
                .await
        }
    });
    wait_for_send_entries(&entered, &entry_changed, 1).await;
    let second_task = tokio::spawn({
        let handler = Arc::clone(&handler);
        async move {
            handler
                .handle_target_response(second_handle, second_response)
                .await
        }
    });

    wait_for_send_entries(&entered, &entry_changed, 2).await;
    let fixed_codec_capacity = handler.codec.shard_count() * 2 * MAX_UDP_WIRE_DATAGRAM_BYTES;
    assert_eq!(
        registry.snapshot().udp_buffered_bytes,
        fixed_codec_capacity,
        "all shard direct-to-wire capacity is fixed and charged at startup"
    );
    send_gate.add_permits(2);
    assert!(first_task.await.expect("first response task").is_ok());
    assert!(second_task.await.expect("second response task").is_ok());
    assert_eq!(
        registry.snapshot().udp_buffered_bytes,
        fixed_codec_capacity,
        "leased wires return to the fixed pool without changing its budget"
    );
    assert_eq!(
        handler.codec.available_wire_count(),
        handler.codec.shard_count() * 2
    );

    {
        let sent = sent.lock().expect("concurrent sends");
        assert_eq!(sent.len(), 2);
        let mut response_scratch = UdpPacketScratch::new();
        for (peer, wire) in &*sent {
            let pending = if *peer == first_peer {
                first_client
                    .prepare_response(clock.as_ref(), wire, &mut response_scratch)
                    .expect("first encoded response")
            } else {
                assert_eq!(*peer, second_peer);
                second_client
                    .prepare_response(clock.as_ref(), wire, &mut response_scratch)
                    .expect("second encoded response")
            };
            let expected = if *peer == first_peer {
                b"first response".as_slice()
            } else {
                b"second response".as_slice()
            };
            assert_eq!(pending.datagram().payload(), expected);
        }
    }

    let serial_response = accounted_response(
        &mut first_client,
        &protocol,
        &manager,
        &clock,
        first_handle,
        (target, b"serial response"),
        &mut request_scratch,
    );
    assert!(
        handler
            .handle_target_response(first_handle, serial_response)
            .await
            .is_ok()
    );
    assert_eq!(
        handler.codec.available_wire_count(),
        handler.codec.shard_count() * 2
    );
    assert_eq!(
        registry.snapshot().udp_buffered_bytes,
        fixed_codec_capacity,
        "steady-state responses reuse the fixed accounted shard wires"
    );

    #[cfg(feature = "structural-metrics")]
    {
        let snapshot = structural.snapshot();
        assert!(snapshot.get(ferrum2_structural::StructuralCounter::ResponseCodecLockSamples) >= 3);
        assert!(snapshot.get(ferrum2_structural::StructuralCounter::UdpPayloadToWireCopyBytes) > 0);
    }

    manager.cancel_all();
    drop(handler);
    drop(manager);
    assert_eq!(active(registry.snapshot()), baseline);
}

#[tokio::test]
async fn response_codec_pool_is_fixed_and_third_lease_waits_for_one_return() {
    let keys = aes_keys();
    let protocol = Arc::new(UdpServer::new(&keys).expect("server protocol"));
    let clock = Arc::new(SystemClock::new());
    let registry = OwnerRegistry::new();
    let baseline = active(registry.snapshot());
    let byte_limit = 1024 * 1024;
    let manager = UdpSessionManager::new(
        UdpRuntimeLimits::new(1, byte_limit, Duration::from_secs(60)).expect("response limits"),
        registry.clone(),
    );
    let budget = manager.buffer_budget();
    let codec = Arc::new(ResponseCodecPool::new(budget.clone(), 1).expect("response codec"));
    let mappings = UdpMappings::new(1);
    let mut client =
        UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("client protocol");
    let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53));
    let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_003));
    let mut scratch = UdpPacketScratch::new();
    let (capability, _handle) = commit_lifecycle_generation(
        &mut client,
        protocol.as_ref(),
        &manager,
        &mappings,
        clock.as_ref(),
        target,
        peer,
        b"request",
        ferrum2_crypto::MonotonicInstant::from_duration(Duration::ZERO),
        &mut scratch,
    );
    let wire = encoded_udp_request(
        &mut client,
        clock.as_ref(),
        TargetAddr::ip(target).expect("response source target"),
        b"response",
    );
    let pending = protocol
        .prepare_request(clock.as_ref(), &wire, &mut scratch)
        .expect("prepare response datagram");
    let (response, _unused_commit) = pending.into_parts();
    let response = Arc::new(response);

    let first_encoded = codec
        .encode(protocol.as_ref(), capability, clock.as_ref(), &response)
        .await
        .unwrap_or_else(|_| panic!("first fixed wire encodes"));
    let second_encoded = codec
        .encode(protocol.as_ref(), capability, clock.as_ref(), &response)
        .await
        .unwrap_or_else(|_| panic!("second fixed wire encodes"));
    assert_eq!(
        budget.reserved_bytes(),
        2 * MAX_UDP_WIRE_DATAGRAM_BYTES,
        "one shard owns exactly two fixed direct-to-wire buffers"
    );
    assert_eq!(codec.available_wire_count(), 0);

    let waiting = tokio::spawn({
        let codec = Arc::clone(&codec);
        let protocol = Arc::clone(&protocol);
        let clock = Arc::clone(&clock);
        let response = Arc::clone(&response);
        async move {
            codec
                .encode(protocol.as_ref(), capability, clock.as_ref(), &response)
                .await
        }
    });
    tokio::task::yield_now().await;
    assert!(!waiting.is_finished());
    assert_eq!(codec.observations().0, 2);
    assert_eq!(codec.observations().1, 1);

    drop(first_encoded);
    let third_encoded = tokio::time::timeout(Duration::from_secs(1), waiting)
        .await
        .expect("one return wakes one codec waiter")
        .expect("codec waiter task")
        .unwrap_or_else(|_| panic!("returned fixed wire encodes"));

    drop(third_encoded);
    drop(second_encoded);
    assert_eq!(codec.available_wire_count(), 2);
    assert_eq!(budget.reserved_bytes(), 2 * MAX_UDP_WIRE_DATAGRAM_BYTES);

    let fourth_encoded = codec
        .encode(protocol.as_ref(), capability, clock.as_ref(), &response)
        .await
        .unwrap_or_else(|_| panic!("fourth fixed wire encodes"));
    let fifth_encoded = codec
        .encode(protocol.as_ref(), capability, clock.as_ref(), &response)
        .await
        .unwrap_or_else(|_| panic!("fifth fixed wire encodes"));
    let cancelled_waiter = tokio::spawn({
        let codec = Arc::clone(&codec);
        let protocol = Arc::clone(&protocol);
        let clock = Arc::clone(&clock);
        let response = Arc::clone(&response);
        async move {
            codec
                .encode(protocol.as_ref(), capability, clock.as_ref(), &response)
                .await
        }
    });
    tokio::task::yield_now().await;
    assert!(!cancelled_waiter.is_finished());
    cancelled_waiter.abort();
    assert!(matches!(
        cancelled_waiter.await,
        Err(error) if error.is_cancelled()
    ));
    drop(fourth_encoded);
    drop(fifth_encoded);
    tokio::task::yield_now().await;
    assert_eq!(
        codec.available_wire_count(),
        2,
        "cancelling a waiter neither leaks a permit nor consumes a fixed wire"
    );
    assert_eq!(budget.reserved_bytes(), 2 * MAX_UDP_WIRE_DATAGRAM_BYTES);
    manager.cancel_all();
    drop(codec);
    drop(manager);
    assert_eq!(active(registry.snapshot()), baseline);
}

#[test]
fn response_codec_shard_count_is_power_of_two_and_hard_bounded() {
    for maximum_sessions in [0, 1, 2, 3, 4, 5, 65_535] {
        let shards = response_codec_shards(maximum_sessions);
        assert!(shards.is_power_of_two());
        assert!((1..=MAX_RESPONSE_CODEC_SHARDS).contains(&shards));
        assert!(shards <= maximum_sessions.max(1));
    }
}
