use super::*;

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
    let handler = Arc::new(ServerUdpResponseHandler {
        listener,
        protocol: Arc::clone(&protocol),
        mappings,
        clock: Arc::clone(&clock),
        codec: Arc::new(ResponseCodecPool::new(manager.buffer_budget()).expect("response codec")),
        metrics: Arc::new(Metrics::new()),
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
    assert_eq!(
        registry.snapshot().udp_buffered_bytes,
        3 * MAX_UDP_WIRE_DATAGRAM_BYTES,
        "two in-flight owned wires plus the shared codec scratch are charged"
    );
    send_gate.add_permits(2);
    assert!(first_task.await.expect("first response task").is_ok());
    assert!(second_task.await.expect("second response task").is_ok());
    assert_eq!(
        registry.snapshot().udp_buffered_bytes,
        2 * MAX_UDP_WIRE_DATAGRAM_BYTES,
        "the concurrency wire is released after the burst"
    );
    let idle_wire = {
        let codec = handler.codec.state.lock().expect("response codec");
        assert_eq!(codec.available_wires.len(), 1);
        codec.available_wires[0].wire.as_ptr()
    };

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
    let codec = handler.codec.state.lock().expect("response codec");
    assert_eq!(codec.available_wires.len(), 1);
    assert_eq!(codec.available_wires[0].wire.as_ptr(), idle_wire);
    drop(codec);
    assert_eq!(
        registry.snapshot().udp_buffered_bytes,
        2 * MAX_UDP_WIRE_DATAGRAM_BYTES,
        "steady-state serial responses reuse the same accounted wire"
    );

    manager.cancel_all();
    drop(handler);
    drop(manager);
    assert_eq!(active(registry.snapshot()), baseline);
}

#[tokio::test]
async fn response_codec_budget_wakeup_grows_before_leased_wire_returns() {
    let keys = aes_keys();
    let protocol = UdpServer::new(&keys).expect("server protocol");
    let clock = SystemClock::new();
    let registry = OwnerRegistry::new();
    let baseline = active(registry.snapshot());
    let byte_limit = 1024 * 1024;
    let manager = UdpSessionManager::new(
        UdpRuntimeLimits::new(1, byte_limit, Duration::from_secs(60)).expect("response limits"),
        registry.clone(),
    );
    let budget = manager.buffer_budget();
    let codec = Arc::new(ResponseCodecPool::new(budget.clone()).expect("response codec"));
    let mappings = UdpMappings::new(1);
    let mut client =
        UdpClientSession::new(&keys, &SystemRandom, |_| false).expect("client protocol");
    let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53));
    let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40_003));
    let mut scratch = UdpPacketScratch::new();
    let (capability, _handle) = commit_lifecycle_generation(
        &mut client,
        &protocol,
        &manager,
        &mappings,
        &clock,
        target,
        peer,
        b"request",
        ferrum2_crypto::MonotonicInstant::from_duration(Duration::ZERO),
        &mut scratch,
    );
    let wire = encoded_udp_request(
        &mut client,
        &clock,
        TargetAddr::ip(target).expect("response source target"),
        b"response",
    );
    let pending = protocol
        .prepare_request(&clock, &wire, &mut scratch)
        .expect("prepare response datagram");

    let first_encoded = match codec.try_encode(&protocol, capability, &clock, pending.datagram()) {
        Ok(Some(encoded)) => encoded,
        Ok(None) => panic!("initial response wire is reserved"),
        Err(_) => panic!("initial response encoding succeeds"),
    };
    let mut pressure = Vec::new();
    let mut remaining = byte_limit - budget.reserved_bytes();
    while remaining != 0 {
        let capacity = remaining.min(MAX_UDP_WIRE_DATAGRAM_BYTES);
        pressure.push(budget.reserve(capacity).expect("budget pressure"));
        remaining -= capacity;
    }
    assert_eq!(budget.reserved_bytes(), byte_limit);
    assert!(matches!(
        codec.try_encode(&protocol, capability, &clock, pending.datagram()),
        Ok(None)
    ));

    let returned = codec.returned.notified();
    let released = pressure
        .iter()
        .position(|reservation| reservation.capacity() == MAX_UDP_WIRE_DATAGRAM_BYTES)
        .expect("full response-wire pressure chunk");
    drop(pressure.swap_remove(released));
    codec.notify_capacity_change();
    tokio::time::timeout(Duration::from_secs(1), returned)
        .await
        .expect("budget release notification");
    let second_encoded = match codec.try_encode(&protocol, capability, &clock, pending.datagram()) {
        Ok(Some(encoded)) => encoded,
        Ok(None) => panic!("released capacity funds a concurrent response wire"),
        Err(_) => panic!("concurrent response encoding succeeds"),
    };
    assert_eq!(
        budget.reserved_bytes(),
        byte_limit,
        "the second wire is fully budget-accounted while the first remains leased"
    );

    drop(second_encoded);
    drop(first_encoded);
    drop(pressure);
    assert_eq!(budget.reserved_bytes(), 2 * MAX_UDP_WIRE_DATAGRAM_BYTES);
    let state = codec.state.lock().expect("response codec");
    assert_eq!(state.available_wires.len(), 1);
    drop(state);
    manager.cancel_all();
    drop(codec);
    drop(manager);
    assert_eq!(active(registry.snapshot()), baseline);
}
