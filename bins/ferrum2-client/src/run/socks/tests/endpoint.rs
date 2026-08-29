use super::*;

use ferrum2_socks5::{decode_udp_datagram, encode_udp_datagram};

use crate::run::socks::endpoint::SocksUdpPacket;

async fn endpoint_and_application() -> (SocksUdpEndpoint, UdpSocket, SocketAddr) {
    let endpoint = SocksUdpEndpoint::bind(
        Ipv4Addr::LOCALHOST,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        0,
        #[cfg(feature = "candidate-udp-owned-headroom")]
        standalone_udp_buffer_budget(),
        UdpSocket::bind,
    )
    .await
    .expect("SOCKS endpoint");
    let relay = SocketAddr::V4(endpoint.local_addr().expect("SOCKS relay address"));
    let application = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("SOCKS application socket");
    (endpoint, application, relay)
}

#[cfg(feature = "structural-metrics")]
#[tokio::test]
async fn structural_counters_report_lazy_buffers_and_only_response_payload_copies() {
    use ferrum2_structural::{StructuralCounter, StructuralHub};

    let structural = StructuralHub::new();
    let (endpoint, application, relay) = endpoint_and_application().await;
    let mut endpoint = endpoint.with_structural(structural.local());
    let target = TargetAddr::ipv4("192.0.2.20:53".parse().expect("target")).expect("target");
    let mut request_wire = [0_u8; 128];
    let request_len =
        encode_udp_datagram(&target, b"owned request", &mut request_wire).expect("request encode");
    application
        .send_to(&request_wire[..request_len], relay)
        .await
        .expect("request send");
    let SocksUdpPacket::Valid(packet) = endpoint.receive().await.expect("owned receive") else {
        panic!("valid owned request")
    };
    endpoint.accept(packet.source_port());
    assert_eq!(packet.payload(), b"owned request");
    assert_eq!(
        structural
            .snapshot()
            .get(StructuralCounter::SocksUdpAllocations),
        1,
        "the receive allocation is created only on its first poll",
    );
    assert_eq!(
        structural
            .snapshot()
            .get(StructuralCounter::SocksUdpCopyBytes),
        0,
        "the owned request path does not copy its payload",
    );
    endpoint.recycle(packet);

    for response in [b"first response".as_slice(), b"second".as_slice()] {
        endpoint
            .send(&target, response)
            .await
            .expect("instrumented response send");
        let mut wire = [0_u8; 128];
        let _ = application
            .recv_from(&mut wire)
            .await
            .expect("instrumented response receive");
    }
    let snapshot = structural.snapshot();
    assert_eq!(
        snapshot.get(StructuralCounter::SocksUdpAllocations),
        2,
        "the independent response wire allocates once and is then reused",
    );
    assert_eq!(
        snapshot.get(StructuralCounter::SocksUdpCopyBytes),
        u64::try_from(b"first response".len() + b"second".len()).expect("small copy count"),
    );

    application
        .send_to(&request_wire[..request_len], relay)
        .await
        .expect("replacement request send");
    let SocksUdpPacket::Valid(mut packet) = endpoint.receive().await.expect("replacement receive")
    else {
        panic!("valid replacement request")
    };
    #[cfg(not(feature = "candidate-udp-owned-headroom"))]
    drop(std::mem::take(packet.payload_mut()));
    #[cfg(feature = "candidate-udp-owned-headroom")]
    drop(packet.headroom_mut().take());
    endpoint.recycle(packet);
    #[cfg(not(feature = "candidate-udp-owned-headroom"))]
    let expected_allocations = 3;
    #[cfg(feature = "candidate-udp-owned-headroom")]
    let expected_allocations = 2;
    assert_eq!(
        structural
            .snapshot()
            .get(StructuralCounter::SocksUdpAllocations),
        expected_allocations,
        "a consumed failed request backing is replaced and reported",
    );
}

#[tokio::test]
async fn endpoint_starts_with_uninitialized_lengths_and_lazy_send_capacity() {
    let (endpoint, _application, _relay) = endpoint_and_application().await;
    let (receive, send) = endpoint.buffer_state();
    assert_eq!(
        receive.0, 0,
        "receive capacity must not become logical data"
    );
    assert_eq!(receive.1, 0, "receive storage must allocate on first poll");
    assert_eq!(send, (0, 0), "response storage must allocate lazily");
}

#[tokio::test]
async fn cancelled_and_invalid_receive_keep_the_same_allocation_available() {
    let (mut endpoint, application, relay) = endpoint_and_application().await;

    assert!(
        tokio::time::timeout(Duration::from_millis(10), endpoint.receive())
            .await
            .is_err(),
        "empty receive must remain pending"
    );
    let pointer = endpoint
        .receive_allocation_pointer()
        .expect("lazy receive allocation");
    let receive_state = endpoint.buffer_state().0;
    #[cfg(not(feature = "candidate-udp-owned-headroom"))]
    assert_eq!(receive_state.0, 0);
    #[cfg(not(feature = "candidate-udp-owned-headroom"))]
    assert_eq!(receive_state.1, MAX_SOCKS_UDP_DATAGRAM_BYTES);
    #[cfg(feature = "candidate-udp-owned-headroom")]
    assert_eq!(
        receive_state.1
            - receive_state.0
            - ferrum2_shadowsocks::udp_request_owned_headroom().rear(),
        MAX_SOCKS_UDP_DATAGRAM_BYTES,
        "front reserve does not reduce the socket receive bound",
    );
    assert_eq!(endpoint.receive_allocation_pointer(), Some(pointer));

    application
        .send_to(b"invalid", relay)
        .await
        .expect("invalid datagram send");
    assert!(matches!(
        endpoint.receive().await.expect("invalid receive"),
        SocksUdpPacket::InvalidWire
    ));
    assert_eq!(endpoint.receive_allocation_pointer(), Some(pointer));

    let target = TargetAddr::ipv4("192.0.2.1:53".parse().expect("target")).expect("target");
    let mut wire = [0_u8; 128];
    let length = encode_udp_datagram(&target, b"valid", &mut wire).expect("valid encode");
    application
        .send_to(&wire[..length], relay)
        .await
        .expect("valid datagram send");
    let SocksUdpPacket::Valid(packet) = endpoint.receive().await.expect("valid receive") else {
        panic!("valid owned packet")
    };
    #[cfg(not(feature = "candidate-udp-owned-headroom"))]
    assert_ne!(packet.allocation_pointer(), pointer);
    #[cfg(feature = "candidate-udp-owned-headroom")]
    assert_eq!(packet.allocation_pointer(), pointer);
    endpoint.recycle(packet);
    assert_eq!(endpoint.receive_allocation_pointer(), Some(pointer));
}

#[tokio::test]
async fn owned_request_unsplit_reuses_identity_and_send_storage_is_independent() {
    let (mut endpoint, application, relay) = endpoint_and_application().await;
    let target = TargetAddr::ipv4("192.0.2.2:53".parse().expect("target")).expect("target");
    let mut wire = vec![0_u8; MAX_SOCKS_UDP_DATAGRAM_BYTES];
    let mut receive_base_pointer = None;
    let mut payload_pointer = None;
    let large_request = vec![0x5a; MAX_SOCKS_UDP_DATAGRAM_BYTES - 10];

    for payload in [
        b"small".as_slice(),
        large_request.as_slice(),
        b"again".as_slice(),
    ] {
        let length = encode_udp_datagram(&target, payload, &mut wire).expect("request encode");
        application
            .send_to(&wire[..length], relay)
            .await
            .expect("request send");
        let SocksUdpPacket::Valid(packet) = endpoint.receive().await.expect("owned request") else {
            panic!("valid owned packet")
        };
        assert_eq!(packet.target(), &target);
        assert_eq!(packet.payload(), payload);
        match payload_pointer {
            Some(pointer) => assert_eq!(packet.allocation_pointer(), pointer),
            None => payload_pointer = Some(packet.allocation_pointer()),
        }
        endpoint.accept(packet.source_port());

        endpoint
            .send(packet.target(), b"response")
            .await
            .expect("independent response send");
        let mut response_wire = [0_u8; 128];
        let (response_len, source) = application
            .recv_from(&mut response_wire)
            .await
            .expect("response receive");
        assert_eq!(source, relay);
        let response =
            decode_udp_datagram(&response_wire[..response_len]).expect("response decode");
        assert_eq!(response.payload(), b"response");

        endpoint.recycle(packet);
        match receive_base_pointer {
            Some(pointer) => assert_eq!(endpoint.receive_allocation_pointer(), Some(pointer)),
            None => receive_base_pointer = endpoint.receive_allocation_pointer(),
        }
        assert_eq!(endpoint.buffer_state().0.0, 0);
    }

    let mut send_pointer = None;
    let large_response = vec![0xa5; MAX_SOCKS_UDP_DATAGRAM_BYTES - 10];
    for payload in [
        b"tiny".as_slice(),
        &[0x3c; 40_000][..],
        &[0xc3; 50_000][..],
        large_response.as_slice(),
        b"last".as_slice(),
    ] {
        endpoint
            .send(&target, payload)
            .await
            .expect("high-water response send");
        let mut response_wire = vec![0_u8; MAX_SOCKS_UDP_DATAGRAM_BYTES];
        let (response_len, _) = application
            .recv_from(&mut response_wire)
            .await
            .expect("high-water response receive");
        let response =
            decode_udp_datagram(&response_wire[..response_len]).expect("response decode");
        assert_eq!(response.payload(), payload);
        match send_pointer {
            Some(pointer) => assert_eq!(endpoint.send_allocation_pointer(), pointer),
            None => send_pointer = Some(endpoint.send_allocation_pointer()),
        }
        assert_eq!(endpoint.buffer_state().1.0, 0);
        assert!(endpoint.buffer_state().1.1 <= MAX_SOCKS_UDP_DATAGRAM_BYTES);
    }
}

#[cfg(feature = "candidate-udp-owned-headroom")]
#[tokio::test]
async fn single_hop_owned_requests_keep_one_lease_through_send_and_clear_rejection() {
    let registry = OwnerRegistry::new();
    let proxy = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("proxy socket");
    let proxy_address = match proxy.local_addr().expect("proxy address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 proxy"),
    };
    let (path, context) = udp_test_context_for_server(registry.clone(), proxy_address);
    let budget = context_udp_buffer_budget(&context);
    let mut endpoint = SocksUdpEndpoint::bind(
        Ipv4Addr::LOCALHOST,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        0,
        budget.clone(),
        UdpSocket::bind,
    )
    .await
    .expect("SOCKS endpoint");
    let relay = SocketAddr::V4(endpoint.local_addr().expect("SOCKS relay"));
    let target = TargetAddr::ipv4("192.0.2.44:53".parse().expect("target")).expect("target");
    let mut association = context
        .egress
        .prepare_udp_for_ingress(
            crate::run::egress::ClientRequestOrigin::Socks,
            0,
            Some(ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned()),
            Some(&target),
        )
        .await
        .expect("single-hop association");
    association
        .activate(&context.egress)
        .expect("single-hop activation");
    assert!(association.supports_owned_headroom_request());
    let server = UdpServer::new(&context.keys).expect("proxy protocol");
    let clock = SystemClock::new();
    let random = SystemRandom;
    let mut scratch = UdpPacketScratch::new();
    let mut socks_wire = vec![0_u8; MAX_SOCKS_UDP_DATAGRAM_BYTES];
    let mut allocation = None;

    for payload_len in [1, 8_192, 31] {
        let payload = vec![0x5a; payload_len];
        let socks_len =
            encode_udp_datagram(&target, &payload, &mut socks_wire).expect("SOCKS request encode");
        application_send(&proxy, &socks_wire[..socks_len], relay).await;
        let SocksUdpPacket::Valid(mut packet) = endpoint.receive().await.expect("owned receive")
        else {
            panic!("valid owned packet")
        };
        endpoint.accept(packet.source_port());
        let state = (
            packet.allocation_pointer(),
            packet.allocation_capacity(),
            budget.reserved_bytes(),
        );
        assert!(state.1 > ferrum2_shadowsocks::MAX_UDP_WIRE_LEN);
        match allocation {
            Some(expected) => assert_eq!(state.0, expected),
            None => allocation = Some(state.0),
        }
        let wire_range = association
            .prepare_owned_headroom_application_request(
                &context.egress,
                &context.egress.outbounds,
                packet.headroom_mut(),
                Instant::now(),
            )
            .unwrap_or_else(|_| panic!("owned request encode"));
        assert_eq!(
            (
                packet.allocation_pointer(),
                packet.allocation_capacity(),
                budget.reserved_bytes(),
            ),
            state,
            "accounting and in-place seal retain the exact receive lease",
        );
        let wire = packet
            .headroom_mut()
            .as_ref()
            .expect("encoded packet")
            .wire(wire_range.clone())
            .expect("owned wire");
        assert_eq!(
            association.send_owned_encoded_request(wire).await.unwrap(),
            wire_range.len()
        );
        let mut received_wire = vec![0_u8; ferrum2_shadowsocks::MAX_UDP_WIRE_LEN];
        let (received, peer) = proxy
            .recv_from(&mut received_wire)
            .await
            .expect("proxy receives request");
        let pending = server
            .prepare_request(&clock, &received_wire[..received], &mut scratch)
            .expect("proxy opens request");
        assert_eq!(pending.datagram().payload(), payload);
        let (_, commit) = pending.into_parts();
        server
            .commit_request(commit, peer, clock.monotonic_now(), &random)
            .expect("proxy commits request");
        endpoint.recycle(packet);
        assert_eq!(
            endpoint.receive_allocation_pointer(),
            allocation,
            "the same lease returns after the awaited socket send",
        );
        assert_eq!(budget.reserved_bytes(), state.2);
    }

    let sensitive = b"undelivered plaintext";
    let socks_len =
        encode_udp_datagram(&target, sensitive, &mut socks_wire).expect("failure request encode");
    application_send(&proxy, &socks_wire[..socks_len], relay).await;
    let SocksUdpPacket::Valid(mut packet) = endpoint.receive().await.expect("failure receive")
    else {
        panic!("valid failure packet")
    };
    let failure_state = (
        packet.allocation_pointer(),
        packet.allocation_capacity(),
        budget.reserved_bytes(),
    );
    context
        .egress
        .udp
        .as_ref()
        .expect("UDP context")
        .manager
        .cancel_all();
    assert!(matches!(
        association.prepare_owned_headroom_application_request(
            &context.egress,
            &context.egress.outbounds,
            packet.headroom_mut(),
            Instant::now(),
        ),
        Err(crate::run::egress::UdpPlanResponseError::Runtime(
            ferrum2_runtime::UdpRuntimeError::Cancelled
        ))
    ));
    assert!(packet.payload().iter().all(|byte| *byte == 0));
    assert_eq!(
        (
            packet.allocation_pointer(),
            packet.allocation_capacity(),
            budget.reserved_bytes(),
        ),
        failure_state,
        "rejected accounting physically clears and returns the exact lease",
    );
    endpoint.recycle_failure(packet);
    assert_eq!(endpoint.receive_allocation_pointer(), allocation);
    assert_eq!(budget.reserved_bytes(), failure_state.2);

    drop(association);
    drop(endpoint);
    drop(context);
    assert_eq!(registry.snapshot().udp_buffered_bytes, 0);
    std::fs::remove_file(path).expect("remove test config");
}

#[cfg(feature = "candidate-udp-owned-headroom")]
async fn application_send(socket: &UdpSocket, wire: &[u8], relay: SocketAddr) {
    socket
        .send_to(wire, relay)
        .await
        .expect("application sends request");
}

#[tokio::test]
#[cfg(not(feature = "candidate-udp-owned-headroom"))]
async fn routed_owned_request_restores_allocation_and_charges_its_exact_capacity() {
    let registry = OwnerRegistry::new();
    let proxy = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("proxy socket");
    let proxy_address = match proxy.local_addr().expect("proxy address") {
        SocketAddr::V4(address) => address,
        SocketAddr::V6(_) => unreachable!("IPv4 proxy"),
    };
    let (path, context) = udp_test_context_for_server(registry.clone(), proxy_address);
    let target = TargetAddr::ipv4("192.0.2.9:53".parse().expect("target")).expect("target");
    let mut association = context
        .egress
        .prepare_udp_for_ingress(
            crate::run::egress::ClientRequestOrigin::Socks,
            0,
            Some(ferrum2_core::route::EgressPlanHandle::direct(0).snapshot_owned()),
            Some(&target),
        )
        .await
        .expect("routed association");
    association
        .activate(&context.egress)
        .expect("association activation");

    let (mut endpoint, application, relay) = endpoint_and_application().await;
    assert!(
        tokio::time::timeout(Duration::from_millis(10), endpoint.receive())
            .await
            .is_err()
    );
    let receive_base = endpoint
        .receive_allocation_pointer()
        .expect("receive allocation");
    let mut wire = [0_u8; 128];

    let first_length =
        encode_udp_datagram(&target, b"first", &mut wire).expect("first request encode");
    application
        .send_to(&wire[..first_length], relay)
        .await
        .expect("first request send");
    let SocksUdpPacket::Valid(mut first) = endpoint.receive().await.expect("first request") else {
        panic!("valid first request")
    };
    let first_state = (
        first.allocation_pointer(),
        first.payload().len(),
        first.allocation_capacity(),
    );
    association
        .prepare_owned_application_request(
            &context.egress,
            &context.egress.outbounds,
            target.clone(),
            first.payload_mut(),
            Instant::now(),
        )
        .unwrap_or_else(|_| panic!("first routed request"));
    assert_eq!(
        (
            first.allocation_pointer(),
            first.payload().len(),
            first.allocation_capacity(),
        ),
        first_state,
        "the routed request must return the exact owned allocation"
    );
    endpoint.recycle(first);
    assert_eq!(endpoint.receive_allocation_pointer(), Some(receive_base));

    let second_length =
        encode_udp_datagram(&target, b"second", &mut wire).expect("second request encode");
    application
        .send_to(&wire[..second_length], relay)
        .await
        .expect("second request send");
    let SocksUdpPacket::Valid(mut second) = endpoint.receive().await.expect("second request")
    else {
        panic!("valid second request")
    };
    let second_state = (
        second.allocation_pointer(),
        second.payload().len(),
        second.allocation_capacity(),
    );
    let budget = context
        .egress
        .udp
        .as_ref()
        .expect("UDP context")
        .manager
        .buffer_budget();
    let desired_free = second.allocation_capacity() - 1;
    let mut to_reserve = ferrum2_runtime::MIN_UDP_MAX_BUFFERED_BYTES
        .checked_sub(budget.reserved_bytes())
        .and_then(|available| available.checked_sub(desired_free))
        .expect("test budget headroom");
    let one_byte = budget.reserve(1).expect("one-byte release token");
    to_reserve -= 1;
    let mut held = Vec::new();
    while to_reserve != 0 {
        let capacity = to_reserve.min(ferrum2_runtime::MAX_UDP_WIRE_DATAGRAM_BYTES);
        held.push(budget.reserve(capacity).expect("fill UDP budget"));
        to_reserve -= capacity;
    }
    let before_failure = registry.snapshot();
    let idle_before_failure = association.idle_deadline().expect("idle deadline");
    assert!(matches!(
        association.prepare_owned_application_request(
            &context.egress,
            &context.egress.outbounds,
            target.clone(),
            second.payload_mut(),
            Instant::now(),
        ),
        Err(crate::run::egress::UdpPlanResponseError::Runtime(
            ferrum2_runtime::UdpRuntimeError::BufferLimit
        ))
    ));
    assert_eq!(
        (
            second.allocation_pointer(),
            second.payload().len(),
            second.allocation_capacity(),
        ),
        second_state,
        "capacity rejection happens before ownership transfer"
    );
    assert_eq!(registry.snapshot(), before_failure);
    assert_eq!(
        association.idle_deadline().expect("idle after failure"),
        idle_before_failure,
        "capacity rejection must not advance session activity"
    );

    drop(one_byte);
    association
        .prepare_owned_application_request(
            &context.egress,
            &context.egress.outbounds,
            target,
            second.payload_mut(),
            Instant::now(),
        )
        .unwrap_or_else(|_| panic!("exact-capacity request"));
    assert_eq!(
        (
            second.allocation_pointer(),
            second.payload().len(),
            second.allocation_capacity(),
        ),
        second_state
    );
    endpoint.recycle(second);
    assert_eq!(endpoint.receive_allocation_pointer(), Some(receive_base));

    drop(held);
    drop(association);
    drop(context);
    assert_eq!(registry.snapshot().udp_buffered_bytes, 0);
    std::fs::remove_file(path).expect("remove test config");
}
