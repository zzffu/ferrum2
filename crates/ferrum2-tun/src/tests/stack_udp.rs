use super::support::*;

#[tokio::test]
async fn fragmented_udp_reaches_admission_only_after_out_of_order_reassembly() {
    let (first, second) = ipv4_udp_fragments();
    let (mut stack, _flows, mut candidates) = Stack::new_with_udp(
        (
            Some((Ipv4Addr::new(198, 18, 0, 2), 30)),
            Some((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2), 126)),
        ),
        1420,
        1,
        4096,
        Duration::from_secs(60),
        Arc::new(AtomicUsize::new(0)),
        OwnerRegistry::new(),
        1,
        Duration::from_secs(60),
        UdpFiltering::AddressDependent,
        0,
        OwnerWake::default(),
    )
    .expect("UDP stack");

    assert!(stack.enqueue_at(&second, true, 1));
    assert!(matches!(
        candidates.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert!(stack.enqueue_at(&first, true, 2));
    let candidate = candidates.try_recv().expect("reassembled candidate");
    assert_eq!(candidate.first_payload(), &[0, 1, 2, 3]);
}

#[tokio::test]
async fn atomic_ipv6_fragment_normalization_emits_no_reassembly_lifecycle_events() {
    let original = ipv6_udp();
    let mut atomic = original[..40].to_vec();
    atomic[4..6].copy_from_slice(
        &u16::try_from(original.len() - 40 + 8)
            .unwrap()
            .to_be_bytes(),
    );
    atomic[6] = 44;
    atomic.extend_from_slice(&[17, 0, 0, 0]);
    atomic.extend_from_slice(&99_u32.to_be_bytes());
    atomic.extend_from_slice(&original[40..]);

    let (mut stack, _flows, mut candidates) = Stack::new_with_udp(
        (
            Some((Ipv4Addr::new(198, 18, 0, 2), 30)),
            Some((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2), 126)),
        ),
        1420,
        1,
        4096,
        Duration::from_secs(60),
        Arc::new(AtomicUsize::new(0)),
        OwnerRegistry::new(),
        1,
        Duration::from_secs(60),
        UdpFiltering::AddressDependent,
        0,
        OwnerWake::default(),
    )
    .expect("UDP stack");
    let observed = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&observed);
    stack.set_event_sink(TunEventSink::new(move |event| {
        captured.lock().expect("TUN events").push(event);
    }));

    assert!(stack.enqueue_at(&atomic, true, 0));
    assert_eq!(
        candidates
            .try_recv()
            .expect("normalized UDP candidate")
            .first_payload(),
        b"test"
    );
    assert_eq!(stack.reassembly.len(), 0);
    let reassembly_events = observed
        .lock()
        .expect("TUN events")
        .iter()
        .copied()
        .filter(|event| {
            matches!(
                event,
                TunEvent::ReassemblyEntriesActive(_)
                    | TunEvent::ReassemblyStarted
                    | TunEvent::ReassemblyCompleted
                    | TunEvent::ReassemblyDroppedOverlap
                    | TunEvent::ReassemblyDroppedTimeout
                    | TunEvent::ReassemblyDroppedLimit
                    | TunEvent::ReassemblyDroppedMalformed
            )
        })
        .collect::<Vec<_>>();
    assert!(
        reassembly_events.is_empty(),
        "atomic normalization is not a reassembly lifecycle: {reassembly_events:?}"
    );
}

#[test]
fn fragment_admission_reports_expiration_and_replacement_at_equal_active_count() {
    let (first, _) = ipv4_udp_fragments();
    let mut replacement = first.clone();
    replacement[4..6].copy_from_slice(&8_u16.to_be_bytes());
    replacement[10..12].fill(0);
    let replacement_checksum = checksum(&[&replacement[..20]]);
    replacement[10..12].copy_from_slice(&replacement_checksum.to_be_bytes());

    let (mut stack, _flows, _candidates) = Stack::new_with_udp(
        (
            Some((Ipv4Addr::new(198, 18, 0, 2), 30)),
            Some((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2), 126)),
        ),
        1420,
        1,
        4096,
        Duration::from_secs(60),
        Arc::new(AtomicUsize::new(0)),
        OwnerRegistry::new(),
        1,
        Duration::from_secs(60),
        UdpFiltering::AddressDependent,
        0,
        OwnerWake::default(),
    )
    .expect("UDP stack");
    let observed = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&observed);
    stack.set_event_sink(TunEventSink::new(move |event| {
        captured.lock().expect("TUN events").push(event);
    }));

    assert!(stack.enqueue_at(&first, true, 0));
    observed.lock().expect("TUN events").clear();
    assert!(stack.enqueue_at(&replacement, true, REASSEMBLY_TIMEOUT_MILLIS));

    assert_eq!(
        *observed.lock().expect("TUN events"),
        [
            TunEvent::ReassemblyDroppedTimeout,
            TunEvent::PacketRejected(TunRejectReason::FragmentTimeout),
            TunEvent::ReassemblyStarted,
            TunEvent::ReassemblyEntriesActive(1),
        ]
    );
    assert_eq!(stack.reassembly.len(), 1);
}

#[tokio::test]
async fn reassembled_udp_larger_than_mtu_reaches_one_eim_association() {
    const MTU: usize = 1_280;
    let payload = vec![0x5a; 2_000];
    let cases = [
        (
            fragment_ipv4_udp(&crate::packet::test_support::ipv4_udp(&payload, &[]), MTU),
            MTU - 28,
        ),
        (
            fragment_ipv6_udp(&crate::packet::test_support::ipv6_udp(&payload), MTU),
            MTU - 48,
        ),
    ];

    for (fragments, response_payload_bound) in cases {
        assert!(fragments.iter().all(|fragment| fragment.len() <= MTU));
        let (mut stack, _flows, mut candidates) = Stack::new_with_udp(
            (
                Some((Ipv4Addr::new(198, 18, 0, 2), 30)),
                Some((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2), 126)),
            ),
            MTU,
            1,
            4096,
            Duration::from_secs(60),
            Arc::new(AtomicUsize::new(0)),
            OwnerRegistry::new(),
            1,
            Duration::from_secs(60),
            UdpFiltering::AddressDependent,
            0,
            OwnerWake::default(),
        )
        .expect("UDP stack");

        for fragment in fragments.iter().rev() {
            assert!(stack.enqueue_at(fragment, true, 1));
        }
        let candidate = candidates.try_recv().expect("reassembled candidate");
        assert_eq!(candidate.first_payload(), payload);
        assert_eq!(candidate.packet_payload_bound(), response_payload_bound);
        let commit = tokio::spawn(candidate.commit_association());
        tokio::task::yield_now().await;
        assert_eq!(stack.poll_udp_events(2, true).committed, 1);
        let mut association = commit.await.unwrap().expect("association commit");
        assert_eq!(
            association
                .receive()
                .await
                .expect("first datagram")
                .payload(),
            payload
        );
    }
}

#[tokio::test]
async fn owner_control_stage_services_udp_lifecycle_while_forwarding() {
    let (mut stack, _flows, mut candidates) = Stack::new_with_udp(
        (
            Some((Ipv4Addr::new(198, 18, 0, 2), 30)),
            Some((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2), 126)),
        ),
        1_420,
        1,
        4_096,
        Duration::from_secs(60),
        Arc::new(AtomicUsize::new(0)),
        OwnerRegistry::new(),
        1,
        Duration::from_secs(60),
        UdpFiltering::AddressDependent,
        7,
        OwnerWake::default(),
    )
    .expect("UDP control-stage stack");
    assert!(stack.enqueue_at(&ipv4_udp(), true, 0));
    let candidate = candidates.try_recv().expect("UDP candidate");
    let commit = tokio::spawn(candidate.commit_association());
    tokio::task::yield_now().await;

    assert!(
        stack.process_owner_control_stage(1, true, true),
        "forwarding work and UDP lifecycle work are both serviced"
    );
    let association = commit.await.expect("commit task").expect("association");
    assert_eq!(stack.live_udp_associations(), 1);

    drop(association);
    assert!(
        stack.process_owner_control_stage(2, true, true),
        "forwarding work cannot starve an association close"
    );
    assert_eq!(stack.live_udp_associations(), 0);
}

#[tokio::test]
async fn udp_ipv4_ipv6_candidates_commit_and_inject_through_the_real_stack() {
    for (packet, expected_source, expected_target, response) in [
        (
            ipv4_udp(),
            "198.18.0.1:10000".parse().expect("IPv4 source"),
            "192.0.2.1:53".parse().expect("IPv4 target"),
            b"v4".as_slice(),
        ),
        (
            ipv6_udp(),
            "[::2]:10000".parse().expect("IPv6 source"),
            "[2001:db8::1]:53".parse().expect("IPv6 target"),
            b"v6".as_slice(),
        ),
    ] {
        let (mut stack, _flows, mut candidates) = Stack::new_with_udp(
            (
                Some((Ipv4Addr::new(198, 18, 0, 2), 30)),
                Some((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2), 126)),
            ),
            1420,
            1,
            4096,
            Duration::from_secs(60),
            Arc::new(AtomicUsize::new(0)),
            OwnerRegistry::new(),
            1,
            Duration::from_secs(60),
            UdpFiltering::AddressDependent,
            0,
            OwnerWake::default(),
        )
        .expect("UDP stack");
        assert!(stack.enqueue_at(&packet, true, 0));
        assert_eq!(
            stack.live_udp_associations(),
            0,
            "provisional is not active"
        );
        let candidate = candidates.try_recv().expect("candidate");
        assert_eq!(candidate.source(), expected_source);
        assert_eq!(candidate.first_target(), expected_target);
        assert_eq!(candidate.first_payload(), &packet[packet.len() - 4..]);
        let commit = tokio::spawn(candidate.commit_association());
        tokio::task::yield_now().await;
        assert_eq!(stack.poll_udp_events(1, true).committed, 1);
        let mut mapping = commit.await.expect("commit task").expect("mapping");
        assert_eq!(
            mapping.receive().await.expect("first datagram").payload(),
            &packet[packet.len() - 4..]
        );
        assert!(matches!(
            mapping.authorize_peer(expected_target.ip()),
            UdpPeerAuthorization::Authorized
                | UdpPeerAuthorization::AlreadyAuthorized
                | UdpPeerAuthorization::NotRequired
        ));
        assert_eq!(
            mapping.send_response(expected_target, response),
            crate::UdpResponseSendOutcome::Queued
        );
        assert_eq!(stack.poll_udp_events(2, true).injected, 1);
        let mut emitted = Vec::new();
        assert_eq!(
            stack.flush_output(|packet| {
                emitted.extend_from_slice(packet);
                OutputSendOutcome::Sent
            }),
            OutputFlushOutcome::Sent
        );
        assert!(PacketValidator::new(1420).accepts(&emitted));
        let (reverse, payload, _) = crate::udp_datagram(&emitted, 1420).expect("UDP response");
        assert_eq!(reverse.source(), expected_target);
        assert_eq!(reverse.target(), expected_source);
        assert_eq!(payload, response);
    }
}

#[tokio::test]
async fn session_quiesce_resets_tcp_invalidates_udp_and_discards_packet_state() {
    let flow_count = Arc::new(AtomicUsize::new(0));
    let (mut stack, _flows, mut candidates) = Stack::new_with_udp(
        (
            Some((Ipv4Addr::new(198, 18, 0, 2), 30)),
            Some((Ipv6Addr::LOCALHOST, 128)),
        ),
        1420,
        2,
        4096,
        Duration::from_secs(60),
        Arc::clone(&flow_count),
        OwnerRegistry::new(),
        2,
        Duration::from_secs(60),
        UdpFiltering::AddressDependent,
        7,
        OwnerWake::default(),
    )
    .expect("restart test stack");
    assert!(stack.enqueue_at(&ipv4_tcp(), true, 0));
    let mut old_flow = stack
        .flows
        .iter_mut()
        .flatten()
        .next()
        .and_then(|entry| entry.pending.take())
        .expect("old-generation TCP flow");
    assert_eq!(flow_count.load(Ordering::Acquire), 1);

    let endpoints = UdpDatagramEndpoints::new(
        "198.18.0.1:20000".parse().expect("source"),
        "192.0.2.9:53".parse().expect("target"),
    );
    assert_ne!(
        stack.udp.admit(endpoints, b"request", 128, 0, true),
        crate::UdpAdmission::Dropped
    );
    let candidate = candidates.try_recv().expect("old-generation candidate");
    assert_eq!(
        stack.device.inject_udp_response(endpoints, b"response"),
        UdpInjectOutcome::Injected
    );
    assert!(stack.pending() != 0 && stack.has_output());

    assert_eq!(stack.quiesce(8, UdpResponseDropReason::SessionReset), 1);
    assert_eq!(
        stack.quiesce(8, UdpResponseDropReason::SessionReset),
        0,
        "quiesce is idempotent"
    );
    assert_eq!(flow_count.load(Ordering::Acquire), 0);
    assert_eq!(stack.live_tcp_flows(), 0);
    assert_eq!(stack.live_udp_associations(), 0);
    assert_eq!(stack.pending(), 0);
    assert!(!stack.has_output());
    assert_eq!(
        old_flow
            .write(b"stale")
            .await
            .expect_err("old flow is reset")
            .kind(),
        std::io::ErrorKind::ConnectionReset
    );
    assert!(matches!(
        candidate.commit_association().await,
        Err(crate::UdpCommitError::Unavailable | crate::UdpCommitError::Rejected)
    ));
}

#[test]
fn stack_routes_are_exact_and_udp_candidates_bypass_foundation_drop() {
    let (mut stack, _flows, mut datagrams) = Stack::new_with_udp(
        (
            Some((Ipv4Addr::new(198, 18, 0, 2), 30)),
            Some((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2), 126)),
        ),
        1420,
        8,
        4096,
        Duration::from_secs(60),
        Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        OwnerRegistry::new(),
        1,
        Duration::from_secs(60),
        UdpFiltering::AddressDependent,
        0,
        OwnerWake::default(),
    )
    .expect("bounded stack");
    assert!(stack.has_exact_routes());
    let packet = ipv4_udp();
    assert!(
        stack.enqueue(&packet, true),
        "first UDP packet becomes a provisional candidate"
    );
    assert!(
        stack.enqueue(&packet, true),
        "a pending candidate queues subsequent datagrams without another mapping"
    );
    let _candidate = datagrams.try_recv().expect("one source candidate");
    assert!(matches!(
        datagrams.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    assert_eq!(stack.poll_quantum(Instant::ZERO), 0);
    assert_eq!(stack.pending(), 0);
    assert_eq!(
        stack.discarded_packets(),
        0,
        "T05 UDP no longer reaches the foundation drop"
    );

    let valid_foundation_drops = stack.discarded_packets();
    let valid_egress = stack.validated_egress_packets();
    let rejected_egress = stack.rejected_egress_packets();
    stack
        .device
        .transmit(Instant::ZERO)
        .expect("fixed TX slot")
        .consume(1, |output| output[0] = 0);
    assert_eq!(
        stack.discarded_packets(),
        valid_foundation_drops,
        "invalid egress cannot be counted as a validated foundation packet"
    );
    assert_eq!(stack.validated_egress_packets(), valid_egress);
    assert_eq!(stack.rejected_egress_packets(), rejected_egress + 1);
}

#[test]
fn generation_table_is_bounded_and_stale_ids_fail_closed() {
    let mut table = GenerationTable::new(2);
    let first = table.current(0).expect("first slot");
    assert!(table.recycle(first));
    assert!(
        !table.recycle(first),
        "stale generation must not touch reused slot"
    );
    assert!(table.current(2).is_none(), "capacity is exact");

    table.slots[1] = u32::MAX - 1;
    let last = table.current(1).expect("last usable generation");
    assert!(table.recycle(last));
    assert!(
        table.current(1).is_none(),
        "generation exhaustion permanently retires the slot"
    );
    assert!(
        !table.recycle(last),
        "exhaustion cannot resurrect an old ID"
    );
}
