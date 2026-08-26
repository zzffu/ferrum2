use super::support::*;

#[test]
fn tcp_five_tuple_admission_is_bounded_before_socket_or_buffer_creation() {
    let flow_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (mut stack, _flows) = Stack::new(
        (
            Ipv4Addr::new(198, 18, 0, 2),
            30,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            126,
        ),
        1420,
        1,
        4096,
        Duration::from_secs(60),
        Arc::clone(&flow_count),
    )
    .expect("bounded stack");
    for (name, mut packet, flags) in [
        ("SYN+FIN", ipv4_tcp(), 0x03),
        ("SYN+RST", ipv4_tcp(), 0x06),
        ("SYN+ACK", ipv4_tcp(), 0x12),
    ] {
        packet[33] = flags;
        repair_ipv4_tcp_checksum(&mut packet);
        assert!(
            !stack.enqueue(&packet, true),
            "{name} is not an initial SYN"
        );
        assert_eq!(stack.live_tcp_flows(), 0, "{name} leaked a flow slot");
    }
    let mut malformed_option = ipv4_tcp();
    malformed_option.resize(44, 0);
    malformed_option[2..4].copy_from_slice(&44_u16.to_be_bytes());
    malformed_option[32] = 0x60;
    malformed_option[40..44].copy_from_slice(&[2, 1, 0, 0]);
    repair_ipv4_header(&mut malformed_option);
    repair_ipv4_tcp_checksum(&mut malformed_option);
    assert!(
        !stack.enqueue(&malformed_option, true),
        "malformed TCP options fail before admission"
    );
    assert_eq!(stack.live_tcp_flows(), 0, "malformed options leaked a slot");

    let first = ipv4_tcp();
    assert!(stack.enqueue(&first, true));
    assert_eq!(stack.live_tcp_flows(), 1);
    assert_eq!(flow_count.load(Ordering::Acquire), 1);

    assert!(
        stack.enqueue(&first, true),
        "duplicate SYN reuses its tuple"
    );
    assert_eq!(stack.live_tcp_flows(), 1);

    let mut second = first.clone();
    second[20..22].copy_from_slice(&10_001_u16.to_be_bytes());
    repair_ipv4_tcp_checksum(&mut second);
    assert!(!stack.enqueue(&second, true), "flow ceiling is exact");
    assert_eq!(stack.live_tcp_flows(), 1);

    let mut closed = Stack::new(
        (
            Ipv4Addr::new(198, 18, 0, 2),
            30,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            126,
        ),
        1420,
        1,
        4096,
        Duration::from_secs(60),
        Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    )
    .expect("closed stack")
    .0;
    assert!(!closed.enqueue(&first, false), "quiesce rejects new SYN");
    assert_eq!(closed.live_tcp_flows(), 0);

    let (mut ipv6_stack, _) = Stack::new(
        (
            Ipv4Addr::new(198, 18, 0, 2),
            30,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            126,
        ),
        1420,
        1,
        4096,
        Duration::from_secs(60),
        Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    )
    .expect("IPv6 stack");
    assert!(ipv6_stack.enqueue(&ipv6_tcp(), true));
    assert_eq!(ipv6_stack.live_tcp_flows(), 1, "IPv6 has the same ceiling");
    let ipv6_flow = ipv6_stack.flows[0].as_ref().expect("IPv6 flow");
    assert_eq!(ipv6_flow.tuple.source, "[fd00::2]:10000".parse().unwrap());
    assert_eq!(ipv6_flow.tuple.target, "[2001:db8::1]:443".parse().unwrap());
}

#[test]
fn malformed_ipv6_options_are_rejected_before_tcp_admission() {
    let flow_count = Arc::new(AtomicUsize::new(0));
    let (mut stack, _flows) = Stack::new(
        (
            Ipv4Addr::new(198, 18, 0, 2),
            30,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            126,
        ),
        1420,
        1,
        4096,
        Duration::from_secs(60),
        Arc::clone(&flow_count),
    )
    .expect("IPv6 stack");
    let base = ipv6_tcp();
    let mut packet = Vec::with_capacity(base.len() + 8);
    packet.extend_from_slice(&base[..40]);
    packet[6] = 0;
    packet.extend_from_slice(&[6, 0, 0x22, 5, 0, 0, 0, 0]);
    packet.extend_from_slice(&base[40..]);
    packet[4..6].copy_from_slice(&28_u16.to_be_bytes());

    assert!(
        !stack.enqueue(&packet, true),
        "an option crossing the HBH header is rejected"
    );
    assert_eq!(stack.live_tcp_flows(), 0, "malformed options leaked a slot");
    assert_eq!(flow_count.load(Ordering::Acquire), 0);
}

#[test]
fn tcp_flow_index_enforces_capacity_and_reuses_the_recycled_slot() {
    let flow_count = Arc::new(AtomicUsize::new(0));
    let (mut stack, _flows) = Stack::new(
        (
            Ipv4Addr::new(198, 18, 0, 2),
            30,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            126,
        ),
        1420,
        3,
        4096,
        Duration::from_secs(60),
        Arc::clone(&flow_count),
    )
    .expect("three-flow stack");
    let observed = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&observed);
    stack.set_event_sink(TunEventSink::new(move |event| {
        captured.lock().expect("TCP events").push(event);
    }));
    let tuple = |source_port| crate::TcpTuple {
        source: SocketAddr::from((Ipv4Addr::new(198, 18, 0, 2), source_port)),
        target: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 443)),
    };
    let first = tuple(10_000);
    let second = tuple(10_001);
    let third = tuple(10_002);
    let replacement = tuple(10_003);

    assert!(stack.admit_tcp(first, true));
    assert!(stack.admit_tcp(second, true));
    assert!(stack.admit_tcp(third, true));
    assert_eq!(stack.live_tcp_flows(), 3);
    assert_eq!(flow_count.load(Ordering::Acquire), 3);
    assert_eq!(stack.flow_index.len(), 3);
    assert!(stack.free_flow_slots.is_empty());

    assert!(stack.admit_tcp(first, true), "duplicate reuses its index");
    assert_eq!(stack.live_tcp_flows(), 3);
    observed.lock().expect("TCP events").clear();
    assert!(
        !stack.admit_tcp(replacement, true),
        "a distinct tuple cannot exceed the exact flow ceiling"
    );
    assert_eq!(
        *observed.lock().expect("TCP events"),
        [
            TunEvent::TcpFlowRejectedLimit,
            TunEvent::PacketRejected(TunRejectReason::TcpFlowLimit),
        ]
    );

    let recycled = stack.flow_index[&second];
    drop(
        stack.flows[recycled.slot]
            .as_mut()
            .expect("indexed flow is live")
            .pending
            .take(),
    );
    assert!(stack.drive_tcp(), "dropped bridge aborts its socket");
    assert_eq!(stack.reap_tcp(), 1);
    assert!(!stack.flow_index.contains_key(&second));
    assert_eq!(stack.live_tcp_flows(), 2);
    assert_eq!(flow_count.load(Ordering::Acquire), 2);

    assert!(stack.admit_tcp(replacement, true));
    let reused = stack.flow_index[&replacement];
    assert_eq!(reused.slot, recycled.slot, "free-list reuses the sole slot");
    assert_eq!(
        reused.generation,
        recycled.generation + 1,
        "slot reuse advances its generation exactly once"
    );
    assert_eq!(stack.live_tcp_flows(), 3);
    assert_eq!(flow_count.load(Ordering::Acquire), 3);
    assert!(stack.free_flow_slots.is_empty());

    let mut active = Vec::new();
    let mut current = stack.active_flow_head;
    while let Some(slot) = current {
        active.push(slot);
        current = stack.flows[slot]
            .as_ref()
            .expect("active slot is live")
            .active_next;
    }
    assert_eq!(active, [0, 2, 1], "reused slot rejoins at the fair tail");
}

#[test]
fn tcp_flow_drive_rotates_across_only_the_live_slots() {
    let (mut stack, _flows) = Stack::new(
        (
            Ipv4Addr::new(198, 18, 0, 2),
            30,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            126,
        ),
        1420,
        64,
        4096,
        Duration::from_secs(60),
        Arc::new(AtomicUsize::new(0)),
    )
    .expect("sparse flow table");
    for source_port in 10_000..10_003 {
        assert!(stack.admit_tcp(
            crate::TcpTuple {
                source: SocketAddr::from((Ipv4Addr::new(198, 18, 0, 2), source_port,)),
                target: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 443)),
            },
            true,
        ));
    }
    assert_eq!(stack.next_flow_cursor, Some(0));
    for expected in [Some(1), Some(2), Some(0), Some(1)] {
        assert!(!stack.drive_tcp(), "idle listeners do not invent work");
        assert_eq!(
            stack.next_flow_cursor, expected,
            "each active flow gets the first visit in turn"
        );
    }
    assert_eq!(stack.live_tcp_flows(), 3);
    assert_eq!(stack.flow_index.len(), 3);
    assert_eq!(stack.free_flow_slots.len(), 61);

    for slot in [0, 1, 2] {
        drop(
            stack.flows[slot]
                .as_mut()
                .expect("live flow")
                .pending
                .take(),
        );
    }
    assert!(stack.drive_tcp());
    assert_eq!(stack.reap_tcp(), 3, "one live snapshot reaps every flow");
    assert_eq!(stack.live_tcp_flows(), 0);
    assert!(stack.flow_index.is_empty());
    assert_eq!(stack.free_flow_slots.len(), 64);
    assert_eq!(stack.active_flow_head, None);
    assert_eq!(stack.active_flow_tail, None);
    assert_eq!(stack.next_flow_cursor, None);
    assert_eq!(stack.next_reap_cursor, None);
}

#[test]
fn tcp_reap_uses_a_bounded_rotating_cursor() {
    let flow_total = crate::TCP_REAP_QUANTUM * 2 + 3;
    let (mut stack, _flows) = Stack::new(
        (
            Ipv4Addr::new(198, 18, 0, 2),
            30,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            126,
        ),
        1420,
        flow_total,
        4096,
        Duration::from_secs(60),
        Arc::new(AtomicUsize::new(0)),
    )
    .expect("bounded reap stack");
    for offset in 0..flow_total {
        let source_port = 10_000 + u16::try_from(offset).expect("test port offset");
        assert!(stack.admit_tcp(
            crate::TcpTuple {
                source: SocketAddr::from((Ipv4Addr::new(198, 18, 0, 1), source_port)),
                target: SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 443)),
            },
            true,
        ));
        drop(
            stack.flows[offset]
                .as_mut()
                .expect("admitted flow")
                .pending
                .take(),
        );
    }
    assert!(stack.drive_tcp(), "dropped bridges abort every socket");

    assert_eq!(stack.reap_tcp(), crate::TCP_REAP_QUANTUM);
    assert_eq!(
        stack.next_reap_cursor,
        Some(crate::TCP_REAP_QUANTUM),
        "cleanup resumes after the bounded first slice"
    );
    assert_eq!(stack.live_tcp_flows(), crate::TCP_REAP_QUANTUM + 3);
    assert_eq!(stack.reap_tcp(), crate::TCP_REAP_QUANTUM);
    assert_eq!(stack.live_tcp_flows(), 3);
    assert_eq!(stack.reap_tcp(), 3);
    assert_eq!(stack.live_tcp_flows(), 0);
    assert_eq!(stack.next_reap_cursor, None);
    assert_eq!(stack.free_flow_slots.len(), flow_total);
}

#[test]
fn configured_ipv4_directed_broadcast_never_reaches_tcp_or_udp_admission() {
    let flow_count = Arc::new(AtomicUsize::new(0));
    let (mut stack, mut flows, mut candidates) = Stack::new_with_udp(
        (
            Some((Ipv4Addr::new(198, 18, 0, 2), 30)),
            Some((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2), 126)),
        ),
        1420,
        1,
        4096,
        Duration::from_secs(60),
        Arc::clone(&flow_count),
        OwnerRegistry::new(),
        1,
        Duration::from_secs(60),
        UdpFiltering::AddressDependent,
        1,
        OwnerWake::default(),
    )
    .expect("directed-broadcast stack");
    let observed = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&observed);
    stack.set_event_sink(TunEventSink::new(move |event| {
        captured.lock().expect("TUN events").push(event);
    }));

    let retarget = |packet: &mut [u8], destination: Ipv4Addr, protocol: u8| {
        packet[12..16].copy_from_slice(&Ipv4Addr::new(198, 18, 0, 2).octets());
        packet[16..20].copy_from_slice(&destination.octets());
        crate::packet::test_support::repair_transport_checksum(packet, 20, protocol);
        repair_ipv4_header(packet);
    };

    let mut broadcast_udp = ipv4_udp();
    retarget(&mut broadcast_udp, Ipv4Addr::new(198, 18, 0, 3), 17);
    assert!(!stack.enqueue_at(&broadcast_udp, true, 0));
    assert_eq!(stack.udp.provisional_candidates(), 0);
    assert_eq!(stack.udp.active_associations(), 0);
    assert!(candidates.try_recv().is_err());

    let mut broadcast_tcp = ipv4_tcp();
    retarget(&mut broadcast_tcp, Ipv4Addr::new(198, 18, 0, 3), 6);
    assert!(!stack.enqueue_at(&broadcast_tcp, true, 0));
    assert_eq!(stack.live_tcp_flows(), 0);
    assert_eq!(flow_count.load(Ordering::Acquire), 0);
    assert_eq!(stack.pending(), 0);
    assert!(flows.try_recv().is_err());
    assert_eq!(
        observed
            .lock()
            .expect("TUN events")
            .iter()
            .filter(|event| {
                **event == TunEvent::PacketRejected(TunRejectReason::InvalidDestination)
            })
            .count(),
        2
    );

    let mut unicast_udp = ipv4_udp();
    retarget(&mut unicast_udp, Ipv4Addr::new(198, 18, 0, 1), 17);
    assert!(stack.enqueue_at(&unicast_udp, true, 1));
    let candidate = candidates.try_recv().expect("unicast UDP candidate");
    assert_eq!(
        candidate.first_target(),
        SocketAddr::from((Ipv4Addr::new(198, 18, 0, 1), 53))
    );

    let mut unicast_tcp = ipv4_tcp();
    retarget(&mut unicast_tcp, Ipv4Addr::new(198, 18, 0, 1), 6);
    assert!(stack.enqueue_at(&unicast_tcp, true, 1));
    assert_eq!(stack.live_tcp_flows(), 1);
    assert_eq!(flow_count.load(Ordering::Acquire), 1);
    assert_eq!(stack.pending(), 1);
}

#[tokio::test]
async fn tcp_handshake_publishes_once_and_preserves_both_byte_directions() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let registry = OwnerRegistry::new();
    let (mut stack, mut flows, _datagrams) = Stack::new_with_udp(
        (
            Some((Ipv4Addr::new(198, 18, 0, 2), 30)),
            Some((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2), 126)),
        ),
        1420,
        1,
        4096,
        Duration::from_secs(60),
        Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        registry.clone(),
        1,
        Duration::from_secs(60),
        UdpFiltering::AddressDependent,
        0,
        OwnerWake::default(),
    )
    .expect("bounded stack");
    assert_eq!(registry.snapshot().active_tun_tcp_flows, 0);
    assert!(stack.enqueue(&ipv4_tcp(), true));
    assert_eq!(registry.snapshot().active_tun_tcp_flows, 1);
    assert_eq!(
        stack.poll_quantum(Instant::ZERO),
        0,
        "TCP is not a foundation drop"
    );
    let mut syn_ack = Vec::new();
    assert_eq!(
        stack.flush_output(|packet| {
            syn_ack.extend_from_slice(packet);
            OutputSendOutcome::Sent
        }),
        OutputFlushOutcome::Sent
    );
    assert_eq!(syn_ack[33] & 0x12, 0x12);

    let ack = ipv4_tcp_after_syn(&syn_ack, 0x10, &[]);
    assert!(stack.enqueue(&ack, true));
    assert_eq!(
        stack.poll_quantum(Instant::from_millis(1)),
        0,
        "TCP is not a foundation drop"
    );
    let mut flow = flows.try_recv().expect("flow after completed handshake");
    assert_eq!(flow.target(), "192.0.2.1:443".parse().expect("target"));
    assert!(flows.try_recv().is_err(), "one handshake publishes once");

    let inbound = ipv4_tcp_after_syn(&syn_ack, 0x18, b"inbound");
    assert!(stack.enqueue(&inbound, true));
    assert_eq!(
        stack.poll_quantum(Instant::from_millis(2)),
        0,
        "TCP is not a foundation drop"
    );
    let mut received = [0; 7];
    flow.read_exact(&mut received).await.expect("stack to app");
    assert_eq!(&received, b"inbound");
    assert_ne!(
        stack.flush_output(|_| OutputSendOutcome::Sent),
        OutputFlushOutcome::Fatal,
        "optional ACK leaves the fixed TX slot"
    );

    let bridge_capacity = stack.bridge_capacity;
    let outbound = vec![0x5a; bridge_capacity + 17];
    flow.write_all(&outbound[..bridge_capacity])
        .await
        .expect("fill app-to-stack bridge exactly");
    let mut overflow = Box::pin(flow.write_all(&outbound[bridge_capacity..]));
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut overflow)
            .await
            .is_err(),
        "bytes beyond the bridge capacity apply backpressure"
    );
    assert_eq!(
        registry.snapshot().active_tun_tcp_flows,
        1,
        "the production Stack entry owns the pressured flow"
    );
    assert_eq!(bridge_capacity, 4096, "bridge uses tcp_buffer_bytes");
    let mut observed = vec![0_u8; bridge_capacity + 17];
    let first = stack.flows[0]
        .as_mut()
        .expect("live flow")
        .owner
        .read_to_stack(&mut observed[..bridge_capacity]);
    assert_eq!(first, bridge_capacity);
    overflow.await.expect("released bridge write");
    let second = stack.flows[0]
        .as_mut()
        .expect("live flow")
        .owner
        .read_to_stack(&mut observed[bridge_capacity..]);
    assert_eq!(second, 17);
    assert_eq!(observed, outbound, "full bridge drains without byte loss");

    drop(flow);
    stack.poll_quantum(Instant::from_millis(3));
    assert_eq!(
        stack.live_tcp_flows(),
        1,
        "the flow remains owned while its reset is queued"
    );
    let mut reset = false;
    assert_eq!(
        stack.flush_output(|packet| {
            reset = packet[33] & 0x04 != 0;
            OutputSendOutcome::Sent
        }),
        OutputFlushOutcome::Sent
    );
    assert!(reset, "terminal drop emits a local TCP reset");
    assert_eq!(
        stack.live_tcp_flows(),
        1,
        "adapter acceptance is resolved before the next reap pass"
    );
    stack.poll_quantum(Instant::from_millis(4));
    assert_eq!(stack.live_tcp_flows(), 0);
    assert_eq!(registry.snapshot().active_tun_tcp_flows, 0);
    assert!(stack.enqueue(&ipv4_tcp(), true));
    assert_eq!(registry.snapshot().active_tun_tcp_flows, 1);
    assert_eq!(
        stack.flows[0]
            .as_ref()
            .expect("reused slot")
            .generation
            .generation,
        1,
        "reused tuples receive a new generation"
    );
    drop(stack);
    assert_eq!(
        registry.snapshot().active_tun_tcp_flows,
        0,
        "dropping Stack releases the production flow guard"
    );
}

#[tokio::test]
async fn tcp_abort_waits_for_existing_wave_and_queued_reset_before_reap() {
    const FLOW_TOTAL: usize = 2;
    const BUFFER_BYTES: usize = 4_096;
    const PAYLOAD_BYTES: usize = 512;
    let flow_count = Arc::new(AtomicUsize::new(0));
    let (mut stack, mut flows) = Stack::new(
        (
            Ipv4Addr::new(198, 18, 0, 2),
            30,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            126,
        ),
        1420,
        FLOW_TOTAL,
        BUFFER_BYTES,
        Duration::from_secs(60),
        Arc::clone(&flow_count),
    )
    .expect("two-flow abort stack");
    let (mut retained, _) = establish_ipv4_tcp_flow(&mut stack, &mut flows, 10_000, 0);
    let (mut aborted, _) = establish_ipv4_tcp_flow(&mut stack, &mut flows, 10_001, 2);

    retained
        .write_all(&vec![0x41; PAYLOAD_BYTES])
        .await
        .expect("fill retained flow bridge");
    aborted
        .write_all(&vec![0x42; PAYLOAD_BYTES])
        .await
        .expect("fill aborted flow bridge");
    assert!(stack.drive_tcp(), "both bridges reach smoltcp");
    assert!(stack.poll_stack_once(Instant::from_millis(100)).worked);
    assert_eq!(
        stack.device.output_count, FLOW_TOTAL,
        "the existing data wave contains one packet per flow"
    );

    let aborted_slot = stack
        .flows
        .iter()
        .position(|entry| {
            entry
                .as_ref()
                .is_some_and(|entry| entry.tuple.source.port() == 10_001)
        })
        .expect("aborted flow slot");
    drop(aborted);
    assert!(stack.poll_stack_once(Instant::from_millis(101)).worked);
    let aborted_socket = stack.flows[aborted_slot]
        .as_ref()
        .expect("aborted flow remains live during the old wave")
        .socket;
    assert_eq!(
        stack.sockets.get::<TcpSocket>(aborted_socket).state(),
        TcpState::Closed
    );
    assert!(
        stack
            .sockets
            .get::<TcpSocket>(aborted_socket)
            .remote_endpoint()
            .is_some(),
        "the undispatched reset retains its remote tuple"
    );
    assert_eq!(stack.live_tcp_flows(), FLOW_TOTAL);
    assert_eq!(
        stack.device.output_count, FLOW_TOTAL,
        "an abort cannot grow a partially drained wave"
    );

    while stack.has_output() {
        assert_eq!(
            stack.flush_output(|packet| {
                assert_eq!(packet[33] & 0x04, 0, "the old wave contains data, not RST");
                OutputSendOutcome::Sent
            }),
            OutputFlushOutcome::Sent
        );
    }
    assert!(stack.poll_stack_once(Instant::from_millis(102)).worked);
    assert!(
        stack
            .sockets
            .get::<TcpSocket>(aborted_socket)
            .remote_endpoint()
            .is_none(),
        "RST dispatch clears the smoltcp tuple"
    );
    assert_eq!(
        stack.live_tcp_flows(),
        FLOW_TOTAL,
        "the queued reset still owns its flow slot"
    );

    let mut reset_seen = false;
    while stack.has_output() {
        assert_eq!(
            stack.flush_output(|packet| {
                let destination_port = u16::from_be_bytes([packet[22], packet[23]]);
                if destination_port == 10_001 {
                    assert_ne!(packet[33] & 0x04, 0, "aborted flow emits RST");
                    reset_seen = true;
                } else {
                    assert_eq!(packet[33] & 0x04, 0, "retained flow is not reset");
                }
                OutputSendOutcome::Sent
            }),
            OutputFlushOutcome::Sent
        );
    }
    assert!(reset_seen, "the next wave contains the abort RST");
    assert_eq!(stack.live_tcp_flows(), FLOW_TOTAL);
    stack.poll_quantum(Instant::from_millis(103));
    assert_eq!(stack.live_tcp_flows(), 1);
    assert_eq!(flow_count.load(Ordering::Acquire), 1);
    drop(retained);
}

#[tokio::test]
async fn established_rst_packet_surfaces_connection_reset_to_the_application() {
    let (mut stack, mut flows) = Stack::new(
        (
            Ipv4Addr::new(198, 18, 0, 2),
            30,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            126,
        ),
        1420,
        1,
        4096,
        Duration::from_secs(60),
        Arc::new(AtomicUsize::new(0)),
    )
    .expect("RST packet-path stack");
    let (mut flow, syn_ack) = establish_ipv4_tcp_flow(&mut stack, &mut flows, 10_000, 0);

    let rst = ipv4_tcp_after_syn(&syn_ack, 0x14, &[]);
    assert!(stack.enqueue(&rst, true));
    stack.poll_quantum(Instant::from_millis(2));

    let read_error = flow
        .read(&mut [0_u8; 1])
        .await
        .expect_err("an established RST is not EOF");
    assert_eq!(read_error.kind(), std::io::ErrorKind::ConnectionReset);
    let write_error = flow
        .write_all(b"after reset")
        .await
        .expect_err("an established RST rejects application writes");
    assert_eq!(write_error.kind(), std::io::ErrorKind::ConnectionReset);
    assert_eq!(stack.live_tcp_flows(), 0, "reset socket is reaped");
}

#[tokio::test]
async fn tcp_drive_skips_blocked_flow_and_rotates_across_active_flows() {
    const FLOW_TOTAL: usize = 20;
    const BUFFER_BYTES: usize = 16 * 1024;
    let (mut stack, mut flows) = Stack::new(
        (
            Ipv4Addr::new(198, 18, 0, 2),
            30,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            126,
        ),
        1420,
        FLOW_TOTAL,
        BUFFER_BYTES,
        Duration::from_secs(60),
        Arc::new(AtomicUsize::new(0)),
    )
    .expect("multi-flow fairness stack");
    let mut application_flows = Vec::with_capacity(FLOW_TOTAL);
    let mut syn_acks = Vec::with_capacity(FLOW_TOTAL);
    for offset in 0..FLOW_TOTAL {
        let (flow, syn_ack) = establish_ipv4_tcp_flow(
            &mut stack,
            &mut flows,
            10_000 + u16::try_from(offset).expect("test port offset"),
            i64::try_from(offset * 2).expect("test time"),
        );
        application_flows.push(flow);
        syn_acks.push(syn_ack);
    }

    let blocked_fill = vec![0x41; BUFFER_BYTES];
    assert_eq!(
        stack.flows[0]
            .as_mut()
            .expect("blocked flow")
            .owner
            .write_from_stack(&blocked_fill),
        BUFFER_BYTES
    );
    assert!(stack.enqueue(&ipv4_tcp_after_syn(&syn_acks[0], 0x18, b"blocked"), true));
    stack.poll_quantum(Instant::from_millis(100));
    assert!(matches!(
        stack.flush_output(|_| OutputSendOutcome::Sent),
        OutputFlushOutcome::Empty | OutputFlushOutcome::Sent
    ));

    let outbound = vec![0x5a; BUFFER_BYTES];
    for flow in application_flows.iter_mut().skip(1) {
        flow.write_all(&outbound)
            .await
            .expect("fill active flow bridge");
    }
    stack.next_flow_cursor = Some(0);
    assert!(stack.drive_tcp());
    assert_eq!(
        stack.flows[0]
            .as_ref()
            .expect("blocked flow")
            .owner
            .application_capacity(),
        0,
        "a blocked receive flow is skipped without consuming the byte budget"
    );
    for slot in 1..=16 {
        assert_eq!(
            stack.flows[slot]
                .as_ref()
                .expect("active flow")
                .owner
                .stack_buffered(),
            0,
            "the first quantum serves active slot {slot}"
        );
    }
    for slot in 17..FLOW_TOTAL {
        assert_eq!(
            stack.flows[slot]
                .as_ref()
                .expect("deferred flow")
                .owner
                .stack_buffered(),
            BUFFER_BYTES,
            "the global byte quantum defers slot {slot}"
        );
    }
    assert_eq!(stack.next_flow_cursor, Some(17));

    assert!(stack.drive_tcp());
    for slot in 1..FLOW_TOTAL {
        assert_eq!(
            stack.flows[slot]
                .as_ref()
                .expect("active flow")
                .owner
                .stack_buffered(),
            0,
            "the rotating cursor reaches slot {slot}"
        );
    }
}
