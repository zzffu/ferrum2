use super::support::*;

use crate::packet::{ParsedIpPacket, TransportMetadata};
use crate::system_tcp::{PortQuarantine, SystemTcp};

const TEST_ADDRESSES: crate::system_tcp::InterfaceAddresses = (
    Some((Ipv4Addr::new(198, 18, 0, 2), 30)),
    Some((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2), 126)),
);
const TEST_LISTENER_PORTS: (Option<u16>, Option<u16>) = (Some(40_001), Some(40_002));

fn system_tcp(max_flows: usize, generation: u64) -> SystemTcp {
    let (mut tcp, _flows) = SystemTcp::new(
        max_flows,
        Duration::from_secs(60),
        generation,
        Arc::new(AtomicUsize::new(0)),
        OwnerRegistry::new(),
        OwnerWake::default(),
        Arc::new(Mutex::new(PortQuarantine::default())),
    );
    tcp.configure_bindings_for_test(TEST_ADDRESSES, TEST_LISTENER_PORTS)
        .expect("deterministic TCP bindings");
    tcp
}

fn parsed_tcp(packet: &[u8]) -> ParsedIpPacket {
    let ParsedPacket::Complete(parsed) = PacketParser::new(Families::DUAL)
        .parse(packet)
        .expect("valid complete TCP packet")
    else {
        panic!("complete TCP packet expected")
    };
    assert!(matches!(parsed.transport, TransportMetadata::Tcp(_)));
    parsed
}

fn tcp_endpoints(packet: &[u8]) -> (SocketAddr, SocketAddr) {
    let parsed = parsed_tcp(packet);
    let TransportMetadata::Tcp(tcp) = parsed.transport else {
        unreachable!()
    };
    (
        SocketAddr::new(parsed.source, tcp.source_port),
        SocketAddr::new(parsed.destination, tcp.destination_port),
    )
}

fn repair_tcp_packet(packet: &mut [u8]) {
    match packet[0] >> 4 {
        4 => {
            repair_ipv4_header(packet);
            repair_ipv4_tcp_checksum(packet);
        }
        6 => {
            let offset = 40;
            packet[offset + 16..offset + 18].fill(0);
            let length = u32::try_from(packet.len() - offset).unwrap().to_be_bytes();
            let next = [0_u8, 0, 0, 6];
            let value = checksum(&[
                &packet[8..24],
                &packet[24..40],
                &length,
                &next,
                &packet[offset..],
            ]);
            packet[offset + 16..offset + 18].copy_from_slice(&value.to_be_bytes());
        }
        version => panic!("unexpected IP version {version}"),
    }
}

fn reverse_tcp_segment(packet: &[u8], flags: u8) -> Vec<u8> {
    let parsed = parsed_tcp(packet);
    let offset = parsed.transport_offset;
    let mut reverse = packet.to_vec();
    match parsed.family {
        crate::packet::IpFamily::Ipv4 => {
            let source: [u8; 4] = reverse[12..16].try_into().unwrap();
            let destination: [u8; 4] = reverse[16..20].try_into().unwrap();
            reverse[12..16].copy_from_slice(&destination);
            reverse[16..20].copy_from_slice(&source);
        }
        crate::packet::IpFamily::Ipv6 => {
            let source: [u8; 16] = reverse[8..24].try_into().unwrap();
            let destination: [u8; 16] = reverse[24..40].try_into().unwrap();
            reverse[8..24].copy_from_slice(&destination);
            reverse[24..40].copy_from_slice(&source);
        }
    }
    let source_port: [u8; 2] = reverse[offset..offset + 2].try_into().unwrap();
    let destination_port: [u8; 2] = reverse[offset + 2..offset + 4].try_into().unwrap();
    reverse[offset..offset + 2].copy_from_slice(&destination_port);
    reverse[offset + 2..offset + 4].copy_from_slice(&source_port);
    reverse[offset + 13] = flags;
    repair_tcp_packet(&mut reverse);
    reverse
}

fn ipv4_tcp_segment(source_port: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = ipv4_tcp_from_source_port(source_port);
    packet[12..16].copy_from_slice(&Ipv4Addr::new(198, 18, 0, 2).octets());
    packet.resize(44 + payload.len(), 0);
    let packet_len = u16::try_from(packet.len()).unwrap();
    packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
    packet[24..28].copy_from_slice(&u32::from(source_port).to_be_bytes());
    packet[32] = 6 << 4;
    packet[33] = flags;
    packet[40..44].copy_from_slice(&[2, 4, 5, 180]);
    packet[44..].copy_from_slice(payload);
    repair_tcp_packet(&mut packet);
    packet
}

fn ipv6_tcp_segment(source_port: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = ipv6_tcp();
    packet.resize(64 + payload.len(), 0);
    let payload_len = u16::try_from(packet.len() - 40).unwrap();
    packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
    packet[40..42].copy_from_slice(&source_port.to_be_bytes());
    packet[44..48].copy_from_slice(&u32::from(source_port).to_be_bytes());
    packet[52] = 6 << 4;
    packet[53] = flags;
    packet[60..64].copy_from_slice(&[2, 4, 5, 180]);
    packet[64..].copy_from_slice(payload);
    repair_tcp_packet(&mut packet);
    packet
}

#[test]
fn tcp_tuple_rewrite_round_trips_ipv4_and_ipv6_without_touching_tcp_contents() {
    for (syn, data, listener) in [
        (
            ipv4_tcp_segment(10_000, 0x02, &[]),
            ipv4_tcp_segment(10_000, 0x18, b"v4 payload"),
            SocketAddr::from((Ipv4Addr::new(198, 18, 0, 2), 40_001)),
        ),
        (
            ipv6_tcp_segment(10_001, 0x02, &[]),
            ipv6_tcp_segment(10_001, 0x18, b"v6 payload"),
            SocketAddr::from((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2), 40_002)),
        ),
    ] {
        let mut tcp = system_tcp(2, 1);
        let mut rewritten_syn = syn.clone();
        let parsed = parsed_tcp(&rewritten_syn);
        tcp.rewrite(&mut rewritten_syn, parsed, true, 0)
            .expect("initial SYN mapping");
        assert_eq!(tcp_endpoints(&rewritten_syn).1, listener);
        assert!(PacketValidator::new(1_420).accepts(&rewritten_syn));

        let mut rewritten_data = data.clone();
        let parsed = parsed_tcp(&rewritten_data);
        tcp.rewrite(&mut rewritten_data, parsed, true, 1)
            .expect("mapped forward packet");
        let mut internal_reply = reverse_tcp_segment(&rewritten_data, 0x18);
        let expected_reply = reverse_tcp_segment(&data, 0x18);
        let parsed = parsed_tcp(&internal_reply);
        tcp.rewrite(&mut internal_reply, parsed, true, 2)
            .expect("mapped reverse packet");

        assert_eq!(internal_reply, expected_reply);
        assert!(PacketValidator::new(1_420).accepts(&internal_reply));
        assert_eq!(tcp.live_flows(), 1);
    }
}

#[test]
fn tcp_admission_requires_a_clean_syn_and_enforces_the_exact_mapping_limit() {
    for flags in [0x03, 0x06, 0x12, 0x10] {
        let mut tcp = system_tcp(1, 1);
        let mut packet = ipv4_tcp_segment(10_000, flags, &[]);
        let parsed = parsed_tcp(&packet);
        assert_eq!(
            tcp.rewrite(&mut packet, parsed, true, 0),
            Err(TunRejectReason::InvalidDestination)
        );
        assert_eq!(tcp.live_flows(), 0);
    }

    let flow_count = Arc::new(AtomicUsize::new(0));
    let (mut tcp, _flows) = SystemTcp::new(
        1,
        Duration::from_secs(60),
        7,
        Arc::clone(&flow_count),
        OwnerRegistry::new(),
        OwnerWake::default(),
        Arc::new(Mutex::new(PortQuarantine::default())),
    );
    tcp.configure_bindings_for_test(TEST_ADDRESSES, TEST_LISTENER_PORTS)
        .expect("deterministic TCP bindings");

    let original = ipv4_tcp_segment(10_000, 0x02, &[]);
    for now in [0, 1] {
        let mut retransmission = original.clone();
        let parsed = parsed_tcp(&retransmission);
        tcp.rewrite(&mut retransmission, parsed, true, now)
            .expect("SYN retransmission reuses mapping");
    }
    assert_eq!(tcp.live_flows(), 1);
    assert_eq!(flow_count.load(Ordering::Acquire), 1);

    let mut overflow = ipv4_tcp_segment(10_001, 0x02, &[]);
    let parsed = parsed_tcp(&overflow);
    assert_eq!(
        tcp.rewrite(&mut overflow, parsed, true, 2),
        Err(TunRejectReason::TcpFlowLimit)
    );
    assert_eq!(tcp.live_flows(), 1);
    assert_eq!(flow_count.load(Ordering::Acquire), 1);

    let mut closed = system_tcp(1, 7);
    let mut packet = original;
    let parsed = parsed_tcp(&packet);
    assert_eq!(
        closed.rewrite(&mut packet, parsed, false, 0),
        Err(TunRejectReason::StaleGeneration)
    );
    assert_eq!(closed.live_flows(), 0);

    assert!(!tcp.expire(59_999));
    assert!(tcp.expire(60_000));
    assert_eq!(tcp.live_flows(), 0);
    assert_eq!(flow_count.load(Ordering::Acquire), 0);
}

#[test]
fn unknown_reverse_tuple_and_malformed_ipv6_options_fail_before_admission() {
    let mut tcp = system_tcp(1, 1);
    let forward = ipv4_tcp_segment(12_345, 0x02, &[]);
    let mut unknown_reverse = reverse_tcp_segment(&forward, 0x12);
    unknown_reverse[12..16].copy_from_slice(&Ipv4Addr::new(198, 18, 0, 2).octets());
    unknown_reverse[16..20].copy_from_slice(&Ipv4Addr::new(198, 18, 0, 1).octets());
    unknown_reverse[20..22].copy_from_slice(&40_001_u16.to_be_bytes());
    repair_tcp_packet(&mut unknown_reverse);
    let parsed = parsed_tcp(&unknown_reverse);
    assert_eq!(
        tcp.rewrite(&mut unknown_reverse, parsed, true, 0),
        Err(TunRejectReason::InvalidDestination)
    );
    assert_eq!(tcp.live_flows(), 0);

    let base = ipv6_tcp_segment(10_000, 0x02, &[]);
    let mut malformed = Vec::with_capacity(base.len() + 8);
    malformed.extend_from_slice(&base[..40]);
    malformed[6] = 0;
    malformed.extend_from_slice(&[6, 0, 0x22, 5, 0, 0, 0, 0]);
    malformed.extend_from_slice(&base[40..]);
    let payload_len = u16::try_from(malformed.len() - 40).unwrap();
    malformed[4..6].copy_from_slice(&payload_len.to_be_bytes());
    crate::packet::test_support::repair_transport_checksum(&mut malformed, 48, 6);
    assert!(PacketParser::new(Families::DUAL).parse(&malformed).is_err());
    let (mut stack, _flows) = Stack::new(
        (
            Ipv4Addr::new(198, 18, 0, 2),
            30,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            126,
        ),
        1_420,
        1,
        Duration::from_secs(60),
        Arc::new(AtomicUsize::new(0)),
    )
    .expect("malformed-packet stack");
    assert!(!stack.enqueue_at(&malformed, true, 0));
    assert_eq!(stack.live_tcp_flows(), 0);
}

#[test]
fn tcp_output_backpressure_preserves_packet_order_without_owner_spinning() {
    let (mut stack, mut flows) = Stack::new(
        (
            Ipv4Addr::new(198, 18, 0, 2),
            30,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            126,
        ),
        1_420,
        2,
        Duration::from_secs(60),
        Arc::new(AtomicUsize::new(0)),
    )
    .expect("deterministic TCP stack");
    let first = ipv4_tcp_segment(10_000, 0x02, &[]);
    let second = ipv4_tcp_segment(10_001, 0x02, &[]);
    assert!(stack.enqueue_at(&first, true, 0));
    assert!(stack.enqueue_at(&second, true, 1));
    assert_eq!(stack.pending(), 2);
    assert!(stack.process_one_tcp_packet());
    assert!(
        !stack.process_one_tcp_packet(),
        "occupied output retains the next rewritten packet"
    );

    let mut emitted = Vec::new();
    assert_eq!(
        stack.flush_output(|packet| {
            emitted.push(packet.to_vec());
            OutputSendOutcome::Sent
        }),
        OutputFlushOutcome::Sent
    );
    assert!(stack.process_one_tcp_packet());
    assert_eq!(
        stack.flush_output(|packet| {
            emitted.push(packet.to_vec());
            OutputSendOutcome::Sent
        }),
        OutputFlushOutcome::Sent
    );
    assert_eq!(stack.pending(), 0);
    assert!(flows.try_recv().is_err(), "mapping alone publishes no flow");
    assert_eq!(emitted.len(), 2);
    assert_eq!(
        emitted
            .iter()
            .map(|packet| u32::from_be_bytes(packet[24..28].try_into().unwrap()))
            .collect::<Vec<_>>(),
        [10_000, 10_001]
    );
    assert!(
        emitted
            .iter()
            .all(|packet| PacketValidator::new(1_420).accepts(packet))
    );
}

#[test]
fn fragmented_tcp_reassembles_and_rewrites_above_the_configured_mtu() {
    const MTU: usize = 1_280;
    let payload = vec![0x5a; 2_000];
    let original = ipv4_tcp_segment(10_000, 0x02, &payload);
    let fragments = fragment_ipv4_packet(&original, MTU);
    assert!(original.len() > MTU);
    assert!(fragments.iter().all(|fragment| fragment.len() <= MTU));

    let (mut stack, mut flows) = Stack::new(
        (
            Ipv4Addr::new(198, 18, 0, 2),
            30,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            126,
        ),
        MTU,
        1,
        Duration::from_secs(60),
        Arc::new(AtomicUsize::new(0)),
    )
    .expect("TCP reassembly stack");
    for (now, fragment) in fragments.iter().rev().enumerate() {
        assert!(stack.enqueue_at(fragment, true, i64::try_from(now).unwrap()));
    }
    assert_eq!(stack.pending(), 1);
    assert!(stack.process_one_tcp_packet());

    let mut rewritten = Vec::new();
    assert_eq!(
        stack.flush_output(|packet| {
            rewritten.extend_from_slice(packet);
            OutputSendOutcome::Sent
        }),
        OutputFlushOutcome::Sent
    );
    assert_eq!(rewritten.len(), original.len());
    assert!(rewritten.len() > MTU);
    assert_eq!(&rewritten[44..], payload);
    let _ = parsed_tcp(&rewritten);
    assert_eq!(
        tcp_endpoints(&rewritten).1,
        SocketAddr::from((Ipv4Addr::new(198, 18, 0, 2), 20_000))
    );
    assert!(flows.try_recv().is_err(), "mapping alone publishes no flow");
}

#[test]
fn configured_ipv4_directed_broadcast_never_reaches_tcp_or_udp_admission() {
    let flow_count = Arc::new(AtomicUsize::new(0));
    let (mut stack, mut flows, mut candidates) = Stack::new_with_udp(
        TEST_ADDRESSES,
        1_420,
        1,
        Duration::from_secs(60),
        Arc::clone(&flow_count),
        OwnerRegistry::new(),
        1,
        Duration::from_secs(60),
        UdpFiltering::AddressDependent,
        1,
        OwnerWake::default(),
        Arc::new(Mutex::new(PortQuarantine::default())),
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
    assert!(candidates.try_recv().is_err());

    let mut broadcast_tcp = ipv4_tcp_segment(10_000, 0x02, &[]);
    retarget(&mut broadcast_tcp, Ipv4Addr::new(198, 18, 0, 3), 6);
    assert!(!stack.enqueue_at(&broadcast_tcp, true, 0));
    assert_eq!(stack.live_tcp_flows(), 0);
    assert_eq!(flow_count.load(Ordering::Acquire), 0);
    assert!(flows.try_recv().is_err());

    let mut unicast_udp = ipv4_udp();
    retarget(&mut unicast_udp, Ipv4Addr::new(198, 18, 0, 1), 17);
    assert!(stack.enqueue_at(&unicast_udp, true, 1));
    assert_eq!(
        candidates
            .try_recv()
            .expect("unicast UDP candidate")
            .first_target(),
        SocketAddr::from((Ipv4Addr::new(198, 18, 0, 1), 53))
    );

    let mut unicast_tcp = ipv4_tcp_segment(10_000, 0x02, &[]);
    retarget(&mut unicast_tcp, Ipv4Addr::new(198, 18, 0, 1), 6);
    assert!(stack.enqueue_at(&unicast_tcp, true, 1));
    assert_eq!(stack.live_tcp_flows(), 1);
    assert_eq!(flow_count.load(Ordering::Acquire), 1);
    assert_eq!(stack.pending(), 1);
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
}
