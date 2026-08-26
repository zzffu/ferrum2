use super::support::*;

#[test]
fn parser_address_rejections_preserve_the_public_source_destination_split() {
    assert_eq!(
        crate::map_packet_reject(crate::packet::PacketRejectReason::InvalidSource),
        TunRejectReason::InvalidSource
    );
    assert_eq!(
        crate::map_packet_reject(crate::packet::PacketRejectReason::InvalidDestination),
        TunRejectReason::InvalidDestination
    );
}

#[test]
fn smoltcp_accepts_reassembled_rx_larger_than_reported_device_mtu() {
    use smoltcp::iface::{
        Config as InterfaceConfig, Interface, PollIngressSingleResult, SocketSet,
    };
    use smoltcp::socket::udp::{PacketBuffer, PacketMetadata, Socket as UdpSocket};
    use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};

    const REPORTED_MTU: usize = 1_280;
    const PAYLOAD_LEN: usize = 2_000;
    let packet = ipv4_udp_with_payload(PAYLOAD_LEN);
    let ParsedPacket::Complete(parsed) = PacketParser::new(Families::DUAL)
        .parse(&packet)
        .expect("canonical oversized packet")
    else {
        panic!("complete packet expected")
    };
    assert!(packet.len() > REPORTED_MTU);

    let mut device = MemoryDevice::new(REPORTED_MTU, Families::DUAL);
    assert_eq!(device.capabilities().max_transmission_unit, REPORTED_MTU);
    let mut interface = Interface::new(
        InterfaceConfig::new(HardwareAddress::Ip),
        &mut device,
        Instant::ZERO,
    );
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(
                IpAddress::Ipv4(Ipv4Address::new(192, 0, 2, 1)),
                24,
            ))
            .expect("one interface address");
    });
    let rx = PacketBuffer::new(vec![PacketMetadata::EMPTY; 1], vec![0_u8; PAYLOAD_LEN]);
    let tx = PacketBuffer::new(vec![PacketMetadata::EMPTY; 1], vec![0_u8; 1]);
    let mut socket = UdpSocket::new(rx, tx);
    socket.bind(53).expect("UDP listener");
    let mut sockets = SocketSet::new(Vec::new());
    let handle = sockets.add(socket);

    assert!(device.enqueue_parsed(&packet, parsed));
    assert_ne!(
        interface.poll_ingress_single(Instant::ZERO, &mut device, &mut sockets),
        PollIngressSingleResult::None,
        "smoltcp 0.13.1 must not apply reported egress MTU to RX tokens"
    );
    let (payload, metadata) = sockets
        .get_mut::<UdpSocket>(handle)
        .recv()
        .expect("oversized RX delivered");
    assert_eq!(payload.len(), PAYLOAD_LEN);
    assert_eq!(metadata.endpoint.port, 10_000);
    assert_eq!(device.capabilities().max_transmission_unit, REPORTED_MTU);
}

#[test]
fn capacity_aware_rotation_drains_eight_sixteen_and_sixty_four_packets() {
    use std::collections::VecDeque;

    use crate::scheduler::StepOutcome;

    let packet = ipv4_tcp();
    let ParsedPacket::Complete(parsed) = PacketParser::new(Families::DUAL)
        .parse(&packet)
        .expect("canonical TCP packet")
    else {
        panic!("complete packet expected")
    };

    for count in [8, 16, 64] {
        let mut device = MemoryDevice::new(1_420, Families::DUAL);
        let mut source = VecDeque::from(vec![packet.clone(); count]);
        let mut scheduler = crate::FairScheduler::default();
        let mut drained = 0;
        while !source.is_empty() || device.ingress_len != 0 {
            let outcome = scheduler.run_budget(64, |stage| match stage {
                crate::WorkStage::Receive if device.ingress_available() != 0 => {
                    let Some(packet) = source.pop_front() else {
                        return StepOutcome::Idle;
                    };
                    assert!(device.enqueue_parsed(&packet, parsed));
                    StepOutcome::Worked
                }
                crate::WorkStage::Stack => {
                    if device.dequeue_index().is_some() {
                        drained += 1;
                        StepOutcome::Worked
                    } else {
                        StepOutcome::Idle
                    }
                }
                _ => StepOutcome::Idle,
            });
            assert!(!outcome.fatal);
            assert!(outcome.work_units != 0, "scheduler made bounded progress");
            assert!(device.ingress_len <= INGRESS_SLOTS);
        }
        assert_eq!(drained, count);
    }
}

#[test]
fn ring_full_drops_exactly_one_complete_output_and_fatal_retains_it() {
    let mut device = MemoryDevice::new(1_420, Families::DUAL);
    let endpoints = UdpDatagramEndpoints::new(
        "198.18.0.1:10000".parse().expect("local"),
        "192.0.2.1:53".parse().expect("remote"),
    );
    assert_eq!(
        device.inject_udp_response(endpoints, b"one"),
        crate::UdpInjectOutcome::Injected
    );
    assert_eq!(
        device.flush_output(|_| OutputSendOutcome::DroppedRingFull),
        OutputFlushOutcome::DroppedRingFull
    );
    assert_eq!(
        device.flush_output(|_| OutputSendOutcome::Sent),
        OutputFlushOutcome::Empty,
        "ring-full output is never retried"
    );

    assert_eq!(
        device.inject_udp_response(endpoints, b"two"),
        crate::UdpInjectOutcome::Injected
    );
    assert_eq!(
        device.flush_output(|_| OutputSendOutcome::Fatal),
        OutputFlushOutcome::Fatal
    );
    assert!(
        device.has_output(),
        "fatal send preserves evidence for cleanup"
    );
}

#[test]
fn output_wave_is_packet_bounded_and_preserves_fifo_send_outcomes() {
    const OUTPUT_SLOTS: usize = 3;
    let mut device = MemoryDevice::with_output_slots(1_420, Families::DUAL, OUTPUT_SLOTS);
    let packets = (0..OUTPUT_SLOTS)
        .map(|offset| {
            ipv4_tcp_from_source_port(10_000 + u16::try_from(offset).expect("test port offset"))
        })
        .collect::<Vec<_>>();

    for packet in &packets {
        device
            .transmit(Instant::ZERO)
            .expect("bounded output slot")
            .consume(packet.len(), |bytes| bytes.copy_from_slice(packet));
    }
    assert!(
        device.transmit(Instant::ZERO).is_none(),
        "the packet-count bound is exact"
    );
    assert_eq!(device.output_count, OUTPUT_SLOTS);
    assert_eq!(device.front_output(), Some(packets[0].as_slice()));

    let endpoints = UdpDatagramEndpoints::new(
        "198.18.0.1:10000".parse().expect("local"),
        "192.0.2.1:53".parse().expect("remote"),
    );
    assert_eq!(
        device.inject_udp_response(endpoints, b"deferred"),
        UdpInjectOutcome::Backpressured,
        "UDP keeps its response while a TCP wave is queued"
    );
    assert_eq!(
        device.flush_output(|packet| {
            assert_eq!(packet, packets[0]);
            OutputSendOutcome::DroppedRingFull
        }),
        OutputFlushOutcome::DroppedRingFull
    );
    assert_eq!(device.output_count, 2);
    assert_eq!(device.front_output(), Some(packets[1].as_slice()));
    assert_eq!(
        device.flush_output(|packet| {
            assert_eq!(packet, packets[1]);
            OutputSendOutcome::Sent
        }),
        OutputFlushOutcome::Sent
    );
    assert_eq!(device.output_count, 1);
    assert_eq!(
        device.flush_output(|packet| {
            assert_eq!(packet, packets[2]);
            OutputSendOutcome::Fatal
        }),
        OutputFlushOutcome::Fatal
    );
    assert_eq!(
        device.front_output(),
        Some(packets[2].as_slice()),
        "fatal send retains the exact head packet"
    );
    assert_eq!(
        device.flush_output(|_| OutputSendOutcome::Sent),
        OutputFlushOutcome::Sent
    );
    assert_eq!(
        device.inject_udp_response(endpoints, b"released"),
        UdpInjectOutcome::Injected,
        "the same UDP path resumes only after the TCP wave drains"
    );
}

#[test]
fn udp_injection_preserves_the_canonical_packet_reject_reason() {
    let mut device = MemoryDevice::new(1_420, Families::IPV4_ONLY);
    let ipv6 = UdpDatagramEndpoints::new(
        "[fd00::1]:10000".parse().expect("local IPv6"),
        "[2001:db8::1]:53".parse().expect("remote IPv6"),
    );
    assert_eq!(
        device.inject_udp_response(ipv6, b"disabled family"),
        crate::UdpInjectOutcome::Rejected(crate::TunRejectReason::FamilyDisabled)
    );
    let mixed = UdpDatagramEndpoints::new(
        "198.18.0.1:10000".parse().expect("local IPv4"),
        "[2001:db8::1]:53".parse().expect("remote IPv6"),
    );
    assert_eq!(
        device.inject_udp_response(mixed, b"mixed family"),
        crate::UdpInjectOutcome::Rejected(crate::TunRejectReason::InvalidDestination)
    );
    assert_eq!(device.rejected_output, 2);
    assert!(!device.has_output());
}

#[test]
fn stack_injects_pmtu_feedback_at_a_fixed_rate() {
    use crate::packet::test_support::{ipv4_udp, repair_ipv4_header};

    const MTU: usize = 1_280;
    let (mut stack, _flows) = Stack::new(
        (
            Ipv4Addr::new(198, 18, 0, 2),
            30,
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            126,
        ),
        MTU,
        1,
        1_024,
        Duration::from_secs(60),
        Arc::new(AtomicUsize::new(0)),
    )
    .expect("bounded stack");
    let mut packet = ipv4_udp(&vec![0x5a; MTU], &[]);
    packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    repair_ipv4_header(&mut packet);

    assert!(!stack.enqueue_at(&packet, true, 0));
    let mut control = Vec::new();
    assert_eq!(
        stack.flush_output(|packet| {
            control.extend_from_slice(packet);
            OutputSendOutcome::Sent
        }),
        OutputFlushOutcome::Sent
    );
    assert_eq!(&control[20..22], &[3, 4]);
    assert_eq!(u16::from_be_bytes([control[26], control[27]]), MTU as u16);

    assert!(!stack.enqueue_at(&packet, true, 99));
    assert_eq!(
        stack.flush_output(|_| OutputSendOutcome::Sent),
        OutputFlushOutcome::Empty
    );
    assert!(!stack.enqueue_at(&packet, true, 100));
    assert_eq!(
        stack.flush_output(|_| OutputSendOutcome::Sent),
        OutputFlushOutcome::Sent
    );
}

#[test]
fn packet_filter_accepts_only_complete_direct_tcp_or_udp() {
    let valid_v4 = ipv4_udp();
    let valid_v6 = ipv6_udp();
    let valid_v4_tcp = ipv4_tcp();
    let valid_v6_tcp = ipv6_tcp();
    let valid_zero_checksum_tcp = crate::packet::test_support::ipv4_tcp_zero_checksum();
    for (name, packet) in [
        ("IPv4 UDP", valid_v4.as_slice()),
        ("IPv4 TCP", valid_v4_tcp.as_slice()),
        ("IPv6 UDP", valid_v6.as_slice()),
        ("IPv6 TCP", valid_v6_tcp.as_slice()),
        ("IPv4 TCP zero checksum", valid_zero_checksum_tcp.as_slice()),
    ] {
        assert_ingress_and_egress(name, packet, 1420, true);
    }
    let mut zero_v4_udp = valid_v4.clone();
    zero_v4_udp[26..28].fill(0);
    assert_ingress_and_egress("IPv4 UDP zero checksum", &zero_v4_udp, 1420, true);

    let mut df = valid_v4.clone();
    df[6] = 0x40;
    repair_ipv4_header(&mut df);
    assert_ingress_and_egress("IPv4 DF", &df, 1420, true);

    let minimum_udp = ipv4_udp_with_payload(0);
    assert_ingress_and_egress("IPv4 UDP minimum", &minimum_udp, 1420, true);
    let mtu_packet = ipv4_udp_with_payload(1420 - 28);
    assert_ingress_and_egress("MTU exact", &mtu_packet, 1420, true);
    assert_ingress_and_egress("MTU plus one", &mtu_packet, 1419, false);

    let mut mutations = vec![
        ("empty", Vec::new()),
        ("IPv4 header minimum minus one", valid_v4[..19].to_vec()),
        ("IPv4 transport minimum minus one", valid_v4[..27].to_vec()),
        ("IPv4 version", {
            let mut p = valid_v4.clone();
            p[0] = 0x55;
            repair_ipv4_header(&mut p);
            p
        }),
        ("IPv4 IHL 4", {
            let mut p = valid_v4.clone();
            p[0] = 0x44;
            repair_ipv4_header(&mut p);
            p
        }),
        ("IPv4 option", {
            let mut p = valid_v4.clone();
            p[0] = 0x46;
            repair_ipv4_header(&mut p);
            p
        }),
        ("IPv4 declared length minimum minus one", {
            let mut p = valid_v4.clone();
            p[2..4].copy_from_slice(&31_u16.to_be_bytes());
            repair_ipv4_header(&mut p);
            p
        }),
        ("IPv4 declared length plus one", {
            let mut p = valid_v4.clone();
            p[2..4].copy_from_slice(&33_u16.to_be_bytes());
            repair_ipv4_header(&mut p);
            p
        }),
        ("IPv4 reserved", {
            let mut p = valid_v4.clone();
            p[6] = 0x80;
            repair_ipv4_header(&mut p);
            p
        }),
        ("IPv4 MF", {
            let mut p = valid_v4.clone();
            p[6] = 0x20;
            repair_ipv4_header(&mut p);
            p
        }),
        ("IPv4 fragment offset", {
            let mut p = valid_v4.clone();
            p[7] = 1;
            repair_ipv4_header(&mut p);
            p
        }),
        ("IPv4 trailing", {
            let mut p = valid_v4.clone();
            p.push(0);
            p
        }),
        ("IPv4 checksum", {
            let mut p = valid_v4.clone();
            p[10] ^= 1;
            p
        }),
        ("IPv4 ICMP", {
            let mut p = valid_v4.clone();
            p[9] = 1;
            repair_ipv4_header(&mut p);
            p
        }),
        ("IPv4 unknown protocol", {
            let mut p = valid_v4.clone();
            p[9] = 99;
            repair_ipv4_header(&mut p);
            p
        }),
        ("IPv4 zero port", {
            let mut p = valid_v4.clone();
            p[20..22].fill(0);
            p
        }),
        ("IPv4 UDP destination zero", {
            let mut p = valid_v4.clone();
            p[22..24].fill(0);
            p
        }),
        ("IPv4 UDP length minimum minus one", {
            let mut p = valid_v4.clone();
            p[24..26].copy_from_slice(&7_u16.to_be_bytes());
            p
        }),
        ("IPv4 UDP length short", {
            let mut p = valid_v4.clone();
            p[24..26].copy_from_slice(&11_u16.to_be_bytes());
            p
        }),
        ("IPv4 UDP length long", {
            let mut p = valid_v4.clone();
            p[24..26].copy_from_slice(&13_u16.to_be_bytes());
            p
        }),
        ("IPv4 UDP checksum", {
            let mut p = valid_v4.clone();
            p[28] ^= 1;
            p
        }),
        ("TCP data offset", {
            let mut p = valid_v4_tcp.clone();
            p[32] = 0x40;
            p
        }),
        ("TCP data offset beyond payload", {
            let mut p = valid_v4_tcp.clone();
            p[32] = 0x60;
            p
        }),
        ("TCP source zero", {
            let mut p = valid_v4_tcp.clone();
            p[20..22].fill(0);
            p
        }),
        ("TCP destination zero", {
            let mut p = valid_v4_tcp.clone();
            p[22..24].fill(0);
            p
        }),
        ("TCP checksum", {
            let mut p = valid_v4_tcp.clone();
            p[36] ^= 1;
            p
        }),
        ("IPv6 header minimum minus one", valid_v6[..39].to_vec()),
        ("IPv6 payload length short", {
            let mut p = valid_v6.clone();
            p[4..6].copy_from_slice(&11_u16.to_be_bytes());
            p
        }),
        ("IPv6 payload length long", {
            let mut p = valid_v6.clone();
            p[4..6].copy_from_slice(&13_u16.to_be_bytes());
            p
        }),
        ("IPv6 UDP source zero", {
            let mut p = valid_v6.clone();
            p[40..42].fill(0);
            p
        }),
        ("IPv6 UDP destination zero", {
            let mut p = valid_v6.clone();
            p[42..44].fill(0);
            p
        }),
        ("IPv6 UDP length minimum minus one", {
            let mut p = valid_v6.clone();
            p[44..46].copy_from_slice(&7_u16.to_be_bytes());
            p
        }),
        ("IPv6 UDP length mismatch", {
            let mut p = valid_v6.clone();
            p[44..46].copy_from_slice(&11_u16.to_be_bytes());
            p
        }),
        ("IPv6 zero checksum", {
            let mut p = valid_v6.clone();
            p[46..48].fill(0);
            p
        }),
        ("IPv6 UDP nonzero bad checksum", {
            let mut p = valid_v6.clone();
            p[46] ^= 1;
            p
        }),
        ("IPv6 trailing", {
            let mut p = valid_v6.clone();
            p.push(0);
            p
        }),
        ("IPv6 TCP data offset minimum minus one", {
            let mut p = valid_v6_tcp.clone();
            p[52] = 0x40;
            p
        }),
        ("IPv6 TCP data offset beyond payload", {
            let mut p = valid_v6_tcp.clone();
            p[52] = 0x60;
            p
        }),
        ("IPv6 TCP checksum", {
            let mut p = valid_v6_tcp.clone();
            p[56] ^= 1;
            p
        }),
        ("IPv6 TCP source zero", {
            let mut p = valid_v6_tcp.clone();
            p[40..42].fill(0);
            p
        }),
        ("IPv6 TCP destination zero", {
            let mut p = valid_v6_tcp.clone();
            p[42..44].fill(0);
            p
        }),
    ];

    for (name, range, bytes) in [
        ("IPv4 source unspecified", 12..16, [0, 0, 0, 0]),
        ("IPv4 source multicast", 12..16, [224, 0, 0, 1]),
        ("IPv4 destination unspecified", 16..20, [0, 0, 0, 0]),
        ("IPv4 destination multicast", 16..20, [224, 0, 0, 1]),
        ("IPv4 destination broadcast", 16..20, [255, 255, 255, 255]),
    ] {
        let mut packet = valid_v4.clone();
        packet[range].copy_from_slice(&bytes);
        repair_ipv4_header(&mut packet);
        mutations.push((name, packet));
    }

    for (name, range, bytes) in [
        (
            "IPv6 source unspecified",
            8..24,
            Ipv6Addr::UNSPECIFIED.octets(),
        ),
        (
            "IPv6 source multicast",
            8..24,
            Ipv6Addr::LOCALHOST.octets().map(|_| 0),
        ),
        (
            "IPv6 destination unspecified",
            24..40,
            Ipv6Addr::UNSPECIFIED.octets(),
        ),
        (
            "IPv6 destination multicast",
            24..40,
            Ipv6Addr::LOCALHOST.octets().map(|_| 0),
        ),
    ] {
        let mut packet = valid_v6.clone();
        let mut address = bytes;
        if name.contains("multicast") {
            address[0] = 0xff;
            address[1] = 0x02;
            address[15] = 1;
        }
        packet[range].copy_from_slice(&address);
        mutations.push((name, packet));
    }

    for (name, packet) in mutations {
        assert_ingress_and_egress(name, &packet, 1420, false);
    }

    for next_header in [0, 43, 44, 50, 51, 59, 60, 135, 139, 140, 253, 254] {
        for (shape, mut packet) in [
            ("absent", valid_v6[..40].to_vec()),
            ("truncated", valid_v6[..41].to_vec()),
            ("well-formed/chained", valid_v6.clone()),
        ] {
            packet[6] = next_header;
            let payload = packet.len() - 40;
            packet[4..6].copy_from_slice(&(payload as u16).to_be_bytes());
            if payload > 0 {
                packet[40] = 17;
            }
            assert_ingress_and_egress(
                &format!("IPv6 next header {next_header} {shape}"),
                &packet,
                1420,
                false,
            );
        }
    }
}
